"""dastyab_terminal_shell — Stateful Linux-compatible CPython shell for DastYab Android Terminal Mode.

Handles:
  • `dastyab flow ...` / `dastyab-flow.py ...`  -> in-process Linux `dastyab_flow` module
  • `dastyab aistudio ...` / `dastyab-aistudio.py ...` -> in-process Linux `dastyab_aistudio` module
  • `pip list | check | show | install [--recommended] | uninstall` -> runtime pure-Python installer
  • `python3 -c ...`, `python3 <script.py>`, `python3 -m <mod>`, `python3 --version`
  • `dastyab <native-subcommand>` -> delegates to `libdastyab.so` via host callback
  • Linux shell built-ins (`pwd`, `cd`, `ls`, `cat`, `head`, `tail`, `grep`, `wc`,
    `echo`, `env`, `export`, `unset`, `mkdir`, `rm`, `touch`, `cp`, `mv`, `which`,
    `uname`, `whoami`, `id`, `date`, `clear`, `help`)
"""
import io
import json
import os
import platform
import runpy
import shlex
import shutil
import sys
import threading
import time

import dastyab_android_shim as _shim
import dastyab_aistudio
import dastyab_flow
import dastyab_pip

_SHELL_LOCK = threading.Lock()
_STOP_EVENT = threading.Event()
_ENV_INITIALIZED = False
_CWD = None


class _StreamingWriter(io.TextIOBase):
    def __init__(self, emit_fn):
        self._emit = emit_fn

    def write(self, s):
        if s:
            self._emit(s)
        return len(s)

    def flush(self):
        pass


def init_env(home_dir, tmp_dir, native_lib_dir="", extra_env=None):
    """Initialize HOME, TMPDIR, PATH, and `~/.dastyab` directory tree once."""
    global _ENV_INITIALIZED, _CWD
    os.makedirs(home_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)
    prof = os.path.join(home_dir, ".dastyab", "profiles", "default")
    os.makedirs(prof, exist_ok=True)
    bin_dir = os.path.join(home_dir, ".dastyab", "bin")
    os.makedirs(bin_dir, exist_ok=True)

    os.environ["DASTYAB_ANDROID"] = "1"
    os.environ["HOME"] = home_dir
    os.environ["TMPDIR"] = tmp_dir
    os.environ["PWD"] = home_dir
    os.environ["USER"] = "dastyab"
    os.environ["HOSTNAME"] = "dastyab-android"
    os.environ["PYTHONUNBUFFERED"] = "1"
    if native_lib_dir:
        os.environ["DASTYAB_NATIVE_DIR"] = native_lib_dir

    path_parts = [bin_dir]
    if native_lib_dir:
        path_parts.append(native_lib_dir)
    termux_bin = "/data/data/com.termux/files/usr/bin"
    if os.path.isdir(termux_bin):
        path_parts.append(termux_bin)
    old_path = os.environ.get("PATH", "")
    if old_path:
        path_parts.append(old_path)
    os.environ["PATH"] = os.pathsep.join(dict.fromkeys(p for p in path_parts if p))

    if isinstance(extra_env, dict):
        for k, v in extra_env.items():
            os.environ[str(k)] = str(v)

    if _CWD is None or not os.path.isdir(_CWD):
        _CWD = home_dir
    dastyab_pip.ensure_site_packages_on_path()
    _ENV_INITIALIZED = True
    return prof


def sync_nodes(vless_uris_json, route_info_json="{}"):
    """Sync Android harvested proxy/VPN URIs and route state into `~/.dastyab/profiles/default/`."""
    prof = _shim.profile_dir()
    try:
        uris = json.loads(vless_uris_json) if isinstance(vless_uris_json, str) else list(vless_uris_json)
    except Exception:
        uris = []
    if not isinstance(uris, list):
        uris = []

    nodes = []
    parsed_nodes = []
    seen = set()
    for u in uris:
        if not isinstance(u, str):
            continue
        u = u.strip()
        if not u or u in seen:
            continue
        seen.add(u)
        nodes.append({"url": u, "healthy": True, "source": "android-harvest"})
        pn = dastyab_aistudio.parse_node_uri(u)
        if pn:
            parsed_nodes.append(pn)

    nodes_path = os.path.join(prof, "nodes.json")
    tmp = nodes_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump({"synced_epoch": int(time.time()), "nodes": nodes}, fh, indent=1)
    os.replace(tmp, nodes_path)

    # Populate fresh_vless.json if empty so `dastyab aistudio` works out of the box
    aistudio_pool = os.path.join(prof, "fresh_vless.json")
    if parsed_nodes and (not os.path.isfile(aistudio_pool) or os.path.getsize(aistudio_pool) < 5):
        tmp2 = aistudio_pool + ".tmp"
        with open(tmp2, "w") as fh:
            json.dump(parsed_nodes[:64], fh, indent=1)
        os.replace(tmp2, aistudio_pool)

    # Also write raw uris.txt for quick inspection or `build-pool uris.txt`
    uris_txt = os.path.join(prof, "uris.txt")
    with open(uris_txt, "w") as fh:
        for u in uris:
            if isinstance(u, str) and u.strip():
                fh.write(u.strip() + "\n")

    # Sync Android live VPN / proxy bridge context
    route_path = os.path.join(prof, "android_route.json")
    try:
        route_doc = json.loads(route_info_json) if isinstance(route_info_json, str) else {}
    except Exception:
        route_doc = {}
    with open(route_path, "w") as fh:
        json.dump(route_doc, fh, indent=1)

    return len(nodes)


def get_cwd():
    return _CWD or os.path.expanduser("~")


def prompt_path():
    cwd = get_cwd()
    home = os.path.expanduser("~")
    if cwd == home:
        return "~"
    if cwd.startswith(home + "/"):
        return "~" + cwd[len(home):]
    return cwd


def get_packages_summary():
    dastyab_pip.ensure_site_packages_on_path()
    return json.dumps(dastyab_pip.get_packages_summary())


def request_stop():
    _STOP_EVENT.set()
    try:
        dastyab_flow.stop(quiet=True)
    except Exception:
        pass
    try:
        dastyab_aistudio.stop(quiet=True)
    except Exception:
        pass


def _resolve_path(arg):
    cwd = get_cwd()
    expanded = os.path.expanduser(os.path.expandvars(arg))
    if os.path.isabs(expanded):
        return os.path.normpath(expanded)
    return os.path.normpath(os.path.join(cwd, expanded))


def _expand_vars_in_tokens(tokens):
    out = []
    for tok in tokens:
        if tok.startswith("~"):
            tok = os.path.expanduser(tok)
        tok = os.path.expandvars(tok)
        out.append(tok)
    return out


def execute(command_line, stdout_cb=None, event_cb=None, native_cli_cb=None):
    """Execute one command line inside CPython Terminal Mode. Returns integer exit code."""
    global _CWD
    _STOP_EVENT.clear()
    _shim.set_event_callback(event_cb)

    def emit(text):
        if stdout_cb is not None:
            stdout_cb(text)
        else:
            sys.__stdout__.write(text)

    cmd_text = (command_line or "").strip()
    if not cmd_text:
        return 0

    try:
        tokens = shlex.split(cmd_text)
    except ValueError as e:
        emit(f"sh: parse error: {e}\n")
        return 2

    if not tokens:
        return 0

    tokens = _expand_vars_in_tokens(tokens)
    prog = tokens[0]
    args = tokens[1:]

    with _SHELL_LOCK:
        old_stdout, old_stderr = sys.stdout, sys.stderr
        writer = _StreamingWriter(emit)
        sys.stdout = writer
        sys.stderr = writer
        cwd_before = os.getcwd()
        try:
            target_cwd = get_cwd()
            if os.path.isdir(target_cwd):
                os.chdir(target_cwd)
            return _dispatch(prog, args, native_cli_cb, event_cb)
        except SystemExit as e:
            code = e.code
            if isinstance(code, int):
                return code
            if code:
                print(str(code))
            return 1
        except KeyboardInterrupt:
            print("\n^C Interrupted")
            return 130
        except Exception as e:
            import traceback
            traceback.print_exc()
            return 1
        finally:
            try:
                os.chdir(cwd_before)
            except OSError:
                pass
            sys.stdout = old_stdout
            sys.stderr = old_stderr


def execute_for_host(command_line, host):
    """Chaquopy/JVM entry point accepting a HostBridge object with onStdout/onEvent/runNativeCli."""
    return execute(
        command_line,
        stdout_cb=lambda s: host.onStdout(s),
        event_cb=lambda kind, payload: host.onEvent(kind, payload),
        native_cli_cb=lambda args_json: int(host.runNativeCli(args_json)),
    )


def _dispatch(prog, args, native_cli_cb, event_cb):
    global _CWD
    base = os.path.basename(prog)

    if base in ("dastyab-flow.py", "dastyab_flow.py"):
        return dastyab_flow.main(args)
    if base in ("dastyab-aistudio.py", "dastyab_aistudio.py"):
        return dastyab_aistudio.main(args)

    if base == "dastyab":
        if not args:
            _print_help()
            return 0
        sub = args[0].lower()
        if sub == "flow":
            return dastyab_flow.main(args[1:])
        if sub == "aistudio":
            return dastyab_aistudio.main(args[1:])
        if native_cli_cb is not None:
            return int(native_cli_cb(json.dumps(args)))
        print(f"[dastyab] Native CLI subcommand queued: dastyab {' '.join(args)}")
        return 0

    if base in ("pip", "pip3"):
        return dastyab_pip.main(args)

    if base in ("python3", "python"):
        return _run_python(args)

    if base.endswith(".py"):
        return _run_python([prog] + args)

    if base == "help":
        _print_help()
        return 0
    if base == "clear":
        _shim.emit_event("CLEAR_TERMINAL", {})
        return 0
    if base == "pwd":
        print(get_cwd())
        return 0
    if base == "cd":
        dest = _resolve_path(args[0]) if args else os.path.expanduser("~")
        if not os.path.isdir(dest):
            print(f"cd: {args[0] if args else dest}: No such directory")
            return 1
        _CWD = dest
        os.environ["PWD"] = dest
        os.chdir(dest)
        return 0
    if base == "ls":
        return _cmd_ls(args)
    if base == "cat":
        return _cmd_cat(args)
    if base == "head":
        return _cmd_head_tail(args, tail=False)
    if base == "tail":
        return _cmd_head_tail(args, tail=True)
    if base == "grep":
        return _cmd_grep(args)
    if base == "wc":
        return _cmd_wc(args)
    if base == "echo":
        print(" ".join(args))
        return 0
    if base == "env":
        for k in sorted(os.environ.keys()):
            print(f"{k}={os.environ[k]}")
        return 0
    if base == "export":
        for item in args:
            if "=" in item:
                k, v = item.split("=", 1)
                os.environ[k] = v
        return 0
    if base == "unset":
        for k in args:
            os.environ.pop(k, None)
        return 0
    if base == "mkdir":
        return _cmd_mkdir(args)
    if base == "rm":
        return _cmd_rm(args)
    if base == "touch":
        for a in args:
            p = _resolve_path(a)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "a").close()
        return 0
    if base == "cp" and len(args) >= 2:
        src, dst = _resolve_path(args[0]), _resolve_path(args[1])
        if os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
        return 0
    if base == "mv" and len(args) >= 2:
        shutil.move(_resolve_path(args[0]), _resolve_path(args[1]))
        return 0
    if base == "which":
        rc = 0
        for name in args:
            if name in ("python3", "python"):
                print(sys.executable or "/usr/bin/python3 (embedded CPython 3.11)")
            elif name in ("pip", "pip3"):
                print(f"~/.dastyab/bin/pip (dastyab_pip -> {dastyab_pip.site_packages_dir()})")
            elif name == "dastyab":
                print(os.path.join(os.environ.get("DASTYAB_NATIVE_DIR", "/app/bin"), "libdastyab.so"))
            elif name in ("dastyab-flow.py", "dastyab-aistudio.py"):
                print(os.path.join(os.path.dirname(__file__), name.replace("-", "_")))
            else:
                found = shutil.which(name)
                if found:
                    print(found)
                else:
                    print(f"{name} not found")
                    rc = 1
        return rc
    if base == "uname":
        if "-a" in args:
            print(f"Linux {platform.node() or 'dastyab-android'} {platform.release()} {platform.machine()} Android-CPython/{platform.python_version()}")
        else:
            print("Linux (Android DastYab CPython Core)")
        return 0
    if base == "whoami":
        print(os.environ.get("USER", "dastyab"))
        return 0
    if base == "id":
        print(f"uid={os.getuid()}({os.environ.get('USER', 'dastyab')}) gid={os.getgid()}")
        return 0
    if base == "date":
        print(time.strftime("%a %b %d %H:%M:%S %Z %Y"))
        return 0

    print(f"sh: {prog}: command not found (type 'help' for supported Linux/Python commands)")
    return 127


def _run_python(args):
    dastyab_pip.ensure_site_packages_on_path()
    if not args or args[0] in ("--version", "-V"):
        print(f"Python {platform.python_version()}")
        return 0
    if args[0] in ("-h", "--help"):
        print("Usage: python3 [--version | -c <code > | -m <module> | <script.py>] [args...]")
        return 0
    if args[0] == "-c":
        if len(args) < 2:
            print("python3: option -c requires an argument")
            return 2
        code = args[1]
        saved_argv = sys.argv
        sys.argv = ["-c"] + args[2:]
        try:
            ns = {"__name__": "__main__", "__builtins__": __builtins__}
            exec(compile(code, "<string>", "exec"), ns)
            return 0
        finally:
            sys.argv = saved_argv
    if args[0] == "-m":
        if len(args) < 2:
            print("python3: option -m requires a module name")
            return 2
        mod = args[1]
        if mod in ("pip", "pip3"):
            return dastyab_pip.main(args[2:])
        saved_argv = sys.argv
        sys.argv = [mod] + args[2:]
        try:
            runpy.run_module(mod, run_name="__main__", alter_sys=True)
            return 0
        finally:
            sys.argv = saved_argv

    script_path = _resolve_path(args[0])
    if not os.path.isfile(script_path):
        # Allow running packaged python modules directly by script name
        bundled = os.path.join(os.path.dirname(__file__), os.path.basename(args[0]).replace("-", "_"))
        if os.path.isfile(bundled):
            script_path = bundled
        else:
            print(f"python3: can't open file '{args[0]}': No such file")
            return 2
    saved_argv = sys.argv
    sys.argv = [script_path] + args[1:]
    try:
        runpy.run_path(script_path, run_name="__main__")
        return 0
    finally:
        sys.argv = saved_argv


def _cmd_ls(args):
    long_fmt = False
    show_all = False
    targets = []
    for a in args:
        if a.startswith("-"):
            if "l" in a:
                long_fmt = True
            if "a" in a:
                show_all = True
        else:
            targets.append(a)
    if not targets:
        targets = ["."]
    rc = 0
    for t in targets:
        p = _resolve_path(t)
        if not os.path.exists(p):
            print(f"ls: cannot access '{t}': No such file or directory")
            rc = 1
            continue
        if os.path.isfile(p):
            print(os.path.basename(p))
            continue
        entries = sorted(os.listdir(p))
        if not show_all:
            entries = [e for e in entries if not e.startswith(".")]
        for e in entries:
            ep = os.path.join(p, e)
            if long_fmt:
                try:
                    st = os.stat(ep)
                    kind = "d" if os.path.isdir(ep) else "-"
                    ts = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
                    print(f"{kind}rw-r--r-- {st.st_size:8d} {ts} {e}")
                except OSError:
                    print(f"?---------        0 ? {e}")
            else:
                suffix = "/" if os.path.isdir(ep) else ""
                print(f"{e}{suffix}")
    return rc


def _cmd_cat(args):
    if not args:
        print("cat: missing file operand")
        return 1
    rc = 0
    for a in args:
        p = _resolve_path(a)
        if not os.path.isfile(p):
            print(f"cat: {a}: No such file")
            rc = 1
            continue
        with open(p, errors="replace") as fh:
            sys.stdout.write(fh.read())
    return rc


def _cmd_head_tail(args, tail=False):
    n = 10
    files = []
    i = 0
    while i < len(args):
        if args[i] == "-n" and i + 1 < len(args):
            n = max(1, int(args[i + 1]))
            i += 2
        else:
            files.append(args[i])
            i += 1
    if not files:
        return 1
    p = _resolve_path(files[0])
    if not os.path.isfile(p):
        print(f"No such file: {files[0]}")
        return 1
    with open(p, errors="replace") as fh:
        lines = fh.readlines()
    picked = lines[-n:] if tail else lines[:n]
    sys.stdout.writelines(picked)
    return 0


def _cmd_grep(args):
    if len(args) < 2:
        print("Usage: grep <pattern> <file>")
        return 2
    pat, target = args[0], _resolve_path(args[1])
    if not os.path.isfile(target):
        print(f"grep: {args[1]}: No such file")
        return 2
    matched = False
    with open(target, errors="replace") as fh:
        for line in fh:
            if pat in line:
                sys.stdout.write(line)
                matched = True
    return 0 if matched else 1


def _cmd_wc(args):
    rc = 0
    for a in args:
        if a.startswith("-"):
            continue
        p = _resolve_path(a)
        if not os.path.isfile(p):
            print(f"wc: {a}: No such file")
            rc = 1
            continue
        with open(p, "rb") as fh:
            data = fh.read()
        nl = data.count(b"\n")
        print(f" {nl} {len(data.split())} {len(data)} {a}")
    return rc


def _cmd_mkdir(args):
    for a in args:
        if a == "-p":
            continue
        os.makedirs(_resolve_path(a), exist_ok=True)
    return 0


def _cmd_rm(args):
    recursive = any("r" in a for a in args if a.startswith("-"))
    force = any("f" in a for a in args if a.startswith("-"))
    rc = 0
    for a in args:
        if a.startswith("-"):
            continue
        p = _resolve_path(a)
        if not os.path.exists(p):
            if not force:
                print(f"rm: cannot remove '{a}': No such file")
                rc = 1
            continue
        if os.path.isdir(p):
            if recursive:
                shutil.rmtree(p)
            else:
                print(f"rm: cannot remove '{a}': Is a directory")
                rc = 1
        else:
            os.remove(p)
    return rc


def _print_help():
    print(
        f"DastYab Terminal Mode — Embedded CPython {platform.python_version()} (Linux-Compatible Core)\n"
        "\n"
        "Google Flow & AI Studio (exact Linux Python algorithms):\n"
        "  dastyab flow best [--try N] [--country XX]     Scan routes + benchmark pool\n"
        "  dastyab flow ingest <file> [--entry URI|FILE]  Import ALL configs from .txt/any ext\n"
        "  dastyab flow build-pool <file> [--entry ...]   Build verified pool from .txt/config\n"
        "  dastyab flow start [idx] [--country XX]        Verify gates + open Flow in browser\n"
        "  dastyab flow status                            Live egress IP, geo & gate check\n"
        "  dastyab flow verify                            Re-probe saved routes\n"
        "  dastyab flow countries                         List all 151 Google Flow countries\n"
        "  dastyab aistudio ingest <file> [--entry ...]   Import ALL configs from .txt/any ext\n"
        "  dastyab aistudio build-pool <file> [--entry]   Build verified AI Studio pool\n"
        "  dastyab aistudio verify                        Check AI Studio routes + pool\n"
        "  dastyab aistudio start                         Start AI Studio tunnel + browser\n"
        "\n"
        "Python Package Manager (pip -> ~/.dastyab/site-packages):\n"
        "  pip list                                    List bundled & user-installed packages\n"
        "  pip check                                   Verify core & recommended imports\n"
        "  pip install --recommended                   Install all recommended pure-Python pkgs\n"
        "  pip install <pkg> [<pkg2>...]               Install pure-Python packages from PyPI\n"
        "  pip install -r <requirements.txt>           Install packages from requirements file\n"
        "  pip show <pkg>  |  pip uninstall [-y] <pkg> Inspect or remove user packages\n"
        "\n"
        "Python & Native CLI:\n"
        "  python3 --version                           Show embedded CPython version\n"
        "  python3 -m pip <args>                       Invoke runtime pip via python3 -m\n"
        "  python3 -c \"<code...>\"                      Execute Python 3 code directly\n"
        "  python3 <script.py> [args]                  Run any .py script inside profile\n"
        "  dastyab <subcommand>                        Run native Rust dastyab CLI\n"
        "\n"
        "Linux Shell Built-ins:\n"
        "  pwd, cd, ls [-la], cat, head, tail, grep, wc, echo, env, export, mkdir, rm, clear"
    )
