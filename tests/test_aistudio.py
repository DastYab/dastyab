#!/usr/bin/env python3
"""Foundry-lite tests for the AI Studio bridge helper.

Run with:  python3 -m pytest tests/test_aistudio.py -q

These cover the regressions that made `dastyab aistudio start` unusable:

  * selecting a nekoray wrapper as if it were an xray core
  * binding only pool[0], so one dead node broke the whole command
  * `build-pool` importing from a hardcoded /tmp path
  * `build-pool` writing an empty pool over a working one
  * `verify` printing stale stored egress as if it were live
"""
import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name="dastyab-aistudio.py", alias="ai"):
    path = os.path.join(ROOT, name)
    spec = importlib.util.spec_from_file_location(alias, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def ai():
    return load()


@pytest.fixture(scope="module")
def tfv():
    return load("test_fresh_vless.py", "tfv")


# --- parsing ---------------------------------------------------------------

def test_parse_vless_keeps_unknown_keys(ai):
    u = ai.parse_vless(
        "vless://uuid-1@1.2.3.4:443?security=reality&type=tcp"
        "&sni=a.example&pbk=KEY&fp=firefox&flow=xtls-rprx-vision"
    )
    assert u["addr"] == "1.2.3.4"
    assert u["port"] == 443
    assert u["q"]["security"] == "reality"
    assert u["q"]["sni"] == "a.example"


def test_parse_vless_strips_fragment_label(ai):
    u = ai.parse_vless("vless://u@h.example:1?security=none#my%20node")
    assert u["addr"] == "h.example"
    assert "#" not in json.dumps(u)


@pytest.mark.parametrize("bad", [
    "garbage",
    "",
    "vless://@1.2.3.4:443?security=none",       # empty uuid
    "vless://uuid@host:notaport?security=none",  # non-numeric port
])
def test_parse_vless_rejects_malformed(ai, bad):
    assert ai.parse_vless(bad) is None


def test_parse_vless_agrees_with_standalone_parser(ai, tfv):
    line = ("vless://uid@host.example:8443?security=tls&type=ws"
            "&path=%2Fws&host=cdn.example")
    assert ai.parse_vless(line) == tfv.parse_vless(line)


# --- core selection --------------------------------------------------------

def test_rejects_nekoray_wrapper(ai):
    """`nekoray_core version` prints 'Xray: ... NekoRay: ...' but cannot run -c."""
    if not os.path.exists("/opt/nekoray/nekoray_core"):
        pytest.skip("nekoray not installed")
    assert ai._is_real_xray("/opt/nekoray/nekoray_core") is False


def test_rejects_nekobox():
    """`nekobox_core` is sing-box: different CLI, must not be selected."""
    ai = load()
    if not os.path.exists("/opt/nekoray/nekobox_core"):
        pytest.skip("nekobox not installed")
    assert ai._is_real_xray("/opt/nekoray/nekobox_core") is False


def test_rejects_missing_and_non_xray(ai):
    assert ai._is_real_xray("/nonexistent/xray") is False
    assert ai._is_real_xray("/bin/true") is False


def test_accepts_real_core_if_present(ai):
    try:
        core = ai.find_xray()
    except SystemExit:
        pytest.skip("no xray core installed")
    assert ai._is_real_xray(core) is True


# --- build-pool must not destroy state -------------------------------------

def test_build_pool_keeps_pool_when_batch_is_dead(ai, tmp_path, monkeypatch):
    pool = tmp_path / "fresh_vless.json"
    pool.write_text('[{"addr": "keep.me", "port": 443, "uuid": "u", "q": {}}]')
    monkeypatch.setattr(ai, "POOL", str(pool))

    uris = tmp_path / "cards.txt"
    uris.write_text("vless://dead-0000@192.0.2.1:443?security=none&type=tcp\n")
    # 192.0.2.1 is TEST-NET-1: guaranteed unroutable, so this probes as dead.
    with pytest.raises(SystemExit) as e:
        ai.pop_pool(str(uris), want=1, probe_port=10985)

    # Two environments reach this assertion:
    #   * a box with an xray core -> every probe is dead, so pop_pool reports
    #     that the pool was kept "unchanged";
    #   * a box without one (CI) -> find_xray aborts before probing. The
    #     guarantee under test is identical: a failed rebuild never touches
    #     the pool. Demanding the "unchanged" wording here made this test fail
    #     on every CI runner, which ships no xray.
    msg = str(e.value)
    assert "unchanged" in msg or "No xray core found" in msg, msg

    survived = json.loads(pool.read_text())
    assert survived[0]["addr"] == "keep.me", "a dead batch must not clobber the pool"


def test_build_pool_rejects_missing_file(ai, tmp_path):
    with pytest.raises(SystemExit):
        ai.pop_pool(str(tmp_path / "nope.txt"))


def test_build_pool_rejects_file_without_uris(ai, tmp_path):
    f = tmp_path / "junk.txt"
    f.write_text("not a uri\nstill not one\n")
    with pytest.raises(SystemExit) as e:
        ai.pop_pool(str(f))
    assert "No vless://" in str(e.value)


def test_build_pool_does_not_import_from_tmp(ai):
    """The old implementation did sys.path.insert(0, '/tmp') + import."""
    src = open(os.path.join(ROOT, "dastyab-aistudio.py")).read()
    assert 'sys.path.insert(0,"/tmp")\n    import test_fresh_vless' not in src
    assert "import test_fresh_vless as tfv" not in src


# --- start() must walk the pool --------------------------------------------

def test_start_walks_pool_and_skips_dead(ai, tmp_path, monkeypatch):
    pool = [{"addr": "dead1", "port": 1, "uuid": "u", "q": {}},
            {"addr": "dead2", "port": 2, "uuid": "u", "q": {}},
            {"addr": "live", "port": 3, "uuid": "u", "q": {}}]
    (tmp_path / "fresh_vless.json").write_text(json.dumps(pool))
    monkeypatch.setattr(ai, "POOL", str(tmp_path / "fresh_vless.json"))
    monkeypatch.setattr(ai, "is_running", lambda: False)
    monkeypatch.setattr(ai, "launch_browser", lambda: None)
    monkeypatch.setattr(ai, "stop", lambda quiet=False: None)
    monkeypatch.setattr(ai, "_bring_up",
                        lambda srv, announce=True: "203.0.113.9" if srv["addr"] == "live" else None)

    ok, idx = ai.start()
    assert ok is True
    assert idx == 2, "start must advance past dead entries to the live one"


def test_start_reports_failure_when_all_dead(ai, tmp_path, monkeypatch, capsys):
    pool = [{"addr": "d1", "port": 1, "uuid": "u", "q": {}}]
    (tmp_path / "fresh_vless.json").write_text(json.dumps(pool))
    monkeypatch.setattr(ai, "POOL", str(tmp_path / "fresh_vless.json"))
    monkeypatch.setattr(ai, "is_running", lambda: False)
    monkeypatch.setattr(ai, "launch_browser", lambda: None)
    monkeypatch.setattr(ai, "stop", lambda quiet=False: None)
    monkeypatch.setattr(ai, "_bring_up", lambda srv, announce=True: None)

    ok, idx = ai.start()
    assert (ok, idx) == (False, None)
    assert "every node in the pool is dead" in capsys.readouterr().err


def test_start_does_not_announce_a_dead_node(ai, tmp_path, monkeypatch, capsys):
    """'Tunnel started' must never be printed for a node that cannot pass traffic."""
    pool = [{"addr": "dead", "port": 1, "uuid": "u", "q": {}}]
    (tmp_path / "fresh_vless.json").write_text(json.dumps(pool))
    monkeypatch.setattr(ai, "POOL", str(tmp_path / "fresh_vless.json"))
    monkeypatch.setattr(ai, "is_running", lambda: False)
    monkeypatch.setattr(ai, "launch_browser", lambda: None)
    monkeypatch.setattr(ai, "stop", lambda quiet=False: None)
    monkeypatch.setattr(ai, "probe_egress", lambda timeout=20: None)
    monkeypatch.setattr(ai, "build_cfg", lambda srv: {"inbounds": [{}], "outbounds": [{}]})
    monkeypatch.setattr(ai, "find_xray", lambda: "/bin/true")
    monkeypatch.setattr(ai.os, "remove", lambda p: None)

    class FakeProc:
        pid = 1
        def poll(self):
            return None  # still alive: the SOCKS port check is what we exercise
        def kill(self):
            pass
        def wait(self, timeout=None):
            pass

    # Socket connect must succeed so _bring_up proceeds to the egress probe.
    class FakeSock:
        def __init__(self, *a, **k):
            pass
        def settimeout(self, t):
            pass
        def connect(self, addr):
            pass
        def close(self):
            pass

    monkeypatch.setattr(ai.subprocess, "Popen", lambda *a, **k: FakeProc())
    monkeypatch.setattr(ai.socket, "socket", FakeSock)
    ai.start()
    out = capsys.readouterr().out
    assert "Tunnel started" not in out


# --- verify() must report reality, not the stored snapshot ------------------

def test_verify_probes_instead_of_printing_stored_egress(ai, tmp_path, monkeypatch, capsys):
    pool = [{"addr": "n1", "port": 1, "uuid": "u", "q": {}, "egress": "10.0.0.1"},
            {"addr": "n2", "port": 2, "uuid": "u", "q": {}, "egress": "10.0.0.2"}]
    p = tmp_path / "fresh_vless.json"
    p.write_text(json.dumps(pool))
    monkeypatch.setattr(ai, "POOL", str(p))
    monkeypatch.setattr(ai, "is_running", lambda: False)
    monkeypatch.setattr(ai, "stop", lambda quiet=False: None)
    monkeypatch.setattr(ai, "_bring_up",
                        lambda srv, announce=True: None if srv["addr"] == "n1" else "203.0.113.7")

    ai.verify()
    out = capsys.readouterr().out
    # Index labels are positional, so the dead entry must be reported at
    # its own index with a DEAD mark, not silently skipped.
    assert "[0]" in out and "DEAD" in out
    assert "DEAD" in out and "203.0.113.7" in out
    assert "1/2 reachable" in out
    # the stale stored value must not be presented as current
    assert "10.0.0.1" not in out


# --- start() on a live tunnel must be a success, not a failure ---------------

def test_start_succeeds_when_tunnel_already_running(ai, monkeypatch):
    """`start` twice in a row must not exit non-zero.

    The CLI turns a non-zero exit into "Aistudio failed". Returning False here
    meant the second `dastyab aistudio start` printed a failure immediately
    after successfully opening the browser on the running tunnel.
    """
    monkeypatch.setattr(ai, "is_running", lambda: True)
    monkeypatch.setattr(ai, "launch_browser", lambda: None)
    ok, idx = ai.start()
    assert ok is True
    assert idx is None


# --- the watchdog must survive a failed rotation ---------------------------

def test_watch_survives_systemexit_during_rotation(ai, tmp_path, monkeypatch):
    """A dead pool during rotation must not kill the watchdog.

    `start` signals an unusable core/pool with SystemExit, which derives from
    BaseException — so `except Exception` let it escape and terminated the
    watchdog on its first rotation.
    """
    pool = [{"addr": "a", "port": 1, "uuid": "u", "q": {}},
            {"addr": "b", "port": 2, "uuid": "u", "q": {}}]
    (tmp_path / "fresh_vless.json").write_text(json.dumps(pool))
    monkeypatch.setattr(ai, "POOL", str(tmp_path / "fresh_vless.json"))
    monkeypatch.setattr(ai, "stop", lambda quiet=False: None)
    # The tunnel never comes back: every probe fails, so rotation keeps going.
    monkeypatch.setattr(ai, "probe_egress", lambda *a, **k: None)

    calls = []

    def fake_start(idx):
        calls.append(idx)
        raise SystemExit("[aistudio] No xray core found")

    monkeypatch.setattr(ai, "start", fake_start)

    class Sentinel(Exception):
        pass

    ticks = {"n": 0}

    def fake_sleep(_seconds):
        ticks["n"] += 1
        if ticks["n"] > 12:
            raise Sentinel()

    monkeypatch.setattr(ai.time, "sleep", fake_sleep)
    with pytest.raises(Sentinel):
        ai.watch(interval=0, max_fail=2)

    # Each rotation tries every other entry: two attempts per round.
    assert len(calls) >= 2, f"watchdog stopped after {len(calls)} attempt(s)"


# --- argv handling ----------------------------------------------------------

def test_build_pool_without_argument_explains_instead_of_indexerror(ai, monkeypatch):
    """`build-pool` with no file is a usage error, not a traceback."""
    import runpy
    monkeypatch.setattr(ai.sys, "argv", ["dastyab-aistudio.py", "build-pool"])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(os.path.join(ROOT, "dastyab-aistudio.py"), run_name="__main__")
    assert "needs a file" in str(e.value)
    assert "IndexError" not in str(e.value)


def test_unknown_action_exits_non_zero(ai, monkeypatch):
    """A typo must not print the docstring and exit 0 (which looks like success)."""
    import runpy
    monkeypatch.setattr(ai.sys, "argv", ["dastyab-aistudio.py", "strat"])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(os.path.join(ROOT, "dastyab-aistudio.py"), run_name="__main__")
    assert "Unknown action" in str(e.value)


def test_dead_pool_advice_uses_the_cli_not_a_loose_file(ai, tmp_path, monkeypatch, capsys):
    """The advice must work on an installed system, where no .py file is on disk."""
    p = tmp_path / "fresh_vless.json"
    p.write_text(json.dumps([{"addr": "n", "port": 1, "uuid": "u", "q": {}}]))
    monkeypatch.setattr(ai, "POOL", str(p))
    monkeypatch.setattr(ai, "is_running", lambda: False)
    monkeypatch.setattr(ai, "stop", lambda quiet=False: None)
    monkeypatch.setattr(ai, "_bring_up", lambda srv, announce=True: None)

    ai.verify()
    out = capsys.readouterr().out
    assert "dastyab aistudio build-pool" in out
    assert "dastyab-aistudio.py build-pool" not in out


# --- Lion brutal multi-layer extensions -----------------------------------

def test_lion_multihop_and_tls_fragment_config(ai):
    hops = [
        {"proto": "trojan", "addr": "203.0.113.10", "port": 443,
         "password": "pw1", "q": {"security": "tls", "type": "tcp"}},
        {"proto": "vless", "addr": "198.51.100.20", "port": 443,
         "uuid": "uid-r1", "q": {"security": "none", "type": "tcp"}},
        {"proto": "vless", "addr": "192.0.2.30", "port": 443,
         "uuid": "uid-en", "q": {"security": "tls", "type": "ws"}},
    ]
    cfg = ai.build_lion_cfg(hops, port=10855, fragment=True)
    obs = cfg["outbounds"]
    tags = [o["tag"] for o in obs]
    assert tags[:3] == ["exit", "relay-1", "entry"]
    assert "frag-dialer" in tags
    assert obs[0]["sockopt"]["dialerProxy"] == "relay-1"
    assert obs[1]["sockopt"]["dialerProxy"] == "entry"
    assert obs[2]["sockopt"]["dialerProxy"] == "frag-dialer"
    frag_ob = next(o for o in obs if o["tag"] == "frag-dialer")
    assert frag_ob["settings"]["fragment"]["packets"] == "tlshello"


def test_lion_parse_multi_protocol_uris(ai):
    import base64
    vm = base64.b64encode(json.dumps({
        "add": "2.2.2.2", "port": 443, "id": "vm-id", "net": "ws", "tls": "tls"
    }).encode()).decode()
    assert ai.parse_node_uri(f"vmess://{vm}")["proto"] == "vmess"
    assert ai.parse_node_uri("trojan://pw@3.3.3.3:443?sni=a.b")["proto"] == "trojan"
    ss_cred = base64.b64encode(b"aes-256-gcm:secret").decode()
    assert ai.parse_node_uri(f"ss://{ss_cred}@4.4.4.4:8388")["proto"] == "ss"
    assert ai.parse_node_uri("socks5://127.0.0.1:9050")["local"] is True


def test_lion_asn_reputation_and_strict_warp_rejection(ai, monkeypatch):
    rep_res, s_res = ai.classify_asn_reputation("Deutsche Telekom AG", False, False, False)
    rep_dc, s_dc = ai.classify_asn_reputation("Hetzner Online GmbH", True, True, False)
    rep_warp, s_warp = ai.classify_asn_reputation("Cloudflare", False, False, True)
    assert rep_res == "residential-isp" and s_res > s_dc
    assert rep_dc == "hosting-high-risk"
    assert rep_warp == "warp-or-tor" and s_warp < 0

    def fake_curl(args, timeout=15):
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "104.28.1.5"})()
        if "cdn-cgi/trace" in url:
            return type("R", (), {"stdout": "ip=104.28.1.5\nloc=DE\nwarp=on\n"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "Germany", "countryCode": "DE",
                 "isp": "Cloudflare", "org": "Cloudflare", "proxy": False, "hosting": False})})()
        return type("R", (), {"stdout": "\n__DYB_META__:200:" + url})()

    monkeypatch.setattr(ai, "_curl", fake_curl)
    g = ai.probe_lion_gates(strict=True)
    assert g["verdict"] is False
    assert "WARP egress rejected" in g["reason"]


def test_lion_hardened_browser_args_and_isolated_blacklist(ai, tmp_path, monkeypatch):
    args = ai.hardened_browser_args("/usr/bin/chrome", "/tmp/p", "https://aistudio.google.com/", "DE")
    joined = " ".join(args)
    assert "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" in joined
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in joined
    assert "--lang=de-DE" in joined

    bl = tmp_path / "lion_blacklist.json"
    monkeypatch.setattr(ai, "BLACKLIST_PATH", str(bl))
    ai._remember_blocked_exit("vless:9.9.9.9:443")
    assert ai._is_blacklisted("vless:9.9.9.9:443") is True


def test_lion_unpacks_npv_ovpn_wireguard_and_clash_yaml(ai):
    vless = "vless://11111111-1111-1111-1111-111111111111@203.0.113.44:443?security=tls"
    npv_bytes = b"\x00\x01NPVT\x02" + vless.encode() + b"\x00\xff"
    npv_nodes = ai.parse_config_file_bytes("free.npvt", npv_bytes)
    assert any(n["addr"] == "203.0.113.44" and n["proto"] == "vless" for n in npv_nodes)

    wg_conf = (
        b"[Interface]\nPrivateKey = privkey123=\nAddress = 10.7.0.2/32\nMTU = 1280\n"
        b"[Peer]\nPublicKey = pubkey456=\nEndpoint = 198.51.100.88:51820\n"
    )
    wg_nodes = ai.parse_config_file_bytes("warp.conf", wg_conf)
    assert len(wg_nodes) == 1
    assert wg_nodes[0]["proto"] == "wireguard"
    assert wg_nodes[0]["q"]["publickey"] == "pubkey456="

    ovpn = b"client\ndev tun\nhttp-proxy 192.0.2.9 8080\n"
    ovpn_nodes = ai.parse_config_file_bytes("exit.ovpn", ovpn)
    assert any(n["proto"] == "http" and n["port"] == 8080 for n in ovpn_nodes)

    clash = b"proxies:\n  - {name: n1, type: hy2, server: 198.51.100.77, port: 443, password: pw}\n"
    clash_nodes = ai.parse_config_file_bytes("clash.yaml", clash)
    assert any(n["proto"] == "hy2" and n["addr"] == "198.51.100.77" for n in clash_nodes)


def test_lion_eight_hop_and_wireguard_outbound(ai):
    wg_hop = {
        "proto": "wireguard", "addr": "198.51.100.88", "port": 51820,
        "secret": "priv", "q": {"publickey": "pub", "address": "10.7.0.2/32", "mtu": "1280"},
    }
    chain = [
        ai.mutate_fp({"proto": "vless", "addr": f"203.0.113.{i}", "port": 443,
                      "uuid": f"u{i}", "q": {"security": "tls"}}, "firefox")
        for i in range(1, 8)
    ] + [wg_hop]
    cfg = ai.build_lion_cfg(chain, port=10855, fragment=True)
    obs = cfg["outbounds"]
    tags = [o["tag"] for o in obs]
    assert len(chain) == 8
    assert tags[:8] == ["exit", "relay-1", "relay-2", "relay-3", "relay-4", "relay-5", "relay-6", "entry"]
    assert obs[0]["sockopt"]["dialerProxy"] == "relay-1"
    assert obs[6]["sockopt"]["dialerProxy"] == "entry"
    assert obs[7]["protocol"] == "wireguard"
    assert obs[7]["settings"]["secretKey"] == "priv"
    assert obs[0]["streamSettings"]["tlsSettings"]["fingerprint"] == "firefox"


def test_telegram_619_txt_drop_and_non_proxy_url_filtering(ai):
    header = (
        "داخل فایل 619 عدد سرور از تمام کشورها هست ری اکشن فراموش نکنید\n"
        "مخابرات و تمام اپراتورها\n"
        "بااین برنامه اجرا کنید PattNG (https://t.me/proxy_kafee/48582?single)👉👉 کیلیک کنید\n"
        "#ویتوری #v2box\n#pattNG\n@proxy_kafee\n"
        "PattNG 2.3.10-P62\nآپدیت جدید کلاینت\n"
        "امکان chain کردن پروکسی های دیگر به کانفیگ اتر (وارپ):\n"
        "🔗لینک دانلود نسخه جدید\n"
        "https://github.com/patterniha/PattNG/releases/tag/2.3.8-P50\n"
        "🔺آموزش fragment+fingerprint (https://t.me/proxy_kafee/46097)\n"
        "@proxy_kafee\n"
    )
    servers = []
    for i in range(619):
        if i % 3 == 0:
            servers.append(f"vless://11111111-1111-1111-1111-{i:012d}@198.51.100.{(i % 250) + 1}:{443 + (i % 50)}?security=tls&type=ws#DE_{i}")
        elif i % 3 == 1:
            servers.append(f"trojan://pw{i}@203.0.113.{(i % 250) + 1}:{1000 + i}?sni=cdn.example#US_{i}")
        else:
            servers.append(f"hy2://pw{i}@192.0.2.{(i % 250) + 1}:{2000 + i}?sni=hy.example#NL_{i}")
    payload = (header + "\n".join(servers)).encode("utf-8")
    nodes = ai.parse_config_file_bytes("servers_619.txt", payload)
    assert len(nodes) == 619
    assert not any(n["addr"] in ("t.me", "github.com") for n in nodes)


def test_all_extensions_utf16_clash_block_xray_json_and_nested_b64(ai, tmp_path, monkeypatch):
    import base64
    block_yaml = (
        "proxies:\n"
        "  - name: block-vless\n"
        "    type: vless\n"
        "    server: 198.51.100.51\n"
        "    port: 443\n"
        "    uuid: uid-block\n"
        "    tls: true\n"
        "    network: ws\n"
        "    servername: sni.example\n"
        "    client-fingerprint: firefox\n"
    ).encode("utf-16-le")
    nodes_yaml = ai.parse_config_file_bytes("pack.mihomo", b"\xff\xfe" + block_yaml)
    assert len(nodes_yaml) == 1
    assert nodes_yaml[0]["addr"] == "198.51.100.51"
    assert nodes_yaml[0]["q"]["fp"] == "firefox"

    xray_json = json.dumps({
        "outbounds": [
            {"protocol": "vless", "settings": {"vnext": [{"address": "203.0.113.52", "port": 8443, "users": [{"id": "xr-1"}]}]},
             "streamSettings": {"security": "tls", "network": "grpc", "tlsSettings": {"serverName": "g.example"}}},
            {"protocol": "freedom", "tag": "direct"},
        ]
    }).encode()
    nodes_json = ai.parse_config_file_bytes("cfg.sbox", xray_json)
    assert len(nodes_json) == 1 and nodes_json[0]["addr"] == "203.0.113.52"

    inner = "vless://22222222-2222-2222-2222-222222222222@192.0.2.53:443?security=tls\n"
    nested = base64.b64encode(base64.b64encode(inner.encode())).decode().encode()
    nodes_b64 = ai.parse_config_file_bytes("sub.b64", nested)
    assert len(nodes_b64) == 1 and nodes_b64[0]["addr"] == "192.0.2.53"

    imp = tmp_path / "imports"
    imp.mkdir()
    (imp / "robots.txt").write_text("http://203.0.113.99:8080\n")
    (imp / "nodes.list").write_text("trojan://pw@203.0.113.55:443?sni=x.example\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    # Force _paths() lookup under tmp_path if using gather_multi_format_candidates
    prof = tmp_path / ".dastyab" / "profiles" / "default" / "imports"
    prof.mkdir(parents=True)
    (prof / "robots.txt").write_text("http://203.0.113.99:8080\n")
    (prof / "nodes.awg").write_text("[Interface]\nPrivateKey = p1=\n[Peer]\nPublicKey = k1=\nEndpoint = 198.51.100.70:51820\n")
    gathered = ai.gather_multi_format_candidates()
    addrs = {n["addr"] for n in gathered}
    assert "198.51.100.70" in addrs
    assert "203.0.113.99" not in addrs


def test_pattng_warp_entry_exit_chain_and_android_parity(ai):
    warp_entry = ai.parse_node_uri("warp://privKey%3D@162.159.192.1:2408?publickey=bmXOC%2B1%3D&address=172.16.0.2%2F32")
    exit_node = ai.parse_node_uri("vless://33333333-3333-3333-3333-333333333333@203.0.113.10:443?security=tls&type=ws")
    cfg = ai.build_entry_exit_chain(warp_entry, exit_node, port=10855, fragment=True, fp="safari")
    obs = cfg["outbounds"]
    assert obs[0]["tag"] == "exit"
    assert obs[0]["sockopt"]["dialerProxy"] == "entry"
    assert obs[0]["streamSettings"]["tlsSettings"]["fingerprint"] == "safari"
    assert obs[1]["tag"] == "entry"
    assert obs[1]["protocol"] == "wireguard"

    android_py = os.path.join(ROOT, "android", "app", "src", "main", "python")
    if android_py not in sys.path:
        sys.path.insert(0, android_py)
    a_ai = load(os.path.join("android", "app", "src", "main", "python", "dastyab_aistudio.py"), "android_ai")
    a_nodes = a_ai.parse_config_file_bytes("drop.txt", b"Header\n" + "\n".join(
        f"vless://44444444-4444-4444-4444-{i:012d}@198.51.100.{(i % 200) + 1}:{443 + i}?security=tls"
        for i in range(619)
    ).encode())
    assert len(a_nodes) == 619
    a_cfg = a_ai.build_entry_exit_chain(warp_entry, exit_node, port=10855, fragment=True, fp="chrome")
    assert a_cfg["outbounds"][0]["sockopt"]["dialerProxy"] == "entry"
    assert a_cfg["outbounds"][1]["protocol"] == "wireguard"


