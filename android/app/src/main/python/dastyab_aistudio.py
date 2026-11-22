#!/usr/bin/env python3
"""
dastyab aistudio — one-command clean-IP access to Google AI Studio.

USAGE:
  dastyab aistudio start [pool index]     -> start tunnel + open AI Studio
  dastyab aistudio watch [interval secs]  -> keep tunnel alive, rotating nodes
  dastyab aistudio verify                 -> check which server works + your clean IP
  dastyab aistudio stop                   -> stop the tunnel
  dastyab aistudio build-pool <uris.txt>  -> rebuild the pool from server cards
"""
import argparse
import base64
import glob
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.parse

import dastyab_android_shim as _shim

MULTI_FORMAT_EXTS = frozenset((
    ".npv", ".npvt", ".npvs", ".npv4",
    ".ovpn", ".ovpn2", ".openvpn",
    ".conf", ".wg", ".awg", ".amneziawg", ".warp",
    ".hc", ".ehi", ".custom", ".dark", ".hat", ".tls", ".nm",
    ".sbox", ".singbox", ".clash", ".mihomo", ".nekobox", ".hiddify",
    ".xray", ".v2ray", ".prox", ".rules", ".tunnels", ".vpn", ".profile",
    ".list", ".links", ".urls", ".nodes", ".servers", ".proxies",
    ".ini", ".cfg", ".json", ".jsonc", ".yaml", ".yml", ".toml",
    ".sub", ".txt", ".b64", ".base64",
))
NOISE_CONFIG_FILENAMES = frozenset((
    "robots.txt", "ads.txt", "humans.txt", "security.txt",
    "license.txt", "changelog.txt", "readme.txt",
))
WEB_NON_PROXY_HOSTS = frozenset((
    "t.me", "telegram.me", "telegram.dog", "github.com", "raw.githubusercontent.com",
    "gist.github.com", "cdn.jsdelivr.net", "youtube.com", "youtu.be",
    "twitter.com", "x.com", "instagram.com", "facebook.com", "google.com",
    "aistudio.google.com", "flow.google.com", "support.google.com",
    "cloudflare.com", "wikipedia.org", "reddit.com", "discord.gg", "discord.com",
))
MAX_CONFIG_FILE_BYTES = 8 * 1024 * 1024

SOCK = int(os.environ.get("DASTYAB_AISTUDIO_SOCKS", "10850"))
AISTUDIO_URL = "https://aistudio.google.com/"
ACCOUNTS_URL = "https://accounts.google.com/"
AISTUDIO_BLOCKED_COUNTRIES = frozenset({"IR", "CN", "RU", "KP", "BY", "SY", "CU", "SD", "AF", "HK", "MO", "MM", "SS", "XX"})
AISTUDIO_GATE_MARKERS = (
    "your region may not be supported",
    "not available in your country",
    "isn't available in your country",
    "available-regions",
    "unsupported-country",
    "/unsupported",
    "country is not supported",
    "region is not supported",
)
CHROME_CANDS = [
    "/opt/google/chrome/google-chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    "/usr/bin/microsoft-edge",
    "/usr/bin/brave-browser",
]


def _paths():
    home = os.path.expanduser("~")
    tmp = _shim.tmp_dir()
    return (
        home,
        os.path.join(home, ".dastyab", "profiles", "default", "fresh_vless.json"),
        os.path.join(tmp, "dastyab_aistudio.pid"),
        os.path.join(tmp, "dastyab_aistudio.json"),
        os.path.join(tmp, "dastyab_aistudio_idx"),
        os.path.join(tmp, "dastyab_aistudio_bridge.json"),
    )


def find_xray():
    """Locate an xray-compatible core (or raise SystemExit on desktop without xray)."""
    here = os.path.dirname(os.path.abspath(__file__))
    found = _shim.find_xray_android(extra_paths=(os.path.join(here, "xray"),))
    if found:
        return found
    raise SystemExit(
        "[aistudio] No xray core found. Install xray and put it on PATH, or set "
        "DASTYAB_XRAY=/path/to/xray"
    )


_XRAY_VERSION = None


def xray_supports_vision():
    """True if the resolved core is xray >= 1.7 (vision/XTLS support)."""
    global _XRAY_VERSION
    if _XRAY_VERSION is None:
        _XRAY_VERSION = ""
        try:
            out = subprocess.run(
                [find_xray(), "version"], capture_output=True, text=True, timeout=10
            ).stdout
            m = re.search(r"Xray\s+(\d+)\.(\d+)", out)
            if m:
                _XRAY_VERSION = f"{m.group(1)}.{m.group(2)}"
        except (SystemExit, OSError, subprocess.SubprocessError):
            _XRAY_VERSION = ""
    if not _XRAY_VERSION:
        return False
    major, minor = (int(x) for x in _XRAY_VERSION.split("."))
    return (major, minor) >= (1, 7)


def _build_outbound(server, tag="proxy"):
    q = server.get("q", {}) or {}
    addr = server["addr"]
    port = int(server["port"])
    proto = server.get("proto") or ("vless" if server.get("uuid") else "vless")

    if proto == "vless":
        out = {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{"address": addr, "port": port, "users": [{"id": server["uuid"], "encryption": "none"}]}]
            },
        }
        flow = q.get("flow")
        if flow and q.get("security", "none") in ("tls", "reality") and xray_supports_vision():
            out["settings"]["vnext"][0]["users"][0]["flow"] = flow
    elif proto == "vmess":
        out = {
            "tag": tag,
            "protocol": "vmess",
            "settings": {"vnext": [{"address": addr, "port": port, "users": [{"id": server["uuid"], "alterId": 0}]}]},
        }
    elif proto == "trojan":
        out = {
            "tag": tag,
            "protocol": "trojan",
            "settings": {"servers": [{"address": addr, "port": port, "password": server.get("password", "")}]},
        }
    elif proto in ("ss", "shadowsocks"):
        out = {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": addr, "port": port,
                    "method": server.get("method", "aes-256-gcm"),
                    "password": server.get("password", ""),
                }]
            },
        }
    elif proto == "wireguard":
        secret = server.get("secret") or server.get("private_key") or ""
        pubkey = q.get("publickey") or q.get("publicKey") or ""
        if not secret or not pubkey:
            return None
        wg_addrs = [x.strip() for x in (q.get("address") or "172.16.0.2/32").split(",") if x.strip()]
        try:
            mtu = int(q.get("mtu") or 1280)
        except ValueError:
            mtu = 1280
        return {
            "tag": tag,
            "protocol": "wireguard",
            "settings": {
                "secretKey": secret,
                "address": wg_addrs or ["172.16.0.2/32"],
                "mtu": mtu,
                "peers": [{"publicKey": pubkey, "endpoint": f"{addr}:{port}"}],
            },
        }
    elif proto == "socks":
        so = {"address": addr, "port": port}
        if server.get("user"):
            so["users"] = [{"user": server["user"], "pass": server.get("password", "")}]
        return {"tag": tag, "protocol": "socks", "settings": {"servers": [so]}}
    elif proto == "http":
        so = {"address": addr, "port": port}
        if server.get("user"):
            so["users"] = [{"user": server["user"], "pass": server.get("password", "")}]
        return {"tag": tag, "protocol": "http", "settings": {"servers": [so]}}
    else:
        return None

    sec = q.get("security", "none")
    net = q.get("type", "tcp")
    ss = {}
    if sec == "reality":
        ss.update(
            security="reality",
            realitySettings={
                "serverName": q.get("sni") or addr,
                "fingerprint": q.get("fp", "chrome"),
                "publicKey": q.get("pbk", ""),
                "shortId": q.get("sid", ""),
                "spiderX": q.get("spx", "/"),
            },
        )
    elif sec == "tls":
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": q.get("sni") or addr, "fingerprint": q.get("fp", "chrome")}
        if q.get("alpn"):
            ss["tlsSettings"]["alpn"] = [x for x in q["alpn"].split(",") if x]
        if q.get("pinSHA256"):
            ss["tlsSettings"]["pinnedPeerCertSha256"] = [q["pinSHA256"]]
    else:
        ss["security"] = "none"
    if net == "ws":
        ss["network"] = "ws"
        ss["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host") or q.get("sni") or addr}}
    elif net == "xhttp":
        ss["network"] = "xhttp"
        ss["xhttpSettings"] = {"path": q.get("path", "/"), "host": q.get("host") or q.get("sni") or addr, "mode": q.get("mode", "auto")}
    elif net == "grpc":
        ss["network"] = "grpc"
        ss["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    else:
        ss["network"] = "tcp"
    out["streamSettings"] = ss
    return out


def build_lion_cfg(nodes, port=SOCK, fragment=False):
    if not nodes:
        return None
    outbounds = []
    for idx, srv in enumerate(nodes):
        if idx == 0:
            tag = "exit"
        elif idx + 1 == len(nodes):
            tag = "entry"
        else:
            tag = f"relay-{idx}"
        ob = _build_outbound(srv, tag=tag)
        if ob is None:
            return None
        if idx + 1 < len(nodes):
            nxt = "entry" if idx + 2 == len(nodes) else f"relay-{idx + 1}"
            ob["sockopt"] = {"dialerProxy": nxt}
        elif fragment and not srv.get("local") and srv.get("proto") not in ("socks", "http", "wireguard"):
            ob["sockopt"] = {"dialerProxy": "frag-dialer"}
        outbounds.append(ob)
    tail = nodes[-1]
    if fragment and not tail.get("local") and tail.get("proto") not in ("socks", "http", "wireguard"):
        outbounds.append({
            "tag": "frag-dialer", "protocol": "freedom",
            "settings": {"domainStrategy": "AsIs", "fragment": {"packets": "tlshello", "length": "10-30", "interval": "10-20"}},
            "sockopt": {"tcpNoDelay": True},
        })
    else:
        outbounds.append({"protocol": "freedom", "tag": "direct"})
    inb = {"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}, "tag": "socks-in"}
    return {"log": {"loglevel": "warning"}, "inbounds": [inb], "outbounds": outbounds}


def build_entry_exit_chain(entry, exit_node, port=SOCK, fragment=True, fp="chrome"):
    ex = dict(exit_node)
    if fp:
        q = dict(ex.get("q") or {})
        q["fp"] = fp
        ex["q"] = q
    return build_lion_cfg([ex, entry], port=port, fragment=fragment)


def build_cfg(server):
    if isinstance(server, dict) and isinstance(server.get("nodes"), list):
        return build_lion_cfg(server["nodes"], SOCK, fragment=bool(server.get("fragment", False)))
    ob = _build_outbound(server, tag="proxy")
    if ob is None:
        return None
    ob.pop("tag", None)
    inb = {"listen": "127.0.0.1", "port": SOCK, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}, "tag": "socks-in"}
    return {"log": {"loglevel": "warning"}, "inbounds": [inb], "outbounds": [ob, {"protocol": "freedom", "tag": "direct"}]}


def is_running():
    _, _, pidfile, _, _, bridgefile = _paths()
    if os.path.exists(pidfile):
        try:
            pid = int(open(pidfile).read())
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, ValueError, PermissionError, OSError):
            pass
    if os.path.exists(bridgefile):
        return True
    return False


def _find_xray_optional():
    here = os.path.dirname(os.path.abspath(__file__))
    return _shim.find_xray_android(extra_paths=(os.path.join(here, "xray"),))


def _curl(args, timeout=15):
    if _shim.is_android() or not _has_curl():
        return _shim.android_curl(args, timeout=timeout, default_socks_port=SOCK)
    try:
        return subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), "--socks5-hostname", f"127.0.0.1:{SOCK}"] + args,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except (OSError, subprocess.SubprocessError):
        return _shim.android_curl(args, timeout=timeout, default_socks_port=SOCK)


def fetch_egress_geo(timeout=10):
    """Fetch public egress IP + ISO country + hosting/proxy flags through the active route (HTTPS-first)."""
    trace_ip = ""
    trace_cc = ""
    r_tr = _curl(["https://1.1.1.1/cdn-cgi/trace"], timeout=min(timeout, 6))
    if r_tr and r_tr.stdout:
        for line in r_tr.stdout.splitlines():
            if line.startswith("ip="):
                trace_ip = line[3:].strip()
            elif line.startswith("loc="):
                cc = line[4:].strip().upper()
                if len(cc) == 2 and cc != "XX":
                    trace_cc = cc

    providers = [
        "https://ipwho.is/",
        "https://ipapi.co/json/",
        "https://ipinfo.io/json",
    ]
    if not _shim.is_android():
        providers.append("http://ip-api.com/json/?fields=status,query,country,countryCode,proxy,hosting")

    for url in providers:
        r = _curl([url], timeout=min(timeout, 8))
        raw = (r.stdout or "").strip() if r else ""
        if not raw or not raw.startswith("{"):
            continue
        try:
            j = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if j.get("status") == "fail" or j.get("success") is False:
            continue
        ip = (j.get("ip") or j.get("query") or trace_ip or "").strip()
        json_cc = (
            j.get("countryCode")
            or j.get("country_code")
            or (j.get("country") if isinstance(j.get("country"), str) and len(j.get("country")) == 2 else "")
            or trace_cc
        ).strip().upper()
        if len(trace_cc) == 2 and trace_cc != json_cc and trace_cc in AISTUDIO_BLOCKED_COUNTRIES:
            cc = trace_cc
            cname = trace_cc
        else:
            cc = json_cc
            cname = (
                j.get("country_name")
                or (j.get("country") if isinstance(j.get("country"), str) and len(j.get("country")) > 2 else "")
                or cc
            )
        sec = j.get("security") if isinstance(j.get("security"), dict) else {}
        org = str(j.get("org") or "").lower()
        org_hosting = any(
            k in org
            for k in ("datacenter", "hosting", "cloud", "amazon", "digitalocean", "hetzner", "ovh", "linode", "vultr", "cdn77", "m247", "leaseweb")
        )
        hosting = bool(j.get("hosting") or sec.get("hosting") or sec.get("vpn") or sec.get("tor") or org_hosting)
        proxy_flag = bool(j.get("proxy") or sec.get("proxy") or sec.get("vpn") or sec.get("tor"))
        if ip and len(cc) == 2:
            return {
                "ip": ip,
                "country": cc,
                "country_name": cname,
                "proxy": proxy_flag,
                "hosting": hosting,
            }

    if trace_ip and len(trace_cc) == 2:
        return {
            "ip": trace_ip,
            "country": trace_cc,
            "country_name": trace_cc,
            "proxy": False,
            "hosting": False,
        }
    return None


def probe_aistudio_gates(want_country=None, timeout=12):
    """Deep geo-restriction + reachability gate check for Google AI Studio."""
    res = {
        "egress": None,
        "country": None,
        "country_name": None,
        "proxy": False,
        "hosting": False,
        "aistudio_ok": False,
        "accounts_ok": False,
        "unsupported_region": False,
        "http_code": 0,
        "final_url": "",
        "latency_ms": None,
        "verdict": False,
        "reason": "",
    }
    t0 = time.monotonic()
    geo = fetch_egress_geo(timeout=min(timeout, 10))
    if not geo:
        ip = probe_egress(timeout=min(timeout, 8))
        res["egress"] = ip
        res["latency_ms"] = int((time.monotonic() - t0) * 1000)
        res["reason"] = (
            "geo country unverified (cannot confirm non-georestricted exit)"
            if ip
            else "no egress (tunnel/VPN unreachable)"
        )
        return res

    res["egress"] = geo["ip"]
    res["country"] = geo["country"]
    res["country_name"] = geo["country_name"]
    res["proxy"] = bool(geo["proxy"])
    res["hosting"] = bool(geo["hosting"])

    cc = (geo["country"] or "").upper()
    if len(cc) != 2 or cc in AISTUDIO_BLOCKED_COUNTRIES:
        res["unsupported_region"] = True
        res["latency_ms"] = int((time.monotonic() - t0) * 1000)
        res["reason"] = f"GEO-BLOCKED: egress {geo['ip']} is in {cc or '??'} ({geo['country_name']})"
        return res
    if want_country and cc != want_country.upper():
        res["latency_ms"] = int((time.monotonic() - t0) * 1000)
        res["reason"] = f"egress country {cc} != requested {want_country.upper()}"
        return res

    using_shim = _shim.is_android() or not _has_curl()
    r_ai = _curl(["-L", AISTUDIO_URL], timeout=timeout)
    body = (r_ai.stdout or "") if r_ai else ""
    if using_shim:
        code = int(_shim._LAST_HTTP_META.get("code") or 0)
        final_url = _shim.get_last_final_url() or AISTUDIO_URL
    else:
        r_meta = _curl(["-L", "-o", "/dev/null", "-w", "%{http_code}|%{url_effective}", AISTUDIO_URL], timeout=timeout)
        meta_parts = ((r_meta.stdout or "").strip() if r_meta else "").split("|", 1)
        code = int(meta_parts[0]) if meta_parts and meta_parts[0].isdigit() else 0
        final_url = meta_parts[1] if len(meta_parts) > 1 else AISTUDIO_URL

    res["http_code"] = code
    res["final_url"] = final_url
    final_low = final_url.lower()
    body_low = body.lower()

    geo_hit = (
        code in (403, 451)
        or "/unsupported" in final_low
        or "available-regions" in final_low
        or "country-not-supported" in final_low
        or "unsupported-country" in final_low
        or "/sorry/" in final_low
        or next((m for m in AISTUDIO_GATE_MARKERS if m in body_low), None)
    )
    if geo_hit:
        res["unsupported_region"] = True
        res["latency_ms"] = int((time.monotonic() - t0) * 1000)
        res["reason"] = f"REGION-GATE: AI Studio geo-restricted on {cc} ({geo['ip']}, HTTP {code}, {final_url})"
        return res

    if code == 0 or code >= 500 or not body.strip():
        res["latency_ms"] = int((time.monotonic() - t0) * 1000)
        res["reason"] = f"aistudio.google.com unreachable (HTTP {code})"
        return res

    # Secondary gate: verify generativelanguage API doesn't report location unsupported
    # and gemini.google.com doesn't redirect to /unsupported
    api_url = "https://generativelanguage.googleapis.com/v1beta/models"
    r_api = _curl([api_url], timeout=min(timeout, 8))
    api_body = (r_api.stdout or "").lower() if r_api else ""
    api_markers = (
        "location is not supported",
        "not available in your country",
        "not available in your region",
        "region is not supported",
        "country is not supported",
        "user location",
    )
    if any(m in api_body for m in api_markers):
        res["unsupported_region"] = True
        res["latency_ms"] = int((time.monotonic() - t0) * 1000)
        res["reason"] = f"REGION-GATE: generativelanguage API rejected location on {cc} ({geo['ip']})"
        return res

    gemini_url = "https://gemini.google.com/"
    r_gem = _curl(["-L", gemini_url], timeout=min(timeout, 8))
    gem_body = (r_gem.stdout or "") if r_gem else ""
    if using_shim:
        gem_code = int(_shim._LAST_HTTP_META.get("code") or 0)
        gem_final = (_shim.get_last_final_url() or gemini_url).lower()
    else:
        gem_code = 0
        gem_final = gemini_url
    gem_low = gem_body.lower()
    if (
        gem_code in (403, 451)
        or "/unsupported" in gem_final
        or "available-regions" in gem_final
        or "/sorry/" in gem_final
        or any(m in gem_low for m in AISTUDIO_GATE_MARKERS)
    ):
        res["unsupported_region"] = True
        res["latency_ms"] = int((time.monotonic() - t0) * 1000)
        res["reason"] = f"REGION-GATE: gemini.google.com geo-restricted on {cc} ({geo['ip']}, HTTP {gem_code})"
        return res

    res["aistudio_ok"] = True

    r_acc = _curl(["-o", "/dev/null", "-w", "%{http_code}", ACCOUNTS_URL], timeout=min(timeout, 10))
    acc_code = (r_acc.stdout or "").strip() if r_acc else "000"
    res["accounts_ok"] = acc_code not in ("", "000")
    res["latency_ms"] = int((time.monotonic() - t0) * 1000)
    if not res["accounts_ok"]:
        res["reason"] = f"accounts.google.com unreachable (HTTP {acc_code}; sign-in would fail)"
        return res

    res["verdict"] = True
    flags = []
    if res["proxy"]:
        flags.append("proxy-flagged")
    if res["hosting"]:
        flags.append("hosting")
    flag_str = f" [{', '.join(flags)}]" if flags else ""
    res["reason"] = f"egress {geo['ip']} in {cc} ({geo['country_name']}); AI Studio HTTP {code} + accounts OK{flag_str}"
    return res


def gate_score(g):
    return (
        0 if g.get("verdict") else 1,
        0 if not g.get("proxy") else 1,
        0 if not g.get("hosting") else 1,
        g.get("latency_ms") or 10_000,
    )


def start(server_index=0):
    _, pool_path, _, _, idxfile, bridgefile = _paths()
    if is_running():
        print(f"[aistudio] Tunnel already running on 127.0.0.1:{SOCK}")
        print("[aistudio] Opening AI Studio through the existing tunnel...")
        proxy_port = None
        if _shim.is_android() and os.path.exists(bridgefile):
            try:
                b = json.load(open(bridgefile))
                p = b.get("port")
                if isinstance(p, int) and p > 0:
                    proxy_port = p
            except Exception:
                pass
        launch_browser(proxy_port=proxy_port)
        return True, None

    if _find_xray_optional() is None and _shim.is_android():
        return _start_android_bridge(server_index, pool_path, idxfile, bridgefile)

    try:
        with open(pool_path) as fh:
            pool = json.load(fh)
    except FileNotFoundError:
        raise SystemExit("[aistudio] No server pool yet. Run: dastyab aistudio verify")
    except (json.JSONDecodeError, OSError) as e:
        raise SystemExit(
            f"[aistudio] Server pool is unreadable ({e}). Run: dastyab aistudio verify"
        )
    if not pool:
        raise SystemExit("[aistudio] Server pool is empty. Run: dastyab aistudio verify")

    first = server_index % len(pool)
    order = [first] + [(first + off) % len(pool) for off in range(1, len(pool))]
    dead = []
    for idx in order:
        egress = _bring_up(pool[idx])
        if egress:
            if dead:
                print(f"[aistudio] Skipped dead node(s): {', '.join(dead)}", file=sys.stderr)
            with open(idxfile, "w") as fh:
                fh.write(str(idx))
            print(f"[aistudio] Clean egress IP: {egress}")
            print("[aistudio] Opening AI Studio through the tunnel...")
            launch_browser()
            return True, idx
        dead.append(f"{pool[idx]['addr']}:{pool[idx]['port']}")
        stop(quiet=True)

    print("[aistudio] WARNING: every node in the pool is dead at the far end.", file=sys.stderr)
    print(
        "[aistudio] Run `dastyab aistudio verify` to rebuild the pool from fresh server cards.",
        file=sys.stderr,
    )
    return False, None


def _route_to_chain_hops(route):
    scheme, host, port, _ = route
    if scheme == "chain" and isinstance(host, list):
        return [
            {
                "scheme": h[0],
                "host": h[1],
                "port": int(h[2]),
                "username": h[3] if len(h) > 3 else "",
                "password": h[4] if len(h) > 4 else "",
            }
            for h in host
        ]
    if scheme in ("http", "socks5") and host and int(port or 0) > 0:
        return [{"scheme": scheme, "host": host, "port": int(port), "username": "", "password": ""}]
    return []


def _start_android_bridge(server_index, pool_path, idxfile, bridgefile):
    """Android bridge: verify external Lantern VPN and progressively auto-chain 1/2/3/4 proxy layers until AI Studio is non-georestricted."""
    print("[aistudio] Android Python Core: deep geo-gate probing & progressive multi-layer route chaining...")
    results = _shim.discover_best_android_route(
        probe_aistudio_gates, target_service="aistudio", max_candidates=36
    )
    best = None
    for route, g in results:
        scheme, host, port, label = route
        status_s = f"PASS {g['country']} {g['egress']} ({g['latency_ms']}ms)" if g["verdict"] else f"FAIL: {g['reason']}"
        print(f"   • {label} -> {status_s}", flush=True)
        if g["verdict"] and (best is None or gate_score(g) < gate_score(best[1])):
            best = (route, g)

    if best is None:
        print(
            "[aistudio] No route passed AI Studio's non-georestricted gate checks (country + HTTPS redirect + DOM + accounts).",
            file=sys.stderr,
        )
        print(
            "[aistudio] Connect a clean residential/v2rayNG/harvested proxy hop on top of Lantern, or switch Lantern region.",
            file=sys.stderr,
        )
        return False, None

    route, g = best
    scheme, host, port, label = route
    chain_hops = _route_to_chain_hops(route)
    with open(bridgefile, "w") as fh:
        json.dump(
            {
                "scheme": scheme,
                "host": host if scheme != "chain" else "",
                "port": port,
                "hops": len(chain_hops),
                "chain": chain_hops,
                "label": label,
                "egress": g["egress"],
                "country": g["country"],
            },
            fh,
        )
    _shim.emit_event(
        "SYNC_SERVICE_CHAIN",
        {
            "target_service": "aistudio",
            "chain": chain_hops,
            "label": label,
            "egress": g["egress"],
            "country": g["country"],
        },
    )
    print(f"[aistudio] Unlocked via {label} | {g['reason']}")
    print("[aistudio] Opening AI Studio in DastYab Browser...")
    proxy_port = port if scheme in ("http", "socks5") and port > 0 else None
    launch_browser(proxy_port=proxy_port)
    return True, server_index


def _bring_up(srv, announce=True):
    """Start one core on one pool entry; return the egress IP, or None."""
    _, _, pidfile, cfgpath, _, _ = _paths()
    cfg = build_cfg(srv)
    with open(cfgpath, "w") as fh:
        json.dump(cfg, fh)
    xray = find_xray()
    try:
        proc = subprocess.Popen(
            [xray, "run", "-c", cfgpath],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        raise SystemExit(f"[aistudio] Cannot launch {xray}: {e}")
    with open(pidfile, "w") as fh:
        fh.write(str(proc.pid))
    up = False
    for _ in range(25):
        if proc.poll() is not None:
            break
        s = None
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect(("127.0.0.1", SOCK))
            up = True
            break
        except Exception:
            time.sleep(0.3)
        finally:
            if s is not None:
                s.close()
    if not up:
        rc = proc.poll()
        proc.kill()
        try:
            os.remove(pidfile)
        except OSError:
            pass
        detail = (
            f"{xray} exited immediately (code {rc}) — does not accept `run -c <config>`"
            if rc is not None
            else f"{xray} never opened 127.0.0.1:{SOCK}"
        )
        raise SystemExit(
            f"[aistudio] Tunnel failed to start: {detail}.\n"
            f"[aistudio] Set DASTYAB_XRAY=/path/to/xray (a real xray core)."
        )
    ip = probe_egress(timeout=20)
    if ip and announce:
        print(f"[aistudio] Tunnel started via {srv['addr']}:{srv['port']} (pid {proc.pid})")
        print(f"[aistudio] Local SOCKS5 proxy: 127.0.0.1:{SOCK}")
    return ip


def probe_egress(timeout=12):
    """Return current egress IP via tunnel, or None if tunnel dead."""
    if _shim.is_android() or not _has_curl():
        r = _shim.android_curl(
            ["-s", "--max-time", str(timeout), "--socks5-hostname", f"127.0.0.1:{SOCK}", "https://api.ipify.org"],
            timeout=timeout,
            default_socks_port=SOCK,
        )
        out = (r.stdout or "").strip()
        if out and "\n" not in out and len(out) < 60:
            return out
        return None
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), "--socks5-hostname", f"127.0.0.1:{SOCK}", "https://api.ipify.org"],
            capture_output=True,
            text=True,
            timeout=timeout + 3,
        )
        out = r.stdout.strip()
        return out if out and not out.startswith("curl") else None
    except Exception:
        return None


def _has_curl():
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, "curl") if d else ""
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return True
    return False


def stop(quiet=False):
    _, _, pidfile, _, _, bridgefile = _paths()
    if os.path.exists(pidfile):
        try:
            pid = int(open(pidfile).read())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.3)
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            os.remove(pidfile)
        except OSError:
            pass
    if os.path.exists(bridgefile):
        try:
            os.remove(bridgefile)
        except OSError:
            pass
    if not _shim.is_android():
        subprocess.run(
            [
                "bash",
                "-c",
                'for p in $(pgrep -f dastyab_aistudio.json); do '
                '[ "$p" = "${1}" ] || [ "$p" = "$$" ] || kill -9 "$p" 2>/dev/null; done',
                "dastyab-stop",
                str(os.getpid()),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if not quiet:
        print("[aistudio] Tunnel stopped")


def launch_browser(proxy_port=None):
    """Open AI Studio pinned to the tunnel (InAppBrowserActivity on Android, Chrome on Linux)."""
    if _shim.is_android():
        _shim.emit_event(
            "OPEN_BROWSER",
            {"title": "Google AI Studio", "url": AISTUDIO_URL, "proxy_port": proxy_port or SOCK},
        )
        print("[aistudio] Requested DastYab Browser for AI Studio.")
        return
    home, _, _, _, _, _ = _paths()
    cands = [os.environ.get("DASTYAB_BROWSER", "")] + CHROME_CANDS
    ch = next((c for c in cands if c and os.path.isfile(c) and os.access(c, os.X_OK)), None)
    if ch is None:
        print("[aistudio] No Chromium-based browser found (Chrome/Chromium/Edge/Brave).")
        print(
            f"[aistudio] Open {AISTUDIO_URL} yourself through socks5://127.0.0.1:{SOCK}."
        )
        return
    tmp = os.path.join(home, ".dastyab-aistudio-profile")
    os.makedirs(tmp, exist_ok=True)
    subprocess.Popen(
        [
            ch,
            "--ozone-platform=x11",
            f"--proxy-server=socks5://127.0.0.1:{SOCK}",
            f"--user-data-dir={tmp}",
            AISTUDIO_URL,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("[aistudio] Opened the browser with the tunnel proxy.")


def verify():
    _, pool_path, _, _, _, _ = _paths()
    pool = json.load(open(pool_path)) if os.path.exists(pool_path) else []
    has_xray = _find_xray_optional() is not None

    if not has_xray and _shim.is_android():
        print("[aistudio] Checking Android Layer 0 (Lantern) & progressive multi-layer routes for AI Studio:")
        results = _shim.discover_best_android_route(
            probe_aistudio_gates, target_service="aistudio", max_candidates=36
        )
        passed_count = 0
        best = None
        for route, g in results:
            if g["verdict"]:
                passed_count += 1
                mark = f"OK   {g['country']} {g['egress']} (HTTP {g['http_code']}, {g['latency_ms']}ms)"
                if best is None or gate_score(g) < gate_score(best[1]):
                    best = (route, g)
            else:
                mark = f"FAIL ({g['reason']})"
            print(f"   • {route[3]}  {mark}", flush=True)
        if best is not None:
            b_route, b_g = best
            _shim.emit_event(
                "SYNC_SERVICE_CHAIN",
                {
                    "target_service": "aistudio",
                    "chain": _route_to_chain_hops(b_route),
                    "label": b_route[3],
                    "egress": b_g["egress"],
                    "country": b_g["country"],
                },
            )
        print(f"[aistudio] {passed_count}/{len(results)} route(s) passed AI Studio non-georestricted gates.")
        if pool:
            print(f"[aistudio] Probing TCP/TLS latency for {len(pool)} stored VLESS server(s):")
            alive_tcp = 0
            for i, s in enumerate(pool[:15]):
                ms = _shim.probe_vless_node_transport(s, timeout=2.5)
                if ms is not None:
                    alive_tcp += 1
                mark = f"OK ({ms}ms)" if ms is not None else "DEAD"
                print(f"   [{i}] {s['addr']}:{s['port']}  {mark}")
            print(f"[aistudio] {alive_tcp}/{min(len(pool), 15)} pool endpoints reachable at transport layer.")
        return

    if not pool:
        print("[aistudio] No verified servers stored yet. Run with a server list to build the pool.")
        return
    print(f"[aistudio] {len(pool)} servers in pool — probing each one now:")
    alive = 0
    if is_running():
        stop(quiet=True)
    for i, s in enumerate(pool):
        ip = _bring_up(s, announce=False)
        stop(quiet=True)
        mark = f"OK   egress {ip}" if ip else "DEAD"
        if ip:
            alive += 1
        print(f"   [{i}] {s['addr']}:{s['port']}  {mark}")
    print(f"[aistudio] {alive}/{len(pool)} reachable now. `start` walks the pool and skips dead entries.")


def parse_vless(line):
    line = line.split("#")[0].strip()
    m = re.match(r"vless://([^@]*)@([^:]+):(\d+)\?(.*)", line)
    if not m:
        return None
    uuid, host, port, qs = m.group(1), m.group(2), int(m.group(3)), m.group(4)
    if not uuid or not host:
        return None
    return {"proto": "vless", "uuid": uuid, "addr": host, "port": port, "q": dict(urllib.parse.parse_qsl(qs))}


def _b64_decode(raw):
    raw = re.sub(r"\s+", "", raw or "").replace("-", "+").replace("_", "/")
    pad = (-len(raw)) % 4
    return base64.b64decode(raw + "=" * pad)


def is_non_proxy_http_url(raw):
    s = (raw or "").strip()
    low = s.lower()
    if not low.startswith(("http://", "https://")):
        return False
    try:
        u = urllib.parse.urlparse(s)
    except ValueError:
        return True
    host = (u.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if not host or host in WEB_NON_PROXY_HOSTS or not u.port:
        return True
    if u.path not in ("", "/") or u.query:
        return True
    return False


def _parse_host_port(hp):
    hp = (hp or "").strip()
    if hp.startswith("[") and "]" in hp:
        end = hp.index("]")
        host = hp[1:end]
        rest = hp[end + 1:]
        port_s = rest[1:] if rest.startswith(":") else ""
    elif ":" in hp:
        host, port_s = hp.rsplit(":", 1)
    else:
        return None, None
    try:
        port = int(port_s)
    except ValueError:
        return None, None
    if not host or not (1 <= port <= 65535):
        return None, None
    return host, port


def parse_node_uri(line):
    s = (line or "").strip()
    if not s or "://" not in s:
        return None
    low = s.lower()
    if low.startswith("vless://"):
        return parse_vless(s)
    if low.startswith("vmess://"):
        try:
            obj = json.loads(_b64_decode(s[8:].split("#")[0]).decode("utf-8", "replace"))
            addr, port, uid = obj.get("add", ""), int(obj.get("port", 0)), obj.get("id", "")
            if not addr or not port or not uid:
                return None
            return {
                "proto": "vmess", "addr": addr, "port": port, "uuid": uid,
                "name": obj.get("ps", ""),
                "q": {
                    "type": obj.get("net", "tcp"),
                    "security": obj.get("tls", "none") or "none",
                    "sni": obj.get("sni", ""),
                    "host": obj.get("host", ""),
                    "path": obj.get("path", "/") or "/",
                },
            }
        except Exception:
            return None
    if low.startswith("trojan://"):
        body = s.split("#")[0][9:]
        if "@" not in body:
            return None
        pw, hpq = body.split("@", 1)
        hp, qs = (hpq.split("?", 1) + [""])[:2]
        host, port = _parse_host_port(hp)
        if not pw or not host:
            return None
        q = dict(urllib.parse.parse_qsl(qs))
        q.setdefault("security", "tls")
        q.setdefault("type", "tcp")
        return {"proto": "trojan", "addr": host, "port": port, "password": pw, "q": q}
    if low.startswith("ss://"):
        body = s.split("#")[0][5:]
        try:
            if "@" in body:
                cred, hp = body.split("@", 1)
                hp = hp.split("?")[0]
                if ":" not in cred:
                    cred = _b64_decode(cred).decode("utf-8", "replace")
            else:
                dec = _b64_decode(body.split("?")[0]).decode("utf-8", "replace")
                cred, hp = dec.rsplit("@", 1)
            method, pw = cred.split(":", 1)
            host, port = _parse_host_port(hp)
            if not host:
                return None
            return {"proto": "ss", "addr": host, "port": port, "method": method, "password": pw, "q": {}}
        except Exception:
            return None
    if low.startswith(("wireguard://", "wg://", "warp://")):
        body = s.split("#")[0].split("://", 1)[1]
        if "@" not in body:
            return None
        priv, hpq = body.split("@", 1)
        hp, qs = (hpq.split("?", 1) + [""])[:2]
        host, port = _parse_host_port(hp)
        if not priv or not host:
            return None
        q = dict(urllib.parse.parse_qsl(qs))
        if "publickey" not in q and "publicKey" in q:
            q["publickey"] = q["publicKey"]
        return {"proto": "wireguard", "addr": host, "port": port, "secret": urllib.parse.unquote(priv), "q": q}
    if low.startswith(("hysteria2://", "hy2://")):
        body = s.split("#")[0].split("://", 1)[1]
        if "@" not in body:
            return None
        pw, hpq = body.split("@", 1)
        hp, qs = (hpq.split("?", 1) + [""])[:2]
        host, port = _parse_host_port(hp)
        if not pw or not host:
            return None
        return {"proto": "hy2", "addr": host, "port": port, "password": urllib.parse.unquote(pw), "q": dict(urllib.parse.parse_qsl(qs))}
    if low.startswith("tuic://"):
        body = s.split("#")[0][7:]
        if "@" not in body:
            return None
        cred, hpq = body.split("@", 1)
        hp, qs = (hpq.split("?", 1) + [""])[:2]
        host, port = _parse_host_port(hp)
        if not host:
            return None
        uid, pw = (cred.split(":", 1) + [""])[:2]
        if not uid:
            return None
        return {"proto": "tuic", "addr": host, "port": port, "uuid": urllib.parse.unquote(uid), "password": urllib.parse.unquote(pw), "q": dict(urllib.parse.parse_qsl(qs))}
    if low.startswith(("socks5://", "socks://", "http://", "https://")):
        if low.startswith(("http://", "https://")) and is_non_proxy_http_url(s):
            return None
        try:
            u = urllib.parse.urlparse(s)
        except ValueError:
            return None
        if not u.hostname or not u.port:
            return None
        return {
            "proto": "socks" if u.scheme.startswith("socks") else "http",
            "addr": u.hostname, "port": int(u.port),
            "user": urllib.parse.unquote(u.username or ""),
            "password": urllib.parse.unquote(u.password or ""),
            "local": u.hostname in ("127.0.0.1", "localhost"),
            "q": {},
        }
    return None


def _extract_wg_ini_nodes(text):
    if "[interface]" not in text.lower() or "[peer]" not in text.lower():
        return []
    out = []
    for block in re.split(r"(?=\[Interface\])", text, flags=re.IGNORECASE):
        if "[peer]" not in block.lower():
            continue
        sec, priv, addr, mtu, pub, host, port = "", "", "", "1280", "", None, None
        for raw in block.splitlines():
            line = raw.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            low = line.lower()
            if low == "[interface]":
                sec = "if"
                continue
            if low == "[peer]":
                sec = "peer"
                continue
            if line.startswith("["):
                sec = ""
                continue
            if "=" not in line:
                continue
            k, v = [x.strip() for x in line.split("=", 1)]
            kl = k.lower()
            if sec == "if":
                if kl == "privatekey":
                    priv = v
                elif kl == "address":
                    addr = v
                elif kl == "mtu" and v.isdigit():
                    mtu = v
            elif sec == "peer":
                if kl == "publickey":
                    pub = v
                elif kl == "endpoint":
                    host, port = _parse_host_port(v)
        if priv and pub and host and port:
            out.append({"proto": "wireguard", "addr": host, "port": port, "secret": priv,
                        "q": {"publickey": pub, "address": addr or "172.16.0.2/32", "mtu": mtu}})
    return out


def _extract_ovpn_proxy_nodes(text):
    out = []
    for raw in text.splitlines():
        parts = raw.split("#", 1)[0].split(";", 1)[0].strip().split()
        if len(parts) >= 3 and parts[0].lower() in ("http-proxy", "socks-proxy"):
            try:
                p = int(parts[2])
            except ValueError:
                continue
            if 1 <= p <= 65535 and parts[1]:
                out.append({"proto": "socks" if parts[0].lower() == "socks-proxy" else "http",
                            "addr": parts[1], "port": p, "q": {}})
    return out


def _clash_vals_to_node(vals):
    t = vals.get("type", "").lower()
    host = vals.get("server", "")
    try:
        port = int(vals.get("port", 0))
    except ValueError:
        return None
    if not host or not (1 <= port <= 65535) or host in ("127.0.0.1", "0.0.0.0"):
        return None
    if t == "vless" and vals.get("uuid"):
        return {"proto": "vless", "addr": host, "port": port, "uuid": vals["uuid"],
                "q": {"security": "tls" if vals.get("tls") == "true" else "none",
                      "sni": vals.get("servername") or vals.get("sni", ""),
                      "type": vals.get("network", "tcp"),
                      "fp": vals.get("client-fingerprint", "chrome")}}
    if t == "vmess" and vals.get("uuid"):
        return {"proto": "vmess", "addr": host, "port": port, "uuid": vals["uuid"],
                "q": {"security": "tls" if vals.get("tls") == "true" else "none",
                      "sni": vals.get("servername") or vals.get("sni", ""),
                      "type": vals.get("network", "tcp")}}
    if t == "trojan" and vals.get("password"):
        return {"proto": "trojan", "addr": host, "port": port, "password": vals["password"],
                "q": {"security": "tls", "sni": vals.get("sni", ""), "type": vals.get("network", "tcp")}}
    if t in ("ss", "shadowsocks") and vals.get("password"):
        return {"proto": "ss", "addr": host, "port": port, "method": vals.get("cipher", "aes-256-gcm"), "password": vals["password"], "q": {}}
    if t == "wireguard" and vals.get("private-key") and vals.get("public-key"):
        return {"proto": "wireguard", "addr": host, "port": port, "secret": vals["private-key"],
                "q": {"publickey": vals["public-key"], "address": vals.get("ip", "172.16.0.2/32")}}
    if t in ("hy2", "hysteria2") and vals.get("password"):
        return {"proto": "hy2", "addr": host, "port": port, "password": vals["password"], "q": {"sni": vals.get("sni", "")}}
    if t == "tuic" and vals.get("uuid"):
        return {"proto": "tuic", "addr": host, "port": port, "uuid": vals["uuid"], "password": vals.get("password", ""), "q": {"sni": vals.get("sni", "")}}
    if t in ("socks5", "http"):
        return {"proto": "socks" if t == "socks5" else "http", "addr": host, "port": port, "q": {}}
    return None


def _extract_clash_yaml_nodes(text):
    if "proxies:" not in text or "server:" not in text:
        return []
    out = []
    kv_re = re.compile(r"([A-Za-z0-9_-]+)\s*:\s*(\"[^\"]*\"|'[^']*'|[^,\}\n#]+)")
    in_proxies = False
    cur = {}
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("proxies:"):
            in_proxies = True
            continue
        if in_proxies and not raw[:1].isspace() and not stripped.startswith("-") and ":" in stripped:
            break
        if not in_proxies:
            continue
        if stripped.startswith("-"):
            if cur:
                node = _clash_vals_to_node(cur)
                if node:
                    out.append(node)
                cur = {}
            after = stripped[1:].strip()
            if after.startswith("{"):
                node = _clash_vals_to_node({k.lower(): v.strip().strip("\"'") for k, v in kv_re.findall(after)})
                if node:
                    out.append(node)
            else:
                for k, v in kv_re.findall(after):
                    cur[k.lower()] = v.strip().strip("\"'")
        elif cur or ":" in stripped:
            for k, v in kv_re.findall(stripped):
                cur[k.lower()] = v.strip().strip("\"'")
    if cur:
        node = _clash_vals_to_node(cur)
        if node:
            out.append(node)
    return out


def _extract_json_nodes(raw_txt):
    cleaned = re.sub(r"(?m)^\s*//.*$", "", raw_txt or "").lstrip()
    if not cleaned.startswith(("{", "[")):
        return []
    try:
        doc = json.loads(cleaned)
    except json.JSONDecodeError:
        return []
    items = doc.get("outbounds", []) if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
    if isinstance(doc, dict) and not items and doc.get("add") and doc.get("port") and doc.get("id"):
        items = [{"type": "vmess", "server": doc["add"], "server_port": doc["port"], "uuid": doc["id"],
                  "tls": {"enabled": doc.get("tls") == "tls", "server_name": doc.get("sni", "")}}]
    if not isinstance(items, list):
        return []
    out = []
    for ob in items:
        if not isinstance(ob, dict):
            continue
        t = (ob.get("type") or ob.get("protocol") or "").lower()
        if t in ("direct", "block", "dns", "freedom", "blackhole", "selector", "urltest"):
            continue
        host = ob.get("server") or ""
        port = ob.get("server_port") or 0
        if host and port:
            if t == "vless" and ob.get("uuid"):
                tls_o = ob.get("tls") or {}
                out.append({"proto": "vless", "addr": host, "port": int(port), "uuid": ob["uuid"],
                            "q": {"security": "tls" if tls_o.get("enabled") else "none", "sni": tls_o.get("server_name", "")}})
            elif t == "vmess" and ob.get("uuid"):
                tls_o = ob.get("tls") or {}
                out.append({"proto": "vmess", "addr": host, "port": int(port), "uuid": ob["uuid"],
                            "q": {"security": "tls" if tls_o.get("enabled") else "none", "sni": tls_o.get("server_name", "")}})
            elif t == "trojan" and ob.get("password"):
                out.append({"proto": "trojan", "addr": host, "port": int(port), "password": ob["password"], "q": {"security": "tls"}})
            elif t in ("shadowsocks", "ss") and ob.get("password"):
                out.append({"proto": "ss", "addr": host, "port": int(port), "method": ob.get("method", "aes-256-gcm"), "password": ob["password"], "q": {}})
            elif t == "wireguard" and ob.get("private_key") and ob.get("peer_public_key"):
                out.append({"proto": "wireguard", "addr": host, "port": int(port), "secret": ob["private_key"], "q": {"publickey": ob["peer_public_key"]}})
            elif t in ("hy2", "hysteria2") and ob.get("password"):
                out.append({"proto": "hy2", "addr": host, "port": int(port), "password": ob["password"], "q": {}})
            elif t == "tuic" and ob.get("uuid"):
                out.append({"proto": "tuic", "addr": host, "port": int(port), "uuid": ob["uuid"], "password": ob.get("password", ""), "q": {}})
            elif t in ("socks", "http"):
                out.append({"proto": t, "addr": host, "port": int(port), "q": {}})
            continue
        sett = ob.get("settings") if isinstance(ob.get("settings"), dict) else {}
        ss = ob.get("streamSettings") if isinstance(ob.get("streamSettings"), dict) else {}
        sec = ss.get("security", "none")
        tls_s = ss.get("tlsSettings") or ss.get("realitySettings") or {}
        sni = tls_s.get("serverName", "") if isinstance(tls_s, dict) else ""
        if t in ("vless", "vmess") and isinstance(sett.get("vnext"), list) and sett["vnext"]:
            vn = sett["vnext"][0]
            users = vn.get("users") or [{}]
            uid = users[0].get("id") if users else ""
            if vn.get("address") and vn.get("port") and uid:
                out.append({"proto": t, "addr": vn["address"], "port": int(vn["port"]), "uuid": uid,
                            "q": {"security": sec, "sni": sni, "type": ss.get("network", "tcp")}})
        elif t in ("trojan", "shadowsocks", "socks", "http") and isinstance(sett.get("servers"), list) and sett["servers"]:
            sv = sett["servers"][0]
            if sv.get("address") and sv.get("port"):
                p_norm = "ss" if t == "shadowsocks" else t
                node = {"proto": p_norm, "addr": sv["address"], "port": int(sv["port"]),
                        "password": sv.get("password", ""), "q": {"security": sec, "sni": sni}}
                if p_norm == "ss":
                    node["method"] = sv.get("method", "aes-256-gcm")
                out.append(node)
        elif t == "wireguard" and sett.get("secretKey") and isinstance(sett.get("peers"), list) and sett["peers"]:
            peer = sett["peers"][0]
            hp = _parse_host_port(peer.get("endpoint", ""))
            if hp[0] and hp[1] and peer.get("publicKey"):
                addrs = sett.get("address") or ["172.16.0.2/32"]
                out.append({"proto": "wireguard", "addr": hp[0], "port": hp[1], "secret": sett["secretKey"],
                            "q": {"publickey": peer["publicKey"], "address": ",".join(addrs) if isinstance(addrs, list) else str(addrs)}})
    return out


_URI_SCAN_RE = re.compile(
    r"(?:vless|vmess|trojan|ss|wireguard|wg|warp|hy2|hysteria2|tuic|socks5|socks|http|https)://[^\s\"'<>`\\]+",
    re.IGNORECASE,
)


def _decode_config_bytes(raw):
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", "replace")
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


def parse_config_file_bytes(filename, raw):
    """Unpack ALL VPN/proxy file extensions including arbitrary Telegram .txt drops."""
    if not raw or len(raw) > MAX_CONFIG_FILE_BYTES:
        return []
    ext = os.path.splitext(filename or "")[1].lower()
    raw_txt = _decode_config_bytes(raw)
    low_head = raw_txt.lstrip()[:120].lower()
    if low_head.startswith("<!doctype html") or low_head.startswith("<html"):
        return []
    has_ctrl = bool(re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", raw_txt))
    corpus = raw_txt
    if has_ctrl:
        printable_runs = re.findall(r"[\x20-\x7e\r\n\t]{10,}", raw_txt)
        if printable_runs:
            corpus = raw_txt + "\n" + "\n".join(printable_runs)

    b64_exts = frozenset((
        "", ".sub", ".txt", ".b64", ".base64", ".list", ".links", ".urls",
        ".nodes", ".servers", ".proxies", ".npv", ".npvt", ".npvs", ".npv4",
    ))
    if ext in b64_exts:
        cur_full = corpus
        for _ in range(3):
            compact = re.sub(r"\s+", "", cur_full)
            if not (16 <= len(compact) <= 2_000_000 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact)):
                break
            try:
                dec = _b64_decode(compact).decode("utf-8", "replace")
            except Exception:
                break
            dec_compact = re.sub(r"\s+", "", dec)
            is_cfg = any(m in dec for m in ("://", "[Peer]", '"outbounds"', "proxies:"))
            is_b64_next = 16 <= len(dec_compact) <= 2_000_000 and bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", dec_compact))
            if is_cfg:
                corpus += "\n" + dec
                cur_full = dec
            elif is_b64_next:
                cur_full = dec
            else:
                break
        for b64_tok in re.findall(r"[A-Za-z0-9+/=_-]{28,}", corpus)[:256]:
            cur_tok = b64_tok
            for _ in range(3):
                try:
                    dec = _b64_decode(cur_tok).decode("utf-8", "replace")
                except Exception:
                    break
                dec_compact = re.sub(r"\s+", "", dec)
                if any(m in dec for m in ("://", "[Peer]", '"outbounds"', "proxies:")):
                    corpus += "\n" + dec
                if 24 <= len(dec_compact) and re.fullmatch(r"[A-Za-z0-9+/=_-]+", dec_compact):
                    cur_tok = dec_compact
                else:
                    break

    nodes = []
    for m in _URI_SCAN_RE.findall(corpus):
        u = parse_node_uri(m.rstrip(",;.)]}\u200c\u200d\u200e\u200f"))
        if u:
            nodes.append(u)
    nodes.extend(_extract_wg_ini_nodes(corpus))
    nodes.extend(_extract_ovpn_proxy_nodes(corpus))
    nodes.extend(_extract_clash_yaml_nodes(corpus))
    if ext in (".json", ".jsonc", ".sbox", ".singbox", ".nekobox", ".hiddify", ".xray", ".v2ray") or raw_txt.lstrip().startswith(("{", "[")):
        nodes.extend(_extract_json_nodes(raw_txt))
    seen, unique = set(), []
    for n in nodes:
        k = (n.get("proto"), n.get("addr"), n.get("port"), n.get("uuid") or n.get("password") or n.get("secret") or "")
        if k not in seen:
            seen.add(k)
            unique.append(n)
    return unique


def _resolve_entry_arg(entry_spec):
    if not entry_spec:
        return None
    if os.path.isfile(entry_spec):
        with open(entry_spec, "rb") as fh:
            nodes = parse_config_file_bytes(entry_spec, fh.read())
        return nodes[0] if nodes else None
    return parse_node_uri(entry_spec)


def _load_nodes_from_file(path):
    if not os.path.isfile(path):
        raise SystemExit(f"[aistudio] No such URI/config file: {path}")
    try:
        with open(path, "rb") as bfh:
            raw_bytes = bfh.read()
    except OSError as e:
        raise SystemExit(f"[aistudio] Cannot read {path}: {e}")
    uris, seen = [], set()
    for u in parse_config_file_bytes(path, raw_bytes):
        key = (u["addr"], u["port"], u.get("proto", "vless"))
        if key not in seen:
            seen.add(key)
            uris.append(u)
    return uris


def pop_pool(uris_txt, want=6, probe_port=10930, entry_spec=None):
    _, pool_path, _, _, _, _ = _paths()
    uris = _load_nodes_from_file(uris_txt)
    if not uris:
        raise SystemExit(f"[aistudio] No vless:// or proxy/VPN URIs found in {uris_txt}")
    entry_node = _resolve_entry_arg(entry_spec) if entry_spec else None
    candidates = [{"nodes": [u, entry_node], "fragment": True, **u} for u in uris] if entry_node else uris
    probe_limit = max(len(candidates), want) if len(candidates) <= 200 else 200
    has_xray = _find_xray_optional() is not None
    working = []
    for u in candidates[:probe_limit]:
        if has_xray:
            ip = _probe_entry(u, probe_port)
            status = f"OK   egress {ip}" if ip else "DEAD"
            print(f"   {u['addr']}:{u['port']}  {status}", flush=True)
            if ip:
                working.append({**u, "egress": ip})
        else:
            ms = _shim.probe_vless_node_transport(u, timeout=2.5)
            status = f"OK   tls {ms}ms" if ms is not None else "DEAD"
            print(f"   {u['addr']}:{u['port']}  {status}", flush=True)
            if ms is not None:
                working.append({**u, "latency_ms": ms})
        if len(working) >= want:
            break

    if not working:
        raise SystemExit(
            f"[aistudio] None of the supplied URIs are live; keeping existing pool at {pool_path} unchanged."
        )
    os.makedirs(os.path.dirname(pool_path), exist_ok=True)
    tmp = pool_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(working, fh, indent=1)
    os.replace(tmp, pool_path)
    print(f"[aistudio] Built pool: {len(working)} working server(s) -> {pool_path}")


def _probe_entry(u, port):
    cfg = build_cfg(u)
    if cfg is None:
        return None
    cfg["inbounds"][0]["port"] = port
    cfgpath = os.path.join(_shim.tmp_dir(), f"dastyab_buildpool_{port}.json")
    with open(cfgpath, "w") as fh:
        json.dump(cfg, fh)
    proc = None
    try:
        proc = subprocess.Popen(
            [find_xray(), "run", "-c", cfgpath],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    try:
        for _ in range(20):
            if proc.poll() is not None:
                return None
            s = None
            try:
                s = socket.socket()
                s.settimeout(0.4)
                s.connect(("127.0.0.1", port))
                break
            except Exception:
                time.sleep(0.3)
            finally:
                if s is not None:
                    s.close()
        else:
            return None
        r = _shim.android_curl(
            ["-s", "--max-time", "12", "--socks5-hostname", f"127.0.0.1:{port}", "https://api.ipify.org"],
            timeout=12,
            default_socks_port=port,
        )
        out = (r.stdout or "").strip()
        return out if out and "\n" not in out and len(out) < 60 else None
    finally:
        if proc is not None:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.SubprocessError:
                pass


def watch(interval=20, max_fail=2):
    _, pool_path, _, _, idxfile, _ = _paths()
    def load_pool():
        try:
            with open(pool_path) as fh:
                return json.load(fh), None
        except FileNotFoundError:
            return None, "no server pool yet"
        except (json.JSONDecodeError, OSError) as e:
            return None, f"pool unreadable ({e})"

    pool, why = load_pool()
    if not pool and _find_xray_optional() is not None:
        raise SystemExit(f"[aistudio] Cannot watch: {why}. Run: dastyab aistudio verify")
    fail = 0
    idx = 0
    if os.path.exists(idxfile):
        try:
            idx = int(open(idxfile).read())
        except (OSError, ValueError):
            pass
    print(f"[aistudio] Watchdog started: probing every {interval}s")
    while True:
        time.sleep(interval)
        ip = probe_egress()
        if ip:
            fail = 0
            continue
        fail += 1
        if fail < max_fail:
            continue
        print(f"[aistudio] Tunnel down (probe {fail}). Rotating...")
        stop(quiet=True)
        time.sleep(1)
        try:
            start(idx + 1)
            fail = 0
        except SystemExit as e:
            print(f"[aistudio] Rotation attempt failed: {e}", file=sys.stderr)


USAGE = """[aistudio] Usage:
  dastyab aistudio start [pool index]     start the tunnel + open AI Studio
  dastyab aistudio watch [interval secs]  keep the tunnel alive, rotating nodes
  dastyab aistudio verify                 probe every node in the pool now
  dastyab aistudio stop                   stop the tunnel
  dastyab aistudio build-pool <file>      rebuild pool from .txt / any config file
  dastyab aistudio ingest <file>          parse & import all configs from any file"""


def _want_int(value, default, name):
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SystemExit(f"[aistudio] {name} must be a whole number, got {value!r}.\n{USAGE}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dastyab-aistudio.py", add_help=False)
    ap.add_argument("action", nargs="?", default="start")
    ap.add_argument("arg", nargs="?", default=None)
    ap.add_argument("--entry", default=None)
    raw = sys.argv[1:] if argv is None else list(argv)
    if raw and raw[0].strip().lower() in ("help", "--help", "-h"):
        print(USAGE)
        return 0
    a = ap.parse_args(raw)
    cmd = (a.action or "start").strip().lower()
    if cmd in ("start", "on", "up"):
        idx = _want_int(a.arg, 0, "Pool index")
        ok, _ = start(idx)
        return 0 if ok else 3
    if cmd == "stop":
        stop()
        return 0
    if cmd in ("verify", "status"):
        verify()
        return 0
    if cmd == "watch":
        interval = _want_int(a.arg, 20, "Watch interval")
        watch(interval=interval)
        return 0
    if cmd == "build-pool":
        if not a.arg:
            raise SystemExit(f"[aistudio] build-pool needs a file of vless:// cards.\n{USAGE}")
        pop_pool(a.arg, entry_spec=a.entry)
        return 0
    if cmd == "ingest":
        if not a.arg:
            raise SystemExit(f"[aistudio] ingest needs a file path.\n{USAGE}")
        _, pool_path, _, _, _, _ = _paths()
        nodes = _load_nodes_from_file(a.arg)
        if not nodes:
            raise SystemExit(f"[aistudio] No vless:// or proxy/VPN URIs found in {a.arg}")
        en = _resolve_entry_arg(a.entry) if a.entry else None
        out_items = [{"nodes": [u, en], "fragment": True, **u} for u in nodes] if en else nodes
        os.makedirs(os.path.dirname(pool_path), exist_ok=True)
        with open(pool_path + ".tmp", "w") as fh:
            json.dump(out_items, fh, indent=1)
        os.replace(pool_path + ".tmp", pool_path)
        print(f"[aistudio] Imported {len(out_items)} node(s) from {a.arg} -> {pool_path}")
        return 0
    raise SystemExit(f"[aistudio] Unknown action: {cmd}\n{USAGE}")


if __name__ == "__main__":
    sys.exit(main() or 0)
