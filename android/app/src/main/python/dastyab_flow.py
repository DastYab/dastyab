#!/usr/bin/env python3
"""
dastyab flow — multi-layer access to Google Flow (flow.google.com).

THE LAYERS (identical to Linux `dastyab-flow.py`):
  L0 supply    — union of node sources: flow_pool, fresh_vless, nekoray, nodes.json
  L1 transport — xray config builder (reality / tls / ws / grpc / xhttp, vision)
  L2 chain     — optional two-hop: you -> entry -> exit -> Google
  L3 geo gate  — Google's official 151-country Flow allowlist (`SUPPORTED_COUNTRIES`)
  L4 reach     — live flow.google.com (`AiSandboxAngularFrontend`) + accounts.google.com
  L5 quality   — ip-api proxy/hosting flags; prefers clean non-flagged IPs
  L6 browser   — dedicated Chrome on Linux / pinned InAppBrowserActivity on Android
  L7 watchdog  — `watch` re-probes gates & rotates automatically

USAGE:
  dastyab flow start [idx] [--hops 1|2] [--country XX]
  dastyab flow next
  dastyab flow stop
  dastyab flow status
  dastyab flow verify [--country XX]
  dastyab flow best [--try N] [--country XX]
  dastyab flow prove [--try N] [--country XX]
  dastyab flow watch [secs]
  dastyab flow build-pool <uris.txt>
  dastyab flow countries
"""
import argparse
import base64
import glob
import json
import os
import re
import shutil
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

SOCK = int(os.environ.get("DASTYAB_FLOW_SOCKS", "10860"))

FLOW_URL = "https://flow.google.com/"
ACCOUNTS_URL = "https://accounts.google.com/"
GATE_MARKERS = (
    "unsupported-country-title",
    "not available in your country yet",
    "not available in your country",
    "isn't available in your country",
    "unsupported_country",
    "flow is not available in your country",
)
UNAVAILABLE_MARKERS = (
    "unavailable-title",
    "don't have access to flow",
    "dont have access to flow",
    "do not have access to flow",
)
ACCOUNT_HELP = (
    "Flow's account gate. Per support.google.com/flow/answer/16353333 you "
    "need ALL of: (1) age verified, 18+; (2) a supported region; "
    "(3) Google AI Plus/Pro/Ultra (or a qualifying Workspace plan). "
    "The tunnel only satisfies (2)."
)
IPIFY = "https://api.ipify.org"
IPAPI = "http://ip-api.com/json/?fields=status,country,countryCode,proxy,hosting,mobile"

SUPPORTED_COUNTRIES = frozenset(
    """
AL DZ AS AO AG AR AM AW AU AT AZ BS BH BD BE BZ BJ BM BO BA BW BR BG BF
CV KH CM CA KY CL CO CR CI HR CY CZ DK DO EC EG SV EE FJ FI FR GA DE GH
GI GR GU GT GW HT HN HK HU IS IN ID IQ IE IL IT JM JP JO KZ KE KW KG LA
LV LB LI LT LU MO MY MV ML MT MU MX MD MC MA MZ NA NP NL NZ NI NE NG MK
MP NO OM PK PW PA PG PY PE PH PL PT PR QA RO RW SM SA SN RS SC SL SG SK
SI ZA KR ES LK SE CH TW TJ TZ TH TG TO TT TN TR TM VI UG UA AE GB US UY
UZ VE VN VG YE ZM ZW
""".split()
)


def _paths():
    home = os.path.expanduser("~")
    prof = os.path.join(home, ".dastyab", "profiles", "default")
    tmp = _shim.tmp_dir()
    return {
        "HOME": home,
        "PROFILE_DIR": prof,
        "FLOW_POOL": os.path.join(prof, "flow_pool.json"),
        "AISTUDIO_POOL": os.path.join(prof, "fresh_vless.json"),
        "NODES_JSON": os.path.join(prof, "nodes.json"),
        "NEKORAY_PROFILES": os.path.join(home, ".config/nekoray/config/profiles"),
        "PIDFILE": os.path.join(tmp, "dastyab_flow.pid"),
        "CFGPATH": os.path.join(tmp, "dastyab_flow.json"),
        "IDXFILE": os.path.join(tmp, "dastyab_flow_idx"),
        "STATEFILE": os.path.join(tmp, "dastyab_flow_state.json"),
        "BRIDGEFILE": os.path.join(tmp, "dastyab_flow_bridge.json"),
        "BROWSER_PROFILE": os.path.join(home, ".dastyab-flow-profile"),
    }


_XRAY_VERSION = None


def _find_xray_optional():
    here = os.path.dirname(os.path.abspath(__file__))
    return _shim.find_xray_android(extra_paths=(os.path.join(here, "xray"),))


def find_xray():
    here = os.path.dirname(os.path.abspath(__file__))
    found = _shim.find_xray_android(extra_paths=(os.path.join(here, "xray"),))
    if found:
        return found
    raise SystemExit(
        "[flow] No xray core found. Install xray and put it on PATH, or set "
        "DASTYAB_XRAY=/path/to/xray"
    )


def xray_supports_vision():
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


def read_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, OSError):
        return default


def write_json_atomic(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=1)
    os.replace(tmp, path)


def parse_vless(line):
    line = line.split("#")[0].strip()
    m = re.match(r"vless://([^@]*)@([^:]+):(\d+)\?(.*)", line)
    if not m:
        return None
    uuid_, host, port, qs = m.group(1), m.group(2), int(m.group(3)), m.group(4)
    if not uuid_ or not host:
        return None
    return {
        "proto": "vless",
        "uuid": uuid_,
        "addr": host,
        "port": port,
        "q": dict(urllib.parse.parse_qsl(qs)),
    }


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
                "proto": "vmess",
                "addr": addr,
                "port": port,
                "uuid": uid,
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
        return {
            "proto": "hy2", "addr": host, "port": port,
            "password": urllib.parse.unquote(pw), "q": dict(urllib.parse.parse_qsl(qs)),
        }
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
        return {
            "proto": "tuic", "addr": host, "port": port,
            "uuid": urllib.parse.unquote(uid), "password": urllib.parse.unquote(pw),
            "q": dict(urllib.parse.parse_qsl(qs)),
        }
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
            "addr": u.hostname,
            "port": int(u.port),
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
            out.append({
                "proto": "wireguard", "addr": host, "port": port, "secret": priv,
                "q": {"publickey": pub, "address": addr or "172.16.0.2/32", "mtu": mtu},
            })
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
                out.append({
                    "proto": "socks" if parts[0].lower() == "socks-proxy" else "http",
                    "addr": parts[1], "port": p, "q": {},
                })
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
        return {
            "proto": "vless", "addr": host, "port": port, "uuid": vals["uuid"],
            "q": {
                "security": "tls" if vals.get("tls") == "true" else "none",
                "sni": vals.get("servername") or vals.get("sni", ""),
                "type": vals.get("network", "tcp"),
                "fp": vals.get("client-fingerprint", "chrome"),
            },
        }
    if t == "vmess" and vals.get("uuid"):
        return {
            "proto": "vmess", "addr": host, "port": port, "uuid": vals["uuid"],
            "q": {
                "security": "tls" if vals.get("tls") == "true" else "none",
                "sni": vals.get("servername") or vals.get("sni", ""),
                "type": vals.get("network", "tcp"),
            },
        }
    if t == "trojan" and vals.get("password"):
        return {
            "proto": "trojan", "addr": host, "port": port, "password": vals["password"],
            "q": {"security": "tls", "sni": vals.get("sni", ""), "type": vals.get("network", "tcp")},
        }
    if t in ("ss", "shadowsocks") and vals.get("password"):
        return {
            "proto": "ss", "addr": host, "port": port,
            "method": vals.get("cipher", "aes-256-gcm"), "password": vals["password"], "q": {},
        }
    if t == "wireguard" and vals.get("private-key") and vals.get("public-key"):
        return {
            "proto": "wireguard", "addr": host, "port": port, "secret": vals["private-key"],
            "q": {"publickey": vals["public-key"], "address": vals.get("ip", "172.16.0.2/32")},
        }
    if t in ("hy2", "hysteria2") and vals.get("password"):
        return {"proto": "hy2", "addr": host, "port": port, "password": vals["password"], "q": {"sni": vals.get("sni", "")}}
    if t == "tuic" and vals.get("uuid"):
        return {
            "proto": "tuic", "addr": host, "port": port,
            "uuid": vals["uuid"], "password": vals.get("password", ""), "q": {"sni": vals.get("sni", "")},
        }
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
        items = [{
            "type": "vmess", "server": doc["add"], "server_port": doc["port"], "uuid": doc["id"],
            "tls": {"enabled": doc.get("tls") == "tls", "server_name": doc.get("sni", "")},
        }]
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
                out.append({
                    "proto": "vless", "addr": host, "port": int(port), "uuid": ob["uuid"],
                    "q": {"security": "tls" if tls_o.get("enabled") else "none", "sni": tls_o.get("server_name", "")},
                })
            elif t == "vmess" and ob.get("uuid"):
                tls_o = ob.get("tls") or {}
                out.append({
                    "proto": "vmess", "addr": host, "port": int(port), "uuid": ob["uuid"],
                    "q": {"security": "tls" if tls_o.get("enabled") else "none", "sni": tls_o.get("server_name", "")},
                })
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
                out.append({
                    "proto": t, "addr": vn["address"], "port": int(vn["port"]), "uuid": uid,
                    "q": {"security": sec, "sni": sni, "type": ss.get("network", "tcp")},
                })
        elif t in ("trojan", "shadowsocks", "socks", "http") and isinstance(sett.get("servers"), list) and sett["servers"]:
            sv = sett["servers"][0]
            if sv.get("address") and sv.get("port"):
                p_norm = "ss" if t == "shadowsocks" else t
                node = {
                    "proto": p_norm, "addr": sv["address"], "port": int(sv["port"]),
                    "password": sv.get("password", ""), "q": {"security": sec, "sni": sni},
                }
                if p_norm == "ss":
                    node["method"] = sv.get("method", "aes-256-gcm")
                out.append(node)
        elif t == "wireguard" and sett.get("secretKey") and isinstance(sett.get("peers"), list) and sett["peers"]:
            peer = sett["peers"][0]
            hp = _parse_host_port(peer.get("endpoint", ""))
            if hp[0] and hp[1] and peer.get("publicKey"):
                addrs = sett.get("address") or ["172.16.0.2/32"]
                out.append({
                    "proto": "wireguard", "addr": hp[0], "port": hp[1], "secret": sett["secretKey"],
                    "q": {"publickey": peer["publicKey"], "address": ",".join(addrs) if isinstance(addrs, list) else str(addrs)},
                })
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
    """Extract all node dicts from .txt drops, NPV, OVPN, WireGuard/WARP, Clash/Sing-Box JSON, or Base64."""
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


def gather_multi_format_candidates():
    p = _paths()
    out, dirs = [], (
        os.path.join(p["PROFILE_DIR"], "imports"),
        os.path.join(p["PROFILE_DIR"], "downloads"),
        os.path.join(p["PROFILE_DIR"], "harvested"),
        os.path.join(p["HOME"], "Downloads"),
    )
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            entries = sorted(os.listdir(d))[:500]
        except OSError:
            continue
        for name in entries:
            if name.lower() in NOISE_CONFIG_FILENAMES:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext not in MULTI_FORMAT_EXTS:
                continue
            fp = os.path.join(d, name)
            if not os.path.isfile(fp) or os.path.getsize(fp) > MAX_CONFIG_FILE_BYTES:
                continue
            try:
                with open(fp, "rb") as fh:
                    out.extend(parse_config_file_bytes(name, fh.read()))
            except OSError:
                continue
    return out


def _bean_to_server(bean, typ):
    if not bean.get("addr") or not bean.get("port"):
        return None
    st = bean.get("stream", {}) or {}
    q = {
        "security": st.get("sec", "none"),
        "type": st.get("net", "tcp"),
        "sni": st.get("sni", ""),
        "host": st.get("host", ""),
        "path": st.get("path", "/"),
        "serviceName": st.get("servicename", ""),
        "pbk": st.get("pbk", ""),
        "sid": st.get("sid", ""),
        "fp": st.get("utls", "chrome"),
        "flow": bean.get("flow", ""),
    }
    srv = {
        "proto": typ,
        "addr": bean["addr"],
        "port": int(bean["port"]),
        "q": q,
        "name": bean.get("name", ""),
    }
    if typ in ("vless", "vmess"):
        srv["uuid"] = bean.get("pass", "")
    else:
        srv["password"] = bean.get("pass", "")
        if typ == "ss":
            srv["method"] = bean.get("method", "aes-256-gcm")
    return srv


def load_candidates(limit=4096):
    p = _paths()
    out, seen = [], set()

    def add(srv):
        if not srv or not srv.get("addr") or not srv.get("port"):
            return
        key = (str(srv["addr"]), int(srv["port"]), str(srv.get("proto", "")))
        if key in seen:
            return
        seen.add(key)
        out.append(srv)

    for e in read_json(p["FLOW_POOL"], []):
        if isinstance(e, dict) and e.get("nodes"):
            for n in e["nodes"]:
                add(n)
        elif isinstance(e, dict) and "addr" in e:
            add(e)

    for e in read_json(p["AISTUDIO_POOL"], []):
        if isinstance(e, dict) and e.get("addr") and e.get("port"):
            add({
                "proto": e.get("proto") or "vless",
                **e,
                "port": int(e["port"]),
                "q": e.get("q", {}),
            })

    beans = []
    for f in sorted(glob.glob(os.path.join(p["NEKORAY_PROFILES"], "*.json"))):
        d = read_json(f, {})
        if not isinstance(d, dict):
            continue
        srv = _bean_to_server(d.get("bean", {}) or {}, d.get("type", ""))
        if srv:
            beans.append(srv)
    prio = {"vless": 0, "trojan": 1, "vmess": 2, "shadowsocks": 3, "ss": 3}
    for srv in sorted(beans, key=lambda s: prio.get(s["proto"], 9)):
        add(srv)

    nodes_doc = read_json(p["NODES_JSON"], {})
    urls = []
    if isinstance(nodes_doc, dict):
        for n in nodes_doc.get("nodes", []):
            u = (n or {}).get("url", "")
            if u:
                urls.append((not n.get("healthy", False), u))
    elif isinstance(nodes_doc, list):
        for n in nodes_doc:
            u = (n or {}).get("url", "")
            if u:
                urls.append((not n.get("healthy", False), u))
    for _, u in sorted(urls):
        add(parse_node_uri(u))

    for mf in gather_multi_format_candidates():
        add(mf)

    return out[:limit]


def build_outbound(srv, tag):
    q = srv.get("q", {})
    addr, port = srv["addr"], int(srv["port"])
    proto = srv["proto"]

    if proto == "vless":
        out = {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{"address": addr, "port": port, "users": [{"id": srv["uuid"], "encryption": "none"}]}]
            },
        }
        flow = q.get("flow")
        if flow:
            if q.get("security") not in ("tls", "reality"):
                flow = None
            elif not xray_supports_vision():
                flow = None
        if flow:
            out["settings"]["vnext"][0]["users"][0]["flow"] = flow
    elif proto == "trojan":
        out = {
            "tag": tag,
            "protocol": "trojan",
            "settings": {"servers": [{"address": addr, "port": port, "password": srv.get("password", "")}]},
        }
    elif proto == "vmess":
        out = {
            "tag": tag,
            "protocol": "vmess",
            "settings": {"vnext": [{"address": addr, "port": port, "users": [{"id": srv["uuid"], "alterId": 0}]}]},
        }
    elif proto in ("ss", "shadowsocks"):
        out = {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": addr,
                        "port": port,
                        "method": srv.get("method", "aes-256-gcm"),
                        "password": srv.get("password", ""),
                    }
                ]
            },
        }
    elif proto == "wireguard":
        secret = srv.get("secret") or srv.get("private_key") or ""
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
        if srv.get("user"):
            so["users"] = [{"user": srv["user"], "pass": srv.get("password", "")}]
        return {"tag": tag, "protocol": "socks", "settings": {"servers": [so]}}
    elif proto == "http":
        so = {"address": addr, "port": port}
        if srv.get("user"):
            so["users"] = [{"user": srv["user"], "pass": srv.get("password", "")}]
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
        ss["xhttpSettings"] = {
            "path": q.get("path", "/"),
            "host": q.get("host") or q.get("sni") or addr,
            "mode": q.get("mode", "auto"),
        }
    elif net == "grpc":
        ss["network"] = "grpc"
        ss["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    else:
        ss["network"] = "tcp"
    out["streamSettings"] = ss
    return out


def build_config(nodes, port=SOCK, fragment=False):
    if not nodes:
        return None
    if len(nodes) == 1:
        ob = build_outbound(nodes[0], "exit")
        if not ob:
            return None
        outbounds = [ob]
        if fragment and not nodes[0].get("local") and nodes[0].get("proto") not in ("socks", "http", "wireguard"):
            ob["sockopt"] = {"dialerProxy": "frag-dialer"}
            outbounds.append({
                "tag": "frag-dialer",
                "protocol": "freedom",
                "settings": {"domainStrategy": "AsIs", "fragment": {"packets": "tlshello", "length": "10-30", "interval": "10-20"}},
                "sockopt": {"tcpNoDelay": True},
            })
    else:
        tags = ["exit"] + [f"relay-{i}" for i in range(1, len(nodes) - 1)] + ["entry"]
        outbounds = []
        for idx, (node, tag) in enumerate(zip(nodes, tags)):
            ob = build_outbound(node, tag)
            if not ob:
                return None
            if idx + 1 < len(tags):
                ob["sockopt"] = {"dialerProxy": tags[idx + 1]}
            elif fragment and not node.get("local") and node.get("proto") not in ("socks", "http", "wireguard"):
                ob["sockopt"] = {"dialerProxy": "frag-dialer"}
            outbounds.append(ob)
        tail = nodes[-1]
        if fragment and not tail.get("local") and tail.get("proto") not in ("socks", "http", "wireguard"):
            outbounds.append({
                "tag": "frag-dialer",
                "protocol": "freedom",
                "settings": {"domainStrategy": "AsIs", "fragment": {"packets": "tlshello", "length": "10-30", "interval": "10-20"}},
                "sockopt": {"tcpNoDelay": True},
            })
    if not outbounds:
        return None
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "tag": "socks-in",
            }
        ],
        "outbounds": outbounds,
    }


def build_entry_exit_chain(entry, exit_node, port=SOCK, fragment=True, fp="chrome"):
    ex = dict(exit_node)
    if fp:
        q = dict(ex.get("q") or {})
        q["fp"] = fp
        ex["q"] = q
    return build_config([ex, entry], port=port, fragment=fragment)


def is_running():
    p = _paths()
    if os.path.exists(p["PIDFILE"]):
        try:
            pid = int(open(p["PIDFILE"]).read())
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, ValueError, PermissionError, OSError):
            pass
    if os.path.exists(p["BRIDGEFILE"]):
        return True
    return False


def _has_curl():
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, "curl") if d else ""
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return True
    return False


def _curl(args, timeout):
    """Run curl via SOCKS5 tunnel — uses pure-Python curl bridge on Android."""
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


def bring_up(nodes):
    p = _paths()
    cfg = build_config(nodes, SOCK)
    if cfg is None:
        return None
    with open(p["CFGPATH"], "w") as fh:
        json.dump(cfg, fh)
    xray = find_xray()
    try:
        proc = subprocess.Popen(
            [xray, "run", "-c", p["CFGPATH"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
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
        proc.kill()
        return None
    with open(p["PIDFILE"], "w") as fh:
        fh.write(str(proc.pid))
    return proc.pid


def stop(quiet=False):
    p = _paths()
    if os.path.exists(p["PIDFILE"]):
        try:
            pid = int(open(p["PIDFILE"]).read())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.3)
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            os.remove(p["PIDFILE"])
        except OSError:
            pass
    if os.path.exists(p["BRIDGEFILE"]):
        try:
            os.remove(p["BRIDGEFILE"])
        except OSError:
            pass
    if not _shim.is_android():
        subprocess.run(
            [
                "bash",
                "-c",
                'for p in $(pgrep -f dastyab_flow.json); do '
                '[ "$p" = "${1}" ] || [ "$p" = "$$" ] || kill -9 "$p" 2>/dev/null; done',
                "dastyab-flow-stop",
                str(os.getpid()),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if not quiet:
        print("[flow] Tunnel stopped")


def _fetch_geo_via_tunnel():
    """Query egress IP + ISO country + proxy/hosting flags via HTTPS providers (or HTTP ip-api on Linux)."""
    trace_ip = ""
    trace_cc = ""
    r_tr = _curl(["https://1.1.1.1/cdn-cgi/trace"], 8)
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
        providers.insert(0, IPAPI)

    for url in providers:
        r = _curl([url], 12)
        raw = (r.stdout or "").strip() if r else ""
        if not raw or not raw.startswith("{"):
            continue
        try:
            j = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if j.get("status") == "fail" or j.get("success") is False:
            continue
        json_cc = (
            j.get("countryCode")
            or j.get("country_code")
            or (j.get("country") if isinstance(j.get("country"), str) and len(j.get("country")) == 2 else "")
            or trace_cc
        ).strip().upper()
        if len(trace_cc) == 2 and trace_cc != json_cc and trace_cc not in SUPPORTED_COUNTRIES and json_cc in SUPPORTED_COUNTRIES:
            cc = trace_cc
            cname = trace_cc
        else:
            cc = json_cc
            cname = (
                j.get("country_name")
                or (j.get("country") if isinstance(j.get("country"), str) and len(j.get("country")) > 2 else "")
                or (j.get("country") if len(str(j.get("country") or "")) > 2 else "")
                or cc
            )
        sec = j.get("security") if isinstance(j.get("security"), dict) else {}
        org = str(j.get("org") or "").lower()
        org_hosting = any(
            k in org
            for k in ("datacenter", "hosting", "cloud", "amazon", "digitalocean", "hetzner", "ovh", "linode", "vultr", "cdn77", "m247", "leaseweb")
        )
        if len(cc) == 2:
            return {
                "status": "success",
                "countryCode": cc,
                "country": cname,
                "proxy": bool(j.get("proxy") or sec.get("proxy") or sec.get("vpn") or sec.get("tor")),
                "hosting": bool(j.get("hosting") or sec.get("hosting") or sec.get("vpn") or sec.get("tor") or org_hosting),
            }

    if trace_ip and len(trace_cc) == 2:
        return {
            "status": "success",
            "countryCode": trace_cc,
            "country": trace_cc,
            "proxy": False,
            "hosting": False,
        }
    return {}


def probe_gates(want_country=None, browser_profile=None):
    res = {
        "egress": None,
        "country": None,
        "country_name": None,
        "proxy": None,
        "hosting": None,
        "flow_ok": False,
        "accounts_ok": False,
        "latency_ms": None,
        "verdict": False,
        "reason": "",
    }

    t0 = time.time()
    r = _curl([IPIFY], 20)
    ip = (r.stdout or "").strip() if r else ""
    if not ip or len(ip) > 60 or "\n" in ip:
        res["reason"] = "no egress (tunnel dead at the far end)"
        return res
    res["egress"] = ip

    geo = _fetch_geo_via_tunnel()
    if geo.get("status") != "success":
        res["reason"] = "geo lookup failed (geo providers unreachable through route)"
        res["latency_ms"] = int((time.time() - t0) * 1000)
        return res
    res["country"] = geo.get("countryCode")
    res["country_name"] = geo.get("country")
    res["proxy"] = bool(geo.get("proxy"))
    res["hosting"] = bool(geo.get("hosting"))
    res["latency_ms"] = int((time.time() - t0) * 1000)

    if res["country"] not in SUPPORTED_COUNTRIES:
        res["reason"] = f"egress {ip} is in {res['country']} ({res['country_name']}) — not on Google's Flow list"
        return res
    if want_country and res["country"] != want_country.upper():
        res["reason"] = f"egress country {res['country']} != requested {want_country.upper()}"
        return res

    using_shim = _shim.is_android() or not _has_curl()
    r_body = _curl(["-L", FLOW_URL], 25)
    body = (r_body.stdout or "") if r_body else ""
    if using_shim:
        code_num = int(_shim._LAST_HTTP_META.get("code") or 0)
        code = f"{code_num:03d}" if code_num > 0 else "000"
        final_url = _shim.get_last_final_url() or FLOW_URL
    else:
        r_meta = _curl(["-L", "-o", "/dev/null", "-w", "%{http_code}|%{url_effective}", FLOW_URL], 25)
        meta_parts = ((r_meta.stdout or "").strip() if r_meta else "").split("|", 1)
        code = meta_parts[0] if meta_parts and meta_parts[0] else "000"
        final_url = meta_parts[1] if len(meta_parts) > 1 else FLOW_URL

    res["flow_ok"] = code not in ("", "000", "403", "451")
    final_low = final_url.lower()
    if "unsupported-country" in final_low or "/sorry/" in final_low:
        res["flow_ok"] = False
        res["reason"] = f"REGION-GATE: Flow redirected to {final_url} (HTTP {code})"
        return res
    if not res["flow_ok"]:
        res["reason"] = f"flow.google.com blocked or unreachable through tunnel (HTTP {code})"
        return res

    low_body = body.lower()
    for marker in GATE_MARKERS:
        if marker in low_body:
            res["reason"] = f"REGION-GATE: Flow rejected this egress (shows '{marker}')"
            return res
    res["app_shell_ok"] = "AiSandboxAngularFrontend" in body
    if not res["app_shell_ok"]:
        res["reason"] = "flow.google.com answered but not with the Flow app shell (AiSandboxAngularFrontend missing)"
        return res

    r = _curl(["-o", "/dev/null", "-w", "%{http_code}", ACCOUNTS_URL], 25)
    acc_code = (r.stdout or "").strip() if r else "000"
    res["accounts_ok"] = acc_code not in ("", "000")
    if not res["accounts_ok"]:
        res["reason"] = "accounts.google.com unreachable (sign-in would fail)"
        return res

    b_ok, b_detail = browser_gate(profile_dir=browser_profile)
    res["browser_ok"] = b_ok
    res["browser_detail"] = b_detail
    if b_ok is False:
        res["reason"] = b_detail
        return res

    res["verdict"] = True
    flags = []
    if res["proxy"]:
        flags.append("proxy-flagged")
    if res["hosting"]:
        flags.append("hosting")
    suffix = f"; browser check ({b_detail})" if b_ok is None else ""
    res["reason"] = "egress %s in %s (%s); Flow + accounts reachable%s%s" % (
        res["egress"],
        res["country"],
        res["country_name"],
        ("; " + ", ".join(flags)) if flags else "",
        suffix,
    )
    return res


def gate_score(g):
    return (
        0 if g["verdict"] else 1,
        0 if not g["proxy"] else 1,
        0 if not g["hosting"] else 1,
        g["latency_ms"] or 10_000,
    )


def _label(nodes):
    return " -> ".join(f"{n['proto']} {n['addr']}:{n['port']}" for n in nodes)


def load_pool():
    pool = read_json(_paths()["FLOW_POOL"], [])
    return [e for e in pool if isinstance(e, dict) and e.get("nodes")]


def save_pool(passing):
    p = _paths()
    if not passing:
        raise SystemExit(
            f"[flow] No candidate passed the gates; keeping existing pool at {p['FLOW_POOL']} unchanged."
        )
    write_json_atomic(p["FLOW_POOL"], passing)


def _try_nodes(nodes, want_country=None):
    pid = bring_up(nodes)
    if pid is None:
        return None
    try:
        return probe_gates(want_country)
    finally:
        stop(quiet=True)


def _node_endpoint(node):
    return (node.get("addr"), int(node.get("port", 0)))


def _record_pass(nodes, g):
    return {
        "nodes": nodes,
        "egress": g["egress"],
        "country": g["country"],
        "country_name": g["country_name"],
        "proxy": g["proxy"],
        "hosting": g["hosting"],
        "latency_ms": g["latency_ms"],
        "checked_epoch": time.time(),
    }


def scan(candidates, want_country=None, try_n=10, allow_chain=True):
    passing = []
    tested = 0
    dead_entries = set()
    alive_nodes = []
    for cand in candidates[:try_n]:
        tested += 1
        nodes = [cand]
        print(f"[flow] [{tested}] trying {_label(nodes)} ...", flush=True)
        g = _try_nodes(nodes, want_country)
        if g and g.get("egress"):
            alive_nodes.append(cand)
        else:
            dead_entries.add(_node_endpoint(cand))
        if g and g["verdict"]:
            print(f"[flow]     PASS {g['reason']} ({g['latency_ms']}ms)")
            passing.append(_record_pass(nodes, g))
            if len(passing) >= 3:
                break
        else:
            print(f"[flow]     fail: {(g or {}).get('reason', 'transport dead')}", flush=True)

    if passing or not allow_chain:
        return passing

    print("[flow] No single hop passed — engaging the two-hop chain layer (both directions)...")
    pool = candidates[:try_n]
    entries = (alive_nodes + [c for c in pool if _node_endpoint(c) not in dead_entries])[:4]
    if not entries:
        entries = pool[:3]
    tested_chains = set()

    def _chain_id(nodes):
        return tuple(_node_endpoint(n) for n in nodes)

    for cand in pool:
        for entry in entries:
            if _node_endpoint(entry) == _node_endpoint(cand):
                continue
            for nodes in ([cand, entry], [entry, cand]):
                if _node_endpoint(nodes[-1]) in dead_entries:
                    continue
                cid = _chain_id(nodes)
                if cid in tested_chains:
                    continue
                tested_chains.add(cid)
                tested += 1
                print(f"[flow] [{tested}] 2-hop chain {_label(nodes)} ...", flush=True)
                g = _try_nodes(nodes, want_country)
                if g and g["verdict"]:
                    print(f"[flow]     PASS {g['reason']} ({g['latency_ms']}ms)")
                    passing.append(_record_pass(nodes, g))
                    break
                reason = (g or {}).get("reason", "transport dead")
                print(f"[flow]     fail: {reason}", flush=True)
            if len(passing) >= 2:
                break
        if len(passing) >= 2:
            break

    if passing:
        return passing

    print("[flow] Two-hop layer insufficient — escalating to three-hop cascade...")
    hop_pool = pool[:min(6, len(pool))]
    for exit_n in hop_pool:
        for mid_n in hop_pool:
            if _node_endpoint(mid_n) == _node_endpoint(exit_n):
                continue
            for entry_n in entries[:3]:
                if _node_endpoint(entry_n) in (_node_endpoint(exit_n), _node_endpoint(mid_n)):
                    continue
                nodes = [exit_n, mid_n, entry_n]
                cid = _chain_id(nodes)
                if cid in tested_chains:
                    continue
                tested_chains.add(cid)
                tested += 1
                print(f"[flow] [{tested}] 3-hop chain {_label(nodes)} ...", flush=True)
                g = _try_nodes(nodes, want_country)
                if g and g["verdict"]:
                    print(f"[flow]     PASS {g['reason']} ({g['latency_ms']}ms)")
                    passing.append(_record_pass(nodes, g))
                    return passing
                reason = (g or {}).get("reason", "transport dead")
                print(f"[flow]     fail: {reason}", flush=True)
    return passing


def find_browser():
    cands = [
        os.environ.get("DASTYAB_BROWSER", ""),
        "/opt/google/chrome/google-chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        "/usr/bin/microsoft-edge",
        "/usr/bin/brave-browser",
    ]
    return next((c for c in cands if c and os.path.isfile(c) and os.access(c, os.X_OK)), None)


def browser_gate(timeout=150, profile_dir=None):
    ch = find_browser()
    if ch is None:
        return None, "no headless Chromium (verified via live TLS HTML shell on Android)"
    prof = profile_dir or os.path.join(_shim.tmp_dir(), f"dastyab-flow-gate-{os.getpid()}")
    args = [
        ch,
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        f"--proxy-server=socks5://127.0.0.1:{SOCK}",
        "--virtual-time-budget=12000",
        f"--user-data-dir={prof}",
        "--dump-dom",
        FLOW_URL,
    ]
    dom = ""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        dom = r.stdout or ""
    except subprocess.TimeoutExpired as e:
        dom = e.stdout or ""
        if isinstance(dom, bytes):
            dom = dom.decode("utf-8", "replace")
        if not dom:
            return None, "browser gate timed out before the page settled"
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"browser gate failed to run ({e})"
    finally:
        if profile_dir is None:
            shutil.rmtree(prof, ignore_errors=True)

    low = dom.lower()
    for marker in UNAVAILABLE_MARKERS:
        if marker in low:
            return False, f"ACCOUNT-GATE: {ACCOUNT_HELP} (shows '{marker}')"
    for marker in GATE_MARKERS:
        if marker in low:
            return False, f"REGION-GATE: Flow rejected this egress in the browser (shows '{marker}')"
    if len(dom) < 1000:
        return False, "browser rendered nothing (tunnel unusable for HTTPS)"
    if "aisandboxangularfrontend" not in low:
        return False, "browser did not render the Flow app"
    if "sign in" in low and "credits" not in low:
        return None, "region gate clear; pass signed-in profile to test account entitlement"
    return True, "browser loaded the Flow app (no region or account gate)"


def launch_browser(proxy_port=None):
    if _shim.is_android():
        _shim.emit_event(
            "OPEN_BROWSER",
            {"title": "Google Flow", "url": FLOW_URL, "proxy_port": proxy_port or SOCK},
        )
        print("[flow] Opening Google Flow inside DastYab Browser...")
        return
    p = _paths()
    ch = find_browser()
    if ch is None:
        print("[flow] No Chromium-based browser found.")
        print(f"[flow] Open {FLOW_URL} through socks5://127.0.0.1:{SOCK}")
        return
    os.makedirs(p["BROWSER_PROFILE"], exist_ok=True)
    subprocess.Popen(
        [
            ch,
            "--ozone-platform=x11",
            f"--proxy-server=socks5://127.0.0.1:{SOCK}",
            "--no-first-run",
            "--no-default-browser-check",
            f"--user-data-dir={p['BROWSER_PROFILE']}",
            FLOW_URL,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("[flow] Opened Flow in the dedicated tunnel-pinned browser.")


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


def _android_start_bridge(want_country=None):
    """Android multi-layer bridge: probes active VPN (Lantern) + progressive 1/2/3/4-hop proxy cascades against Flow gates."""
    p = _paths()
    print("[flow] Android CPython Core: probing Layer 0 (Lantern) + progressive multi-hop chains against Flow L3+L4+L5 gates...")
    results = _shim.discover_best_android_route(
        probe_gates, want_country=want_country, target_service="flow", max_candidates=44
    )
    best = None
    for route, g in results:
        scheme, host, port, label = route
        status_str = f"PASS {g['country']} {g['egress']} ({g['latency_ms']}ms)" if g["verdict"] else f"fail: {g['reason']}"
        print(f"   • {label}: {status_str}", flush=True)
        if g["verdict"] and (best is None or gate_score(g) < gate_score(best[1])):
            best = (route, g)

    if best is None:
        print(
            "[flow] No active Android route or multi-hop chain passed Flow's 151-country + HTTPS + shell gates.",
            file=sys.stderr,
        )
        print(
            "[flow] Tip: Harvest residential SOCKS5/HTTP hops, connect v2rayNG (:10808/:10809), or switch Lantern country.",
            file=sys.stderr,
        )
        return 3

    route, g = best
    scheme, host, port, label = route
    chain_hops = _route_to_chain_hops(route)
    hops_count = len(chain_hops)
    write_json_atomic(
        p["BRIDGEFILE"],
        {
            "scheme": scheme,
            "host": host if scheme != "chain" else "",
            "port": port,
            "hops": hops_count,
            "chain": chain_hops,
            "label": label,
            "egress": g["egress"],
            "country": g["country"],
        },
    )
    write_json_atomic(
        p["STATEFILE"],
        {
            "idx": 0,
            "hops": hops_count,
            "egress": g["egress"],
            "country": g["country"],
            "country_name": g["country_name"],
            "verified_epoch": time.time(),
            "route_label": label,
        },
    )
    _shim.emit_event(
        "SYNC_SERVICE_CHAIN",
        {
            "target_service": "flow",
            "chain": chain_hops,
            "label": label,
            "egress": g["egress"],
            "country": g["country"],
        },
    )
    print(f"[flow] Verified route ({hops_count}-hop): {label}")
    print(f"[flow] {g['reason']}")
    launch_browser(proxy_port=port if scheme in ("http", "socks5") and port > 0 else None)
    return 0


def cmd_start(index=None, hops=1, want_country=None):
    p = _paths()
    if is_running():
        print(f"[flow] Tunnel already active on 127.0.0.1:{SOCK}")
        bridge = read_json(p["BRIDGEFILE"], {})
        bport = bridge.get("port")
        launch_browser(proxy_port=bport if isinstance(bport, int) and bport > 0 else None)
        return 0

    if _find_xray_optional() is None and _shim.is_android():
        return _android_start_bridge(want_country=want_country)

    pool = load_pool()
    if not pool:
        print("[flow] No ranked pool yet — scanning candidates first ...")
        passing = scan(load_candidates(), want_country, try_n=10)
        if not passing:
            print("[flow] No candidate passed the gates. Widen the scan: dastyab flow best --try 25", file=sys.stderr)
            return 3
        save_pool(passing)
        pool = load_pool()

    first = (index or 0) % len(pool)
    order = [first] + [(first + off) % len(pool) for off in range(1, len(pool))]
    for idx in order:
        route = pool[idx]
        nodes = route["nodes"]
        if hops == 1 and len(nodes) > 1:
            nodes = nodes[:1]
        print(f"[flow] Bringing up {_label(nodes)} ...")
        pid = bring_up(nodes)
        if pid is None:
            print("[flow] transport dead, next node", flush=True)
            continue
        g = probe_gates(want_country)
        if g["verdict"]:
            print(f"[flow] Tunnel up (pid {pid}) via {_label(nodes)}")
            print(f"[flow] SOCKS5: 127.0.0.1:{SOCK} | {g['reason']}")
            write_json_atomic(
                p["STATEFILE"],
                {
                    "idx": idx,
                    "hops": len(nodes),
                    "egress": g["egress"],
                    "country": g["country"],
                    "country_name": g["country_name"],
                    "verified_epoch": time.time(),
                },
            )
            with open(p["IDXFILE"], "w") as fh:
                fh.write(str(idx))
            launch_browser()
            return 0
        stop(quiet=True)
        print(f"[flow] gate fail: {g['reason']} — rotating", flush=True)

    print("[flow] Every route in the pool failed the gates live.", file=sys.stderr)
    return 3


def cmd_next():
    p = _paths()
    state = read_json(p["STATEFILE"], {})
    pool = load_pool()
    if not pool:
        print("[flow] No pool to rotate through. Run: dastyab flow best")
        return 3
    idx = (state.get("idx", 0) + 1) % len(pool)
    print(f"[flow] Rotating to route {idx + 1}/{len(pool)}")
    stop(quiet=True)
    return cmd_start(index=idx)


def cmd_stop():
    stop()
    return 0


def cmd_status():
    p = _paths()
    xray = _find_xray_optional()
    print(f"[flow] xray core: {xray or 'Not installed (Android Multi-Layer Bridge active)'}")
    print(f"[flow] SOCKS port: 127.0.0.1:{SOCK} | profile: {p['PROFILE_DIR']}")
    if _shim.is_android() and not xray:
        results = _shim.discover_best_android_route(
            probe_gates, target_service="flow", max_candidates=44
        )
        any_ok = False
        for route, g in results:
            verdict = "PASS" if g["verdict"] else "FAIL"
            print(f"[flow]   {route[3]} -> {verdict}: {g['reason']}")
            if g["verdict"]:
                any_ok = True
        return 0 if any_ok else 1

    if not is_running():
        state = read_json(p["STATEFILE"], {})
        if state:
            age = int(time.time() - state.get("verified_epoch", 0))
            print(f"[flow] Tunnel DOWN. Last route {state.get('country')} / {state.get('egress')} ({age // 60}m ago)")
        else:
            print("[flow] Tunnel DOWN. Start with: dastyab flow start")
        return 1
    g = probe_gates()
    if g["verdict"]:
        print(f"[flow] Tunnel UP. {g['reason']}")
        return 0
    print(f"[flow] Tunnel UP but gates FAIL: {g['reason']}")
    return 1


def cmd_verify(want_country=None):
    if _find_xray_optional() is None and _shim.is_android():
        return cmd_best(try_n=15, want_country=want_country)
    pool = load_pool()
    if not pool:
        print("[flow] No saved pool. Run: dastyab flow best")
        return 1
    print(f"[flow] {len(pool)} saved route(s) — re-probing each live:")
    alive = 0
    for i, route in enumerate(pool):
        nodes = route["nodes"]
        g = _try_nodes(nodes, want_country)
        if g and g["verdict"]:
            alive += 1
            print(f"   [{i}] {_label(nodes)}  OK  {g['country']} {g['egress']} ({g['latency_ms']}ms)")
        else:
            print(f"   [{i}] {_label(nodes)}  DEAD  {(g or {}).get('reason', 'transport dead')}")
    print(f"[flow] {alive}/{len(pool)} routes still pass the gates.")
    return 0 if alive else 3


def cmd_best(try_n=10, want_country=None):
    p = _paths()
    xray = _find_xray_optional()
    cands = load_candidates()

    if xray is None and _shim.is_android():
        print("[flow] Step 1/2: Probing Layer 0 (Lantern) + progressive multi-hop chains against Flow gates...")
        results = _shim.discover_best_android_route(
            probe_gates, want_country=want_country, target_service="flow", max_candidates=44
        )
        best_android = None
        for route, g in results:
            mark = f"PASS {g['country']} {g['egress']} ({g['latency_ms']}ms)" if g["verdict"] else f"FAIL ({g['reason']})"
            print(f"   • {route[3]} -> {mark}", flush=True)
            if g["verdict"] and (best_android is None or gate_score(g) < gate_score(best_android[1])):
                best_android = (route, g)
        if best_android is not None:
            b_route, b_g = best_android
            _shim.emit_event(
                "SYNC_SERVICE_CHAIN",
                {
                    "target_service": "flow",
                    "chain": _route_to_chain_hops(b_route),
                    "label": b_route[3],
                    "egress": b_g["egress"],
                    "country": b_g["country"],
                },
            )

        print(f"[flow] Step 2/2: Benchmarking {min(len(cands), try_n)} harvested VLESS nodes (TCP+TLS latency)...")
        reachable = []
        for idx, srv in enumerate(cands[:try_n], 1):
            ms = _shim.probe_vless_node_transport(srv, timeout=2.5)
            status_s = f"OK ({ms}ms)" if ms is not None else "DEAD"
            print(f"   [{idx}] {srv['proto']} {srv['addr']}:{srv['port']}  {status_s}", flush=True)
            if ms is not None:
                reachable.append((ms, srv))
        reachable.sort(key=lambda item: item[0])
        if reachable:
            pool_entries = [
                {
                    "nodes": [srv],
                    "egress": "tls-verified",
                    "country": want_country or "??",
                    "country_name": "Pending xray",
                    "proxy": False,
                    "hosting": False,
                    "latency_ms": ms,
                    "checked_epoch": time.time(),
                }
                for ms, srv in reachable[:6]
            ]
            write_json_atomic(p["FLOW_POOL"], pool_entries)
            top_uri = _shim.vless_dict_to_uri(reachable[0][1])
            if top_uri:
                _shim.emit_event(
                    "SYNC_BEST_VLESS",
                    {"uri": top_uri, "latency_ms": reachable[0][0]},
                )
            print(f"[flow] Ranked {len(pool_entries)} fastest VLESS endpoint(s) -> {p['FLOW_POOL']}")
        return 0 if (any(g["verdict"] for _, g in results) or reachable) else 3

    if not cands:
        print("[flow] No candidates found in any source (pool, nekoray, nodes.json).", file=sys.stderr)
        return 3
    print(f"[flow] {len(cands)} candidate(s) from all sources; testing up to {try_n} for the gates ...")
    passing = scan(cands, want_country, try_n=try_n)
    if not passing:
        print("[flow] Nothing passed.", file=sys.stderr)
        return 3
    passing.sort(key=lambda r: (0 if not r["proxy"] else 1, 0 if not r["hosting"] else 1, r["latency_ms"]))
    save_pool(passing)
    print(f"[flow] Ranked pool saved ({len(passing)} route(s)) -> {p['FLOW_POOL']}")
    for i, r in enumerate(passing):
        print(f"   [{i}] {r['country']} {r['egress']} ({r['latency_ms']}ms)")
    return 0


def cmd_watch(interval=30):
    p = _paths()
    print(f"[flow] Watchdog started: probing every {interval}s")
    fails = 0
    while True:
        try:
            g = probe_gates() if is_running() else None
            if g and g["verdict"]:
                fails = 0
            elif g is None:
                cmd_start(index=read_json(p["STATEFILE"], {}).get("idx", 0))
                fails = 0
            else:
                fails += 1
                print(f"[flow] gate fail ({fails}): {g['reason']}", file=sys.stderr)
                if fails >= 2:
                    cmd_next()
                    fails = 0
            time.sleep(interval)
        except KeyboardInterrupt:
            print("[flow] Watchdog stopped.")
            return 0


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
        raise SystemExit(f"[flow] No such URI/config file: {path}")
    try:
        with open(path, "rb") as bfh:
            raw_bytes = bfh.read()
    except OSError as e:
        raise SystemExit(f"[flow] Cannot read {path}: {e}")
    uris, seen = [], set()
    for u in parse_config_file_bytes(path, raw_bytes):
        key = (u["addr"], u["port"], u.get("proto", "vless"))
        if key not in seen:
            seen.add(key)
            uris.append(u)
    return uris


def cmd_build_pool(uris_txt, want=6, entry_spec=None):
    uris = _load_nodes_from_file(uris_txt)
    if not uris:
        raise SystemExit(f"[flow] No proxy URIs found in {uris_txt}")
    entry_node = _resolve_entry_arg(entry_spec) if entry_spec else None
    probe_limit = max(len(uris), want) if len(uris) <= 200 else 200
    print(f"[flow] {len(uris)} unique URI(s); testing up to {probe_limit} ...")
    has_xray = _find_xray_optional() is not None
    passing = []
    for u in uris[:probe_limit]:
        nodes = [u, entry_node] if entry_node else [u]
        if has_xray:
            g = _try_nodes(nodes)
            if g and g["verdict"]:
                print(f"   {u['addr']}:{u['port']}  OK  {g['country']} {g['egress']}", flush=True)
                passing.append(
                    {
                        "nodes": nodes,
                        "fragment": bool(entry_node),
                        "egress": g["egress"],
                        "country": g["country"],
                        "country_name": g["country_name"],
                        "proxy": g["proxy"],
                        "hosting": g["hosting"],
                        "latency_ms": g["latency_ms"],
                        "checked_epoch": time.time(),
                    }
                )
            else:
                print(f"   {u['addr']}:{u['port']}  DEAD  {(g or {}).get('reason', 'transport dead')}", flush=True)
        else:
            ms = _shim.probe_vless_node_transport(u, timeout=2.5)
            if ms is not None:
                print(f"   {u['addr']}:{u['port']}  OK  tls {ms}ms", flush=True)
                passing.append(
                    {
                        "nodes": nodes,
                        "fragment": bool(entry_node),
                        "egress": "tls-verified",
                        "country": "??",
                        "country_name": "Pending xray",
                        "proxy": False,
                        "hosting": False,
                        "latency_ms": ms,
                        "checked_epoch": time.time(),
                    }
                )
            else:
                print(f"   {u['addr']}:{u['port']}  DEAD", flush=True)
        if len(passing) >= want:
            break
    save_pool(passing)
    print(f"[flow] Built pool: {len(passing)} route(s) -> {_paths()['FLOW_POOL']}")


def cmd_prove(tries=6, want_country=None, profile=None):
    ch = find_browser()
    if ch is None:
        print("[flow] Android Proof Check: running live L3+L4+L5 gate verification & opening DastYab Browser...")
        return _android_start_bridge(want_country=want_country)
    print(f"[flow] Proving Flow access with headless browser ({ch})")
    cands = load_candidates()
    if not cands:
        print("[flow] No candidates in any source.", file=sys.stderr)
        return 3
    for i, cand in enumerate(cands[:tries], 1):
        pid = bring_up([cand])
        if pid is None:
            continue
        try:
            g = probe_gates(want_country, browser_profile=profile)
            if g["verdict"] and g.get("browser_ok"):
                print(f"[flow] PROVEN egress {g['egress']} ({g['country']}) {g['latency_ms']}ms")
                return 0
        finally:
            stop(quiet=True)
    return 3


def cmd_countries():
    codes = sorted(SUPPORTED_COUNTRIES)
    print(
        f"[flow] Google Flow is officially available in {len(codes)} "
        "countries/territories (per support.google.com, fetched 2026-11-16):"
    )
    for i in range(0, len(codes), 16):
        print("   " + " ".join(codes[i : i + 16]))
    print("[flow] Filter egress with: dastyab flow start --country XX")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="dastyab-flow.py",
        description="Multi-layer access to Google Flow (flow.google.com).",
    )
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("start", help="tunnel + open Flow (default)")
    p.add_argument("index", nargs="?", type=int, default=None)
    p.add_argument("--hops", type=int, default=1, choices=(1, 2))
    p.add_argument("--country", default=None)

    sub.add_parser("next", help="rotate to the next ranked route")
    sub.add_parser("stop", help="stop the tunnel")
    sub.add_parser("status", help="current egress + gate verdict")

    p = sub.add_parser("verify", help="re-probe every saved route")
    p.add_argument("--country", default=None)

    p = sub.add_parser("best", help="scan candidates wider, re-rank the pool")
    p.add_argument("--try", dest="try_n", type=int, default=10)
    p.add_argument("--country", default=None)
    p.add_argument("--entry", default=None)

    p = sub.add_parser("watch", help="self-healing watchdog")
    p.add_argument("interval", nargs="?", type=int, default=30)

    p = sub.add_parser("build-pool", help="build the pool from .txt or any config file")
    p.add_argument("uris", help="file with share URIs, Clash YAML, WireGuard, Sing-Box, or .npv*/.ovpn/.txt")
    p.add_argument("--entry", default=None, help="optional PattNG entry proxy/WARP URI or file")

    p = sub.add_parser("ingest", help="parse and save all nodes from .txt or any config file")
    p.add_argument("uris", help="path to .txt, .sub, .yaml, .json, .conf, .ovpn, .npvt, etc.")
    p.add_argument("--entry", default=None, help="optional PattNG entry proxy/WARP URI or file")

    p = sub.add_parser("prove", help="prove Flow access live")
    p.add_argument("--try", dest="try_n", type=int, default=6)
    p.add_argument("--country", default=None)
    p.add_argument("--profile", default=None)

    sub.add_parser("countries", help="show Google's supported-country list")

    raw_args = sys.argv[1:] if argv is None else list(argv)
    if not raw_args:
        raw_args = ["start"]
    a = ap.parse_args(args=raw_args)
    cmd = (a.cmd or "start").lower()

    if cmd == "start":
        return cmd_start(a.index, a.hops, a.country)
    if cmd == "next":
        return cmd_next()
    if cmd == "stop":
        return cmd_stop()
    if cmd == "status":
        return cmd_status()
    if cmd == "verify":
        return cmd_verify(a.country)
    if cmd == "best":
        return cmd_best(a.try_n, a.country)
    if cmd == "watch":
        return cmd_watch(a.interval)
    if cmd == "build-pool":
        cmd_build_pool(a.uris, entry_spec=getattr(a, "entry", None))
        return 0
    if cmd == "ingest":
        nodes = _load_nodes_from_file(a.uris)
        if not nodes:
            raise SystemExit(f"[flow] No proxy URIs found in {a.uris}")
        en = _resolve_entry_arg(getattr(a, "entry", None))
        entries = [
            {
                "nodes": [u, en] if en else [u],
                "fragment": bool(en),
                "egress": "pending",
                "country": "??",
                "country_name": "Imported",
                "proxy": False,
                "hosting": False,
                "latency_ms": 0,
                "checked_epoch": time.time(),
            }
            for u in nodes
        ]
        save_pool(entries)
        print(f"[flow] Imported {len(entries)} route(s) from {a.uris} -> {_paths()['FLOW_POOL']}")
        return 0
    if cmd == "prove":
        return cmd_prove(a.try_n, a.country, a.profile)
    if cmd == "countries":
        cmd_countries()
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main() or 0)
