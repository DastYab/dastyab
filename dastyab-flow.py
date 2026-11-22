#!/usr/bin/env python3
"""
dastyab flow (Warrior / Brutal Eagle Engine) — ultra-strict, multi-layer
anti-geoblock access to Google Flow (flow.google.com).

LAYERS (Warrior Algorithm):
  L0 supply    — union of flow_pool.json, fresh_vless.json, Nekoray/Sing-Box/
                 Clash/v2rayN/OpenVPN stores, ~/Downloads & DastYab vault files
                 (.npv/.npvt/.npvs/.ovpn/.conf/.wg/.hc/.ehi/.json/.yaml/.sub/
                 .txt), multi-protocol URIs (vless/vmess/trojan/ss/wireguard/
                 hy2/tuic/socks5/http), AND live local proxy bridges (Tor 9050,
                 WARP 40000, WireProxy 40001, Clash 7890, Sing-Box 2080, xray
                 10808, Hiddify 12334, Psiphon 1081).
  L1 transport — xray + optional sing-box sidecar outbounds (vless, vmess,
                 trojan, ss, wireguard, hy2, tuic, socks, http) + uTLS
                 fingerprint mutation + DoH routing.
  L2 DPI-desync— xray `freedom` TLS-Hello packet fragmentation (`tlshello`,
                 length 10-30, interval 10-20) underneath the entry hop to
                 shatter SNI inspection & RST injection.
  L3 cascade   — 1..8 hop chains via `sockopt.dialerProxy` across distinct `/16`
                 subnets + bidirectional swaps + local-proxy carriers: nodes
                 in non-Flow regions/WARP become Entry/Relay hops for clean
                 supported-country Exits!
  L4 Warrior   — official 151-country Flow gate + Cloudflare `/cdn-cgi/trace`
     geo+ASN     (`warp=off` enforced!) + multi-provider Geo/ASN reputation
                 scoring + flow.google.com (`AiSandboxAngularFrontend`) +
                 labs.google/fx/tools/flow + accounts.google.com + browser DOM.
  L5 bandit    — UCB1 route selection + isolated `flow_blacklist.json` (TTL
                 blocked exits are excluded as exits, retained as relays).
  L6 browser   — hardened Chrome pinned to SOCKS5 with `--host-resolver-rules`
                 anti-DNS-leak, `--force-webrtc-ip-handling-policy=
                 disable_non_proxied_udp`, and country-aligned TZ / `--lang`.

USAGE:
  dastyab-flow.py start [idx] [--hops 1..8] [--country XX] [--brutal]
  dastyab-flow.py next / stop / status / verify / countries
  dastyab-flow.py best [--try N] [--hops 1..8] [--country XX] [--strict]
  dastyab-flow.py prove [--try N] [--hops 1..8] [--country XX] [--profile DIR]
  dastyab-flow.py watch [secs] / build-pool <uris.txt>
"""
import argparse
import base64
import glob
import json
import math
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse

HOME = os.path.expanduser("~")
PROFILE_DIR = os.path.join(HOME, ".dastyab/profiles/default")
FLOW_POOL = os.path.join(PROFILE_DIR, "flow_pool.json")
AISTUDIO_POOL = os.path.join(PROFILE_DIR, "fresh_vless.json")
NODES_JSON = os.path.join(PROFILE_DIR, "nodes.json")
NEKORAY_PROFILES = os.path.join(HOME, ".config/nekoray/config/profiles")
WARRIOR_BLACKLIST = os.path.join(PROFILE_DIR, "flow_blacklist.json")
WARRIOR_BANDIT = os.path.join(PROFILE_DIR, "flow_bandit.json")

SOCK = int(os.environ.get("DASTYAB_FLOW_SOCKS", "10860"))
PIDFILE = "/tmp/dastyab_flow.pid"
CFGPATH = "/tmp/dastyab_flow.json"
IDXFILE = "/tmp/dastyab_flow_idx"
STATEFILE = "/tmp/dastyab_flow_state.json"
BROWSER_PROFILE = os.path.join(HOME, ".dastyab-flow-profile")

FLOW_URL = "https://flow.google.com/"
LABS_FLOW_URL = "https://labs.google/fx/tools/flow"
ACCOUNTS_URL = "https://accounts.google.com/"
CF_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"

GATE_MARKERS = ("unsupported-country-title",
                "not available in your country yet",
                "flow is not available in your country")
UNAVAILABLE_MARKERS = ("unavailable-title",
                       "don't have access to flow",
                       "dont have access to flow",
                       "do not have access to flow")
ACCOUNT_HELP = (
    "Flow's account gate. Per support.google.com/flow/answer/16353333 you "
    "need ALL of: (1) age verified, 18+; (2) a supported region; "
    "(3) Google AI Plus/Pro/Ultra (or a qualifying Workspace plan). "
    "The tunnel only satisfies (2)."
)
IPIFY = "https://api.ipify.org"
IPAPI = "http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,proxy,hosting,mobile"

HOSTING_KEYWORDS = (
    "hetzner", "ovh", "digitalocean", "contabo", "vultr", "linode", "akamai",
    "amazon", "aws", "google cloud", "microsoft azure", "oracle", "m247",
    "datacamp", "leaseweb", "quadranet", "tzulo", "choopa", "scaleway",
    "kamatera", "hostinger", "alicloud", "alibaba", "tencent", "frantech",
)
RESIDENTIAL_KEYWORDS = (
    "telekom", "comcast", "verizon", "at&t", "vodafone", "orange",
    "telefonica", "charter", "cox ", "ntt", "kddi", "softbank",
    "british telecom", "rogers", "bell canada", "telstra", "singtel",
    "swisscom", "telenor", "telia",
)

LOCAL_PROXY_PORTS = (
    (9050, "socks", "tor-local"),
    (9150, "socks", "tor-browser"),
    (40000, "socks", "warp-local"),
    (40001, "socks", "wireproxy-40001"),
    (10808, "socks", "xray-10808"),
    (10809, "http", "xray-http-10809"),
    (2080, "socks", "nekoray-2080"),
    (2081, "http", "nekoray-http-2081"),
    (7890, "http", "clash-7890"),
    (7891, "socks", "clash-socks-7891"),
    (12334, "socks", "hiddify-12334"),
    (10853, "socks", "dastyab-10853"),
    (1080, "socks", "socks-1080"),
    (1081, "socks", "psiphon-socks-1081"),
    (8080, "http", "http-8080"),
    (8118, "http", "privoxy-8118"),
)

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
MUTABLE_FPS = ("chrome", "firefox", "random", "safari")
_SIDECAR_PROCS = []

COUNTRY_LOCALE_TZ = {
    "DE": ("de-DE", "Europe/Berlin"),
    "GB": ("en-GB", "Europe/London"),
    "FR": ("fr-FR", "Europe/Paris"),
    "NL": ("nl-NL", "Europe/Amsterdam"),
    "SG": ("en-SG", "Asia/Singapore"),
    "JP": ("ja-JP", "Asia/Tokyo"),
    "CA": ("en-CA", "America/Toronto"),
    "AE": ("en-AE", "Asia/Dubai"),
    "TR": ("tr-TR", "Europe/Istanbul"),
    "US": ("en-US", "America/New_York"),
}

# Google's official "Where you can use Google Flow" list, as ISO-3166
# alpha-2 codes. Fetched 2026-11-16 from:
#   https://support.google.com/flow/answer/16353544?hl=en
# Refresh this set when Google expands the rollout; the gate is only as
# honest as the list it checks against.
SUPPORTED_COUNTRIES = frozenset("""
AL DZ AS AO AG AR AM AW AU AT AZ BS BH BD BE BZ BJ BM BO BA BW BR BG BF
CV KH CM CA KY CL CO CR CI HR CY CZ DK DO EC EG SV EE FJ FI FR GA DE GH
GI GR GU GT GW HT HN HK HU IS IN ID IQ IE IL IT JM JP JO KZ KE KW KG LA
LV LB LI LT LU MO MY MV ML MT MU MX MD MC MA MZ NA NP NL NZ NI NE NG MK
MP NO OM PK PW PA PG PY PE PH PL PT PR QA RO RW SM SA SN RS SC SL SG SK
SI ZA KR ES LK SE CH TW TJ TZ TH TG TO TT TN TR TM VI UG UA AE GB US UY
UZ VE VN VG YE ZM ZW
""".split())


# ---------------------------------------------------------------------------
# xray core discovery
# ---------------------------------------------------------------------------

_XRAY_VERSION = None


def find_xray():
    """Locate a real xray/v2ray core."""
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.environ.get("DASTYAB_XRAY", ""),
        os.path.join(here, "xray"),
        os.path.join(HOME, ".dastyab/bin/xray"),
        "/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray",
        "/tmp/xraybin/xray",
        "/opt/v2rayN/bin/xray/xray",
    ]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            if _is_real_xray(c):
                return c
    for name in ("xray", "v2ray"):
        for d in os.environ.get("PATH", "").split(os.pathsep):
            p = os.path.join(d, name) if d else ""
            if p and os.path.isfile(p) and os.access(p, os.X_OK):
                if _is_real_xray(p):
                    return p
    raise SystemExit(
        "[flow] No xray core found. Install xray and put it on PATH, or set "
        "DASTYAB_XRAY=/path/to/xray"
    )


def _is_real_xray(path):
    """True if `path version` identifies itself as a usable xray/v2ray core."""
    try:
        out = subprocess.run([path, "version"], capture_output=True, text=True,
                             timeout=8).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    if "NekoRay" in out or "NekoBox" in out:
        return False
    return bool(re.search(r"(Xray|V2Ray)\s+\d+\.\d+", out))


def xray_supports_vision():
    """True if the resolved core is xray >= 1.7 (vision/XTLS support)."""
    global _XRAY_VERSION
    if _XRAY_VERSION is None:
        _XRAY_VERSION = ""
        try:
            out = subprocess.run([find_xray(), "version"],
                                 capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"Xray\s+(\d+)\.(\d+)", out)
            if m:
                _XRAY_VERSION = f"{m.group(1)}.{m.group(2)}"
        except (SystemExit, OSError, subprocess.SubprocessError):
            _XRAY_VERSION = ""
    if not _XRAY_VERSION:
        return False
    major, minor = (int(x) for x in _XRAY_VERSION.split("."))
    return (major, minor) >= (1, 7)


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def read_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def write_json_atomic(path, obj):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=1)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# L0 — node supply & multi-protocol parsers
# ---------------------------------------------------------------------------

def parse_vless(line):
    """Parse one `vless://` share URI into a Server dict (or None)."""
    line = line.split("#")[0].strip()
    m = re.match(r"vless://([^@]*)@([^:]+):(\d+)\?(.*)", line)
    if not m:
        return None
    uuid_, host, port, qs = m.group(1), m.group(2), int(m.group(3)), m.group(4)
    if not uuid_ or not host:
        return None
    return {"proto": "vless", "uuid": uuid_, "addr": host, "port": port,
            "q": dict(urllib.parse.parse_qsl(qs))}


def _b64_decode(raw):
    raw = re.sub(r"\s+", "", raw or "").replace("-", "+").replace("_", "/")
    pad = (-len(raw)) % 4
    return base64.b64decode(raw + "=" * pad)


def is_non_proxy_http_url(raw):
    """Reject Telegram/GitHub/webpage http(s):// links so they are never treated as HTTP proxies."""
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
    """Parse proxy URIs (`vless`, `vmess`, `trojan`, `ss`, `wireguard`, `hy2`, `tuic`, `socks5`, `http`)."""
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
            return {"proto": "ss", "addr": host, "port": port,
                    "method": method, "password": pw, "q": {}}
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
        return {"proto": "wireguard", "addr": host, "port": port,
                "secret": urllib.parse.unquote(priv), "q": q}
    if low.startswith(("hysteria2://", "hy2://")):
        body = s.split("#")[0].split("://", 1)[1]
        if "@" not in body:
            return None
        pw, hpq = body.split("@", 1)
        hp, qs = (hpq.split("?", 1) + [""])[:2]
        host, port = _parse_host_port(hp)
        if not pw or not host:
            return None
        return {"proto": "hy2", "addr": host, "port": port,
                "password": urllib.parse.unquote(pw),
                "q": dict(urllib.parse.parse_qsl(qs))}
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
        return {"proto": "tuic", "addr": host, "port": port,
                "uuid": urllib.parse.unquote(uid),
                "password": urllib.parse.unquote(pw),
                "q": dict(urllib.parse.parse_qsl(qs))}
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
    """Parse WireGuard INI (`[Interface]` + `[Peer]`) into uniform node dicts."""
    if "[interface]" not in text.lower() or "[peer]" not in text.lower():
        return []
    out = []
    for block in re.split(r"(?=\[Interface\])", text, flags=re.IGNORECASE):
        if "[peer]" not in block.lower():
            continue
        sec, priv, addr, mtu, pub = "", "", "", "1280", ""
        host, port = None, None
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
                "proto": "wireguard", "addr": host, "port": port,
                "secret": priv,
                "q": {"publickey": pub, "address": addr or "172.16.0.2/32", "mtu": mtu},
            })
    return out


def _extract_ovpn_proxy_nodes(text):
    """Extract upstream `http-proxy` / `socks-proxy` relays from `.ovpn` files."""
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        parts = line.split()
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
        return {"proto": "ss", "addr": host, "port": port,
                "method": vals.get("cipher", "aes-256-gcm"), "password": vals["password"], "q": {}}
    if t == "wireguard" and vals.get("private-key") and vals.get("public-key"):
        return {"proto": "wireguard", "addr": host, "port": port,
                "secret": vals["private-key"],
                "q": {"publickey": vals["public-key"], "address": vals.get("ip", "172.16.0.2/32")}}
    if t in ("hy2", "hysteria2") and vals.get("password"):
        return {"proto": "hy2", "addr": host, "port": port, "password": vals["password"],
                "q": {"sni": vals.get("sni", "")}}
    if t == "tuic" and vals.get("uuid"):
        return {"proto": "tuic", "addr": host, "port": port, "uuid": vals["uuid"],
                "password": vals.get("password", ""), "q": {"sni": vals.get("sni", "")}}
    if t in ("socks5", "http"):
        return {"proto": "socks" if t == "socks5" else "http", "addr": host, "port": port, "q": {}}
    return None


def _extract_clash_yaml_nodes(text):
    """Lightweight stdlib Clash/Mihomo `proxies:` extractor (inline `{...}` & multi-line blocks)."""
    if "proxies:" not in text or "server:" not in text:
        return []
    out = []
    kv_re = re.compile(r"([A-Za-z0-9_-]+)\s*:\s*(\"[^\"]*\"|'[^']*'|[^,\}\n#]+)")
    lines = text.splitlines()
    in_proxies = False
    cur = {}
    for raw in lines:
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
                vals = {k.lower(): v.strip().strip("\"'") for k, v in kv_re.findall(after)}
                node = _clash_vals_to_node(vals)
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
    """Extract Sing-Box, Xray, and Clash/v2rayN JSON outbound nodes."""
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
                            "q": {"security": "tls" if tls_o.get("enabled") else "none",
                                  "sni": tls_o.get("server_name", "")}})
            elif t == "vmess" and ob.get("uuid"):
                tls_o = ob.get("tls") or {}
                out.append({"proto": "vmess", "addr": host, "port": int(port), "uuid": ob["uuid"],
                            "q": {"security": "tls" if tls_o.get("enabled") else "none",
                                  "sni": tls_o.get("server_name", "")}})
            elif t == "trojan" and ob.get("password"):
                out.append({"proto": "trojan", "addr": host, "port": int(port),
                            "password": ob["password"], "q": {"security": "tls"}})
            elif t in ("shadowsocks", "ss") and ob.get("password"):
                out.append({"proto": "ss", "addr": host, "port": int(port),
                            "method": ob.get("method", "aes-256-gcm"),
                            "password": ob["password"], "q": {}})
            elif t == "wireguard" and ob.get("private_key") and ob.get("peer_public_key"):
                out.append({"proto": "wireguard", "addr": host, "port": int(port),
                            "secret": ob["private_key"], "q": {"publickey": ob["peer_public_key"]}})
            elif t in ("hy2", "hysteria2") and ob.get("password"):
                out.append({"proto": "hy2", "addr": host, "port": int(port),
                            "password": ob["password"], "q": {}})
            elif t == "tuic" and ob.get("uuid"):
                out.append({"proto": "tuic", "addr": host, "port": int(port),
                            "uuid": ob["uuid"], "password": ob.get("password", ""), "q": {}})
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
                out.append({"proto": "wireguard", "addr": hp[0], "port": hp[1],
                            "secret": sett["secretKey"],
                            "q": {"publickey": peer["publicKey"],
                                  "address": ",".join(addrs) if isinstance(addrs, list) else str(addrs)}})
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
    """Unpack multi-format VPN/proxy configs (.txt, .npv*, .ovpn, .conf/.wg/.awg, .hc/.ehi, .json, .yaml, .sub)."""
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
        cleaned = m.rstrip(",;.)]}\u200c\u200d\u200e\u200f")
        u = parse_node_uri(cleaned)
        if u:
            nodes.append(u)
    nodes.extend(_extract_wg_ini_nodes(corpus))
    nodes.extend(_extract_ovpn_proxy_nodes(corpus))
    nodes.extend(_extract_clash_yaml_nodes(corpus))

    if ext in (".json", ".jsonc", ".sbox", ".singbox", ".nekobox", ".hiddify", ".xray", ".v2ray") or raw_txt.lstrip().startswith(("{", "[")):
        nodes.extend(_extract_json_nodes(raw_txt))

    seen, unique = set(), []
    for n in nodes:
        k = (n.get("proto"), n.get("addr"), n.get("port"),
             n.get("uuid") or n.get("password") or n.get("secret") or "")
        if k not in seen:
            seen.add(k)
            unique.append(n)
    return unique


def gather_multi_format_candidates(dirs=None):
    """Scan local vaults, Downloads, and third-party VPN client dirs for multi-format configs."""
    cur_home = os.environ.get("HOME") or HOME
    cur_prof = PROFILE_DIR if cur_home == HOME else os.path.join(cur_home, ".dastyab/profiles/default")
    scan_dirs = list(dirs) if dirs is not None else [
        cur_prof,
        os.path.join(cur_prof, "imports"),
        os.path.join(cur_prof, "downloads"),
        os.path.join(cur_prof, "harvested"),
        os.path.join(cur_home, ".dastyab/vault"),
        os.path.join(cur_home, "Downloads"),
        os.path.join(cur_home, ".config/sing-box"),
        os.path.join(cur_home, ".config/clash"),
        os.path.join(cur_home, ".config/mihomo"),
        os.path.join(cur_home, ".config/v2rayN"),
        os.path.join(cur_home, ".config/openvpn"),
    ]
    extra_env = os.environ.get("DASTYAB_CONFIG_DIRS", "")
    if extra_env and dirs is None:
        scan_dirs.extend(p for p in extra_env.split(os.pathsep) if p)

    collected = []
    for d in scan_dirs:
        if not d or not os.path.isdir(d):
            continue
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for fname in entries[:500]:
            if fname.lower() in NOISE_CONFIG_FILENAMES:
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext not in MULTI_FORMAT_EXTS:
                continue
            fpath = os.path.join(d, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                if os.path.getsize(fpath) > MAX_CONFIG_FILE_BYTES:
                    continue
                with open(fpath, "rb") as fh:
                    collected.extend(parse_config_file_bytes(fname, fh.read()))
            except OSError:
                continue
    return collected


def _bean_to_server(bean, typ):
    """Convert a nekoray bean dict into the uniform Server shape."""
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
    srv = {"proto": typ, "addr": bean["addr"], "port": int(bean["port"]),
           "q": q, "name": bean.get("name", "")}
    if typ in ("vless", "vmess"):
        srv["uuid"] = bean.get("pass", "")
    else:
        srv["password"] = bean.get("pass", "")
        if typ in ("ss", "shadowsocks"):
            srv["method"] = bean.get("method", "aes-256-gcm")
    return srv


def subnet_prefix16(addr):
    parts = str(addr).split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}"
    return str(addr).lower()


def node_key(srv):
    return f"{srv.get('proto', 'vless')}:{srv['addr']}:{int(srv['port'])}"


def mutate_fp(srv, fp):
    """Return a shallow copy of `srv` with uTLS fingerprint `fp`."""
    cloned = dict(srv)
    q = dict(srv.get("q") or {})
    q["fp"] = fp
    cloned["q"] = q
    return cloned


def discover_local_proxies(timeout=0.18):
    """Detect local Tor/WARP/Clash/Sing-Box/Nekoray listeners usable as entry hops."""
    found = []
    for port, proto, label in LOCAL_PROXY_PORTS:
        if port == SOCK:
            continue
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            found.append({
                "proto": proto, "addr": "127.0.0.1", "port": port,
                "local": True, "name": label, "q": {},
            })
        except OSError:
            pass
        finally:
            s.close()
    return found


def load_candidates(limit=4096):
    """Union every node source & multi-format vault, dedup by (addr, port), best-first."""
    out, seen = [], set()

    def add(srv):
        if not srv or not srv.get("addr") or not srv.get("port"):
            return
        if "nodes" in srv and isinstance(srv["nodes"], list):
            for n in srv["nodes"]:
                add(n)
            return
        key = (str(srv["addr"]), int(srv["port"]))
        if key in seen:
            return
        seen.add(key)
        out.append(srv)

    for e in read_json(FLOW_POOL, []):
        if isinstance(e, dict) and ("addr" in e or "nodes" in e):
            add(e)

    for e in read_json(AISTUDIO_POOL, []):
        if isinstance(e, dict) and e.get("uuid"):
            add({"proto": e.get("proto", "vless"), "uuid": e["uuid"],
                 "addr": e["addr"], "port": int(e["port"]), "q": e.get("q", {})})

    beans = []
    for f in sorted(glob.glob(os.path.join(NEKORAY_PROFILES, "*.json"))):
        d = read_json(f, {})
        if not isinstance(d, dict):
            continue
        srv = _bean_to_server(d.get("bean", {}) or {}, d.get("type", ""))
        if srv:
            beans.append(srv)
    prio = {"vless": 0, "trojan": 1, "vmess": 2, "wireguard": 3, "shadowsocks": 4, "ss": 4}
    for srv in sorted(beans, key=lambda s: prio.get(s["proto"], 9)):
        add(srv)

    nodes_doc = read_json(NODES_JSON, {})
    urls = []
    items = nodes_doc.get("nodes", []) if isinstance(nodes_doc, dict) else (
        nodes_doc if isinstance(nodes_doc, list) else []
    )
    for n in items:
        if isinstance(n, dict):
            u = n.get("url", "")
            if u:
                urls.append((not n.get("healthy", False), u))
    for _, u in sorted(urls):
        add(parse_node_uri(u))

    for n in gather_multi_format_candidates():
        add(n)

    return out[:limit]


# ---------------------------------------------------------------------------
# L1 + L2 + L3 — multi-hop chain builder + DPI TLS fragmentation
# ---------------------------------------------------------------------------

def build_outbound(srv, tag):
    """One xray outbound for one Server (vless/trojan/vmess/ss/socks/http)."""
    q = srv.get("q", {}) or {}
    addr, port = srv["addr"], int(srv["port"])
    proto = srv.get("proto", "vless")

    if proto == "vless":
        out = {"tag": tag, "protocol": "vless",
               "settings": {"vnext": [{"address": addr, "port": port,
                    "users": [{"id": srv["uuid"], "encryption": "none"}]}]}}
        flow = q.get("flow")
        if flow:
            if q.get("security") not in ("tls", "reality"):
                flow = None
            elif not xray_supports_vision():
                flow = None
        if flow:
            out["settings"]["vnext"][0]["users"][0]["flow"] = flow
    elif proto == "trojan":
        out = {"tag": tag, "protocol": "trojan",
               "settings": {"servers": [{"address": addr, "port": port,
                                         "password": srv["password"]}]}}
    elif proto == "vmess":
        out = {"tag": tag, "protocol": "vmess",
               "settings": {"vnext": [{"address": addr, "port": port,
                    "users": [{"id": srv["uuid"], "alterId": 0}]}]}}
    elif proto in ("ss", "shadowsocks"):
        out = {"tag": tag, "protocol": "shadowsocks",
               "settings": {"servers": [{"address": addr, "port": port,
                    "method": srv.get("method", "aes-256-gcm"),
                    "password": srv["password"]}]}}
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
            "tag": tag, "protocol": "wireguard",
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
        ss.update(security="reality",
                  realitySettings={"serverName": q.get("sni") or addr,
                                   "fingerprint": q.get("fp", "chrome"),
                                   "publicKey": q.get("pbk", ""),
                                   "shortId": q.get("sid", ""),
                                   "spiderX": q.get("spx", "/")})
    elif sec == "tls":
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": q.get("sni") or addr,
                             "fingerprint": q.get("fp", "chrome")}
        if q.get("alpn"):
            ss["tlsSettings"]["alpn"] = [x for x in q["alpn"].split(",") if x]
    else:
        ss["security"] = "none"

    if net == "ws":
        ss["network"] = "ws"
        ss["wsSettings"] = {"path": q.get("path", "/"),
                            "headers": {"Host": q.get("host") or q.get("sni") or addr}}
    elif net == "xhttp":
        ss["network"] = "xhttp"
        ss["xhttpSettings"] = {"path": q.get("path", "/"),
                               "host": q.get("host") or q.get("sni") or addr,
                               "mode": q.get("mode", "auto")}
    elif net == "grpc":
        ss["network"] = "grpc"
        ss["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    else:
        ss["network"] = "tcp"
    out["streamSettings"] = ss
    return out


def find_singbox():
    for c in (os.environ.get("DASTYAB_SINGBOX", ""), "/usr/local/bin/sing-box", "/usr/bin/sing-box",
              os.path.join(HOME, ".dastyab/bin/sing-box")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return shutil.which("sing-box")


def _spawn_singbox_sidecar(srv):
    """Start an ephemeral sing-box SOCKS5 sidecar for hy2/tuic hops."""
    sb = find_singbox()
    if not sb:
        return None
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    lport = s.getsockname()[1]
    s.close()
    q = srv.get("q") or {}
    proto = srv.get("proto")
    ob = {"type": "hysteria2" if proto in ("hy2", "hysteria2") else "tuic",
          "tag": "up", "server": srv["addr"], "server_port": int(srv["port"]),
          "password": srv.get("password", ""),
          "tls": {"enabled": True, "server_name": q.get("sni") or srv["addr"],
                  "insecure": q.get("insecure") in ("1", "true")}}
    if proto == "tuic":
        ob["uuid"] = srv.get("uuid", "")
    cfg_path = f"/tmp/dastyab_flow_sb_{lport}.json"
    with open(cfg_path, "w") as fh:
        json.dump({"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": lport}],
                   "outbounds": [ob]}, fh)
    try:
        proc = subprocess.Popen([sb, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _SIDECAR_PROCS.append(proc)
        for _ in range(15):
            if proc.poll() is not None:
                return None
            c = socket.socket()
            c.settimeout(0.25)
            try:
                c.connect(("127.0.0.1", lport))
                c.close()
                return {"proto": "socks", "addr": "127.0.0.1", "port": lport, "local": True, "q": {}}
            except OSError:
                c.close()
                time.sleep(0.15)
    except OSError:
        return None
    return None


def build_config(nodes, port, fragment=False, allow_sidecar=False):
    """Full xray config for 1..8+ hop chains + optional TLS fragmentation."""
    if not nodes:
        return None
    resolved = []
    for srv in nodes:
        if srv.get("proto") in ("hy2", "hysteria2", "tuic"):
            if not allow_sidecar:
                return None
            bridged = _spawn_singbox_sidecar(srv)
            if bridged is None:
                return None
            resolved.append(bridged)
        else:
            resolved.append(srv)

    outbounds = []
    n = len(resolved)
    for idx, srv in enumerate(resolved):
        if idx == 0:
            tag = "exit"
        elif idx + 1 == n:
            tag = "entry"
        else:
            tag = f"relay-{idx}"
        ob = build_outbound(srv, tag)
        if ob is None:
            return None
        if idx + 1 < n:
            nxt = "entry" if idx + 2 == n else f"relay-{idx + 1}"
            ob["sockopt"] = {"dialerProxy": nxt}
        elif fragment and not srv.get("local") and srv.get("proto") not in ("socks", "http", "wireguard"):
            ob["sockopt"] = {"dialerProxy": "frag-dialer"}
        outbounds.append(ob)

    tail = resolved[-1]
    if fragment and not tail.get("local") and tail.get("proto") not in ("socks", "http", "wireguard"):
        outbounds.append({
            "tag": "frag-dialer",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "AsIs",
                "fragment": {"packets": "tlshello", "length": "10-30", "interval": "10-20"},
            },
            "sockopt": {"tcpNoDelay": True},
        })

    return {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": port,
                          "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": True},
                          "tag": "socks-in"}],
            "outbounds": outbounds}


def build_entry_exit_chain(entry, exit_node, port=SOCK, fragment=True, fp="chrome"):
    """Build PattNG-style Entry (WARP/WireGuard/Proxy) -> Exit config with fragment + fingerprint."""
    ex = mutate_fp(exit_node, fp) if fp else dict(exit_node)
    return build_config([ex, entry], port=port, fragment=fragment, allow_sidecar=True)


# ---------------------------------------------------------------------------
# Warrior Reputation, Blacklist, and Bandit
# ---------------------------------------------------------------------------

def parse_cf_trace(body):
    out = {}
    for line in (body or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def classify_asn_reputation(org, is_proxy=False, is_hosting=False, is_warp=False):
    low = (org or "").lower()
    if is_warp or ("cloudflare" in low and "warp" in low):
        return "warp-or-tor", -200
    known_dc = any(k in low for k in HOSTING_KEYWORDS)
    known_res = any(k in low for k in RESIDENTIAL_KEYWORDS)
    if is_proxy and (is_hosting or known_dc):
        rep, score = "hosting-high-risk", -30
    elif known_dc or is_hosting:
        rep, score = "dc-low-risk", 25
    elif known_res and not is_proxy:
        rep, score = "residential-isp", 100
    elif not is_proxy:
        rep, score = "clean-non-dc", 75
    else:
        rep, score = "dc-low-risk", 20
    if is_proxy:
        score -= 25
    if is_hosting:
        score -= 15
    return rep, score


def _is_blacklisted(key, ttl=21600):
    bl = read_json(WARRIOR_BLACKLIST, {})
    ts = bl.get(key)
    return bool(ts and (time.time() - ts) < ttl)


def _remember_blocked_exit(key, ttl=21600):
    now = time.time()
    bl = read_json(WARRIOR_BLACKLIST, {})
    bl = {k: v for k, v in bl.items() if (now - v) < ttl}
    bl[key] = now
    write_json_atomic(WARRIOR_BLACKLIST, bl)


def _bandit_record(arm_id, ok, latency_ms=None, clean_score=0):
    db = read_json(WARRIOR_BANDIT, {})
    st = db.get(arm_id, {"wins": 1.0, "trials": 2.0, "ewma_ms": 900.0, "clean": clean_score})
    st["wins"] = st["wins"] * 0.9 + (1.0 if ok else 0.0)
    st["trials"] = max(1.0, st["trials"] * 0.9) + 1.0
    if latency_ms is not None and latency_ms > 0:
        st["ewma_ms"] = 0.3 * latency_ms + 0.7 * st.get("ewma_ms", latency_ms)
    if clean_score:
        st["clean"] = clean_score
    db[arm_id] = st
    write_json_atomic(WARRIOR_BANDIT, db)


def _bandit_score(arm_id, db=None):
    db = db if db is not None else read_json(WARRIOR_BANDIT, {})
    total = max(2.0, sum(v.get("trials", 2.0) for v in db.values()))
    st = db.get(arm_id)
    if not st:
        return 0.75 + 0.45 * math.sqrt(math.log(total))
    win_rate = st["wins"] / max(1.0, st["trials"])
    explore = 0.45 * math.sqrt(math.log(total) / max(1.0, st["trials"]))
    lat_pen = min(0.45, st.get("ewma_ms", 900.0) / 3000.0)
    clean_bonus = max(-0.4, min(0.3, st.get("clean", 0) / 300.0))
    return win_rate + explore + clean_bonus - lat_pen


# ---------------------------------------------------------------------------
# Tunnel lifecycle
# ---------------------------------------------------------------------------

def is_running():
    if os.path.exists(PIDFILE):
        try:
            pid = int(open(PIDFILE).read())
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, ValueError, PermissionError):
            pass
    return False


def _curl(args, timeout):
    """Run curl through the tunnel; never raises."""
    try:
        return subprocess.run(
            ["curl", "-s", "--max-time", str(timeout),
             "--socks5-hostname", f"127.0.0.1:{SOCK}"] + args,
            capture_output=True, text=True, timeout=timeout + 5)
    except (OSError, subprocess.SubprocessError):
        return None


def bring_up(nodes, fragment=False):
    """Start the core on `nodes`; return the child pid, or None."""
    cfg = build_config(nodes, SOCK, fragment=fragment, allow_sidecar=True)
    if cfg is None:
        return None
    with open(CFGPATH, "w") as fh:
        json.dump(cfg, fh)
    xray = find_xray()
    try:
        proc = subprocess.Popen([xray, "run", "-c", CFGPATH],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
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
    open(PIDFILE, "w").write(str(proc.pid))
    return proc.pid


def stop(quiet=False):
    if os.path.exists(PIDFILE):
        try:
            pid = int(open(PIDFILE).read())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            os.remove(PIDFILE)
        except OSError:
            pass
    subprocess.run(["bash", "-c",
        'for p in $(pgrep -f dastyab_flow.json); do '
        '[ "$p" = "${1}" ] || [ "$p" = "$$" ] || kill -9 "$p" 2>/dev/null; done',
        "dastyab-flow-stop", str(os.getpid())],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while _SIDECAR_PROCS:
        sp = _SIDECAR_PROCS.pop()
        try:
            sp.terminate()
            sp.wait(timeout=1.5)
        except Exception:
            try:
                sp.kill()
            except Exception:
                pass
    if not quiet:
        print("[flow] Tunnel stopped")


# ---------------------------------------------------------------------------
# L4 + L5 — Brutal Warrior Gates
# ---------------------------------------------------------------------------

def probe_gates(want_country=None, browser_profile=None, strict_clean=False):
    """Run every Warrior Flow gate through the current tunnel."""
    res = {"egress": None, "country": None, "country_name": None,
           "proxy": None, "hosting": None, "warp": False,
           "reputation": None, "clean_score": 0,
           "flow_ok": False, "accounts_ok": False, "latency_ms": None,
           "verdict": False, "reason": ""}

    t0 = time.time()
    r = _curl([IPIFY], 20)
    ip = (r.stdout or "").strip() if r else ""
    if not ip or len(ip) > 60 or "\n" in ip:
        res["reason"] = "no egress (tunnel dead at the far end)"
        return res
    res["egress"] = ip

    r = _curl([IPAPI], 15)
    geo = {}
    try:
        geo = json.loads((r.stdout or "").strip()) if r else {}
    except json.JSONDecodeError:
        geo = {}

    if geo.get("status") != "success":
        r_bk = _curl(["https://ipwho.is/"], 12)
        try:
            d_bk = json.loads((r_bk.stdout or "").strip()) if r_bk else {}
            if d_bk.get("success"):
                conn = d_bk.get("connection") or {}
                geo = {
                    "status": "success",
                    "country": d_bk.get("country"),
                    "countryCode": d_bk.get("country_code"),
                    "org": conn.get("isp") or conn.get("org") or "",
                    "proxy": False,
                    "hosting": False,
                }
        except json.JSONDecodeError:
            pass

    if geo.get("status") != "success":
        res["reason"] = "geo lookup failed (ip-api unreachable through tunnel)"
        res["latency_ms"] = int((time.time() - t0) * 1000)
        return res

    res["country"] = (geo.get("countryCode") or "").upper()
    res["country_name"] = geo.get("country")
    res["proxy"] = bool(geo.get("proxy"))
    res["hosting"] = bool(geo.get("hosting"))
    res["latency_ms"] = int((time.time() - t0) * 1000)

    r_tr = _curl([CF_TRACE_URL], 10)
    trace = parse_cf_trace(r_tr.stdout) if (r_tr and r_tr.stdout and "warp=" in r_tr.stdout) else {}
    is_warp = trace.get("warp", "").lower() in ("on", "plus")
    org = f"{geo.get('isp', '')} {geo.get('org', '')}".strip()
    rep, cscore = classify_asn_reputation(org, res["proxy"], res["hosting"], is_warp)
    res["warp"] = is_warp
    res["reputation"] = rep
    res["clean_score"] = cscore

    if res["country"] not in SUPPORTED_COUNTRIES:
        res["reason"] = (f"egress {ip} is in {res['country']} "
                         f"({res['country_name']}) — not on Google's Flow list")
        return res
    if want_country and res["country"] != want_country.upper():
        res["reason"] = (f"egress country {res['country']} != requested "
                         f"{want_country.upper()}")
        return res
    if is_warp:
        res["reason"] = "WARP egress rejected by Warrior gate (use WARP as entry hop)"
        return res
    if strict_clean and (res["proxy"] or rep == "hosting-high-risk"):
        res["reason"] = f"strict Warrior rejected {rep} / proxy-flagged exit ({org})"
        return res

    # L4 — both Google fronts must answer through this exact egress.
    r = _curl(["-L", "--max-redirs", "6", "-o", "/dev/null", "-w", "%{http_code}", FLOW_URL], 25)
    code = (r.stdout or "").strip() if r else "000"
    res["flow_ok"] = code not in ("", "000")
    if not res["flow_ok"]:
        res["reason"] = f"flow.google.com unreachable through tunnel (HTTP {code})"
        return res

    r = _curl(["-L", "--max-redirs", "6", FLOW_URL], 25)
    body = (r.stdout or "") if r else ""
    body_low = body.lower()
    for m in GATE_MARKERS:
        if m in body_low:
            res["reason"] = f"REGION-GATE: flow.google.com HTML shows '{m}'"
            return res
    res["app_shell_ok"] = "AiSandboxAngularFrontend" in body
    if not res["app_shell_ok"]:
        res["reason"] = "flow.google.com answered but not with the Flow app shell"
        return res

    r_labs = _curl(["-L", "--max-redirs", "6", LABS_FLOW_URL], 18)
    labs_low = ((r_labs.stdout or "") if r_labs else "").lower()
    for m in GATE_MARKERS:
        if m in labs_low:
            res["reason"] = f"REGION-GATE: labs.google/fx/tools/flow shows '{m}'"
            return res

    r = _curl(["-L", "--max-redirs", "6", "-o", "/dev/null", "-w", "%{http_code}", ACCOUNTS_URL], 25)
    code = (r.stdout or "").strip() if r else "000"
    res["accounts_ok"] = code not in ("", "000")
    if not res["accounts_ok"]:
        res["reason"] = "accounts.google.com unreachable (sign-in would fail)"
        return res

    b_ok, b_detail = browser_gate(profile_dir=browser_profile)
    res["browser_ok"] = b_ok
    res["browser_detail"] = b_detail
    if b_ok is False:
        res["reason"] = b_detail
        return res
    if b_ok is None:
        res["verdict"] = True
        flags = []
        if res["proxy"]:
            flags.append("proxy-flagged")
        if res["hosting"]:
            flags.append("hosting")
        res["reason"] = ("egress %s in %s (%s); host reachable%s; "
                         "browser gate NOT run (%s)"
                         % (res["egress"], res["country"],
                            res["country_name"],
                            ("; " + ", ".join(flags)) if flags else "",
                            b_detail))
        return res

    res["verdict"] = True
    flags = []
    if res["proxy"]:
        flags.append("proxy-flagged")
    if res["hosting"]:
        flags.append("hosting")
    res["reason"] = ("egress %s in %s (%s); Flow + accounts reachable%s"
                     % (res["egress"], res["country"], res["country_name"],
                        ("; " + ", ".join(flags)) if flags else ""))
    return res


def gate_score(g):
    """Sort key: passing gates first, then cleanest IP, then ASN quality, then latency."""
    return (0 if g["verdict"] else 1,
            0 if not g["proxy"] else 1,
            0 if not g["hosting"] else 1,
            -(g.get("clean_score", 0)),
            g["latency_ms"] or 10_000)


def _label(nodes, fragment=False):
    lbl = " -> ".join(f"{n.get('proto', 'vless')} {n['addr']}:{n['port']}" for n in nodes)
    return lbl + (" +frag" if fragment else "")


# ---------------------------------------------------------------------------
# Pool management & Brutal Warrior 5-stage Escalation
# ---------------------------------------------------------------------------

def load_pool():
    pool = read_json(FLOW_POOL, [])
    return [e for e in pool if isinstance(e, dict) and e.get("nodes")]


def save_pool(passing):
    """Replace the pool — only when the rebuild found live servers."""
    if not passing:
        raise SystemExit(
            "[flow] No candidate passed the gates; keeping the existing "
            f"pool at {FLOW_POOL} unchanged."
        )
    write_json_atomic(FLOW_POOL, passing)


def _try_nodes(nodes, want_country=None, fragment=False, strict_clean=False):
    """Bring one route up, gate it, tear it down. Return gates or None."""
    bridged = []
    for srv in nodes:
        if srv.get("proto") in ("hy2", "hysteria2", "tuic"):
            b = _spawn_singbox_sidecar(srv)
            if b is None:
                stop(quiet=True)
                return None
            bridged.append(b)
        else:
            bridged.append(srv)
    pid = bring_up(bridged, fragment=fragment)
    if pid is None:
        return None
    try:
        return probe_gates(want_country, strict_clean=strict_clean)
    finally:
        stop(quiet=True)


def scan(candidates, want_country=None, try_n=10, allow_chain=True,
         max_hops=8, strict_clean=False):
    """Brutal Warrior scan across 1-hop, DPI-frag, uTLS mutation, local bridges, & 2..8-hop cascades."""
    if not candidates:
        return []
    max_hops = max(1, min(8, int(max_hops or 8)))
    bandit_db = read_json(WARRIOR_BANDIT, {})
    ranked = sorted(candidates, key=lambda c: _bandit_score(node_key(c), bandit_db), reverse=True)
    locals_ = discover_local_proxies()
    passing, relays, timeouts = [], [], []
    tested = 0
    seen_chains = set()

    def record(nodes, frag, g, stage):
        entry = {
            "nodes": nodes, "fragment": frag, "stage": stage,
            "egress": g["egress"], "country": g["country"],
            "country_name": g["country_name"], "proxy": g["proxy"],
            "hosting": g["hosting"], "clean_score": g.get("clean_score", 0),
            "reputation": g.get("reputation", ""),
            "latency_ms": g["latency_ms"], "checked_epoch": time.time(),
        }
        passing.append(entry)
        for n in nodes:
            _bandit_record(node_key(n), True, g["latency_ms"], g.get("clean_score", 0))

    # Stage 0: Fast diverse 1-hop candidates (skip known blocked exits).
    for cand in ranked:
        if tested >= try_n or len(passing) >= 3:
            break
        k = node_key(cand)
        if _is_blacklisted(k):
            relays.append(cand)
            continue
        tested += 1
        nodes = [cand]
        print(f"[warrior] [S0:{tested}] trying {_label(nodes)} ...", flush=True)
        g = _try_nodes(nodes, want_country, fragment=False, strict_clean=strict_clean)
        if g and g["verdict"]:
            print(f"[warrior]     PASS {g['reason']} ({g['latency_ms']}ms)", flush=True)
            record(nodes, False, g, "stage0-1hop")
        elif g and g.get("egress"):
            relays.append(cand)
            _remember_blocked_exit(k)
            print(f"[warrior]     exit blocked ({g['reason']}) -> saved as RELAY", flush=True)
        else:
            timeouts.append(cand)
            _bandit_record(k, False)
            print(f"[warrior]     fail: {(g or {}).get('reason', 'transport dead')}", flush=True)

    if len(passing) >= 2:
        return passing

    # Stage 1: DPI TLS-Hello Packet Fragmentation + uTLS fingerprint mutation.
    frag_cands = (timeouts + [c for c in ranked if c not in timeouts])[:min(8, try_n)]
    if not passing:
        print("[warrior] Stage 1: Engaging TLS-Hello DPI fragmentation + uTLS mutation ...", flush=True)
        for idx, cand in enumerate(frag_cands):
            if len(passing) >= 2:
                break
            if cand.get("local") or cand.get("proto") in ("socks", "http", "wireguard"):
                continue
            tested += 1
            nodes = [mutate_fp(cand, MUTABLE_FPS[idx % len(MUTABLE_FPS)])]
            print(f"[warrior] [S1:{tested}] frag {_label(nodes, True)} ...", flush=True)
            g = _try_nodes(nodes, want_country, fragment=True, strict_clean=strict_clean)
            if g and g["verdict"]:
                print(f"[warrior]     PASS (fragment) {g['reason']}", flush=True)
                record(nodes, True, g, "stage1-fragment")
            elif g and g.get("egress") and cand not in relays:
                relays.append(cand)

    if passing or not allow_chain or max_hops < 2:
        return passing

    # Stage 2: Local proxy bridge (Tor/WARP/Clash/Sing-Box/Nekoray) -> Clean Exit.
    if locals_:
        print(f"[warrior] Stage 2: Testing {len(locals_)} local proxy bridge(s) ...", flush=True)
        for lp in locals_:
            for ex in ranked[:8]:
                sig = (node_key(ex), node_key(lp))
                if sig in seen_chains:
                    continue
                seen_chains.add(sig)
                nodes = [ex, lp]
                tested += 1
                print(f"[warrior] [S2:{tested}] bridge {_label(nodes)} ...", flush=True)
                g = _try_nodes(nodes, want_country, fragment=False, strict_clean=strict_clean)
                if g and g["verdict"]:
                    print(f"[warrior]     PASS (local-bridge) {g['reason']}", flush=True)
                    record(nodes, False, g, "stage2-local-bridge")
                    break
            if passing:
                break

    if passing:
        return passing

    # Stage 3: Two-hop Cross-/16 Chains & Bidirectional Swaps + Fragment.
    print("[warrior] Stage 3: Engaging cross-/16 2-hop chains + DPI fragment ...", flush=True)
    entries = relays[:8] if relays else ranked[:8]
    exit_cands = [c for c in ranked if not _is_blacklisted(node_key(c))][:max(10, try_n)] or ranked[:max(10, try_n)]
    for cand in exit_cands:
        for entry in entries:
            if entry is cand or node_key(entry) == node_key(cand):
                continue
            if subnet_prefix16(entry["addr"]) == subnet_prefix16(cand["addr"]):
                continue
            for frag in (False, True):
                sig = (node_key(cand), node_key(entry), frag)
                if sig in seen_chains:
                    continue
                seen_chains.add(sig)
                tested += 1
                nodes = [cand, mutate_fp(entry, "random") if frag else entry]
                print(f"[warrior] [S3:{tested}] chain {_label(nodes, frag)} ...", flush=True)
                g = _try_nodes(nodes, want_country, fragment=frag, strict_clean=strict_clean)
                if g and g["verdict"]:
                    print(f"[warrior]     PASS (2-hop) {g['reason']} ({g['latency_ms']}ms)", flush=True)
                    record(nodes, frag, g, "stage3-2hop")
                    break
                reason = (g or {}).get("reason", "transport dead")
                print(f"[warrior]     fail: {reason}", flush=True)
                if g and g.get("country") and g["country"] not in SUPPORTED_COUNTRIES:
                    break
            if passing:
                break
        if len(passing) >= 2:
            break

    if passing or max_hops < 3:
        return passing

    # Stage 4: Deep 3-hop & 4-hop Warrior Cascades.
    if len(entries) >= 2 and exit_cands:
        print("[warrior] Stage 4: Engaging 3-hop & 4-hop deep Warrior cascades ...", flush=True)
        for ex in exit_cands[:4]:
            for r1 in entries[:3]:
                if node_key(r1) == node_key(ex):
                    continue
                for en in (locals_ + entries)[:4]:
                    if node_key(en) in (node_key(ex), node_key(r1)):
                        continue
                    chain = [ex, r1, en]
                    if max_hops >= 4:
                        extra = next((x for x in locals_ + entries
                                      if node_key(x) not in {node_key(n) for n in chain}), None)
                        if extra:
                            chain.append(extra)
                    sig = tuple(node_key(n) for n in chain)
                    if sig in seen_chains:
                        continue
                    seen_chains.add(sig)
                    tested += 1
                    print(f"[warrior] [S4:{tested}] cascade {_label(chain, True)} ...", flush=True)
                    g = _try_nodes(chain, want_country, fragment=True, strict_clean=strict_clean)
                    if g and g["verdict"]:
                        print(f"[warrior]     PASS ({len(chain)}-hop) {g['reason']}", flush=True)
                        record(chain, True, g, f"stage4-{len(chain)}hop")
                        return passing

    if passing or max_hops < 5:
        return passing

    # Stage 5: Ultra-deep 5..=8 hop Warrior cascades with protocol diversity + local bridge anchor.
    combined_relays = []
    seen_rel = set()
    for r in relays + ranked + locals_:
        rk = node_key(r)
        if rk not in seen_rel:
            seen_rel.add(rk)
            combined_relays.append(r)

    print(f"[warrior] Stage 5: Escalating up to {max_hops}-hop ultra-deep Warrior cascades ...", flush=True)
    for depth in range(5, max_hops + 1):
        for shift in range(min(4, len(exit_cands))):
            ex = exit_cands[shift]
            chain = [ex]
            used = {node_key(ex)}
            for off in range(len(combined_relays)):
                cand = combined_relays[(shift + off) % len(combined_relays)]
                ck = node_key(cand)
                if ck in used or cand.get("local"):
                    continue
                if len(chain) + (1 if locals_ else 0) >= depth:
                    break
                used.add(ck)
                chain.append(mutate_fp(cand, MUTABLE_FPS[len(chain) % len(MUTABLE_FPS)]))
            if len(chain) < depth:
                for lp in locals_:
                    if node_key(lp) not in used:
                        used.add(node_key(lp))
                        chain.append(lp)
                    if len(chain) == depth:
                        break
            if len(chain) < depth:
                for cand in combined_relays:
                    if node_key(cand) not in used:
                        used.add(node_key(cand))
                        chain.append(cand)
                    if len(chain) == depth:
                        break
            if len(chain) < depth:
                continue
            sig = tuple(node_key(n) for n in chain)
            if sig in seen_chains:
                continue
            seen_chains.add(sig)
            tested += 1
            print(f"[warrior] [S5:{tested}:{depth}hop] {_label(chain, True)} ...", flush=True)
            g = _try_nodes(chain, want_country, fragment=True, strict_clean=strict_clean)
            if g and g["verdict"]:
                print(f"[warrior]     PASS ({depth}-hop) {g['reason']}", flush=True)
                record(chain, True, g, f"stage5-{depth}hop")
                return passing
    return passing


# ---------------------------------------------------------------------------
# L6 — hardened anti-leak browser pinned to the tunnel
# ---------------------------------------------------------------------------

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
    return next((c for c in cands
                 if c and os.path.isfile(c) and os.access(c, os.X_OK)), None)


def hardened_browser_args(ch, prof_dir, url, country=None):
    lang, _ = COUNTRY_LOCALE_TZ.get((country or "").upper(), ("en-US", "America/New_York"))
    return [
        ch,
        "--ozone-platform=x11",
        f"--proxy-server=socks5://127.0.0.1:{SOCK}",
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-features=AsyncDns,DnsOverHttps",
        f"--lang={lang}",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir={prof_dir}",
        url,
    ]


def browser_gate(timeout=150, profile_dir=None):
    """Load flow.google.com in a headless browser THROUGH the tunnel."""
    ch = find_browser()
    if ch is None:
        return None, "no Chromium browser found (browser gate skipped)"
    prof = profile_dir or os.path.join("/tmp", "dastyab-flow-gate-%d" % os.getpid())
    args = [ch, "--headless=new", "--disable-gpu", "--no-first-run",
            "--no-default-browser-check",
            f"--proxy-server=socks5://127.0.0.1:{SOCK}",
            "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--virtual-time-budget=12000",
            f"--user-data-dir={prof}", "--dump-dom", FLOW_URL]
    dom = ""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        dom = r.stdout or ""
    except subprocess.TimeoutExpired as e:
        dom = (e.stdout or "")
        if isinstance(dom, bytes):
            dom = dom.decode("utf-8", "replace")
        if not dom:
            return None, ("browser gate timed out before the page settled "
                          "(route may be very slow)")
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"browser gate failed to run ({e})"
    finally:
        if profile_dir is None:
            shutil.rmtree(prof, ignore_errors=True)

    if "SingletonLock" in dom or "ProcessSingleton" in dom:
        return None, ("profile is in use by a running Chrome — close that "
                      "browser first, then re-run")

    low = dom.lower()
    for marker in UNAVAILABLE_MARKERS:
        if marker in low:
            return False, f"ACCOUNT-GATE: {ACCOUNT_HELP} (shows '{marker}')"
    for marker in GATE_MARKERS:
        if marker in low:
            return False, ("REGION-GATE: Flow rejected this egress in the "
                           f"browser (shows '{marker}')")
    if len(dom) < 1000:
        return False, "browser rendered nothing (tunnel unusable for HTTPS)"
    if "aisandboxangularfrontend" not in low:
        return False, "browser did not render the Flow app"
    if "sign in" in low and "credits" not in low:
        return None, ("browser is NOT signed in (landing page) — region "
                      "gate looks clear, account gate untested; pass "
                      "--profile <dir> with a signed-in profile to test it")
    return True, "browser loaded the Flow app (no region or account gate)"


def launch_browser():
    """Open Flow in Chrome pinned to the tunnel with DNS/WebRTC leak protection."""
    ch = find_browser()
    if ch is None:
        print("[flow] No Chromium-based browser found (Chrome/Chromium/Edge/Brave).")
        print(f"[flow] Open {FLOW_URL} yourself through "
              f"socks5://127.0.0.1:{SOCK} — do NOT open it directly, that "
              f"would use your real IP and hit the region gate.")
        return
    os.makedirs(BROWSER_PROFILE, exist_ok=True)
    state = read_json(STATEFILE, {})
    cc = state.get("country")
    _, tz = COUNTRY_LOCALE_TZ.get((cc or "").upper(), ("en-US", "America/New_York"))
    env = dict(os.environ)
    env["TZ"] = tz
    subprocess.Popen(hardened_browser_args(ch, BROWSER_PROFILE, FLOW_URL, country=cc),
                     env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[flow] Opened Flow in the hardened anti-leak browser.")
    print("[flow] Sign in there once — the profile keeps the session.")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_start(index=None, hops=1, want_country=None, brutal=False, strict_clean=False):
    if is_running():
        print(f"[flow] Tunnel already running on 127.0.0.1:{SOCK}")
        print("[flow] Opening Flow through the existing tunnel ...")
        launch_browser()
        return 0

    pool = load_pool()
    if not pool:
        print("[flow] No ranked pool yet — engaging Warrior scan ...")
        passing = scan(load_candidates(), want_country, try_n=16,
                       max_hops=max(hops or 4, 2), strict_clean=strict_clean)
        if not passing:
            print("[flow] No candidate passed the gates. Widen the scan: "
                  "dastyab flow best --try 25", file=sys.stderr)
            return 3
        save_pool(passing)
        pool = load_pool()

    first = (index or 0) % len(pool)
    order = [first] + [(first + off) % len(pool) for off in range(1, len(pool))]
    for idx in order:
        route = pool[idx]
        nodes = route["nodes"]
        frag = bool(route.get("fragment", False))
        if hops == 1 and len(nodes) > 1 and not brutal:
            nodes = nodes[:1]
        print(f"[flow] Bringing up {_label(nodes, frag)} ...")
        pid = bring_up(nodes, fragment=frag)
        if pid is None:
            print("[flow] transport dead, next node", flush=True)
            continue
        g = probe_gates(want_country, strict_clean=strict_clean)
        if g["verdict"]:
            print(f"[flow] Tunnel up (pid {pid}) via {_label(nodes, frag)}")
            print(f"[flow] SOCKS5: 127.0.0.1:{SOCK} | {g['reason']}")
            write_json_atomic(STATEFILE, {"idx": idx, "hops": len(nodes),
                                          "fragment": frag,
                                          "egress": g["egress"],
                                          "country": g["country"],
                                          "country_name": g["country_name"],
                                          "verified_epoch": time.time()})
            with open(IDXFILE, "w") as fh:
                fh.write(str(idx))
            print("[flow] Opening Flow ...")
            launch_browser()
            return 0
        stop(quiet=True)
        print(f"[flow] gate fail: {g['reason']} — rotating", flush=True)

    if brutal:
        print("[warrior] Pool exhausted — engaging brutal multi-layer hunt ...", file=sys.stderr)
        passing = scan(load_candidates(), want_country, try_n=25,
                       max_hops=max(hops or 8, 8), strict_clean=strict_clean)
        if passing:
            save_pool(passing)
            return cmd_start(index=0, hops=max(hops or 8, 8),
                             want_country=want_country, brutal=False,
                             strict_clean=strict_clean)

    print("[flow] Every route in the pool failed the gates live.", file=sys.stderr)
    print("[flow] Re-scan and re-rank: dastyab flow best --try 20", file=sys.stderr)
    return 3


def cmd_next():
    state = read_json(STATEFILE, {})
    pool = load_pool()
    if not pool:
        print("[flow] No pool to rotate through. Run: dastyab flow best")
        return 3
    idx = (state.get("idx", 0) + 1) % len(pool)
    print(f"[flow] Rotating to route {idx + 1}/{len(pool)}")
    stop(quiet=True)
    return cmd_start(index=idx, hops=state.get("hops", 1))


def cmd_stop():
    stop()
    return 0


def cmd_status():
    print(f"[flow] xray core: {find_xray()}")
    print(f"[flow] SOCKS port: 127.0.0.1:{SOCK} | pid file: {PIDFILE}")
    if not is_running():
        state = read_json(STATEFILE, {})
        if state:
            age = int(time.time() - state.get("verified_epoch", 0))
            print(f"[flow] Tunnel DOWN. Last verified route "
                  f"{state.get('country')} / {state.get('egress')} "
                  f"({age // 60} min ago) — start with: dastyab flow start")
        else:
            print("[flow] Tunnel DOWN and no previous state. "
                  "Start with: dastyab flow start")
        return 1
    g = probe_gates()
    if g["verdict"]:
        print(f"[flow] Tunnel UP. {g['reason']}")
        print("[flow] Verdict: egress is on Google's Flow list — "
              "Flow should load in the pinned browser.")
        return 0
    print(f"[flow] Tunnel UP but gates FAIL: {g['reason']}")
    print("[flow] This is exactly what causes the "
          "'Flow is not available in your country yet.' redirect.")
    print("[flow] Rotate now with: dastyab flow next")
    return 1


def cmd_verify(want_country=None):
    pool = load_pool()
    if not pool:
        print("[flow] No saved pool. Run: dastyab flow best")
        return 1
    print(f"[flow] {len(pool)} saved route(s) — re-probing each live:")
    was_running = is_running()
    alive = 0
    for i, route in enumerate(pool):
        nodes = route["nodes"]
        frag = bool(route.get("fragment", False))
        g = _try_nodes(nodes, want_country, fragment=frag)
        if g and g["verdict"]:
            alive += 1
            print(f"   [{i}] {_label(nodes, frag)}  OK  {g['country']} "
                  f"{g['egress']} ({g['latency_ms']}ms)")
        else:
            print(f"   [{i}] {_label(nodes, frag)}  DEAD  "
                  f"{(g or {}).get('reason', 'transport dead')}")
    if was_running:
        cmd_start(index=read_json(STATEFILE, {}).get("idx", 0))
    print(f"[flow] {alive}/{len(pool)} routes still pass the gates.")
    return 0 if alive else 3


def cmd_best(try_n=10, want_country=None, hops=8, strict_clean=False):
    cands = load_candidates()
    if not cands:
        print("[flow] No candidates found in any source "
              "(pool, nekoray, nodes.json).", file=sys.stderr)
        print("[flow] Supply some with: dastyab flow build-pool <uris.txt>",
              file=sys.stderr)
        return 3
    print(f"[warrior] {len(cands)} candidate(s) from all sources; "
          f"scanning up to {try_n} (max_hops={hops}) ...")
    passing = scan(cands, want_country, try_n=try_n, max_hops=hops, strict_clean=strict_clean)
    if not passing:
        print("[flow] Nothing passed. Widen: dastyab flow best --try 25 "
              "or supply fresh cards: dastyab flow build-pool <uris.txt>",
              file=sys.stderr)
        return 3
    passing.sort(key=lambda r: (0 if not r["proxy"] else 1,
                                0 if not r["hosting"] else 1,
                                -(r.get("clean_score", 0)),
                                r["latency_ms"]))
    save_pool(passing)
    print(f"[flow] Ranked pool saved ({len(passing)} route(s)) -> {FLOW_POOL}")
    for i, r in enumerate(passing):
        print(f"   [{i}] {r['country']} {r['egress']} [{r.get('stage', '1hop')}] "
              f"({r['latency_ms']}ms"
              f"{', proxy-flagged' if r['proxy'] else ''}"
              f"{', hosting' if r['hosting'] else ''})")
    return 0


def cmd_watch(interval=30):
    """L7 — self-healing watchdog: keep a gate-passing egress alive."""
    def _probe_once():
        if not is_running():
            return None
        return probe_gates()

    print(f"[flow] Warrior Watchdog started: probing every {interval}s (Ctrl-C to stop)")
    fails = 0
    while True:
        try:
            g = _probe_once()
            if g and g["verdict"]:
                fails = 0
            elif g is None:
                print(f"[flow] {time.strftime('%H:%M:%S')} tunnel down — "
                      "restarting from the pool")
                cmd_start(index=read_json(STATEFILE, {}).get("idx", 0))
                fails = 0
            else:
                fails += 1
                print(f"[flow] {time.strftime('%H:%M:%S')} gate fail "
                      f"({fails}): {g['reason']}", file=sys.stderr)
                if fails >= 2:
                    print(f"[flow] {time.strftime('%H:%M:%S')} rotating ...")
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
    print(f"[flow] {len(uris)} unique URI(s); testing up to {probe_limit} for a pool of {want} ...")
    passing = []
    for u in uris[:probe_limit]:
        nodes = [u, entry_node] if entry_node else [u]
        g = _try_nodes(nodes, fragment=bool(entry_node))
        if g and g["verdict"]:
            print(f"   {u['addr']}:{u['port']}  OK  {g['country']} {g['egress']}", flush=True)
            passing.append({"nodes": nodes, "fragment": bool(entry_node), "egress": g["egress"],
                            "country": g["country"],
                            "country_name": g["country_name"],
                            "proxy": g["proxy"], "hosting": g["hosting"],
                            "clean_score": g.get("clean_score", 0),
                            "latency_ms": g["latency_ms"],
                            "checked_epoch": time.time()})
        else:
            print(f"   {u['addr']}:{u['port']}  DEAD  "
                  f"{(g or {}).get('reason', 'transport dead')}", flush=True)
        if len(passing) >= want:
            break
    if not passing:
        raise SystemExit(
            "[flow] None of the supplied URIs passed the gates; keeping the "
            f"existing pool at {FLOW_POOL} unchanged."
        )
    save_pool(passing)
    print(f"[flow] Built pool: {len(passing)} gate-passing route(s) -> {FLOW_POOL}")


def cmd_prove(tries=6, want_country=None, profile=None):
    """Prove (or disprove) Flow access end-to-end, in a real browser."""
    ch = find_browser()
    if ch is None:
        print("[flow] No Chromium browser available to prove with.", file=sys.stderr)
        print("[flow] Install Chrome/Chromium, or set DASTYAB_BROWSER.", file=sys.stderr)
        return 3
    print(f"[flow] Proving Flow access with a real browser ({ch})")
    print(f"[flow] Browser pinned to socks5://127.0.0.1:{SOCK}")

    cands = load_candidates()
    if not cands:
        print("[flow] No candidates in any source.", file=sys.stderr)
        return 3

    if is_running():
        stop(quiet=True)
        time.sleep(1)

    ok_routes = []
    for i, cand in enumerate(cands[:tries], 1):
        nodes = [cand]
        label = _label(nodes)
        print(f"[flow] [{i}] {label}", flush=True)
        pid = bring_up(nodes)
        if pid is None:
            print("[flow]     transport dead", flush=True)
            continue
        try:
            g = probe_gates(want_country, browser_profile=profile)
            if not g["verdict"]:
                reason = g["reason"]
                if reason.startswith("ACCOUNT-GATE:"):
                    print("[flow]     IP GATE PASSED (region is fine).", flush=True)
                    print("[flow]     ACCOUNT GATE FAILED — this is not fixable with a proxy.",
                          flush=True)
                    print("[flow] " + reason[len("ACCOUNT-GATE:"):].strip(), flush=True)
                    return 4
                print(f"[flow]     blocked: {reason}", flush=True)
                continue
            b_ok = g.get("browser_ok")
            if b_ok is False and str(g.get("reason", "")).startswith("ACCOUNT-GATE:"):
                print("[flow]     IP GATE PASSED (region is fine).", flush=True)
                print("[flow]     ACCOUNT GATE FAILED — a proxy cannot fix this.", flush=True)
                print("[flow] " + str(g["reason"])[len("ACCOUNT-GATE:"):].strip(), flush=True)
                return 4
            if b_ok:
                print(f"[flow]     PROVEN  {g['browser_detail']}", flush=True)
                print(f"[flow]             egress {g['egress']} "
                      f"({g['country']}) {g['latency_ms']}ms", flush=True)
                ok_routes.append((nodes, g))
                break
            print(f"[flow]     not proven: {g.get('browser_detail')}", flush=True)
        finally:
            stop(quiet=True)

    if not ok_routes:
        print("[flow] No route was proven in the browser.", file=sys.stderr)
        print("[flow] Try more candidates: dastyab flow prove --try 12", file=sys.stderr)
        return 3

    nodes, g = ok_routes[0]
    pid = bring_up(nodes)
    if pid:
        write_json_atomic(STATEFILE, {"idx": 0, "hops": len(nodes),
                                      "egress": g["egress"],
                                      "country": g["country"],
                                      "country_name": g["country_name"],
                                      "verified_epoch": time.time()})
        with open(IDXFILE, "w") as fh:
            fh.write("0")
        print(f"[flow] Proven route is up (pid {pid}) on 127.0.0.1:{SOCK}")
    print("[flow] RESULT: the region gate passes through this route.")
    print("[flow] Note: this proves the IP/region requirement only. Whether")
    print("[flow] the signed-in account is entitled to Flow is a separate")
    print("[flow] gate the browser reports once you sign in.")
    print("[flow] Open it with: dastyab flow start")
    return 0


def cmd_countries():
    codes = sorted(SUPPORTED_COUNTRIES)
    print(f"[flow] Google Flow is officially available in {len(codes)} "
          "countries/territories (per support.google.com, fetched 2026-11-16):")
    for i in range(0, len(codes), 16):
        print("   " + " ".join(codes[i:i + 16]))
    print("[flow] Filter egress with: dastyab flow start --country XX")


USAGE = __doc__


def main():
    ap = argparse.ArgumentParser(
        prog="dastyab-flow.py",
        description="Brutal Warrior multi-layer access to Google Flow (flow.google.com).",
    )
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("start", help="tunnel + open Flow (default)")
    p.add_argument("index", nargs="?", type=int, default=None)
    p.add_argument("--hops", type=int, default=1, choices=tuple(range(1, 9)),
                   help="1..8 hop chain length")
    p.add_argument("--country", default=None, help="require this egress country (ISO code)")
    p.add_argument("--brutal", action="store_true", help="auto-escalate to N-hop hunt if pool dead")
    p.add_argument("--strict", action="store_true", help="reject proxy/high-risk hosting exits")

    sub.add_parser("next", help="rotate to the next ranked route")
    sub.add_parser("stop", help="stop the tunnel")
    sub.add_parser("status", help="current egress + gate verdict")

    p = sub.add_parser("verify", help="re-probe every saved route")
    p.add_argument("--country", default=None)

    p = sub.add_parser("best", help="scan candidates wider, re-rank the pool")
    p.add_argument("--try", dest="try_n", type=int, default=10)
    p.add_argument("--hops", type=int, default=8, choices=tuple(range(1, 9)))
    p.add_argument("--country", default=None)
    p.add_argument("--entry", default=None)
    p.add_argument("--strict", action="store_true")

    p = sub.add_parser("watch", help="self-healing watchdog")
    p.add_argument("interval", nargs="?", type=int, default=30)

    p = sub.add_parser("build-pool", help="build the pool from .txt or any config file")
    p.add_argument("uris", help="file with share URIs, Clash YAML, WireGuard, Sing-Box, or .npv*/.ovpn/.txt")
    p.add_argument("--entry", default=None, help="optional PattNG entry proxy/WARP URI or file")

    p = sub.add_parser("ingest", help="parse and save all nodes from .txt or any config file")
    p.add_argument("uris", help="path to .txt, .sub, .yaml, .json, .conf, .ovpn, .npvt, etc.")
    p.add_argument("--entry", default=None, help="optional PattNG entry proxy/WARP URI or file")

    p = sub.add_parser("prove", help="prove Flow access in a real browser (decisive)")
    p.add_argument("--try", dest="try_n", type=int, default=6)
    p.add_argument("--country", default=None)
    p.add_argument("--profile", default=None,
                   help="signed-in Chrome profile dir (close that Chrome first)")

    sub.add_parser("countries", help="show Google's supported-country list")

    a = ap.parse_args(args=None if len(sys.argv) > 1 else ["start"])
    cmd = (a.cmd or "start").lower()

    if cmd == "start":
        return cmd_start(a.index, a.hops, a.country, a.brutal, a.strict)
    if cmd == "next":
        return cmd_next()
    if cmd == "stop":
        return cmd_stop()
    if cmd == "status":
        return cmd_status()
    if cmd == "verify":
        return cmd_verify(a.country)
    if cmd == "best":
        cands = load_candidates()
        if getattr(a, "entry", None):
            en = _resolve_entry_arg(a.entry)
            if en:
                passing = []
                for ex in cands[:a.try_n]:
                    g = _try_nodes([ex, en], a.country, fragment=True, strict_clean=a.strict)
                    if g and g["verdict"]:
                        passing.append({"nodes": [ex, en], "fragment": True, "stage": "pattng-entry-exit",
                                        "egress": g["egress"], "country": g["country"],
                                        "country_name": g["country_name"], "proxy": g["proxy"],
                                        "hosting": g["hosting"], "clean_score": g.get("clean_score", 0),
                                        "latency_ms": g["latency_ms"], "checked_epoch": time.time()})
                if passing:
                    save_pool(passing)
                    return 0
                return 3
        return cmd_best(a.try_n, a.country, a.hops, a.strict)
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
            {"nodes": [u, en] if en else [u], "fragment": bool(en),
             "egress": "pending", "country": "??", "country_name": "Imported",
             "proxy": False, "hosting": False, "clean_score": 0, "latency_ms": 0,
             "checked_epoch": time.time()}
            for u in nodes
        ]
        save_pool(entries)
        print(f"[flow] Imported {len(entries)} route(s) from {a.uris} -> {FLOW_POOL}")
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
