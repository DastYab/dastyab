#!/usr/bin/env python3
"""
dastyab aistudio (Lion Engine) — brutal, multi-layer anti-geoblock access to
Google AI Studio + Gemini on Linux.

LAYERS (Lion Algorithm):
  L0 supply    — union of fresh_vless.json, flow_pool.json, nodes.json,
                 Nekoray/Sing-Box/Clash/v2rayN/OpenVPN stores, ~/Downloads &
                 DastYab vault files (.npv/.npvt/.npvs/.ovpn/.conf/.wg/.hc/
                 .ehi/.json/.yaml/.sub/.txt), multi-protocol URIs (vless/vmess/
                 trojan/ss/wireguard/hy2/tuic/socks5/http), and local proxy
                 bridges (Tor 9050, WARP 40000, Clash 7890, Sing-Box 2080,
                 xray 10808, Hiddify 12334, Psiphon/WireProxy).
  L1 transport — xray + optional sing-box sidecar outbounds (vless, vmess,
                 trojan, ss, wireguard, hy2, tuic, socks, http) + uTLS
                 fingerprint mutation + DoH routing.
  L2 DPI-desync— xray `freedom` outbound TLS-Hello packet fragmentation
                 (`packets: tlshello`, `length: 10-30`, `interval: 10-20`) under
                 the entry hop to defeat ISP SNI inspection & RST injection.
  L3 cascade   — arbitrary 1..8 hop chains via `sockopt.dialerProxy` across
                 distinct `/16` subnets + bidirectional swaps + local-proxy
                 entry bridges: geo-blocked nodes become Entry/Relay hops!
  L4 Lion gate — live egress IP + Cloudflare `/cdn-cgi/trace` (`warp`, `loc`)
                 + multi-provider Geo/ASN reputation scoring + strict redirect/
                 HTTP/DOM check on aistudio.google.com,
                 generativelanguage.googleapis.com, and accounts.google.com.
  L5 bandit    — UCB1 route selection + persistent isolated `lion_blacklist.json`
                 (TTL-aged blocked exits are skipped for exits, kept for relays).
  L6 browser   — hardened Chrome launch pinned to SOCKS5 with anti-DNS-leak
                 `--host-resolver-rules`, `--force-webrtc-ip-handling-policy=
                 disable_non_proxied_udp`, and country-aligned TZ / `--lang`.

USAGE:
  dastyab-aistudio.py start [idx] [--hops 1..8] [--country XX] [--brutal]
  dastyab-aistudio.py best  [--try N] [--hops 1..8] [--country XX] [--brutal]
  dastyab-aistudio.py prove [--try N] [--hops 1..8] [--country XX] [--profile DIR]
  dastyab-aistudio.py verify / status / next / watch [secs] / stop / build-pool <uris.txt>
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
POOL = os.path.join(PROFILE_DIR, "fresh_vless.json")
FLOW_POOL = os.path.join(PROFILE_DIR, "flow_pool.json")
NODES_JSON = os.path.join(PROFILE_DIR, "nodes.json")
NEKORAY_PROFILES = os.path.join(HOME, ".config/nekoray/config/profiles")
BLACKLIST_PATH = os.path.join(PROFILE_DIR, "lion_blacklist.json")
BANDIT_PATH = os.path.join(PROFILE_DIR, "lion_bandit.json")
STATEFILE = "/tmp/dastyab_aistudio_state.json"

SOCK = int(os.environ.get("DASTYAB_AISTUDIO_SOCKS", "10850"))
PIDFILE = "/tmp/dastyab_aistudio.pid"
CFGPATH = "/tmp/dastyab_aistudio.json"
IDXFILE = "/tmp/dastyab_aistudio_idx"
AISTUDIO_URL = "https://aistudio.google.com/"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/"
ACCOUNTS_URL = "https://accounts.google.com/"
IPIFY_URL = "https://api.ipify.org"
CF_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"

LION_BLOCKED_COUNTRIES = frozenset(("IR", "CN", "RU", "KP", "SY", "CU", "BY"))
GEO_BLOCK_URL_MARKERS = (
    "unsupported-country",
    "available-regions",
    "/sorry/",
    "region-not-supported",
)
GEO_BLOCK_BODY_MARKERS = (
    "unsupported-country-title",
    "not available in your country",
    "isn't available in your country",
    "google ai studio is not available",
)

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

CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
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


# ---------------------------------------------------------------------------
# Core discovery
# ---------------------------------------------------------------------------

def find_xray():
    """Locate an xray-compatible core."""
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.environ.get("DASTYAB_XRAY", ""),
        os.path.join(here, "xray"),
        os.path.join(HOME, ".dastyab/bin/xray"),
        "/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray",
        "/tmp/xraybin/xray",
        "/opt/v2rayN/bin/xray/xray",
        "/opt/nekoray/nekoray_core", "/opt/nekoray/nekobox_core",
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
        "[aistudio] No xray core found. Install xray and put it on PATH, or set "
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


_XRAY_VERSION = None


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
# JSON / persistence helpers
# ---------------------------------------------------------------------------

def _read_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def _write_json_atomic(path, obj):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=1)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# L0 — URI parsing & candidate supply
# ---------------------------------------------------------------------------

def parse_vless(line):
    """Parse one `vless://` share URI into a pool entry."""
    line = line.split("#")[0].strip()
    m = re.match(r"vless://([^@]*)@([^:]+):(\d+)\?(.*)", line)
    if not m:
        return None
    uuid, host, port, qs = m.group(1), m.group(2), int(m.group(3)), m.group(4)
    if not uuid or not host:
        return None
    return {"uuid": uuid, "addr": host, "port": port,
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
        v = parse_vless(s)
        if v:
            v["proto"] = "vless"
        return v
    if low.startswith("vmess://"):
        try:
            payload = s[8:].split("#")[0].strip()
            obj = json.loads(_b64_decode(payload).decode("utf-8", "replace"))
            addr = obj.get("add", "")
            port = int(obj.get("port", 0))
            uid = obj.get("id", "")
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
        if "@" in body:
            cred, hp = body.split("@", 1)
            hp = hp.split("?")[0]
            if ":" not in cred:
                try:
                    cred = _b64_decode(cred).decode("utf-8", "replace")
                except Exception:
                    return None
            if ":" not in cred:
                return None
            method, pw = cred.split(":", 1)
            host, port = _parse_host_port(hp)
        else:
            try:
                dec = _b64_decode(body.split("?")[0]).decode("utf-8", "replace")
                cred, hp = dec.rsplit("@", 1)
                method, pw = cred.split(":", 1)
                host, port = _parse_host_port(hp)
            except Exception:
                return None
        if not host:
            return None
        return {"proto": "ss", "addr": host, "port": port,
                "method": method, "password": pw, "q": {}}
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
        return {
            "proto": "wireguard",
            "addr": host,
            "port": port,
            "secret": urllib.parse.unquote(priv),
            "q": q,
        }
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
        proto = "socks" if u.scheme.startswith("socks") else "http"
        return {
            "proto": proto,
            "addr": u.hostname,
            "port": int(u.port),
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
                    "addr": parts[1],
                    "port": p,
                    "q": {},
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
        # Sing-Box flat shape
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
        # Xray nested settings shape
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
    """Convert a nekoray bean dict into Lion's uniform node shape."""
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
    """Return IPv4 `/16` prefix (`a.b`) or domain root for subnet diversity."""
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
    """Probe common Linux proxy ports (Tor/WARP/Clash/Sing-Box/Nekoray/Xray)."""
    found = []
    for port, proto, label in LOCAL_PROXY_PORTS:
        if port == SOCK:
            continue
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            found.append({
                "proto": proto,
                "addr": "127.0.0.1",
                "port": port,
                "local": True,
                "name": label,
                "q": {},
            })
        except OSError:
            pass
        finally:
            s.close()
    return found


def load_lion_candidates(limit=4096):
    """Load and deduplicate multi-protocol candidates from all local stores & config vaults."""
    out, seen = [], set()
    allowed = (
        "vless", "vmess", "trojan", "ss", "shadowsocks",
        "wireguard", "hy2", "hysteria2", "tuic", "socks", "http",
    )

    def add(srv):
        if not srv or not srv.get("addr") or not srv.get("port"):
            return
        if "nodes" in srv and isinstance(srv["nodes"], list):
            for n in srv["nodes"]:
                add(n)
            return
        proto = srv.get("proto") or ("vless" if srv.get("uuid") else "")
        if proto not in allowed:
            return
        srv = dict(srv)
        srv["proto"] = proto
        k = (str(srv["addr"]), int(srv["port"]), proto)
        if k in seen:
            return
        seen.add(k)
        out.append(srv)

    for e in _read_json(POOL, []):
        if isinstance(e, dict):
            add(e)
    for e in _read_json(FLOW_POOL, []):
        if isinstance(e, dict):
            add(e)
    for f in sorted(glob.glob(os.path.join(NEKORAY_PROFILES, "*.json"))):
        d = _read_json(f, {})
        if isinstance(d, dict):
            add(_bean_to_server(d.get("bean", {}) or {}, d.get("type", "")))
    nodes_doc = _read_json(NODES_JSON, {})
    items = nodes_doc.get("nodes", []) if isinstance(nodes_doc, dict) else (
        nodes_doc if isinstance(nodes_doc, list) else []
    )
    items_sorted = sorted(items, key=lambda n: not (isinstance(n, dict) and n.get("healthy", False)))
    for n in items_sorted:
        if isinstance(n, dict):
            add(parse_node_uri(n.get("url", "")))
    for n in gather_multi_format_candidates():
        add(n)
    return out[:limit]


# ---------------------------------------------------------------------------
# L1 + L2 + L3 — Outbound, DPI Fragment, and Arbitrary N-hop Config Builders
# ---------------------------------------------------------------------------

def _build_outbound(server, tag="proxy"):
    proto = server.get("proto") or ("vless" if server.get("uuid") else "vless")
    q = server.get("q", {}) or {}
    addr = server["addr"]
    port = int(server["port"])

    if proto == "vless":
        out = {"tag": tag, "protocol": "vless",
               "settings": {"vnext": [{"address": addr, "port": port,
                    "users": [{"id": server["uuid"], "encryption": "none"}]}]}}
        sec = q.get("security", "none")
        flow = q.get("flow")
        if flow and sec in ("tls", "reality") and xray_supports_vision():
            out["settings"]["vnext"][0]["users"][0]["flow"] = flow
    elif proto == "vmess":
        out = {"tag": tag, "protocol": "vmess",
               "settings": {"vnext": [{"address": addr, "port": port,
                    "users": [{"id": server["uuid"], "alterId": 0}]}]}}
    elif proto == "trojan":
        out = {"tag": tag, "protocol": "trojan",
               "settings": {"servers": [{"address": addr, "port": port,
                                         "password": server.get("password", "")}]}}
    elif proto in ("ss", "shadowsocks"):
        out = {"tag": tag, "protocol": "shadowsocks",
               "settings": {"servers": [{"address": addr, "port": port,
                    "method": server.get("method", "aes-256-gcm"),
                    "password": server.get("password", "")}]}}
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
        srv_obj = {"address": addr, "port": port}
        if server.get("user"):
            srv_obj["users"] = [{"user": server["user"], "pass": server.get("password", "")}]
        return {"tag": tag, "protocol": "socks", "settings": {"servers": [srv_obj]}}
    elif proto == "http":
        srv_obj = {"address": addr, "port": port}
        if server.get("user"):
            srv_obj["users"] = [{"user": server["user"], "pass": server.get("password", "")}]
        return {"tag": tag, "protocol": "http", "settings": {"servers": [srv_obj]}}
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
        if q.get("pinSHA256"):
            ss["tlsSettings"]["pinnedPeerCertSha256"] = [q["pinSHA256"]]
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
    cfg_path = f"/tmp/dastyab_aistudio_sb_{lport}.json"
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


def build_lion_cfg(nodes, port=SOCK, fragment=False, allow_sidecar=False):
    """Build 1..8+ hop xray config (`[exit, relay1, ..., entry]`) + optional TLS fragment."""
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
    for idx, srv in enumerate(resolved):
        if idx == 0:
            tag = "exit"
        elif idx + 1 == len(resolved):
            tag = "entry"
        else:
            tag = f"relay-{idx}"
        ob = _build_outbound(srv, tag=tag)
        if ob is None:
            return None
        if idx + 1 < len(resolved):
            nxt = "entry" if idx + 2 == len(resolved) else f"relay-{idx + 1}"
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
    else:
        outbounds.append({"protocol": "freedom", "tag": "direct"})

    inb = {"listen": "127.0.0.1", "port": port, "protocol": "socks",
           "settings": {"auth": "noauth", "udp": True}, "tag": "socks-in"}
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["https://1.1.1.1/dns-query", "8.8.8.8"], "queryStrategy": "UseIPv4"},
        "routing": {"domainStrategy": "IPIfNonMatch"},
        "inbounds": [inb],
        "outbounds": outbounds,
    }


def build_entry_exit_chain(entry, exit_node, port=SOCK, fragment=True, fp="chrome"):
    """Build PattNG-style Entry (WARP/WireGuard/Proxy) -> Exit config with fragment + fingerprint."""
    ex = mutate_fp(exit_node, fp) if fp else dict(exit_node)
    return build_lion_cfg([ex, entry], port=port, fragment=fragment, allow_sidecar=True)


def build_cfg(server):
    """Build xray config for a single Server or a Lion route entry."""
    if isinstance(server, dict) and isinstance(server.get("nodes"), list):
        return build_lion_cfg(
            server["nodes"],
            SOCK,
            fragment=bool(server.get("fragment", False)),
            allow_sidecar=bool(server.get("allow_sidecar", False)),
        )
    ob = _build_outbound(server, tag="proxy")
    if ob is None:
        return None
    ob.pop("tag", None)
    inb = {"listen": "127.0.0.1", "port": SOCK, "protocol": "socks",
           "settings": {"auth": "noauth", "udp": True}, "tag": "socks-in"}
    return {"log": {"loglevel": "warning"}, "inbounds": [inb],
            "outbounds": [ob, {"protocol": "freedom", "tag": "direct"}]}


# ---------------------------------------------------------------------------
# Reputation, Blacklist, and Bandit
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
    bl = _read_json(BLACKLIST_PATH, {})
    ts = bl.get(key)
    return bool(ts and (time.time() - ts) < ttl)


def _remember_blocked_exit(key, ttl=21600):
    now = time.time()
    bl = _read_json(BLACKLIST_PATH, {})
    bl = {k: v for k, v in bl.items() if (now - v) < ttl}
    bl[key] = now
    _write_json_atomic(BLACKLIST_PATH, bl)


def _bandit_record(arm_id, ok, latency_ms=None, clean_score=0):
    db = _read_json(BANDIT_PATH, {})
    st = db.get(arm_id, {"wins": 1.0, "trials": 2.0, "ewma_ms": 800.0, "clean": clean_score})
    st["wins"] = st["wins"] * 0.9 + (1.0 if ok else 0.0)
    st["trials"] = max(1.0, st["trials"] * 0.9) + 1.0
    if latency_ms is not None and latency_ms > 0:
        st["ewma_ms"] = 0.3 * latency_ms + 0.7 * st.get("ewma_ms", latency_ms)
    if clean_score:
        st["clean"] = clean_score
    db[arm_id] = st
    _write_json_atomic(BANDIT_PATH, db)


def _bandit_score(arm_id, db=None):
    db = db if db is not None else _read_json(BANDIT_PATH, {})
    total = max(2.0, sum(v.get("trials", 2.0) for v in db.values()))
    st = db.get(arm_id)
    if not st:
        return 0.75 + 0.45 * math.sqrt(math.log(total))
    win_rate = st["wins"] / max(1.0, st["trials"])
    explore = 0.45 * math.sqrt(math.log(total) / max(1.0, st["trials"]))
    lat_pen = min(0.45, st.get("ewma_ms", 800.0) / 3000.0)
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


def _curl(args, timeout=15):
    try:
        return subprocess.run(
            ["curl", "-s", "--max-time", str(timeout),
             "--socks5-hostname", f"127.0.0.1:{SOCK}"] + args,
            capture_output=True, text=True, timeout=timeout + 5)
    except (OSError, subprocess.SubprocessError):
        return None


def _route_label(srv):
    if isinstance(srv, dict) and isinstance(srv.get("nodes"), list):
        lbl = " <- ".join(f"{n.get('proto', 'vless')} {n['addr']}:{n['port']}" for n in srv["nodes"])
        return lbl + (" +frag" if srv.get("fragment") else "")
    return f"{srv['addr']}:{srv['port']}"


def _bring_up_raw(srv):
    """Spawn xray core for `srv` without probing egress yet. Returns proc or raises SystemExit."""
    cfg = build_cfg(srv)
    if cfg is None:
        return None
    with open(CFGPATH, "w") as fh:
        json.dump(cfg, fh)
    xray = find_xray()
    try:
        proc = subprocess.Popen([xray, "run", "-c", CFGPATH],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        raise SystemExit(f"[aistudio] Cannot launch {xray}: {e}")
    open(PIDFILE, "w").write(str(proc.pid))
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
            os.remove(PIDFILE)
        except OSError:
            pass
        detail = (
            f"{xray} exited immediately (code {rc}) — it does not accept "
            f"`run -c <config>`; that is a nekoray wrapper, not an xray core"
            if rc is not None
            else f"{xray} never opened 127.0.0.1:{SOCK}"
        )
        raise SystemExit(
            f"[aistudio] Tunnel failed to start: {detail}.\n"
            f"[aistudio] Set DASTYAB_XRAY=/path/to/xray (a real xray core)."
        )
    return proc


def _bring_up(srv, announce=True):
    """Start one core on one pool/chain entry; return the egress IP, or None."""
    proc = _bring_up_raw(srv)
    if proc is None:
        return None
    ip = probe_egress(timeout=20)
    if ip and announce:
        print(f"[aistudio] Tunnel started via {_route_label(srv)} (pid {proc.pid})")
        print(f"[aistudio] Local SOCKS5 proxy: 127.0.0.1:{SOCK}")
    return ip


def probe_egress(timeout=12):
    """Return current egress IP via tunnel, or None if tunnel dead."""
    r = _curl([IPIFY_URL], timeout=timeout)
    if not r:
        return None
    out = (r.stdout or "").strip()
    return out if out and not out.startswith("curl") and len(out) < 60 else None


# ---------------------------------------------------------------------------
# L4 — Strict Lion AI Studio Geo/ASN/Redirect/DOM Gate
# ---------------------------------------------------------------------------

def _curl_with_meta(url, timeout=22):
    r = _curl([
        "-L", "--max-redirs", "6",
        "-H", f"User-Agent: {CHROME_UA}",
        "-H", "Accept: text/html,application/xhtml+xml,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-w", "\n__DYB_META__:%{http_code}:%{url_effective}",
        url,
    ], timeout=timeout)
    if not r:
        return 0, url, ""
    txt = r.stdout or ""
    code, eff = 0, url
    if "__DYB_META__:" in txt:
        body, meta = txt.rsplit("__DYB_META__:", 1)
        parts = meta.strip().split(":", 1)
        try:
            code = int(parts[0])
        except ValueError:
            code = 0
        if len(parts) > 1 and parts[1]:
            eff = parts[1].strip()
        return code, eff, body
    return 200 if txt else 0, url, txt


def _fetch_geo_asn():
    trace = {}
    r_tr = _curl([CF_TRACE_URL], 10)
    if r_tr and r_tr.stdout and "warp=" in r_tr.stdout:
        trace = parse_cf_trace(r_tr.stdout)

    geo = {}
    r1 = _curl(["http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,proxy,hosting"], 12)
    if r1 and r1.stdout:
        try:
            d = json.loads(r1.stdout)
            if d.get("status") == "success":
                geo = {
                    "country": (d.get("countryCode") or "").upper(),
                    "country_name": d.get("country", ""),
                    "org": f"{d.get('isp', '')} {d.get('org', '')}".strip(),
                    "asn": d.get("as", ""),
                    "proxy": bool(d.get("proxy")),
                    "hosting": bool(d.get("hosting")),
                }
        except json.JSONDecodeError:
            pass

    if not geo:
        r2 = _curl(["https://ipwho.is/"], 12)
        if r2 and r2.stdout:
            try:
                d = json.loads(r2.stdout)
                if d.get("success"):
                    conn = d.get("connection") or {}
                    geo = {
                        "country": (d.get("country_code") or "").upper(),
                        "country_name": d.get("country", ""),
                        "org": conn.get("isp") or conn.get("org") or "",
                        "asn": f"AS{conn['asn']}" if conn.get("asn") else "",
                        "proxy": False,
                        "hosting": False,
                    }
            except json.JSONDecodeError:
                pass

    if not geo and trace.get("loc"):
        geo = {
            "country": trace["loc"].upper(),
            "country_name": trace["loc"].upper(),
            "org": "Cloudflare Trace",
            "asn": "",
            "proxy": False,
            "hosting": False,
        }
    if not geo:
        return None
    is_warp = trace.get("warp", "").lower() in ("on", "plus")
    rep, cscore = classify_asn_reputation(geo["org"], geo["proxy"], geo["hosting"], is_warp)
    geo["warp"] = is_warp
    geo["reputation"] = rep
    geo["clean_score"] = cscore
    return geo


def probe_lion_gates(want_country=None, strict=False, use_browser=False):
    """Run strict Lion verification on the currently active SOCKS5 tunnel."""
    res = {
        "egress": None, "country": None, "country_name": None,
        "reputation": None, "clean_score": 0, "warp": False,
        "aistudio_ok": False, "gemini_ok": False, "accounts_ok": False,
        "latency_ms": None, "verdict": False, "reason": "",
    }
    t0 = time.time()
    ip = probe_egress(timeout=18)
    if not ip:
        res["reason"] = "no egress IP (tunnel dead at far end)"
        return res
    res["egress"] = ip

    geo = _fetch_geo_asn()
    if not geo or not geo.get("country"):
        res["latency_ms"] = int((time.time() - t0) * 1000)
        res["reason"] = "geo/ASN lookup failed through tunnel"
        return res
    res["country"] = geo["country"]
    res["country_name"] = geo["country_name"]
    res["reputation"] = geo["reputation"]
    res["clean_score"] = geo["clean_score"]
    res["warp"] = geo["warp"]
    res["latency_ms"] = int((time.time() - t0) * 1000)

    if res["country"] in LION_BLOCKED_COUNTRIES:
        res["reason"] = f"egress {ip} in blocked country {res['country']}"
        return res
    if want_country and res["country"] != want_country.upper():
        res["reason"] = f"country {res['country']} != requested {want_country.upper()}"
        return res
    if strict and res["warp"]:
        res["reason"] = "Cloudflare WARP egress rejected in strict Lion mode (use as entry)"
        return res

    code_ai, eff_ai, body_ai = _curl_with_meta(AISTUDIO_URL, timeout=24)
    low_eff = eff_ai.lower()
    low_body = body_ai.lower()
    if code_ai in (0, 403, 451, 429) or code_ai >= 500:
        res["reason"] = f"aistudio.google.com blocked/unreachable (HTTP {code_ai})"
        return res
    for m in GEO_BLOCK_URL_MARKERS:
        if m in low_eff:
            res["reason"] = f"AI Studio redirected to geo-block ({m})"
            return res
    for m in GEO_BLOCK_BODY_MARKERS:
        if m in low_body:
            res["reason"] = f"AI Studio returned geo-block marker ({m})"
            return res
    res["aistudio_ok"] = True

    code_gem, _, _ = _curl_with_meta(GEMINI_API_URL, timeout=18)
    res["gemini_ok"] = 200 <= code_gem < 500 and code_gem not in (403, 451)
    if not res["gemini_ok"]:
        res["reason"] = f"generativelanguage.googleapis.com blocked (HTTP {code_gem})"
        return res

    code_acc, _, _ = _curl_with_meta(ACCOUNTS_URL, timeout=18)
    res["accounts_ok"] = 200 <= code_acc < 500
    if not res["accounts_ok"]:
        res["reason"] = f"accounts.google.com unreachable (HTTP {code_acc})"
        return res

    if use_browser:
        b_ok, b_msg = lion_browser_gate()
        if b_ok is False:
            res["reason"] = b_msg
            return res

    res["verdict"] = True
    res["reason"] = (
        f"egress {ip} ({res['country']} / {res['reputation']}, "
        f"score={res['clean_score']}); AI Studio + Gemini + Accounts CLEAR"
    )
    return res


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


def lion_browser_gate(timeout=120, profile_dir=None):
    ch = find_browser()
    if ch is None:
        return None, "no Chromium browser found"
    prof = profile_dir or os.path.join("/tmp", f"dastyab-lion-gate-{os.getpid()}")
    args = hardened_browser_args(ch, prof, AISTUDIO_URL)
    args = [args[0], "--headless=new", "--disable-gpu", "--virtual-time-budget=12000", "--dump-dom"] + args[1:]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        dom = r.stdout or ""
    except subprocess.TimeoutExpired as e:
        dom = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        if not dom:
            return None, "browser gate timed out"
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"browser error: {e}"
    finally:
        if profile_dir is None:
            shutil.rmtree(prof, ignore_errors=True)
    low = dom.lower()
    for m in GEO_BLOCK_BODY_MARKERS:
        if m in low:
            return False, f"REGION-GATE: browser showed AI Studio block ({m})"
    if len(dom) < 600:
        return False, "browser rendered empty page"
    return True, "browser loaded Google AI Studio cleanly"


# ---------------------------------------------------------------------------
# Brutal Lion Multi-Layer Escalation Engine
# ---------------------------------------------------------------------------

def _try_lion_route(nodes, fragment=False, want_country=None, strict=False, use_browser=False):
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
    route = bridged[0] if len(bridged) == 1 and not fragment else {"nodes": bridged, "fragment": fragment}
    try:
        proc = _bring_up_raw(route)
    except SystemExit:
        stop(quiet=True)
        return None
    if proc is None:
        stop(quiet=True)
        return None
    try:
        return probe_lion_gates(want_country=want_country, strict=strict, use_browser=use_browser)
    finally:
        stop(quiet=True)


def lion_hunt(cands, try_n=18, max_hops=8, want_country=None, strict=False, use_browser=False):
    """Progressive 6-stage Lion multi-layer hunt (1..8 layers) until clear AI Studio egress."""
    if not cands:
        return []
    max_hops = max(1, min(8, int(max_hops or 8)))
    bandit_db = _read_json(BANDIT_PATH, {})
    ranked = sorted(cands, key=lambda c: _bandit_score(node_key(c), bandit_db), reverse=True)
    locals_ = discover_local_proxies()
    passing, relays, timeouts = [], [], []
    seen_chains = set()

    def record(nodes, frag, g, stage):
        entry = dict(nodes[0])
        entry.update({
            "nodes": nodes,
            "fragment": frag,
            "stage": stage,
            "egress": g["egress"],
            "country": g["country"],
            "country_name": g["country_name"],
            "reputation": g["reputation"],
            "clean_score": g["clean_score"],
            "latency_ms": g["latency_ms"],
            "checked_epoch": time.time(),
        })
        passing.append(entry)
        for n in nodes:
            _bandit_record(node_key(n), True, g["latency_ms"], g["clean_score"])

    # Stage 0: Diverse /16 fast 1-hop candidates (skip known blocked exits).
    checked = 0
    for c in ranked:
        if checked >= try_n or len(passing) >= 4:
            break
        k = node_key(c)
        if _is_blacklisted(k):
            relays.append(c)
            continue
        checked += 1
        print(f"[lion] [S0:{checked}] 1-hop {_route_label(c)} ...", flush=True)
        g = _try_lion_route([c], False, want_country, strict, use_browser)
        if g and g["verdict"]:
            print(f"[lion]     CLEAR {g['reason']} ({g['latency_ms']}ms)", flush=True)
            record([c], False, g, "stage0-1hop")
        elif g and g.get("egress"):
            relays.append(c)
            _remember_blocked_exit(k)
            print(f"[lion]     exit blocked ({g['reason']}) -> saved as RELAY", flush=True)
        else:
            timeouts.append(c)
            _bandit_record(k, False)
            print(f"[lion]     dead/blocked TCP ({(g or {}).get('reason', 'timeout')})", flush=True)

    if len(passing) >= 2 or max_hops < 1:
        return passing

    # Stage 1: DPI TLS-Hello Fragmentation + uTLS fingerprint mutation.
    frag_pool = (timeouts + [c for c in ranked if c not in timeouts])[:min(8, try_n)]
    print("[lion] Stage 1: Engaging TLS-Hello DPI fragmentation + uTLS mutation ...", flush=True)
    for idx, c in enumerate(frag_pool, 1):
        if len(passing) >= 3:
            break
        if c.get("local") or c.get("proto") in ("socks", "http", "wireguard"):
            continue
        mutated = mutate_fp(c, MUTABLE_FPS[idx % len(MUTABLE_FPS)])
        print(f"[lion] [S1:{idx}] 1-hop+frag {_route_label(mutated)} ...", flush=True)
        g = _try_lion_route([mutated], True, want_country, strict, use_browser)
        if g and g["verdict"]:
            print(f"[lion]     CLEAR (fragment) {g['reason']}", flush=True)
            record([mutated], True, g, "stage1-fragment")
        elif g and g.get("egress") and c not in relays:
            relays.append(c)

    if passing:
        return passing

    # Stage 2: Local proxy bridge -> Clean Exit (Tor/WARP/Clash/Sing-Box + Exit).
    if locals_ and max_hops >= 2:
        print(f"[lion] Stage 2: Testing {len(locals_)} local proxy bridge(s) as entry hops ...", flush=True)
        for lp in locals_:
            for exit_c in ranked[:8]:
                sig = (node_key(exit_c), node_key(lp))
                if sig in seen_chains:
                    continue
                seen_chains.add(sig)
                nodes = [exit_c, lp]
                print(f"[lion] [S2] bridge {_route_label({'nodes': nodes})} ...", flush=True)
                g = _try_lion_route(nodes, False, want_country, strict, use_browser)
                if g and g["verdict"]:
                    print(f"[lion]     CLEAR (local-bridge) {g['reason']}", flush=True)
                    record(nodes, False, g, "stage2-local-bridge")
                    break
            if passing:
                break

    if passing or max_hops < 2:
        return passing

    # Stage 3: Cross-/16 subnet 2-hop chains + bidirectional swaps + frag.
    entry_pool = relays[:8] if relays else ranked[:8]
    exit_pool = [c for c in ranked if not _is_blacklisted(node_key(c))][:12] or ranked[:12]
    print("[lion] Stage 3: Engaging cross-/16 2-hop chains + DPI fragment ...", flush=True)
    for ex in exit_pool:
        for en in entry_pool:
            if node_key(ex) == node_key(en) or subnet_prefix16(ex["addr"]) == subnet_prefix16(en["addr"]):
                continue
            for frag in (False, True):
                sig = (node_key(ex), node_key(en), frag)
                if sig in seen_chains:
                    continue
                seen_chains.add(sig)
                nodes = [ex, mutate_fp(en, "random") if frag else en]
                print(f"[lion] [S3] {_route_label({'nodes': nodes, 'fragment': frag})} ...", flush=True)
                g = _try_lion_route(nodes, frag, want_country, strict, use_browser)
                if g and g["verdict"]:
                    print(f"[lion]     CLEAR (2-hop) {g['reason']}", flush=True)
                    record(nodes, frag, g, "stage3-2hop")
                    break
            if len(passing) >= 2:
                break
        if len(passing) >= 2:
            break

    if passing or max_hops < 3:
        return passing

    # Stage 4: 3-hop & 4-hop cascades.
    if len(entry_pool) >= 2 and exit_pool:
        print("[lion] Stage 4: Engaging 3-hop & 4-hop brutal cascades ...", flush=True)
        for ex in exit_pool[:4]:
            r1_list = [r for r in entry_pool if node_key(r) != node_key(ex)]
            for r1 in r1_list[:3]:
                for en in entry_pool[:4]:
                    if node_key(en) in (node_key(ex), node_key(r1)):
                        continue
                    chain = [ex, r1, en]
                    if max_hops >= 4:
                        extra = next((x for x in locals_ + entry_pool
                                      if node_key(x) not in {node_key(n) for n in chain}), None)
                        if extra:
                            chain.append(extra)
                    sig = tuple(node_key(n) for n in chain)
                    if sig in seen_chains:
                        continue
                    seen_chains.add(sig)
                    print(f"[lion] [S4] {_route_label({'nodes': chain, 'fragment': True})} ...", flush=True)
                    g = _try_lion_route(chain, True, want_country, strict, use_browser)
                    if g and g["verdict"]:
                        print(f"[lion]     CLEAR ({len(chain)}-hop) {g['reason']}", flush=True)
                        record(chain, True, g, f"stage4-{len(chain)}hop")
                        return passing

    if passing or max_hops < 5:
        return passing

    # Stage 5: Ultra-deep 5..=8 hop cascades with protocol & /16 diversity + local bridge anchor.
    combined_relays = []
    seen_rel = set()
    for r in relays + ranked + locals_:
        rk = node_key(r)
        if rk not in seen_rel:
            seen_rel.add(rk)
            combined_relays.append(r)

    print(f"[lion] Stage 5: Escalating up to {max_hops}-hop ultra-deep Lion cascades ...", flush=True)
    for depth in range(5, max_hops + 1):
        for shift in range(min(4, len(exit_pool))):
            ex = exit_pool[shift]
            chain = [ex]
            used = {node_key(ex)}
            # Pick diverse protocol & /16 relays
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
            print(f"[lion] [S5:{depth}hop] {_route_label({'nodes': chain, 'fragment': True})} ...", flush=True)
            g = _try_lion_route(chain, True, want_country, strict, use_browser)
            if g and g["verdict"]:
                print(f"[lion]     CLEAR ({depth}-hop) {g['reason']}", flush=True)
                record(chain, True, g, f"stage5-{depth}hop")
                return passing
    return passing


# ---------------------------------------------------------------------------
# Public Commands (backward-compatible + Lion enhancements)
# ---------------------------------------------------------------------------

def start(server_index=0, hops=None, want_country=None, brutal=False):
    if is_running():
        print(f"[aistudio] Tunnel already running on 127.0.0.1:{SOCK}")
        print("[aistudio] Opening AI Studio through the existing tunnel...")
        launch_browser()
        return True, None
    try:
        with open(POOL) as fh:
            pool = json.load(fh)
    except FileNotFoundError:
        if brutal:
            pool = []
        else:
            raise SystemExit(
                "[aistudio] No server pool yet. Run: dastyab aistudio verify"
            )
    except (json.JSONDecodeError, OSError) as e:
        raise SystemExit(f"[aistudio] Server pool is unreadable ({e}). Run: dastyab aistudio verify")

    if not pool and not brutal:
        raise SystemExit(
            "[aistudio] Server pool is empty. Run: dastyab aistudio verify"
        )

    if pool:
        first = server_index % len(pool)
        order = [first] + [(first + off) % len(pool) for off in range(1, len(pool))]
        dead = []
        for idx in order:
            entry = pool[idx]
            if hops == 1 and isinstance(entry, dict) and isinstance(entry.get("nodes"), list):
                entry = entry["nodes"][0]
            egress = _bring_up(entry)
            if egress:
                if dead:
                    print(f"[aistudio] Skipped dead node(s): {', '.join(dead)}",
                          file=sys.stderr)
                open(IDXFILE, "w").write(str(idx))
                _write_json_atomic(STATEFILE, {
                    "idx": idx, "egress": egress,
                    "country": entry.get("country") if isinstance(entry, dict) else None,
                    "verified_epoch": time.time(),
                })
                print(f"[aistudio] Clean egress IP: {egress}")
                print("[aistudio] Opening AI Studio through the tunnel...")
                launch_browser()
                return True, idx
            dead.append(f"{entry['addr']}:{entry['port']}")
            stop(quiet=True)

    if brutal:
        print("[lion] Pool exhausted — engaging brutal multi-layer Lion hunt ...", file=sys.stderr)
        found = lion_hunt(load_lion_candidates(), try_n=24, max_hops=hops or 8, want_country=want_country)
        if found:
            _write_json_atomic(POOL, found)
            egress = _bring_up(found[0])
            if egress:
                open(IDXFILE, "w").write("0")
                _write_json_atomic(STATEFILE, {
                    "idx": 0, "egress": egress, "country": found[0].get("country"),
                    "verified_epoch": time.time(),
                })
                print(f"[aistudio] Clean egress IP: {egress}")
                launch_browser()
                return True, 0

    print("[aistudio] WARNING: every node in the pool is dead at the far end.",
          file=sys.stderr)
    print("[aistudio] Run `dastyab aistudio verify` to rebuild the pool from "
          "fresh server cards.", file=sys.stderr)
    return False, None


def watch(interval=20, max_fail=2):
    """Self-healing Lion watchdog: monitors tunnel & rotates automatically."""
    def load_pool():
        try:
            with open(POOL) as fh:
                return json.load(fh), None
        except FileNotFoundError:
            return None, "no server pool yet"
        except (json.JSONDecodeError, OSError) as e:
            return None, f"pool unreadable ({e})"

    pool, why = load_pool()
    if not pool:
        raise SystemExit(
            f"[aistudio] Cannot watch: {why}. Run: dastyab aistudio verify"
        )
    fail = 0
    idx = 0
    if os.path.exists(IDXFILE):
        try:
            idx = int(open(IDXFILE).read())
        except (OSError, ValueError):
            pass
    print(f"[aistudio] Lion Watchdog started: probing every {interval}s (pool={len(pool)})")
    while True:
        time.sleep(interval)
        ip = probe_egress()
        if ip:
            fail = 0
            continue
        fail += 1
        if fail < max_fail:
            continue
        print(f"[aistudio] Tunnel down (probe {fail}). Rotating server...")
        stop(quiet=True)
        time.sleep(1)
        fresh, why = load_pool()
        if fresh:
            pool = fresh
            idx %= len(pool)
        else:
            print(f"[aistudio] Cannot rotate: {why}. Keeping the watchdog alive.",
                  file=sys.stderr)
            time.sleep(interval)
            continue
        for off in range(1, len(pool) + 1):
            nxt = (idx + off) % len(pool)
            try:
                started, landed = start(nxt)
            except (SystemExit, OSError) as e:
                print(f"[aistudio] Rotation attempt failed: {e}", file=sys.stderr)
                started, landed = False, None
            time.sleep(4)
            if started and probe_egress():
                idx = landed if landed is not None else nxt
                fail = 0
                print(f"[aistudio] Switched to {pool[idx]['addr']}:{pool[idx]['port']}")
                break
        else:
            print("[aistudio] No server in pool responded. Will retry.", file=sys.stderr)


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
        "for p in $(pgrep -f dastyab_aistudio.json); do "
        "[ \"$p\" = \"${1}\" ] || [ \"$p\" = \"$$\" ] || kill -9 \"$p\" 2>/dev/null; done",
        "dastyab-stop", str(os.getpid())],
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
        print("[aistudio] Tunnel stopped")


def launch_browser():
    """Open AI Studio in Chromium pinned to the tunnel with DNS/WebRTC leak protection."""
    ch = find_browser()
    if ch is None:
        print("[aistudio] No Chromium-based browser found (Chrome/Chromium/Edge/Brave).")
        print(f"[aistudio] Open {AISTUDIO_URL} yourself through "
              f"socks5://127.0.0.1:{SOCK} — do NOT open it directly, that "
              f"would use your real IP.")
        return
    tmp = os.path.join(HOME, ".dastyab-aistudio-profile")
    os.makedirs(tmp, exist_ok=True)
    state = _read_json(STATEFILE, {})
    cc = state.get("country")
    _, tz = COUNTRY_LOCALE_TZ.get((cc or "").upper(), ("en-US", "America/New_York"))
    env = dict(os.environ)
    env["TZ"] = tz
    subprocess.Popen(hardened_browser_args(ch, tmp, AISTUDIO_URL, country=cc),
                     env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[aistudio] Opened the browser with anti-leak tunnel proxy.")


def verify():
    pool = json.load(open(POOL)) if os.path.exists(POOL) else []
    if not pool:
        print("[aistudio] No verified servers stored yet. Run with a server list to build the pool.")
        return
    print(f"[aistudio] {len(pool)} servers in pool — probing each one now:")
    alive = 0
    was_running = is_running()
    if was_running:
        stop(quiet=True)
    for i, s in enumerate(pool):
        ip = _bring_up(s, announce=False)
        stop(quiet=True)
        mark = f"OK   egress {ip}" if ip else "DEAD"
        if ip:
            alive += 1
        print(f"   [{i}] {_route_label(s)}  {mark}")
    print(f"[aistudio] {alive}/{len(pool)} reachable now. "
          f"`start` walks the pool and skips dead entries.")
    if alive == 0:
        print("[aistudio] Pool is dead. Rebuild it from fresh server cards "
              "with: dastyab aistudio build-pool <uris.txt>")


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
    """Rebuild pool from ANY .txt / share-URI list / VPN config file (.npv*, .ovpn, .conf, .json, .yaml, .sub)."""
    uris = _load_nodes_from_file(uris_txt)
    if not uris:
        raise SystemExit(f"[aistudio] No vless:// or proxy/VPN URIs found in {uris_txt}")

    entry_node = _resolve_entry_arg(entry_spec) if entry_spec else None
    if entry_node:
        candidates = [{"nodes": [u, entry_node], "fragment": True, **u} for u in uris]
    else:
        candidates = uris

    import random
    random.seed(1)
    random.shuffle(candidates)
    probe_limit = max(len(candidates), want) if len(candidates) <= 200 else 200
    print(f"[aistudio] {len(candidates)} unique URI(s); testing up to {probe_limit} for a pool of {want}...")

    working = []
    for u in candidates[:probe_limit]:
        ip = _probe_entry(u, probe_port)
        status = f"OK   egress {ip}" if ip else "DEAD"
        print(f"   {u['addr']}:{u['port']}  {status}", flush=True)
        if ip:
            working.append({**u, "egress": ip})
        if len(working) >= want:
            break

    if not working:
        raise SystemExit(
            "[aistudio] None of the supplied URIs are live; keeping the "
            f"existing pool at {POOL} unchanged."
        )

    _write_json_atomic(POOL, working)
    print(f"[aistudio] Built pool: {len(working)} working server(s) -> {POOL}")


def _probe_entry(u, port):
    """Test one candidate on its own port; returns egress IP if live."""
    target = u
    if isinstance(u, dict) and u.get("proto") in ("hy2", "hysteria2", "tuic") and not u.get("nodes"):
        target = {"nodes": [u], "fragment": False, "allow_sidecar": True}
    elif isinstance(u, dict) and isinstance(u.get("nodes"), list):
        target = {**u, "allow_sidecar": True}
    cfg = build_cfg(target)
    if cfg is None:
        return None
    cfg["inbounds"][0]["port"] = port
    cfgpath = f"/tmp/dastyab_buildpool_{port}.json"
    with open(cfgpath, "w") as fh:
        json.dump(cfg, fh)
    proc = None
    try:
        proc = subprocess.Popen([find_xray(), "run", "-c", cfgpath],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        r = subprocess.run(["curl", "-s", "--max-time", "12",
                            "--socks5-hostname", f"127.0.0.1:{port}", IPIFY_URL],
                           capture_output=True, text=True)
        out = (r.stdout or "").strip()
        return out if out and "curl" not in out.lower() and len(out) < 60 else None
    finally:
        if proc is not None:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.SubprocessError:
                pass


USAGE = """[aistudio] Usage:
  dastyab aistudio start [pool index]     start the tunnel + open AI Studio
  dastyab aistudio best [--try N]         brutal multi-layer Lion hunt & rank
  dastyab aistudio next                   rotate to next ranked route
  dastyab aistudio prove                  prove AI Studio access in real browser
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


def _parse_main_args(argv):
    ap = argparse.ArgumentParser(prog="dastyab-aistudio.py", add_help=False)
    ap.add_argument("action", nargs="?", default="start")
    ap.add_argument("arg", nargs="?", default=None)
    ap.add_argument("--hops", type=int, default=None)
    ap.add_argument("--country", default=None)
    ap.add_argument("--entry", default=None)
    ap.add_argument("--try", dest="try_n", type=int, default=18)
    ap.add_argument("--brutal", action="store_true")
    ap.add_argument("--strict", action="store_true")
    return ap.parse_args(argv)


if __name__ == "__main__":
    raw_cmd = sys.argv[1].strip().lower() if len(sys.argv) > 1 else "start"
    if raw_cmd in ("help", "--help", "-h"):
        print(__doc__)
        sys.exit(0)
    a = _parse_main_args(sys.argv[1:])
    cmd = a.action.strip().lower()
    if cmd in ("start", "on", "up"):
        idx = _want_int(a.arg, 0, "Pool index")
        ok, _ = start(idx, hops=a.hops, want_country=a.country, brutal=a.brutal)
        sys.exit(0 if ok else 3)
    elif cmd == "stop":
        stop()
    elif cmd == "next":
        pool = _read_json(POOL, [])
        if not pool:
            raise SystemExit("[aistudio] No pool to rotate. Run: dastyab aistudio best")
        st = _read_json(STATEFILE, {})
        nxt = (st.get("idx", 0) + 1) % len(pool)
        stop(quiet=True)
        ok, _ = start(nxt, hops=a.hops, want_country=a.country, brutal=a.brutal)
        sys.exit(0 if ok else 3)
    elif cmd == "best":
        cands = load_lion_candidates()
        if not cands:
            raise SystemExit("[aistudio] No candidates found. Supply URIs with build-pool.")
        entry_n = _resolve_entry_arg(a.entry) if a.entry else None
        if entry_n:
            cands = [{"nodes": [c, entry_n], "fragment": True, **c} for c in cands]
        found = lion_hunt(cands, try_n=a.try_n, max_hops=a.hops or 8,
                          want_country=a.country, strict=a.strict)
        if not found:
            raise SystemExit("[aistudio] Brutal Lion hunt found no clear AI Studio route.")
        _write_json_atomic(POOL, found)
        print(f"[lion] Saved {len(found)} verified Lion route(s) -> {POOL}")
    elif cmd == "prove":
        cands = load_lion_candidates()
        found = lion_hunt(cands, try_n=a.try_n, max_hops=a.hops or 8,
                          want_country=a.country, strict=a.strict, use_browser=True)
        if not found:
            raise SystemExit("[aistudio] No route proven in headless browser.")
        _write_json_atomic(POOL, found)
        _bring_up(found[0])
        print(f"[lion] Proven AI Studio route active: {_route_label(found[0])}")
    elif cmd in ("verify", "status"):
        if cmd == "status" and is_running():
            g = probe_lion_gates(want_country=a.country, strict=a.strict)
            print(f"[lion] {'PASS' if g['verdict'] else 'FAIL'}: {g['reason']}")
            sys.exit(0 if g["verdict"] else 1)
        verify()
    elif cmd == "watch":
        interval = _want_int(a.arg, 20, "Watch interval")
        watch(interval=interval)
    elif cmd == "build-pool":
        if a.arg is None:
            raise SystemExit(
                f"[aistudio] build-pool needs a file of vless:// cards.\n{USAGE}"
            )
        pop_pool(a.arg, entry_spec=a.entry)
    elif cmd == "ingest":
        if a.arg is None:
            raise SystemExit(f"[aistudio] ingest needs a file path.\n{USAGE}")
        nodes = _load_nodes_from_file(a.arg)
        if not nodes:
            raise SystemExit(f"[aistudio] No vless:// or proxy/VPN URIs found in {a.arg}")
        entry_n = _resolve_entry_arg(a.entry) if a.entry else None
        out_items = [{"nodes": [u, entry_n], "fragment": True, **u} for u in nodes] if entry_n else nodes
        _write_json_atomic(POOL, out_items)
        print(f"[aistudio] Imported {len(out_items)} node(s) from {a.arg} -> {POOL}")
    else:
        raise SystemExit(f"[aistudio] Unknown action: {cmd}\n{USAGE}")
