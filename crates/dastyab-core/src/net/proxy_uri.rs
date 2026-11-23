//! Scheme-agnostic proxy share-link parsing.
//!
//! Iranian Telegram config channels publish share-links in **many** schemes,
//! not just `vless://`. Under the doctrine (Level 1 wants Shadowsocks-2022;
//! every working transport is a way out of a blackout), DastYab must be
//! able to ingest them all. This module is the single, boring decoder that
//! turns any supported share-link into a normal form:
//!
//! ```text
//! (scheme, host, port, id, alias)
//! ```
//!
//! Supported schemes:
//! - `vless://UUID@host:port?params#frag`
//! - `trojan://PASSWORD@host:port?params#frag`
//! - `hysteria2://AUTH@host:port?params#frag`
//! - `tuic://UUID:TOKEN@host:port?params#frag` (id = part before first `:`)
//! - `ss://METHOD:PASSWORD@host:port#frag` or `ss://BASE64(...)`
//! - `vmess://BASE64(JSON)` (JSON carries `add`/`port`/`id`)
//! - `ssr://BASE64(server:port:protocol:method:obfs:password/)`
//!
//! The parser is deliberately **lossy-but-normalizing**: it extracts just
//! enough to deduplicate and probe a node, and preserves the raw link for
//! faithful v2rayN export. It never fabricates a field it cannot parse.

use base64::Engine;

/// Proxy URI schemes the node store / harvester understand.
#[rustfmt::skip]
pub const SUPPORTED_SCHEMES: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria2",
    "hysteria",
    "hy2",
    "tuic",
    "wireguard",
    "wg",
    "warp",
    "amneziawg",
    "openvpn",
    "ovpn",
    "npv",
    "npv4",
    "napsternetv",
    "juicity",
    "anytls",
    "naive+https",
    "naive+quic",
    "naive",
    "socks5",
    "socks4",
    "socks",
    "http",
    "https",
    "ssh",
    "sn",
    "dnstt",
    "slipnet",
];

/// Normalized view of a single share-link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyUri {
    /// Lowercase scheme (e.g. `vless`, `trojan`, `wireguard`, `npv4`, `mtproto`).
    pub scheme: String,
    /// Server host (IP or domain).
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Identity used for dedup: uuid (vless/vmess/tuic), password
    /// (trojan), auth token (hysteria2), private key (wireguard), secret (mtproto),
    /// or `method:password` (ss/ssr).
    pub id: String,
    /// Fragment after `#` (v2rayN alias), percent-decoded.
    pub alias: String,
    /// The raw share-link as given (params preserved).
    pub raw: String,
}

impl ProxyUri {
    /// Parse any supported share-link. Returns `None` for malformed or
    /// unsupported input.
    pub fn parse(raw: &str) -> Option<ProxyUri> {
        let raw = raw.trim();
        if is_mtproto_link(raw) {
            return parse_mtproto(raw);
        }
        let (scheme_raw, rest) = split_scheme(raw)?;
        let scheme = scheme_raw.to_ascii_lowercase();
        let mut out = ProxyUri {
            scheme: scheme.clone(),
            host: String::new(),
            port: 0,
            id: String::new(),
            alias: String::new(),
            raw: raw.to_string(),
        };
        let ok = match scheme.as_str() {
            "vless" | "trojan" | "hysteria2" | "hy2" | "juicity" | "anytls" | "ssh" => {
                parse_userinfo_host(&mut out, rest, 1)
            }
            "hysteria" => parse_hysteria_v1(&mut out, rest),
            "tuic" => parse_userinfo_host(&mut out, rest, 2),
            "wireguard" | "wg" | "warp" | "amneziawg" | "openvpn" | "ovpn" | "socks5"
            | "socks4" | "socks" | "naive+https" | "naive+quic" | "naive" | "sn" | "dnstt"
            | "slipnet" => parse_optional_userinfo_host(&mut out, rest),
            "http" | "https" => parse_explicit_http_proxy(&mut out, raw),
            "npv" | "npv4" | "napsternetv" => parse_napsternet(&mut out, rest),
            "ss" => parse_ss(&mut out, rest),
            "vmess" => parse_vmess(&mut out, rest),
            "ssr" => parse_ssr(&mut out, rest),
            _ => false,
        };
        if !ok {
            return None;
        }
        // Alias from the `#frag` fragment (all schemes), percent-decoded. If
        // there is no fragment, keep whatever the scheme parser set (e.g. the
        // vmess `ps` field).
        if let Some((_, frag)) = raw.rsplit_once('#') {
            out.alias = crate::artifact::vless::decode_query(frag);
        }
        Some(out)
    }

    /// Return the canonical lowercase scheme name (e.g. `hy2` -> `hysteria2`,
    /// `wg` -> `wireguard`, `socks` -> `socks5`).
    pub fn canonical_scheme(&self) -> &str {
        match self.scheme.as_str() {
            "hy2" => "hysteria2",
            "wg" => "wireguard",
            "socks" => "socks5",
            "ovpn" => "openvpn",
            other => other,
        }
    }

    /// Deduplication key using `protocol+host+port+id` (canonical scheme and
    /// lowercased host).
    pub fn dedup_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.canonical_scheme(),
            self.host.to_ascii_lowercase(),
            self.port,
            self.id
        )
    }
}

/// Deduplicate share-links by `protocol+host+port+id` (canonical scheme),
/// preserving original order and raw strings.
pub fn deduplicate_links(links: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(links.len());
    for link in links {
        let trimmed = link.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = ProxyUri::parse(trimmed)
            .map(|u| u.dedup_key())
            .unwrap_or_else(|| trimmed.to_string());
        if seen.insert(key) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Split `scheme://...` into `(scheme, rest_after_://)`.
fn split_scheme(raw: &str) -> Option<(&str, &str)> {
    let idx = raw.find("://")?;
    let scheme = &raw[..idx];
    let valid = scheme.chars().enumerate().all(|(i, c)| {
        if i == 0 {
            c.is_ascii_alphabetic()
        } else {
            c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
        }
    });
    if scheme.is_empty() || !valid {
        return None;
    }
    Some((scheme, &raw[idx + 3..]))
}

/// Strip `?query` and `#frag` from the host part. Returns the bare
/// `host:port` segment.
fn strip_query_frag(host_part: &str) -> &str {
    let host_part = host_part.split(['?', '#']).next().unwrap_or(host_part);
    host_part.split('/').next().unwrap_or(host_part)
}

/// Parse `host:port` (including bracketed IPv6 `[host]:port`) into `out.host` / `out.port`.
fn set_host_port(out: &mut ProxyUri, host_port: &str) -> bool {
    let host_port = strip_query_frag(host_port).trim();
    let (host, port) = if let Some(after_open) = host_port.strip_prefix('[') {
        let Some((ipv6, rest)) = after_open.split_once(']') else {
            return false;
        };
        let Some(port_str) = rest.strip_prefix(':') else {
            return false;
        };
        (ipv6, port_str)
    } else {
        match host_port.rsplit_once(':') {
            Some(x) => x,
            None => return false,
        }
    };
    let Ok(port) = port.trim().parse::<u16>() else {
        return false;
    };
    if host.is_empty() || port == 0 {
        return false;
    }
    out.host = host.trim().to_string();
    out.port = port;
    true
}

/// For `userinfo@host:port` links. `split_at` is the index inside
/// `userinfo` to cut the id (1 keeps the whole userinfo; 2 strips a
/// trailing `:token` — used by `tuic://uuid:token@...`).
fn parse_userinfo_host(out: &mut ProxyUri, rest: &str, split_at: usize) -> bool {
    let auth_part = rest.split(['?', '#']).next().unwrap_or(rest);
    let (userinfo, host_part) = match auth_part.split_once('@') {
        Some(x) => x,
        None => return false,
    };
    if userinfo.is_empty() {
        return false;
    }
    let id = if split_at > 1 {
        userinfo.split(':').next().unwrap_or(userinfo).to_string()
    } else {
        crate::artifact::vless::decode_query(userinfo)
    };
    if id.is_empty() {
        return false;
    }
    if !set_host_port(out, host_part) {
        return false;
    }
    out.id = id;
    true
}

/// Hysteria v1 supports `hysteria://auth@host:port?...` or
/// `hysteria://host:port?auth=token&...`.
fn parse_hysteria_v1(out: &mut ProxyUri, rest: &str) -> bool {
    let auth_part = rest.split(['?', '#']).next().unwrap_or(rest);
    if auth_part.contains('@') {
        return parse_userinfo_host(out, rest, 1);
    }
    if !set_host_port(out, rest) {
        return false;
    }
    let query = rest
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(q))
        .unwrap_or("");
    let auth = query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k.eq_ignore_ascii_case("auth") {
            let dec = crate::artifact::vless::decode_query(v);
            (!dec.is_empty()).then_some(dec)
        } else {
            None
        }
    });
    out.id = auth.unwrap_or_else(|| format!("{}:{}", out.host, out.port));
    true
}

/// For schemes where userinfo before `@` is optional
/// (`wireguard`, `wg`, `warp`, `socks5`, `naive+https`, `sn`, `dnstt`).
fn parse_optional_userinfo_host(out: &mut ProxyUri, rest: &str) -> bool {
    let auth_part = rest.split(['?', '#']).next().unwrap_or(rest);
    if auth_part.contains('@') {
        return parse_userinfo_host(out, rest, 1);
    }
    if !set_host_port(out, rest) {
        return false;
    }
    out.id = format!("{}:{}", out.host, out.port);
    true
}

/// NapsternetV (`npv://`, `npv4://`, `napsternetv://`) supports both authority URIs
/// and Base64 JSON blobs.
fn parse_napsternet(out: &mut ProxyUri, rest: &str) -> bool {
    if rest.contains('@') && parse_userinfo_host(out, rest, 1) {
        return true;
    }
    let clean = rest.split(['?', '#']).next().unwrap_or(rest);
    if let Some(decoded) = b64_decode(clean) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&decoded) {
            let host_keys = ["add", "host", "server", "address"];
            let host = first_non_empty_str(&v, &host_keys).unwrap_or("");
            let port_opt = ["port", "serverPort"].iter().find_map(|k| {
                v.get(*k).and_then(|x| {
                    x.as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .or_else(|| x.as_u64().map(|n| n.to_string()))
                })
            });
            let id_keys = ["id", "uuid", "password", "username"];
            let id = first_non_empty_str(&v, &id_keys).unwrap_or("napsternetv");
            if let Some(port_str) = port_opt {
                if let Ok(port) = port_str.parse::<u16>() {
                    if !host.is_empty() && port > 0 {
                        out.host = host.to_string();
                        out.port = port;
                        out.id = id.to_string();
                        if let Some(ps) = first_non_empty_str(&v, &["ps", "remarks", "name"]) {
                            out.alias = ps.to_string();
                        }
                        return true;
                    }
                }
            }
        }
    }
    if set_host_port(out, rest) {
        out.id = format!("{}:{}", out.host, out.port);
        return true;
    }
    false
}

/// Return the first non-empty string value among candidate JSON keys.
fn first_non_empty_str<'a>(v: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| {
        let s = v.get(*k)?.as_str()?;
        (!s.is_empty()).then_some(s)
    })
}

/// Recognized Telegram MTProto share-link prefixes (matched ASCII case-insensitively).
#[rustfmt::skip]
pub const MTPROTO_PREFIXES: &[&str] = &[
    "tg://proxy?",
    "https://t.me/proxy?",
    "http://t.me/proxy?",
    "https://telegram.me/proxy?",
    "http://telegram.me/proxy?",
];

/// Return the query slice after a recognized Telegram MTProto prefix (ASCII case-insensitive).
pub fn mtproto_query(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    MTPROTO_PREFIXES.iter().find_map(|prefix| {
        let head = raw.get(..prefix.len())?;
        if head.eq_ignore_ascii_case(prefix) {
            raw.get(prefix.len()..)
        } else {
            None
        }
    })
}

/// Return whether `raw` begins with a recognized Telegram MTProto share-link prefix.
pub fn is_mtproto_link(raw: &str) -> bool {
    mtproto_query(raw).is_some()
}

/// Extract all valid Telegram MTProto share-links from an HTML or plain-text payload.
pub fn extract_mtproto_links(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let tokens = body.split(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '`')
    });
    for token in tokens {
        let decoded = token
            .replace("&amp;", "&")
            .trim_end_matches(['#', ',', ';', '.'])
            .to_string();
        if is_mtproto_link(&decoded)
            && ProxyUri::parse(&decoded).is_some()
            && !out.contains(&decoded)
        {
            out.push(decoded);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MtprotoKey {
    Server,
    Port,
    Secret,
}

impl MtprotoKey {
    fn parse(key: &str) -> Option<Self> {
        match key.trim().to_ascii_lowercase().as_str() {
            "server" | "host" => Some(Self::Server),
            "port" => Some(Self::Port),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }
}

fn validate_mtproto_server(raw: &str) -> Option<String> {
    let decoded = crate::artifact::vless::decode_query(raw.trim());
    let val = decoded.trim();
    if val.is_empty()
        || val.chars().any(char::is_whitespace)
        || val.contains('/')
        || val.contains('#')
        || val.contains('?')
    {
        return None;
    }
    Some(val.to_string())
}

fn validate_mtproto_port(raw: &str) -> Option<u16> {
    let decoded = crate::artifact::vless::decode_query(raw.trim());
    if decoded.is_empty() || !decoded.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    decoded.parse::<u16>().ok().filter(|&p| p > 0)
}

fn validate_mtproto_secret(raw: &str) -> Option<String> {
    let decoded = crate::artifact::vless::decode_query(raw.trim());
    let val = decoded.trim();
    if val.is_empty() || val.chars().any(char::is_whitespace) {
        return None;
    }
    Some(val.to_string())
}

/// Telegram MTProto links (`tg://proxy?server=...&port=...&secret=...`,
/// `https://t.me/proxy?...`, or `https://telegram.me/proxy?...`).
fn parse_mtproto(raw: &str) -> Option<ProxyUri> {
    let query = mtproto_query(raw)?;
    let (query_clean, frag_opt) = match query.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (query, None),
    };
    let mut server: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut secret: Option<String> = None;
    for pair in query_clean.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=')?;
        match MtprotoKey::parse(key)? {
            MtprotoKey::Server => {
                if server.is_some() {
                    return None;
                }
                server = Some(validate_mtproto_server(value)?);
            }
            MtprotoKey::Port => {
                if port.is_some() {
                    return None;
                }
                port = Some(validate_mtproto_port(value)?);
            }
            MtprotoKey::Secret => {
                if secret.is_some() {
                    return None;
                }
                secret = Some(validate_mtproto_secret(value)?);
            }
        }
    }
    let host = server?;
    let port = port?;
    let secret = secret?;
    let alias = frag_opt
        .map(|f| crate::artifact::vless::decode_query(f.trim()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "MTProto".to_string());
    Some(ProxyUri {
        scheme: "mtproto".to_string(),
        host,
        port,
        id: secret,
        alias,
        raw: raw.to_string(),
    })
}

/// Shadowsocks: plain `method:password@host:port`, SIP002
/// `BASE64(method:password)@host:port`, or whole-link base64.
fn parse_ss(out: &mut ProxyUri, rest: &str) -> bool {
    if let Some((userinfo, host_part)) = rest.split_once('@') {
        // SIP002: `ss://BASE64(method:password)@host:port`. The userinfo is
        // base64 of `method:password` (the ':' is not in the base64 alphabet,
        // so if it decodes, it is unambiguous).
        if let Some(decoded) = b64_decode(userinfo) {
            if decoded.contains(':') && set_host_port(out, host_part) {
                out.id = decoded;
                return true;
            }
        }
        // Plain form: `ss://method:password@host:port`.
        if userinfo.contains(':') && set_host_port(out, host_part) {
            out.id = crate::artifact::vless::decode_query(userinfo);
            return !out.id.is_empty() && out.id.contains(':');
        }
        return false;
    }
    // Whole-link base64 form: `ss://BASE64(method:password@host:port)`.
    // Some clients also append `#frag` — strip the fragment before decoding.
    let b64_candidate = rest.split(['?', '#']).next().unwrap_or(rest);
    let decoded = match b64_decode(b64_candidate) {
        Some(d) => d,
        None => return false,
    };
    // Now decoded is `method:password@host:port` (or `method:password`).
    let (userinfo, host_part) = match decoded.split_once('@') {
        Some(x) => x,
        None => return false,
    };
    if !userinfo.contains(':') {
        return false;
    }
    if !set_host_port(out, host_part) {
        return false;
    }
    out.id = userinfo.to_string();
    true
}

/// Vmess: `vmess://BASE64(JSON)` where JSON has `add`, `port`, `id`, `ps`.
fn parse_vmess(out: &mut ProxyUri, rest: &str) -> bool {
    let decoded = match b64_decode(rest) {
        Some(d) => d,
        None => return false,
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&decoded) else {
        return false;
    };
    let host = match v.get("add").and_then(|x| x.as_str()) {
        Some(h) => h,
        None => return false,
    };
    let port = match v.get("port").and_then(|x| {
        x.as_str()
            .map(|s| s.to_string())
            .or_else(|| x.as_u64().map(|n| n.to_string()))
    }) {
        Some(p) => p,
        None => return false,
    };
    let id = match v.get("id").and_then(|x| x.as_str()) {
        Some(i) => i,
        None => return false,
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    if host.is_empty() || port == 0 || id.is_empty() {
        return false;
    }
    out.host = host.to_string();
    out.port = port;
    out.id = id.to_string();
    // `ps` is the friendly name — prefer it as the alias.
    if let Some(ps) = v
        .get("ps")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        out.alias = ps.to_string();
    }
    true
}

/// SSR: `ssr://BASE64(server:port:protocol:method:obfs:password/)`.
fn parse_ssr(out: &mut ProxyUri, rest: &str) -> bool {
    let decoded = match b64_decode(rest) {
        Some(d) => d,
        None => return false,
    };
    let head = decoded.split('/').next().unwrap_or(&decoded);
    let parts: Vec<&str> = head.split(':').collect();
    if parts.len() < 2 {
        return false;
    }
    let host = parts[0];
    let Ok(port) = parts[1].parse::<u16>() else {
        return false;
    };
    if host.is_empty() || port == 0 {
        return false;
    }
    out.host = host.to_string();
    out.port = port;
    // id = `method:password` when available; else just the method.
    out.id = if parts.len() >= 6 {
        format!("{}:{}", parts[3], parts[5])
    } else {
        parts.get(3).copied().unwrap_or("").to_string()
    };
    true
}

/// Hosts belonging to web platforms / channel posts / release pages that must
/// never be mistaken for HTTP proxy servers when scanning arbitrary `.txt` blobs.
const WEB_NON_PROXY_HOSTS: &[&str] = &[
    "t.me",
    "telegram.me",
    "github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "gitlab.com",
    "youtube.com",
    "youtu.be",
    "twitter.com",
    "x.com",
    "instagram.com",
    "facebook.com",
    "google.com",
    "support.google.com",
    "docs.google.com",
    "play.google.com",
    "drive.google.com",
    "reddit.com",
    "medium.com",
    "wikipedia.org",
];

/// Return true when an `http://` or `https://` URL is a web page / release /
/// Telegram message link rather than an explicit HTTP proxy endpoint.
pub fn is_non_proxy_http_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }
    let Ok(url) = url::Url::parse(trimmed) else {
        return true;
    };
    let Some(host) = url.host_str() else {
        return true;
    };
    let host_low = host.to_ascii_lowercase();
    if WEB_NON_PROXY_HOSTS
        .iter()
        .any(|d| host_low == *d || host_low.ends_with(&format!(".{d}")))
    {
        return true;
    }
    let has_explicit_port = url.port().is_some();
    let has_userinfo = !url.username().is_empty() || url.password().is_some();
    let path = url.path();
    if (!path.is_empty() && path != "/") || url.query().is_some() {
        return true;
    }
    !has_explicit_port && !has_userinfo
}

fn parse_explicit_http_proxy(out: &mut ProxyUri, raw: &str) -> bool {
    if is_non_proxy_http_url(raw) {
        return false;
    }
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let port = match url.port() {
        Some(p) if p > 0 => p,
        _ => return false,
    };
    out.host = host.to_string();
    out.port = port;
    out.id = if !url.username().is_empty() {
        format!("{}:{}", url.username(), url.password().unwrap_or(""))
    } else {
        format!("{host}:{port}")
    };
    true
}

/// Base64 decode with the usual encodings used in share-links (standard with
/// padding, unpadded, URL-safe, or whitespace-wrapped). Returns `None` on failure.
fn b64_decode(s: &str) -> Option<String> {
    let raw = s.trim().trim_end_matches('#');
    let mut clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return None;
    }
    clean = clean.replace('-', "+").replace('_', "/");
    let unpadded = clean.trim_end_matches('=');
    let mut repadded = unpadded.to_string();
    let rem = repadded.len() % 4;
    if rem == 2 {
        repadded.push_str("==");
    } else if rem == 3 {
        repadded.push('=');
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
    for cand in [clean.as_str(), unpadded, repadded.as_str()] {
        if let Ok(bytes) = STANDARD.decode(cand) {
            if let Ok(text) = String::from_utf8(bytes) {
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
        if let Ok(bytes) = STANDARD_NO_PAD.decode(cand) {
            if let Ok(text) = String::from_utf8(bytes) {
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// Public wrapper for share-link base64 decoding (used by xray config
/// rendering for vmess/ssr links).
pub fn b64_decode_for(s: &str) -> Option<String> {
    b64_decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_roundtrip() {
        let link = concat!(
            "vless://06ef598c-1555-4887-b3f9-08214a2f6792@",
            "104.17.72.206:443?encryption=none&type=ws#my-node"
        );
        let u = ProxyUri::parse(link).unwrap();
        assert_eq!(u.scheme, "vless");
        assert_eq!(u.host, "104.17.72.206");
        assert_eq!(u.port, 443);
        assert_eq!(u.id, "06ef598c-1555-4887-b3f9-08214a2f6792");
        assert_eq!(u.alias, "my-node");
    }

    #[test]
    fn trojan_parses() {
        let link = concat!(
            "trojan://secret-password@ali.example.com:8443",
            "?security=tls&sni=ali.example.com#trojan-node"
        );
        let u = ProxyUri::parse(link).unwrap();
        assert_eq!(u.scheme, "trojan");
        assert_eq!(u.host, "ali.example.com");
        assert_eq!(u.port, 8443);
        assert_eq!(u.id, "secret-password");
        assert_eq!(u.alias, "trojan-node");
    }

    #[test]
    fn hysteria2_parses() {
        let u =
            ProxyUri::parse("hysteria2://open-token@107.189.20.41:8443?insecure=1#hy2").unwrap();
        assert_eq!(u.id, "open-token");
        assert_eq!(u.host, "107.189.20.41");
        assert_eq!(u.port, 8443);
    }

    #[test]
    fn tuic_uses_uuid_before_colon() {
        let link = concat!(
            "tuic://413a66e9-b05b-4ae6-a9eb-6d28204a28f4:tok@",
            "138.68.53.88:7780?congestion_control=bbr#tuic"
        );
        let u = ProxyUri::parse(link).unwrap();
        assert_eq!(u.id, "413a66e9-b05b-4ae6-a9eb-6d28204a28f4");
        assert_eq!(u.port, 7780);
    }

    #[test]
    fn ss_plain_and_base64() {
        let plain = ProxyUri::parse("ss://chacha20-ietf-poly1305:key@1.2.3.4:8388#ss1").unwrap();
        assert_eq!(plain.id, "chacha20-ietf-poly1305:key");
        assert_eq!(plain.host, "1.2.3.4");
        assert_eq!(plain.port, 8388);

        // Base64 of `chacha20-ietf-poly1305:key@1.2.3.4:8388`.
        let b64 = base64::engine::general_purpose::STANDARD
            .encode("chacha20-ietf-poly1305:key@1.2.3.4:8388");
        let enc = ProxyUri::parse(&format!("ss://{b64}#ss2")).unwrap();
        assert_eq!(enc.id, "chacha20-ietf-poly1305:key");
        assert_eq!(enc.host, "1.2.3.4");
        assert_eq!(enc.port, 8388);
    }

    #[test]
    fn ss_sip002_base64_userinfo() {
        // Subscriptions use SIP002: only the `method:password` part is base64,
        // followed by @host:port#frag.
        let userinfo = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:supersecret");
        let link = format!("ss://{userinfo}@198.244.201.129:19999#London");
        let u = ProxyUri::parse(&link).unwrap();
        assert_eq!(u.id, "aes-256-gcm:supersecret");
        assert_eq!(u.host, "198.244.201.129");
        assert_eq!(u.port, 19999);
        assert_eq!(u.alias, "London");
    }

    #[test]
    fn vmess_base64_json() {
        let json = concat!(
            r#"{"v":"2","ps":"vmess-telegram","add":"192.168.1.100","#,
            r#""port":"443","id":"7748b328-f0e8-40ab-b2e3-9a1c2c22d111","aid":"0"}"#
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let u = ProxyUri::parse(&format!("vmess://{b64}")).unwrap();
        assert_eq!(u.scheme, "vmess");
        assert_eq!(u.host, "192.168.1.100");
        assert_eq!(u.port, 443);
        assert_eq!(u.id, "7748b328-f0e8-40ab-b2e3-9a1c2c22d111");
        // ps becomes the alias.
        assert_eq!(u.alias, "vmess-telegram");
    }

    #[test]
    fn ssr_parses() {
        // `server:port:protocol:method:obfs:password` (base64) — password
        // here is already the encoded form; we just need host/port.
        let plain = "95.85.234.66:10001:auth_aes128_md5:aes-128-ctr:tls1.2_ticket_auth:Zm9vYmFy";
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        let u = ProxyUri::parse(&format!("ssr://{b64}")).unwrap();
        assert_eq!(u.scheme, "ssr");
        assert_eq!(u.host, "95.85.234.66");
        assert_eq!(u.port, 10001);
    }

    #[test]
    fn rejects_malformed() {
        assert!(ProxyUri::parse("").is_none());
        assert!(ProxyUri::parse("http://google.com").is_none());
        assert!(ProxyUri::parse("vless://@host:443").is_none());
        assert!(ProxyUri::parse("vless://uuid@host").is_none());
        assert!(ProxyUri::parse("vless://uuid@host:0").is_none());
        assert!(ProxyUri::parse("vmess://not-base64").is_none());
    }

    #[test]
    fn supported_schemes_cover_level1() {
        // Doctrine Level 1: VLESS + Shadowsocks. Both must be ingestible.
        for s in SUPPORTED_SCHEMES {
            assert!(!s.is_empty());
        }
        assert!(SUPPORTED_SCHEMES.contains(&"vless"));
        assert!(SUPPORTED_SCHEMES.contains(&"ss"));
        assert!(SUPPORTED_SCHEMES.contains(&"wireguard"));
        assert!(SUPPORTED_SCHEMES.contains(&"npv4"));
    }

    #[test]
    fn parses_wireguard_napsternet_hy2_and_mtproto() {
        let wg_link = "wireguard://privKey==@162.159.192.1:2408?publickey=pubKey==#WARP";
        let wg = ProxyUri::parse(wg_link).unwrap();
        assert_eq!(wg.scheme, "wireguard");
        assert_eq!(wg.host, "162.159.192.1");
        assert_eq!(wg.port, 2408);
        assert_eq!(wg.id, "privKey==");
        assert_eq!(wg.alias, "WARP");

        let wg6 = ProxyUri::parse("warp://[2606:4700:d0::a29f:c001]:2408#WARPv6").unwrap();
        assert_eq!(wg6.scheme, "warp");
        assert_eq!(wg6.host, "2606:4700:d0::a29f:c001");
        assert_eq!(wg6.port, 2408);

        let npv_json = concat!(
            r#"{"server":"npv.example.com","port":8443,"#,
            r#""uuid":"abc-123","remarks":"NPV-Fast"}"#
        );
        let npv_b64 = base64::engine::general_purpose::STANDARD.encode(npv_json);
        let npv = ProxyUri::parse(&format!("npv4://{npv_b64}")).unwrap();
        assert_eq!(npv.scheme, "npv4");
        assert_eq!(npv.host, "npv.example.com");
        assert_eq!(npv.port, 8443);
        assert_eq!(npv.id, "abc-123");
        assert_eq!(npv.alias, "NPV-Fast");

        let hy2_link = "hy2://tok@hy.example.com:443?sni=hy.example.com#Hy2Node";
        let hy2 = ProxyUri::parse(hy2_link).unwrap();
        assert_eq!(hy2.scheme, "hy2");
        assert_eq!(hy2.port, 443);

        let mt = ProxyUri::parse("tg://proxy?server=1.2.3.4&port=443&secret=dd00001111").unwrap();
        assert_eq!(mt.scheme, "mtproto");
        assert_eq!(mt.host, "1.2.3.4");
        assert_eq!(mt.port, 443);
        assert_eq!(mt.id, "dd00001111");

        let ovpn_link = "openvpn://198.51.100.77:1194?proto=tcp&dev=tun#OpenVPN-TCP";
        let ovpn = ProxyUri::parse(ovpn_link).unwrap();
        assert_eq!(ovpn.scheme, "openvpn");
        assert_eq!(ovpn.host, "198.51.100.77");
        assert_eq!(ovpn.port, 1194);
        assert_eq!(ovpn.alias, "OpenVPN-TCP");
    }

    #[test]
    fn napsternet_skips_empty_earlier_keys() {
        let npv_json = concat!(
            r#"{"add":"","server":"npv2.example.com","port":"","serverPort":8443,"#,
            r#""id":"","uuid":"abc-123","ps":"","remarks":"NPV-Fallback"}"#
        );
        let npv_b64 = base64::engine::general_purpose::STANDARD.encode(npv_json);
        let npv = ProxyUri::parse(&format!("npv4://{npv_b64}")).unwrap();
        assert_eq!(npv.host, "npv2.example.com");
        assert_eq!(npv.port, 8443);
        assert_eq!(npv.id, "abc-123");
        assert_eq!(npv.alias, "NPV-Fallback");
    }

    #[test]
    fn mtproto_accepts_supported_forms_and_rejects_malformed_forms() {
        for link in [
            "tg://proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "https://t.me/proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "http://t.me/proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "https://telegram.me/proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "http://telegram.me/proxy?server=1.2.3.4&port=443&secret=dd00001111",
            "HTTPS://T.ME/PROXY?server=1.2.3.4&port=443&secret=dd00001111",
            "TG://PROXY?host=1.2.3.4&port=443&secret=dd00001111",
        ] {
            assert!(is_mtproto_link(link), "{link}");
            let proxy = ProxyUri::parse(link).expect(link);
            assert_eq!(proxy.scheme, "mtproto");
            assert_eq!(proxy.host, "1.2.3.4");
            assert_eq!(proxy.port, 443);
            assert_eq!(proxy.id, "dd00001111");
            assert_eq!(proxy.alias, "MTProto");
        }
        let with_frag = ProxyUri::parse("tg://proxy?server=1.2.3.4&port=8443&secret=ee12#FastTag")
            .expect("fragmented mtproto");
        assert_eq!(with_frag.port, 8443);
        assert_eq!(with_frag.id, "ee12");
        assert_eq!(with_frag.alias, "FastTag");

        for bad in [
            "https://evil.example/t.me/proxy?server=1.2.3.4&port=443&secret=abc",
            "https://evil.example/https://t.me/proxy?server=1.2.3.4&port=443&secret=abc",
            "ftp://t.me/proxy?server=1.2.3.4&port=443&secret=abc",
            "tg://proxyevil?server=1.2.3.4&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=0&secret=abc",
            "tg://proxy?server=1.2.3.4&port=65536&secret=abc",
            "tg://proxy?server=1.2.3.4&port=abc&secret=abc",
            "tg://proxy?server=1.2.3.4&secret=abc",
            "tg://proxy?port=443&secret=abc",
            "tg://proxy?server=%20%20&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4/path&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443",
            "tg://proxy?server=1.2.3.4&port=443&secret=",
            "tg://proxy?server=1.2.3.4&port=443&secret=%20",
            "tg://proxy?server=1.2.3.4&server=5.6.7.8&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&host=5.6.7.8&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443&port=8443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443&secret=abc&secret=def",
            "tg://proxy?server=1.2.3.4&port=443&secret=abc&extra=1",
            "tg://proxy?server=1.2.3.4&port=443&secret=abc&dangling",
            "tg://proxy?server=1.2.3.4&port=+443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=%2B443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=%20443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443%20&secret=abc",
            "tg://proxy?server=1.2.3.4%23bad&port=443&secret=abc",
            "tg://proxy?server=1.2.3.4&port=443&secret=ab%20cd",
            "https://t.me/some_channel",
        ] {
            assert!(ProxyUri::parse(bad).is_none(), "expected None for {bad}");
        }
        for non_mt in [
            "https://t.me/some_channel",
            "vless://uuid@1.2.3.4:443#v",
            "ss://chacha20-ietf-poly1305:key@1.2.3.4:8388#ss1",
        ] {
            assert!(!is_mtproto_link(non_mt), "not mtproto: {non_mt}");
            assert!(parse_mtproto(non_mt).is_none(), "not mtproto: {non_mt}");
        }
        let vless = ProxyUri::parse("vless://uuid@1.2.3.4:443#v").expect("valid vless");
        assert_eq!(vless.scheme, "vless");

        let html = concat!(
            r#"<a href="HTTPS://T.ME/PROXY?server=1.2.3.4&amp;port=443&amp;secret=abc">p</a> "#,
            r#"<span>(tg://proxy?server=5.6.7.8&amp;port=8443&amp;secret=def),</span> "#,
            r#"<a href="https://evil.example/t.me/proxy?"#,
            r#"server=9.9.9.9&amp;port=443&amp;secret=bad">x</a> "#,
            r#"<span>tg://proxy?server=7.7.7.7&amp;port=443</span>"#
        );
        let extracted = extract_mtproto_links(html);
        assert_eq!(
            extracted,
            vec![
                "HTTPS://T.ME/PROXY?server=1.2.3.4&port=443&secret=abc",
                "tg://proxy?server=5.6.7.8&port=8443&secret=def",
            ]
        );
    }

    #[test]
    fn parse_never_panics_on_fuzz_inputs() {
        let fuzz = [
            "",
            "://",
            "tg://proxy?",
            "tg://proxy?====&&&&####",
            "tg://proxy?server=%ZZ&port=%FF&secret=%E2%28%A1",
            "https://t.me/proxy?server=🔒&port=443&secret=کلید",
            "vless://[[[[::::@@@@",
            "vmess:///////",
            "npv4://%%%%",
        ];
        for s in fuzz {
            let _ = ProxyUri::parse(s);
            let _ = extract_mtproto_links(s);
        }
    }

    #[test]
    fn parses_ipv6_and_percent_decoded_aliases() {
        let v6 = ProxyUri::parse("vless://uuid-1@[2001:db8::1]:443?type=tcp#Edge%20Node").unwrap();
        assert_eq!(v6.host, "2001:db8::1");
        assert_eq!(v6.port, 443);
        assert_eq!(v6.alias, "Edge Node");

        let s5 = ProxyUri::parse("socks5://[::1]:1080").unwrap();
        assert_eq!(s5.host, "::1");
        assert_eq!(s5.port, 1080);
        assert_eq!(s5.id, "::1:1080");

        assert!(ProxyUri::parse("vless://u@[2001:db8::1:443").is_none());

        let tr = ProxyUri::parse("trojan://p%40ss@example.com:8443#My%20Relay").unwrap();
        assert_eq!(tr.id, "p@ss");
        assert_eq!(tr.alias, "My Relay");
    }

    #[test]
    fn parses_explicit_http_proxy_and_rejects_web_urls() {
        let auth = ProxyUri::parse("http://alice:s3cr3t@198.51.100.2:8080").unwrap();
        assert_eq!(auth.scheme, "http");
        assert_eq!(auth.host, "198.51.100.2");
        assert_eq!(auth.port, 8080);
        assert_eq!(auth.id, "alice:s3cr3t");

        let plain = ProxyUri::parse("http://198.51.100.2:3128").unwrap();
        assert_eq!(plain.id, "198.51.100.2:3128");

        assert!(ProxyUri::parse("https://github.com/org/repo").is_none());
        assert!(ProxyUri::parse("http://198.51.100.2/login").is_none());
        assert!(ProxyUri::parse("http://198.51.100.2:8080?q=1").is_none());
    }

    #[test]
    fn parses_whole_link_ss_and_vmess_integer_port() {
        let ss_raw = "chacha20-ietf-poly1305:pw123@203.0.113.5:8388";
        let ss_b64 = base64::engine::general_purpose::STANDARD.encode(ss_raw);
        let ss = ProxyUri::parse(&format!("ss://{ss_b64}#SS-Whole")).unwrap();
        assert_eq!(ss.host, "203.0.113.5");
        assert_eq!(ss.port, 8388);
        assert_eq!(ss.id, "chacha20-ietf-poly1305:pw123");
        assert_eq!(ss.alias, "SS-Whole");

        let vmess_json = r#"{"add":"198.51.100.9","port":443,"id":"vm-id-1"}"#;
        let vm_b64 = base64::engine::general_purpose::STANDARD.encode(vmess_json);
        let vm = ProxyUri::parse(&format!("vmess://{vm_b64}")).unwrap();
        assert_eq!(vm.host, "198.51.100.9");
        assert_eq!(vm.port, 443);
        assert_eq!(vm.id, "vm-id-1");

        let upper = ProxyUri::parse("VLESS://uuid@1.2.3.4:443").unwrap();
        assert_eq!(upper.scheme, "vless");
    }

    #[test]
    fn rejects_malformed_vmess_ssr_and_ss() {
        let zero_port = base64::engine::general_purpose::STANDARD
            .encode(r#"{"add":"1.2.3.4","port":0,"id":"abc"}"#);
        assert!(ProxyUri::parse(&format!("vmess://{zero_port}")).is_none());

        let missing_id =
            base64::engine::general_purpose::STANDARD.encode(r#"{"add":"1.2.3.4","port":443}"#);
        assert!(ProxyUri::parse(&format!("vmess://{missing_id}")).is_none());

        let bad_ssr = base64::engine::general_purpose::STANDARD.encode("1.2.3.4:0:origin:plain");
        assert!(ProxyUri::parse(&format!("ssr://{bad_ssr}")).is_none());
        let short_ssr = base64::engine::general_purpose::STANDARD.encode("onlyhost");
        assert!(ProxyUri::parse(&format!("ssr://{short_ssr}")).is_none());

        let ss_no_colon = base64::engine::general_purpose::STANDARD.encode("nocolon@1.2.3.4:8388");
        assert!(ProxyUri::parse(&format!("ss://{ss_no_colon}")).is_none());
    }

    #[test]
    fn parses_all_required_share_link_schemes_and_deduplicates() {
        let vmess_b64 = base64::engine::general_purpose::STANDARD
            .encode(r#"{"v":"2","ps":"vm","add":"203.0.113.2","port":"443","id":"vm-id"}"#);
        let ssr_b64 = base64::engine::general_purpose::STANDARD
            .encode("203.0.113.5:8388:origin:aes-256-cfb:plain:cGFzcw");
        let ss_b64 = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:sspass");

        let cases = [
            ("vless", "vless://uuid-1@203.0.113.1:443?security=tls#v"),
            ("vmess", &format!("vmess://{vmess_b64}")),
            ("trojan", "trojan://pass1@203.0.113.3:443#t"),
            ("ss", &format!("ss://{ss_b64}@203.0.113.4:8388#s")),
            ("ssr", &format!("ssr://{ssr_b64}")),
            (
                "hysteria",
                "hysteria://203.0.113.6:443?auth=hy1tok&upmbps=20#hy1",
            ),
            ("hysteria2", "hysteria2://hy2tok@203.0.113.7:443#hy2"),
            ("hy2", "hy2://hy2tok@203.0.113.8:443#hy2b"),
            ("tuic", "tuic://tuic-u:tok@203.0.113.9:443#tuic"),
            (
                "wireguard",
                "wireguard://priv1=@203.0.113.10:51820?publickey=pub#wg",
            ),
            ("wg", "wg://priv2=@203.0.113.11:51820?publickey=pub#wg2"),
            ("socks", "socks://203.0.113.12:1080#s4"),
            ("socks5", "socks5://u:p@203.0.113.13:1080#s5"),
            ("http", "http://u:p@203.0.113.14:8080#hp"),
            ("https", "https://u:p@203.0.113.15:8443#hps"),
            (
                "naive+https",
                "naive+https://user:pw@203.0.113.16:443#naive",
            ),
            ("juicity", "juicity://ju-id:pw@203.0.113.17:443#jc"),
            ("anytls", "anytls://pw123@203.0.113.18:443#any"),
        ];
        for (expected_scheme, uri) in cases {
            let parsed = ProxyUri::parse(uri).unwrap_or_else(|| panic!("failed {expected_scheme}"));
            assert_eq!(parsed.scheme, expected_scheme);
        }

        // Dedup uses canonical protocol + host + port + id (ignoring fragment & alias).
        let dups = vec![
            "hy2://tok@edge.example.com:443?sni=a#One".to_string(),
            "hysteria2://tok@EDGE.EXAMPLE.COM:443?sni=b#Two".to_string(),
            "hysteria2://other@edge.example.com:443#Three".to_string(),
        ];
        let deduped = deduplicate_links(&dups);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0], dups[0]);
        assert_eq!(deduped[1], dups[2]);
    }
}
