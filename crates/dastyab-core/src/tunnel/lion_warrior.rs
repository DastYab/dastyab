//! Brutal anti-geoblock engine for Linux DastYab:
//! - **Lion** (`ServicePersona::LionAiStudio`): Google AI Studio + Gemini API
//! - **Warrior** (`ServicePersona::WarriorFlow`): Google Flow (ultra-strict)
//!
//! Combines multi-layer hops (`1..=8` hops across distinct `/16` subnets, local
//! proxy bridges like Tor/WARP/Clash/Sing-Box/Nekoray/OpenVPN, multi-format
//! `.npv*`/`.ovpn`/`.conf`/`.wg`/`.json`/`.sub` configs, and xray `freedom`
//! TLS-Hello packet fragmentation for DPI bypass) with multi-source Geo/ASN
//! and Cloudflare `/cdn-cgi/trace` verification, strict HTML/redirect DOM
//! checking, UCB1 bandit scoring, isolated blacklists, and hardened anti-leak
//! Linux Chrome flags.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::artifact::vless::{decode_query, VlessProfile};
use crate::error::CFError;
use crate::net::proxy_uri::ProxyUri;
use crate::probe::bandit::{
    AutopilotIntent, CandidateArm, ContextualBanditStore, GEO_CLEAR_AISTUDIO, GEO_CLEAR_FLOW,
    GEO_CLEAR_WEB,
};
use crate::store::{profiles::profile_dir, read_opt, write_json};

/// Target service persona governing strictness, gates, blacklists & profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePersona {
    /// **Lion**: brutal resilient multi-layer route finder for Google AI Studio.
    LionAiStudio,
    /// **Warrior**: hyper-strict eagle engine for Google Flow.
    WarriorFlow,
}

impl ServicePersona {
    pub fn code_name(self) -> &'static str {
        match self {
            Self::LionAiStudio => "lion",
            Self::WarriorFlow => "warrior",
        }
    }

    pub fn display_title(self) -> &'static str {
        match self {
            Self::LionAiStudio => "Lion (AI Studio)",
            Self::WarriorFlow => "Warrior (Google Flow)",
        }
    }

    pub fn bandit_intent(self) -> AutopilotIntent {
        match self {
            Self::LionAiStudio => AutopilotIntent::AiStudio,
            Self::WarriorFlow => AutopilotIntent::GoogleFlow,
        }
    }

    pub fn geo_mask(self) -> u8 {
        match self {
            Self::LionAiStudio => GEO_CLEAR_WEB | GEO_CLEAR_AISTUDIO,
            Self::WarriorFlow => GEO_CLEAR_WEB | GEO_CLEAR_FLOW,
        }
    }
}

/// Supported countries for Google Flow (151 ISO-3166 alpha-2 codes matching
/// `support.google.com/flow/answer/16353544`).
#[rustfmt::skip]
pub const FLOW_SUPPORTED_COUNTRIES: &[&str] = &[
    "AE", "AG", "AL", "AM", "AO", "AR", "AS", "AT", "AU", "AW", "AZ", "BA",
    "BD", "BE", "BF", "BG", "BH", "BJ", "BM", "BO", "BR", "BS", "BW", "BZ",
    "CA", "CH", "CI", "CL", "CM", "CO", "CR", "CV", "CY", "CZ", "DE", "DK",
    "DO", "DZ", "EC", "EE", "EG", "ES", "FI", "FJ", "FR", "GA", "GB", "GH",
    "GI", "GR", "GT", "GU", "GW", "HK", "HN", "HR", "HT", "HU", "ID", "IE",
    "IL", "IN", "IQ", "IS", "IT", "JM", "JO", "JP", "KE", "KG", "KH", "KR",
    "KW", "KY", "KZ", "LA", "LB", "LI", "LK", "LT", "LU", "LV", "MA", "MC",
    "MD", "MK", "ML", "MO", "MP", "MT", "MU", "MV", "MX", "MY", "MZ", "NA",
    "NE", "NG", "NI", "NL", "NO", "NP", "NZ", "OM", "PA", "PE", "PG", "PH",
    "PK", "PL", "PR", "PT", "PW", "PY", "QA", "RO", "RS", "RW", "SA", "SC",
    "SE", "SG", "SI", "SK", "SL", "SM", "SN", "SV", "TG", "TH", "TJ", "TM",
    "TN", "TO", "TR", "TT", "TW", "TZ", "UA", "UG", "US", "UY", "UZ", "VE",
    "VG", "VI", "VN", "YE", "ZA", "ZM", "ZW",
];

/// Known blocked/sanctioned regions rejected by Google AI Studio.
pub const AISTUDIO_BLOCKED_COUNTRIES: &[&str] = &["IR", "CN", "RU", "KP", "SY", "CU", "BY"];

pub fn is_flow_supported_country(code: &str) -> bool {
    let up = code.trim().to_ascii_uppercase();
    FLOW_SUPPORTED_COUNTRIES.binary_search(&up.as_str()).is_ok()
}

pub fn is_aistudio_supported_country(code: &str) -> bool {
    let up = code.trim().to_ascii_uppercase();
    if up.len() != 2 || !up.chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }
    !AISTUDIO_BLOCKED_COUNTRIES.contains(&up.as_str())
}

/// Egress IP reputation tier for anti-geoblock scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExitReputation {
    ResidentialIsp,
    CleanNonDc,
    DatacenterLowRisk,
    HostingHighRisk,
    WarpOrTor,
}

impl ExitReputation {
    pub fn label(self) -> &'static str {
        match self {
            Self::ResidentialIsp => "residential-isp",
            Self::CleanNonDc => "clean-non-dc",
            Self::DatacenterLowRisk => "dc-low-risk",
            Self::HostingHighRisk => "hosting-high-risk",
            Self::WarpOrTor => "warp-or-tor",
        }
    }

    pub fn base_score(self) -> i32 {
        match self {
            Self::ResidentialIsp => 100,
            Self::CleanNonDc => 75,
            Self::DatacenterLowRisk => 25,
            Self::HostingHighRisk => -30,
            Self::WarpOrTor => -200,
        }
    }
}

/// Parsed output from `https://www.cloudflare.com/cdn-cgi/trace`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceInfo {
    pub ip: Option<String>,
    pub loc: Option<String>,
    pub warp: Option<String>,
    pub colo: Option<String>,
}

impl TraceInfo {
    pub fn is_warp(&self) -> bool {
        matches!(self.warp.as_deref(), Some("on") | Some("plus"))
    }
}

pub fn parse_cloudflare_trace(body: &str) -> TraceInfo {
    let mut info = TraceInfo::default();
    for line in body.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        if val.is_empty() {
            continue;
        }
        match key {
            "ip" => info.ip = Some(val.to_string()),
            "loc" => info.loc = Some(val.to_ascii_uppercase()),
            "warp" => info.warp = Some(val.to_ascii_lowercase()),
            "colo" => info.colo = Some(val.to_ascii_uppercase()),
            _ => {}
        }
    }
    info
}

/// Combined Geo/ASN/WARP intelligence report for an egress IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAsnReport {
    pub ip: String,
    pub country: String,
    pub country_name: String,
    pub asn: String,
    pub org: String,
    pub is_proxy: bool,
    pub is_hosting: bool,
    pub is_tor: bool,
    pub is_warp: bool,
    pub cf_colo: Option<String>,
    pub reputation: ExitReputation,
    pub clean_score: i32,
}

const HOSTING_ORG_KEYWORDS: &[&str] = &[
    "hetzner",
    "ovh",
    "digitalocean",
    "contabo",
    "vultr",
    "linode",
    "akamai",
    "amazon",
    "aws",
    "google cloud",
    "microsoft azure",
    "oracle",
    "m247",
    "datacamp",
    "leaseweb",
    "quadranet",
    "tzulo",
    "choopa",
    "scaleway",
    "kamatera",
    "hostinger",
    "alicloud",
    "alibaba",
    "tencent",
    "buyvm",
    "frantech",
];

const RESIDENTIAL_ORG_KEYWORDS: &[&str] = &[
    "telekom",
    "comcast",
    "verizon",
    "at&t",
    "vodafone",
    "orange",
    "telefonica",
    "liberty global",
    "charter",
    "cox ",
    "ntt",
    "kddi",
    "softbank",
    "british telecom",
    "bt ",
    "rogers",
    "bell canada",
    "telstra",
    "singtel",
    "swisscom",
    "telenor",
    "telia",
];

pub fn classify_exit_reputation(
    org: &str,
    is_proxy: bool,
    is_hosting: bool,
    is_tor: bool,
    is_warp: bool,
) -> (ExitReputation, i32) {
    let low = org.to_ascii_lowercase();
    if is_warp
        || is_tor
        || (low.contains("cloudflare") && low.contains("warp"))
        || low.contains("tor")
    {
        return (ExitReputation::WarpOrTor, ExitReputation::WarpOrTor.base_score());
    }
    let known_dc = HOSTING_ORG_KEYWORDS.iter().any(|k| low.contains(k));
    let known_res = RESIDENTIAL_ORG_KEYWORDS.iter().any(|k| low.contains(k));

    let rep = if is_proxy && (is_hosting || known_dc) {
        ExitReputation::HostingHighRisk
    } else if known_dc || is_hosting {
        ExitReputation::DatacenterLowRisk
    } else if known_res && !is_proxy {
        ExitReputation::ResidentialIsp
    } else if !is_proxy {
        ExitReputation::CleanNonDc
    } else {
        ExitReputation::DatacenterLowRisk
    };
    let mut score = rep.base_score();
    if is_proxy {
        score -= 25;
    }
    if is_hosting {
        score -= 15;
    }
    (rep, score)
}

/// Supported hop protocol schemes for xray and local Rust cascade chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HopScheme {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    WireGuard,
    Socks5,
    Http,
}

impl HopScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::WireGuard => "wireguard",
            Self::Socks5 => "socks",
            Self::Http => "http",
        }
    }
}

/// Normalized single proxy hop used in multi-layer Lion/Warrior chains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHop {
    pub scheme: HopScheme,
    pub host: String,
    pub port: u16,
    pub auth_id: String,
    pub secret: String,
    pub method: String,
    pub params: HashMap<String, String>,
    pub alias: String,
    pub raw: String,
    #[serde(default)]
    pub is_local_bridge: bool,
}

impl ChainHop {
    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.scheme.as_str(), self.host, self.port)
    }

    /// Approximate `/16` prefix for IPv4 subnet-diversity selection.
    pub fn subnet_prefix16(&self) -> String {
        let parts: Vec<&str> = self.host.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            format!("{}.{}", parts[0], parts[1])
        } else {
            self.host.to_ascii_lowercase()
        }
    }

    pub fn is_socks_or_http(&self) -> bool {
        matches!(self.scheme, HopScheme::Socks5 | HopScheme::Http)
    }

    pub fn param_val<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        match self.params.get(key) {
            Some(s) => s.as_str(),
            None => default,
        }
    }
}

fn set_default_param(params: &mut HashMap<String, String>, key: &str, value: &str) {
    let k = key.to_string();
    params.entry(k).or_insert_with(|| value.to_string());
}

/// Parse any proxy URI (`vless://`, `vmess://`, `trojan://`, `ss://`, `socks5://`, `http://`).
pub fn parse_chain_hop(raw: &str) -> Result<ChainHop, CFError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CFError::new("chain", "empty proxy link", "Paste a proxy URI."));
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let url = url::Url::parse(trimmed)
            .map_err(|e| CFError::new("chain", format!("invalid http proxy url: {e}"), ""))?;
        let host = url
            .host_str()
            .ok_or_else(|| CFError::new("chain", "missing http proxy host", ""))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(8080);
        return Ok(ChainHop {
            scheme: HopScheme::Http,
            host: host.clone(),
            port,
            auth_id: url.username().to_string(),
            secret: url.password().unwrap_or("").to_string(),
            method: String::new(),
            params: HashMap::new(),
            alias: url.fragment().map(decode_query).unwrap_or_default(),
            raw: trimmed.to_string(),
            is_local_bridge: host == "127.0.0.1" || host == "localhost",
        });
    }

    let parsed = ProxyUri::parse(trimmed).ok_or_else(|| {
        CFError::new(
            "chain",
            format!("unsupported or malformed proxy link: {trimmed}"),
            "Use vless://, vmess://, trojan://, ss://, socks5://, or http://.",
        )
    })?;

    let mut params = HashMap::new();
    let before_hash = trimmed.split('#').next().unwrap_or(trimmed);
    if let Some((_, qpart)) = before_hash.split_once('?') {
        for pair in qpart.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if !k.is_empty() {
                    params.insert(k.to_string(), decode_query(v));
                }
            }
        }
    }

    match parsed.scheme.as_str() {
        "vless" => {
            let vp = VlessProfile::parse(trimmed)?;
            set_default_param(&mut params, "security", &vp.security);
            set_default_param(&mut params, "type", &vp.transport);
            if let Some(sni) = &vp.sni {
                set_default_param(&mut params, "sni", sni);
            }
            if let Some(hh) = &vp.header_host {
                set_default_param(&mut params, "host", hh);
            }
            set_default_param(&mut params, "path", &vp.canonical_path());
            if let Some(pbk) = &vp.pbk {
                set_default_param(&mut params, "pbk", pbk);
            }
            if let Some(sid) = &vp.sid {
                set_default_param(&mut params, "sid", sid);
            }
            if let Some(spx) = &vp.spx {
                set_default_param(&mut params, "spx", spx);
            }
            if let Some(fp) = &vp.fp {
                set_default_param(&mut params, "fp", fp);
            }
            if let Some(flow) = &vp.flow {
                set_default_param(&mut params, "flow", flow);
            }
            Ok(ChainHop {
                scheme: HopScheme::Vless,
                host: parsed.host,
                port: parsed.port,
                auth_id: parsed.id,
                secret: String::new(),
                method: String::new(),
                params,
                alias: parsed.alias,
                raw: trimmed.to_string(),
                is_local_bridge: false,
            })
        }
        "vmess" => {
            let mut net = "tcp".to_string();
            let mut sec = "none".to_string();
            let mut sni = String::new();
            let mut host_hdr = String::new();
            let mut path = "/".to_string();
            if let Some(b64) = trimmed
                .strip_prefix("vmess://")
                .map(|s| s.split('#').next().unwrap_or(s))
            {
                if let Some(raw_json) = decode_base64_flex(b64) {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&raw_json) {
                        if let Some(v) = val.get("net").and_then(|x| x.as_str()) {
                            net = v.to_string();
                        }
                        if let Some(v) = val.get("tls").and_then(|x| x.as_str()) {
                            if !v.is_empty() {
                                sec = v.to_string();
                            }
                        }
                        if let Some(v) = val.get("sni").and_then(|x| x.as_str()) {
                            sni = v.to_string();
                        }
                        if let Some(v) = val.get("host").and_then(|x| x.as_str()) {
                            host_hdr = v.to_string();
                        }
                        if let Some(v) = val.get("path").and_then(|x| x.as_str()) {
                            if !v.is_empty() {
                                path = v.to_string();
                            }
                        }
                    }
                }
            }
            params.insert("type".to_string(), net);
            params.insert("security".to_string(), sec);
            if !sni.is_empty() {
                params.insert("sni".to_string(), sni);
            }
            if !host_hdr.is_empty() {
                params.insert("host".to_string(), host_hdr);
            }
            params.insert("path".to_string(), path);
            Ok(ChainHop {
                scheme: HopScheme::Vmess,
                host: parsed.host,
                port: parsed.port,
                auth_id: parsed.id,
                secret: String::new(),
                method: String::new(),
                params,
                alias: parsed.alias,
                raw: trimmed.to_string(),
                is_local_bridge: false,
            })
        }
        "trojan" => {
            set_default_param(&mut params, "security", "tls");
            set_default_param(&mut params, "type", "tcp");
            Ok(ChainHop {
                scheme: HopScheme::Trojan,
                host: parsed.host,
                port: parsed.port,
                auth_id: String::new(),
                secret: parsed.id,
                method: String::new(),
                params,
                alias: parsed.alias,
                raw: trimmed.to_string(),
                is_local_bridge: false,
            })
        }
        "ss" => {
            let (method, password) = parsed
                .id
                .split_once(':')
                .map(|(m, p)| (m.to_string(), p.to_string()))
                .unwrap_or_else(|| ("aes-256-gcm".to_string(), parsed.id.clone()));
            Ok(ChainHop {
                scheme: HopScheme::Shadowsocks,
                host: parsed.host,
                port: parsed.port,
                auth_id: String::new(),
                secret: password,
                method,
                params,
                alias: parsed.alias,
                raw: trimmed.to_string(),
                is_local_bridge: false,
            })
        }
        "wireguard" | "wg" | "warp" => {
            if parsed.id.is_empty() {
                return Err(CFError::new(
                    "chain",
                    "wireguard URI missing private key",
                    "Use wireguard://<private_key>@host:port?publickey=...",
                ));
            }
            Ok(ChainHop {
                scheme: HopScheme::WireGuard,
                host: parsed.host,
                port: parsed.port,
                auth_id: String::new(),
                secret: parsed.id,
                method: String::new(),
                params,
                alias: parsed.alias,
                raw: trimmed.to_string(),
                is_local_bridge: false,
            })
        }
        "socks5" | "socks" => {
            let is_local = parsed.host == "127.0.0.1" || parsed.host == "localhost";
            let authority = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
            let (user, pass) = if authority.contains('@') {
                parsed
                    .id
                    .split_once(':')
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .unwrap_or_else(|| (parsed.id.clone(), String::new()))
            } else {
                (String::new(), String::new())
            };
            Ok(ChainHop {
                scheme: HopScheme::Socks5,
                host: parsed.host,
                port: parsed.port,
                auth_id: user,
                secret: pass,
                method: String::new(),
                params,
                alias: parsed.alias,
                raw: trimmed.to_string(),
                is_local_bridge: is_local,
            })
        }
        other => Err(CFError::new(
            "chain",
            format!("scheme '{other}' requires an external core (not direct xray chain)"),
            "Use vless://, vmess://, trojan://, ss://, wireguard://, socks5://, or http://.",
        )),
    }
}

/// Extract runnable multi-layer hops from `.npv`/`.npvt`/`.npvs`/`.npv4`,
/// `.ovpn`/`.openvpn`, `.conf`/`.wg` (WireGuard INI), `.json`, `.yaml`, or
/// base64 `.sub`/`.txt` config files.
pub fn parse_configs_from_blob(filename: &str, bytes: &[u8]) -> Vec<ChainHop> {
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let mut hops = Vec::new();
    let mut seen = HashSet::new();
    let mut push_hop = |h: ChainHop| {
        if seen.insert(h.key()) {
            hops.push(h);
        }
    };

    // 1. Collect printable ASCII/UTF-8 text + any WireGuard/OpenVPN/URI snippets
    // (works for plain text, .ovpn, .wg, AND NapsternetV .npv/.npvt/.npvs payloads).
    let text = String::from_utf8_lossy(bytes);
    let mut printable = String::with_capacity(bytes.len().min(65536));
    let mut run = String::new();
    for &b in bytes {
        if b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
            run.push(b as char);
        } else {
            if run.len() >= 10 {
                printable.push_str(&run);
                printable.push('\n');
            }
            run.clear();
        }
    }
    if run.len() >= 10 {
        printable.push_str(&run);
    }

    let combined = if printable.len() > text.len() / 2 {
        format!("{printable}\n{text}")
    } else {
        text.into_owned()
    };

    // 2. Try base64-decoded whole-blob subscriptions or base64 payloads inside .npv*.
    let mut scan_corpus = combined.clone();
    if matches!(ext.as_str(), "sub" | "txt" | "npv" | "npvt" | "npvs" | "npv4" | "") {
        let compact: String = combined.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.len() >= 16 {
            if let Some(dec) = decode_base64_flex(&compact) {
                if let Ok(s) = String::from_utf8(dec) {
                    scan_corpus.push('\n');
                    scan_corpus.push_str(&s);
                }
            }
        }
        // Check long base64 runs embedded inside .npv* / text blocks.
        let is_b64 = |c: char| {
            c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_')
        };
        for tok in combined.split(|c: char| !is_b64(c)) {
            if tok.len() >= 28 {
                if let Some(dec) = decode_base64_flex(tok) {
                    let s = String::from_utf8_lossy(&dec);
                    if s.contains("://") || s.contains("[Peer]") || s.contains("\"outbounds\"") {
                        scan_corpus.push('\n');
                        scan_corpus.push_str(&s);
                    }
                }
            }
        }
    }

    // 3. Extract standard share URIs + WireGuard [Interface]/[Peer] + OpenVPN inline.
    for link in crate::discovery::harvest::extract_proxy_links(&scan_corpus) {
        if let Ok(h) = parse_chain_hop(&link) {
            push_hop(h);
        }
    }

    // 4. Parse explicit .ovpn `http-proxy <h> <p>` / `socks-proxy <h> <p>` relays.
    if matches!(ext.as_str(), "ovpn" | "openvpn") || scan_corpus.contains("http-proxy ") {
        for raw_line in scan_corpus.lines() {
            let line = raw_line.split(['#', ';']).next().unwrap_or("").trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && matches!(parts[0], "http-proxy" | "socks-proxy") {
                if let Ok(port) = parts[2].parse::<u16>() {
                    let scheme = if parts[0] == "socks-proxy" {
                        "socks5"
                    } else {
                        "http"
                    };
                    if let Ok(h) = parse_chain_hop(&format!("{scheme}://{}:{port}", parts[1])) {
                        push_hop(h);
                    }
                }
            }
        }
    }

    // 5. Parse JSON configs (sing-box / xray outbounds array or v2rayN array).
    let trimmed_corpus = scan_corpus.trim_start();
    if ext == "json" || trimmed_corpus.starts_with('{') || trimmed_corpus.starts_with('[') {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&scan_corpus) {
            let outs = val.get("outbounds").and_then(|o| o.as_array());
            let outs = outs.or_else(|| val.as_array());
            if let Some(arr) = outs {
                for ob in arr {
                    let proto = ob
                        .get("type")
                        .or_else(|| ob.get("protocol"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    if let Some(server) = ob.get("server").and_then(|x| x.as_str()) {
                        let raw_port = ob.get("server_port").and_then(|x| x.as_u64());
                        let port = raw_port.unwrap_or(0) as u16;
                        if port > 0 {
                            let uuid = ob.get("uuid").and_then(|x| x.as_str());
                            let pass = ob.get("password").and_then(|x| x.as_str());
                            let uri = match (proto, uuid, pass) {
                                ("vless", Some(u), _) => {
                                    Some(format!("vless://{u}@{server}:{port}?security=tls"))
                                }
                                ("trojan", _, Some(pw)) => {
                                    Some(format!("trojan://{pw}@{server}:{port}?security=tls"))
                                }
                                ("socks", _, _) => Some(format!("socks5://{server}:{port}")),
                                ("http", _, _) => Some(format!("http://{server}:{port}")),
                                _ => None,
                            };
                            if let Some(u) = uri {
                                if let Ok(h) = parse_chain_hop(&u) {
                                    push_hop(h);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    hops
}

fn decode_base64_flex(raw: &str) -> Option<Vec<u8>> {
    let clean = raw.trim().replace('-', "+").replace('_', "/");
    base64::engine::general_purpose::STANDARD
        .decode(&clean)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean))
        .ok()
}

/// Options governing multi-hop xray chain compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainDialOptions {
    pub socks_port: u16,
    pub fragment_dpi: bool,
    pub fragment_packets: String,
    pub fragment_length: String,
    pub fragment_interval: String,
    pub enable_doh: bool,
}

impl Default for ChainDialOptions {
    fn default() -> Self {
        Self {
            socks_port: 10850,
            fragment_dpi: false,
            fragment_packets: "tlshello".to_string(),
            fragment_length: "10-30".to_string(),
            fragment_interval: "10-20".to_string(),
            enable_doh: true,
        }
    }
}

/// Build an N-hop xray configuration (`1..=4+` hops) chained via `sockopt.dialerProxy`.
///
/// `hops` must be ordered **`[exit, relay_n, ..., entry]`**:
/// - `hops[0]` (`"exit"`) is the egress Google sees.
/// - `hops[last]` (`"entry"`) is the first hop the local machine dials.
/// - If `opts.fragment_dpi` is `true`, an additional `freedom` outbound `"frag-dialer"`
///   performs TLS-Hello packet fragmentation underneath the entry hop!
pub fn build_xray_chain_config(
    hops: &[ChainHop],
    opts: &ChainDialOptions,
) -> Result<String, CFError> {
    if hops.is_empty() {
        return Err(CFError::new(
            "chain",
            "cannot build chain with zero hops",
            "Supply at least one server hop.",
        ));
    }

    let mut outbounds: Vec<serde_json::Value> = Vec::with_capacity(hops.len() + 1);
    for (idx, hop) in hops.iter().enumerate() {
        let tag = if idx == 0 {
            "exit".to_string()
        } else if idx + 1 == hops.len() {
            "entry".to_string()
        } else {
            format!("relay-{idx}")
        };
        let next_tag = if idx + 1 < hops.len() {
            if idx + 2 == hops.len() {
                Some("entry".to_string())
            } else {
                Some(format!("relay-{}", idx + 1))
            }
        } else if opts.fragment_dpi && !hop.is_local_bridge {
            Some("frag-dialer".to_string())
        } else {
            None
        };
        outbounds.push(hop_to_xray_outbound(hop, &tag, next_tag.as_deref()));
    }

    if opts.fragment_dpi && hops.last().is_some_and(|h| !h.is_local_bridge) {
        outbounds.push(serde_json::json!({
            "tag": "frag-dialer",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "AsIs",
                "fragment": {
                    "packets": opts.fragment_packets,
                    "length": opts.fragment_length,
                    "interval": opts.fragment_interval
                }
            },
            "sockopt": {
                "tcpNoDelay": true
            }
        }));
    }

    let mut cfg = serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": opts.socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": true}
        }],
        "outbounds": outbounds,
    });

    if opts.enable_doh {
        cfg["dns"] = serde_json::json!({
            "servers": ["https://1.1.1.1/dns-query", "8.8.8.8"],
            "queryStrategy": "UseIPv4"
        });
        cfg["routing"] = serde_json::json!({
            "domainStrategy": "IPIfNonMatch"
        });
    }

    serde_json::to_string_pretty(&cfg)
        .map_err(|e| CFError::new("chain", format!("serialize xray chain: {e}"), ""))
}

fn hop_to_xray_outbound(hop: &ChainHop, tag: &str, dialer: Option<&str>) -> serde_json::Value {
    let mut out = match hop.scheme {
        HopScheme::Vless => {
            let mut user = serde_json::json!({
                "id": hop.auth_id,
                "encryption": "none"
            });
            let sec = hop.param_val("security", "none");
            if matches!(sec, "tls" | "reality") {
                if let Some(flow) = hop.params.get("flow").filter(|f| !f.is_empty()) {
                    user["flow"] = serde_json::json!(flow);
                }
            }
            serde_json::json!({
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": hop.host,
                        "port": hop.port,
                        "users": [user]
                    }]
                }
            })
        }
        HopScheme::Vmess => serde_json::json!({
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": hop.host,
                    "port": hop.port,
                    "users": [{"id": hop.auth_id, "alterId": 0}]
                }]
            }
        }),
        HopScheme::Trojan => serde_json::json!({
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": hop.host,
                    "port": hop.port,
                    "password": hop.secret
                }]
            }
        }),
        HopScheme::Shadowsocks => {
            let method = if hop.method.is_empty() {
                "aes-256-gcm"
            } else {
                &hop.method
            };
            serde_json::json!({
                "tag": tag,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": hop.host,
                        "port": hop.port,
                        "method": method,
                        "password": hop.secret
                    }]
                }
            })
        }
        HopScheme::WireGuard => {
            let addr = hop
                .params
                .get("address")
                .filter(|s| !s.is_empty())
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect::<Vec<_>>())
                .unwrap_or_else(|| vec!["172.16.0.2/32".to_string()]);
            let mtu_raw = hop.params.get("mtu").and_then(|s| s.parse::<u16>().ok());
            let mtu = mtu_raw.unwrap_or(1280);
            serde_json::json!({
                "tag": tag,
                "protocol": "wireguard",
                "settings": {
                    "secretKey": hop.secret,
                    "address": addr,
                    "mtu": mtu,
                    "peers": [{
                        "publicKey": hop.param_val("publickey", ""),
                        "endpoint": format!("{}:{}", hop.host, hop.port)
                    }]
                }
            })
        }
        HopScheme::Socks5 => {
            let mut server = serde_json::json!({
                "address": hop.host,
                "port": hop.port
            });
            if !hop.auth_id.is_empty() {
                server["users"] = serde_json::json!([{
                    "user": hop.auth_id,
                    "pass": hop.secret
                }]);
            }
            serde_json::json!({
                "tag": tag,
                "protocol": "socks",
                "settings": {"servers": [server]}
            })
        }
        HopScheme::Http => {
            let mut server = serde_json::json!({
                "address": hop.host,
                "port": hop.port
            });
            if !hop.auth_id.is_empty() {
                server["users"] = serde_json::json!([{
                    "user": hop.auth_id,
                    "pass": hop.secret
                }]);
            }
            serde_json::json!({
                "tag": tag,
                "protocol": "http",
                "settings": {"servers": [server]}
            })
        }
    };

    if !hop.is_socks_or_http() && hop.scheme != HopScheme::WireGuard {
        let sec = hop.param_val("security", "none");
        let net = hop.param_val("type", "tcp");
        let sni = hop
            .params
            .get("sni")
            .filter(|s| !s.is_empty())
            .map(|s| s.as_str())
            .unwrap_or(&hop.host);
        let fp = hop
            .params
            .get("fp")
            .filter(|s| !s.is_empty())
            .map(|s| s.as_str())
            .unwrap_or("chrome");
        let hdr_host = hop
            .params
            .get("host")
            .filter(|s| !s.is_empty())
            .map(|s| s.as_str())
            .unwrap_or(sni);
        let path = hop
            .params
            .get("path")
            .filter(|s| !s.is_empty())
            .map(|s| s.as_str())
            .unwrap_or("/");

        let mut ss = serde_json::json!({
            "network": net,
            "security": sec
        });
        if sec == "reality" {
            ss["realitySettings"] = serde_json::json!({
                "serverName": sni,
                "fingerprint": fp,
                "publicKey": hop.param_val("pbk", ""),
                "shortId": hop.param_val("sid", ""),
                "spiderX": hop.param_val("spx", "/")
            });
        } else if sec == "tls" {
            let mut tls = serde_json::json!({
                "serverName": sni,
                "fingerprint": fp
            });
            if let Some(alpn) = hop.params.get("alpn").filter(|s| !s.is_empty()) {
                let list: Vec<&str> = alpn.split(',').filter(|x| !x.is_empty()).collect();
                tls["alpn"] = serde_json::json!(list);
            }
            ss["tlsSettings"] = tls;
        }
        match net {
            "ws" => {
                ss["wsSettings"] = serde_json::json!({
                    "path": path,
                    "headers": {"Host": hdr_host}
                });
            }
            "xhttp" => {
                ss["xhttpSettings"] = serde_json::json!({
                    "path": path,
                    "host": hdr_host,
                    "mode": hop.param_val("mode", "auto")
                });
            }
            "grpc" => {
                let svc = hop.param_val("serviceName", "");
                ss["grpcSettings"] = serde_json::json!({ "serviceName": svc });
            }
            _ => {}
        }
        out["streamSettings"] = ss;
    }

    if let Some(dp) = dialer {
        out["sockopt"] = serde_json::json!({"dialerProxy": dp});
    }
    out
}

/// Planned brutal multi-layer candidate route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrutalChainPlan {
    /// Ordered `[exit, ..., entry]` hops.
    pub hops: Vec<ChainHop>,
    pub fragment_dpi: bool,
    pub stage_label: String,
}

impl BrutalChainPlan {
    pub fn arm_id(&self) -> String {
        let keys: Vec<String> = self.hops.iter().map(ChainHop::key).collect();
        let hops_id = keys.join("<-");
        if self.fragment_dpi {
            format!("{hops_id}+frag")
        } else {
            hops_id
        }
    }
}

/// Mutate a hop's uTLS fingerprint (`chrome` -> `firefox` -> `random`) to defeat
/// strict TLS-ClientHello JA3/JA4 classifiers without changing the upstream node.
pub fn mutate_hop_fingerprint(hop: &ChainHop, fingerprint: &str) -> ChainHop {
    let mut cloned = hop.clone();
    let fp = fingerprint.to_string();
    cloned.params.insert("fp".to_string(), fp);
    cloned
}

fn push_brutal_plan(
    plans: &mut Vec<BrutalChainPlan>,
    seen: &mut HashSet<String>,
    budget: usize,
    plan: BrutalChainPlan,
) {
    if plans.len() < budget && seen.insert(plan.arm_id()) {
        plans.push(plan);
    }
}

/// Generate brutal multi-layer routes (1-hop, fragment DPI, uTLS mutations,
/// cross-`/16` 2-hop bidirectional swaps, 3-hop & 4-hop cascades, plus deep
/// 5..=8-hop multi-relay cascades + local proxy bridges).
pub fn generate_brutal_chains(
    candidates: &[ChainHop],
    relays: &[ChainHop],
    local_proxies: &[ChainHop],
    bandit: &ContextualBanditStore,
    persona: ServicePersona,
    max_hops: usize,
    budget: usize,
) -> Vec<BrutalChainPlan> {
    if candidates.is_empty() || budget == 0 {
        return Vec::new();
    }
    let max_hops = max_hops.clamp(1, 8);
    let now = crate::store::now_ts() as u64;

    let arms: Vec<CandidateArm> = candidates
        .iter()
        .map(|h| CandidateArm {
            arm_id: h.key(),
            protocol_family: h.scheme.as_str().to_string(),
            base_priority: 0.5,
        })
        .collect();
    let slate =
        bandit.select_diverse_slate("default", &arms, persona.bandit_intent(), arms.len(), now);
    let by_key: HashMap<String, &ChainHop> = candidates.iter().map(|c| (c.key(), c)).collect();
    let ordered_exits: Vec<&ChainHop> = slate
        .iter()
        .filter_map(|a| by_key.get(&a.arm_id).copied())
        .collect();

    let mut relay_pool: Vec<&ChainHop> = relays.iter().collect();
    for h in &ordered_exits {
        if !relay_pool.iter().any(|r| r.key() == h.key()) {
            relay_pool.push(*h);
        }
    }

    let mut plans = Vec::new();
    let mut seen = HashSet::new();

    // Stage 0: Fast diverse 1-hop routes.
    for exit in ordered_exits.iter().take(budget) {
        push_brutal_plan(
            &mut plans,
            &mut seen,
            budget,
            BrutalChainPlan {
                hops: vec![(*exit).clone()],
                fragment_dpi: false,
                stage_label: "stage0-1hop".to_string(),
            },
        );
    }

    // Stage 1: DPI-fragmented + uTLS-mutated 1-hop routes.
    for exit in ordered_exits.iter().take((budget / 3).max(4)) {
        if !exit.is_local_bridge && !exit.is_socks_or_http() {
            push_brutal_plan(
                &mut plans,
                &mut seen,
                budget,
                BrutalChainPlan {
                    hops: vec![mutate_hop_fingerprint(exit, "firefox")],
                    fragment_dpi: true,
                    stage_label: "stage1-fragment".to_string(),
                },
            );
        }
    }

    let stage4_reserve = if max_hops >= 4 {
        ((max_hops - 3) * 3).min(budget / 3)
    } else {
        0
    };
    let pre_stage4_cap = budget.saturating_sub(stage4_reserve);
    let stage2b_cap = if max_hops >= 4 {
        (pre_stage4_cap * 3) / 4
    } else {
        budget
    };

    if max_hops >= 2 {
        // Stage 2: Local proxy bridge -> Clean Exit (WARP/Tor/OpenVPN/SingBox -> Exit).
        for exit in ordered_exits.iter().take(8) {
            for local in local_proxies {
                if local.key() != exit.key() {
                    push_brutal_plan(
                        &mut plans,
                        &mut seen,
                        budget,
                        BrutalChainPlan {
                            hops: vec![(*exit).clone(), local.clone()],
                            fragment_dpi: false,
                            stage_label: "stage2-local-bridge".to_string(),
                        },
                    );
                }
            }
        }

        // Stage 2b: Cross-/16 subnet 2-hop + bidirectional swaps [Exit <- Entry].
        'stage2b: for exit in ordered_exits.iter().take(8) {
            let ex_net = exit.subnet_prefix16();
            for entry in &relay_pool {
                if plans.len() >= stage2b_cap {
                    break 'stage2b;
                }
                if entry.key() == exit.key() || entry.subnet_prefix16() == ex_net {
                    continue;
                }
                push_brutal_plan(
                    &mut plans,
                    &mut seen,
                    budget,
                    BrutalChainPlan {
                        hops: vec![(*exit).clone(), (*entry).clone()],
                        fragment_dpi: false,
                        stage_label: "stage2-2hop-cross16".to_string(),
                    },
                );
                if plans.len() >= stage2b_cap {
                    break 'stage2b;
                }
                push_brutal_plan(
                    &mut plans,
                    &mut seen,
                    budget,
                    BrutalChainPlan {
                        hops: vec![(*exit).clone(), mutate_hop_fingerprint(entry, "random")],
                        fragment_dpi: true,
                        stage_label: "stage2-2hop-frag".to_string(),
                    },
                );
            }
        }
    }

    if max_hops >= 3 && relay_pool.len() >= 2 {
        // Stage 3: 3-hop & 4-hop cascades forcing protocol & subnet diversity.
        'stage3: for exit in ordered_exits.iter().take(5) {
            for r1 in relay_pool.iter().take(5) {
                if r1.key() == exit.key() {
                    continue;
                }
                for entry in relay_pool.iter().take(5) {
                    if plans.len() >= pre_stage4_cap {
                        break 'stage3;
                    }
                    if entry.key() == exit.key()
                        || entry.key() == r1.key()
                        || entry.subnet_prefix16() == r1.subnet_prefix16()
                    {
                        continue;
                    }
                    push_brutal_plan(
                        &mut plans,
                        &mut seen,
                        budget,
                        BrutalChainPlan {
                            hops: vec![(*exit).clone(), (*r1).clone(), (*entry).clone()],
                            fragment_dpi: true,
                            stage_label: "stage3-3hop-brutal".to_string(),
                        },
                    );
                }
            }
        }
    }

    // Stage 4: Deep multi-layer cascades (4..=max_hops, up to 8 layers + local anchor).
    if max_hops >= 4 {
        let mut combined_entries: Vec<ChainHop> =
            relay_pool.iter().map(|h| (*h).clone()).collect();
        for lp in local_proxies {
            if !combined_entries.iter().any(|x| x.key() == lp.key()) {
                combined_entries.push(lp.clone());
            }
        }
        for target_depth in 4..=max_hops {
            if plans.len() >= budget {
                break;
            }
            for exit in ordered_exits.iter().take(3) {
                let mut chain = vec![(*exit).clone()];
                let mut used_keys = HashSet::from([exit.key()]);
                let reserve = usize::from(!local_proxies.is_empty());
                for hop in &combined_entries {
                    if !hop.is_local_bridge && used_keys.insert(hop.key()) {
                        chain.push(hop.clone());
                    }
                    if chain.len() + reserve >= target_depth {
                        break;
                    }
                }
                if chain.len() < target_depth {
                    for lp in local_proxies {
                        if used_keys.insert(lp.key()) {
                            chain.push(lp.clone());
                        }
                        if chain.len() == target_depth {
                            break;
                        }
                    }
                }
                if chain.len() >= target_depth {
                    chain.truncate(target_depth);
                    push_brutal_plan(
                        &mut plans,
                        &mut seen,
                        budget,
                        BrutalChainPlan {
                            hops: chain,
                            fragment_dpi: true,
                            stage_label: format!("stage4-{target_depth}hop-max"),
                        },
                    );
                }
            }
        }
    }

    plans
}

// ---------------------------------------------------------------------------
// Isolated Blacklists (separate files for Lion vs Warrior; exit vs entry)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersonaBlacklist {
    pub blocked_exits: HashMap<String, f64>,
}

const EXIT_BLACKLIST_TTL_SECS: f64 = 6.0 * 3600.0;

pub fn blacklist_path(profile_id: &str, persona: ServicePersona) -> PathBuf {
    let fname = match persona {
        ServicePersona::LionAiStudio => "lion-blacklist.json",
        ServicePersona::WarriorFlow => "warrior-blacklist.json",
    };
    profile_dir(profile_id).join(fname)
}

pub fn record_blocked_exit(profile_id: &str, persona: ServicePersona, key: &str) {
    let path = blacklist_path(profile_id, persona);
    let mut store: PersonaBlacklist = read_opt(&path).unwrap_or_default();
    let now = crate::store::now_ts();
    let map = &mut store.blocked_exits;
    map.retain(|_, ts| now - *ts < EXIT_BLACKLIST_TTL_SECS);
    map.insert(key.to_string(), now);
    let _ = write_json(&path, &store);
}

pub fn is_exit_blacklisted(profile_id: &str, persona: ServicePersona, key: &str) -> bool {
    let path = blacklist_path(profile_id, persona);
    let Some(store) = read_opt::<PersonaBlacklist>(&path) else {
        return false;
    };
    let now = crate::store::now_ts();
    let ts = store.blocked_exits.get(key);
    ts.is_some_and(|t| now - *t < EXIT_BLACKLIST_TTL_SECS)
}

// ---------------------------------------------------------------------------
// Strict Lion & Warrior HTTP/HTML/Redirect Verification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaProbeCheck {
    pub target: String,
    pub passed: bool,
    pub status: u16,
    pub final_url: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaAccessReport {
    pub persona: ServicePersona,
    pub ok: bool,
    pub egress_ip: Option<String>,
    pub geo: Option<GeoAsnReport>,
    pub checks: Vec<PersonaProbeCheck>,
    pub reason: String,
}

const REGION_BLOCK_URL_SUBSTRS: &[&str] = &[
    "unsupported-country",
    "available-regions",
    "/sorry/",
    "region-not-supported",
];

const REGION_BLOCK_BODY_SUBSTRS: &[&str] = &[
    "unsupported-country-title",
    "not available in your country",
    "isn't available in your country",
    "flow is not available in your country",
    "google ai studio is not available",
];

const CHROME_LINUX_UA: &str = concat!(
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ",
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
);

/// Pure verdict evaluator for Lion (AI Studio) HTML responses & redirects.
pub fn evaluate_lion_response(status: u16, final_url: &str, body: &str) -> (bool, String) {
    let url_low = final_url.to_ascii_lowercase();
    let body_low = body.to_ascii_lowercase();
    if status == 403 || status == 451 || status == 429 {
        return (false, format!("HTTP {status} (geo/rate block)"));
    }
    for mark in REGION_BLOCK_URL_SUBSTRS {
        if url_low.contains(mark) {
            return (false, format!("redirected to geo-block ({mark})"));
        }
    }
    for mark in REGION_BLOCK_BODY_SUBSTRS {
        if body_low.contains(mark) {
            return (false, format!("geo-block page marker ({mark})"));
        }
    }
    if !(200..400).contains(&status) {
        return (false, format!("unexpected HTTP {status}"));
    }
    (true, format!("HTTP {status} clean"))
}

/// Pure verdict evaluator for Warrior (Google Flow) HTML responses & redirects.
pub fn evaluate_warrior_response(
    status: u16,
    final_url: &str,
    body: &str,
    require_app_shell: bool,
) -> (bool, String) {
    let url_low = final_url.to_ascii_lowercase();
    let body_low = body.to_ascii_lowercase();
    if status == 403 || status == 451 || status == 429 {
        return (false, format!("HTTP {status} (Flow blocked)"));
    }
    for mark in REGION_BLOCK_URL_SUBSTRS {
        if url_low.contains(mark) {
            return (false, format!("redirected to Flow region-gate ({mark})"));
        }
    }
    for mark in REGION_BLOCK_BODY_SUBSTRS {
        if body_low.contains(mark) {
            return (false, format!("REGION-GATE marker ({mark})"));
        }
    }
    if !(200..400).contains(&status) {
        return (false, format!("unexpected HTTP {status}"));
    }
    if require_app_shell && !body.contains("AiSandboxAngularFrontend") {
        return (
            false,
            "Flow responded without AiSandboxAngularFrontend shell".to_string(),
        );
    }
    (true, format!("HTTP {status} Flow clean"))
}

/// Probe `socks5h://127.0.0.1:<socks_port>` with strict Lion or Warrior checks.
pub async fn verify_persona_through_socks(
    socks_port: u16,
    persona: ServicePersona,
    want_country: Option<&str>,
    strict_clean: bool,
) -> Result<PersonaAccessReport, CFError> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
        .map_err(|e| CFError::new("lion_warrior", format!("socks proxy cfg: {e}"), ""))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(20))
        .user_agent(CHROME_LINUX_UA)
        .build()
        .map_err(|e| CFError::new("lion_warrior", format!("http client: {e}"), ""))?;

    let egress_ip = fetch_egress_ip(&client).await;
    let Some(ip) = egress_ip.clone() else {
        return Ok(PersonaAccessReport {
            persona,
            ok: false,
            egress_ip: None,
            geo: None,
            checks: Vec::new(),
            reason: "no egress IP through tunnel".to_string(),
        });
    };

    let geo = fetch_geo_asn(&client, &ip).await;
    let Some(g) = geo.clone() else {
        return Ok(PersonaAccessReport {
            persona,
            ok: false,
            egress_ip: Some(ip),
            geo: None,
            checks: Vec::new(),
            reason: "geo/ASN lookup failed through tunnel".to_string(),
        });
    };

    if let Some(req_cc) = want_country.filter(|c| !c.trim().is_empty()) {
        if !g.country.eq_ignore_ascii_case(req_cc.trim()) {
            let got = &g.country;
            let want = req_cc.to_uppercase();
            return Ok(PersonaAccessReport {
                persona,
                ok: false,
                egress_ip: Some(ip),
                geo: Some(g.clone()),
                checks: Vec::new(),
                reason: format!("country {got} != requested {want}"),
            });
        }
    }

    match persona {
        ServicePersona::LionAiStudio => {
            if !is_aistudio_supported_country(&g.country) {
                return Ok(PersonaAccessReport {
                    persona,
                    ok: false,
                    egress_ip: Some(ip),
                    geo: Some(g.clone()),
                    checks: Vec::new(),
                    reason: format!("country {} blocked by AI Studio", g.country),
                });
            }
            if strict_clean && g.reputation == ExitReputation::WarpOrTor {
                return Ok(PersonaAccessReport {
                    persona,
                    ok: false,
                    egress_ip: Some(ip),
                    geo: Some(g.clone()),
                    checks: Vec::new(),
                    reason: "WARP/Tor exit rejected in strict mode".to_string(),
                });
            }
        }
        ServicePersona::WarriorFlow => {
            if !is_flow_supported_country(&g.country) {
                return Ok(PersonaAccessReport {
                    persona,
                    ok: false,
                    egress_ip: Some(ip),
                    geo: Some(g.clone()),
                    checks: Vec::new(),
                    reason: format!("country {} not on Google Flow rollout list", g.country),
                });
            }
            if g.reputation == ExitReputation::WarpOrTor {
                return Ok(PersonaAccessReport {
                    persona,
                    ok: false,
                    egress_ip: Some(ip),
                    geo: Some(g.clone()),
                    checks: Vec::new(),
                    reason: "WARP/Tor exit rejected by Warrior (use as entry hop)".to_string(),
                });
            }
            if strict_clean && g.reputation == ExitReputation::HostingHighRisk {
                return Ok(PersonaAccessReport {
                    persona,
                    ok: false,
                    egress_ip: Some(ip),
                    geo: Some(g.clone()),
                    checks: Vec::new(),
                    reason: "high-risk hosting IP rejected in strict Warrior mode".to_string(),
                });
            }
        }
    }

    let targets: &[(&str, &str, bool)] = match persona {
        ServicePersona::LionAiStudio => &[
            ("AI Studio", "https://aistudio.google.com/", false),
            (
                "Gemini API",
                "https://generativelanguage.googleapis.com/",
                false,
            ),
            ("Google Accounts", "https://accounts.google.com/", false),
        ],
        ServicePersona::WarriorFlow => &[
            ("Google Flow", "https://flow.google.com/", true),
            ("Labs Flow", "https://labs.google/fx/tools/flow", false),
            ("Google Accounts", "https://accounts.google.com/", false),
        ],
    };

    let mut checks = Vec::with_capacity(targets.len());
    for (name, url, need_shell) in targets {
        let chk = run_http_gate(&client, persona, name, url, *need_shell).await;
        checks.push(chk);
    }

    let all_ok = checks.iter().all(|c| c.passed);
    let reason = if all_ok {
        format!(
            "{} CLEAR via {} ({}, rep={}, score={})",
            persona.display_title(),
            ip,
            g.country,
            g.reputation.label(),
            g.clean_score
        )
    } else {
        checks
            .iter()
            .find(|c| !c.passed)
            .map(|c| format!("{}: {}", c.target, c.detail))
            .unwrap_or_else(|| "probe failed".to_string())
    };

    Ok(PersonaAccessReport {
        persona,
        ok: all_ok,
        egress_ip: Some(ip),
        geo: Some(g),
        checks,
        reason,
    })
}

async fn run_http_gate(
    client: &reqwest::Client,
    persona: ServicePersona,
    target: &str,
    url: &str,
    require_shell: bool,
) -> PersonaProbeCheck {
    match client
        .get(url)
        .header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Sec-Fetch-Site", "none")
        .header("Sec-Fetch-Mode", "navigate")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let final_url = resp.url().as_str().to_string();
            let body = resp.text().await.unwrap_or_default();
            let (passed, detail) = match persona {
                ServicePersona::LionAiStudio => evaluate_lion_response(status, &final_url, &body),
                ServicePersona::WarriorFlow => {
                    evaluate_warrior_response(status, &final_url, &body, require_shell)
                }
            };
            PersonaProbeCheck {
                target: target.to_string(),
                passed,
                status,
                final_url,
                detail,
            }
        }
        Err(e) => PersonaProbeCheck {
            target: target.to_string(),
            passed: false,
            status: 0,
            final_url: url.to_string(),
            detail: e.to_string(),
        },
    }
}

async fn fetch_egress_ip(client: &reqwest::Client) -> Option<String> {
    for url in ["https://api.ipify.org", "https://ifconfig.me/ip"] {
        if let Ok(r) = client.get(url).send().await {
            if let Ok(txt) = r.text().await {
                let s = txt.trim().to_string();
                if !s.is_empty() && s.len() < 64 && !s.contains('<') {
                    return Some(s);
                }
            }
        }
    }
    None
}

async fn fetch_geo_asn(client: &reqwest::Client, ip: &str) -> Option<GeoAsnReport> {
    let trace = match client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .await
    {
        Ok(r) => parse_cloudflare_trace(&r.text().await.unwrap_or_default()),
        Err(_) => TraceInfo::default(),
    };

    const IP_API_URL: &str =
        "http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,proxy,hosting";
    if let Ok(r) = client.get(IP_API_URL).send().await {
        if let Ok(v) = r.json::<serde_json::Value>().await {
            if v.get("status").and_then(|x| x.as_str()) == Some("success") {
                let cc = v["countryCode"].as_str().unwrap_or("").to_ascii_uppercase();
                let org = format!(
                    "{} {}",
                    v["isp"].as_str().unwrap_or(""),
                    v["org"].as_str().unwrap_or("")
                )
                .trim()
                .to_string();
                let proxy = v["proxy"].as_bool().unwrap_or(false);
                let hosting = v["hosting"].as_bool().unwrap_or(false);
                let is_warp = trace.is_warp();
                let (reputation, clean_score) =
                    classify_exit_reputation(&org, proxy, hosting, false, is_warp);
                return Some(GeoAsnReport {
                    ip: ip.to_string(),
                    country: cc,
                    country_name: v["country"].as_str().unwrap_or("").to_string(),
                    asn: v["as"].as_str().unwrap_or("").to_string(),
                    org,
                    is_proxy: proxy,
                    is_hosting: hosting,
                    is_tor: false,
                    is_warp,
                    cf_colo: trace.colo,
                    reputation,
                    clean_score,
                });
            }
        }
    }

    if let Ok(r) = client.get("https://ipwho.is/").send().await {
        if let Ok(v) = r.json::<serde_json::Value>().await {
            if v["success"].as_bool() == Some(true) {
                let cc = v["country_code"].as_str().unwrap_or("").to_ascii_uppercase();
                let org = v["connection"]["isp"]
                    .as_str()
                    .or_else(|| v["connection"]["org"].as_str())
                    .unwrap_or("")
                    .to_string();
                let is_warp = trace.is_warp();
                let (reputation, clean_score) =
                    classify_exit_reputation(&org, false, false, false, is_warp);
                return Some(GeoAsnReport {
                    ip: ip.to_string(),
                    country: cc,
                    country_name: v["country"].as_str().unwrap_or("").to_string(),
                    asn: v["connection"]["asn"]
                        .as_u64()
                        .map(|a| format!("AS{a}"))
                        .unwrap_or_default(),
                    org,
                    is_proxy: false,
                    is_hosting: false,
                    is_tor: false,
                    is_warp,
                    cf_colo: trace.colo,
                    reputation,
                    clean_score,
                });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Hardened Anti-Leak Chrome Launch Args (DNS + WebRTC + Locale/TZ)
// ---------------------------------------------------------------------------

pub fn country_to_locale_tz(country: Option<&str>) -> (&'static str, &'static str) {
    let up = country.unwrap_or("").trim().to_ascii_uppercase();
    match up.as_str() {
        "DE" => ("de-DE", "Europe/Berlin"),
        "GB" => ("en-GB", "Europe/London"),
        "FR" => ("fr-FR", "Europe/Paris"),
        "NL" => ("nl-NL", "Europe/Amsterdam"),
        "SG" => ("en-SG", "Asia/Singapore"),
        "JP" => ("ja-JP", "Asia/Tokyo"),
        "CA" => ("en-CA", "America/Toronto"),
        "AE" => ("en-AE", "Asia/Dubai"),
        "TR" => ("tr-TR", "Europe/Istanbul"),
        _ => ("en-US", "America/New_York"),
    }
}

pub fn hardened_chrome_args(
    socks_port: u16,
    profile_dir_path: &Path,
    target_url: &str,
    country: Option<&str>,
) -> Vec<String> {
    let (lang, _) = country_to_locale_tz(country);
    vec![
        "--ozone-platform=x11".to_string(),
        format!("--proxy-server=socks5://127.0.0.1:{socks_port}"),
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
        "--disable-features=AsyncDns,DnsOverHttps".to_string(),
        format!("--lang={lang}"),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        format!("--user-data-dir={}", profile_dir_path.display()),
        target_url.to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Pure-Rust Async Multi-Hop SOCKS5 / HTTP-CONNECT Cascade Bridge
// ---------------------------------------------------------------------------

/// Handle to a running pure-Rust local SOCKS5 listener forwarding traffic
/// sequentially through `hops` (`socks5` / `http` CONNECT chain).
pub struct CascadeProxyHandle {
    pub local_addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl CascadeProxyHandle {
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }
}

impl Drop for CascadeProxyHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start an in-process SOCKS5 proxy at `127.0.0.1:<bind_port>` (use `0` for OS
/// ephemeral port) that tunnels through `hops` in connection order (`hops[0]`
/// connected directly first, then `hops[1]`, ..., ending at `target`).
pub async fn start_cascade_socks_proxy(
    bind_port: u16,
    hops: Vec<ChainHop>,
) -> Result<CascadeProxyHandle, CFError> {
    for h in &hops {
        if !h.is_socks_or_http() {
            let got = h.scheme.as_str();
            return Err(CFError::new(
                "cascade",
                format!("native cascade supports socks5/http hops, got {got}"),
                "Use build_xray_chain_config for vless/vmess/trojan/ss chains.",
            ));
        }
    }
    let listener = match TcpListener::bind(("127.0.0.1", bind_port)).await {
        Ok(l) => l,
        Err(e) => {
            let msg = format!("bind 127.0.0.1:{bind_port}: {e}");
            return Err(CFError::new("cascade", msg, ""));
        }
    };
    let local_addr = listener
        .local_addr()
        .map_err(|e| CFError::new("cascade", format!("local_addr: {e}"), ""))?;

    let hops = std::sync::Arc::new(hops);
    let task = tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let hops_cl = hops.clone();
            tokio::spawn(async move {
                let _ = handle_socks_client(client, &hops_cl).await;
            });
        }
    });

    Ok(CascadeProxyHandle { local_addr, task })
}

async fn handle_socks_client(
    mut client: TcpStream,
    hops: &[ChainHop],
) -> Result<(), std::io::Error> {
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not SOCKS5",
        ));
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;
    client.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        let err_rep = [0x05u8, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _ = client.write_all(&err_rep).await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "only CONNECT",
        ));
    }
    let target_host = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            client.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => {
            let err_rep = [0x05u8, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let _ = client.write_all(&err_rep).await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad atyp",
            ));
        }
    };
    let mut pbuf = [0u8; 2];
    client.read_exact(&mut pbuf).await?;
    let target_port = u16::from_be_bytes(pbuf);

    let mut stream = if let Some(first) = hops.first() {
        TcpStream::connect((first.host.as_str(), first.port)).await?
    } else {
        TcpStream::connect((target_host.as_str(), target_port)).await?
    };

    for (idx, hop) in hops.iter().enumerate() {
        let (next_host, next_port) = match hops.get(idx + 1) {
            Some(next) => (next.host.as_str(), next.port),
            None => (target_host.as_str(), target_port),
        };
        dial_through_proxy(&mut stream, hop, next_host, next_port).await?;
    }

    let ok_rep = [0x05u8, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    client.write_all(&ok_rep).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut stream).await;
    Ok(())
}

async fn dial_through_proxy(
    stream: &mut TcpStream,
    hop: &ChainHop,
    dst_host: &str,
    dst_port: u16,
) -> Result<(), std::io::Error> {
    match hop.scheme {
        HopScheme::Socks5 => {
            if hop.auth_id.is_empty() {
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
            } else {
                stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
            }
            let mut m = [0u8; 2];
            stream.read_exact(&mut m).await?;
            if m[1] == 0x02 {
                let u = hop.auth_id.as_bytes();
                let p = hop.secret.as_bytes();
                let mut auth = Vec::with_capacity(3 + u.len() + p.len());
                auth.push(0x01);
                auth.push(u.len() as u8);
                auth.extend_from_slice(u);
                auth.push(p.len() as u8);
                auth.extend_from_slice(p);
                stream.write_all(&auth).await?;
                let mut ar = [0u8; 2];
                stream.read_exact(&mut ar).await?;
                if ar[1] != 0x00 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "socks5 auth rejected",
                    ));
                }
            }
            let hb = dst_host.as_bytes();
            let mut pkt = Vec::with_capacity(7 + hb.len());
            pkt.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, hb.len() as u8]);
            pkt.extend_from_slice(hb);
            pkt.extend_from_slice(&dst_port.to_be_bytes());
            stream.write_all(&pkt).await?;
            let mut resp = [0u8; 4];
            stream.read_exact(&mut resp).await?;
            if resp[1] != 0x00 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "socks5 upstream connect failed",
                ));
            }
            match resp[3] {
                0x01 => {
                    let mut b = [0u8; 6];
                    stream.read_exact(&mut b).await?;
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    stream.read_exact(&mut l).await?;
                    let mut b = vec![0u8; l[0] as usize + 2];
                    stream.read_exact(&mut b).await?;
                }
                0x04 => {
                    let mut b = [0u8; 18];
                    stream.read_exact(&mut b).await?;
                }
                _ => {}
            }
            Ok(())
        }
        HopScheme::Http => {
            let mut req = format!(
                "CONNECT {dst_host}:{dst_port} HTTP/1.1\r\nHost: {dst_host}:{dst_port}\r\n"
            );
            if !hop.auth_id.is_empty() {
                let creds = format!("{}:{}", hop.auth_id, hop.secret);
                let b64 = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
                req.push_str(&format!("Proxy-Authorization: Basic {b64}\r\n"));
            }
            req.push_str("\r\n");
            stream.write_all(req.as_bytes()).await?;
            let mut buf = Vec::with_capacity(1024);
            let mut byte = [0u8; 1];
            while buf.len() < 8192 {
                stream.read_exact(&mut byte).await?;
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf);
            if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("HTTP CONNECT rejected: {head}"),
                ));
            }
            Ok(())
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported native hop",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vless(ip: &str) -> ChainHop {
        parse_chain_hop(&format!(
            "vless://11111111-2222-3333-4444-555555555555@{ip}:443?security=tls&type=ws#n-{ip}"
        ))
        .unwrap()
    }

    #[test]
    fn flow_supported_country_list_has_151_codes() {
        assert_eq!(FLOW_SUPPORTED_COUNTRIES.len(), 151);
        assert!(is_flow_supported_country("de"));
        assert!(is_flow_supported_country("US"));
        assert!(!is_flow_supported_country("IR"));
        assert!(!is_flow_supported_country("RU"));
        assert!(is_aistudio_supported_country("DE"));
        assert!(!is_aistudio_supported_country("IR"));
    }

    #[test]
    fn parses_trace_and_classifies_reputation() {
        let trace = parse_cloudflare_trace("ip=1.2.3.4\nloc=DE\nwarp=on\ncolo=FRA\n");
        assert!(trace.is_warp());
        assert_eq!(trace.loc.as_deref(), Some("DE"));

        let (r_warp, _) = classify_exit_reputation("Cloudflare", false, false, false, true);
        assert_eq!(r_warp, ExitReputation::WarpOrTor);

        let (r_res, s_res) =
            classify_exit_reputation("Deutsche Telekom AG", false, false, false, false);
        assert_eq!(r_res, ExitReputation::ResidentialIsp);

        let (r_dc, s_dc) =
            classify_exit_reputation("Hetzner Online GmbH", false, true, false, false);
        assert_eq!(r_dc, ExitReputation::DatacenterLowRisk);
        assert!(s_res > s_dc);
    }

    #[test]
    fn builds_four_hop_xray_chain_with_fragment_dialer() {
        let hops = vec![
            sample_vless("5.5.5.5"),
            sample_vless("6.6.6.6"),
            sample_vless("7.7.7.7"),
            sample_vless("8.8.8.8"),
        ];
        let opts = ChainDialOptions {
            socks_port: 10899,
            fragment_dpi: true,
            ..Default::default()
        };
        let cfg_str = build_xray_chain_config(&hops, &opts).unwrap();
        let v: serde_json::Value = serde_json::from_str(&cfg_str).unwrap();
        let outs = v["outbounds"].as_array().unwrap();
        assert_eq!(outs.len(), 5);
        assert_eq!(outs[0]["tag"], "exit");
        assert_eq!(outs[0]["sockopt"]["dialerProxy"], "relay-1");
        assert_eq!(outs[1]["tag"], "relay-1");
        assert_eq!(outs[1]["sockopt"]["dialerProxy"], "relay-2");
        assert_eq!(outs[2]["tag"], "relay-2");
        assert_eq!(outs[2]["sockopt"]["dialerProxy"], "entry");
        assert_eq!(outs[3]["tag"], "entry");
        assert_eq!(outs[3]["sockopt"]["dialerProxy"], "frag-dialer");
        assert_eq!(outs[4]["protocol"], "freedom");
        assert_eq!(outs[4]["settings"]["fragment"]["packets"], "tlshello");
    }

    #[test]
    fn brutal_generator_produces_multi_hop_and_cross_subnet_plans() {
        let cands = vec![
            sample_vless("10.1.1.1"),
            sample_vless("20.2.2.2"),
            sample_vless("30.3.3.3"),
            sample_vless("40.4.4.4"),
        ];
        let local = vec![parse_chain_hop("socks5://127.0.0.1:9050").unwrap()];
        let bandit = ContextualBanditStore::default();
        let plans = generate_brutal_chains(
            &cands,
            &cands,
            &local,
            &bandit,
            ServicePersona::WarriorFlow,
            4,
            40,
        );
        assert!(plans.iter().any(|p| p.fragment_dpi));
        assert!(plans.iter().any(|p| p.hops.len() == 2));
        assert!(plans.iter().any(|p| p.hops.len() >= 3));
        assert!(plans.iter().any(|p| p.stage_label == "stage2-local-bridge"));
    }

    #[test]
    fn evaluators_detect_geoblock_markers_and_shell() {
        assert!(
            !evaluate_lion_response(200, "https://aistudio.google.com/unsupported-country", "").0
        );
        let ai_url = "https://aistudio.google.com/";
        assert!(evaluate_lion_response(200, ai_url, "<html>app</html>").0);
        assert!(
            !evaluate_warrior_response(200, "https://flow.google.com/", "<html>nope</html>", true).0
        );
        assert!(
            evaluate_warrior_response(
                200,
                "https://flow.google.com/",
                "<html>AiSandboxAngularFrontend</html>",
                true
            )
            .0
        );
    }

    #[test]
    fn isolated_blacklists_do_not_bleed_between_lion_and_warrior() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".dastyab"));
        let pid = crate::store::profiles::create_profile("lw-iso", "t").unwrap();
        let ex = "1.2.3.4:443";
        record_blocked_exit(&pid, ServicePersona::WarriorFlow, ex);
        assert!(is_exit_blacklisted(&pid, ServicePersona::WarriorFlow, ex));
        assert!(!is_exit_blacklisted(&pid, ServicePersona::LionAiStudio, ex));
        crate::store::clear_mem_dir_override();
    }

    #[test]
    fn hardened_chrome_args_prevent_dns_and_webrtc_leaks() {
        let args = hardened_chrome_args(
            10860,
            &PathBuf::from("/tmp/p"),
            "https://flow.google.com/",
            Some("DE"),
        );
        let joined = args.join(" ");
        assert!(joined.contains("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"));
        assert!(joined.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"));
        assert!(joined.contains("--lang=de-DE"));
    }

    #[tokio::test]
    async fn native_two_hop_socks5_http_cascade_forwards_payload() {
        // Spawn a dummy target TCP echo/HTTP server.
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let target_task = tokio::spawn(async move {
            if let Ok((mut s, _)) = target_listener.accept().await {
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let _ = s.write_all(&buf[..n]).await;
            }
        });

        // Upstream hop 2: HTTP CONNECT proxy -> target.
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        let http_task = tokio::spawn(async move {
            if let Ok((mut s, _)) = http_listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let hp = first_line.split_whitespace().nth(1).unwrap_or("");
                if let Ok(mut dst) = TcpStream::connect(hp).await {
                    let ok_resp = b"HTTP/1.1 200 Connection Established\r\n\r\n";
                    let _ = s.write_all(ok_resp).await;
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut dst).await;
                }
            }
        });

        // Upstream hop 1: SOCKS5 proxy -> HTTP proxy.
        let inner = start_cascade_socks_proxy(0, Vec::new()).await.unwrap();
        let h1 = parse_chain_hop(&format!("socks5://127.0.0.1:{}", inner.port())).unwrap();
        let h2 = parse_chain_hop(&format!("http://127.0.0.1:{http_port}")).unwrap();
        let outer = start_cascade_socks_proxy(0, vec![h1, h2]).await.unwrap();

        // Connect through outer 2-hop cascade to dummy target.
        let mut client = TcpStream::connect(("127.0.0.1", outer.port())).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut g = [0u8; 2];
        client.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [0x05, 0x00]);
        let host = b"127.0.0.1";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&target_port.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00);

        client.write_all(b"WARRIOR-OK").await.unwrap();
        let mut echo = [0u8; 10];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"WARRIOR-OK");

        drop(outer);
        drop(inner);
        http_task.abort();
        target_task.abort();
    }

    #[test]
    fn parses_npv_ovpn_and_wireguard_config_blobs_into_chains() {
        let embedded_vless = concat!(
            "vless://11111111-1111-1111-1111-111111111111",
            "@203.0.113.44:443?security=tls"
        );
        let mut npv_bytes = b"\x00\x01NPVT\x02".to_vec();
        npv_bytes.extend_from_slice(embedded_vless.as_bytes());
        npv_bytes.extend_from_slice(b"\x00\xff");
        let npv_hops = parse_configs_from_blob("free.npvt", &npv_bytes);
        assert_eq!(npv_hops.len(), 1);
        assert_eq!(npv_hops[0].host, "203.0.113.44");
        assert_eq!(npv_hops[0].param_val("security", ""), "tls");

        let wg_conf = concat!(
            "[Interface]\n",
            "PrivateKey = cHJpdl9rZXlfMDEyMzQ1Njc4OWFiY2RlZg==\n",
            "Address = 10.7.0.2/32\n",
            "MTU = 1280\n",
            "[Peer]\n",
            "PublicKey = cHViX2tleV8wMTIzNDU2Nzg5YWJjZGVm\n",
            "Endpoint = 198.51.100.88:51820\n"
        );
        let wg_hops = parse_configs_from_blob("warp.conf", wg_conf.as_bytes());
        assert_eq!(wg_hops.len(), 1);
        assert_eq!(wg_hops[0].scheme, HopScheme::WireGuard);

        let ovpn = concat!(
            "client\ndev tun\nproto tcp\n",
            "http-proxy 192.0.2.9 8080\nremote 203.0.113.77 1194\n"
        );
        let ovpn_hops = parse_configs_from_blob("exit.ovpn", ovpn.as_bytes());
        let is_http_8080 = |h: &ChainHop| h.scheme == HopScheme::Http && h.port == 8080;
        assert!(ovpn_hops.iter().any(is_http_8080));

        let cands = vec![
            sample_vless("10.1.1.1"),
            sample_vless("20.2.2.2"),
            sample_vless("30.3.3.3"),
            sample_vless("40.4.4.4"),
            sample_vless("50.5.5.5"),
            wg_hops[0].clone(),
        ];
        let local_hop = parse_chain_hop("socks5://127.0.0.1:9050").unwrap();
        assert!(local_hop.auth_id.is_empty());
        assert!(local_hop.is_local_bridge);
        let authed_socks = parse_chain_hop("socks5://alice:bob@192.0.2.1:1080").unwrap();
        assert_eq!(authed_socks.auth_id, "alice");
        assert_eq!(authed_socks.secret, "bob");
        assert!(!authed_socks.is_local_bridge);

        let local = vec![local_hop];
        let plans = generate_brutal_chains(
            &cands,
            &cands,
            &local,
            &ContextualBanditStore::default(),
            ServicePersona::WarriorFlow,
            8,
            80,
        );
        assert!(plans.iter().any(|p| p.hops.len() == 6));
    }
}
