//! Unified censorship-resistant config source manager and latency ranker.
//!
//! Manages four unified source classes per profile (`<profile>/sources.json`):
//! - `github_raw`: GitHub raw URLs with automatic `jsdelivr` and `statically`
//!   CDN mirror fallbacks.
//! - `subscription_url`: arbitrary HTTP/HTTPS subscription endpoints (base64,
//!   Clash YAML, sing-box JSON, or plain URI lists).
//! - `telegram_channel`: public `t.me/s/<channel>` archive feeds.
//! - `telegram_post`: single public `t.me/<channel>/<id>` drop posts.
//!
//! Tracks per-source telemetry (`last_fetch_ts`, `configs_found`,
//! `attempt_count`, `success_count`), supports JSON & plain-text import/export,
//! and provides concurrent TCP/TLS latency ranking of harvested share-links.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures_util::stream::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::CFError;
use crate::net::proxy_uri::ProxyUri;
use crate::store::profiles::{now_ts, profile_dir};
use crate::store::{read_opt, write_json};

const MAX_SOURCE_BODY_BYTES: usize = 8 * 1024 * 1024;
const SOURCE_FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// Source category managed in the unified source store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    GithubRaw,
    SubscriptionUrl,
    TelegramChannel,
    TelegramPost,
}

impl SourceKind {
    /// Canonical lowercase wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::GithubRaw => "github_raw",
            SourceKind::SubscriptionUrl => "subscription_url",
            SourceKind::TelegramChannel => "telegram_channel",
            SourceKind::TelegramPost => "telegram_post",
        }
    }

    /// Parse a user/CLI source kind token (e.g. `github_raw`, `sub`, `tg`, `post`).
    pub fn from_token(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "github_raw" | "github" | "gh" | "raw" => Some(Self::GithubRaw),
            "subscription_url" | "subscription" | "sub" | "url" => Some(Self::SubscriptionUrl),
            "telegram_channel" | "telegram" | "tg" | "channel" => Some(Self::TelegramChannel),
            "telegram_post" | "post" | "tg_post" => Some(Self::TelegramPost),
            _ => None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Persistent entry in `<profile>/sources.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HarvestSource {
    pub id: String,
    pub name: String,
    pub kind: SourceKind,
    pub value: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub last_fetch_ts: u64,
    #[serde(default)]
    pub configs_found: usize,
    #[serde(default)]
    pub attempt_count: u64,
    #[serde(default)]
    pub success_count: u64,
}

impl HarvestSource {
    /// Fetch success percentage `[0..=100]` across all recorded attempts.
    pub fn success_rate(&self) -> u8 {
        if self.attempt_count == 0 {
            return 0;
        }
        ((self.success_count.saturating_mul(100)) / self.attempt_count).min(100) as u8
    }
}

/// Summary of importing sources from JSON or plain-text lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceImportSummary {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
    pub total: usize,
}

/// Reachable share-link with measured TCP/TLS latency.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TestedLink {
    pub uri: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub latency_ms: u64,
    pub tls_verified: bool,
}

/// Aggregate result of harvesting enabled unified sources.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UnifiedHarvestReport {
    pub sources_attempted: usize,
    pub sources_ok: usize,
    pub raw_links_found: usize,
    pub filtered_links: usize,
    pub links: Vec<String>,
    pub tested: Vec<TestedLink>,
    pub added: usize,
    pub duplicates: usize,
    pub errors: Vec<(String, String)>,
}

const DEFAULT_GITHUB_RAW_SOURCES: &[(&str, &str)] = &[
    (
        "barry-far V2ray-Configs (VLESS)",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    ),
    (
        "barry-far V2ray-Configs (All)",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    ),
    (
        "Epodonios v2ray-configs (VLESS)",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    ),
    (
        "Epodonios v2ray-configs (All)",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    ),
    (
        "MahsaNetConfigTopic (Xray Final)",
        "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/main/xray_final.txt",
    ),
    (
        "yebekhe TVC (VLESS)",
        "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
    ),
    (
        "yebekhe TVC (Mix Base64)",
        "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix",
    ),
    (
        "yebekhe TelegramV2rayCollector (Mix)",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    ),
    (
        "soroushmirzaei collector (VLESS)",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    ),
    (
        "soroushmirzaei collector (Hysteria)",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria",
    ),
    (
        "soroushmirzaei collector (TUIC)",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/tuic",
    ),
    (
        "NiREvil vless (Sub)",
        "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime",
    ),
    (
        "MrMohebi xray-proxy-grabber",
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-v2ray-config/master/CollectedConfigs.txt",
    ),
    (
        "SoliSpirit v2ray-configs",
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    ),
    (
        "Danialsamadi v2go",
        "https://raw.githubusercontent.com/Danialsamadi/v2go/main/All_Configs_Sub.txt",
    ),
    (
        "peasoft NoMoreWalls",
        "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    ),
    (
        "mfuu v2ray",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    ),
    (
        "mahdibland V2RayAggregator",
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    ),
];

const EXTRA_TELEGRAM_CHANNELS: &[&str] = &[
    "v2rayng_org",
    "PrivateVPNs",
    "DirectVPN",
    "vless_vmess",
    "v2ray_outlineir",
    "V2rayNGn",
    "outline_vpn",
    "VlessConfig",
    "FreeV2rays",
    "v2ray_saz",
    "meli_proxyy",
    "V2RayRoot",
    "ShadowSocks_s",
    "v2rayng_vpnrog",
    "iranproxy98",
    "Warp_ir",
    "v2ray_free_conf",
];

/// Compute the deterministic source ID (`<kind>:<lowercased value>`).
pub fn make_source_id(kind: SourceKind, value: &str) -> String {
    format!("{}:{}", kind.as_str(), value.trim().to_ascii_lowercase())
}

/// Built-in expanded list of GitHub raw feeds and Telegram public channels.
pub fn default_sources() -> Vec<HarvestSource> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for &(name, url) in DEFAULT_GITHUB_RAW_SOURCES {
        let id = make_source_id(SourceKind::GithubRaw, url);
        if seen.insert(id.clone()) {
            out.push(HarvestSource {
                id,
                name: name.to_string(),
                kind: SourceKind::GithubRaw,
                value: url.to_string(),
                enabled: true,
                is_default: true,
                last_fetch_ts: 0,
                configs_found: 0,
                attempt_count: 0,
                success_count: 0,
            });
        }
    }

    for ch in crate::discovery::harvest::DISCOVER_CANDIDATE_CHANNELS
        .iter()
        .copied()
        .chain(EXTRA_TELEGRAM_CHANNELS.iter().copied())
    {
        let clean = ch.trim().trim_start_matches('@');
        if clean.is_empty() {
            continue;
        }
        let id = make_source_id(SourceKind::TelegramChannel, clean);
        if seen.insert(id.clone()) {
            out.push(HarvestSource {
                id,
                name: format!("@{clean}"),
                kind: SourceKind::TelegramChannel,
                value: clean.to_string(),
                enabled: true,
                is_default: true,
                last_fetch_ts: 0,
                configs_found: 0,
                attempt_count: 0,
                success_count: 0,
            });
        }
    }

    out
}

/// Convert a standard GitHub `blob` page URL to `raw.githubusercontent.com` when applicable.
pub fn normalize_github_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    if !(s.starts_with("http://") || s.starts_with("https://")) || s.contains(char::is_whitespace) {
        return None;
    }
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))?;
    let mut parts = rest.splitn(6, '/');
    let host = parts.next()?.to_ascii_lowercase();
    if host == "github.com" || host == "www.github.com" {
        let owner = parts.next()?;
        let repo = parts.next()?;
        let blob = parts.next()?;
        let branch = parts.next()?;
        let path = parts.next()?;
        if blob.eq_ignore_ascii_case("blob")
            && !owner.is_empty()
            && !repo.is_empty()
            && !branch.is_empty()
            && !path.is_empty()
        {
            return Some(format!(
                "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
            ));
        }
    }
    Some(s.to_string())
}

/// Validate and normalize a generic HTTP/HTTPS subscription URL.
pub fn normalize_subscription_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    if !(s.starts_with("http://") || s.starts_with("https://")) || s.contains(char::is_whitespace) {
        return None;
    }
    let after = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))?;
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || (!host.contains('.') && host != "localhost" && !host.starts_with("127."))
    {
        return None;
    }
    Some(s.to_string())
}

/// Normalize a Telegram public channel reference (`@chan`, `t.me/chan`, `t.me/s/chan`).
pub fn normalize_telegram_channel(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.contains(char::is_whitespace) {
        return None;
    }
    let handle = if let Some(idx) = s.to_ascii_lowercase().find("t.me/") {
        let tail = &s[idx + "t.me/".len()..];
        let tail = tail.strip_prefix("s/").unwrap_or(tail);
        tail.split(['/', '?', '#']).next().unwrap_or("")
    } else if let Some(idx) = s.to_ascii_lowercase().find("telegram.me/") {
        let tail = &s[idx + "telegram.me/".len()..];
        let tail = tail.strip_prefix("s/").unwrap_or(tail);
        tail.split(['/', '?', '#']).next().unwrap_or("")
    } else if !s.contains("://") && !s.contains('/') {
        s.trim_start_matches('@')
    } else {
        return None;
    };

    let clean = handle.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
    if clean.len() < 3
        || matches!(
            clean.to_ascii_lowercase().as_str(),
            "s" | "proxy" | "joinchat" | "share"
        )
        || !clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(clean.to_string())
}

/// Normalize a single Telegram post URL (`t.me/<channel>/<post_id>` -> `(channel, post_id)`).
pub fn normalize_telegram_post(raw: &str) -> Option<(String, u64)> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    let tail = if let Some(idx) = lower.find("t.me/") {
        &s[idx + "t.me/".len()..]
    } else {
        let idx = lower.find("telegram.me/")?;
        &s[idx + "telegram.me/".len()..]
    };
    let tail = tail.strip_prefix("s/").unwrap_or(tail);
    let clean_path = tail.split(['?', '#']).next().unwrap_or("");
    let mut parts = clean_path.split('/').filter(|p| !p.is_empty());
    let chan = parts.next()?.trim_start_matches('@');
    let post_str = parts.next()?;
    let post_id = post_str.parse::<u64>().ok()?;
    if post_id == 0
        || chan.len() < 3
        || !chan.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some((chan.to_string(), post_id))
}

/// Classify arbitrary user input into `(SourceKind, normalized_value, default_label)`.
pub fn classify_source_input(
    raw: &str,
    explicit_kind: Option<SourceKind>,
) -> Option<(SourceKind, String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    if let Some(kind) = explicit_kind {
        return match kind {
            SourceKind::GithubRaw => {
                let norm = normalize_github_url(trimmed)?;
                let label = norm.rsplit('/').next().unwrap_or("github").to_string();
                Some((kind, norm, label))
            }
            SourceKind::SubscriptionUrl => {
                let norm = normalize_subscription_url(trimmed)?;
                let label = norm
                    .split("://")
                    .nth(1)
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("subscription")
                    .to_string();
                Some((kind, norm, label))
            }
            SourceKind::TelegramChannel => {
                let ch = normalize_telegram_channel(trimmed)?;
                let label = format!("@{ch}");
                Some((kind, ch, label))
            }
            SourceKind::TelegramPost => {
                let (ch, id) = normalize_telegram_post(trimmed)?;
                let val = format!("https://t.me/{ch}/{id}");
                let label = format!("@{ch}/{id}");
                Some((kind, val, label))
            }
        };
    }

    if let Some((ch, id)) = normalize_telegram_post(trimmed) {
        return Some((
            SourceKind::TelegramPost,
            format!("https://t.me/{ch}/{id}"),
            format!("@{ch}/{id}"),
        ));
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        if lower.contains("t.me/") || lower.contains("telegram.me/") {
            let ch = normalize_telegram_channel(trimmed)?;
            return Some((SourceKind::TelegramChannel, ch.clone(), format!("@{ch}")));
        }
        if lower.contains("raw.githubusercontent.com")
            || lower.contains("cdn.jsdelivr.net/gh/")
            || lower.contains("cdn.statically.io/gh/")
            || (lower.contains("github.com/") && lower.contains("/blob/"))
        {
            let norm = normalize_github_url(trimmed)?;
            let label = norm.rsplit('/').next().unwrap_or("github").to_string();
            return Some((SourceKind::GithubRaw, norm, label));
        }
        let norm = normalize_subscription_url(trimmed)?;
        let label = norm
            .split("://")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .unwrap_or("subscription")
            .to_string();
        return Some((SourceKind::SubscriptionUrl, norm, label));
    }

    let ch = normalize_telegram_channel(trimmed)?;
    Some((SourceKind::TelegramChannel, ch.clone(), format!("@{ch}")))
}

/// Build direct + CDN mirror URLs (`raw.githubusercontent`, `jsdelivr`, `statically`)
/// for a GitHub raw file URL. Non-GitHub URLs are returned as a single-item vector.
pub fn mirror_urls_for_raw(raw_url: &str) -> Vec<String> {
    let norm = normalize_github_url(raw_url).unwrap_or_else(|| raw_url.trim().to_string());
    let mut out = vec![norm.clone()];
    if let Some(after) = norm
        .strip_prefix("https://raw.githubusercontent.com/")
        .or_else(|| norm.strip_prefix("http://raw.githubusercontent.com/"))
    {
        let mut parts = after.splitn(4, '/');
        if let (Some(owner), Some(repo), Some(branch), Some(path)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        {
            if !owner.is_empty() && !repo.is_empty() && !branch.is_empty() && !path.is_empty() {
                out.push(format!(
                    "https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"
                ));
                out.push(format!(
                    "https://cdn.statically.io/gh/{owner}/{repo}/{branch}/{path}"
                ));
            }
        }
    }
    out
}

/// Path to the profile's unified source list (`<profile>/sources.json`).
pub fn sources_path(profile: &str) -> PathBuf {
    profile_dir(profile).join("sources.json")
}

/// Load unified sources for a profile, falling back to [`default_sources`] if
/// no `sources.json` exists yet.
pub fn load_sources(profile: &str) -> Vec<HarvestSource> {
    let path = sources_path(profile);
    if !path.is_file() {
        return default_sources();
    }
    match read_opt::<Vec<HarvestSource>>(&path) {
        Some(list) if !list.is_empty() => list,
        Some(_) => Vec::new(),
        None => default_sources(),
    }
}

/// Persist the unified source list atomically.
pub fn save_sources(profile: &str, sources: &[HarvestSource]) -> Result<(), CFError> {
    write_json(&sources_path(profile), &sources)
}

/// Add or update a source entry by URL, channel handle, or post link.
pub fn add_source(
    profile: &str,
    explicit_kind: Option<SourceKind>,
    input: &str,
    name: Option<&str>,
) -> Result<HarvestSource, CFError> {
    let (kind, value, default_name) =
        classify_source_input(input, explicit_kind).ok_or_else(|| {
            CFError::new(
            "sources",
            format!("unrecognized source '{input}'"),
            "Provide a GitHub URL, HTTP/HTTPS subscription URL, @channel, or t.me/ch/id post link.",
        )
        })?;
    let label = name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or(default_name);
    let id = make_source_id(kind, &value);
    let mut list = load_sources(profile);
    if let Some(existing) = list.iter_mut().find(|s| s.id == id) {
        existing.name = label;
        existing.enabled = true;
        let updated = existing.clone();
        save_sources(profile, &list)?;
        return Ok(updated);
    }
    let src = HarvestSource {
        id,
        name: label,
        kind,
        value,
        enabled: true,
        is_default: false,
        last_fetch_ts: 0,
        configs_found: 0,
        attempt_count: 0,
        success_count: 0,
    };
    list.push(src.clone());
    save_sources(profile, &list)?;
    Ok(src)
}

fn matches_source_query(src: &HarvestSource, query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() {
        return false;
    }
    let q_no_at = q.trim_start_matches('@');
    src.id.eq_ignore_ascii_case(q)
        || src.value.eq_ignore_ascii_case(q)
        || src.value.eq_ignore_ascii_case(q_no_at)
        || src.name.eq_ignore_ascii_case(q)
}

/// Remove a source by id, value, or display name. Returns `true` if removed.
pub fn remove_source(profile: &str, query: &str) -> Result<bool, CFError> {
    let mut list = load_sources(profile);
    let before = list.len();
    list.retain(|s| !matches_source_query(s, query));
    let removed = list.len() != before;
    if removed {
        save_sources(profile, &list)?;
    }
    Ok(removed)
}

/// Enable or disable a source by id, value, or display name. Returns `true` if matched.
pub fn set_source_enabled(profile: &str, query: &str, enabled: bool) -> Result<bool, CFError> {
    let mut list = load_sources(profile);
    let mut changed = false;
    for s in &mut list {
        if matches_source_query(s, query) {
            s.enabled = enabled;
            changed = true;
        }
    }
    if changed {
        save_sources(profile, &list)?;
    }
    Ok(changed)
}

/// Reset a profile's source list back to [`default_sources`].
pub fn reset_sources(profile: &str) -> Result<Vec<HarvestSource>, CFError> {
    let defs = default_sources();
    save_sources(profile, &defs)?;
    Ok(defs)
}

/// Export the profile's source list as pretty JSON or line-separated text.
pub fn export_sources(profile: &str, format: &str) -> Result<String, CFError> {
    let list = load_sources(profile);
    match format.trim().to_ascii_lowercase().as_str() {
        "" | "json" => serde_json::to_string_pretty(&list).map_err(|e| {
            CFError::new(
                "sources",
                format!("cannot serialize sources JSON: {e}"),
                "Internal error.",
            )
        }),
        "text" | "txt" => {
            let lines: Vec<String> = list
                .iter()
                .map(|s| {
                    if s.kind == SourceKind::TelegramChannel {
                        format!("https://t.me/s/{}", s.value)
                    } else {
                        s.value.clone()
                    }
                })
                .collect();
            Ok(lines.join("\n"))
        }
        other => Err(CFError::new(
            "sources",
            format!("unsupported export format '{other}'"),
            "Use 'json' or 'text'.",
        )),
    }
}

/// Import sources from JSON array or newline-separated text into `profile`.
pub fn import_sources(
    profile: &str,
    raw: &str,
    format: &str,
    replace: bool,
) -> Result<SourceImportSummary, CFError> {
    let trimmed = raw.trim();
    let use_json = match format.trim().to_ascii_lowercase().as_str() {
        "json" => true,
        "text" | "txt" => false,
        "" | "auto" => trimmed.starts_with('['),
        other => {
            return Err(CFError::new(
                "sources",
                format!("unsupported import format '{other}'"),
                "Use 'json', 'text', or 'auto'.",
            ));
        }
    };

    let mut current = if replace {
        Vec::new()
    } else {
        load_sources(profile)
    };
    let mut by_id: HashMap<String, usize> = current
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.clone(), i))
        .collect();
    let mut summary = SourceImportSummary::default();

    if use_json {
        let parsed: Vec<HarvestSource> = serde_json::from_str(trimmed).map_err(|e| {
            CFError::new(
                "sources",
                format!("invalid sources JSON: {e}"),
                "Check the JSON array structure.",
            )
        })?;
        for mut item in parsed {
            if item.id.trim().is_empty() {
                item.id = make_source_id(item.kind, &item.value);
            }
            if let Some(&idx) = by_id.get(&item.id) {
                current[idx].name = item.name;
                current[idx].enabled = item.enabled;
                summary.updated += 1;
            } else {
                by_id.insert(item.id.clone(), current.len());
                current.push(item);
                summary.added += 1;
            }
        }
    } else {
        for line in trimmed.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((kind, value, name)) = classify_source_input(line, None) else {
                summary.skipped += 1;
                continue;
            };
            let id = make_source_id(kind, &value);
            if let Some(&idx) = by_id.get(&id) {
                current[idx].enabled = true;
                summary.updated += 1;
            } else {
                by_id.insert(id.clone(), current.len());
                current.push(HarvestSource {
                    id,
                    name,
                    kind,
                    value,
                    enabled: true,
                    is_default: false,
                    last_fetch_ts: 0,
                    configs_found: 0,
                    attempt_count: 0,
                    success_count: 0,
                });
                summary.added += 1;
            }
        }
    }

    summary.total = current.len();
    save_sources(profile, &current)?;
    Ok(summary)
}

async fn fetch_body_urls(client: &reqwest::Client, urls: &[String]) -> Result<Vec<u8>, String> {
    let mut last_err = String::new();
    for url in urls {
        let resp = match client.get(url).timeout(SOURCE_FETCH_TIMEOUT).send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };
        if resp.status().as_u16() != 200 {
            last_err = format!("HTTP {}", resp.status());
            continue;
        }
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };
        if bytes.is_empty() {
            last_err = "empty response".to_string();
            continue;
        }
        if bytes.len() > MAX_SOURCE_BODY_BYTES {
            last_err = "response exceeded max size".to_string();
            continue;
        }
        return Ok(bytes.to_vec());
    }
    if last_err.is_empty() {
        last_err = "no candidate URL succeeded".to_string();
    }
    Err(last_err)
}

async fn fetch_single_source(
    client: &reqwest::Client,
    src: &HarvestSource,
    depth: usize,
) -> Result<Vec<String>, String> {
    match src.kind {
        SourceKind::GithubRaw => {
            let urls = mirror_urls_for_raw(&src.value);
            let bytes = fetch_body_urls(client, &urls).await?;
            let links = crate::tunnel::lion_warrior::extract_all_config_links_from_blob(
                "source.txt",
                &bytes,
            );
            Ok(links)
        }
        SourceKind::SubscriptionUrl => {
            let bytes = fetch_body_urls(client, std::slice::from_ref(&src.value)).await?;
            let links = crate::tunnel::lion_warrior::extract_all_config_links_from_blob(
                "subscription.txt",
                &bytes,
            );
            Ok(links)
        }
        SourceKind::TelegramChannel => {
            crate::discovery::harvest::fetch_channel_links_depth_async(client, &src.value, depth)
                .await
                .map_err(|e| e.brief())
        }
        SourceKind::TelegramPost => {
            let Some((ch, post_id)) = normalize_telegram_post(&src.value) else {
                return Err("invalid telegram post URL".to_string());
            };
            crate::discovery::harvest::fetch_post_links_async(client, &ch, post_id)
                .await
                .map_err(|e| e.brief())
        }
    }
}

fn extract_sni_for_tls_probe(parsed: &ProxyUri) -> Option<String> {
    let canon = parsed.canonical_scheme();
    if !matches!(
        canon,
        "vless" | "trojan" | "anytls" | "naive+https" | "naive" | "https"
    ) {
        return None;
    }
    let query = parsed
        .raw
        .split('?')
        .nth(1)
        .and_then(|q| q.split('#').next())
        .unwrap_or("");
    let mut security = String::new();
    let mut sni = String::new();
    let mut host_header = String::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = crate::artifact::vless::decode_query(v.trim());
            match key.as_str() {
                "security" => security = val.to_ascii_lowercase(),
                "sni" | "peer" if sni.is_empty() => sni = val,
                "host" if host_header.is_empty() => host_header = val,
                _ => {}
            }
        }
    }
    if canon == "vless" && !security.is_empty() && security != "tls" && security != "reality" {
        return None;
    }
    if !sni.is_empty() {
        Some(sni)
    } else if !host_header.is_empty() {
        Some(host_header)
    } else {
        Some(parsed.host.clone())
    }
}

async fn probe_single_link(link: String, timeout_ms: u64) -> Option<TestedLink> {
    let parsed = ProxyUri::parse(&link)?;
    if parsed.host.is_empty() || parsed.port == 0 {
        return None;
    }
    let dur = Duration::from_millis(timeout_ms.max(200));
    let start = Instant::now();
    let addr = (parsed.host.as_str(), parsed.port);
    let mut stream = tokio::time::timeout(dur, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let tcp_ms = start.elapsed().as_millis() as u64;

    let mut tls_verified = false;
    let mut final_ms = tcp_ms;
    if let Some(sni) = extract_sni_for_tls_probe(&parsed) {
        let hello = crate::probe::node_probe::build_client_hello(&sni);
        let tls_fut = async {
            stream.write_all(&hello).await.ok()?;
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.ok()?;
            if n > 0 && matches!(buf[0], 0x16 | 0x15) {
                Some(())
            } else {
                None
            }
        };
        if tokio::time::timeout(dur, tls_fut)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            tls_verified = true;
            final_ms = start.elapsed().as_millis() as u64;
        }
    }

    Some(TestedLink {
        uri: link,
        protocol: parsed.canonical_scheme().to_string(),
        host: parsed.host,
        port: parsed.port,
        latency_ms: final_ms.max(1),
        tls_verified,
    })
}

/// Concurrently test TCP/TLS reachability for share-links and return reachable
/// entries sorted fastest-first (breaking latency ties in favor of TLS-verified).
pub async fn test_links_latency(
    links: &[String],
    timeout_ms: u64,
    concurrency: usize,
) -> Vec<TestedLink> {
    let conc = concurrency.clamp(1, 48);
    let mut out: Vec<TestedLink> = futures_util::stream::iter(links.iter().cloned())
        .map(|link| probe_single_link(link, timeout_ms))
        .buffer_unordered(conc)
        .filter_map(|opt| async move { opt })
        .collect()
        .await;
    out.sort_by(|a, b| {
        a.latency_ms
            .cmp(&b.latency_ms)
            .then_with(|| b.tls_verified.cmp(&a.tls_verified))
    });
    out
}

/// Harvest all enabled unified sources for `profile`, update telemetry,
/// deduplicate, apply optional `protocol_filter`, optionally TCP/TLS latency-test
/// (`run_latency_test`), and import surviving configs into `config_store`.
pub async fn harvest_enabled_sources(
    profile: &str,
    use_proxy: bool,
    depth: usize,
    protocol_filter: &str,
    run_latency_test: bool,
    import_to_store: bool,
) -> Result<UnifiedHarvestReport, CFError> {
    let client = crate::discovery::harvest::build_client(use_proxy)?;
    let mut all_sources = load_sources(profile);
    let enabled_indices: Vec<usize> = all_sources
        .iter()
        .enumerate()
        .filter(|(_, s)| s.enabled)
        .map(|(i, _)| i)
        .collect();

    let mut report = UnifiedHarvestReport {
        sources_attempted: enabled_indices.len(),
        ..Default::default()
    };

    let jobs: Vec<(usize, HarvestSource)> = enabled_indices
        .iter()
        .map(|&i| (i, all_sources[i].clone()))
        .collect();

    let results: Vec<(usize, Result<Vec<String>, String>)> = futures_util::stream::iter(jobs)
        .map(|(idx, src)| {
            let client = client.clone();
            async move {
                let res = fetch_single_source(&client, &src, depth).await;
                (idx, res)
            }
        })
        .buffer_unordered(8)
        .collect()
        .await;

    let ts_now = now_ts() as u64;
    let mut raw_links: Vec<String> = Vec::new();
    for (idx, res) in results {
        let src = &mut all_sources[idx];
        src.attempt_count = src.attempt_count.saturating_add(1);
        src.last_fetch_ts = ts_now;
        match res {
            Ok(links) => {
                src.success_count = src.success_count.saturating_add(1);
                src.configs_found = links.len();
                report.sources_ok += 1;
                raw_links.extend(links);
            }
            Err(err) => {
                report.errors.push((src.name.clone(), err));
            }
        }
    }
    let _ = save_sources(profile, &all_sources);

    let deduped = crate::net::proxy_uri::deduplicate_links(&raw_links);
    report.raw_links_found = deduped.len();

    let filtered = crate::discovery::harvest::filter_links_by_protocol(&deduped, protocol_filter);
    report.filtered_links = filtered.len();

    let final_links = if run_latency_test {
        let tested = test_links_latency(&filtered, 3000, 24).await;
        let uris: Vec<String> = tested.iter().map(|t| t.uri.clone()).collect();
        report.tested = tested;
        uris
    } else {
        filtered
    };

    if import_to_store && !final_links.is_empty() {
        let summary = crate::artifact::config_store::import_links_bulk_source(
            profile,
            &final_links,
            "sources",
        )?;
        report.added = summary.added;
        report.duplicates = summary.duplicates;
    }
    report.links = final_links;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemDirGuard;

    impl MemDirGuard {
        fn new(dir: &tempfile::TempDir) -> Self {
            crate::store::set_mem_dir_override(dir.path().join("mem"));
            Self
        }
    }

    impl Drop for MemDirGuard {
        fn drop(&mut self) {
            crate::store::clear_mem_dir_override();
        }
    }

    #[test]
    fn default_sources_are_unique_and_cover_github_and_telegram() {
        let defs = default_sources();
        assert!(defs.len() >= 60);
        let mut ids = HashSet::new();
        for s in &defs {
            assert!(ids.insert(s.id.clone()), "duplicate default id: {}", s.id);
        }
        assert!(defs.iter().any(|s| s.kind == SourceKind::GithubRaw));
        assert!(defs.iter().any(|s| s.kind == SourceKind::TelegramChannel));
    }

    #[test]
    fn classifies_all_four_source_types_and_builds_mirrors() {
        let gh = classify_source_input(
            "https://github.com/barry-far/V2ray-Configs/blob/main/All_Configs_Sub.txt",
            None,
        )
        .unwrap();
        assert_eq!(gh.0, SourceKind::GithubRaw);
        assert_eq!(
            gh.1,
            "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"
        );
        let mirrors = mirror_urls_for_raw(&gh.1);
        assert_eq!(mirrors.len(), 3);
        assert!(mirrors[1].starts_with("https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/"));
        assert!(
            mirrors[2].starts_with("https://cdn.statically.io/gh/barry-far/V2ray-Configs/main/")
        );

        let sub = classify_source_input("https://example.org/sub/abc123", None).unwrap();
        assert_eq!(sub.0, SourceKind::SubscriptionUrl);

        let tg = classify_source_input("https://t.me/s/v2ray_config", None).unwrap();
        assert_eq!(tg.0, SourceKind::TelegramChannel);
        assert_eq!(tg.1, "v2ray_config");

        let post = classify_source_input("https://t.me/v2ray_config/425?embed=1", None).unwrap();
        assert_eq!(post.0, SourceKind::TelegramPost);
        assert_eq!(post.1, "https://t.me/v2ray_config/425");
    }

    #[test]
    fn source_crud_and_import_export_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = MemDirGuard::new(&tmp);
        let profile = "default";

        let added =
            add_source(profile, None, "https://example.org/feed.txt", Some("MySub")).unwrap();
        assert_eq!(added.kind, SourceKind::SubscriptionUrl);
        assert!(load_sources(profile).iter().any(|s| s.id == added.id));

        assert!(set_source_enabled(profile, &added.id, false).unwrap());
        let disabled = load_sources(profile)
            .into_iter()
            .find(|s| s.id == added.id)
            .unwrap();
        assert!(!disabled.enabled);

        let exported_json = export_sources(profile, "json").unwrap();
        let exported_txt = export_sources(profile, "text").unwrap();
        assert!(exported_txt.contains("https://example.org/feed.txt"));

        assert!(remove_source(profile, &added.id).unwrap());
        assert!(!load_sources(profile).iter().any(|s| s.id == added.id));

        let imp = import_sources(profile, &exported_json, "json", true).unwrap();
        assert!(imp.added >= 60);
        assert!(load_sources(profile).iter().any(|s| s.id == added.id));

        let reset = reset_sources(profile).unwrap();
        assert!(!reset.iter().any(|s| s.id == added.id));
    }

    #[tokio::test]
    async fn test_links_latency_keeps_reachable_sorted_and_drops_dead_ports() {
        let listener_fast = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fast_port = listener_fast.local_addr().unwrap().port();
        let accept_task = tokio::spawn(async move {
            let _ = listener_fast.accept().await;
        });

        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead_listener.local_addr().unwrap().port();
        drop(dead_listener);

        let fast_uri = format!(
            "vless://06ef598c-1555-4887-b3f9-08214a2f6792@127.0.0.1:{fast_port}?security=none#fast"
        );
        let dead_uri = format!(
            "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{dead_port}?security=none#dead"
        );
        let tested = test_links_latency(&[dead_uri, fast_uri.clone()], 800, 4).await;
        accept_task.abort();

        assert_eq!(tested.len(), 1);
        assert_eq!(tested[0].uri, fast_uri);
        assert_eq!(tested[0].port, fast_port);
        assert!(tested[0].latency_ms >= 1);
    }
}
