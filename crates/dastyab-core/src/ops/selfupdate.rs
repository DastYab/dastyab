//! Self-update support for DastYab across all editions and platforms.
//!
//! Checks `https://github.com/DastYab/dastyab/releases/latest` (via the GitHub
//! REST API with an automatic web-redirect fallback and optional local SOCKS5
//! proxy fallback), compares the release tag against the installed version,
//! selects the matching platform + edition binary (`dastyab`, `dastyab-gui`, or
//! `dastyab-tui`), verifies its SHA-256 digest against `SHA256SUMS.txt` plus
//! native executable header magic, and atomically swaps it in place (including
//! safe `.old` rename/rollback on Windows and user-dir staging fallback when
//! installed in a read-only system path).

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CFError;
use crate::store::{atomic_write, mem_dir, now_ts, read_or_default};
use crate::tunnel::multilayer::PROXY_SOCKS_PORT;

/// GitHub repo owner.
pub const OWNER: &str = "DastYab";
/// GitHub repo name.
pub const REPO: &str = "dastyab";
/// GitHub API base.
pub const GITHUB_API: &str = "https://api.github.com";

/// How often the daemon checks for an auto-update (seconds). 24h.
pub const AUTO_UPDATE_INTERVAL_SECS: u64 = 86400;

/// How often interactive clients (CLI/GUI/TUI) background-check for an
/// auto-update (seconds). 1h.
pub const INTERACTIVE_CHECK_INTERVAL_SECS: u64 = 3600;

const RELEASE_LATEST: &str = "https://api.github.com/repos/DastYab/dastyab/releases/latest";

/// Public web latest-release endpoint (redirects to `/releases/tag/vX.Y.Z`).
pub const RELEASE_LATEST_WEB: &str = "https://github.com/DastYab/dastyab/releases/latest";

/// Which DastYab binary edition is updating itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryKind {
    Cli,
    Gui,
    Tui,
}

impl BinaryKind {
    /// Detect which edition is currently running from `std::env::current_exe()`.
    pub fn detect_current() -> Self {
        let exe = std::env::current_exe().ok();
        let fname = exe.as_deref().and_then(Path::file_name);
        let name = fname
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self::detect_from_exe_name(&name)
    }

    /// Detect the edition from an executable filename or stem.
    pub fn detect_from_exe_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if lower.contains("gui") {
            Self::Gui
        } else if lower.contains("tui") {
            Self::Tui
        } else {
            Self::Cli
        }
    }

    /// Release asset filename prefix for this edition.
    pub fn asset_prefix(self) -> &'static str {
        match self {
            Self::Cli => "dastyab",
            Self::Gui => "dastyab-gui",
            Self::Tui => "dastyab-tui",
        }
    }

    /// Human-readable edition label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Cli => "CLI",
            Self::Gui => "GUI",
            Self::Tui => "TUI",
        }
    }
}

/// Version metadata parsed from a release tag.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub tag: String,
    pub version: (u32, u32, u32),
    pub assets: Vec<ReleaseAsset>,
}

/// A named binary or checksum asset attached to a release.
#[derive(Debug, Clone)]
pub struct ReleaseAsset {
    pub name: String,
    /// Public download URL (GitHub CDN; may be redirected/blocked on some networks).
    pub url: String,
    /// API asset endpoint (`api.github.com`) — more reliable on restricted networks.
    pub api_url: String,
}

/// Persisted auto-update preference & check cadence state (`~/.dastyab/selfupdate.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfUpdatePrefs {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub last_check_ts: u64,
    #[serde(default)]
    pub last_seen_tag: Option<String>,
    #[serde(default)]
    pub last_applied_tag: Option<String>,
    #[serde(default)]
    pub last_note: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for SelfUpdatePrefs {
    fn default() -> Self {
        Self {
            enabled: true,
            last_check_ts: 0,
            last_seen_tag: None,
            last_applied_tag: None,
            last_note: None,
        }
    }
}

/// Path to the global auto-update preference/state file.
pub fn auto_update_prefs_path() -> PathBuf {
    mem_dir().join("selfupdate.json")
}

/// Load auto-update preferences/state (defaults to `enabled: true`).
pub fn load_auto_update_prefs() -> SelfUpdatePrefs {
    read_or_default(&auto_update_prefs_path())
}

fn upd_err(detail: impl Into<String>, hint: &str) -> CFError {
    CFError::new("Updater error", detail, hint)
}

/// Persist auto-update preferences/state atomically.
pub fn save_auto_update_prefs(prefs: &SelfUpdatePrefs) -> Result<(), CFError> {
    let bytes = match serde_json::to_vec_pretty(prefs) {
        Ok(b) => b,
        Err(e) => {
            let detail = format!("Cannot serialize selfupdate prefs: {e}");
            return Err(CFError::new("Storage error", detail, "Internal error."));
        }
    };
    atomic_write(&auto_update_prefs_path(), &bytes)
}

/// Whether automatic startup/background updates are enabled.
///
/// Honors `DASTYAB_NO_AUTO_UPDATE=1` as a runtime opt-out for scripts/CI.
pub fn auto_update_enabled() -> bool {
    if matches!(
        std::env::var("DASTYAB_NO_AUTO_UPDATE").ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes")
    ) {
        return false;
    }
    load_auto_update_prefs().enabled
}

/// Enable or disable automatic updates in user prefs.
pub fn set_auto_update_enabled(enabled: bool) -> Result<(), CFError> {
    let mut prefs = load_auto_update_prefs();
    prefs.enabled = enabled;
    save_auto_update_prefs(&prefs)
}

/// Pure helper checking whether an auto-update check is due at `now`.
pub fn check_throttle_due(prefs: &SelfUpdatePrefs, now: u64, interval_secs: u64) -> bool {
    if !prefs.enabled {
        return false;
    }
    prefs.last_check_ts == 0 || now.saturating_sub(prefs.last_check_ts) >= interval_secs
}

/// Whether an automatic background update check is due right now.
pub fn should_auto_check(interval_secs: u64) -> bool {
    if !auto_update_enabled() {
        return false;
    }
    let prefs = load_auto_update_prefs();
    let now = now_ts().max(0.0) as u64;
    check_throttle_due(&prefs, now, interval_secs)
}

/// Record the timestamp and outcome of an update check.
pub fn mark_auto_checked(seen_tag: Option<&str>, applied_tag: Option<&str>, note: Option<&str>) {
    let mut prefs = load_auto_update_prefs();
    prefs.last_check_ts = now_ts().max(0.0) as u64;
    if let Some(t) = seen_tag {
        prefs.last_seen_tag = Some(t.to_string());
    }
    if let Some(t) = applied_tag {
        prefs.last_applied_tag = Some(t.to_string());
    }
    if let Some(n) = note {
        prefs.last_note = Some(n.to_string());
    }
    let _ = save_auto_update_prefs(&prefs);
}

fn parse_ver_component(s: &str) -> u32 {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(0)
}

/// Parse a semantic-ish version string into a comparable tuple.
pub fn normalize_version(v: &str) -> (u32, u32, u32) {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let mut parts = v.split('.');
    let major = parts.next().map(parse_ver_component).unwrap_or(0);
    let minor = parts.next().map(parse_ver_component).unwrap_or(0);
    let patch = parts.next().map(parse_ver_component).unwrap_or(0);
    (major, minor, patch)
}

/// The version of the currently running binary.
pub fn current_version() -> String {
    crate::VERSION.to_string()
}

/// Map `(os, arch)` (using `std::env::consts::{OS, ARCH}` values) to DastYab's
/// GitHub release artifact platform slug. Returns `None` on Android (handled by
/// the APK self-updater) or unsupported targets.
pub fn platform_slug_for(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Some("linux-amd64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("macos", "aarch64") => Some("macos-arm64"),
        ("macos", "x86_64") => Some("macos-x86_64"),
        ("windows", "x86_64") => Some("windows-amd64"),
        ("windows", "aarch64") => Some("windows-arm64"),
        _ => None,
    }
}

/// Platform slug for the compiled host target.
pub fn current_platform_slug() -> Option<&'static str> {
    platform_slug_for(std::env::consts::OS, std::env::consts::ARCH)
}

/// Expected exact release asset filename for `(kind, os, arch)`.
pub fn expected_asset_name(kind: BinaryKind, os: &str, arch: &str) -> Option<String> {
    let slug = platform_slug_for(os, arch)?;
    let ext = if os == "windows" { ".exe" } else { "" };
    Some(format!("{}-{slug}{ext}", kind.asset_prefix()))
}

/// Extract a release tag (`vX.Y.Z`) from a GitHub release URL such as
/// `https://github.com/DastYab/dastyab/releases/tag/v0.3.2`.
pub fn parse_tag_from_release_url(url: &str) -> Option<String> {
    let marker = "/releases/tag/";
    let idx = url.find(marker)?;
    let rest = &url[idx + marker.len()..];
    let tag = rest.split(['?', '#', '/']).next().unwrap_or("").trim();
    if tag.is_empty() || tag == "latest" {
        None
    } else {
        Some(tag.to_string())
    }
}

/// Build synthetic release asset entries from a known release tag when the
/// GitHub REST API is unavailable/rate-limited and only `/releases/latest`
/// redirect resolution succeeded.
pub fn synthesize_release_assets(tag: &str) -> Vec<ReleaseAsset> {
    let base = format!("https://github.com/{OWNER}/{REPO}/releases/download/{tag}");
    let mut assets = Vec::new();
    for (os, arch) in [
        ("linux", "x86_64"),
        ("linux", "aarch64"),
        ("windows", "x86_64"),
        ("windows", "aarch64"),
        ("macos", "aarch64"),
        ("macos", "x86_64"),
    ] {
        for kind in [BinaryKind::Cli, BinaryKind::Gui, BinaryKind::Tui] {
            if let Some(name) = expected_asset_name(kind, os, arch) {
                assets.push(ReleaseAsset {
                    url: format!("{base}/{name}"),
                    api_url: String::new(),
                    name,
                });
            }
        }
    }
    assets.push(ReleaseAsset {
        name: "SHA256SUMS.txt".to_string(),
        url: format!("{base}/SHA256SUMS.txt"),
        api_url: String::new(),
    });
    assets
}

fn build_http_client(
    timeout: Duration,
    socks_port: Option<u16>,
    follow_redirects: bool,
) -> Result<reqwest::Client, CFError> {
    let ua = format!("dastyab-selfupdate/{}", crate::VERSION);
    let mut builder = reqwest::Client::builder().timeout(timeout).user_agent(ua);
    if !follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }
    if let Some(port) = socks_port {
        let url = format!("socks5h://127.0.0.1:{port}");
        let proxy = match reqwest::Proxy::all(url) {
            Ok(p) => p,
            Err(e) => {
                let detail = format!("Invalid SOCKS5 proxy: {e}");
                return Err(upd_err(detail, ""));
            }
        };
        builder = builder.proxy(proxy);
    }
    match builder.build() {
        Ok(c) => Ok(c),
        Err(e) => {
            let detail = e.to_string();
            Err(upd_err(detail, "Internal HTTP client error."))
        }
    }
}

async fn candidate_clients(timeout: Duration, follow_redirects: bool) -> Vec<reqwest::Client> {
    let mut clients = Vec::new();
    if let Ok(direct) = build_http_client(timeout, None, follow_redirects) {
        clients.push(direct);
    }
    // Probe local DastYab SOCKS5 proxy ports (multilayer primary + flow) with a
    // short connect check so direct blocks on censored networks fall back cleanly.
    for port in [PROXY_SOCKS_PORT, PROXY_SOCKS_PORT + 10] {
        let wait = Duration::from_millis(250);
        let conn = tokio::net::TcpStream::connect(("127.0.0.1", port));
        let probe = tokio::time::timeout(wait, conn).await;
        if matches!(probe, Ok(Ok(_))) {
            if let Ok(proxied) = build_http_client(timeout, Some(port), follow_redirects) {
                clients.push(proxied);
            }
        }
    }
    clients
}

async fn fetch_release_via_api(client: &reqwest::Client) -> Result<ReleaseInfo, CFError> {
    let mut req = client.get(RELEASE_LATEST);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let detail = format!("Could not reach GitHub API: {e}");
            return Err(upd_err(detail, "Check your network connection."));
        }
    };

    if !resp.status().is_success() {
        let detail = format!("GitHub API responded HTTP {}", resp.status());
        return Err(upd_err(detail, "GitHub may be rate-limiting requests."));
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            let detail = e.to_string();
            return Err(upd_err(detail, "Malformed GitHub API response."));
        }
    };

    let tag = body["tag_name"].as_str().unwrap_or("").to_string();
    if tag.is_empty() {
        return Err(upd_err(
            "No release tag found.",
            "No public release exists yet.",
        ));
    }

    let mut assets = Vec::new();
    if let Some(arr) = body.get("assets").and_then(|a| a.as_array()) {
        for a in arr {
            let name = a["name"].as_str().unwrap_or("").to_string();
            let url = a["browser_download_url"].as_str().unwrap_or("").to_string();
            let api_url = a["url"].as_str().unwrap_or("").to_string();
            if !name.is_empty() {
                assets.push(ReleaseAsset { name, url, api_url });
            }
        }
    }

    let version = normalize_version(&tag);
    Ok(ReleaseInfo {
        tag,
        version,
        assets,
    })
}

async fn fetch_release_via_web_redirect(
    client_no_redirect: &reqwest::Client,
    client_follow: &reqwest::Client,
) -> Result<ReleaseInfo, CFError> {
    if let Ok(resp) = client_no_redirect.get(RELEASE_LATEST_WEB).send().await {
        let loc_hdr = resp.headers().get("location");
        if let Some(loc) = loc_hdr.and_then(|v| v.to_str().ok()) {
            if let Some(tag) = parse_tag_from_release_url(loc) {
                let version = normalize_version(&tag);
                let assets = synthesize_release_assets(&tag);
                return Ok(ReleaseInfo {
                    tag,
                    version,
                    assets,
                });
            }
        }
    }

    let resp = match client_follow.get(RELEASE_LATEST_WEB).send().await {
        Ok(r) => r,
        Err(e) => {
            let detail = format!("Could not reach GitHub releases page: {e}");
            return Err(upd_err(detail, "Check your network connection."));
        }
    };
    let final_url = resp.url().as_str().to_string();
    let tag = match parse_tag_from_release_url(&final_url) {
        Some(t) => t,
        None => {
            let detail = format!("Unexpected redirect URL for latest release: {final_url}");
            return Err(upd_err(detail, "Check GitHub Releases manually."));
        }
    };

    let version = normalize_version(&tag);
    let assets = synthesize_release_assets(&tag);
    Ok(ReleaseInfo {
        tag,
        version,
        assets,
    })
}

/// Fetch metadata for the latest GitHub release, with automatic REST API ->
/// web redirect fallback and direct -> local SOCKS5 proxy fallback.
pub async fn latest_release(timeout: Duration) -> Result<ReleaseInfo, CFError> {
    let clients = candidate_clients(timeout, true).await;
    let no_redir_clients = candidate_clients(timeout, false).await;

    let mut last_err: Option<CFError> = None;
    for client in &clients {
        match fetch_release_via_api(client).await {
            Ok(info) => return Ok(info),
            Err(e) => last_err = Some(e),
        }
    }

    for (no_redir, follow) in no_redir_clients.iter().zip(clients.iter()) {
        if let Ok(info) = fetch_release_via_web_redirect(no_redir, follow).await {
            return Ok(info);
        }
    }

    match last_err {
        Some(e) => Err(e),
        None => {
            let hint = "Check your network connection or connect DastYab proxy first.";
            Err(upd_err("Could not reach GitHub Releases.", hint))
        }
    }
}

/// Determine whether an update is available. Returns `(available, newest_tag)`.
pub async fn update_available(timeout: Duration) -> Result<(bool, Option<String>), CFError> {
    let rel = latest_release(timeout).await?;
    let installed = normalize_version(&current_version());
    let available = rel.version > installed;
    Ok((available, available.then_some(rel.tag)))
}

/// Pick the matching release asset for `(kind, os, arch)`.
pub fn asset_for_target(
    assets: &[ReleaseAsset],
    kind: BinaryKind,
    os: &str,
    arch: &str,
) -> Option<ReleaseAsset> {
    let exact = expected_asset_name(kind, os, arch)?;
    if let Some(a) = assets.iter().find(|a| a.name == exact) {
        return Some(a.clone());
    }

    let slug = platform_slug_for(os, arch)?;
    for a in assets {
        let n = a.name.to_ascii_lowercase();
        if !n.contains(slug)
            || n.ends_with(".deb")
            || n.contains("portable")
            || n.ends_with(".apk")
            || n.ends_with(".py")
            || n.ends_with(".sh")
            || n.ends_with(".txt")
        {
            continue;
        }
        if (os == "windows" && !n.ends_with(".exe")) || (os != "windows" && n.ends_with(".exe")) {
            continue;
        }
        let kind_ok = match kind {
            BinaryKind::Cli => !n.contains("gui") && !n.contains("tui"),
            BinaryKind::Gui => n.contains("gui") && !n.contains("tui"),
            BinaryKind::Tui => n.contains("tui") && !n.contains("gui"),
        };
        if kind_ok {
            return Some(a.clone());
        }
    }
    None
}

/// Pick the matching release asset for the given binary edition on the host OS/arch.
pub fn asset_for_kind(assets: &[ReleaseAsset], kind: BinaryKind) -> Option<ReleaseAsset> {
    asset_for_target(assets, kind, std::env::consts::OS, std::env::consts::ARCH)
}

/// Pick the CLI binary asset that matches the current platform (or None).
pub fn current_platform_asset(assets: &[ReleaseAsset]) -> Option<ReleaseAsset> {
    asset_for_kind(assets, BinaryKind::Cli)
}

/// Parse a `SHA256SUMS.txt` file body and extract the expected lowercase SHA-256
/// hex digest for `filename`.
pub fn parse_sha256sums(content: &str, filename: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let hash = parts.next()?.trim();
        let raw_file = parts.next()?.trim();
        let file = raw_file.trim_start_matches('*').trim_start_matches("./");
        if file == filename && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

/// Compute lowercase SHA-256 hex digest of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Basic native executable header sanity check so truncated/HTML error responses
/// are never installed as binaries.
pub fn has_executable_magic(bytes: &[u8], os: &str) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    match os {
        "linux" => bytes.starts_with(b"\x7fELF"),
        "windows" => bytes.starts_with(b"MZ"),
        "macos" => {
            let m = [bytes[0], bytes[1], bytes[2], bytes[3]];
            matches!(
                m,
                [0xFE, 0xED, 0xFA, 0xCE]
                    | [0xCE, 0xFA, 0xED, 0xFE]
                    | [0xFE, 0xED, 0xFA, 0xCF]
                    | [0xCF, 0xFA, 0xED, 0xFE]
                    | [0xCA, 0xFE, 0xBA, 0xBE]
                    | [0xBE, 0xBA, 0xFE, 0xCA]
            )
        }
        _ => true,
    }
}

/// Verify downloaded binary size, native executable magic, and SHA-256 digest.
pub fn verify_binary_payload(
    bytes: &[u8],
    os: &str,
    expected_sha256: Option<&str>,
) -> Result<(), CFError> {
    if bytes.len() < 1024 {
        let detail = format!("Downloaded binary is too small ({} bytes).", bytes.len());
        let hint = "Download appears truncated or blocked by an error page.";
        return Err(upd_err(detail, hint));
    }
    if !has_executable_magic(bytes, os) {
        let detail = format!("Downloaded file is not a valid {os} executable.");
        let hint = "Network proxy or portal may have intercepted the download.";
        return Err(upd_err(detail, hint));
    }
    if let Some(expected) = expected_sha256 {
        let actual = sha256_hex(bytes);
        if !actual.eq_ignore_ascii_case(expected.trim()) {
            let exp_short = &expected[..expected.len().min(12)];
            let got_short = &actual[..12];
            let detail = format!("SHA-256 mismatch (expected {exp_short}..., got {got_short}...).");
            let hint = "Aborting update to protect executable integrity.";
            return Err(CFError::new("Checksum mismatch", detail, hint));
        }
    }
    Ok(())
}

async fn download_bytes_resilient(
    clients: &[reqwest::Client],
    urls: &[&str],
    is_api_binary: bool,
) -> Option<Vec<u8>> {
    for client in clients {
        for &u in urls {
            if u.is_empty() {
                continue;
            }
            let resp = if is_api_binary && u.starts_with("https://api.github.com") {
                let mut req = client.get(u).header("Accept", "application/octet-stream");
                if let Ok(token) = std::env::var("GITHUB_TOKEN") {
                    if !token.is_empty() {
                        req = req.header("Authorization", format!("Bearer {token}"));
                    }
                }
                req.send().await
            } else {
                client.get(u).send().await
            };
            if let Ok(r) = resp {
                if r.status().is_success() {
                    if let Ok(b) = r.bytes().await {
                        return Some(b.to_vec());
                    }
                }
            }
        }
    }
    None
}

async fn fetch_expected_sha256(
    clients: &[reqwest::Client],
    rel: &ReleaseInfo,
    asset_name: &str,
) -> Option<String> {
    let checksum_asset = rel.assets.iter().find(|a| a.name == "SHA256SUMS.txt");
    let base = format!("https://github.com/{OWNER}/{REPO}/releases/download");
    let fallback_url = format!("{base}/{}/SHA256SUMS.txt", rel.tag);
    let urls: Vec<&str> = match checksum_asset {
        Some(a) => vec![a.api_url.as_str(), a.url.as_str(), fallback_url.as_str()],
        None => vec![fallback_url.as_str()],
    };
    let bytes = download_bytes_resilient(clients, &urls, true).await?;
    let text = String::from_utf8(bytes).ok()?;
    parse_sha256sums(&text, asset_name)
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os: OsString = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

/// Remove any leftover `.old` / `.new-tmp` binary left behind by an earlier
/// Windows/Unix self-update swap. Safe to call unconditionally at startup.
pub fn cleanup_stale_old_binary() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    for candidate in [
        sibling_with_suffix(&exe, ".old"),
        sibling_with_suffix(&exe, ".new-tmp"),
        exe.with_extension("old"),
        exe.with_extension("new-tmp"),
    ] {
        if candidate != exe && candidate.is_file() {
            let _ = std::fs::remove_file(candidate);
        }
    }
}

enum SwapPlacement {
    ReplacedInPlace,
    Staged(PathBuf),
}

fn stage_fallback_binary(kind: BinaryKind, payload: &[u8]) -> Result<PathBuf, CFError> {
    let dir = mem_dir().join("bin");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err(CFError::new(
            "Storage error",
            format!("{e}"),
            "Check permissions.",
        ));
    }
    let ext = if cfg!(windows) { ".exe" } else { "" };
    let target = dir.join(format!("{}-new{ext}", kind.asset_prefix()));
    atomic_write(&target, payload)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755));
    }
    Ok(target)
}

fn install_payload_at(
    exe: &Path,
    kind: BinaryKind,
    payload: &[u8],
) -> Result<SwapPlacement, CFError> {
    let tmp = sibling_with_suffix(exe, ".new-tmp");
    if let Err(e) = std::fs::write(&tmp, payload) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            let staged = stage_fallback_binary(kind, payload)?;
            return Ok(SwapPlacement::Staged(staged));
        }
        let detail = format!("Write temp binary failed: {e}");
        return Err(upd_err(detail, "Check disk space and permissions."));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        match std::fs::rename(&tmp, exe) {
            Ok(()) => Ok(SwapPlacement::ReplacedInPlace),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    let staged = stage_fallback_binary(kind, payload)?;
                    Ok(SwapPlacement::Staged(staged))
                } else {
                    let detail = format!("Binary swap failed: {e}");
                    let hint = "Close running instances or run with write permission.";
                    Err(upd_err(detail, hint))
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let old = sibling_with_suffix(exe, ".old");
        let _ = std::fs::remove_file(&old);
        match std::fs::rename(exe, &old) {
            Ok(()) => match std::fs::rename(&tmp, exe) {
                Ok(()) => Ok(SwapPlacement::ReplacedInPlace),
                Err(e) => {
                    let _ = std::fs::rename(&old, exe);
                    let _ = std::fs::remove_file(&tmp);
                    let detail = format!("Binary swap failed (rolled back): {e}");
                    Err(upd_err(detail, "Check antivirus or file locks."))
                }
            },
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    let staged = stage_fallback_binary(kind, payload)?;
                    Ok(SwapPlacement::Staged(staged))
                } else {
                    let detail = format!("Cannot move running binary aside: {e}");
                    let hint = "Run from a user-writable folder or elevate permissions.";
                    Err(upd_err(detail, hint))
                }
            }
        }
    }
}

/// Result of an auto-update attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Already on the latest version.
    UpToDate,
    /// A new binary was downloaded, verified (SHA-256 + magic), and atomically
    /// swapped over the running executable. The caller can re-exec itself.
    Updated { tag: String },
    /// A new binary was verified and staged into `~/.dastyab/bin/` because the
    /// active install location (e.g. `/usr/bin`) is read-only.
    Staged { tag: String, path: String },
    /// The download, verification, or swap failed (caller decides whether to log).
    Failed(String),
}

/// Check, download, verify, and swap the given DastYab binary edition.
pub async fn ensure_updated_with_swap_for(
    kind: BinaryKind,
    timeout: Duration,
) -> Result<UpdateOutcome, CFError> {
    let rel = latest_release(timeout).await?;
    let installed = normalize_version(&current_version());
    if rel.version <= installed {
        mark_auto_checked(Some(&rel.tag), None, Some("Up to date"));
        return Ok(UpdateOutcome::UpToDate);
    }

    let Some(asset) = asset_for_kind(&rel.assets, kind) else {
        let msg = format!(
            "No {} asset for {}/{} in release {}.",
            kind.label(),
            std::env::consts::OS,
            std::env::consts::ARCH,
            rel.tag
        );
        mark_auto_checked(Some(&rel.tag), None, Some(&msg));
        return Ok(UpdateOutcome::UpToDate);
    };

    let clients = candidate_clients(timeout, true).await;
    let base = format!("https://github.com/{OWNER}/{REPO}/releases/download");
    let fallback_url = format!("{base}/{}/{}", rel.tag, asset.name);
    let urls: [&str; 3] = [&asset.api_url, &asset.url, &fallback_url];
    let Some(body) = download_bytes_resilient(&clients, &urls, true).await else {
        let msg = "All download endpoints failed.";
        mark_auto_checked(Some(&rel.tag), None, Some(msg));
        return Ok(UpdateOutcome::Failed(msg.to_string()));
    };

    let expected_sha = fetch_expected_sha256(&clients, &rel, &asset.name).await;
    if let Err(e) = verify_binary_payload(&body, std::env::consts::OS, expected_sha.as_deref()) {
        let msg = e.brief();
        mark_auto_checked(Some(&rel.tag), None, Some(&msg));
        return Ok(UpdateOutcome::Failed(msg));
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return Err(upd_err(e.to_string(), "Cannot locate the binary.")),
    };
    match install_payload_at(&exe, kind, &body) {
        Ok(SwapPlacement::ReplacedInPlace) => {
            let note = format!("Updated {} to {}", kind.label(), rel.tag);
            mark_auto_checked(Some(&rel.tag), Some(&rel.tag), Some(&note));
            Ok(UpdateOutcome::Updated { tag: rel.tag })
        }
        Ok(SwapPlacement::Staged(path)) => {
            let path = path.display().to_string();
            let note = format!("Staged {} {} at {path}", kind.label(), rel.tag);
            mark_auto_checked(Some(&rel.tag), Some(&rel.tag), Some(&note));
            let tag = rel.tag;
            Ok(UpdateOutcome::Staged { tag, path })
        }
        Err(e) => {
            let msg = e.brief();
            mark_auto_checked(Some(&rel.tag), None, Some(&msg));
            Ok(UpdateOutcome::Failed(msg))
        }
    }
}

/// Auto-update the currently running executable edition (`CLI`, `GUI`, or `TUI`).
pub async fn ensure_updated_with_swap(timeout: Duration) -> Result<UpdateOutcome, CFError> {
    ensure_updated_with_swap_for(BinaryKind::detect_current(), timeout).await
}

/// Download, verify, and apply a newer release for the given edition.
pub async fn apply_update_for(kind: BinaryKind, timeout: Duration) -> Result<String, CFError> {
    match ensure_updated_with_swap_for(kind, timeout).await? {
        UpdateOutcome::UpToDate => Ok("Already on the latest version.".to_string()),
        UpdateOutcome::Updated { tag } => {
            let label = kind.label();
            let msg = format!("Updated {label} to {tag}. Restart DastYab to use it.");
            Ok(msg)
        }
        UpdateOutcome::Staged { tag, path } => {
            let msg = format!("Verified {tag} staged at {path} (read-only install dir).");
            Ok(msg)
        }
        UpdateOutcome::Failed(msg) => {
            let hint = "Retry later or download manually from GitHub Releases.";
            Err(upd_err(msg, hint))
        }
    }
}

/// Download, verify, and apply a newer release for the current binary edition.
pub async fn apply_update(timeout: Duration) -> Result<String, CFError> {
    apply_update_for(BinaryKind::detect_current(), timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_version_parses() {
        assert_eq!(normalize_version("v1.2.3"), (1, 2, 3));
        assert_eq!(normalize_version("1.2"), (1, 2, 0));
        assert_eq!(normalize_version("0.0.1"), (0, 0, 1));
        assert_eq!(normalize_version("v0.3.2-rc1"), (0, 3, 2));
        assert_eq!(normalize_version("0.10.4+build9"), (0, 10, 4));
        assert_eq!(normalize_version("garbage"), (0, 0, 0));
    }

    #[test]
    fn version_comparison_orders() {
        assert!(normalize_version("v1.2.3") > normalize_version("v1.2.2"));
        assert!(normalize_version("v1.3.0") > normalize_version("v1.2.9"));
        assert!(normalize_version("v0.10.0") > normalize_version("v0.3.2"));
        assert_eq!(normalize_version("v2.0.0"), normalize_version("2.0.0"));
    }

    #[test]
    fn platform_asset_filter() {
        let assets = vec![
            ReleaseAsset {
                name: "dastyab-linux-amd64".into(),
                url: "u1".into(),
                api_url: "api1".into(),
            },
            ReleaseAsset {
                name: "dastyab-linux-arm64".into(),
                url: "u2".into(),
                api_url: "api2".into(),
            },
        ];
        let picked = current_platform_asset(&assets);
        assert!(picked.is_some());
        assert_eq!(picked.unwrap().url, "u1");
    }

    fn pick(assets: &[ReleaseAsset], k: BinaryKind, os: &str, arch: &str) -> Option<String> {
        asset_for_target(assets, k, os, arch).map(|a| a.name)
    }

    #[test]
    fn edition_asset_selection_covers_all_platforms_and_kinds() {
        let assets = synthesize_release_assets("v0.9.0");
        let p1 = pick(&assets, BinaryKind::Cli, "linux", "x86_64");
        assert_eq!(p1.as_deref(), Some("dastyab-linux-amd64"));
        let p2 = pick(&assets, BinaryKind::Gui, "linux", "aarch64");
        assert_eq!(p2.as_deref(), Some("dastyab-gui-linux-arm64"));
        let p3 = pick(&assets, BinaryKind::Tui, "windows", "x86_64");
        assert_eq!(p3.as_deref(), Some("dastyab-tui-windows-amd64.exe"));
        let p4 = pick(&assets, BinaryKind::Gui, "macos", "aarch64");
        assert_eq!(p4.as_deref(), Some("dastyab-gui-macos-arm64"));
        let p5 = pick(&assets, BinaryKind::Cli, "android", "aarch64");
        assert!(p5.is_none());
    }

    #[test]
    fn binary_kind_detects_from_exe_name() {
        let gui = BinaryKind::detect_from_exe_name("dastyab-gui-windows-amd64.exe");
        assert_eq!(gui, BinaryKind::Gui);
        assert_eq!(
            BinaryKind::detect_from_exe_name("dastyab-tui"),
            BinaryKind::Tui
        );
        assert_eq!(BinaryKind::detect_from_exe_name("dastyab"), BinaryKind::Cli);
    }

    #[test]
    fn parse_tag_from_web_redirect_url() {
        let u1 = "https://github.com/DastYab/dastyab/releases/tag/v0.4.0";
        assert_eq!(parse_tag_from_release_url(u1).as_deref(), Some("v0.4.0"));
        let u2 = "/DastYab/dastyab/releases/tag/v1.2.3?foo=1";
        assert_eq!(parse_tag_from_release_url(u2).as_deref(), Some("v1.2.3"));
        let u3 = "https://github.com/DastYab/dastyab/releases/latest";
        assert!(parse_tag_from_release_url(u3).is_none());
    }

    #[test]
    fn sha256_sums_and_payload_verification() {
        let mut elf = vec![0x7f, b'E', b'L', b'F'];
        elf.resize(2048, 0xAA);
        let digest = sha256_hex(&elf);
        let other = "0".repeat(64);
        let sums = format!("{digest}  dastyab-linux-amd64\n{other} *other-file\n");
        let parsed = parse_sha256sums(&sums, "dastyab-linux-amd64");
        assert_eq!(parsed.as_deref(), Some(digest.as_str()));
        assert!(verify_binary_payload(&elf, "linux", Some(&digest)).is_ok());

        let bad_digest = "0".repeat(64);
        assert!(verify_binary_payload(&elf, "linux", Some(&bad_digest)).is_err());

        let html = vec![b'<'; 2048];
        assert!(verify_binary_payload(&html, "linux", None).is_err());
    }

    #[test]
    fn throttle_and_in_place_swap_work() {
        let mut prefs = SelfUpdatePrefs::default();
        assert!(check_throttle_due(&prefs, 1000, 3600));
        prefs.last_check_ts = 1000;
        assert!(!check_throttle_due(&prefs, 2000, 3600));
        assert!(check_throttle_due(&prefs, 4600, 3600));
        prefs.enabled = false;
        assert!(!check_throttle_due(&prefs, 9999, 3600));

        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("dastyab-test");
        std::fs::write(&exe, b"old-binary").unwrap();
        let mut new_bin = vec![0x7f, b'E', b'L', b'F'];
        new_bin.resize(2048, 0x42);
        let res = install_payload_at(&exe, BinaryKind::Cli, &new_bin).unwrap();
        assert!(matches!(res, SwapPlacement::ReplacedInPlace));
        assert_eq!(std::fs::read(&exe).unwrap(), new_bin);
    }

    #[test]
    fn update_outcome_discriminants() {
        assert_eq!(UpdateOutcome::UpToDate, UpdateOutcome::UpToDate);
        let u1 = UpdateOutcome::Updated { tag: "v1".into() };
        let u2 = UpdateOutcome::Updated { tag: "v2".into() };
        assert_eq!(u1, u1.clone());
        assert_ne!(u1, u2);
        let tag = "v1".into();
        let path = "/tmp/a".into();
        let s1 = UpdateOutcome::Staged { tag, path };
        assert_eq!(s1, s1.clone());
        let f1 = UpdateOutcome::Failed("x".into());
        assert_eq!(f1, f1.clone());
    }

    #[test]
    fn auto_update_interval_is_sane() {
        assert_eq!(AUTO_UPDATE_INTERVAL_SECS, 86400);
    }
}
