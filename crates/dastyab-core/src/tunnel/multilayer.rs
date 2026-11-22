//! Multi-layer tunnel: a user-facing "rescue chain" that ends at a **final
//! server** the user configures (their own VPN / VLESS endpoint), and an
//! access probe that verifies AI Studio + Gemini reachability through the
//! whole chain.
//!
//! The DNS tunnel (VPS or worker) is the *rescue transport*. The final server
//! is the *destination VPN* — the actual egress your traffic leaves from. A
//! user who wants a working foreign IP for AI Studio / Gemini can:
//!
//! 1. Paste their own VLESS link (or any server they trust) as the final
//!    server config.
//! 2. The app builds a local xray proxy that routes through that final server
//!    (and, in a blackout, through the DNS-tunnel rescue transport first).
//! 3. `probe_ai_access` then checks whether AI Studio and Gemini are actually
//!    reachable *through that chain* — the honest, end-to-end test of egress.
//!
//! This module is purely additive: it complements the `fallback_ladder`
//! (transport tiers) with the *user's own endpoint* layer and an egress probe.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::artifact::vless::VlessProfile;
use crate::error::CFError;
use crate::tunnel::lion_warrior::{country_to_locale_tz, hardened_chrome_args};

/// Whether this profile has a final-server chain configured.
pub fn is_chain_configured(profile_id: &str) -> bool {
    load_final_server(profile_id).is_some()
}

/// The user's final server (the VPN they actually want to use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalServerConfig {
    /// Human label (e.g. "my vps").
    #[serde(default)]
    pub name: String,
    /// A `vless://` share link (or any VLESS link the app can parse).
    pub vless_link: String,
    /// Optional hint: the final server's expected egress country.
    #[serde(default)]
    pub country_hint: String,
}

/// A transport layer in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerKind {
    /// Direct connection (no tunnel).
    Direct,
    /// DNS-over-HTTPS (pinned) transport.
    Doh,
    /// DNS-over-TLS transport.
    Dot,
    /// DNS tunnel (rescue transport).
    DnsTunnel,
    /// The final server (user-configured VPN / VLESS egress).
    FinalServer,
}

impl LayerKind {
    pub fn label(self) -> &'static str {
        match self {
            LayerKind::Direct => "direct",
            LayerKind::Doh => "doh",
            LayerKind::Dot => "dot",
            LayerKind::DnsTunnel => "dns-tunnel",
            LayerKind::FinalServer => "final-server",
        }
    }
    /// The ordered chain the app uses to reach egress.
    pub fn default_chain() -> Vec<LayerKind> {
        vec![
            LayerKind::Direct,
            LayerKind::Doh,
            LayerKind::Dot,
            LayerKind::DnsTunnel,
            LayerKind::FinalServer,
        ]
    }
}

// --- Persistence (per profile) -------------------------------------------

fn final_server_path(profile_id: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile_id).join("final-server.json")
}

/// Persist the final-server config (atomic write).
pub fn save_final_server(profile_id: &str, cfg: &FinalServerConfig) -> Result<(), CFError> {
    crate::store::write_json(&final_server_path(profile_id), cfg)
}

/// Load the final-server config, if present.
pub fn load_final_server(profile_id: &str) -> Option<FinalServerConfig> {
    crate::store::read_opt(&final_server_path(profile_id))
}

/// Remove the final-server config.
pub fn clear_final_server(profile_id: &str) -> Result<(), CFError> {
    let p = final_server_path(profile_id);
    if p.exists() {
        std::fs::remove_file(&p)
            .map_err(|e| CFError::new("multilayer", format!("clear failed: {e}"), ""))?;
    }
    Ok(())
}

/// Optional brutal multi-hop relay + DPI-fragment settings layered under the
/// profile's final server (exit).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainExtConfig {
    /// Entry / intermediate hops ordered `[relay_close_to_exit, ..., entry]`.
    #[serde(default)]
    pub relay_links: Vec<String>,
    /// Wrap entry hop with xray TLS-Hello packet fragmentation (`freedom`).
    #[serde(default)]
    pub fragment_dpi: bool,
}

fn chain_ext_path(profile_id: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile_id).join("final-chain-ext.json")
}

pub fn save_chain_ext(profile_id: &str, ext: &ChainExtConfig) -> Result<(), CFError> {
    crate::store::write_json(&chain_ext_path(profile_id), ext)
}

pub fn load_chain_ext(profile_id: &str) -> ChainExtConfig {
    crate::store::read_opt(&chain_ext_path(profile_id)).unwrap_or_default()
}

/// Parse the user's vless link into a VlessProfile.
pub fn parse_final_server(cfg: &FinalServerConfig) -> Result<VlessProfile, CFError> {
    VlessProfile::parse(&cfg.vless_link)
}

/// Compile full 1..=4 hop xray JSON for `cfg` + optional `ext` relays/fragment.
pub fn build_chain_xray_json(
    cfg: &FinalServerConfig,
    ext: &ChainExtConfig,
    socks_port: u16,
) -> Result<String, CFError> {
    if !ext.relay_links.is_empty() || ext.fragment_dpi || !cfg.vless_link.starts_with("vless://") {
        let mut hops = vec![crate::tunnel::lion_warrior::parse_chain_hop(&cfg.vless_link)?];
        for link in &ext.relay_links {
            let trimmed = link.trim();
            if !trimmed.is_empty() {
                hops.push(crate::tunnel::lion_warrior::parse_chain_hop(trimmed)?);
            }
        }
        let opts = crate::tunnel::lion_warrior::ChainDialOptions {
            socks_port,
            fragment_dpi: ext.fragment_dpi,
            ..Default::default()
        };
        return crate::tunnel::lion_warrior::build_xray_chain_config(&hops, &opts);
    }
    parse_final_server(cfg)?.xray_client_json_at_port(socks_port)
}

// --- Access probe ----------------------------------------------------------

/// Result of probing one access target through the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetProbe {
    /// "AI Studio" | "Gemini"
    pub target: String,
    pub reachable: bool,
    /// Egress IP observed for this probe, when available.
    pub egress_ip: Option<String>,
    /// Human detail (e.g. "HTTP 200", "connect timeout", "geo-blocked").
    pub note: String,
}

/// Report from `probe_ai_access`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAccessReport {
    pub probes: Vec<TargetProbe>,
    /// The final-server label used.
    pub final_server: String,
    pub ok: bool,
}

impl AiAccessReport {
    pub fn is_ok(&self) -> bool {
        self.ok
    }
}

/// Discovery for the local xray binary (mirrors the python helper's list).
///
/// Order matters, and it is not arbitrary: `$DASTYAB_XRAY` is the documented
/// escape hatch, then the helper dir the app stages into, then the standard
/// install locations. `/tmp/xraybin/xray` is kept last and only for backward
/// compatibility — it is wiped on reboot, so treating it as the primary
/// location made every probe fail on a fresh boot with a core installed.
///
/// The nekoray entries are deliberately *not* listed: `nekoray_core` answers
/// `version` and accepts `run -c` but exits without serving traffic, and
/// `nekobox_core` is sing-box with a different CLI. Selecting either produces
/// "no traffic is getting through" instead of "no core found".
pub fn find_xray_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("DASTYAB_XRAY") {
        let p = PathBuf::from(p);
        if is_executable_file(&p) {
            return Some(p);
        }
    }

    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            cands.push(dir.join("xray"));
        }
    }
    if let Some(home) = crate::store::home_dir() {
        cands.push(
            home.join(crate::store::MEM_DIR_NAME)
                .join("bin")
                .join("xray"),
        );
    }
    cands.push(PathBuf::from("/usr/local/bin/xray"));
    cands.push(PathBuf::from("/usr/bin/xray"));
    cands.push(PathBuf::from("/opt/xray/xray"));
    cands.push(PathBuf::from("/opt/v2rayN/bin/xray/xray"));
    cands.push(PathBuf::from("/tmp/xraybin/xray"));

    if let Some(found) = cands.into_iter().find(|p| is_executable_file(p)) {
        return Some(found);
    }

    // Last resort: anything named `xray`/`v2ray` on PATH.
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in ["xray", "v2ray"] {
            let cand = dir.join(name);
            if is_executable_file(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

/// True for a path that exists and is an executable file (not a directory).
fn is_executable_file(p: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// The local SOCKS5 port the xray proxy listens on for probes.
pub const PROXY_SOCKS_PORT: u16 = 10850;

// Probes.
const AI_STUDIO_URL: &str = "https://aistudio.google.com/";

/// Probe AI Studio + Gemini through the final-server chain (uses any configured
/// relay hops & DPI fragmentation for this profile).
pub async fn probe_ai_access(profile_id: &str) -> Result<AiAccessReport, CFError> {
    let cfg = load_final_server(profile_id).ok_or_else(|| {
        CFError::new(
            "multilayer",
            "no final server configured",
            "Paste a vless:// link on the Multi-Layer Tunnel panel first.",
        )
    })?;
    let ext = load_chain_ext(profile_id);
    probe_ai_access_with_ext(&cfg, &ext).await
}

/// Inner probe that takes the config directly (testable without the store).
pub async fn probe_ai_access_cfg(cfg: &FinalServerConfig) -> Result<AiAccessReport, CFError> {
    probe_ai_access_with_ext(cfg, &ChainExtConfig::default()).await
}

/// Strict Warrior probe for Google Flow through the profile's multi-layer chain.
pub async fn probe_flow_access(
    profile_id: &str,
) -> Result<crate::tunnel::lion_warrior::PersonaAccessReport, CFError> {
    let cfg = load_final_server(profile_id).ok_or_else(|| {
        CFError::new(
            "multilayer",
            "no final server configured",
            "Paste a proxy link on the Multi-Layer Tunnel panel first.",
        )
    })?;
    let ext = load_chain_ext(profile_id);
    probe_flow_access_with_ext(&cfg, &ext).await
}

pub async fn probe_flow_access_with_ext(
    cfg: &FinalServerConfig,
    ext: &ChainExtConfig,
) -> Result<crate::tunnel::lion_warrior::PersonaAccessReport, CFError> {
    let xray = find_xray_binary().ok_or_else(|| {
        CFError::new(
            "multilayer",
            "xray binary not found",
            "Install xray and put it on PATH, or set DASTYAB_XRAY=/path/to/xray.",
        )
    })?;
    let flow_port = PROXY_SOCKS_PORT + 10;
    let cfg_json = build_chain_xray_json(cfg, ext, flow_port)?;
    let cfg_path =
        std::env::temp_dir().join(format!("dyb-warrior-{}.json", crate::store::new_id()));
    std::fs::write(&cfg_path, &cfg_json)
        .map_err(|e| CFError::new("multilayer", format!("write xray cfg: {e}"), ""))?;

    let mut child = tokio::process::Command::new(&xray)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| CFError::new("multilayer", format!("spawn xray: {e}"), ""))?;

    let ready = wait_for_port(flow_port, Duration::from_secs(15)).await;
    if !ready {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = std::fs::remove_file(&cfg_path);
        return Err(CFError::new(
            "multilayer",
            "xray proxy did not open the socks port",
            "Check relay/exit configs are reachable.",
        ));
    }

    let raw_hint = cfg.country_hint.trim();
    let hint = (!raw_hint.is_empty()).then_some(raw_hint);
    let report = crate::tunnel::lion_warrior::verify_persona_through_socks(
        flow_port,
        crate::tunnel::lion_warrior::ServicePersona::WarriorFlow,
        hint,
        false,
    )
    .await;

    let _ = child.kill().await;
    let _ = child.wait().await;
    let _ = std::fs::remove_file(&cfg_path);
    report
}

async fn probe_ai_access_with_ext(
    cfg: &FinalServerConfig,
    ext: &ChainExtConfig,
) -> Result<AiAccessReport, CFError> {
    let xray = find_xray_binary().ok_or_else(|| {
        CFError::new(
            "multilayer",
            "xray binary not found",
            "Install xray and put it on PATH, or set DASTYAB_XRAY=/path/to/xray.",
        )
    })?;

    let cfg_json = build_chain_xray_json(cfg, ext, PROXY_SOCKS_PORT)?;
    let cfg_path =
        std::env::temp_dir().join(format!("dyb-multilayer-{}.json", crate::store::new_id()));
    std::fs::write(&cfg_path, &cfg_json)
        .map_err(|e| CFError::new("multilayer", format!("write xray cfg: {e}"), ""))?;

    // Spawn xray.
    let mut child = tokio::process::Command::new(&xray)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| CFError::new("multilayer", format!("spawn xray: {e}"), ""))?;

    // Wait for the socks port.
    let deadline = Duration::from_secs(15);
    let ready = wait_for_port(PROXY_SOCKS_PORT, deadline).await;
    if !ready {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = std::fs::remove_file(&cfg_path);
        return Err(CFError::new(
            "multilayer",
            "xray proxy did not open the socks port",
            "Check the final server config is correct and reachable.",
        ));
    }

    let raw_hint = cfg.country_hint.trim();
    let hint = (!raw_hint.is_empty()).then_some(raw_hint);
    let res = crate::tunnel::lion_warrior::verify_persona_through_socks(
        PROXY_SOCKS_PORT,
        crate::tunnel::lion_warrior::ServicePersona::LionAiStudio,
        hint,
        false,
    )
    .await;

    // Cleanup.
    let _ = child.kill().await;
    let _ = child.wait().await;
    let _ = std::fs::remove_file(&cfg_path);

    let report = res?;
    let mut probes: Vec<TargetProbe> = report
        .checks
        .into_iter()
        .map(|c| TargetProbe {
            target: c.target,
            reachable: c.passed,
            egress_ip: report.egress_ip.clone(),
            note: c.detail,
        })
        .collect();
    if probes.is_empty() {
        probes.push(TargetProbe {
            target: "Lion Gate".to_string(),
            reachable: false,
            egress_ip: report.egress_ip.clone(),
            note: report.reason.clone(),
        });
    }
    Ok(AiAccessReport {
        probes,
        final_server: cfg.name.clone(),
        ok: report.ok,
    })
}

/// Wait until a TCP port accepts connections.
async fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

// --- Gemini API probe -------------------------------------------------------

/// Path to the Gemini API key for this profile (kept out of the git history —
/// the repo is public; never commit real keys).
fn gemini_key_path(profile_id: &str) -> PathBuf {
    crate::store::profiles::profile_dir(profile_id).join("gemini-key.json")
}

/// Persist the Gemini API key (atomic write).
pub fn save_gemini_key(profile_id: &str, key: &str) -> Result<(), CFError> {
    #[derive(Serialize, Deserialize)]
    struct KeyFile {
        key: String,
    }
    crate::store::write_json(
        &gemini_key_path(profile_id),
        &KeyFile {
            key: key.to_string(),
        },
    )
}

/// Load the Gemini API key, if present.
pub fn load_gemini_key(profile_id: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct KeyFile {
        key: String,
    }
    crate::store::read_opt::<KeyFile>(&gemini_key_path(profile_id)).map(|k| k.key)
}

/// Gemini `generateContent` result summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiApiResult {
    pub ok: bool,
    pub model: String,
    /// The API's answer text, when the call succeeded.
    pub answer: Option<String>,
    pub note: String,
}

/// Make one real Gemini `generateContent` call **through the chain**.
///
/// This is the strongest end-to-end access proof: not just "can we reach the
/// host", but "does the API actually accept our key and return a completion".
pub async fn probe_gemini_api(profile_id: &str, prompt: &str) -> Result<GeminiApiResult, CFError> {
    let cfg = load_final_server(profile_id).ok_or_else(|| {
        CFError::new(
            "multilayer",
            "no final server configured",
            "Paste a vless:// link on the Multi-Layer Tunnel panel first.",
        )
    })?;
    let key = load_gemini_key(profile_id).ok_or_else(|| {
        CFError::new(
            "multilayer",
            "no Gemini API key configured",
            "Add your Gemini API key on the Multi-Layer Tunnel panel.",
        )
    })?;
    probe_gemini_api_cfg(&cfg, &key, prompt).await
}

/// Inner Gemini probe taking config + key directly (testable without store).
pub async fn probe_gemini_api_cfg(
    cfg: &FinalServerConfig,
    key: &str,
    prompt: &str,
) -> Result<GeminiApiResult, CFError> {
    let profile = parse_final_server(cfg)?;
    let xray = find_xray_binary().ok_or_else(|| {
        CFError::new(
            "multilayer",
            "xray binary not found",
            "Install xray and put it on PATH, or set DASTYAB_XRAY=/path/to/xray.",
        )
    })?;

    let cfg_json = profile.xray_client_json_at_port(PROXY_SOCKS_PORT)?;
    let cfg_name = format!("dyb-gemini-{}.json", crate::store::new_id());
    let cfg_path = std::env::temp_dir().join(cfg_name);
    std::fs::write(&cfg_path, &cfg_json)
        .map_err(|e| CFError::new("multilayer", format!("write xray cfg: {e}"), ""))?;

    let mut child = tokio::process::Command::new(&xray)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| CFError::new("multilayer", format!("spawn xray: {e}"), ""))?;

    let ready = wait_for_port(PROXY_SOCKS_PORT, Duration::from_secs(15)).await;
    if !ready {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = std::fs::remove_file(&cfg_path);
        return Err(CFError::new(
            "multilayer",
            "xray proxy did not open the socks port",
            "Check the final server config is correct and reachable.",
        ));
    }

    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{PROXY_SOCKS_PORT}"))
        .map_err(|e| CFError::new("multilayer", format!("proxy cfg: {e}"), ""))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| CFError::new("multilayer", format!("http client: {e}"), ""))?;

    const MODEL: &str = "gemini-flash-latest";
    let url =
        format!("https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent");
    let body = serde_json::json!({
        "contents": [{ "parts": [{ "text": prompt }] }]
    });

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-goog-api-key", key)
        .json(&body)
        .send()
        .await;

    let result = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            if status == 200 {
                let json: serde_json::Value = r.json().await.unwrap_or_default();
                let answer = json["candidates"][0]["content"]["parts"][0]["text"]
                    .as_str()
                    .map(str::to_string);
                match answer {
                    Some(a) => GeminiApiResult {
                        ok: true,
                        model: MODEL.to_string(),
                        answer: Some(a),
                        note: "API call succeeded (HTTP 200)".to_string(),
                    },
                    None => GeminiApiResult {
                        ok: true,
                        model: MODEL.to_string(),
                        answer: None,
                        note: "HTTP 200 but empty candidates".to_string(),
                    },
                }
            } else {
                GeminiApiResult {
                    ok: false,
                    model: MODEL.to_string(),
                    answer: None,
                    note: format!("HTTP {status}"),
                }
            }
        }
        Err(e) => GeminiApiResult {
            ok: false,
            model: MODEL.to_string(),
            answer: None,
            note: format!("{e}"),
        },
    };

    let _ = child.kill().await;
    let _ = child.wait().await;
    let _ = std::fs::remove_file(&cfg_path);

    Ok(result)
}

// --- Tunnel launch / mode control -----------------------------------------

/// How the multi-layer tunnel is applied on the user's machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    /// Route the whole device's traffic through the tunnel (system proxy /
    /// transparent routing — requires elevated setup).
    Device,
    /// Use the tunnel only for DastYab's dedicated Chrome (AI Studio).
    Chrome,
    /// Expose a local SOCKS5 proxy any app can point at.
    Proxy,
}

impl TunnelMode {
    pub fn label(self) -> &'static str {
        match self {
            TunnelMode::Device => "device",
            TunnelMode::Chrome => "chrome",
            TunnelMode::Proxy => "proxy",
        }
    }
    pub fn parse_mode(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "device" => TunnelMode::Device,
            "proxy" => TunnelMode::Proxy,
            _ => TunnelMode::Chrome,
        }
    }
}

/// Path to the persisted AI-Studio Chrome profile (keeps login across runs).
pub fn ai_studio_chrome_profile() -> PathBuf {
    crate::store::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dastyab-aistudio-profile")
}

/// Path to the persisted Google Flow Chrome profile.
pub fn flow_chrome_profile() -> PathBuf {
    let base = crate::store::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".dastyab-flow-profile")
}

/// Launch the xray proxy rooted at the final server (plus optional relays/DPI
/// fragmentation). Returns the child handle.
pub fn launch_xray_with_ext(
    cfg: &FinalServerConfig,
    ext: &ChainExtConfig,
    socks_port: u16,
) -> Result<tokio::process::Child, CFError> {
    let xray = find_xray_binary().ok_or_else(|| {
        CFError::new(
            "multilayer",
            "xray binary not found",
            "Install xray and put it on PATH, or set DASTYAB_XRAY=/path/to/xray.",
        )
    })?;
    let cfg_json = build_chain_xray_json(cfg, ext, socks_port)?;
    let cfg_name = format!("dyb-tunnel-{}.json", crate::store::new_id());
    let cfg_path = std::env::temp_dir().join(cfg_name);
    std::fs::write(&cfg_path, &cfg_json)
        .map_err(|e| CFError::new("multilayer", format!("write xray cfg: {e}"), ""))?;
    let child = tokio::process::Command::new(&xray)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| CFError::new("multilayer", format!("spawn xray: {e}"), ""))?;
    Ok(child)
}

/// Launch the xray proxy rooted at the final server. Returns the child handle.
/// `socks_port` is the local SOCKS5 port xray binds.
pub fn launch_xray(
    cfg: &FinalServerConfig,
    socks_port: u16,
) -> Result<tokio::process::Child, CFError> {
    launch_xray_with_ext(cfg, &ChainExtConfig::default(), socks_port)
}

/// Start the tunnel in the chosen mode (defaults to AI Studio Chrome target).
pub async fn start_tunnel_mode(
    profile_id: &str,
    mode: TunnelMode,
    socks_port: u16,
    chrome_persist: bool,
) -> Result<String, CFError> {
    start_tunnel_mode_for_persona(
        profile_id,
        crate::tunnel::lion_warrior::ServicePersona::LionAiStudio,
        mode,
        socks_port,
        chrome_persist,
    )
    .await
}

/// Start the multi-layer tunnel for a chosen persona (Lion AI Studio or Warrior
/// Google Flow) with hardened DNS/WebRTC anti-leak Chrome launch flags.
pub async fn start_tunnel_mode_for_persona(
    profile_id: &str,
    persona: crate::tunnel::lion_warrior::ServicePersona,
    mode: TunnelMode,
    socks_port: u16,
    chrome_persist: bool,
) -> Result<String, CFError> {
    let cfg = load_final_server(profile_id).ok_or_else(|| {
        CFError::new(
            "multilayer",
            "no final server configured",
            "Paste a vless:// link on the Multi-Layer Tunnel panel first.",
        )
    })?;
    let ext = load_chain_ext(profile_id);
    let mut child = launch_xray_with_ext(&cfg, &ext, socks_port)?;
    let ready = wait_for_port(socks_port, Duration::from_secs(15)).await;
    if !ready {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(CFError::new(
            "multilayer",
            "xray proxy did not open the socks port",
            "Check the final server config is correct and reachable.",
        ));
    }

    match mode {
        TunnelMode::Chrome => {
            let prof_dir = if chrome_persist {
                match persona {
                    crate::tunnel::lion_warrior::ServicePersona::LionAiStudio => {
                        ai_studio_chrome_profile()
                    }
                    crate::tunnel::lion_warrior::ServicePersona::WarriorFlow => {
                        flow_chrome_profile()
                    }
                }
            } else {
                std::env::temp_dir()
                    .join(format!("dyb-chrome-ephemeral-{}", crate::store::new_id()))
            };
            std::fs::create_dir_all(&prof_dir).ok();
            let chrome = [
                "/opt/google/chrome/google-chrome",
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "google-chrome",
                "google-chrome-stable",
            ]
            .iter()
            .find(|c| std::path::Path::new(c).exists());
            let target_url = match persona {
                crate::tunnel::lion_warrior::ServicePersona::LionAiStudio => AI_STUDIO_URL,
                crate::tunnel::lion_warrior::ServicePersona::WarriorFlow => {
                    "https://flow.google.com/"
                }
            };
            if let Some(chrome) = chrome {
                let raw_hint = cfg.country_hint.trim();
                let country = (!raw_hint.is_empty()).then_some(raw_hint);
                let (_, tz) = country_to_locale_tz(country);
                let args = hardened_chrome_args(socks_port, &prof_dir, target_url, country);
                let mut cmd = std::process::Command::new(chrome);
                cmd.env("TZ", tz).args(&args);
                let _ = cmd.spawn();
                Ok(format!(
                    "Tunnel on (mode=chrome, {}, socks5 127.0.0.1:{socks_port}). \
                     Opened in anti-leak Chrome (persist={chrome_persist}).",
                    persona.display_title()
                ))
            } else {
                let _ = child.kill().await;
                Err(CFError::new(
                    "multilayer",
                    "Chrome not found",
                    "Install Google Chrome or set the browser path.",
                ))
            }
        }
        TunnelMode::Proxy => {
            let _ = child;
            Ok(format!(
                "Tunnel on (mode=proxy, {}). Local SOCKS5: 127.0.0.1:{socks_port}.",
                persona.display_title()
            ))
        }
        TunnelMode::Device => {
            std::env::set_var("http_proxy", format!("socks5h://127.0.0.1:{socks_port}"));
            std::env::set_var("https_proxy", format!("socks5h://127.0.0.1:{socks_port}"));
            let _ = child;
            Ok(format!(
                "Tunnel on (mode=device). Env proxy set to \
                 socks5h://127.0.0.1:{socks_port}."
            ))
        }
    }
}

// Test fixtures build configs field-by-field and serialize whole test
// bodies behind a process-wide mutex by design; both patterns are
// intentional here, so the lints are scoped to the test module.
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn fresh_profile() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().join(".dastyab"));
        let pid = crate::store::profiles::create_profile(
            &format!("ml-test-{}", crate::store::new_id()),
            "t",
        )
        .unwrap();
        (dir, pid)
    }

    #[test]
    fn final_server_roundtrip() {
        let (_dir, pid) = fresh_profile();
        let cfg = FinalServerConfig {
            name: "my vps".into(),
            vless_link: "vless://uuid@1.2.3.4:443?security=tls&type=ws&path=%2F#x".into(),
            country_hint: "DE".into(),
        };
        save_final_server(&pid, &cfg).unwrap();
        let loaded = load_final_server(&pid).unwrap();
        assert_eq!(loaded.name, "my vps");
        assert_eq!(loaded.vless_link, cfg.vless_link);
        assert_eq!(loaded.country_hint, "DE");
        assert!(is_chain_configured(&pid));
        clear_final_server(&pid).unwrap();
        assert!(!is_chain_configured(&pid));
        crate::store::clear_mem_dir_override();
    }

    #[test]
    fn parse_final_server_accepts_vless() {
        let cfg = FinalServerConfig {
            name: "x".into(),
            vless_link: "vless://uuid@1.2.3.4:8443?security=tls&type=ws#y".into(),
            country_hint: String::new(),
        };
        let p = parse_final_server(&cfg).unwrap();
        assert_eq!(p.address, "1.2.3.4");
        assert_eq!(p.port, 8443);
        assert_eq!(p.name, "y");
    }

    #[test]
    fn default_chain_ends_at_final_server() {
        let c = LayerKind::default_chain();
        assert_eq!(c.len(), 5);
        assert_eq!(c[0], LayerKind::Direct);
        assert_eq!(*c.last().unwrap(), LayerKind::FinalServer);
        assert_eq!(LayerKind::DnsTunnel.label(), "dns-tunnel");
    }

    #[test]
    fn xray_proxy_config_is_written() {
        let mut p = VlessProfile::default();
        p.address = "example.workers.dev".into();
        p.uuid = "uuid-1".into();
        let s = p.xray_client_json().unwrap();
        assert!(s.contains("\"socks\""));
        assert!(s.contains("\"vless\""));
    }

    /// The resolver must prefer a real core over the reboot-wiped /tmp path.
    /// Regression: `/tmp/xraybin/xray` was the *first* candidate, so a machine
    /// with xray properly installed still reported "xray binary not found"
    /// after every reboot.
    #[test]
    fn find_xray_binary_prefers_env_override() {
        static XRAY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        struct XrayEnvGuard(Option<String>);
        impl Drop for XrayEnvGuard {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => std::env::set_var("DASTYAB_XRAY", v),
                    None => std::env::remove_var("DASTYAB_XRAY"),
                }
            }
        }
        let _lock = XRAY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = XrayEnvGuard(std::env::var("DASTYAB_XRAY").ok());
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("my-xray");
        std::fs::write(&fake, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("DASTYAB_XRAY", &fake);
        let got = find_xray_binary();
        assert_eq!(got.as_deref(), Some(fake.as_path()));
    }

    /// A directory and a missing path must both be rejected: the old resolver
    /// used `p.exists()`, which accepted a directory named `xray`.
    #[test]
    fn is_executable_file_rejects_directories_and_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_executable_file(dir.path()));
        assert!(!is_executable_file(&dir.path().join("nope")));
    }

    /// A non-executable file is not a core either (e.g. an unpacked tarball
    /// with permissions lost). Selecting it produced an opaque spawn error.
    #[cfg(unix)]
    #[test]
    fn is_executable_file_rejects_non_executable_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("xray");
        std::fs::write(&f, b"data").unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable_file(&f));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable_file(&f));
    }

    #[test]
    fn chain_ext_and_multihop_xray_json_build_properly() {
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_mem_dir_override(dir.path().to_path_buf());
        let cfg = FinalServerConfig {
            name: "trojan-exit".into(),
            vless_link: "trojan://secretpass@203.0.113.50:443?security=tls&sni=cdn.example".into(),
            country_hint: "DE".into(),
        };
        let ext = ChainExtConfig {
            relay_links: vec![
                "vless://11111111-1111-1111-1111-111111111111@198.51.100.20:443?security=tls"
                    .into(),
                "socks5://127.0.0.1:9050".into(),
            ],
            fragment_dpi: true,
        };
        save_chain_ext("test-prof", &ext).unwrap();
        let loaded = load_chain_ext("test-prof");
        assert_eq!(loaded.relay_links.len(), 2);
        assert!(loaded.fragment_dpi);

        let json_str = build_chain_xray_json(&cfg, &loaded, 10861).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let obs = v["outbounds"].as_array().unwrap();
        assert_eq!(obs[0]["tag"], "exit");
        assert_eq!(obs[0]["protocol"], "trojan");
        assert_eq!(obs[0]["sockopt"]["dialerProxy"], "relay-1");
        assert_eq!(obs[1]["tag"], "relay-1");
        assert_eq!(obs[1]["sockopt"]["dialerProxy"], "entry");
        assert_eq!(obs[2]["tag"], "entry");
        assert_eq!(obs[2]["protocol"], "socks");
        assert!(!obs.iter().any(|o| o["tag"] == "frag-dialer"));

        let mut ext_remote = loaded;
        ext_remote.relay_links[1] = "socks5://192.0.2.9:1080".into();
        let json_remote = build_chain_xray_json(&cfg, &ext_remote, 10862).unwrap();
        let vr: serde_json::Value = serde_json::from_str(&json_remote).unwrap();
        let obsr = vr["outbounds"].as_array().unwrap();
        assert!(obsr.iter().any(|o| o["tag"] == "frag-dialer"));
        crate::store::clear_mem_dir_override();
    }
}
