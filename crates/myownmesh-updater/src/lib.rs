//! Self-update for MyOwnMesh.
//!
//! Ported from MyOwnLLM's `src-tauri/src/self_update.rs`. The daemon
//! is set-it-and-forget-it: a background ticker periodically checks the
//! configured release feed and, per the user's `auto_apply` policy:
//!
//!   1. Downloads the platform asset (`myownmesh-<platform>.{tar.gz,zip}`),
//!      SHA-256-verifies it against the sidecar (or `SHA256SUMS`).
//!   2. Extracts the embedded `myownmesh` binary into
//!      `~/.myownmesh/updates/<version>/`.
//!   3. Writes `~/.myownmesh/updates/pending.json` so the next process
//!      start applies it.
//!
//! On the next start, [`apply_pending_if_any`] atomically renames the
//! staged binary over the running one and clears the marker. We never
//! restart a running daemon in place — that would yank the rug out from
//! under in-flight connections. The model is "stage now, apply on next
//! launch."
//!
//! Package-manager installs (Homebrew, dpkg/apt, rpm, MSI, Chocolatey)
//! are detected and skipped — the OS package manager owns versioning
//! there.
//!
//! Only the `myownmesh` daemon binary is self-updated here. The GUI
//! (`myownmesh-gui`) ships its own bundle / portable binary; it
//! auto-spawns whichever daemon is on PATH, which this keeps current.

pub mod policy;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use myownmesh_core::config::AutoUpdateConfig;
use myownmesh_core::MeshConfig;

use policy::{compare_semver, policy_allows, ApplyPolicy};

// ---------------------------------------------------------------------------
// Build-time overridable release-feed defaults. A vendor can point the
// same binary at their own release host at compile time:
//   MYOWNMESH_RELEASE_URL_STABLE=https://example.com/releases/latest cargo build
// At runtime, `auto_update.stable_url` / `beta_url` in config.json take
// precedence (see `resolve_release_url`), so users can redirect without
// rebuilding.
// ---------------------------------------------------------------------------

/// Resolved release feed URL for the stable channel.
pub fn default_release_api_stable() -> &'static str {
    option_env!("MYOWNMESH_RELEASE_URL_STABLE")
        .unwrap_or("https://api.github.com/repos/mrjeeves/MyOwnMesh/releases/latest")
}

/// Resolved release feed URL for the beta channel.
pub fn default_release_api_beta() -> &'static str {
    option_env!("MYOWNMESH_RELEASE_URL_BETA")
        .unwrap_or("https://api.github.com/repos/mrjeeves/MyOwnMesh/releases")
}

const USER_AGENT: &str = concat!("myownmesh-self-update/", env!("CARGO_PKG_VERSION"));

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("core: {0}")]
    Core(#[from] myownmesh_core::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("checksum mismatch for {asset}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        asset: String,
        expected: String,
        actual: String,
    },
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    fn msg(s: impl Into<String>) -> Self {
        Error::Other(s.into())
    }
}

/// How this binary was installed. Package-manager installs defer to the
/// system updater and are never self-updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    Raw,
    PackageManager,
}

/// Snapshot of updater state for `myownmesh update status`.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateStatus {
    /// The running binary's version (`CARGO_PKG_VERSION`).
    pub current_version: String,
    pub install_kind: InstallKind,
    /// Effective enabled state — config `auto_update.enabled` AND not
    /// disabled via `MYOWNMESH_AUTOUPDATE=0`.
    pub enabled: bool,
    pub channel: String,
    pub auto_apply: String,
    pub check_interval_hours: u32,
    /// Unix seconds of the last successful feed check, if any.
    pub last_check_at: Option<i64>,
    /// Version staged at `~/.myownmesh/updates/<version>/` waiting to be
    /// applied on next start. `None` = nothing pending.
    pub staged_version: Option<String>,
    /// Effective release URL for the active channel.
    pub release_url: String,
}

/// Result of a single check. `Serialize`-friendly so the CLI can emit it
/// as JSON; rendered to friendly text otherwise.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckOutcome {
    /// Self-update is turned off (config or env).
    Disabled,
    /// Package-manager install — deferred to the system updater.
    PackageManager,
    /// Not forced and the check interval hasn't elapsed (ticker only).
    NotDue,
    /// Already on the latest published version.
    UpToDate { current: String, latest: String },
    /// A newer version exists but `auto_apply` doesn't permit the jump.
    PolicyBlocked {
        current: String,
        latest: String,
        policy: String,
    },
    /// A new version was downloaded, verified, and staged.
    Staged { version: String },
}

fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ---------------------------------------------------------------------------
// Apply (runs at process start).
// ---------------------------------------------------------------------------

/// Apply any staged update before the process starts real work.
/// Idempotent; errors are logged and swallowed so an update problem
/// never prevents the daemon from booting. Call this *first* in `main`.
pub fn apply_pending_if_any() {
    cleanup_old_replaced_binary();
    if let Err(e) = apply_pending() {
        tracing::warn!("self-update apply skipped: {e}");
    }
}

/// Apply a staged update now, surfacing the result. Returns the version
/// that was applied (the swap is on disk; it takes effect on the next
/// process start), or `None` if there was nothing to apply.
pub fn apply_now() -> Result<Option<String>> {
    cleanup_old_replaced_binary();
    apply_pending()
}

fn apply_pending() -> Result<Option<String>> {
    let dir = myownmesh_core::dirs::updates_dir()?;
    let pending = dir.join("pending.json");
    if !pending.exists() {
        return Ok(None);
    }
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&pending)?)?;
    let staged_path = doc["path"]
        .as_str()
        .ok_or_else(|| Error::msg("pending.json missing path"))?;
    let target_version = doc["version"].as_str().unwrap_or("?").to_string();

    // Refuse downgrades / same-version applies. A stale pending.json left
    // by a previous broken self-update could otherwise replace a freshly
    // installed binary with an older one.
    let current = current_version();
    if compare_semver(&target_version, current) != std::cmp::Ordering::Greater {
        let _ = std::fs::remove_file(&pending);
        return Ok(None);
    }

    let staged = PathBuf::from(staged_path);
    if !staged.exists() {
        let _ = std::fs::remove_file(&pending);
        return Err(Error::msg(format!(
            "staged binary {} missing — clearing marker",
            staged.display()
        )));
    }

    // Tolerate a legacy marker that points at the archive itself: extract
    // on the fly so we never rename a .tar.gz over the live binary.
    let staged_dir = staged
        .parent()
        .ok_or_else(|| Error::msg("staged path has no parent"))?;
    let staged = extract_binary_if_archived(&staged, staged_dir)?;

    let current_exe = std::env::current_exe()?;
    atomic_replace(&staged, &current_exe)?;
    let _ = std::fs::remove_file(&pending);
    tracing::info!("self-update applied {target_version}");
    Ok(Some(target_version))
}

// ---------------------------------------------------------------------------
// Check + stage.
// ---------------------------------------------------------------------------

/// Run one check. With `force`, ignore the interval cooldown and the
/// disabled-via-config short-circuit still applies. Stages a permitted
/// update; never applies (that happens on next launch).
pub async fn check_now(force: bool) -> Result<CheckOutcome> {
    let au = load_auto_update().unwrap_or_default();
    if !au.enabled || env_disabled() {
        return Ok(CheckOutcome::Disabled);
    }
    if detect_install_kind() == InstallKind::PackageManager {
        mark_pm_detected();
        return Ok(CheckOutcome::PackageManager);
    }
    if !force && !is_due(au.check_interval_hours)? {
        return Ok(CheckOutcome::NotDue);
    }
    stamp_check_now()?;

    let release = fetch_release(&au).await?;
    let latest = release["tag_name"]
        .as_str()
        .map(|s| s.trim_start_matches('v').to_string())
        .ok_or_else(|| Error::msg("release missing tag_name"))?;
    let current = current_version().to_string();

    if compare_semver(&current, &latest) != std::cmp::Ordering::Less {
        return Ok(CheckOutcome::UpToDate { current, latest });
    }

    let policy = ApplyPolicy::parse(&au.auto_apply).unwrap_or(ApplyPolicy::Patch);
    if !policy_allows(policy, &current, &latest) {
        return Ok(CheckOutcome::PolicyBlocked {
            current,
            latest,
            policy: au.auto_apply.clone(),
        });
    }

    stage_release(&release, &latest).await?;
    Ok(CheckOutcome::Staged { version: latest })
}

/// Current updater status (no network access).
pub fn status() -> Result<UpdateStatus> {
    let au = load_auto_update().unwrap_or_default();
    Ok(UpdateStatus {
        current_version: current_version().to_string(),
        install_kind: detect_install_kind(),
        enabled: au.enabled && !env_disabled(),
        channel: au.channel.clone(),
        auto_apply: au.auto_apply.clone(),
        check_interval_hours: au.check_interval_hours,
        last_check_at: last_check_at(),
        staged_version: staged_version(),
        release_url: resolve_release_url(&au),
    })
}

/// Flip `auto_update.enabled` in `~/.myownmesh/config.json`.
pub fn set_enabled(enabled: bool) -> Result<()> {
    let mut cfg = MeshConfig::load()?;
    cfg.auto_update.enabled = enabled;
    cfg.save()?;
    Ok(())
}

/// Background ticker. Runs forever; checks the feed at the configured
/// interval (re-read each loop so a config edit takes effect without a
/// restart). The first check fires shortly after launch.
pub async fn tick_forever() {
    // Let a fresh daemon finish binding its sockets before we hit the
    // network.
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
        match check_now(false).await {
            Ok(CheckOutcome::Staged { version }) => {
                tracing::info!("self-update staged {version}; applies on next daemon start");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("self-update check failed: {e}"),
        }
        let hours = load_auto_update()
            .map(|a| a.check_interval_hours)
            .unwrap_or(6)
            .max(1);
        tokio::time::sleep(Duration::from_secs(hours as u64 * 3600)).await;
    }
}

// ---------------------------------------------------------------------------
// Config + env gating.
// ---------------------------------------------------------------------------

fn load_auto_update() -> Result<AutoUpdateConfig> {
    Ok(MeshConfig::load()?.auto_update)
}

/// `MYOWNMESH_AUTOUPDATE=0` (or `false`) hard-disables self-update,
/// regardless of config — useful for fleets where a supervisor owns
/// versioning.
fn env_disabled() -> bool {
    std::env::var("MYOWNMESH_AUTOUPDATE")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

/// Resolve the release-feed URL. Order: explicit `auto_update.stable_url`
/// / `beta_url` in config → build-time `MYOWNMESH_RELEASE_URL_*` → the
/// project's GitHub releases endpoint.
fn resolve_release_url(au: &AutoUpdateConfig) -> String {
    let (override_url, fallback) = if au.channel == "beta" {
        (au.beta_url.as_deref(), default_release_api_beta())
    } else {
        (au.stable_url.as_deref(), default_release_api_stable())
    };
    override_url
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

// ---------------------------------------------------------------------------
// Install-kind detection.
// ---------------------------------------------------------------------------

/// Best-effort: classify the install from the running exe's path.
pub fn detect_install_kind() -> InstallKind {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return InstallKind::Raw,
    };
    detect_install_kind_from_path(&exe.to_string_lossy())
}

fn detect_install_kind_from_path(path_str: &str) -> InstallKind {
    // Homebrew on macOS / Linux.
    if path_str.contains("/Cellar/")
        || path_str.starts_with("/opt/homebrew/")
        || path_str.starts_with("/home/linuxbrew/")
    {
        return InstallKind::PackageManager;
    }

    // System paths typically mean dpkg/rpm.
    #[cfg(target_os = "linux")]
    if path_str.starts_with("/usr/bin/") || path_str.starts_with("/usr/sbin/") {
        return InstallKind::PackageManager;
    }

    // Windows: typical MSI install location and Chocolatey / Scoop paths.
    #[cfg(target_os = "windows")]
    {
        let lower = path_str.to_lowercase();
        if lower.contains(r"\program files\")
            || lower.contains(r"\program files (x86)\")
            || lower.contains(r"\chocolatey\lib\")
            || lower.contains(r"\scoop\apps\")
        {
            return InstallKind::PackageManager;
        }
    }

    InstallKind::Raw
}

fn mark_pm_detected() {
    if let Ok(dir) = myownmesh_core::dirs::updates_dir() {
        let marker = dir.join("pm-detected.flag");
        if !marker.exists() {
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(&marker, "skip");
        }
    }
}

// ---------------------------------------------------------------------------
// Release fetch.
// ---------------------------------------------------------------------------

fn http_client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(timeout)
        .build()?)
}

async fn fetch_release(au: &AutoUpdateConfig) -> Result<Value> {
    let url = resolve_release_url(au);
    let client = http_client(Duration::from_secs(15))?;
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(Error::msg(format!(
            "release feed {url} returned {}",
            resp.status()
        )));
    }
    let body: Value = resp.json().await?;
    if au.channel == "beta" {
        // `/releases` returns an array — pick the first non-draft.
        let arr = body
            .as_array()
            .ok_or_else(|| Error::msg("beta feed: expected a JSON array"))?;
        for r in arr {
            if r["draft"].as_bool().unwrap_or(false) {
                continue;
            }
            return Ok(r.clone());
        }
        return Err(Error::msg("no usable release on the beta channel"));
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// Asset matching.
// ---------------------------------------------------------------------------

/// Platform substring the release assets embed
/// (`myownmesh-<this>.{tar.gz,zip}`).
fn current_platform() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x86_64"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "linux-aarch64"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "macos-x86_64"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "macos-aarch64"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-x86_64"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "unknown"
    }
}

fn archive_ext() -> &'static str {
    if cfg!(windows) {
        "zip"
    } else {
        "tar.gz"
    }
}

/// Pick the **daemon** asset for the current platform. Critically, this
/// must not pick the GUI archive (`myownmesh-gui-<platform>...`), which
/// also carries the platform substring, nor any checksum/signature
/// sidecar. We match the exact published name first, then fall back to a
/// guarded substring scan.
fn pick_daemon_asset(assets: &[Value]) -> Option<&Value> {
    let platform = current_platform();
    let exact = format!("myownmesh-{platform}.{}", archive_ext());
    if let Some(a) = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(exact.as_str()))
    {
        return Some(a);
    }
    assets.iter().find(|a| {
        a["name"].as_str().is_some_and(|n| {
            n.starts_with("myownmesh-")
                && !n.starts_with("myownmesh-gui-")
                && n.contains(platform)
                && !is_sidecar_asset(n)
                && (n.ends_with(".tar.gz") || n.ends_with(".tgz") || n.ends_with(".zip"))
        })
    })
}

/// Files that ride alongside a release artifact (checksums, signatures)
/// and must never be installed as the binary.
fn is_sidecar_asset(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".sha256")
        || lower.ends_with(".sha512")
        || lower.ends_with(".sig")
        || lower.ends_with(".asc")
        || lower.ends_with(".minisig")
        || lower.ends_with(".pem")
}

fn pick_sha_asset<'a>(assets: &'a [Value], asset_name: &str) -> Option<&'a Value> {
    let preferred = format!("{asset_name}.sha256");
    if let Some(matching) = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(preferred.as_str()))
    {
        return Some(matching);
    }
    assets.iter().find(|a| {
        a["name"]
            .as_str()
            .map(|n| n.eq_ignore_ascii_case("SHA256SUMS"))
            .unwrap_or(false)
    })
}

fn expected_sha_for(sha_text: &str, asset_name: &str) -> Option<String> {
    // Lines look like "<hex>  <filename>" or "<hex> *<filename>"; the
    // name column may be a relative path, so match by basename.
    let target = basename(asset_name);
    for line in sha_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else { continue };
        let Some(name) = parts.next() else { continue };
        let name = name.trim_start_matches('*');
        if basename(name) == target {
            return Some(hash.to_string());
        }
    }
    // Single-asset `.sha256` file: just the hash.
    let stripped = sha_text.trim();
    if stripped.len() == 64 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(stripped.to_string());
    }
    None
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

// ---------------------------------------------------------------------------
// Download, verify, extract, stage.
// ---------------------------------------------------------------------------

async fn stage_release(release: &Value, version: &str) -> Result<()> {
    let staged_binary = download_verify_extract(release, version).await?;
    write_pending_marker(&staged_binary, version)?;
    tracing::info!(
        "self-update staged {version} at {} (apply on next launch)",
        staged_binary.display()
    );
    Ok(())
}

/// Download the platform asset, SHA-256-verify it, and extract the
/// embedded `myownmesh` binary. Returns the path of the verified
/// executable. Does NOT write `pending.json`.
async fn download_verify_extract(release: &Value, version: &str) -> Result<PathBuf> {
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| Error::msg("release missing assets"))?;
    let asset = pick_daemon_asset(assets).ok_or_else(|| {
        Error::msg(format!(
            "no release asset matches this platform ({})",
            current_platform()
        ))
    })?;
    let dl_url = asset["browser_download_url"]
        .as_str()
        .ok_or_else(|| Error::msg("asset missing browser_download_url"))?;
    let asset_name = asset["name"].as_str().unwrap_or("myownmesh").to_string();

    let updates_dir = myownmesh_core::dirs::updates_dir()?.join(version);
    std::fs::create_dir_all(&updates_dir)?;
    let archive_path = updates_dir.join(&asset_name);
    let part_path = updates_dir.join(format!("{asset_name}.part"));

    let client = http_client(Duration::from_secs(300))?;
    let bytes = client
        .get(dl_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    std::fs::write(&part_path, &bytes)?;

    if let Some(sha_asset) = pick_sha_asset(assets, &asset_name) {
        let sha_url = sha_asset["browser_download_url"]
            .as_str()
            .ok_or_else(|| Error::msg("sha asset missing url"))?;
        let sha_text = client
            .get(sha_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let expected = expected_sha_for(&sha_text, &asset_name)
            .ok_or_else(|| Error::msg(format!("checksum file lists no entry for {asset_name}")))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual = hex::encode(hasher.finalize());
        if !actual.eq_ignore_ascii_case(&expected) {
            let _ = std::fs::remove_file(&part_path);
            return Err(Error::ChecksumMismatch {
                asset: asset_name,
                expected,
                actual,
            });
        }
    } else {
        tracing::warn!("no checksum sidecar for {asset_name}; skipping integrity check");
    }

    std::fs::rename(&part_path, &archive_path)?;
    let binary = extract_binary_if_archived(&archive_path, &updates_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&binary)?.permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&binary, perms);
    }

    Ok(binary)
}

fn write_pending_marker(staged: &Path, version: &str) -> Result<()> {
    let pending_path = myownmesh_core::dirs::updates_dir()?.join("pending.json");
    if let Some(parent) = pending_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let doc = serde_json::json!({
        "version": version,
        "path": staged.to_string_lossy(),
        "staged_at": iso_now(),
    });
    std::fs::write(&pending_path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

/// If `archive` is a tar.gz / tgz / zip, extract via the system `tar`
/// and return the path to the embedded `myownmesh` (or `myownmesh.exe`).
/// If it's already a raw binary, return it unchanged.
///
/// Uses the system `tar`, which is libarchive-backed on every target we
/// ship for (macOS, Linux, Windows 10 1803+) and auto-detects gzipped
/// tarballs and zips via `tar -xf`.
fn extract_binary_if_archived(archive: &Path, dest_dir: &Path) -> Result<PathBuf> {
    let name = archive.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // Never treat a sidecar as the binary — a stale marker could point at
    // one, and atomic_replace would clobber the live binary with it.
    if is_sidecar_asset(name) {
        return Err(Error::msg(format!(
            "refusing to install sidecar `{name}` as the myownmesh binary"
        )));
    }
    let is_archive = name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".zip");
    if !is_archive {
        return Ok(archive.to_path_buf());
    }

    #[cfg(windows)]
    let bin_name = "myownmesh.exe";
    #[cfg(not(windows))]
    let bin_name = "myownmesh";

    let bin_path = dest_dir.join(bin_name);
    // Wipe any stale extract so the file in place is from THIS archive.
    let _ = std::fs::remove_file(&bin_path);

    let status = std::process::Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest_dir)
        .status()
        .map_err(|e| {
            Error::msg(format!(
                "failed to spawn `tar` for {}: {e}",
                archive.display()
            ))
        })?;
    if !status.success() {
        return Err(Error::msg(format!(
            "tar exited with {status} extracting {}",
            archive.display()
        )));
    }
    if !bin_path.exists() {
        return Err(Error::msg(format!(
            "extracted archive does not contain `{bin_name}`"
        )));
    }
    Ok(bin_path)
}

// ---------------------------------------------------------------------------
// Atomic file replacement.
// ---------------------------------------------------------------------------

fn atomic_replace(staged: &Path, target: &Path) -> Result<()> {
    // Copy the staged binary into a sibling temp of the target, then
    // rename it into place. The sibling keeps src and dst on the same
    // filesystem so the rename is atomic.
    let target_dir = target
        .parent()
        .ok_or_else(|| Error::msg("target has no parent"))?;
    let tmp = target_dir.join(format!(".myownmesh-update-{}.tmp", std::process::id()));
    std::fs::copy(staged, &tmp).map_err(|e| {
        Error::msg(format!(
            "cannot copy staged binary into {}: {e}",
            target_dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&tmp, perms);
    }

    // Unix allows replacing a running executable; the running process
    // keeps the old inode until exit. Windows blocks renaming an open
    // .exe, so we side-rename the running binary to `<exe>.old` (which
    // Windows DOES allow while mapped) and move the new one into place.
    #[cfg(unix)]
    {
        std::fs::rename(&tmp, target)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        match std::fs::rename(&tmp, target) {
            Ok(()) => Ok(()),
            Err(_) => rename_into_place_via_side_swap_windows(&tmp, target),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::rename(&tmp, target)?;
        Ok(())
    }
}

#[cfg(windows)]
fn rename_into_place_via_side_swap_windows(src: &Path, dst: &Path) -> Result<()> {
    let old = old_binary_path(dst);
    if old.exists() {
        let _ = std::fs::remove_file(&old);
    }
    std::fs::rename(dst, &old).map_err(|e| {
        Error::msg(format!(
            "could not rename running binary aside to {}: {e}",
            old.display()
        ))
    })?;
    if let Err(e) = std::fs::rename(src, dst) {
        // Roll back so we never leave the install without a binary.
        let _ = std::fs::rename(&old, dst);
        return Err(Error::msg(format!(
            "swap-in failed after side-rename ({e}); restored original binary"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn old_binary_path(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from("myownmesh"));
    name.push(".old");
    target.with_file_name(name)
}

/// Delete the `<exe>.old` left by a previous Windows side-swap. Cheap,
/// idempotent, runs at startup.
fn cleanup_old_replaced_binary() {
    #[cfg(windows)]
    if let Ok(exe) = std::env::current_exe() {
        let old = old_binary_path(&exe);
        if old.exists() {
            let _ = std::fs::remove_file(&old);
        }
    }
}

// ---------------------------------------------------------------------------
// Check-interval gating + timestamps.
// ---------------------------------------------------------------------------

fn check_marker_path() -> Result<PathBuf> {
    Ok(myownmesh_core::dirs::updates_dir()?.join("last-check"))
}

fn is_due(interval_hours: u32) -> Result<bool> {
    let path = check_marker_path()?;
    if !path.exists() {
        return Ok(true);
    }
    let s = std::fs::read_to_string(&path).unwrap_or_default();
    let prev = s.trim().parse::<i64>().unwrap_or(0);
    let elapsed_h = (unix_secs() - prev) as f64 / 3600.0;
    Ok(elapsed_h >= interval_hours as f64)
}

fn stamp_check_now() -> Result<()> {
    let path = check_marker_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, format!("{}\n", unix_secs()))?;
    Ok(())
}

fn last_check_at() -> Option<i64> {
    let path = check_marker_path().ok()?;
    let s = std::fs::read_to_string(path).ok()?;
    s.trim().parse::<i64>().ok()
}

fn staged_version() -> Option<String> {
    let pending = myownmesh_core::dirs::updates_dir()
        .ok()?
        .join("pending.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(pending).ok()?).ok()?;
    doc.get("version")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Minimal ISO-8601 UTC timestamp (civil-from-days), no chrono dep.
fn iso_now() -> String {
    let secs = unix_secs();
    let z = secs + 719_468 * 86_400;
    let days = z.div_euclid(86_400);
    let secs_of_day = z.rem_euclid(86_400);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day / 60) % 60;
    let ss = secs_of_day % 60;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y_adj = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y_adj + 1 } else { y_adj };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn picks_daemon_not_gui_or_sidecar() {
        // A realistic post-#22 release for the current platform: the GUI
        // archive and the daemon's own sidecar both carry the platform
        // substring and are listed *before* the daemon, so a naive
        // `.contains()` scan would grab the wrong one.
        let platform = current_platform();
        let ext = archive_ext();
        let daemon = format!("myownmesh-{platform}.{ext}");
        let gui = format!("myownmesh-gui-{platform}.{ext}");
        let sidecar = format!("{daemon}.sha256");
        let a = [
            json!({"name": sidecar, "browser_download_url": "https://x/sha"}),
            json!({"name": gui, "browser_download_url": "https://x/gui"}),
            json!({"name": daemon, "browser_download_url": "https://x/daemon"}),
            json!({"name": "MyOwnMesh_0.1.5_amd64.deb", "browser_download_url": "https://x/deb"}),
        ];
        let picked = pick_daemon_asset(&a).expect("daemon archive should match");
        assert_eq!(picked["name"].as_str(), Some(daemon.as_str()));
    }

    #[test]
    fn sidecars_are_rejected() {
        assert!(is_sidecar_asset("myownmesh-linux-x86_64.tar.gz.sha256"));
        assert!(is_sidecar_asset("thing.sig"));
        assert!(!is_sidecar_asset("myownmesh-linux-x86_64.tar.gz"));
    }

    #[test]
    fn sha_sums_matched_by_basename() {
        let sums = "deadbeef00000000000000000000000000000000000000000000000000000000  dist-bin/myownmesh-linux-x86_64.tar.gz\n\
                    cafef00d00000000000000000000000000000000000000000000000000000000  myownmesh-gui-linux-x86_64.tar.gz\n";
        let got = expected_sha_for(sums, "myownmesh-linux-x86_64.tar.gz");
        assert_eq!(
            got.as_deref(),
            Some("deadbeef00000000000000000000000000000000000000000000000000000000")
        );
    }

    #[test]
    fn sha_single_hash_file() {
        let single = "  ABCDEF0000000000000000000000000000000000000000000000000000000000\n";
        let got = expected_sha_for(single, "anything.tar.gz");
        assert_eq!(
            got.as_deref(),
            Some("ABCDEF0000000000000000000000000000000000000000000000000000000000")
        );
    }

    #[test]
    fn pm_paths_detected() {
        assert_eq!(
            detect_install_kind_from_path("/opt/homebrew/bin/myownmesh"),
            InstallKind::PackageManager
        );
        assert_eq!(
            detect_install_kind_from_path("/home/user/.local/bin/myownmesh"),
            InstallKind::Raw
        );
    }

    #[test]
    fn iso_now_is_well_formed() {
        let s = iso_now();
        // YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(s.len(), 20, "got {s}");
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
    }
}
