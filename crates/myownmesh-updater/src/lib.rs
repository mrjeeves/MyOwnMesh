//! Self-update for MyOwnMesh.
//!
//! Ported from MyOwnLLM's `src-tauri/src/self_update.rs`. The daemon
//! is set-it-and-forget-it: a background ticker periodically checks the
//! configured release feed and, per the user's `auto_apply` policy:
//!
//!   1. Downloads the platform asset(s) — `myownmesh-<platform>.{tar.gz,zip}`
//!      and, when a GUI is installed beside the daemon, the matching
//!      `myownmesh-gui-<platform>` archive — SHA-256-verifying each
//!      against its sidecar (or `SHA256SUMS`).
//!   2. Extracts the embedded binaries into `~/.myownmesh/updates/<version>/`.
//!   3. Writes `~/.myownmesh/updates/pending.json` so the next process
//!      start applies them.
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
//! Both halves of a portable install are kept in lockstep: the
//! `myownmesh` daemon binary *and*, when one is installed beside it, the
//! `myownmesh-gui` desktop binary. Every release publishes a
//! `myownmesh-gui-<platform>` archive next to the daemon's, so when we
//! stage an update we stage both and the next launch swaps both — the
//! GUI no longer drifts to an older version than the daemon it spawns. A
//! headless box with no GUI installed just updates the daemon; a macOS
//! `.app` / Linux `.deb` desktop bundle is owned by its own installer
//! and is left alone (same rule as package-manager installs).
//!
//! An explicit `myownmesh update` (see [`update_now`]) does the whole
//! thing in one shot — check, download, verify, apply both binaries —
//! mirroring MyOwnLLM's single `myownllm update` command.

pub mod policy;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
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
    /// True when `release_url` comes from a config override
    /// (`auto_update.{stable,beta}_url`) rather than the build-time /
    /// GitHub default — i.e. the feed has been white-labelled.
    pub release_url_overridden: bool,
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

/// Result of an explicit `myownmesh update` (see [`update_now`]). Unlike
/// [`CheckOutcome`] this reflects an *applied* update — the binaries on
/// disk have already been swapped; the running processes pick the new
/// code up on restart.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum UpdateNowOutcome {
    /// Package-manager install — deferred to the system updater.
    PackageManager,
    /// Already on the latest published version; nothing to do.
    UpToDate { current: String, latest: String },
    /// Updated. `components` lists what was swapped (`daemon`, `gui`).
    Updated { to: String, components: Vec<String> },
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
    let target_version = doc["version"].as_str().unwrap_or("?").to_string();

    let artifacts = parse_pending_artifacts(&doc);
    if artifacts.is_empty() {
        let _ = std::fs::remove_file(&pending);
        return Err(Error::msg(
            "pending.json lists no artifacts — clearing marker",
        ));
    }

    // Daemon first (the required half), then the GUI (best-effort). Each
    // half carries its own downgrade guard (see `artifact_needs_apply`) so
    // a stale marker can't roll a binary back, and so a GUI that lags an
    // already-current daemon still catches up. A GUI that can't swap —
    // it's open on Windows, or was uninstalled since staging — logs and is
    // skipped rather than wedging boot or blocking the daemon update.
    let mut order: Vec<&StagedArtifact> = artifacts.iter().collect();
    order.sort_by_key(|a| if a.kind == ArtifactKind::Daemon { 0 } else { 1 });

    let mut applied: Vec<&'static str> = Vec::new();
    for art in order {
        if !artifact_needs_apply(art.kind, &target_version) {
            continue;
        }
        match apply_one(art) {
            Ok(true) => {
                applied.push(art.kind.as_str());
                // Stamp the GUI version so a current daemon can later tell
                // the GUI is up to date (the GUI binary has no readable
                // version of its own from here).
                if art.kind == ArtifactKind::Gui {
                    record_gui_version(&target_version);
                }
            }
            Ok(false) => {} // nothing installed to replace (e.g. no GUI here)
            Err(e) => {
                if art.kind == ArtifactKind::Daemon {
                    // Leave the marker in place so the next launch retries
                    // rather than silently dropping the update.
                    return Err(e);
                }
                tracing::warn!("self-update: {} apply skipped: {e}", art.kind.as_str());
            }
        }
    }

    let _ = std::fs::remove_file(&pending);
    if applied.is_empty() {
        return Ok(None);
    }
    tracing::info!(
        "self-update applied {target_version} ({})",
        applied.join("+")
    );
    Ok(Some(target_version))
}

/// Per-artifact downgrade guard: only swap a binary when `target_version`
/// is strictly newer than what's installed. The daemon compares against
/// its own running version; the GUI against the version stamp the updater
/// last wrote (absent stamp ⇒ unknown ⇒ allow, so a GUI installed out of
/// band by the shell installer gets synced on the first update). This is
/// what lets `myownmesh update` repair a GUI that's a version behind an
/// already-current daemon — the exact "daemon updated, GUI didn't" drift.
fn artifact_needs_apply(kind: ArtifactKind, target_version: &str) -> bool {
    match kind {
        ArtifactKind::Daemon => version_is_newer(target_version, Some(current_version())),
        ArtifactKind::Gui => version_is_newer(target_version, installed_gui_version().as_deref()),
    }
}

/// True when `target` is strictly newer than `installed`, treating an
/// unknown (`None`) installed version as "needs update" so an out-of-band
/// install gets synced once.
fn version_is_newer(target: &str, installed: Option<&str>) -> bool {
    match installed {
        Some(v) => compare_semver(target, v) == std::cmp::Ordering::Greater,
        None => true,
    }
}

/// Swap one staged artifact over its installed counterpart. `Ok(true)`
/// when a swap happened, `Ok(false)` when there was nothing to replace
/// (e.g. a staged GUI but no GUI installed on this host).
fn apply_one(art: &StagedArtifact) -> Result<bool> {
    if !art.staged.exists() {
        return Err(Error::msg(format!(
            "staged {} binary {} missing",
            art.kind.as_str(),
            art.staged.display()
        )));
    }
    // Tolerate a legacy marker that points at the archive itself: extract
    // on the fly so we never rename a .tar.gz over the live binary.
    let staged_dir = art
        .staged
        .parent()
        .ok_or_else(|| Error::msg("staged path has no parent"))?;
    let staged = extract_binary_if_archived(&art.staged, staged_dir, art.kind.bin_name())?;

    let target = match resolve_apply_target(art.kind)? {
        Some(t) => t,
        None => return Ok(false),
    };
    atomic_replace(&staged, &target)?;
    Ok(true)
}

/// Installed path a staged artifact replaces: the running executable for
/// the daemon, the located GUI binary for the GUI (or `None` when no GUI
/// is installed on this host).
fn resolve_apply_target(kind: ArtifactKind) -> Result<Option<PathBuf>> {
    match kind {
        ArtifactKind::Daemon => Ok(Some(std::env::current_exe()?)),
        ArtifactKind::Gui => Ok(find_installed_gui_binary()),
    }
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

    // Stage the daemon (it's behind — we're past the up-to-date check) and
    // the GUI beside it when that's behind too, so both land in lockstep.
    let mut want = vec![ArtifactKind::Daemon];
    if gui_needs_update(&latest) {
        want.push(ArtifactKind::Gui);
    }
    stage_release(&release, &latest, &want).await?;
    Ok(CheckOutcome::Staged { version: latest })
}

/// Explicit, user-driven "update everything now" — the surface behind a
/// bare `myownmesh update`, mirroring MyOwnLLM's `myownllm update`.
///
/// Unlike the background ticker this ignores the `auto_apply` policy and
/// the check interval (the user asked for it, so consent is implied) and
/// runs even when background checks are disabled in config — but it still
/// defers to the OS package manager, which owns versioning for those
/// installs. Brings every installed half up to the latest release: the
/// daemon if it's behind, and the GUI beside it if its version stamp is
/// behind or unknown (the "daemon updated, GUI didn't" drift). Applies to
/// disk immediately and reports what changed; the running processes keep
/// their old code until restarted.
pub async fn update_now() -> Result<UpdateNowOutcome> {
    if detect_install_kind() == InstallKind::PackageManager {
        mark_pm_detected();
        return Ok(UpdateNowOutcome::PackageManager);
    }

    let au = load_auto_update().unwrap_or_default();
    let release = fetch_release(&au).await?;
    let latest = release["tag_name"]
        .as_str()
        .map(|s| s.trim_start_matches('v').to_string())
        .ok_or_else(|| Error::msg("release missing tag_name"))?;
    let current = current_version().to_string();

    let mut want = Vec::new();
    if compare_semver(&current, &latest) == std::cmp::Ordering::Less {
        want.push(ArtifactKind::Daemon);
    }
    if gui_needs_update(&latest) {
        want.push(ArtifactKind::Gui);
    }

    if want.is_empty() {
        return Ok(UpdateNowOutcome::UpToDate { current, latest });
    }

    stamp_check_now()?;
    let kinds = stage_release(&release, &latest, &want).await?;
    // Apply right now rather than waiting for the next launch.
    apply_now()?;

    Ok(UpdateNowOutcome::Updated {
        to: latest,
        components: kinds.iter().map(|k| k.as_str().to_string()).collect(),
    })
}

/// Current updater status (no network access).
pub fn status() -> Result<UpdateStatus> {
    let au = load_auto_update().unwrap_or_default();
    let override_url = if au.channel == "beta" {
        au.beta_url.as_deref()
    } else {
        au.stable_url.as_deref()
    };
    let release_url_overridden = override_url.map(|s| !s.is_empty()).unwrap_or(false);
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
        release_url_overridden,
    })
}

/// Flip `auto_update.enabled` in `~/.myownmesh/config.json`.
pub fn set_enabled(enabled: bool) -> Result<()> {
    set_prefs(UpdatePrefs {
        enabled: Some(enabled),
        ..Default::default()
    })
    .map(|_| ())
}

/// Editable updater preferences. Every field is optional — `None` leaves
/// the stored value untouched — so the GUI/CLI can apply a partial edit
/// (toggle auto-update, switch channel, repoint the release feed) without
/// re-sending the whole config.
///
/// `stable_url` / `beta_url` are the white-labelling hook: a vendor can
/// point the same binary at their own release host at runtime. An empty
/// string clears the override (revert to the build-time / GitHub
/// default); a non-empty value pins that feed.
#[derive(Debug, Default, Deserialize)]
pub struct UpdatePrefs {
    pub enabled: Option<bool>,
    pub channel: Option<String>,
    pub auto_apply: Option<String>,
    pub check_interval_hours: Option<u32>,
    pub stable_url: Option<String>,
    pub beta_url: Option<String>,
}

/// Apply a partial preferences update to `~/.myownmesh/config.json`,
/// validating the enumerated fields, and return the resulting status.
/// The single write-through point the GUI and CLI use to change updater
/// settings. The daemon re-reads config each tick, so changes take effect
/// without a restart.
pub fn set_prefs(prefs: UpdatePrefs) -> Result<UpdateStatus> {
    let mut cfg = MeshConfig::load()?;
    let au = &mut cfg.auto_update;
    if let Some(v) = prefs.enabled {
        au.enabled = v;
    }
    if let Some(v) = prefs.channel {
        if v != "stable" && v != "beta" {
            return Err(Error::msg(format!(
                "invalid update channel '{v}' (expected 'stable' or 'beta')"
            )));
        }
        au.channel = v;
    }
    if let Some(v) = prefs.auto_apply {
        if ApplyPolicy::parse(&v).is_none() {
            return Err(Error::msg(format!(
                "invalid auto_apply policy '{v}' (expected patch | minor | all | none)"
            )));
        }
        au.auto_apply = v;
    }
    if let Some(v) = prefs.check_interval_hours {
        // Clamp to a sane floor so a fat-fingered 0 doesn't spin the
        // background ticker hot.
        au.check_interval_hours = v.max(1);
    }
    if let Some(v) = prefs.stable_url {
        au.stable_url = normalise_url_override(v);
    }
    if let Some(v) = prefs.beta_url {
        au.beta_url = normalise_url_override(v);
    }
    cfg.save()?;
    status()
}

/// An empty/whitespace override clears back to the default feed; anything
/// else is trimmed and stored verbatim.
fn normalise_url_override(v: String) -> Option<String> {
    let t = v.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
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

/// Platform-specific name of the GUI executable.
fn gui_exe_name() -> &'static str {
    if cfg!(windows) {
        "myownmesh-gui.exe"
    } else {
        "myownmesh-gui"
    }
}

/// Locate an installed `myownmesh-gui` binary so the updater can keep it
/// in lockstep with the daemon. This is the *inverse* of the daemon's own
/// `find_gui_binary` (in `crates/myownmesh/src/cli/gui.rs`) and looks in
/// the same places, minus the dev-artefact fallback — we never swap a
/// `cargo`/`tauri dev` build output from under a contributor:
///
///   1. `MYOWNMESH_GUI_BIN` (explicit override).
///   2. Beside the running daemon — the portable install drops
///      `myownmesh` and `myownmesh-gui` side by side, so the sibling
///      path is the common case.
///   3. `myownmesh-gui` on `$PATH`.
///
/// Returns `None` when no portable GUI is installed (headless box) or
/// when the GUI lives inside an OS bundle the updater shouldn't touch
/// (a macOS `.app`, a Linux `.deb`) — neither is a daemon sibling nor on
/// `$PATH`, so the daemon updates alone and the bundle's own installer
/// owns the GUI.
fn find_installed_gui_binary() -> Option<PathBuf> {
    let exe = gui_exe_name();

    if let Some(p) = std::env::var_os("MYOWNMESH_GUI_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }

    if let Ok(current) = std::env::current_exe() {
        if let Some(candidate) = current.parent().map(|dir| dir.join(exe)) {
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(exe);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

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

/// Pick the **GUI** asset (`myownmesh-gui-<platform>...`) for the current
/// platform — the counterpart to [`pick_daemon_asset`]. Matches the exact
/// published name first, then a guarded substring scan, skipping sidecars
/// (`.sha256`, signatures). Returns `None` when the release predates the
/// portable GUI binary (older tags shipped the daemon only); callers
/// treat a missing GUI asset as "update the daemon, skip the GUI".
fn pick_gui_asset(assets: &[Value]) -> Option<&Value> {
    let platform = current_platform();
    let exact = format!("myownmesh-gui-{platform}.{}", archive_ext());
    if let Some(a) = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(exact.as_str()))
    {
        return Some(a);
    }
    assets.iter().find(|a| {
        a["name"].as_str().is_some_and(|n| {
            n.starts_with("myownmesh-gui-")
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

/// Which executable a staged artifact replaces. A release bumps the
/// daemon and the GUI together, so an update stages one of each (when a
/// GUI is installed) and the next launch applies both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    Daemon,
    Gui,
}

impl ArtifactKind {
    fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Daemon => "daemon",
            ArtifactKind::Gui => "gui",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "daemon" => Some(ArtifactKind::Daemon),
            "gui" => Some(ArtifactKind::Gui),
            _ => None,
        }
    }

    /// Name of the executable embedded in this kind's release archive.
    fn bin_name(self) -> &'static str {
        match self {
            ArtifactKind::Daemon => {
                if cfg!(windows) {
                    "myownmesh.exe"
                } else {
                    "myownmesh"
                }
            }
            ArtifactKind::Gui => gui_exe_name(),
        }
    }
}

/// A verified binary extracted into the staging dir, waiting to be
/// swapped over its installed counterpart on the next launch.
#[derive(Debug, Clone)]
struct StagedArtifact {
    kind: ArtifactKind,
    staged: PathBuf,
}

/// Download, verify, and extract the `want`ed artifacts of a release,
/// then record them in `pending.json` for apply-on-next-launch. The
/// daemon (when wanted) is required — no asset for this platform is a hard
/// error. The GUI is best-effort: a missing GUI asset (older release) or a
/// transient download error logs and continues so a GUI hiccup never
/// blocks the security-relevant daemon update. Returns the kinds actually
/// staged. Does NOT apply — that happens on the next launch (or
/// immediately via [`apply_now`] for an explicit `update`).
async fn stage_release(
    release: &Value,
    version: &str,
    want: &[ArtifactKind],
) -> Result<Vec<ArtifactKind>> {
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| Error::msg("release missing assets"))?;

    let updates_dir = myownmesh_core::dirs::updates_dir()?.join(version);
    std::fs::create_dir_all(&updates_dir)?;
    let client = http_client(Duration::from_secs(300))?;

    let mut staged: Vec<StagedArtifact> = Vec::new();

    if want.contains(&ArtifactKind::Daemon) {
        let daemon_asset = pick_daemon_asset(assets).ok_or_else(|| {
            Error::msg(format!(
                "no daemon release asset matches this platform ({})",
                current_platform()
            ))
        })?;
        let daemon_bin = download_verify_stage(
            &client,
            assets,
            &updates_dir,
            daemon_asset,
            ArtifactKind::Daemon,
        )
        .await?;
        staged.push(StagedArtifact {
            kind: ArtifactKind::Daemon,
            staged: daemon_bin,
        });
    }

    if want.contains(&ArtifactKind::Gui) {
        match pick_gui_asset(assets) {
            Some(gui_asset) => {
                match download_verify_stage(
                    &client,
                    assets,
                    &updates_dir,
                    gui_asset,
                    ArtifactKind::Gui,
                )
                .await
                {
                    Ok(gui_bin) => staged.push(StagedArtifact {
                        kind: ArtifactKind::Gui,
                        staged: gui_bin,
                    }),
                    Err(e) => tracing::warn!("GUI update staging failed ({e}); skipping the GUI"),
                }
            }
            None => tracing::warn!(
                "release has no GUI asset for {}; skipping the GUI",
                current_platform()
            ),
        }
    }

    if staged.is_empty() {
        return Err(Error::msg("nothing to stage"));
    }

    write_pending_marker(version, &staged)?;
    let kinds: Vec<ArtifactKind> = staged.iter().map(|a| a.kind).collect();
    tracing::info!(
        "self-update staged {version} ({}) under {} (apply on next launch)",
        kinds
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join("+"),
        updates_dir.display()
    );
    Ok(kinds)
}

/// Download one release asset, SHA-256-verify it against its sidecar (or
/// `SHA256SUMS`), and extract the embedded `kind` binary. Returns the
/// path of the verified executable. Does NOT write `pending.json`.
async fn download_verify_stage(
    client: &reqwest::Client,
    assets: &[Value],
    updates_dir: &Path,
    asset: &Value,
    kind: ArtifactKind,
) -> Result<PathBuf> {
    let dl_url = asset["browser_download_url"]
        .as_str()
        .ok_or_else(|| Error::msg("asset missing browser_download_url"))?;
    let asset_name = asset["name"]
        .as_str()
        .unwrap_or(kind.bin_name())
        .to_string();

    let archive_path = updates_dir.join(&asset_name);
    let part_path = updates_dir.join(format!("{asset_name}.part"));

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
    let binary = extract_binary_if_archived(&archive_path, updates_dir, kind.bin_name())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&binary)?.permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&binary, perms);
    }

    Ok(binary)
}

/// Build the `pending.json` document for a set of staged artifacts. The
/// `artifacts` array is the current format; we also keep a top-level
/// `path` pointing at the daemon binary so an older `myownmesh` that only
/// understands the single-binary marker still applies the daemon half.
fn pending_doc(version: &str, artifacts: &[StagedArtifact]) -> Value {
    let arts: Vec<Value> = artifacts
        .iter()
        .map(|a| {
            serde_json::json!({
                "kind": a.kind.as_str(),
                "path": a.staged.to_string_lossy(),
            })
        })
        .collect();
    let mut doc = serde_json::json!({
        "version": version,
        "artifacts": arts,
        "staged_at": iso_now(),
    });
    if let Some(daemon) = artifacts.iter().find(|a| a.kind == ArtifactKind::Daemon) {
        doc["path"] = Value::String(daemon.staged.to_string_lossy().into_owned());
    }
    doc
}

/// Parse the staged-artifact list out of a `pending.json` document.
/// Prefers the `artifacts` array; falls back to a legacy single-binary
/// marker (`{ version, path }`), which is always the daemon.
fn parse_pending_artifacts(doc: &Value) -> Vec<StagedArtifact> {
    if let Some(arr) = doc.get("artifacts").and_then(Value::as_array) {
        let mut out = Vec::new();
        for a in arr {
            let kind = a
                .get("kind")
                .and_then(Value::as_str)
                .and_then(ArtifactKind::parse);
            let path = a.get("path").and_then(Value::as_str);
            if let (Some(kind), Some(path)) = (kind, path) {
                out.push(StagedArtifact {
                    kind,
                    staged: PathBuf::from(path),
                });
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    if let Some(path) = doc.get("path").and_then(Value::as_str) {
        return vec![StagedArtifact {
            kind: ArtifactKind::Daemon,
            staged: PathBuf::from(path),
        }];
    }
    Vec::new()
}

fn write_pending_marker(version: &str, artifacts: &[StagedArtifact]) -> Result<()> {
    let pending_path = myownmesh_core::dirs::updates_dir()?.join("pending.json");
    if let Some(parent) = pending_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let doc = pending_doc(version, artifacts);
    std::fs::write(&pending_path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

/// If `archive` is a tar.gz / tgz / zip, extract via the system `tar`
/// and return the path to the embedded `bin_name` (e.g. `myownmesh` or
/// `myownmesh-gui`). If it's already a raw binary, return it unchanged.
///
/// Uses the system `tar`, which is libarchive-backed on every target we
/// ship for (macOS, Linux, Windows 10 1803+) and auto-detects gzipped
/// tarballs and zips via `tar -xf`.
fn extract_binary_if_archived(archive: &Path, dest_dir: &Path, bin_name: &str) -> Result<PathBuf> {
    let name = archive.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // Never treat a sidecar as the binary — a stale marker could point at
    // one, and atomic_replace would clobber the live binary with it.
    if is_sidecar_asset(name) {
        return Err(Error::msg(format!(
            "refusing to install sidecar `{name}` as the {bin_name} binary"
        )));
    }
    let is_archive = name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".zip");
    if !is_archive {
        return Ok(archive.to_path_buf());
    }

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

/// Delete the `<exe>.old` files left by a previous Windows side-swap —
/// both the daemon's own and, if a portable GUI is installed beside us,
/// the GUI's (a daemon can side-swap the GUI binary while the GUI is
/// running). Cheap, idempotent, runs at startup.
fn cleanup_old_replaced_binary() {
    #[cfg(windows)]
    {
        if let Ok(exe) = std::env::current_exe() {
            let old = old_binary_path(&exe);
            if old.exists() {
                let _ = std::fs::remove_file(&old);
            }
        }
        if let Some(gui) = find_installed_gui_binary() {
            let old = old_binary_path(&gui);
            if old.exists() {
                let _ = std::fs::remove_file(&old);
            }
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

// ---------------------------------------------------------------------------
// GUI version stamp.
//
// The GUI binary exposes no version we can read from here (running it just
// opens a window), so the updater records the version it last installed
// for the GUI in `~/.myownmesh/updates/gui.version`. That lets an
// already-current daemon notice the GUI lagging behind it and resync — the
// "daemon updated, GUI didn't" drift this whole change is about.
// ---------------------------------------------------------------------------

fn gui_version_marker_path() -> Result<PathBuf> {
    Ok(myownmesh_core::dirs::updates_dir()?.join("gui.version"))
}

/// Version the updater last installed for the GUI, or `None` when it has
/// never installed one (a fresh shell-installer GUI has no stamp yet).
fn installed_gui_version() -> Option<String> {
    let s = std::fs::read_to_string(gui_version_marker_path().ok()?).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn record_gui_version(version: &str) {
    if let Ok(path) = gui_version_marker_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, format!("{version}\n"));
    }
}

/// Whether the GUI beside the daemon should be brought to `latest`. False
/// when no GUI is installed here; otherwise compares `latest` against the
/// recorded stamp (absent ⇒ unknown ⇒ true, so a GUI installed out of band
/// is synced on the first update).
fn gui_needs_update(latest: &str) -> bool {
    if find_installed_gui_binary().is_none() {
        return false;
    }
    version_is_newer(latest, installed_gui_version().as_deref())
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
    fn picks_gui_archive_not_daemon_or_sidecar() {
        // The GUI matcher must grab `myownmesh-gui-<platform>` and not the
        // daemon archive (whose name is a prefix) nor the GUI's own
        // `.sha256` sidecar, which both carry the platform substring.
        let platform = current_platform();
        let ext = archive_ext();
        let daemon = format!("myownmesh-{platform}.{ext}");
        let gui = format!("myownmesh-gui-{platform}.{ext}");
        let a = [
            json!({"name": format!("{gui}.sha256"), "browser_download_url": "https://x/sha"}),
            json!({"name": daemon, "browser_download_url": "https://x/daemon"}),
            json!({"name": gui, "browser_download_url": "https://x/gui"}),
        ];
        let picked = pick_gui_asset(&a).expect("gui archive should match");
        assert_eq!(picked["name"].as_str(), Some(gui.as_str()));
        // And the daemon matcher must never grab the GUI archive.
        assert_eq!(
            pick_daemon_asset(&a).and_then(|d| d["name"].as_str()),
            Some(daemon.as_str())
        );
    }

    #[test]
    fn missing_gui_asset_returns_none() {
        let platform = current_platform();
        let ext = archive_ext();
        let a = [json!({"name": format!("myownmesh-{platform}.{ext}")})];
        assert!(pick_gui_asset(&a).is_none());
    }

    #[test]
    fn pending_doc_roundtrips_daemon_and_gui() {
        let arts = vec![
            StagedArtifact {
                kind: ArtifactKind::Daemon,
                staged: PathBuf::from("/u/0.1.7/myownmesh"),
            },
            StagedArtifact {
                kind: ArtifactKind::Gui,
                staged: PathBuf::from("/u/0.1.7/myownmesh-gui"),
            },
        ];
        let doc = pending_doc("0.1.7", &arts);
        assert_eq!(doc["version"].as_str(), Some("0.1.7"));
        // Back-compat: top-level `path` is the daemon binary, so an older
        // single-binary applier still swaps the daemon.
        assert_eq!(doc["path"].as_str(), Some("/u/0.1.7/myownmesh"));

        let parsed = parse_pending_artifacts(&doc);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, ArtifactKind::Daemon);
        assert_eq!(parsed[1].kind, ArtifactKind::Gui);
        assert_eq!(parsed[1].staged, PathBuf::from("/u/0.1.7/myownmesh-gui"));
    }

    #[test]
    fn pending_legacy_single_path_is_daemon() {
        // A marker written by an older updater: just { version, path }.
        let doc = json!({ "version": "0.1.6", "path": "/u/0.1.6/myownmesh" });
        let parsed = parse_pending_artifacts(&doc);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, ArtifactKind::Daemon);
        assert_eq!(parsed[0].staged, PathBuf::from("/u/0.1.6/myownmesh"));
    }

    #[test]
    fn version_gate_allows_newer_and_unknown_only() {
        // Newer applies; equal/older never downgrades.
        assert!(version_is_newer("0.1.7", Some("0.1.5")));
        assert!(!version_is_newer("0.1.5", Some("0.1.5")));
        assert!(!version_is_newer("0.1.4", Some("0.1.5")));
        // Unknown installed version (no GUI stamp yet) ⇒ sync once. This is
        // what repairs a GUI left a version behind an already-current
        // daemon — the drift `myownmesh update` has to fix.
        assert!(version_is_newer("0.1.7", None));
        // The daemon arm runs through the same gate against its own version.
        assert!(artifact_needs_apply(ArtifactKind::Daemon, "999.0.0"));
        assert!(!artifact_needs_apply(
            ArtifactKind::Daemon,
            current_version()
        ));
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
    fn set_prefs_validates_and_persists() {
        // One tempdir, one sequential test: MYOWNMESH_HOME is process
        // global, so we don't want two of these racing.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", tmp.path());

        // Bad enumerations are rejected before anything is written.
        assert!(set_prefs(UpdatePrefs {
            channel: Some("nightly".into()),
            ..Default::default()
        })
        .is_err());
        assert!(set_prefs(UpdatePrefs {
            auto_apply: Some("whenever".into()),
            ..Default::default()
        })
        .is_err());

        // A valid partial edit persists and is reflected in status.
        let st = set_prefs(UpdatePrefs {
            channel: Some("beta".into()),
            auto_apply: Some("minor".into()),
            check_interval_hours: Some(0), // clamps up to 1
            beta_url: Some("https://vendor.example/releases".into()),
            ..Default::default()
        })
        .expect("set valid prefs");
        assert_eq!(st.channel, "beta");
        assert_eq!(st.auto_apply, "minor");
        assert_eq!(st.check_interval_hours, 1);
        assert_eq!(st.release_url, "https://vendor.example/releases");
        assert!(st.release_url_overridden);

        // An empty override string clears back to the default feed.
        let st = set_prefs(UpdatePrefs {
            beta_url: Some("   ".into()),
            ..Default::default()
        })
        .expect("clear override");
        assert!(!st.release_url_overridden);
        assert_eq!(st.release_url, default_release_api_beta());

        std::env::remove_var("MYOWNMESH_HOME");
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
