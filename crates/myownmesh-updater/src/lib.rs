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
//! On the next start, [`apply_pending_if_any`] applies the daemon first, then
//! the staged GUI, as individual replacements, not an atomic pair. A daemon
//! apply failure leaves the marker for retry; a failed GUI replacement is
//! retained in `pending.json` for a later launch without hiding daemon success.
//! The marker is removed when no unresolved artifacts remain. We never
//! restart a running daemon in place — that would yank the rug out from
//! under in-flight connections. The model is "stage now, apply on next
//! launch."
//!
//! Package-manager installs (Homebrew, dpkg/apt, rpm, MSI, Chocolatey)
//! are detected and skipped — the OS package manager owns versioning
//! there.
//!
//! Both halves of a portable install target the same release: the
//! `myownmesh` daemon binary and an installed portable `myownmesh-gui`.
//! GUI staging and replacement are best-effort, so the versions may differ
//! until the GUI update succeeds; a missing GUI asset or staging failure
//! does not block a daemon update. A
//! headless box with no GUI installed just updates the daemon; a macOS
//! `.app` / Linux `.deb` desktop bundle is owned by its own installer
//! and is left alone (same rule as package-manager installs).
//!
//! An explicit `myownmesh update` (see [`update_now`]) does the whole
//! sequence in one invocation — check, download, verify, apply per artifact —
//! mirroring MyOwnLLM's single `myownllm update` command.

mod policy;

use std::hash::{BuildHasher, Hash, Hasher, RandomState};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
// rebuilding. The feed must return GitHub release-shaped JSON. Changing
// its URL does not change the embedded signing key; a different trust root
// requires rebuilding with that key.
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

const SECONDS_PER_HOUR: u64 = 60 * 60;

/// The minisign public key releases are signed with, baked in at build time.
/// `None` until release signing is configured (set `MYOWNMESH_RELEASE_PUBKEY`
/// to the base64 key when building the shipped binary). When set, a valid
/// detached signature over each artifact is **required** before it is staged —
/// SHA-256 proves integrity, the signature proves provenance.
const RELEASE_PUBKEY: Option<&str> = option_env!("MYOWNMESH_RELEASE_PUBKEY");

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

const UPDATER_OPERATION_CLAIM: myownmesh_core::ResourceClaim =
    myownmesh_core::ResourceClaim::single(
        myownmesh_core::ResourceClass::OpaqueDependencyResidual,
        1,
    );

static APPLY_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Admission plan for one updater operation.
///
/// The updater has no pre-existing coherent lock or funded source root: status
/// is assembled from config and filesystem probes, while checks cross a remote
/// await and may stage files. This deliberately broader residual is therefore
/// acquired before entering the operation and structurally retained with its
/// owned success or error. It makes no exact claim about the dependency graph.
#[must_use = "an updater operation plan must be funded and run or dropped"]
pub struct PreparedUpdaterOperation;

pub fn prepare_operation() -> PreparedUpdaterOperation {
    PreparedUpdaterOperation
}

impl PreparedUpdaterOperation {
    pub const fn claim(&self) -> myownmesh_core::ResourceClaim {
        UPDATER_OPERATION_CLAIM
    }

    #[expect(
        clippy::result_large_err,
        reason = "returning the exact lease on mismatch is allocation-free; boxing allocates on refusal"
    )]
    pub fn run<T>(
        self,
        lease: myownmesh_core::ResourceLease,
        operation: impl FnOnce() -> Result<T>,
    ) -> std::result::Result<FundedUpdaterResult<T>, myownmesh_core::ResourceLease> {
        if lease.claim() != UPDATER_OPERATION_CLAIM {
            return Err(lease);
        }
        Ok(FundedUpdaterResult {
            result: operation(),
            _operation: lease,
        })
    }

    pub async fn run_async<T, F>(
        self,
        lease: myownmesh_core::ResourceLease,
        operation: F,
    ) -> std::result::Result<FundedUpdaterResult<T>, myownmesh_core::ResourceLease>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        if lease.claim() != UPDATER_OPERATION_CLAIM {
            return Err(lease);
        }
        Ok(FundedUpdaterResult {
            result: operation.await,
            _operation: lease,
        })
    }
}

/// One updater success or error coupled to the broader operation residual.
/// Borrowed inspection only; neither branch can escape its owner unfunded.
pub struct FundedUpdaterResult<T> {
    result: Result<T>,
    _operation: myownmesh_core::ResourceLease,
}

impl<T> FundedUpdaterResult<T> {
    pub fn get(&self) -> std::result::Result<&T, &Error> {
        self.result.as_ref()
    }
}

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
    pub feed_request_timeout_ms: u64,
    pub artifact_download_timeout_ms: u64,
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
    /// Updated. `components` lists only actual swaps (`daemon`, `gui`),
    /// not all staged artifacts; optional GUI work can remain pending.
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
/// process start), or `None` if nothing needed replacement. Pending-only
/// failure returns an error; daemon success with GUI pending returns its version.
pub fn apply_now() -> Result<Option<String>> {
    applied_version_outcome(apply_now_detailed())
}

fn applied_version_outcome(applied: Result<Option<AppliedUpdate>>) -> Result<Option<String>> {
    Ok(applied?.map(|result| result.version))
}

#[derive(Debug)]
struct AppliedUpdate {
    version: String,
    components: Vec<&'static str>,
}

fn apply_now_detailed() -> Result<Option<AppliedUpdate>> {
    cleanup_old_replaced_binary();
    apply_pending()
}

fn apply_pending() -> Result<Option<AppliedUpdate>> {
    let dir = myownmesh_core::dirs::updates_dir()?;
    apply_pending_at(&dir, artifact_needs_apply, apply_one, record_gui_version)
}

// Keep path/target seams explicit so local controls exercise the same marker,
// ordering and replacement results without changing process-global homes.
fn apply_pending_at(
    dir: &Path,
    mut needs_apply: impl FnMut(ArtifactKind, &str) -> bool,
    mut apply: impl FnMut(&StagedArtifact, &Path, &str) -> Result<bool>,
    mut record_gui: impl FnMut(&str),
) -> Result<Option<AppliedUpdate>> {
    recover_pending_marker(dir)?;
    let pending = dir.join("pending.json");
    if !pending.exists() {
        return Ok(None);
    }
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&pending)?)?;
    let target_version = doc
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.trim().is_empty())
        .ok_or_else(|| Error::msg("pending.json has no target version"))?
        .to_string();
    validate_safe_component(&target_version, "pending target version")?;

    let artifacts = parse_pending_artifacts(&doc)?;
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
    let mut remaining = Vec::new();
    for art in order {
        if !needs_apply(art.kind, &target_version) {
            continue;
        }
        match apply(art, dir, &target_version) {
            Ok(true) => {
                applied.push(art.kind.as_str());
                // Stamp the GUI version so a current daemon can later tell
                // the GUI is up to date (the GUI binary has no readable
                // version of its own from here).
                if art.kind == ArtifactKind::Gui {
                    record_gui(&target_version);
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
                remaining.push(art.clone());
            }
        }
    }

    if remaining.is_empty() {
        let _ = std::fs::remove_file(&pending);
    } else {
        // Preserve unresolved optional artifacts for the next launch. The
        // daemon result is never hidden behind a best-effort GUI failure.
        write_pending_marker_at(&pending, &target_version, &remaining)?;
    }
    if applied.is_empty() {
        if !remaining.is_empty() {
            return Err(Error::msg(
                "no staged artifacts were applied; unresolved GUI update remains pending",
            ));
        }
        return Ok(None);
    }
    tracing::info!(
        "self-update applied {target_version} ({})",
        applied.join("+")
    );
    Ok(Some(AppliedUpdate {
        version: target_version,
        components: applied,
    }))
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
#[cfg(test)]
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn validate_staged_artifact(
    art: &StagedArtifact,
    updates_dir: &Path,
    target_version: &str,
) -> Result<(PathBuf, Box<[u8]>)> {
    let updates_root = std::fs::canonicalize(updates_dir)?;
    let version_dir = std::fs::canonicalize(updates_dir.join(target_version))?;
    if !version_dir.starts_with(&updates_root) {
        return Err(Error::msg(
            "pending target version escapes updates directory",
        ));
    }
    let staged = std::fs::canonicalize(&art.staged)?;
    if !staged.starts_with(&version_dir) {
        return Err(Error::msg(format!(
            "staged {} path escapes version directory",
            art.kind.as_str()
        )));
    }
    let metadata = std::fs::symlink_metadata(&art.staged)?;
    if !metadata.file_type().is_file() {
        return Err(Error::msg(format!(
            "staged {} path is not a regular file",
            art.kind.as_str()
        )));
    }
    let Some(expected) = art.sha256.as_deref() else {
        return Err(Error::msg(format!(
            "staged {} artifact has no digest",
            art.kind.as_str()
        )));
    };
    let bytes: Box<[u8]> = std::fs::read(&staged)?.into_boxed_slice();
    let actual = sha256_bytes(&bytes);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(Error::msg(format!(
            "staged {} digest mismatch: expected {expected}, got {actual}",
            art.kind.as_str()
        )));
    }
    Ok((staged, bytes))
}

fn apply_one(art: &StagedArtifact, updates_dir: &Path, target_version: &str) -> Result<bool> {
    apply_one_with_target(art, updates_dir, target_version, None, || {})
}

fn apply_one_with_target(
    art: &StagedArtifact,
    updates_dir: &Path,
    target_version: &str,
    target_override: Option<&Path>,
    after_validate: impl FnOnce(),
) -> Result<bool> {
    if !art.staged.exists() {
        return Err(Error::msg(format!(
            "staged {} binary {} missing",
            art.kind.as_str(),
            art.staged.display()
        )));
    }
    // The staged path is revalidated before extraction/replacement so a
    // marker cannot redirect apply outside its version-owned directory.
    let (staged, archive_bytes) = validate_staged_artifact(art, updates_dir, target_version)?;
    after_validate();
    let archive_name = staged
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let binary_bytes =
        materialize_verified_binary(&archive_bytes, archive_name, art.kind.bin_name())?;

    let target = match target_override {
        Some(target) => target.to_path_buf(),
        None => match resolve_apply_target(art.kind)? {
            Some(t) => t,
            None => return Ok(false),
        },
    };
    atomic_replace_bytes(&binary_bytes, &target)?;
    Ok(true)
}

fn materialize_verified_binary(
    archive_bytes: &[u8],
    archive_name: &str,
    binary_name: &str,
) -> Result<Box<[u8]>> {
    if is_sidecar_asset(archive_name) {
        return Err(Error::msg(format!(
            "refusing to install sidecar `{archive_name}` as the {binary_name} binary"
        )));
    }
    if archive_name.ends_with(".tar.gz")
        || archive_name.ends_with(".tgz")
        || archive_name.ends_with(".zip")
    {
        extract_verified_binary_bytes(archive_bytes, archive_name, binary_name)
    } else if archive_bytes.is_empty() {
        Err(Error::msg(format!(
            "raw artifact `{archive_name}` is empty"
        )))
    } else {
        Ok(archive_bytes.to_vec().into_boxed_slice())
    }
}

/// Read the one validated archive member directly from the verified archive
/// bytes. Applying an update must not create, remove, or follow anything in
/// the mutable staging directory after [`validate_staged_artifact`] returns.
fn extract_verified_binary_bytes(
    archive_bytes: &[u8],
    archive_name: &str,
    binary_name: &str,
) -> Result<Box<[u8]>> {
    let members = tar_output(archive_bytes, archive_name, "-tf")?;
    let details = tar_output(archive_bytes, archive_name, "-tvf")?;
    validate_archive_listing(&members, &details, binary_name)?;

    let mut cmd = std::process::Command::new("tar");
    cmd.arg("-xOf").arg("-").arg(binary_name);
    let output = run_tar_with_bytes(cmd, archive_bytes, archive_name)?;
    if !output.status.success() {
        return Err(Error::msg(format!(
            "tar exited with {} reading {} from {}",
            output.status, binary_name, archive_name
        )));
    }
    if output.stdout.is_empty() {
        return Err(Error::msg(format!(
            "archive member `{binary_name}` is empty"
        )));
    }
    Ok(output.stdout.into_boxed_slice())
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
    let au = load_valid_auto_update()?;
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
    let release = fetch_release(&au).await?;
    let latest = release["tag_name"]
        .as_str()
        .map(|s| s.trim_start_matches('v').to_string())
        .ok_or_else(|| Error::msg("release missing tag_name"))?;
    let current = current_version().to_string();

    let outcome = if compare_semver(&current, &latest) != std::cmp::Ordering::Less {
        CheckOutcome::UpToDate { current, latest }
    } else {
        let policy = ApplyPolicy::parse(&au.auto_apply).unwrap_or(ApplyPolicy::Patch);
        if !policy_allows(policy, &current, &latest) {
            CheckOutcome::PolicyBlocked {
                current,
                latest,
                policy: au.auto_apply.clone(),
            }
        } else {
            // Stage the daemon (it's behind — we're past the up-to-date check) and
            // the GUI beside it when behind too. Each artifact is staged and
            // applied independently; an optional GUI failure can leave drift.
            let mut want = vec![ArtifactKind::Daemon];
            if gui_needs_update(&latest) {
                want.push(ArtifactKind::Gui);
            }
            stage_release(&release, &latest, &want, &au).await?;
            CheckOutcome::Staged { version: latest }
        }
    };
    stamp_check_now()?;
    Ok(outcome)
}

/// Explicit, user-driven "update everything now" — the surface behind a
/// bare `myownmesh update`, mirroring MyOwnLLM's `myownllm update`.
///
/// Unlike the background ticker this ignores the `auto_apply` policy and
/// the check interval (the user asked for it, so consent is implied) and
/// runs even when background checks are disabled in config — but it still
/// defers to the OS package manager, which owns versioning for those
/// installs. Attempts each installed artifact against the latest release: the
/// daemon if it's behind, and the GUI beside it if its version stamp is
/// behind or unknown (the "daemon updated, GUI didn't" drift). Applies to
/// disk per artifact and reports only actual swaps; optional GUI staging or
/// replacement can fail independently, with failed replacements kept pending.
/// If nothing was applied, returns an error rather than claiming an update.
/// Running processes keep their old code until restarted.
pub async fn update_now() -> Result<UpdateNowOutcome> {
    let au = load_valid_auto_update()?;
    if detect_install_kind() == InstallKind::PackageManager {
        mark_pm_detected();
        return Ok(UpdateNowOutcome::PackageManager);
    }

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

    stage_release(&release, &latest, &want, &au).await?;
    // Apply right now rather than waiting for the next launch.
    let outcome = applied_update_outcome(apply_now_detailed())?;
    stamp_check_now()?;

    Ok(outcome)
}

fn applied_update_outcome(applied: Result<Option<AppliedUpdate>>) -> Result<UpdateNowOutcome> {
    let applied = applied?
        .filter(|result| !result.components.is_empty())
        .ok_or_else(|| {
            Error::msg("no staged artifacts were applied; inspect update status before retrying")
        })?;
    Ok(UpdateNowOutcome::Updated {
        to: applied.version,
        components: applied.components.into_iter().map(str::to_owned).collect(),
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
        feed_request_timeout_ms: au.feed_request_timeout_ms,
        artifact_download_timeout_ms: au.artifact_download_timeout_ms,
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
/// point the same binary at a GitHub release-shaped JSON feed at runtime.
/// The override preserves the embedded signing key and signature policy;
/// a different trust root requires rebuilding the binary with that key.
/// An empty string clears the override (revert to the build-time / GitHub
/// default); a non-empty value pins that feed, not a new signing authority.
#[derive(Debug, Default, Deserialize)]
pub struct UpdatePrefs {
    pub enabled: Option<bool>,
    pub channel: Option<String>,
    pub auto_apply: Option<String>,
    pub check_interval_hours: Option<u32>,
    pub feed_request_timeout_ms: Option<u64>,
    pub artifact_download_timeout_ms: Option<u64>,
    pub stable_url: Option<String>,
    pub beta_url: Option<String>,
}

/// Apply a partial preferences update to `~/.myownmesh/config.json`,
/// validating the enumerated fields, and return the resulting status.
/// The single write-through point the GUI and CLI use to change updater
/// settings. The daemon re-reads config each tick, so changes take effect
/// without a restart.
pub fn set_prefs(prefs: UpdatePrefs) -> Result<UpdateStatus> {
    let UpdatePrefs {
        enabled,
        channel,
        auto_apply,
        check_interval_hours,
        feed_request_timeout_ms,
        artifact_download_timeout_ms,
        stable_url,
        beta_url,
    } = prefs;

    if let Some(v) = channel.as_deref() {
        if v != "stable" && v != "beta" {
            return Err(Error::msg(format!(
                "invalid update channel '{v}' (expected 'stable' or 'beta')"
            )));
        }
    }
    if let Some(v) = auto_apply.as_deref() {
        if ApplyPolicy::parse(v).is_none() {
            return Err(Error::msg(format!(
                "invalid auto_apply policy '{v}' (expected patch | minor | all | none)"
            )));
        }
    }
    if matches!(check_interval_hours, Some(0)) {
        return Err(Error::msg(
            "auto_update.check_interval_hours must be non-zero",
        ));
    }
    if matches!(feed_request_timeout_ms, Some(0)) {
        return Err(Error::msg(
            "auto_update.feed_request_timeout_ms must be non-zero",
        ));
    }
    if matches!(artifact_download_timeout_ms, Some(0)) {
        return Err(Error::msg(
            "auto_update.artifact_download_timeout_ms must be non-zero",
        ));
    }

    MeshConfig::transaction(|cfg| {
        let au = &mut cfg.auto_update;
        if let Some(v) = enabled {
            au.enabled = v;
        }
        if let Some(v) = channel {
            au.channel = v;
        }
        if let Some(v) = auto_apply {
            au.auto_apply = v;
        }
        if let Some(v) = check_interval_hours {
            au.check_interval_hours = v;
        }
        if let Some(v) = feed_request_timeout_ms {
            au.feed_request_timeout_ms = v;
        }
        if let Some(v) = artifact_download_timeout_ms {
            au.artifact_download_timeout_ms = v;
        }
        if let Some(v) = stable_url {
            au.stable_url = normalise_url_override(v);
        }
        if let Some(v) = beta_url {
            au.beta_url = normalise_url_override(v);
        }
        au.validate()?;
        Ok(())
    })?;
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
/// restart). The first check runs immediately; the configured cadence is the
/// only background scheduling policy.
pub async fn tick_forever() {
    tick_until_shutdown(std::future::pending()).await;
}

/// Run the updater ticker until its owner submits the terminal shutdown
/// signal.  The wait future is retained across both the feed check and the
/// configured sleep, so the owner can join this task without leaving a
/// network request or a future tick behind the daemon's terminal fence.
pub async fn tick_until_shutdown<F>(shutdown: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::pin!(shutdown);
    loop {
        let checked = tokio::select! {
            result = check_now(false) => result,
            _ = &mut shutdown => return,
        };
        match checked {
            Ok(CheckOutcome::Staged { version }) => {
                tracing::info!("self-update staged {version}; applies on next daemon start");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("self-update check failed: {e}"),
        }
        let hours = match load_valid_auto_update() {
            Ok(a) => a.check_interval_hours,
            Err(e) => {
                tracing::error!("self-update ticker stopped: invalid config: {e}");
                break;
            }
        };
        let delay = match check_interval_duration(hours) {
            Ok(delay) => delay,
            Err(e) => {
                tracing::error!("self-update ticker stopped: invalid check interval: {e}");
                break;
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = &mut shutdown => return,
        }
    }
}

// ---------------------------------------------------------------------------
// Config + env gating.
// ---------------------------------------------------------------------------

fn load_auto_update() -> Result<AutoUpdateConfig> {
    Ok(MeshConfig::load()?.auto_update)
}

/// Load the owner policy for a side-effecting updater operation. The core
/// config loader deliberately quarantines malformed files for daemon startup;
/// an updater mutation must fail closed instead, before package markers,
/// check markers, clients, or staging directories can be touched. Reparse the
/// existing source as a read-only preflight, then use the canonical loader for
/// the actual transaction and validate its timing policy.
fn load_valid_auto_update() -> Result<AutoUpdateConfig> {
    let path = myownmesh_core::dirs::config_path()?;
    if path.exists() {
        let raw = std::fs::read_to_string(&path)?;
        let _: MeshConfig = serde_json::from_str(&raw)?;
    }
    let au = load_auto_update()?;
    au.validate()?;
    Ok(au)
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
    let client = http_client(au.feed_request_timeout()?)?;
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

/// Locate an installed `myownmesh-gui` binary so the updater can attempt
/// the same release independently of the daemon. This is the *inverse* of
/// the daemon's own
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
    // RISC-V Linux — e.g. the NanoKVM SoC (Sophgo SG2002). No mesh release
    // asset ships for this triple (the device updates via its own OTA), but
    // the daemon must still *compile* and report a sensible platform string.
    #[cfg(all(target_os = "linux", target_arch = "riscv64"))]
    {
        "linux-riscv64"
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
    // Anything not explicitly handled above. Spelled as the exact negation of
    // the handled (os, arch) set — not just "non-linux/macos/windows" — so a
    // Linux build on an unlisted arch (the bug this fixes) returns "unknown"
    // instead of falling through to an empty body that fails to compile.
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "riscv64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        target_os = "windows",
    )))]
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

/// The detached minisign signature asset (`<asset>.minisig`) for `asset_name`.
fn pick_sig_asset<'a>(assets: &'a [Value], asset_name: &str) -> Option<&'a Value> {
    let preferred = format!("{asset_name}.minisig");
    assets
        .iter()
        .find(|a| a["name"].as_str() == Some(preferred.as_str()))
}

/// Verify a detached minisign signature over `data` against the baked-in
/// release public key. Pure verification (no signing); fails closed on any
/// malformed input.
fn verify_signature(
    pubkey_b64: &str,
    data: &[u8],
    minisig_text: &str,
) -> std::result::Result<(), String> {
    let pk = minisign_verify::PublicKey::from_base64(pubkey_b64)
        .map_err(|e| format!("bad release public key: {e}"))?;
    let sig = minisign_verify::Signature::decode(minisig_text)
        .map_err(|e| format!("bad signature file: {e}"))?;
    pk.verify(data, &sig, false).map_err(|e| e.to_string())
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

/// Which executable a staged artifact replaces. Daemon and installed GUI
/// artifacts target the same release, but staging and replacement outcomes
/// are independent; a GUI failure must not be reported as a completed swap.
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
    /// Digest of the staged executable, rechecked immediately before apply.
    /// A missing digest is never emitted and is rejected by the apply path.
    sha256: Option<String>,
}

/// A temporary pathname owned by one staging operation. Arm this guard only
/// after `write_exclusive_bytes` succeeds: that helper handles its own write
/// and sync failures, while this guard handles later failures without taking
/// ownership of a pre-planted pathname refused by `create_new`.
struct TempPathGuard {
    path: PathBuf,
    keep: bool,
}

impl TempPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, keep: false }
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn validate_safe_component(value: &str, what: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value
            .chars()
            .any(|character| matches!(character, '<' | '>' | '"' | '|' | '?' | '*'))
        || value.ends_with('.')
        || value.ends_with(' ')
        || value.chars().any(char::is_control)
    {
        return Err(Error::msg(format!(
            "{what} must be one safe path component"
        )));
    }
    Ok(())
}

fn prepare_staging_version_dir(version: &str) -> Result<(PathBuf, PathBuf)> {
    let configured_root = myownmesh_core::dirs::updates_dir()?;
    let updates_root = prepare_updates_root(&configured_root)?;
    let version_dir = updates_root.join(version);
    match std::fs::symlink_metadata(&version_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::msg(format!(
                "staging version path is not a real directory: {}",
                version_dir.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&version_dir)?;
        }
        Err(error) => return Err(error.into()),
    }
    let version_dir = std::fs::canonicalize(version_dir)?;
    if !version_dir.starts_with(&updates_root) {
        return Err(Error::msg("staging version path escapes updates directory"));
    }
    ensure_staging_parent(&version_dir, &updates_root)?;
    Ok((updates_root, version_dir))
}

fn prepare_updates_root(configured_root: &Path) -> Result<PathBuf> {
    match std::fs::symlink_metadata(configured_root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::msg(format!(
                "updates root is not a real directory: {}",
                configured_root.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(configured_root)?;
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(configured_root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::msg(format!(
            "updates root is not a real directory: {}",
            configured_root.display()
        )));
    }
    Ok(std::fs::canonicalize(configured_root)?)
}

fn ensure_staging_parent(parent: &Path, updates_root: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::msg(format!(
            "staging parent is not a real directory: {}",
            parent.display()
        )));
    }
    let canonical_parent = std::fs::canonicalize(parent)?;
    let canonical_root = std::fs::canonicalize(updates_root)?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(Error::msg("staging parent escapes updates directory"));
    }
    Ok(())
}

fn randomized_temp_path(parent: &Path, prefix: &str, suffix: &str) -> PathBuf {
    let counter = APPLY_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut hasher = RandomState::new().build_hasher();
    parent.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    now.as_nanos().hash(&mut hasher);
    counter.hash(&mut hasher);
    parent.join(format!("{prefix}{:016x}{suffix}", hasher.finish()))
}

fn write_exclusive_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            Error::msg(format!(
                "cannot create exclusive updater temp {}: {error}",
                path.display()
            ))
        })?;
    let result = (|| -> Result<()> {
        use std::io::Write as _;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn replace_staged_archive(source: &Path, destination: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(destination) {
        if metadata.file_type().is_symlink() || metadata.is_dir() {
            let _ = std::fs::remove_file(source);
            return Err(Error::msg(format!(
                "archive destination is not a regular file: {}",
                destination.display()
            )));
        }
        std::fs::remove_file(destination)?;
    }
    std::fs::rename(source, destination).map_err(|error| {
        let _ = std::fs::remove_file(source);
        error.into()
    })
}

fn stage_verified_binary(
    bytes: &[u8],
    destination_dir: &Path,
    updates_root: &Path,
    binary_name: &str,
) -> Result<(PathBuf, String)> {
    validate_safe_component(binary_name, "embedded binary name")?;
    ensure_staging_parent(destination_dir, updates_root)?;
    let destination = destination_dir.join(binary_name);
    let temporary = randomized_temp_path(destination_dir, ".myownmesh-binary-", ".tmp");
    write_exclusive_bytes(&temporary, bytes)?;
    let mut guard = TempPathGuard::new(temporary.clone());
    ensure_staging_parent(destination_dir, updates_root)?;
    if let Ok(metadata) = std::fs::symlink_metadata(&destination) {
        if metadata.file_type().is_symlink() || metadata.is_dir() {
            return Err(Error::msg(format!(
                "staging destination is not a regular file: {}",
                destination.display()
            )));
        }
        std::fs::remove_file(&destination)?;
    }
    ensure_staging_parent(destination_dir, updates_root)?;
    std::fs::rename(&temporary, &destination).map_err(|error| {
        Error::msg(format!(
            "cannot publish staged binary {}: {error}",
            destination.display()
        ))
    })?;
    guard.keep();
    Ok((destination, sha256_bytes(bytes)))
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
    au: &AutoUpdateConfig,
) -> Result<Vec<ArtifactKind>> {
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| Error::msg("release missing assets"))?;

    validate_safe_component(version, "release version")?;
    let (updates_root, updates_dir) = prepare_staging_version_dir(version)?;
    let client = http_client(au.artifact_download_timeout()?)?;

    let mut staged: Vec<StagedArtifact> = Vec::new();

    if want.contains(&ArtifactKind::Daemon) {
        let daemon_asset = pick_daemon_asset(assets).ok_or_else(|| {
            Error::msg(format!(
                "no daemon release asset matches this platform ({})",
                current_platform()
            ))
        })?;
        let (daemon_bin, daemon_sha256) = download_verify_stage(
            &client,
            assets,
            &updates_dir,
            &updates_root,
            daemon_asset,
            ArtifactKind::Daemon,
        )
        .await?;
        staged.push(StagedArtifact {
            kind: ArtifactKind::Daemon,
            staged: daemon_bin,
            sha256: Some(daemon_sha256),
        });
    }

    if want.contains(&ArtifactKind::Gui) {
        match pick_gui_asset(assets) {
            Some(gui_asset) => {
                match download_verify_stage(
                    &client,
                    assets,
                    &updates_dir,
                    &updates_root,
                    gui_asset,
                    ArtifactKind::Gui,
                )
                .await
                {
                    Ok((gui_bin, gui_sha256)) => staged.push(StagedArtifact {
                        kind: ArtifactKind::Gui,
                        staged: gui_bin,
                        sha256: Some(gui_sha256),
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
    updates_root: &Path,
    asset: &Value,
    kind: ArtifactKind,
) -> Result<(PathBuf, String)> {
    let dl_url = asset["browser_download_url"]
        .as_str()
        .ok_or_else(|| Error::msg("asset missing browser_download_url"))?;
    let asset_name = asset["name"]
        .as_str()
        .ok_or_else(|| Error::msg("asset missing name"))?
        .to_string();
    validate_safe_component(&asset_name, "release asset name")?;
    ensure_staging_parent(updates_dir, updates_root)?;

    let archive_path = updates_dir.join(&asset_name);
    let part_path = randomized_temp_path(updates_dir, ".myownmesh-download-", ".part");

    let bytes = client
        .get(dl_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    write_exclusive_bytes(&part_path, &bytes)?;
    let mut part_guard = TempPathGuard::new(part_path.clone());

    // Integrity: a published checksum is mandatory. We never stage an
    // unverified binary — a missing sidecar used to fall through to a warning,
    // which let anyone able to omit it serve any payload.
    let Some(sha_asset) = pick_sha_asset(assets, &asset_name) else {
        let _ = std::fs::remove_file(&part_path);
        return Err(Error::msg(format!(
            "no checksum sidecar for {asset_name}; refusing to stage unverified"
        )));
    };
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

    // Authenticity: when a release signing key is baked in, a valid detached
    // minisign signature over the artifact is required before staging. SHA-256
    // comes from the same release and proves only integrity; the signature is
    // what makes a swapped release asset detectable.
    match RELEASE_PUBKEY {
        Some(pubkey) => {
            let Some(sig_asset) = pick_sig_asset(assets, &asset_name) else {
                let _ = std::fs::remove_file(&part_path);
                return Err(Error::msg(format!(
                    "no signature for {asset_name}; refusing to stage"
                )));
            };
            let sig_url = sig_asset["browser_download_url"]
                .as_str()
                .ok_or_else(|| Error::msg("signature asset missing url"))?;
            let sig_text = client
                .get(sig_url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            if let Err(e) = verify_signature(pubkey, &bytes, &sig_text) {
                let _ = std::fs::remove_file(&part_path);
                return Err(Error::msg(format!(
                    "signature check failed for {asset_name}: {e}"
                )));
            }
        }
        None => tracing::warn!(
            "release signing not configured in this build; {asset_name} verified by SHA-256 only"
        ),
    }

    let is_archive = asset_name.ends_with(".tar.gz")
        || asset_name.ends_with(".tgz")
        || asset_name.ends_with(".zip");
    if !is_archive && bytes.is_empty() {
        let _ = std::fs::remove_file(&part_path);
        return Err(Error::msg(format!("raw artifact `{asset_name}` is empty")));
    }

    ensure_staging_parent(updates_dir, updates_root)?;
    replace_staged_archive(&part_path, &archive_path)?;
    part_guard.keep();
    let binary_bytes = if is_archive {
        extract_verified_binary_bytes(&bytes, &asset_name, kind.bin_name())?
    } else {
        bytes.to_vec().into_boxed_slice()
    };
    let (binary, binary_sha256) =
        stage_verified_binary(&binary_bytes, updates_dir, updates_root, kind.bin_name())?;

    Ok((binary, binary_sha256))
}

/// Build the `pending.json` document for a set of staged artifacts. The
/// `artifacts` array, including a digest for every member, is the only
/// accepted on-disk format.
fn pending_doc(version: &str, artifacts: &[StagedArtifact]) -> Result<Value> {
    let mut arts = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let sha256 = artifact
            .sha256
            .as_deref()
            .filter(|digest| !digest.trim().is_empty())
            .ok_or_else(|| Error::msg("staged artifact has no digest"))?;
        arts.push(serde_json::json!({
            "kind": artifact.kind.as_str(),
            "path": artifact.staged.to_string_lossy(),
            "sha256": sha256,
        }));
    }
    Ok(serde_json::json!({
        "version": version,
        "artifacts": arts,
        "staged_at": iso_now(),
    }))
}

/// Parse the staged-artifact list out of a `pending.json` document.
fn parse_pending_artifacts(doc: &Value) -> Result<Vec<StagedArtifact>> {
    let object = doc
        .as_object()
        .ok_or_else(|| Error::msg("pending.json must be an object"))?;
    for key in object.keys() {
        if !matches!(key.as_str(), "version" | "artifacts" | "staged_at") {
            return Err(Error::msg(format!(
                "pending.json has unknown field `{key}`"
            )));
        }
    }
    let arr = object
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::msg("pending.json has no artifacts array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (index, artifact) in arr.iter().enumerate() {
        let artifact = artifact
            .as_object()
            .ok_or_else(|| Error::msg(format!("artifact {index} must be an object")))?;
        for key in artifact.keys() {
            if !matches!(key.as_str(), "kind" | "path" | "sha256") {
                return Err(Error::msg(format!(
                    "artifact {index} has unknown field `{key}`"
                )));
            }
        }
        let kind_name = artifact
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::msg(format!("artifact {index} has no kind")))?;
        let kind = ArtifactKind::parse(kind_name)
            .ok_or_else(|| Error::msg(format!("artifact {index} has unknown kind")))?;
        let path = artifact
            .get("path")
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
            .ok_or_else(|| Error::msg(format!("artifact {index} has no path")))?;
        let sha256 = artifact
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|digest| !digest.trim().is_empty())
            .ok_or_else(|| Error::msg(format!("artifact {index} has no digest")))?;
        out.push(StagedArtifact {
            kind,
            staged: PathBuf::from(path),
            sha256: Some(sha256.to_owned()),
        });
    }
    Ok(out)
}

fn write_pending_marker(version: &str, artifacts: &[StagedArtifact]) -> Result<()> {
    validate_safe_component(version, "release version")?;
    let pending_path = myownmesh_core::dirs::updates_dir()?.join("pending.json");
    write_pending_marker_at(&pending_path, version, artifacts)
}

fn write_pending_marker_at(
    pending_path: &Path,
    version: &str,
    artifacts: &[StagedArtifact],
) -> Result<()> {
    validate_safe_component(version, "release version")?;
    let parent = pending_path
        .parent()
        .ok_or_else(|| Error::msg("pending marker has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let doc = pending_doc(version, artifacts)?;
    let temp_path = randomized_temp_path(parent, ".myownmesh-pending-", ".tmp");
    write_pending_marker_with_temp(pending_path, &doc, &temp_path)
}

fn write_pending_marker_with_temp(
    pending_path: &Path,
    doc: &Value,
    temp_path: &Path,
) -> Result<()> {
    write_exclusive_bytes(temp_path, serde_json::to_string_pretty(doc)?.as_bytes())?;
    let mut temp_guard = TempPathGuard::new(temp_path.to_path_buf());
    #[cfg(windows)]
    {
        let backup_path = pending_backup_path(pending_path);
        // Complete or recover an earlier replacement before beginning this
        // one. A crash after the old marker is moved aside is repaired at the
        // next startup instead of exposing a missing-marker window.
        recover_marker_pair(pending_path, &backup_path)?;
        if pending_path.exists() {
            std::fs::rename(pending_path, &backup_path)?;
        }
        if let Err(error) = std::fs::rename(temp_path, pending_path) {
            let _ = std::fs::rename(&backup_path, pending_path);
            return Err(error.into());
        }
        let _ = std::fs::remove_file(&backup_path);
    }
    #[cfg(not(windows))]
    if let Err(error) = std::fs::rename(temp_path, pending_path) {
        return Err(error.into());
    }
    temp_guard.keep();
    Ok(())
}

fn recover_pending_marker(updates_dir: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let pending = updates_dir.join("pending.json");
        let backup = pending_backup_path(&pending);
        recover_marker_pair(&pending, &backup)?;
    }
    let _ = updates_dir;
    Ok(())
}

#[cfg(windows)]
fn pending_backup_path(pending: &Path) -> PathBuf {
    pending.with_file_name("pending.json.bak")
}

#[cfg(windows)]
fn recover_marker_pair(pending: &Path, backup: &Path) -> Result<()> {
    if pending.exists() {
        if backup.exists() {
            std::fs::remove_file(backup)?;
        }
    } else if backup.exists() {
        std::fs::rename(backup, pending)?;
    }
    Ok(())
}

/// If `archive` is a tar.gz / tgz / zip, extract via the system `tar`
/// and return the path to the embedded `bin_name` (e.g. `myownmesh` or
/// `myownmesh-gui`). If it's already a raw binary, return it unchanged.
///
/// Archives are preflighted before any destination path is touched. The
/// release format is deliberately exact: one flat regular-file member whose
/// name is exactly `bin_name`. Extraction occurs in a fresh sibling directory,
/// followed by canonical regular-file and containment checks before the one
/// expected file is moved into place.
#[cfg(test)]
fn extract_binary_if_archived(
    archive_bytes: &[u8],
    archive_name: &str,
    dest_dir: &Path,
    bin_name: &str,
) -> Result<PathBuf> {
    let name = archive_name;
    // Never treat a sidecar as the binary — a stale marker could point at
    // one, and atomic replacement would clobber the live binary with it.
    if is_sidecar_asset(name) {
        return Err(Error::msg(format!(
            "refusing to install sidecar `{name}` as the {bin_name} binary"
        )));
    }
    let is_archive = name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".zip");
    if !is_archive {
        return Ok(dest_dir.join(name));
    }

    let members = tar_output(archive_bytes, archive_name, "-tf")?;
    let details = tar_output(archive_bytes, archive_name, "-tvf")?;
    validate_archive_listing(&members, &details, bin_name)?;

    let extract_dir = dest_dir.join(format!(".myownmesh-extract-{}", std::process::id()));
    if extract_dir.exists() {
        return Err(Error::msg(format!(
            "refusing archive extraction into existing {}",
            extract_dir.display()
        )));
    }
    std::fs::create_dir(&extract_dir)?;
    let mut extraction = ExtractionDirectory {
        path: extract_dir.clone(),
        keep: false,
    };
    let mut cmd = std::process::Command::new("tar");
    cmd.arg("-xf").arg("-").arg("-C").arg(&extract_dir);
    // When the updater runs inside a windowless process (the GUI, or a
    // daemon it spawned hidden), a console child like `tar` would flash
    // up its own console window on Windows; run it without one.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let output = run_tar_with_bytes(cmd, archive_bytes, archive_name)?;
    if !output.status.success() {
        return Err(Error::msg(format!(
            "tar exited with {} extracting {}",
            output.status, archive_name
        )));
    }
    let extracted = extract_dir.join(bin_name);
    let extracted_root = std::fs::canonicalize(&extract_dir)?;
    let canonical = std::fs::canonicalize(&extracted)?;
    if !canonical.starts_with(&extracted_root) {
        return Err(Error::msg(format!(
            "extracted archive member `{bin_name}` escapes its extraction root"
        )));
    }
    let metadata = std::fs::symlink_metadata(&extracted)?;
    if !metadata.file_type().is_file() {
        return Err(Error::msg(format!(
            "extracted archive member `{bin_name}` is not a regular file"
        )));
    }
    let entries: Vec<_> = std::fs::read_dir(&extract_dir)?.collect::<std::io::Result<_>>()?;
    if entries.len() != 1 {
        return Err(Error::msg(format!(
            "extracted archive contains unexpected files beside `{bin_name}`"
        )));
    }

    let bin_path = dest_dir.join(bin_name);
    if bin_path.exists() || std::fs::symlink_metadata(&bin_path).is_ok() {
        let existing = std::fs::symlink_metadata(&bin_path)?;
        if existing.file_type().is_symlink() || existing.file_type().is_dir() {
            return Err(Error::msg(format!(
                "extraction target `{bin_name}` collides with a non-file"
            )));
        }
        std::fs::remove_file(&bin_path)?;
    }
    if let Err(error) = std::fs::rename(&extracted, &bin_path) {
        return Err(error.into());
    }
    std::fs::remove_dir(&extract_dir)?;
    extraction.keep = true;
    let destination_root = std::fs::canonicalize(dest_dir)?;
    let destination = std::fs::canonicalize(&bin_path)?;
    if !destination.starts_with(&destination_root)
        || !std::fs::symlink_metadata(&bin_path)?.file_type().is_file()
    {
        return Err(Error::msg(format!(
            "extracted archive member `{bin_name}` failed final containment check"
        )));
    }
    Ok(bin_path)
}

fn validate_archive_listing(members: &str, details: &str, bin_name: &str) -> Result<()> {
    let member_names: Vec<&str> = members
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.is_empty())
        .collect();
    if member_names.len() != 1 || member_names[0] != bin_name {
        return Err(Error::msg(format!(
            "archive must contain exactly the flat `{bin_name}` member"
        )));
    }
    let detail_lines: Vec<&str> = details
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.is_empty())
        .collect();
    if detail_lines.len() != 1
        || !detail_lines[0].starts_with('-')
        || detail_lines[0].split_whitespace().last() != Some(bin_name)
    {
        return Err(Error::msg(format!(
            "archive member `{bin_name}` is not one regular flat file"
        )));
    }
    Ok(())
}

#[cfg(test)]
struct ExtractionDirectory {
    path: PathBuf,
    keep: bool,
}

#[cfg(test)]
impl Drop for ExtractionDirectory {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn tar_output(archive_bytes: &[u8], archive_name: &str, listing: &str) -> Result<String> {
    let mut cmd = std::process::Command::new("tar");
    cmd.arg(listing).arg("-");
    let output = run_tar_with_bytes(cmd, archive_bytes, archive_name)?;
    if !output.status.success() {
        return Err(Error::msg(format!(
            "tar exited with {} inspecting {}",
            output.status, archive_name
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| Error::msg(format!("tar produced non-UTF-8 output for {archive_name}")))
}

fn run_tar_with_bytes(
    mut cmd: std::process::Command,
    archive_bytes: &[u8],
    archive_name: &str,
) -> Result<std::process::Output> {
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::msg(format!("failed to run tar for {archive_name}: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        if let Err(error) = stdin.write_all(archive_bytes) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::msg(format!(
                "failed to feed archive bytes to tar for {archive_name}: {error}"
            )));
        }
    }
    Ok(child.wait_with_output()?)
}

// ---------------------------------------------------------------------------
// Atomic file replacement.
// ---------------------------------------------------------------------------

fn atomic_replace_bytes(bytes: &[u8], target: &Path) -> Result<()> {
    let target_dir = target
        .parent()
        .ok_or_else(|| Error::msg("target has no parent"))?;
    let counter = APPLY_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut hasher = RandomState::new().build_hasher();
    target_dir.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    now.as_nanos().hash(&mut hasher);
    counter.hash(&mut hasher);
    let tmp = target_dir.join(format!(".myownmesh-update-{:016x}.tmp", hasher.finish()));
    atomic_replace_bytes_at_path(bytes, target, &tmp)
}

fn atomic_replace_bytes_at_path(bytes: &[u8], target: &Path, tmp: &Path) -> Result<()> {
    // CREATE_NEW/O_EXCL makes the sibling materialization refuse a planted
    // file or symlink instead of following or overwriting it.
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
    {
        Ok(file) => file,
        Err(error) => {
            return Err(Error::msg(format!(
                "cannot create exclusive updater temp {}: {error}",
                tmp.display()
            )))
        }
    };
    let write_result = (|| -> Result<()> {
        use std::io::Write as _;
        file.write_all(bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = file.metadata()?.permissions();
            permissions.set_mode(0o755);
            file.set_permissions(permissions)?;
        }
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        drop(file);
        let _ = std::fs::remove_file(tmp);
        return Err(error);
    }
    drop(file);

    // Unix allows replacing a running executable; the running process
    // keeps the old inode until exit. Windows blocks renaming an open
    // .exe, so we side-rename the running binary to `<exe>.old` (which
    // Windows DOES allow while mapped) and move the new one into place.
    #[cfg(unix)]
    {
        let result = std::fs::rename(tmp, target).map_err(Error::from);
        if result.is_err() {
            let _ = std::fs::remove_file(tmp);
        }
        result
    }
    #[cfg(windows)]
    {
        let result = match std::fs::rename(tmp, target) {
            Ok(()) => Ok(()),
            Err(_) => rename_into_place_via_side_swap_windows(tmp, target),
        };
        if result.is_err() {
            let _ = std::fs::remove_file(tmp);
        }
        result
    }
    #[cfg(not(any(unix, windows)))]
    {
        let result = std::fs::rename(tmp, target).map_err(Error::from);
        if result.is_err() {
            let _ = std::fs::remove_file(tmp);
        }
        result
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

fn check_interval_duration(interval_hours: u32) -> Result<Duration> {
    if interval_hours == 0 {
        return Err(Error::msg(
            "auto_update.check_interval_hours must be non-zero",
        ));
    }
    let hours = u64::from(interval_hours);
    let seconds = hours
        .checked_mul(SECONDS_PER_HOUR)
        .ok_or_else(|| Error::msg("update check interval overflows duration"))?;
    Ok(Duration::from_secs(seconds))
}

fn is_due(interval_hours: u32) -> Result<bool> {
    let path = check_marker_path()?;
    if !path.exists() {
        return Ok(true);
    }
    let s = std::fs::read_to_string(&path).unwrap_or_default();
    let prev = s.trim().parse::<i64>().unwrap_or(0);
    let now = unix_secs();
    if prev > now {
        return Ok(false);
    }
    let elapsed = u64::try_from(now.saturating_sub(prev)).unwrap_or(0);
    Ok(elapsed >= check_interval_duration(interval_hours)?.as_secs())
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    static UPDATE_TEST_LOCK: Mutex<()> = Mutex::const_new(());

    async fn request_counter_server() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the local request observer binds");
        let url = format!("http://{}/releases", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                observed.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        (url, requests, task)
    }

    fn assert_no_update_effects(updates: &std::path::Path) {
        assert!(!updates.exists(), "the updates root must remain absent");
        assert!(!updates.join("pm-detected.flag").exists());
        assert!(!updates.join("last-check").exists());
        assert!(!updates.join("pending.json").exists());
    }

    #[test]
    fn signature_verification_fails_closed_on_garbage() {
        // Malformed key or signature must error, never silently pass — the
        // download path treats any Err here as "do not stage".
        assert!(verify_signature("not-a-valid-key", b"payload", "not-a-sig").is_err());
        assert!(verify_signature("", b"payload", "").is_err());
    }

    #[test]
    fn empty_raw_artifact_is_refused_before_materialization() {
        let error = materialize_verified_binary(b"", "myownmesh-linux-x86_64", "myownmesh")
            .expect_err("an empty raw artifact must not be materialized");
        assert!(
            error.to_string().contains("raw artifact") && error.to_string().contains("is empty")
        );
    }

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

    // These controls share the actual pending-marker/apply/outcome path, not
    // network staging or process-global install discovery. Target overrides
    // are the existing explicit apply_one fixture seam; replacement itself
    // uses the production digest checks and exclusive-temp atomic writer.
    fn forced_gui_replacement_failure(daemon_wanted: bool, explicit_update: bool) {
        // Separate fresh trees exercise each public entry point's actual
        // conversion with a real apply result, without reconstructing errors.
        let root = tempfile::tempdir().expect("owned update fixture");
        let updates = root.path().join("updates");
        let version = "9999.0.0";
        let version_dir = updates.join(version);
        std::fs::create_dir_all(&version_dir).unwrap();
        let daemon_target = root.path().join("installed-daemon");
        std::fs::write(&daemon_target, b"old daemon").unwrap();
        // A regular file where a parent directory is required forces an OS
        // replacement failure on Unix and Windows without ACL/env overrides.
        let blocked_parent = root.path().join("blocked-gui-parent");
        std::fs::write(&blocked_parent, b"unchanged blocker").unwrap();
        let gui_target = blocked_parent.join(gui_exe_name());
        let gui_bytes = b"verified new GUI";
        let daemon_bytes = b"verified new daemon";
        let gui_staged = version_dir.join(gui_exe_name());
        std::fs::write(&gui_staged, gui_bytes).unwrap();
        let gui = StagedArtifact {
            kind: ArtifactKind::Gui,
            staged: gui_staged.clone(),
            sha256: Some(sha256_bytes(gui_bytes)),
        };
        // GUI first in the marker discriminates the required daemon-first
        // execution order as well as the staged-versus-applied outcome.
        let mut artifacts = vec![gui.clone()];
        if daemon_wanted {
            let staged = version_dir.join(ArtifactKind::Daemon.bin_name());
            std::fs::write(&staged, daemon_bytes).unwrap();
            artifacts.push(StagedArtifact {
                kind: ArtifactKind::Daemon,
                staged,
                sha256: Some(sha256_bytes(daemon_bytes)),
            });
        }
        let marker = updates.join("pending.json");
        write_pending_marker_at(&marker, version, &artifacts).unwrap();
        let mut attempts = Vec::new();
        let mut failures = Vec::new();
        let mut gui_stamps = Vec::new();
        let applied = apply_pending_at(
            &updates,
            |_, target| version_is_newer(target, Some("1.0.0")),
            |artifact, directory, target_version| {
                attempts.push(artifact.kind);
                let target = if artifact.kind == ArtifactKind::Daemon {
                    &daemon_target
                } else {
                    &gui_target
                };
                let result =
                    apply_one_with_target(artifact, directory, target_version, Some(target), || {});
                if let Err(error) = &result {
                    failures.push((artifact.kind, error.to_string()));
                }
                result
            },
            |target| gui_stamps.push(target.to_string()),
        );
        assert_eq!(
            attempts,
            if daemon_wanted {
                vec![ArtifactKind::Daemon, ArtifactKind::Gui]
            } else {
                vec![ArtifactKind::Gui]
            }
        );
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, ArtifactKind::Gui);
        assert!(failures[0]
            .1
            .contains("cannot create exclusive updater temp"));
        assert!(
            gui_stamps.is_empty(),
            "failed replacement must not advance GUI stamp"
        );
        assert_eq!(
            std::fs::read(&blocked_parent).unwrap(),
            b"unchanged blocker"
        );
        assert_eq!(std::fs::read(&gui_staged).unwrap(), gui_bytes);
        let pending: Value =
            serde_json::from_slice(&std::fs::read(&marker).expect("failed GUI marker remains"))
                .unwrap();
        assert_eq!(pending["version"], version);
        let remaining = parse_pending_artifacts(&pending).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].kind, ArtifactKind::Gui);
        assert_eq!(remaining[0].staged, gui.staged);
        assert_eq!(remaining[0].sha256, gui.sha256);
        if !explicit_update {
            let outcome = applied_version_outcome(applied);
            if daemon_wanted {
                assert_eq!(std::fs::read(&daemon_target).unwrap(), daemon_bytes);
                assert_eq!(
                    outcome.expect("daemon applied despite pending GUI"),
                    Some(version.into())
                );
            } else {
                assert_eq!(std::fs::read(&daemon_target).unwrap(), b"old daemon");
                assert!(outcome
                    .expect_err("apply_now must not flatten pending-only failure to None")
                    .to_string()
                    .contains("remains pending"));
            }
            return;
        }
        let outcome = applied_update_outcome(applied);
        if daemon_wanted {
            assert_eq!(std::fs::read(&daemon_target).unwrap(), daemon_bytes);
            match outcome.expect("daemon really applied") {
                UpdateNowOutcome::Updated { to, components } => {
                    assert_eq!(to, version);
                    assert_eq!(components, vec!["daemon".to_string()]);
                }
                other => panic!("unexpected actual apply outcome: {other:?}"),
            }
        } else {
            assert_eq!(std::fs::read(&daemon_target).unwrap(), b"old daemon");
            let error = outcome.expect_err("GUI-only failure must not report Updated(gui)");
            assert!(error
                .to_string()
                .contains("no staged artifacts were applied"));
        }
    }

    #[test]
    fn update_now_daemon_applied_gui_failure_reports_only_daemon_and_keeps_pending() {
        forced_gui_replacement_failure(true, false);
        forced_gui_replacement_failure(true, true);
    }

    #[test]
    fn update_now_gui_only_replacement_failure_is_not_updated_and_keeps_pending() {
        forced_gui_replacement_failure(false, false);
        forced_gui_replacement_failure(false, true);
        // No marker/no swap remains None for apply_now, but never Updated
        // for an explicit update_now that already attempted staging.
        assert_eq!(applied_version_outcome(Ok(None)).unwrap(), None);
        assert!(applied_update_outcome(Ok(None)).is_err());
    }

    #[test]
    fn pending_doc_roundtrips_daemon_and_gui() {
        let digest = "a".repeat(64);
        let arts = vec![
            StagedArtifact {
                kind: ArtifactKind::Daemon,
                staged: PathBuf::from("/u/0.1.7/myownmesh"),
                sha256: Some(digest.clone()),
            },
            StagedArtifact {
                kind: ArtifactKind::Gui,
                staged: PathBuf::from("/u/0.1.7/myownmesh-gui"),
                sha256: Some(digest.clone()),
            },
        ];
        let doc = pending_doc("0.1.7", &arts).expect("digests are present");
        assert_eq!(doc["version"].as_str(), Some("0.1.7"));
        assert!(doc.get("path").is_none());
        assert_eq!(
            doc["artifacts"][0]["sha256"].as_str(),
            Some(digest.as_str())
        );

        let parsed = parse_pending_artifacts(&doc).expect("current marker parses");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, ArtifactKind::Daemon);
        assert_eq!(parsed[0].sha256.as_deref(), Some(digest.as_str()));
        assert_eq!(parsed[1].kind, ArtifactKind::Gui);
        assert_eq!(parsed[1].staged, PathBuf::from("/u/0.1.7/myownmesh-gui"));
    }

    #[test]
    fn pending_legacy_single_path_is_rejected() {
        // The retired {version, path} marker must not be migrated or applied
        // without a digest-bearing artifacts array.
        let doc = json!({ "version": "0.1.6", "path": "/u/0.1.6/myownmesh" });
        assert!(parse_pending_artifacts(&doc).is_err());
    }

    #[test]
    fn staged_artifact_revalidates_owned_path_and_digest() {
        let tmp = tempfile::tempdir().expect("temporary update root");
        let version_dir = tmp.path().join("0.1.7");
        std::fs::create_dir_all(&version_dir).expect("version directory");
        let staged = version_dir.join("myownmesh");
        std::fs::write(&staged, b"verified payload").expect("staged binary");
        let digest = sha256_file(&staged).expect("digest");
        let artifact = StagedArtifact {
            kind: ArtifactKind::Daemon,
            staged: staged.clone(),
            sha256: Some(digest),
        };
        let (validated, _bytes) =
            validate_staged_artifact(&artifact, tmp.path(), "0.1.7").expect("valid staging");
        assert_eq!(
            validated,
            std::fs::canonicalize(&staged).expect("canonical staging")
        );
        std::fs::write(&staged, b"tampered payload").expect("tampered staged binary");
        assert!(
            validate_staged_artifact(&artifact, tmp.path(), "0.1.7").is_err(),
            "apply must recheck the staged digest"
        );
    }

    #[test]
    fn apply_one_uses_verified_snapshot_after_staged_path_replacement() {
        let tmp = tempfile::tempdir().expect("temporary update root");
        let version_dir = tmp.path().join("0.1.7");
        std::fs::create_dir_all(&version_dir).expect("version directory");
        let staged = version_dir.join("myownmesh");
        let verified = b"original verified payload";
        std::fs::write(&staged, verified).expect("staged binary");
        let artifact = StagedArtifact {
            kind: ArtifactKind::Daemon,
            staged: staged.clone(),
            sha256: Some(sha256_bytes(verified)),
        };
        let target = tmp.path().join("installed");
        let applied = apply_one_with_target(&artifact, tmp.path(), "0.1.7", Some(&target), || {
            std::fs::write(&staged, b"replacement after validation")
                .expect("replace staged pathname after validation");
        })
        .expect("verified snapshot should apply");

        assert!(applied);
        assert_eq!(
            std::fs::read(&target).expect("installed binary"),
            verified,
            "replacement after validation must not reach the install target"
        );
        assert_eq!(
            std::fs::read(&staged).expect("replaced staged pathname"),
            b"replacement after validation"
        );
    }

    #[test]
    fn atomic_materialization_refuses_preplanted_temp_file() {
        let tmp = tempfile::tempdir().expect("temporary target root");
        let target = tmp.path().join("installed");
        let preplanted = tmp.path().join(".preplanted.tmp");
        std::fs::write(&preplanted, b"attacker content").expect("preplant temp file");

        assert!(atomic_replace_bytes_at_path(b"verified content", &target, &preplanted).is_err());
        assert_eq!(
            std::fs::read(&preplanted).expect("preplanted file remains"),
            b"attacker content"
        );
        assert!(!target.exists(), "refused temp must not reach target");
    }

    #[test]
    fn staging_rejects_traversal_and_non_component_names_before_join() {
        for value in [
            "../release",
            "release/subdir",
            r"release\subdir",
            "",
            ".",
            "..",
        ] {
            assert!(
                validate_safe_component(value, "release version").is_err(),
                "unsafe component must be refused: {value:?}"
            );
        }
        assert!(validate_safe_component("release-1.2.3", "release version").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn updates_root_refuses_preplanted_symlink() {
        let tmp = tempfile::tempdir().expect("temporary updater root");
        let real_root = tmp.path().join("real-updates");
        let updates_root = tmp.path().join("updates");
        std::fs::create_dir(&real_root).expect("real updates root");
        std::os::unix::fs::symlink(&real_root, &updates_root).expect("preplant root symlink");

        assert!(prepare_updates_root(&updates_root).is_err());
        assert!(real_root
            .read_dir()
            .expect("real root remains readable")
            .next()
            .is_none());
        assert!(std::fs::symlink_metadata(&updates_root)
            .expect("root symlink remains")
            .file_type()
            .is_symlink());
    }

    #[test]
    fn download_part_refuses_preplanted_file() {
        let tmp = tempfile::tempdir().expect("temporary staging root");
        let part = tmp.path().join(".myownmesh-download-preplanted.part");
        std::fs::write(&part, b"attacker content").expect("preplant part file");
        assert!(write_exclusive_bytes(&part, b"verified content").is_err());
        assert_eq!(
            std::fs::read(&part).expect("preplant remains"),
            b"attacker content"
        );
    }

    #[cfg(unix)]
    #[test]
    fn download_part_refuses_preplanted_symlink() {
        let tmp = tempfile::tempdir().expect("temporary staging root");
        let victim = tmp.path().join("victim");
        let part = tmp.path().join(".myownmesh-download-preplanted.part");
        std::fs::write(&victim, b"victim content").expect("victim file");
        std::os::unix::fs::symlink(&victim, &part).expect("preplant part symlink");
        assert!(write_exclusive_bytes(&part, b"verified content").is_err());
        assert_eq!(
            std::fs::read(&victim).expect("symlink target remains"),
            b"victim content"
        );
    }

    #[test]
    fn marker_temp_refuses_preplanted_file() {
        let tmp = tempfile::tempdir().expect("temporary marker root");
        let pending = tmp.path().join("pending.json");
        let temp = tmp.path().join(".myownmesh-pending-preplanted.tmp");
        std::fs::write(&temp, b"attacker content").expect("preplant marker temp");
        let doc = json!({ "version": "1.2.3", "artifacts": [] });
        assert!(write_pending_marker_with_temp(&pending, &doc, &temp).is_err());
        assert_eq!(
            std::fs::read(&temp).expect("preplant remains"),
            b"attacker content"
        );
        assert!(!pending.exists(), "refused marker temp must not publish");
    }

    #[test]
    fn marker_temp_is_removed_after_owned_publish_failure() {
        let tmp = tempfile::tempdir().expect("temporary marker root");
        let blocker = tmp.path().join("blocked-parent");
        std::fs::write(&blocker, b"unchanged blocker").expect("block marker parent");
        let pending = blocker.join("pending.json");
        let temp = tmp.path().join(".myownmesh-pending-owned.tmp");
        let doc = json!({ "version": "1.2.3", "artifacts": [] });

        assert!(write_pending_marker_with_temp(&pending, &doc, &temp).is_err());
        assert!(
            !temp.exists(),
            "owned temp must be removed after publish failure"
        );
        assert_eq!(
            std::fs::read(&blocker).expect("blocker remains"),
            b"unchanged blocker"
        );
        assert!(
            !pending.exists(),
            "failed publication must not create a marker"
        );
    }

    #[cfg(unix)]
    #[test]
    fn marker_temp_refuses_preplanted_symlink() {
        let tmp = tempfile::tempdir().expect("temporary marker root");
        let pending = tmp.path().join("pending.json");
        let victim = tmp.path().join("victim");
        let temp = tmp.path().join(".myownmesh-pending-preplanted.tmp");
        std::fs::write(&victim, b"victim content").expect("victim file");
        std::os::unix::fs::symlink(&victim, &temp).expect("preplant marker symlink");
        let doc = json!({ "version": "1.2.3", "artifacts": [] });
        assert!(write_pending_marker_with_temp(&pending, &doc, &temp).is_err());
        assert_eq!(
            std::fs::read(&victim).expect("symlink target remains"),
            b"victim content"
        );
        assert!(!pending.exists(), "refused marker temp must not publish");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_materialization_refuses_preplanted_temp_symlink() {
        let tmp = tempfile::tempdir().expect("temporary target root");
        let target = tmp.path().join("installed");
        let victim = tmp.path().join("victim");
        let preplanted = tmp.path().join(".preplanted.tmp");
        std::fs::write(&victim, b"victim content").expect("victim file");
        std::os::unix::fs::symlink(&victim, &preplanted).expect("preplant temp symlink");

        assert!(atomic_replace_bytes_at_path(b"verified content", &target, &preplanted).is_err());
        assert_eq!(
            std::fs::read(&victim).expect("symlink target remains"),
            b"victim content"
        );
        assert!(!target.exists(), "refused symlink must not reach target");
    }

    #[cfg(windows)]
    #[test]
    fn pending_marker_recovery_closes_the_windows_missing_marker_gap() {
        let tmp = tempfile::tempdir().expect("temporary marker root");
        let pending = tmp.path().join("pending.json");
        let backup = pending_backup_path(&pending);

        // A crash after moving the old marker aside is repaired before any
        // apply decision is made.
        std::fs::write(&backup, b"old marker").expect("backup marker");
        recover_marker_pair(&pending, &backup).expect("restore backup marker");
        assert_eq!(std::fs::read(&pending).unwrap(), b"old marker");
        assert!(!backup.exists());

        // A crash after installing the replacement leaves both files; the
        // primary marker is authoritative and the stale backup is removed.
        std::fs::write(&backup, b"stale marker").expect("stale backup marker");
        recover_marker_pair(&pending, &backup).expect("discard stale backup");
        assert_eq!(std::fs::read(&pending).unwrap(), b"old marker");
        assert!(!backup.exists());
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
    fn updater_timing_policy_and_interval_are_explicit_and_checked() {
        let config = AutoUpdateConfig::default();
        config.validate().expect("default updater policy is valid");
        assert_eq!(
            config.feed_request_timeout().unwrap(),
            Duration::from_millis(15_000)
        );
        assert_eq!(
            config.artifact_download_timeout().unwrap(),
            Duration::from_millis(300_000)
        );
        assert_eq!(
            check_interval_duration(0)
                .expect_err("zero interval must be refused")
                .to_string(),
            "auto_update.check_interval_hours must be non-zero"
        );
        assert_eq!(
            check_interval_duration(u32::MAX)
                .expect("u32 hours fit in the checked duration conversion")
                .as_secs(),
            u64::from(u32::MAX) * SECONDS_PER_HOUR
        );
        assert!(AutoUpdateConfig {
            feed_request_timeout_ms: 0,
            ..config
        }
        .validate()
        .is_err());
    }

    #[test]
    fn sidecars_are_rejected() {
        assert!(is_sidecar_asset("myownmesh-linux-x86_64.tar.gz.sha256"));
        assert!(is_sidecar_asset("thing.sig"));
        assert!(!is_sidecar_asset("myownmesh-linux-x86_64.tar.gz"));
    }

    #[test]
    fn archive_preflight_rejects_extra_paths_and_non_regular_members() {
        assert!(validate_archive_listing(
            "myownmesh\n",
            "-rwxr-xr-x user/group 12 2026-08-31 00:00 myownmesh\n",
            "myownmesh"
        )
        .is_ok());
        assert!(validate_archive_listing(
            "myownmesh\nsecret\n",
            "-rw-r--r-- user/group 12 2026-08-31 00:00 myownmesh\n-rw-r--r-- user/group 1 2026-08-31 00:00 secret\n",
            "myownmesh"
        )
        .is_err());
        assert!(validate_archive_listing(
            "../myownmesh\n",
            "-rw-r--r-- user/group 12 2026-08-31 00:00 ../myownmesh\n",
            "myownmesh"
        )
        .is_err());
        assert!(validate_archive_listing(
            "myownmesh\n",
            "lrwxrwxrwx user/group 0 2026-08-31 00:00 myownmesh -> outside\n",
            "myownmesh"
        )
        .is_err());
        assert!(validate_archive_listing(
            "myownmesh\n",
            "hrw-r--r-- user/group 0 2026-08-31 00:00 myownmesh\n",
            "myownmesh"
        )
        .is_err());
    }

    #[test]
    fn archive_extraction_uses_the_captured_bytes_not_a_replaced_path() {
        let tmp = tempfile::tempdir().expect("temporary archive root");
        let source_dir = tmp.path().join("source");
        std::fs::create_dir(&source_dir).expect("archive source directory");
        let expected = b"original verified binary";
        std::fs::write(source_dir.join("myownmesh"), expected).expect("archive source binary");
        let archive = tmp.path().join("fixture.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&source_dir)
            .arg("myownmesh")
            .status()
            .expect("system tar is available");
        assert!(status.success(), "tar archive creation failed: {status}");

        let captured: Box<[u8]> = std::fs::read(&archive)
            .expect("capture the verified archive bytes")
            .into_boxed_slice();
        std::fs::write(&archive, b"replacement at the original pathname")
            .expect("replace the source pathname after capture");
        let extracted =
            extract_binary_if_archived(&captured, "fixture.tar.gz", tmp.path(), "myownmesh")
                .expect("captured archive remains the input");
        assert_eq!(
            std::fs::read(extracted).expect("read extracted binary"),
            expected,
            "extraction must use the immutable verified snapshot"
        );
        assert_eq!(
            std::fs::read(&archive).expect("read replaced pathname"),
            b"replacement at the original pathname",
            "the replacement pathname must not be reopened or modified"
        );
    }

    #[test]
    fn archive_extraction_rejects_empty_member() {
        let tmp = tempfile::tempdir().expect("temporary archive root");
        let source_dir = tmp.path().join("source");
        std::fs::create_dir(&source_dir).expect("archive source directory");
        std::fs::File::create(source_dir.join("myownmesh")).expect("empty archive source");
        let archive = tmp.path().join("empty.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&source_dir)
            .arg("myownmesh")
            .status()
            .expect("system tar is available");
        assert!(status.success(), "tar archive creation failed: {status}");

        let captured = std::fs::read(&archive).expect("capture empty archive bytes");
        assert!(
            extract_verified_binary_bytes(&captured, "empty.tar.gz", "myownmesh").is_err(),
            "an empty exact regular member must be refused before staging"
        );
    }

    #[cfg(unix)]
    #[test]
    fn apply_one_archive_does_not_touch_swapped_staging_parent() {
        let tmp = tempfile::tempdir().expect("temporary archive root");
        let source_dir = tmp.path().join("source");
        let version_dir = tmp.path().join("0.1.7");
        let detached_dir = tmp.path().join("detached");
        let outside_dir = tmp.path().join("outside");
        std::fs::create_dir_all(&source_dir).expect("archive source directory");
        std::fs::create_dir_all(&version_dir).expect("version directory");
        std::fs::create_dir_all(&outside_dir).expect("outside directory");
        let expected = b"archive verified binary";
        std::fs::write(source_dir.join("myownmesh"), expected).expect("archive source binary");
        std::fs::write(outside_dir.join("myownmesh"), b"outside sentinel")
            .expect("outside sentinel");
        let archive = version_dir.join("fixture.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&source_dir)
            .arg("myownmesh")
            .status()
            .expect("system tar is available");
        assert!(status.success(), "tar archive creation failed: {status}");
        let artifact = StagedArtifact {
            kind: ArtifactKind::Daemon,
            staged: archive,
            sha256: Some(sha256_file(&version_dir.join("fixture.tar.gz")).expect("archive digest")),
        };
        let target = tmp.path().join("installed");
        let applied = apply_one_with_target(&artifact, tmp.path(), "0.1.7", Some(&target), || {
            std::fs::rename(&version_dir, &detached_dir).expect("detach staging parent");
            std::os::unix::fs::symlink(&outside_dir, &version_dir)
                .expect("plant swapped parent symlink");
        })
        .expect("verified archive should apply after parent swap");

        assert!(applied);
        assert_eq!(std::fs::read(&target).expect("installed binary"), expected);
        assert_eq!(
            std::fs::read(outside_dir.join("myownmesh")).expect("outside sentinel remains"),
            b"outside sentinel",
            "archive apply must not create/remove/follow the swapped staging parent"
        );
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

    #[tokio::test]
    async fn set_prefs_validates_and_persists() {
        // One tempdir, one sequential test: MYOWNMESH_HOME is process
        // global, so we don't want two of these racing.
        let _guard = UPDATE_TEST_LOCK.lock().await;
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
        assert!(set_prefs(UpdatePrefs {
            check_interval_hours: Some(0),
            ..Default::default()
        })
        .is_err());
        assert!(set_prefs(UpdatePrefs {
            feed_request_timeout_ms: Some(0),
            ..Default::default()
        })
        .is_err());

        // Mutation paths preflight malformed source bytes before the core
        // loader's startup quarantine policy can substitute defaults. No
        // package marker or staging root may be created on this refusal.
        let config_path = myownmesh_core::dirs::config_path().expect("config path");
        std::fs::create_dir_all(config_path.parent().expect("config parent")).unwrap();
        std::fs::write(&config_path, b"{").unwrap();
        assert!(load_valid_auto_update().is_err());
        let updates = myownmesh_core::dirs::updates_dir().expect("updates path");
        assert!(!updates.exists());

        let mut invalid = myownmesh_core::MeshConfig::default();
        invalid.auto_update.feed_request_timeout_ms = 0;
        std::fs::write(&config_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(load_valid_auto_update().is_err());
        assert!(!updates.exists());
        std::fs::write(
            &config_path,
            serde_json::to_vec(&myownmesh_core::MeshConfig::default()).unwrap(),
        )
        .unwrap();

        // A valid partial edit persists and is reflected in status.
        let st = set_prefs(UpdatePrefs {
            channel: Some("beta".into()),
            auto_apply: Some("minor".into()),
            check_interval_hours: Some(1),
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

    #[tokio::test]
    async fn public_mutations_refuse_malformed_config_before_any_effect() {
        let _guard = UPDATE_TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", tmp.path());
        let (_url, requests, server) = request_counter_server().await;
        let config_path = myownmesh_core::dirs::config_path().expect("config path");
        std::fs::create_dir_all(config_path.parent().expect("config parent")).unwrap();
        std::fs::write(&config_path, b"{").unwrap();
        let updates = myownmesh_core::dirs::updates_dir().expect("updates path");

        assert!(check_now(true).await.is_err());
        assert!(update_now().await.is_err());
        assert_no_update_effects(&updates);
        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "malformed config is refused before any network request"
        );

        server.abort();
        assert!(server
            .await
            .expect_err("the observer was cancelled")
            .is_cancelled());
        std::env::remove_var("MYOWNMESH_HOME");
    }

    #[tokio::test]
    async fn public_mutations_refuse_zero_feed_timeout_before_any_effect() {
        let _guard = UPDATE_TEST_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", tmp.path());
        let (url, requests, server) = request_counter_server().await;
        let config_path = myownmesh_core::dirs::config_path().expect("config path");
        std::fs::create_dir_all(config_path.parent().expect("config parent")).unwrap();
        let mut config = myownmesh_core::MeshConfig::default();
        config.auto_update.enabled = true;
        config.auto_update.stable_url = Some(url);
        config.auto_update.feed_request_timeout_ms = 0;
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let updates = myownmesh_core::dirs::updates_dir().expect("updates path");

        assert!(check_now(true).await.is_err());
        assert!(update_now().await.is_err());
        assert_no_update_effects(&updates);
        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "zero feed timeout is refused before constructing the network client"
        );

        server.abort();
        assert!(server
            .await
            .expect_err("the observer was cancelled")
            .is_cancelled());
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
