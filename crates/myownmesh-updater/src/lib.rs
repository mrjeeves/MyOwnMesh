//! Self-update for MyOwnMesh.
//!
//! Ported in spirit from MyOwnLLM's `src-tauri/src/self_update.rs`
//! (1800+ lines). The lifecycle is unchanged:
//!
//! 1. Background ticker polls the configured release feed every
//!    `check_interval_hours` (default 6).
//! 2. Fetched manifest's latest version is compared to the running
//!    binary's `CARGO_PKG_VERSION`. If newer and the apply policy
//!    permits the jump, the asset is downloaded.
//! 3. SHA-256 verified against the sidecar `.sha256` file (or the
//!    aggregated `SHA256SUMS` if no per-asset sidecar).
//! 4. Extracted into `~/.myownmesh/updates/<version>/` and a
//!    `pending.json` marker is written.
//! 5. On next process start, [`apply_pending_if_any`] atomically
//!    swaps the running binary with the staged one.
//!
//! Package-manager installs (Homebrew, apt/rpm, MSI, Chocolatey)
//! are detected on first launch and a `pm-detected.flag` is
//! written; subsequent runs skip self-update entirely so the OS
//! package manager remains the source of truth.
//!
//! v1 here ships the public API surface + the build-time URL
//! defaults; the actual fetch / verify / stage / apply logic is
//! filled in by porting the MyOwnLLM module file-by-file in a
//! follow-up pass.

pub mod policy;

use serde::{Deserialize, Serialize};

/// Resolved release feed URL for the stable channel. Override via
/// `MYOWNMESH_RELEASE_URL_STABLE` at build time, or via
/// `auto_update.stable_url` in `config.json` at runtime (the runtime
/// override takes precedence; the build-time env baked the default).
pub fn default_release_api_stable() -> &'static str {
    option_env!("MYOWNMESH_RELEASE_URL_STABLE")
        .unwrap_or("https://api.github.com/repos/mrjeeves/MyOwnMesh/releases/latest")
}

/// Resolved release feed URL for the beta channel.
pub fn default_release_api_beta() -> &'static str {
    option_env!("MYOWNMESH_RELEASE_URL_BETA")
        .unwrap_or("https://api.github.com/repos/mrjeeves/MyOwnMesh/releases")
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("core: {0}")]
    Core(#[from] myownmesh_core::Error),
    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("network: {0}")]
    Network(String),
    #[error("policy: {0}")]
    Policy(String),
    #[error("disabled")]
    Disabled,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatus {
    /// Currently running binary's version (`CARGO_PKG_VERSION`).
    pub current_version: String,
    /// Wall-clock unix-seconds timestamp of the last successful
    /// release-feed fetch. None = never checked.
    pub last_check_at: Option<u64>,
    /// Version staged at `~/.myownmesh/updates/<version>/` waiting
    /// to be applied on next start. None = nothing pending.
    pub staged_version: Option<String>,
    /// The effective release URL after considering config overrides
    /// and build-time defaults.
    pub release_url: String,
}

/// Atomically swap the running binary with any staged update from a
/// previous run. Call this *first thing* in `main` — before
/// initialising tokio, parsing argv, or anything else — so the
/// swap happens before file handles or sockets bind.
///
/// No-ops when there's nothing staged. Errors are logged at warn
/// and swallowed so a bad staging attempt doesn't brick startup.
pub fn apply_pending_if_any() {
    // Port from MyOwnLLM `self_update::apply_pending_if_any`.
    tracing::trace!("apply_pending_if_any: not yet implemented");
}

/// Force a release-feed check now and stage any update permitted by
/// the apply policy. Returns the resulting status. Useful for the
/// CLI `update check` subcommand.
pub async fn force_check() -> Result<UpdateStatus> {
    Err(Error::Network("not yet implemented".into()))
}

/// Background ticker: runs forever, checking the feed at the
/// configured interval. Cancellable via the standard tokio task
/// abort.
pub async fn tick_forever() {
    tracing::trace!("updater tick_forever: not yet implemented");
    futures_pending::pending().await;
}

mod futures_pending {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub fn pending() -> impl Future<Output = ()> {
        Pending
    }

    struct Pending;
    impl Future for Pending {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }
}
