//! Daemon process lifecycle. The GUI works against a running
//! `myownmesh serve`; if one isn't already listening when we start
//! up, we spawn one as a child process and hold the handle for the
//! lifetime of the app. Killing the GUI also kills the child via
//! `DaemonChild::Drop`.
//!
//! Binary discovery order:
//!
//! 1. `MYOWNMESH_BIN` environment variable (manual override).
//! 2. Workspace dev artefacts relative to the GUI crate:
//!    `../../target/debug/myownmesh{.exe}` then `../../target/release/...`.
//!    In a source checkout this is the binary you just built, so it must
//!    win over any older release installed on `$PATH` — otherwise
//!    `just dev` would run the GUI you just compiled against a stale
//!    daemon (e.g. one that predates the `services` control ops, which
//!    surfaces as "is the daemon running?" in the Services tab). On an
//!    installed GUI this path doesn't exist, so we fall through to PATH.
//! 3. `myownmesh` (or `myownmesh.exe`) on `$PATH` (the production path).
//!
//! If we already see an existing daemon answering on the control
//! socket, we don't spawn a second one — the user may have started
//! it manually, and binding twice would just trip the second
//! instance up. The first listener wins; subsequent ones bail.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use crate::control_client::{ControlClient, Request};

/// Owned wrapper around a spawned `myownmesh serve` child. The GUI
/// holds this in its global app state; dropping it (process exit,
/// or explicit teardown) kills the child.
pub struct DaemonChild {
    child: Option<Child>,
}

impl DaemonChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // Best-effort: send SIGKILL (or TerminateProcess on
            // Windows). The daemon doesn't have a fast SIGTERM
            // shutdown surface exposed cross-platform; relying on
            // kill is acceptable for a dev tool. Production
            // installs run the daemon as a service and don't go
            // through this path.
            let _ = c.kill();
            let _ = c.wait();
            tracing::info!("daemon child terminated");
        }
    }
}

/// Probe the control socket. Returns `true` when an existing daemon
/// is listening and responding to a `Status` request. Used both
/// before we spawn (skip if already up) and after (poll for
/// readiness).
pub async fn probe(client: &ControlClient) -> bool {
    client.request(&Request::Status).await.is_ok()
}

/// Find the `myownmesh` binary using the documented search order.
pub fn find_daemon_binary() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("MYOWNMESH_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Ok(p);
        }
    }
    let exe = if cfg!(windows) {
        "myownmesh.exe"
    } else {
        "myownmesh"
    };
    // Dev-mode workspace artefacts, checked BEFORE PATH so a source
    // checkout always runs the daemon it just built rather than an older
    // release installed on PATH. The GUI crate's CARGO_MANIFEST_DIR is
    // `gui/src-tauri`, so the workspace target lives at `../../target/...`.
    // On an installed GUI this path doesn't exist, so we fall through to
    // the PATH lookup below.
    let candidates = vec![
        workspace_target_path("debug", exe),
        workspace_target_path("release", exe),
    ];
    for c in candidates.into_iter().flatten() {
        if c.exists() {
            return Ok(c);
        }
    }
    // PATH lookup. We do this manually rather than relying on
    // Command's implicit PATH search so we can report the resolved
    // location and skip non-existent stale entries.
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(exe);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    Err(anyhow!(
        "couldn't find `{exe}` — set MYOWNMESH_BIN, install it on PATH, or run \
         `cargo build -p myownmesh` first"
    ))
}

fn workspace_target_path(profile: &str, exe: &str) -> Option<PathBuf> {
    // `gui/src-tauri/` → workspace root is two parents up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(manifest_dir)
        .parent()? // gui/
        .parent()? // MyOwnMesh/
        .join("target")
        .join(profile)
        .join(exe);
    Some(path)
}

/// Spawn `myownmesh serve` as a child process and wait briefly for
/// the control socket to come up. Returns the wrapped handle so the
/// caller can keep it alive for the app lifetime.
///
/// If a daemon is already listening, we don't spawn a second one —
/// the caller gets `Ok(None)` and just uses the existing daemon.
pub async fn ensure_daemon_running(client: &ControlClient) -> Result<Option<DaemonChild>> {
    if probe(client).await {
        tracing::info!("existing daemon found on control socket");
        return Ok(None);
    }

    let bin = find_daemon_binary().context("locate myownmesh binary")?;
    tracing::info!(?bin, "spawning daemon");

    let mut cmd = Command::new(&bin);
    cmd.arg("serve")
        // Inherit stderr so the user sees engine logs in the GUI's
        // dev console. stdout is also inherited; the daemon's logs
        // go to stderr via tracing-subscriber so this is quiet.
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // The daemon is a console-subsystem binary and this GUI is windowless,
    // so without CREATE_NO_WINDOW Windows would give the child its own
    // console window, parked on screen for the app's whole lifetime. The
    // inherited stdio handles are unaffected by the flag.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    let handle = DaemonChild::new(child);

    // Poll for the socket. The daemon needs to bind the listener
    // before our first request can succeed; ~5s is plenty even on
    // a slow machine (release builds: <1s; debug builds + cold
    // cache: 2-3s).
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(150)).await;
        if probe(client).await {
            tracing::info!("daemon up");
            return Ok(Some(handle));
        }
    }
    // Drop `handle` here would kill the child — but it may still
    // be coming up, just slowly. Return it anyway and let the event
    // pump's retry loop wait for it.
    tracing::warn!(
        "daemon did not respond on control socket within 8s; \
         leaving the child running and continuing — the GUI's \
         retry loop will pick it up if it comes up later"
    );
    Ok(Some(handle))
}
