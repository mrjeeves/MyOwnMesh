//! `myownmesh serve` — run the daemon in the foreground.
//!
//! A thin wrapper over [`myownmesh::embedded`]: load the config, start the
//! daemon on this runtime, and hold it until SIGINT/SIGTERM asks for the
//! graceful teardown. Everything the daemon *is* — the mesh instance, the
//! network registry, hosted services, the updater tick, the control-socket
//! listener — lives in the library, so an embedder (an iOS app, which can't
//! spawn processes) runs the identical daemon in-process.

use anyhow::{Context, Result};

pub async fn run() -> Result<()> {
    let cfg = myownmesh_core::MeshConfig::load().context("load config")?;
    let daemon = myownmesh::embedded::start(cfg).await?;

    // Wait for SIGINT (Ctrl-C) or SIGTERM.
    wait_for_shutdown_signal().await;
    tracing::info!("shutdown requested");
    daemon.shutdown().await;
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = sigint.recv().await;
                return;
            }
        };
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
