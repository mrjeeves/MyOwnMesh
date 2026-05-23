//! `myownmesh serve` — run the daemon in the foreground.
//!
//! Owns:
//! - one [`myownmesh_core::Mesh`] instance bound to this device's
//!   identity
//! - a Nostr signaling driver per joined network
//! - the updater tick loop
//! - the control-socket listener that `myownmesh ctl …` talks to
//! - signal handlers for clean shutdown

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::control;

pub async fn run() -> Result<()> {
    let cfg = myownmesh_core::MeshConfig::load().context("load config")?;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        networks = cfg.networks.len(),
        "daemon starting"
    );

    let mesh = myownmesh_core::Mesh::open(cfg.clone())
        .await
        .context("open mesh")?;
    info!(device_id = %mesh.identity().display_id(), "identity ready");

    // Join each configured network and attach the Nostr signaling
    // driver. The Mesh::join returns a JoinedNetwork that lives
    // until leave() — we stash them so leave() runs on shutdown.
    let mut joined = Vec::new();
    let mut nostr_handles = Vec::new();
    for net in cfg.networks.iter() {
        match mesh.join(net.clone()).await {
            Ok(joined_net) => {
                info!(network = %net.network_id, "joined network");
                let state = joined_net.state();
                if let Some(handle) = myownmesh_core::engine::attach_nostr(&state) {
                    nostr_handles.push(handle);
                } else {
                    warn!(network = %net.network_id, "nostr attach returned no handle");
                }
                joined.push(joined_net);
            }
            Err(e) => {
                warn!(network = %net.network_id, "join failed: {e:#}");
            }
        }
    }

    // Updater tick. Spawned even when disabled in config — the
    // task just exits early.
    let _updater = tokio::spawn(myownmesh_updater::tick_forever());

    // Control socket. Holds a clone of the mesh handle so ctl
    // commands can address the daemon's state.
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let ctl_mesh = mesh.clone();
    let ctl_shutdown = shutdown_tx.subscribe();
    let ctl_socket = cfg.daemon.control_socket.clone();
    let _ctl_handle = tokio::spawn(async move {
        if let Err(e) = control::serve(ctl_mesh, ctl_socket, ctl_shutdown).await {
            warn!("control socket exited with error: {e:#}");
        }
    });

    // Wait for SIGINT (Ctrl-C) or SIGTERM.
    wait_for_shutdown_signal().await;
    info!("shutdown requested");

    let _ = shutdown_tx.send(());
    for net in joined {
        if let Err(e) = net.leave().await {
            warn!("leave failed: {e:#}");
        }
    }
    drop(nostr_handles);

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
