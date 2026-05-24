//! `myownmesh serve` — run the daemon in the foreground.
//!
//! Owns:
//! - one [`myownmesh_core::Mesh`] instance bound to this device's
//!   identity
//! - a Nostr signaling driver per joined network
//! - the updater tick loop
//! - the network registry (so the control socket can address
//!   per-network operations)
//! - the control-socket listener that `myownmesh ctl …` + the GUI
//!   talk to
//! - signal handlers for clean shutdown

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::control;
use crate::registry::NetworkRegistry;

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

    // The registry holds every JoinedNetwork + its signaling driver
    // handle so the control socket can address them by id (peers
    // list, roster ops, topology, add/remove) without serve.rs
    // threading handles through every dispatch arm.
    let registry = NetworkRegistry::new();
    for net in cfg.networks.iter() {
        match mesh.join(net.clone()).await {
            Ok(joined_net) => {
                info!(network = %net.network_id, "joined network");
                let state = joined_net.state();
                let nostr = myownmesh_core::engine::attach_nostr(&state);
                if nostr.is_none() {
                    warn!(network = %net.network_id, "nostr attach returned no handle");
                }
                registry.insert(joined_net, nostr);
            }
            Err(e) => {
                warn!(network = %net.network_id, "join failed: {e:#}");
            }
        }
    }

    // Updater tick. Spawned even when disabled in config — the
    // task just exits early.
    let _updater = tokio::spawn(myownmesh_updater::tick_forever());

    // Control socket. Holds clones of the mesh handle + the registry
    // so ctl commands can address the daemon's state.
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let ctl_mesh = mesh.clone();
    let ctl_registry = registry.clone();
    let ctl_shutdown = shutdown_tx.subscribe();
    let ctl_socket = cfg.daemon.control_socket.clone();
    let _ctl_handle = tokio::spawn(async move {
        if let Err(e) = control::serve(ctl_mesh, ctl_registry, ctl_socket, ctl_shutdown).await {
            warn!("control socket exited with error: {e:#}");
        }
    });

    // Wait for SIGINT (Ctrl-C) or SIGTERM.
    wait_for_shutdown_signal().await;
    info!("shutdown requested");

    let _ = shutdown_tx.send(());
    // Drain the registry — `take_all` returns owned `JoinedNetwork`s
    // for those that aren't still held by an in-flight control
    // request. Anything still pinned by a control client will tear
    // down via process exit; the engine driver task observes its
    // command sender drop and shuts down.
    for net in registry.take_all() {
        if let Err(e) = net.leave().await {
            warn!("leave failed: {e:#}");
        }
    }

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
