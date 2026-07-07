//! Run the daemon wholly inside a host application's process.
//!
//! This is `myownmesh serve` minus the process: the same mesh instance,
//! network registry, hosted services, updater tick, and control-socket
//! listener, started as tasks on the caller's tokio runtime and torn down
//! through the returned [`EmbeddedDaemon`] instead of a signal handler.
//!
//! The one intended consumer is a mobile app (iOS forbids spawning the
//! daemon as a child process), but nothing here is mobile-specific — any
//! embedder that wants the daemon in-process can use it.

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::control;
use crate::registry::NetworkRegistry;
use crate::services::ServiceManager;

/// A daemon running inside this process. Keep it alive for the daemon's
/// lifetime; call [`shutdown`](Self::shutdown) for the same graceful teardown
/// `myownmesh serve` performs on SIGTERM (stop services, announce departures,
/// leave networks).
pub struct EmbeddedDaemon {
    mesh: myownmesh_core::MeshHandle,
    registry: std::sync::Arc<NetworkRegistry>,
    service_manager: std::sync::Arc<ServiceManager>,
    shutdown_tx: broadcast::Sender<()>,
}

impl EmbeddedDaemon {
    /// The device handle — identity, events, joins.
    pub fn mesh(&self) -> &myownmesh_core::MeshHandle {
        &self.mesh
    }

    /// Graceful teardown, exactly like the serve binary's signal path.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        // Stop hosted services before tearing down networks.
        self.service_manager.shutdown().await;
        // Say goodbye before we go: a graceful `leave` per network so peers
        // drop our sessions immediately rather than waiting out a heartbeat.
        self.registry.announce_all_departures().await;
        for net in self.registry.take_all() {
            if let Err(e) = net.leave().await {
                warn!("leave failed: {e:#}");
            }
        }
    }
}

/// Start the daemon on the current tokio runtime and return once it's
/// serving. Identical to `myownmesh serve` except that shutdown is the
/// caller's (via [`EmbeddedDaemon::shutdown`]) rather than a signal's.
pub async fn start(cfg: myownmesh_core::MeshConfig) -> Result<EmbeddedDaemon> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        networks = cfg.networks.len(),
        "embedded daemon starting"
    );

    let mesh = myownmesh_core::Mesh::open(cfg.clone())
        .await
        .context("open mesh")?;
    info!(device_id = %mesh.identity().display_id(), "identity ready");

    // The registry holds every JoinedNetwork + its signaling driver handle so
    // the control socket can address them by id. Node participation is a
    // toggle, exactly as in the serve binary.
    let registry = NetworkRegistry::new();
    if cfg.services.node.enabled {
        for net in cfg.networks.iter() {
            crate::services::join_network(&mesh, &registry, net.clone()).await;
        }
    } else {
        info!("node participation disabled — pure-infrastructure mode (hosting services only)");
    }

    // Infrastructure services (relay / signaling / STUN / TURN); an all-off
    // config (the default) starts nothing.
    let service_manager = ServiceManager::new(mesh.clone(), registry.clone());
    let report = service_manager.apply(cfg.services.clone()).await;
    info!(
        relay = report.relay.enabled,
        signaling = report.signaling.running,
        stun = report.stun.running,
        turn = report.turn.running,
        "services applied from config"
    );

    // Updater tick. Spawned even when disabled in config — the task just
    // exits early.
    let _updater = tokio::spawn(myownmesh_updater::tick_forever());

    // Control socket: the same listener + wire protocol every client talks
    // to, whether the daemon is a process or embedded.
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let ctl_mesh = mesh.clone();
    let ctl_registry = registry.clone();
    let ctl_services = service_manager.clone();
    let ctl_shutdown = shutdown_tx.subscribe();
    let ctl_socket = cfg.daemon.control_socket.clone();
    tokio::spawn(async move {
        if let Err(e) = control::serve(
            ctl_mesh,
            ctl_registry,
            ctl_services,
            ctl_socket,
            ctl_shutdown,
        )
        .await
        {
            warn!("control socket exited with error: {e:#}");
        }
    });

    Ok(EmbeddedDaemon {
        mesh,
        registry,
        service_manager,
        shutdown_tx,
    })
}
