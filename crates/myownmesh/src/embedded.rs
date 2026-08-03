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

use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::control;
use crate::registry::NetworkRegistry;
use crate::services::ServiceManager;

/// Typed startup failures for the embedded daemon.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddedStartError {
    /// Infrastructure-only startup must not create a network participant.
    #[error("infrastructure-only startup requires node participation to be disabled")]
    InfrastructureOnlyRequiresNodeDisabled,

    #[error("open mesh: {0}")]
    OpenMesh(#[from] myownmesh_core::Error),

    #[error("service policy: {0}")]
    ServicePolicy(#[from] crate::services::ServicePolicyError),
}

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

enum ServiceCompatibility {
    V4,
    #[cfg(feature = "legacy-v1")]
    LegacyV1(myownmesh_core::LegacyV1Runtime),
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

/// Start the daemon with the connector policy selected by the process owner.
///
/// This is the only Arc 03 daemon path that can establish connectors. No
/// capacity, callback weight, or structural real-time limit is inferred here.
pub async fn start_connector_capable(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::ConnectorCapableResourcePolicy,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    ServiceManager::validate_config(&cfg.services)?;
    let mesh = myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?;
    start_with_mesh(cfg, mesh, ServiceCompatibility::V4).await
}

/// Start the connector-capable daemon with an explicit frozen LegacyV1
/// compatibility runtime.
///
/// The normal V4 startup path cannot construct or reach this authority. This
/// function exists only with the `legacy-v1` feature and is scheduled for
/// deletion after downstream relay migration.
#[cfg(feature = "legacy-v1")]
#[allow(
    deprecated,
    reason = "this API is the explicit frozen LegacyV1 boundary"
)]
#[deprecated(
    since = "0.3.2",
    note = "LegacyV1 application routing is frozen and scheduled for removal after downstream migration"
)]
pub async fn start_connector_capable_with_legacy_v1(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::ConnectorCapableResourcePolicy,
    runtime: myownmesh_core::LegacyV1Runtime,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    let mesh = myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?;
    start_with_mesh(cfg, mesh, ServiceCompatibility::LegacyV1(runtime)).await
}

/// Start a daemon that only hosts signaling, STUN, or TURN infrastructure.
///
/// The configuration must explicitly disable node participation. This form
/// installs no connector policy, joins no network, and cannot later enable
/// node participation through the live service configuration.
pub async fn start_infrastructure_only(
    cfg: myownmesh_core::MeshConfig,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    if cfg.services.node.enabled {
        return Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled);
    }
    ServiceManager::validate_config(&cfg.services)?;
    let mesh = myownmesh_core::Mesh::open_infrastructure_only(cfg.clone()).await?;
    start_with_mesh(cfg, mesh, ServiceCompatibility::V4).await
}

async fn start_with_mesh(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    compatibility: ServiceCompatibility,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        networks = cfg.networks.len(),
        "embedded daemon starting"
    );

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
    let service_manager = match compatibility {
        ServiceCompatibility::V4 => ServiceManager::new(mesh.clone(), registry.clone()),
        #[cfg(feature = "legacy-v1")]
        ServiceCompatibility::LegacyV1(runtime) => {
            ServiceManager::new_with_legacy_v1(mesh.clone(), registry.clone(), runtime)
        }
    };
    let report = service_manager.apply(cfg.services.clone()).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn infrastructure_start_requires_node_participation_disabled() {
        let result = start_infrastructure_only(myownmesh_core::MeshConfig::default()).await;
        assert!(matches!(
            result,
            Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled)
        ));
    }
}
