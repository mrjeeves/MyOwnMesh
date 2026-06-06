//! Daemon-side lifecycle for the infrastructure services a device hosts
//! for the mesh: the per-network relay forwarder, the self-hosted
//! signaling relay, and the STUN / TURN servers.
//!
//! The [`ServiceManager`] owns the running handles, reconciles them
//! against [`ServicesConfig`] on demand (start what should run, stop
//! what shouldn't), and keeps every joined network's advertised
//! capabilities in sync so peers discover the roles this device offers.
//! It's shared (behind an `Arc`) between [`crate::cli::serve`] — which
//! applies the initial config and tears everything down on shutdown —
//! and the control socket, which handles live `services set` requests.
//!
//! Service start failures are non-fatal: a port already in use shouldn't
//! take the daemon down, so a failed start is logged and surfaced in the
//! status report as `enabled but not running`, leaving the rest of the
//! mesh untouched.

use std::collections::HashMap;
use std::sync::Arc;

use myownmesh_core::services::{ServiceAdvert, ServiceRole};
use myownmesh_core::{CapabilityAdvert, MeshHandle, RelayService, ServicesConfig};
use myownmesh_services::{StunServer, StunServerHandle, TurnServer, TurnServerHandle};
use myownmesh_signaling::server::{SignalingServer, SignalingServerHandle};
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::registry::NetworkRegistry;

/// Owns every running service handle and the config they were started
/// from. Reconfiguration goes through [`ServiceManager::apply`].
pub struct ServiceManager {
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    state: Mutex<ManagerState>,
}

struct ManagerState {
    config: ServicesConfig,
    stun: Option<StunServerHandle>,
    turn: Option<TurnServerHandle>,
    signaling: Option<SignalingServerHandle>,
    /// One relay forwarder per joined network, keyed by config id.
    relays: HashMap<String, RelayService>,
}

/// Status snapshot for the control protocol / CLI / GUI.
#[derive(Debug, Clone, Serialize)]
pub struct ServicesReport {
    pub relay: RelayReport,
    pub signaling: EndpointReport,
    pub stun: EndpointReport,
    pub turn: EndpointReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointReport {
    pub enabled: bool,
    /// True when the listener is actually bound and serving. Differs
    /// from `enabled` when a start failed (e.g. port in use).
    pub running: bool,
    /// The address the listener bound, when running.
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayReport {
    pub enabled: bool,
    /// Number of networks currently being relayed.
    pub networks: usize,
    pub max_fanout: u32,
}

impl ServiceManager {
    pub fn new(mesh: MeshHandle, registry: Arc<NetworkRegistry>) -> Arc<Self> {
        Arc::new(Self {
            mesh,
            registry,
            state: Mutex::new(ManagerState {
                config: ServicesConfig::default(),
                stun: None,
                turn: None,
                signaling: None,
                relays: HashMap::new(),
            }),
        })
    }

    /// Reconcile running services against `desired`. Starts newly-enabled
    /// or reconfigured services, stops disabled ones, rebuilds the relay
    /// set from the current network registry, and refreshes capability
    /// adverts. Returns the resulting status. Per-service start failures
    /// are logged, not propagated.
    pub async fn apply(&self, desired: ServicesConfig) -> ServicesReport {
        let mut g = self.state.lock().await;

        // ---- STUN ----
        if g.stun.is_some() != desired.stun.enabled || g.config.stun != desired.stun {
            if let Some(h) = g.stun.take() {
                h.stop();
            }
            if desired.stun.enabled {
                match StunServer::start(&desired.stun).await {
                    Ok(h) => g.stun = Some(h),
                    Err(e) => warn!("STUN service failed to start: {e}"),
                }
            }
        }

        // ---- TURN ----
        if g.turn.is_some() != desired.turn.enabled || g.config.turn != desired.turn {
            if let Some(h) = g.turn.take() {
                let _ = h.stop().await;
            }
            if desired.turn.enabled {
                match TurnServer::start(&desired.turn).await {
                    Ok(h) => g.turn = Some(h),
                    Err(e) => warn!("TURN service failed to start: {e}"),
                }
            }
        }

        // ---- Signaling ----
        if g.signaling.is_some() != desired.signaling.enabled
            || g.config.signaling != desired.signaling
        {
            if let Some(h) = g.signaling.take() {
                h.stop();
            }
            if desired.signaling.enabled {
                match SignalingServer::start(&desired.signaling.bind, desired.signaling.port).await
                {
                    Ok(h) => g.signaling = Some(h),
                    Err(e) => warn!("signaling service failed to start: {e}"),
                }
            }
        }

        // ---- Relay (per network) ----
        // Cheap to rebuild — RelayService just (re)subscribes to a
        // reserved channel — so reconcile by clearing and re-deriving
        // from the live registry whenever apply runs.
        g.relays.clear();
        if desired.relay.enabled {
            let fanout = desired.relay.max_fanout;
            for summary in self.registry.summaries() {
                if let Some(joined) = self.registry.get(&summary.config_id) {
                    g.relays.insert(
                        summary.config_id,
                        RelayService::start(joined.state(), fanout),
                    );
                }
            }
        }

        g.config = desired;
        self.refresh_adverts_locked(&g);
        info!(
            stun = g.stun.is_some(),
            turn = g.turn.is_some(),
            signaling = g.signaling.is_some(),
            relays = g.relays.len(),
            "services reconciled"
        );
        g.report()
    }

    /// Snapshot the current service status without changing anything.
    pub async fn status(&self) -> ServicesReport {
        self.state.lock().await.report()
    }

    /// The currently-applied config (for persistence round-trips).
    pub async fn current_config(&self) -> ServicesConfig {
        self.state.lock().await.config.clone()
    }

    /// Hook for when a network joins after services were applied: start a
    /// relay for it if relay hosting is on, and push the current advert.
    pub async fn on_network_added(&self, config_id: &str) {
        let mut g = self.state.lock().await;
        let (enabled, fanout) = (g.config.relay.enabled, g.config.relay.max_fanout);
        if enabled && !g.relays.contains_key(config_id) {
            if let Some(joined) = self.registry.get(config_id) {
                g.relays.insert(
                    config_id.to_string(),
                    RelayService::start(joined.state(), fanout),
                );
            }
        }
        self.refresh_adverts_locked(&g);
    }

    /// Hook for when a network leaves: drop its relay forwarder.
    pub async fn on_network_removed(&self, config_id: &str) {
        self.state.lock().await.relays.remove(config_id);
    }

    /// Stop every running service. Called on daemon shutdown.
    pub async fn shutdown(&self) {
        let mut g = self.state.lock().await;
        g.relays.clear();
        if let Some(h) = g.stun.take() {
            h.stop();
        }
        if let Some(h) = g.signaling.take() {
            h.stop();
        }
        if let Some(h) = g.turn.take() {
            let _ = h.stop().await;
        }
    }

    /// Push the service-role capability advert to every joined network so
    /// peers see what this device hosts.
    fn refresh_adverts_locked(&self, g: &ManagerState) {
        let advert = build_capability_advert(&g.config);
        for summary in self.registry.summaries() {
            if let Some(joined) = self.registry.get(&summary.config_id) {
                joined.advertise(advert.clone());
            }
        }
        // Touch `mesh` so the field is considered used even on builds
        // where no networks are joined yet; keeps the handle around for
        // future per-device advert needs.
        let _ = &self.mesh;
    }
}

impl ManagerState {
    fn report(&self) -> ServicesReport {
        ServicesReport {
            relay: RelayReport {
                enabled: self.config.relay.enabled,
                networks: self.relays.len(),
                max_fanout: self.config.relay.max_fanout,
            },
            signaling: EndpointReport {
                enabled: self.config.signaling.enabled,
                running: self.signaling.is_some(),
                listen: self.signaling.as_ref().map(|h| h.local_addr().to_string()),
            },
            stun: EndpointReport {
                enabled: self.config.stun.enabled,
                running: self.stun.is_some(),
                listen: self.stun.as_ref().map(|h| h.local_addr().to_string()),
            },
            turn: EndpointReport {
                enabled: self.config.turn.enabled,
                running: self.turn.is_some(),
                listen: self.turn.as_ref().map(|h| h.local_addr().to_string()),
            },
        }
    }
}

/// Build the capability advert describing the services this device
/// hosts. Role tags are always set for enabled services so peers can
/// discover the host; concrete endpoint URLs are added only when a
/// public address is known (we use the TURN `public_ip` as the host
/// hint, since an operator who set it has declared the device's routable
/// address).
fn build_capability_advert(config: &ServicesConfig) -> CapabilityAdvert {
    let mut tags = Vec::new();
    if config.relay.enabled {
        tags.push(ServiceRole::Relay.tag().to_string());
    }
    if config.signaling.enabled {
        tags.push(ServiceRole::Signaling.tag().to_string());
    }
    if config.stun.enabled {
        tags.push(ServiceRole::Stun.tag().to_string());
    }
    if config.turn.enabled {
        tags.push(ServiceRole::Turn.tag().to_string());
    }

    let host = {
        let h = config.turn.public_ip.trim();
        if h.is_empty() {
            None
        } else {
            Some(h.to_string())
        }
    };
    let mut advert = ServiceAdvert {
        relay: config.relay.enabled,
        ..Default::default()
    };
    if let Some(host) = host {
        if config.signaling.enabled {
            advert.signaling_url = Some(format!("ws://{host}:{}", config.signaling.port));
        }
        if config.stun.enabled {
            advert.stun_url = Some(format!("stun:{host}:{}", config.stun.port));
        }
        if config.turn.enabled {
            advert.turn_url = Some(format!("turn:{host}:{}", config.turn.port));
        }
    }

    let mut extra = serde_json::Value::Null;
    advert.write_into_extra(&mut extra);

    CapabilityAdvert {
        tags,
        app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        max_connections: None,
        extra,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myownmesh_core::services::ServiceAdvert;

    #[test]
    fn advert_tags_track_enabled_services() {
        let mut cfg = ServicesConfig::default();
        cfg.signaling.enabled = true;
        cfg.turn.enabled = true;
        let advert = build_capability_advert(&cfg);
        assert!(advert.tags.contains(&"service:signaling".to_string()));
        assert!(advert.tags.contains(&"service:turn".to_string()));
        assert!(!advert.tags.contains(&"service:stun".to_string()));
    }

    #[test]
    fn advert_endpoints_use_turn_public_ip_as_host() {
        let mut cfg = ServicesConfig::default();
        cfg.signaling.enabled = true;
        cfg.turn.enabled = true;
        cfg.turn.public_ip = "203.0.113.9".into();
        let advert = build_capability_advert(&cfg);
        let svc = ServiceAdvert::from_extra(&advert.extra).unwrap();
        assert_eq!(
            svc.signaling_url.as_deref(),
            Some(format!("ws://203.0.113.9:{}", cfg.signaling.port).as_str())
        );
        assert_eq!(svc.turn_url.as_deref(), Some("turn:203.0.113.9:3478"));
    }

    #[test]
    fn advert_without_public_ip_has_tags_but_no_urls() {
        let mut cfg = ServicesConfig::default();
        cfg.signaling.enabled = true;
        let advert = build_capability_advert(&cfg);
        // Role tag present...
        assert!(advert.tags.contains(&"service:signaling".to_string()));
        // ...but no URL since we don't know a reachable host.
        assert_eq!(ServiceAdvert::from_extra(&advert.extra), None);
    }
}
