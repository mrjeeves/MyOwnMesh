//! Tier 6 — user-driven configuration edits. Decides, when the user
//! edits a network's config at runtime, whether the change can be
//! applied in place ([`apply_hot`]) or genuinely needs the transport
//! torn down and rebuilt ([`requires_restart`], orchestrated by the
//! bin's serve loop — the engine task stops cleanly via Shutdown).
//!
//! Why STUN/TURN are *not* a restart
//! ---------------------------------
//! A full restart drops every live peer, including healthy *direct*
//! WebRTC links. That's a sledgehammer for STUN/TURN: those servers
//! only matter while *gathering candidates for a new connection* —
//! an already-connected data channel never touches them again. And
//! [`super::ensure_peer_session`] reads `stun_servers` / `turn_servers`
//! fresh from `state.config` every time it opens a peer, so a hot
//! update reaches every *future* connection (and every reconnect)
//! without disturbing the ones already up. So a STUN/TURN edit —
//! including a venue rotating its time-limited TURN credentials, which
//! otherwise churned the link on every refresh — applies in place.
//!
//! What still needs a restart
//! --------------------------
//! - `network_id`: a different wire-level network entirely (different
//!   room, identity context) — nothing to preserve.
//! - `signaling`: the Nostr driver binds its relay set at start and has
//!   no in-place "switch relays" path (the bridge's outbound receiver is
//!   taken once), so changing relays means recreating the driver. Rare —
//!   venues keep a stable relay set and rotate only credentials.
//! - `semantic_policy`: admission indexes, durable proof history, and
//!   database reservations are constructed from this policy at startup;
//!   changing them in place would make existing ownership accounting
//!   ambiguous, so the exact runtime must be replaced.
//! - Optional Hub, tree and local-observation policies fix retained owner capacities.
//!   Their changes, and topology changes involving a Hub/tree controller, also
//!   require exact runtime replacement.
//! - `introduction` fixes introduction and demand-link lifetimes/capacities.
//!   Enabling, disabling or editing it replaces the exact
//!   runtime; opaque-flow provider policy remains independent.
//!
//! Local record identity and bootstrap kind edits are refused by [`validate_update`].

use std::sync::Arc;

use crate::config::NetworkConfig;
use crate::error::{Error, Result};

use super::state::NetworkState;

/// Returns `true` when the new config differs from the current one in a
/// way that can't be applied to a running network — `network_id`
/// (a different network), `signaling` (the relay set the Nostr driver
/// is bound to),
/// `semantic_policy` (the admission/store resource envelope), or any
/// construction-time pin, scheduler or broadcast state. Changes to kind
/// or record id also refuse hot application, but must pass [`validate_update`]
/// before replacement (they are not permitted edits). STUN/TURN, unfunded topology,
/// label, and auto-approve are all applied in place by [`apply_hot`]
/// without dropping peers.
/// Changes to `introduction` and `semantic_policy` require restart because
/// their provider-backed/resource-accounting profiles are fixed when
/// `NetworkState` is constructed.
pub fn requires_restart(current: &NetworkConfig, next: &NetworkConfig) -> bool {
    current.id != next.id
        || current.kind != next.kind
        || current.network_id != next.network_id
        || current.pinned_peers != next.pinned_peers
        || current.signaling != next.signaling
        || current.semantic_policy != next.semantic_policy
        || current.scheduler != next.scheduler
        || current.hub != next.hub
        || current.tree != next.tree
        || current.local_observations != next.local_observations
        || current.introduction != next.introduction
        || topology_requires_restart(current, &next.topology)
        || current.event_capacity != next.event_capacity
        || current.connection_trace_capacity != next.connection_trace_capacity
}

/// Validate an edit before either live mutation, predecessor teardown, or saving.
/// A restart decision is not permission to mint a different bootstrap policy.
#[doc(hidden)]
pub fn validate_update(current: &NetworkConfig, next: &NetworkConfig) -> Result<()> {
    if current.id != next.id {
        return Err(Error::Config(
            "network config record id cannot be edited in place".into(),
        ));
    }
    if current.kind != next.kind {
        return Err(Error::Config(
            "network kind is bootstrap-bound; use explicit network creation/import, not a config edit"
                .into(),
        ));
    }
    next.validate()?;
    next.event_capacity_usize()?;
    next.connection_trace_capacity_usize()?;
    if current.pinned_peers != next.pinned_peers {
        for (index, peer) in next.pinned_peers.iter().enumerate() {
            crate::semantic::DeviceId::from_canonical_str(peer)
                .map_err(|_| Error::Config("pinned peer must be a canonical DeviceId".into()))?;
            if next.pinned_peers[..index].contains(peer) {
                return Err(Error::Config("pinned peers must be unique".into()));
            }
        }
    }
    Ok(())
}

/// Configuration-bound controllers cannot survive a topology replacement.
/// Entering HubTree also needs a fresh, validated and funded parent owner.
pub(crate) fn topology_requires_restart(
    current: &NetworkConfig,
    next: &crate::config::TopologyMode,
) -> bool {
    current.topology != *next
        && (current.hub.is_some()
            || current.tree.is_some()
            || matches!(
                current.topology,
                crate::config::TopologyMode::HubTree { .. }
            )
            || matches!(next, crate::config::TopologyMode::HubTree { .. }))
}

/// Apply the hot-reloadable subset of config without tearing down
/// sessions: STUN/TURN servers (picked up by the next connection),
/// topology, label, and auto-approve. Anything left to a
/// restart is gated by [`requires_restart`].
pub fn apply_hot(state: &Arc<NetworkState>, next: NetworkConfig) -> Result<()> {
    {
        let mut cfg = state.config.write();
        validate_update(&cfg, &next)?;
        if requires_restart(&cfg, &next) {
            return Err(Error::Config(
                "network config change requires an exact runtime replacement".into(),
            ));
        }
        cfg.label = next.label;
        cfg.topology = next.topology.clone();
        cfg.auto_approve = next.auto_approve;
        // ICE servers are read fresh per `open_peer`, so updating them
        // here is enough — live peers keep their current connection and
        // the next connect/reconnect uses the new servers.
        cfg.stun_servers = next.stun_servers;
        cfg.turn_servers = next.turn_servers;
    }
    // Topology is connector/deployment policy, not semantic authority. A
    // hot config edit updates the local runtime directly.
    let effective = next.topology;
    {
        let mut topo = state.topology.write();
        *topo = effective.clone();
    }
    {
        let mut sel = state.topology_impl.write();
        *sel = crate::topology::from_mode(&effective);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{StunServer, TurnServer};

    fn base_config() -> NetworkConfig {
        NetworkConfig::from_network_id("test-id", "test-net")
    }

    fn peer_id() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x63; 32]);
        crate::semantic::DeviceId::from_public_key_bytes(key.verifying_key().to_bytes())
            .expect("valid peer key")
            .to_string()
    }

    #[test]
    fn pin_edits_require_validated_replacement() {
        let current = base_config();
        let mut pins = current.clone();
        pins.pinned_peers.push(peer_id());
        validate_update(&current, &pins).expect("valid replacement config");
        assert!(requires_restart(&current, &pins));
        assert!(requires_restart(&pins, &current));
        assert!(!requires_restart(&pins, &pins));

        let state = super::super::build_test_state("reconcile-route-pins");
        let before = state.config.read().clone();
        let peer = peer_id();
        assert!(!state.is_sticky(&peer));
        let mut next = before.clone();
        next.pinned_peers.push(peer.clone());
        assert!(apply_hot(&state, next).is_err());
        assert_eq!(*state.config.read(), before);
        assert!(!state.is_sticky(&peer));
    }

    #[test]
    fn kind_and_record_identity_edits_cannot_hot_apply() {
        use crate::config::NetworkKind;
        for kind in [NetworkKind::Open, NetworkKind::Closed, NetworkKind::Silent] {
            let mut current = base_config();
            current.kind = kind;
            validate_update(&current, &current).expect("unchanged kind");
            for replacement in [NetworkKind::Open, NetworkKind::Closed, NetworkKind::Silent] {
                let mut next = current.clone();
                next.kind = replacement;
                assert_eq!(
                    validate_update(&current, &next).is_err(),
                    kind != replacement
                );
                assert_eq!(requires_restart(&current, &next), kind != replacement);
            }
        }
        let state = super::super::build_test_state("reconcile-kind-identity");
        let before = state.config.read().clone();
        let context = state.mesh_context_id();
        let mut next = before.clone();
        next.kind = NetworkKind::Closed;
        assert_ne!(before.kind, next.kind);
        assert!(apply_hot(&state, next).is_err());
        let mut next = before.clone();
        next.id.push_str("-renamed");
        assert!(requires_restart(&before, &next));
        assert!(apply_hot(&state, next).is_err());
        assert_eq!(*state.config.read(), before);
        assert_eq!(state.mesh_context_id(), context);
    }

    #[test]
    fn invalid_update_refuses_before_config_or_topology_mutation() {
        let state = super::super::build_test_state("reconcile-invalid-policy");
        let before = state.config.read().clone();
        let topology = state.topology.read().clone();
        let mut scheduling = before.clone();
        scheduling.scheduler.heartbeat_interval_ms = 0;
        let mut capacity = before.clone();
        capacity.event_capacity = 0;
        let mut pins = before.clone();
        pins.pinned_peers.push("not-a-device-id".into());
        let mut duplicate_pins = before.clone();
        duplicate_pins.pinned_peers = vec![peer_id(), peer_id()];
        for mut next in [scheduling, capacity, pins, duplicate_pins] {
            next.label = "must-not-apply".into();
            assert!(validate_update(&before, &next).is_err());
            assert!(apply_hot(&state, next).is_err());
            assert_eq!(*state.config.read(), before);
            assert_eq!(*state.topology.read(), topology);
        }
    }

    #[test]
    fn every_hot_field_matches_full_config_without_owner_replacement() {
        let state = super::super::build_test_state("reconcile-full-hot-parity");
        let before = state.config.read().clone();
        let context = state.mesh_context_id();
        let mut next = before.clone();
        next.label = "hot parity".into();
        next.auto_approve = !before.auto_approve;
        next.topology = crate::config::TopologyMode::Ring { n_preferred: None };
        next.stun_servers = vec![StunServer {
            urls: vec!["stun:example.com:3478".into()],
        }];
        next.turn_servers = vec![TurnServer {
            urls: vec!["turn:example.com:3478".into()],
            username: Some("fixture-user".into()),
            credential: Some("fixture-credential".into()),
        }];
        assert!(!requires_restart(&before, &next));
        apply_hot(&state, next.clone()).expect("validated hot edit");
        assert_eq!(*state.config.read(), next);
        assert_eq!(*state.topology.read(), next.topology);
        assert_eq!(state.mesh_context_id(), context);
        apply_hot(&state, before.clone()).expect("hot rollback");
        assert_eq!(*state.config.read(), before);
    }

    #[test]
    fn tree_owner_policy_and_topology_require_replacement() {
        use crate::config::{TopologyMode, TreePolicyConfig};
        let baseline = base_config();
        let mut tree = baseline.clone();
        tree.topology = TopologyMode::HubTree {
            root: "root".into(),
            hubs: vec!["hub".into()],
            backup_candidates: 0,
        };
        tree.tree = Some(TreePolicyConfig {
            max_children: 0,
            max_backups: 0,
            max_pending: 1,
            max_age_ms: 1000,
        });
        assert!(requires_restart(&baseline, &tree));
        assert!(topology_requires_restart(&baseline, &tree.topology));
        assert!(requires_restart(&tree, &baseline));
        assert!(!requires_restart(&tree, &tree));
        assert!(!topology_requires_restart(&tree, &tree.topology));

        let mut capacity_change = tree.clone();
        capacity_change.tree.as_mut().unwrap().max_children = 1;
        assert!(requires_restart(&tree, &capacity_change));
        let mut root_change = tree.clone();
        if let TopologyMode::HubTree { root, .. } = &mut root_change.topology {
            *root = "replacement-root".into();
        }
        assert!(requires_restart(&tree, &root_change));
        assert!(topology_requires_restart(&tree, &root_change.topology));

        let mut label_change = tree.clone();
        label_change.label = "local label".into();
        assert!(!requires_restart(&tree, &label_change));
    }

    #[test]
    fn local_observation_policy_requires_replacement() {
        let baseline = base_config();
        let mut enabled = baseline.clone();
        enabled.local_observations = Some(crate::config::LocalObservationPolicyConfig {
            max_records: 8,
            max_records_per_subject: 2,
            max_age_ms: 1000,
            max_maintenance_per_tick: 1,
        });
        assert!(requires_restart(&baseline, &enabled));
        assert!(requires_restart(&enabled, &baseline));
        let mut resized = enabled.clone();
        resized.local_observations.as_mut().unwrap().max_records += 1;
        assert!(requires_restart(&enabled, &resized));
        assert!(!requires_restart(&enabled, &enabled));
    }

    #[test]
    fn stun_turn_changes_do_not_require_restart() {
        let current = base_config();
        let mut next = current.clone();
        next.stun_servers = vec![StunServer {
            urls: vec!["stun:example.com:3478".into()],
        }];
        next.turn_servers = vec![TurnServer {
            urls: vec!["turn:example.com:3478".into()],
            username: Some("user".into()),
            credential: Some("rotated-secret".into()),
        }];
        assert!(
            !requires_restart(&current, &next),
            "STUN/TURN edits (incl. rotated credentials) must apply in place, not restart"
        );
    }

    #[test]
    fn signaling_and_network_id_changes_require_restart() {
        let current = base_config();

        let mut diff_net = current.clone();
        diff_net.network_id = "other-net".into();
        assert!(requires_restart(&current, &diff_net));

        let mut diff_sig = current.clone();
        diff_sig.signaling.servers = vec!["wss://relay.example.com".into()];
        assert!(requires_restart(&current, &diff_sig));
    }

    #[test]
    fn construction_time_runtime_resources_require_exact_replacement() {
        let current = base_config();

        let mut scheduler = current.clone();
        scheduler.scheduler.heartbeat_interval_ms += 1;
        assert!(requires_restart(&current, &scheduler));

        let mut events = current.clone();
        events.event_capacity += 1;
        assert!(requires_restart(&current, &events));

        let mut traces = current.clone();
        traces.connection_trace_capacity += 1;
        assert!(requires_restart(&current, &traces));

        let mut semantic = current.clone();
        semantic.semantic_policy.max_proof_bytes += 1;
        assert!(requires_restart(&current, &semantic));
    }

    #[test]
    fn introduction_edits_are_validated_exact_replacements() {
        use crate::config::HubIntroductionPolicyConfig;
        let current = base_config();
        let mut enabled = current.clone();
        enabled.introduction = Some(HubIntroductionPolicyConfig {
            max_records: 4,
            max_waiters_per_target: 2,
            max_signaling_bytes: 32_768,
            max_candidates_per_attempt: 4,
            attempt_timeout_ms: 1_000,
            terminal_retention_ms: 2_000,
            max_transient_links: 2,
            idle_timeout_ms: 3_000,
            max_maintenance_per_tick: 2,
        });
        validate_update(&current, &enabled).expect("valid explicit replacement");
        assert!(requires_restart(&current, &enabled));
        assert!(requires_restart(&enabled, &current));
        assert!(!requires_restart(&enabled, &enabled));
        for field in [
            "max_records",
            "max_waiters_per_target",
            "max_signaling_bytes",
            "max_candidates_per_attempt",
            "attempt_timeout_ms",
            "terminal_retention_ms",
            "max_transient_links",
            "idle_timeout_ms",
            "max_maintenance_per_tick",
        ] {
            let mut value = serde_json::to_value(enabled.introduction.unwrap()).unwrap();
            let old = value[field].as_u64().unwrap();
            value[field] = serde_json::json!(old + 1);
            let mut resized = enabled.clone();
            resized.introduction = Some(serde_json::from_value(value).unwrap());
            validate_update(&enabled, &resized).expect("valid finite field edit");
            assert!(requires_restart(&enabled, &resized), "{field}");
            assert!(requires_restart(&resized, &enabled), "{field}");
        }
        let mut changed = enabled.clone();
        changed.introduction.as_mut().unwrap().idle_timeout_ms += 1;
        assert!(requires_restart(&enabled, &changed));
        validate_update(&enabled, &changed).expect("valid lifetime edit requires replacement");
        let state = super::super::build_test_state("reconcile-introduction");
        let before = state.config.read().clone();
        let mut next = before.clone();
        next.introduction = enabled.introduction;
        assert!(apply_hot(&state, next).is_err());
        assert_eq!(
            *state.config.read(),
            before,
            "refused hot edit leaves live config intact"
        );
    }

    #[test]
    fn label_only_hot_update_keeps_runtime_identity() {
        let state = super::super::build_test_state("reconcile-label");
        let current = state.config.read().clone();
        let mut next = current.clone();
        next.label = "updated-label".into();
        assert!(!requires_restart(&current, &next));
        let state_identity = Arc::as_ptr(&state);

        apply_hot(&state, next).expect("label-only apply_hot");

        assert_eq!(Arc::as_ptr(&state), state_identity);
        assert_eq!(state.config.read().label, "updated-label");
    }

    #[test]
    fn construction_time_change_is_refused_by_hot_path() {
        let state = super::super::build_test_state("reconcile-capacity");
        let current = state.config.read().clone();
        let mut next = current.clone();
        next.event_capacity += 1;

        assert!(apply_hot(&state, next).is_err());
        assert_eq!(state.config.read().event_capacity, current.event_capacity);

        let mut semantic = current.clone();
        semantic.semantic_policy.max_proof_bytes += 1;
        assert!(apply_hot(&state, semantic).is_err());
        assert_eq!(
            state.config.read().semantic_policy,
            current.semantic_policy,
            "semantic policy changes must not hot-apply"
        );
    }

    #[test]
    fn apply_hot_updates_ice_servers_in_place() {
        let state = super::super::build_test_state("reconcile-hot");
        let state_identity = Arc::as_ptr(&state);
        let mut next = state.config.read().clone();
        next.label = "updated-label".into();
        next.turn_servers = vec![TurnServer {
            urls: vec!["turn:fresh.example.com:3478".into()],
            username: Some("user".into()),
            credential: Some("fresh-secret".into()),
        }];
        next.stun_servers = vec![StunServer {
            urls: vec!["stun:fresh.example.com:3478".into()],
        }];

        apply_hot(&state, next).expect("apply_hot");

        assert_eq!(
            Arc::as_ptr(&state),
            state_identity,
            "label-only hot updates preserve the existing runtime Arc"
        );

        let cfg = state.config.read();
        assert_eq!(cfg.turn_servers.len(), 1);
        assert_eq!(
            cfg.turn_servers[0].credential.as_deref(),
            Some("fresh-secret")
        );
        assert_eq!(cfg.stun_servers[0].urls[0], "stun:fresh.example.com:3478");
    }
}
