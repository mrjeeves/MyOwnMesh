//! Tier 6 — user-driven configuration edits. When the user
//! changes signaling servers, STUN, or TURN at runtime, the
//! engine needs to tear down all active sessions and bring them
//! back up against the new config. This module exposes the entry
//! point the handle calls when the user edits config; the
//! actual restart is orchestrated by the bin's serve loop
//! (the engine task itself stops cleanly via Shutdown).

use std::sync::Arc;

use crate::config::NetworkConfig;
use crate::error::Result;

use super::state::NetworkState;

/// Returns `true` when the new config differs from the current
/// one in a way that requires a full restart (signaling, STUN,
/// TURN, network_id). Topology / roster changes don't need a
/// restart and are applied in place by the engine's command
/// queue.
pub fn requires_restart(current: &NetworkConfig, next: &NetworkConfig) -> bool {
    current.network_id != next.network_id
        || current.signaling != next.signaling
        || current.stun_servers != next.stun_servers
        || current.turn_servers != next.turn_servers
}

/// Apply a hot-reloadable subset of config (topology, label,
/// roster path, auto_approve) without tearing down sessions.
pub fn apply_hot(state: &Arc<NetworkState>, next: NetworkConfig) -> Result<()> {
    {
        let mut cfg = state.config.write();
        cfg.label = next.label;
        cfg.topology = next.topology.clone();
        cfg.auto_approve = next.auto_approve;
        cfg.roster_path = next.roster_path;
    }
    {
        let mut topo = state.topology.write();
        *topo = next.topology.clone();
    }
    {
        let mut sel = state.topology_impl.write();
        *sel = crate::topology::from_mode(&next.topology);
    }
    Ok(())
}
