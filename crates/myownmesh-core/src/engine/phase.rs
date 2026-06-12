//! Per-network phase computation. Re-runs whenever a peer's
//! status flips; emits a `Phase::Changed` event when the rollup
//! result differs from the cached value.

use std::sync::Arc;

use crate::events::MeshPhase;

use super::connection::PeerStatus;
use super::state::NetworkState;

/// Recompute the rolled-up phase from the per-peer states.
/// Cheap — single pass over the peers map.
pub fn recompute(state: &Arc<NetworkState>) {
    let next = current(state);
    state.set_phase(next);
}

fn current(state: &Arc<NetworkState>) -> MeshPhase {
    if state.peers.is_empty() {
        return MeshPhase::Alone;
    }
    let mut any_active = false;
    let mut any_authenticated = false;
    let mut any_sighted = false;
    let mut any_reconnecting = false;
    for entry in state.peers.iter() {
        let data = entry.value().state.read();
        match data.status {
            PeerStatus::Active | PeerStatus::Shelved => any_active = true,
            PeerStatus::PendingApproval => any_authenticated = true,
            PeerStatus::Handshaking | PeerStatus::Sighted => any_sighted = true,
            PeerStatus::Reconnecting => any_reconnecting = true,
            // Parked is a deliberate steady state (peer present, no
            // transport by topology decision) — it neither makes the
            // mesh Active nor Degraded.
            PeerStatus::Parked | PeerStatus::Offline | PeerStatus::Error => {}
        }
    }
    if any_active {
        MeshPhase::Active
    } else if any_authenticated || any_sighted {
        // Authenticated-but-unapproved and freshly-sighted both
        // sit at the same rollup; the per-peer events carry the
        // finer-grained state.
        MeshPhase::Discovering
    } else if any_reconnecting {
        MeshPhase::Degraded
    } else {
        MeshPhase::Alone
    }
}
