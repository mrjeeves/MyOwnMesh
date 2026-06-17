//! Connection tiers + topology reevaluation.
//!
//! [`ConnectionTier`] is the per-peer recovery-state tag surfaced in
//! diagnostics and the GUI. The recovery *logic* itself lives where the
//! reliable signals are: in-place ICE restart in [`super::ice_watchdog`]
//! and [`super::network_watch`], traffic-confirmed promotion back to
//! `Steady` in the engine's inbound path, and rebuild-on-silence in
//! [`super::heartbeat`]. See `CONNECTION-ENGINE.md` for the model. This
//! module also owns the topology selector pass ([`reevaluate_topology`]).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::events::MeshEvent;

use super::connection::PeerStatus;
use super::state::NetworkState;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ConnectionTier {
    /// Tier 1 — receiving app traffic; nothing to do.
    Steady,
    /// Tier 2 — wake event observed; ping all peers + wait.
    WakeProbe,
    /// Tier 2.5 — ICE went disconnected; per-peer watchdog
    /// scheduled. `since` is when the watchdog started.
    IceWatchdog {
        #[serde(skip, default = "now")]
        since: std::time::Instant,
    },
    /// Tier 3 — `pc.restart_ice()` running; awaiting traffic
    /// confirmation. `started` is re-stamped when ICE reconnects, so the
    /// restart-verify watchdog measures "time since the path should be
    /// carrying frames".
    IceRestart {
        #[serde(skip, default = "now")]
        started: std::time::Instant,
    },
    /// Retained for wire / GUI compatibility — the engine no longer
    /// drives a re-handshake loop (silence rebuilds instead), so this is
    /// never produced.
    Rehandshake {
        attempt: u32,
        #[serde(skip, default = "now")]
        next_at: std::time::Instant,
    },
    /// Retained for wire / GUI compatibility — see [`Self::Rehandshake`].
    RoomRejoin {
        attempt: u32,
        #[serde(skip, default = "now")]
        next_at: std::time::Instant,
    },
    /// Tier 6 — signaling / STUN / TURN config edit forced
    /// stop+start.
    StopStart,
}

/// `serde(default)` helper for the skipped `Instant` fields.
fn now() -> std::time::Instant {
    std::time::Instant::now()
}

impl Default for ConnectionTier {
    fn default() -> Self {
        Self::Steady
    }
}

/// Re-run the topology selector and apply any preferred-set diff
/// as shelve / unshelve frames.
pub async fn reevaluate_topology(state: &Arc<NetworkState>) {
    let me = state.identity.public_id().to_string();
    let active_peers: Vec<String> = state
        .peers
        .iter()
        .filter(|e| {
            matches!(
                e.value().state.read().status,
                PeerStatus::Active | PeerStatus::Shelved
            )
        })
        .map(|e| e.key().clone())
        .collect();
    if active_peers.is_empty() {
        return;
    }
    // Compute the preferred set with the lock held just long
    // enough to call the selector; drop before any awaits.
    let preferred = {
        let topology = state.topology_impl.read();
        topology.select_preferred(&me, &active_peers)
    };

    for peer_id in &active_peers {
        let should_be_shelved = !preferred.contains(peer_id);
        let needs_shelve = {
            let Some(peer) = state.peers.get(peer_id) else {
                continue;
            };
            let mut data = peer.state.write();
            let prev = data.local_shelved;
            data.local_shelved = should_be_shelved;
            if should_be_shelved && data.status == PeerStatus::Active {
                data.status = PeerStatus::Shelved;
            } else if !should_be_shelved && data.status == PeerStatus::Shelved {
                data.status = PeerStatus::Active;
            }
            prev != should_be_shelved
        };
        if needs_shelve {
            send_shelve_unshelve(state, peer_id, should_be_shelved).await;
        }
    }
}

async fn send_shelve_unshelve(state: &Arc<NetworkState>, device_id: &str, shelved: bool) {
    use crate::protocol::topology::{ShelveMessage, UnshelveMessage};
    use crate::protocol::MeshMessage;
    let msg = if shelved {
        MeshMessage::Shelve(ShelveMessage {
            reason: Some("topology-rebalance".into()),
        })
    } else {
        MeshMessage::Unshelve(UnshelveMessage {})
    };
    if let Err(e) = super::send_to_peer(state, device_id, &msg).await {
        debug!(peer = %device_id, "shelve/unshelve send failed: {e}");
    }
    state.emit(if shelved {
        MeshEvent::Peer(crate::events::PeerEvent::Shelved {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            reason: Some("topology-rebalance".into()),
            by_us: true,
        })
    } else {
        MeshEvent::Peer(crate::events::PeerEvent::Unshelved {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            by_us: true,
        })
    });
}
