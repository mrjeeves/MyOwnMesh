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

/// The connection-shaping pass for pruning topologies — the second
/// half of what [`reevaluate_topology`] starts. Where the shelve pass
/// only marks links, this one changes the connection set:
///
/// * **Prune** a connected non-edge once BOTH sides have shelved it —
///   the deterministic signal that both nodes computed "not preferred"
///   from their own view, which is the coordination-free agreement to
///   close. The member is re-recorded as Sighted, so it stays visible
///   and a later shape change redials it.
/// * **Dial** a Sighted-but-unconnected member the shape wants an edge
///   to, lex-lower side initiating (both sides agree the edge exists;
///   exactly one may offer or they'd glare).
///
/// Runs on the state-watch tick (see `engine::tick`) rather than
/// inside [`reevaluate_topology`]: the shelve handshake this keys on
/// completes asynchronously, and drop-driven reevaluation calling back
/// into drops would recurse. Idempotent and cheap when the shape is
/// settled; a no-op entirely for non-pruning modes.
pub(crate) async fn shape_connections(state: &Arc<NetworkState>) {
    if !state.topology_impl.read().prunes() {
        return;
    }
    let me = state.identity.public_id().to_string();
    let mut known: Vec<String> = state.peers.iter().map(|e| e.key().clone()).collect();
    known.push(me.clone());

    let mut to_prune: Vec<String> = Vec::new();
    let mut to_dial: Vec<String> = Vec::new();
    {
        let topo = state.topology_impl.read();
        for entry in state.peers.iter() {
            let id = entry.key();
            let has_session = entry.value().session.lock().is_some();
            let edge = topo.edge(&me, id, &known);
            if has_session {
                let data = entry.value().state.read();
                let both_shelved = data.local_shelved && data.remote_shelved;
                let settled = matches!(data.status, PeerStatus::Shelved);
                if !edge && both_shelved && settled && !state.is_sticky(id) {
                    to_prune.push(id.clone());
                }
            } else if edge && me < *id {
                to_dial.push(id.clone());
            }
        }
    }

    for id in to_prune {
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "topology",
            format!(
                "closing shaped-out connection to {} (stays reachable via forwarders)",
                super::short_peer(&id)
            ),
            serde_json::json!({ "peer": id }),
        );
        super::drop_peer(state, &id, crate::events::DropReason::TopologyPruned).await;
        // Keep the member on the map: visible, and redialable the
        // moment the shape wants it again.
        super::note_sighted_without_dialing(state, &id, "topology pruned");
    }
    for id in to_dial {
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "topology",
            format!("dialing shape edge to {}", super::short_peer(&id)),
            serde_json::json!({ "peer": id }),
        );
        super::ensure_peer_session(state, id, crate::transport::Role::Offerer).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TopologyMode;
    use crate::engine::{build_test_state, insert_session_less_peer};
    use crate::topology::from_mode;

    #[tokio::test]
    async fn full_mesh_shape_pass_is_a_noop() {
        let state = build_test_state("shape-noop");
        insert_session_less_peer(&state, "peer-a", None);
        shape_connections(&state).await;
        assert!(
            state.peers.contains_key("peer-a"),
            "non-pruning mode touches nothing"
        );
    }

    #[tokio::test]
    async fn shape_pass_dials_missing_edges_lex_lower_first() {
        let state = build_test_state("shape-dial");
        // Star with the placeholder itself as hub: the edge exists, and
        // '~' sorts above every base32 identity char so we are lex-lower
        // and must initiate.
        *state.topology.write() = TopologyMode::Star { hub: "~hub".into() };
        *state.topology_impl.write() = from_mode(&TopologyMode::Star { hub: "~hub".into() });
        insert_session_less_peer(&state, "~hub", None);
        assert!(state.peers.get("~hub").unwrap().session.lock().is_none());
        shape_connections(&state).await;
        assert!(
            state.peers.get("~hub").unwrap().session.lock().is_some(),
            "the shape pass upgrades a wanted placeholder to a real dial"
        );
    }

    #[tokio::test]
    async fn shape_pass_prunes_only_when_both_sides_shelved() {
        let state = build_test_state("shape-prune");
        let mode = TopologyMode::Star { hub: "~hub".into() };
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = from_mode(&mode);
        // A spoke↔spoke connection (no edge under Star): built as a real
        // session so the prune has something to close.
        crate::engine::ensure_peer_session(
            &state,
            "spoke-b".into(),
            crate::transport::Role::Offerer,
        )
        .await;
        {
            let peer = state.peers.get("spoke-b").unwrap();
            let mut data = peer.state.write();
            data.status = PeerStatus::Shelved;
            data.local_shelved = true;
            data.remote_shelved = false; // remote hasn't agreed yet
        }
        shape_connections(&state).await;
        assert!(
            state.peers.get("spoke-b").unwrap().session.lock().is_some(),
            "one-sided shelve must NOT prune"
        );
        {
            let peer = state.peers.get("spoke-b").unwrap();
            peer.state.write().remote_shelved = true;
        }
        shape_connections(&state).await;
        let entry = state.peers.get("spoke-b").unwrap();
        assert!(
            entry.session.lock().is_none(),
            "both-sides-shelved non-edge closes, member stays Sighted"
        );
    }

    #[tokio::test]
    async fn shape_pass_never_prunes_a_pinned_peer() {
        let state = build_test_state("shape-sticky");
        let mode = TopologyMode::Star { hub: "~hub".into() };
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = from_mode(&mode);
        crate::engine::ensure_peer_session(
            &state,
            "spoke-b".into(),
            crate::transport::Role::Offerer,
        )
        .await;
        state.add_sticky("spoke-b");
        {
            let peer = state.peers.get("spoke-b").unwrap();
            let mut data = peer.state.write();
            data.status = PeerStatus::Shelved;
            data.local_shelved = true;
            data.remote_shelved = true;
        }
        shape_connections(&state).await;
        assert!(
            state.peers.get("spoke-b").unwrap().session.lock().is_some(),
            "a standing dial outranks the shape"
        );
    }
}
