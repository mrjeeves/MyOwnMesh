//! 7-tier reconnection ladder. See `CONNECTION-ENGINE.md` for the
//! full table.
//!
//! Tier escalations are per-peer and idempotent — the engine
//! tolerates being told to escalate twice. Lower tiers
//! supersede higher when the state machine confirms recovery
//! (e.g. an `IceWatchdog` resolves to `Steady` on the next
//! Connected event).

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::events::MeshEvent;

use super::connection::PeerStatus;
use super::scheduler::{
    RECONNECTING_GRACE_MS, REHANDSHAKE_BACKOFF_MS_SCHEDULE, REHANDSHAKE_JITTER_FRACTION,
    REHANDSHAKE_RESCUE_ATTEMPTS,
};
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
        #[serde(skip, default = "Instant::now")]
        since: Instant,
    },
    /// Tier 3 — `pc.restart_ice()` running; grace window open.
    IceRestart {
        #[serde(skip, default = "Instant::now")]
        started: Instant,
    },
    /// Tier 4 — per-peer re-handshake loop.
    Rehandshake {
        attempt: u32,
        #[serde(skip, default = "Instant::now")]
        next_at: Instant,
    },
    /// Tier 5 — Trystero room rejoin (throttled).
    RoomRejoin {
        attempt: u32,
        #[serde(skip, default = "Instant::now")]
        next_at: Instant,
    },
    /// Tier 6 — signaling / STUN / TURN config edit forced
    /// stop+start.
    StopStart,
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

/// Tier 4 entry: schedule a re-handshake loop for one peer.
pub async fn escalate_to_rehandshake(state: &Arc<NetworkState>, device_id: &str) {
    let attempt = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        if data.rehandshake_attempt >= REHANDSHAKE_RESCUE_ATTEMPTS {
            state.log_diag_with(
                crate::events::DiagLevel::Warn,
                "ladder",
                format!("rehandshake attempts exhausted for {device_id} — escalating to Tier 5"),
                serde_json::json!({ "peer": device_id }),
            );
            data.tier = ConnectionTier::RoomRejoin {
                attempt: 1,
                next_at: Instant::now(),
            };
            data.status = PeerStatus::Offline;
            return;
        }
        data.rehandshake_attempt += 1;
        data.status = PeerStatus::Reconnecting;
        let attempt = data.rehandshake_attempt as usize;
        let base = REHANDSHAKE_BACKOFF_MS_SCHEDULE[attempt
            .saturating_sub(1)
            .min(REHANDSHAKE_BACKOFF_MS_SCHEDULE.len() - 1)];
        let jittered = jittered_delay_ms(base, REHANDSHAKE_JITTER_FRACTION);
        data.tier = ConnectionTier::Rehandshake {
            attempt: data.rehandshake_attempt,
            next_at: Instant::now() + std::time::Duration::from_millis(jittered),
        };
        data.rehandshake_attempt
    };
    let state_clone = state.clone();
    let device_id = device_id.to_string();
    tokio::spawn(async move {
        let delay_ms = {
            let Some(peer) = state_clone.peers.get(&device_id) else {
                return;
            };
            let data = peer.state.read();
            match data.tier {
                ConnectionTier::Rehandshake { next_at, .. } => next_at
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    as u64,
                _ => 0,
            }
        };
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        state_clone.log_diag_with(
            crate::events::DiagLevel::Info,
            "ladder",
            format!("Tier 4 re-handshake attempt {attempt} for {device_id}"),
            serde_json::json!({ "peer": device_id, "attempt": attempt }),
        );
        super::handshake::initiate(&state_clone, &device_id).await;
    });
}

/// Tier 5 maximum-age sweep. Any peer in `Reconnecting` past the
/// grace window gets dropped.
pub async fn reconnect_prune_tick(state: &Arc<NetworkState>) {
    let now = Instant::now();
    let prune: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            if !matches!(data.status, PeerStatus::Reconnecting | PeerStatus::Offline) {
                return None;
            }
            let started = match data.tier {
                ConnectionTier::Rehandshake { next_at, .. } => Some(next_at),
                ConnectionTier::RoomRejoin { next_at, .. } => Some(next_at),
                _ => None,
            }?;
            if now.saturating_duration_since(started).as_millis() as u64 > RECONNECTING_GRACE_MS {
                Some(e.key().clone())
            } else {
                None
            }
        })
        .collect();
    for peer in prune {
        trace!(peer = %peer, "pruning stale reconnecting entry");
        super::drop_peer(state, &peer, crate::events::DropReason::HeartbeatTimeout).await;
    }
}

/// Tier 5 — rostered peer offline > OFFLINE_ROSTERED_CHECK_INTERVAL_MS
/// triggers a room rejoin. v1 leaves the actual rejoin to the
/// embedded signaling task (it's room-level, not peer-level).
pub async fn offline_check_tick(_state: &Arc<NetworkState>) {
    // Placeholder for the room-rejoin escalation. The room
    // rejoin is initiated by the signaling task in response to
    // an engine command — wiring lands when the signaling
    // concrete driver does.
}

fn jittered_delay_ms(base_ms: u64, fraction: f64) -> u64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let signed: f64 = rng.gen_range(-1.0..=1.0);
    let delta = (base_ms as f64) * fraction * signed;
    ((base_ms as f64) + delta).max(0.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jittered_delay_stays_in_range() {
        for _ in 0..100 {
            let v = jittered_delay_ms(10_000, 0.2);
            assert!((8_000..=12_000).contains(&v), "out of range: {v}");
        }
    }

    #[test]
    fn jittered_delay_zero_base_returns_zero() {
        for _ in 0..20 {
            assert_eq!(jittered_delay_ms(0, 0.2), 0);
        }
    }
}
