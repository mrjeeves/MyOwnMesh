//! 7-tier reconnection ladder. See `CONNECTION-ENGINE.md` for the
//! full table.
//!
//! Tier escalations are per-peer and idempotent — the engine
//! tolerates being told to escalate twice. Lower tiers
//! supersede higher when the state machine confirms recovery
//! (e.g. an `IceWatchdog` resolves to `Steady` on the next
//! Connected event).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::events::{MeshEvent, PeerEvent};
use crate::protocol::features::{peer_supports, Feature};

use super::connection::{PeerConnection, PeerStatus};
use super::scheduler::{
    PARKED_PRESENCE_TTL_MS, PARK_LINGER_MS, RECONNECTING_GRACE_MS, REHANDSHAKE_BACKOFF_MS_SCHEDULE,
    REHANDSHAKE_JITTER_FRACTION, REHANDSHAKE_RESCUE_ATTEMPTS,
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

/// Re-run the topology selector and apply both of its decisions:
/// the preferred-set diff as shelve / unshelve frames, then the
/// connect-set diff as park / unpark transitions.
pub async fn reevaluate_topology(state: &Arc<NetworkState>) {
    shelve_pass(state).await;
    park_pass(state).await;
}

/// Preferred-set pass: shelve / unshelve currently-connected peers.
async fn shelve_pass(state: &Arc<NetworkState>) {
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

/// All peers the topology should treat as present in the network:
/// every tracked entry that isn't in a fatal state. Reconnecting /
/// Offline entries are included — they were present moments ago and
/// the prune sweep removes them if they're really gone; excluding
/// them early would shift everyone's ring positions on a blip.
fn present_ids(state: &Arc<NetworkState>, extra: Option<&str>) -> Vec<String> {
    let mut present: Vec<String> = state
        .peers
        .iter()
        .filter(|e| e.value().state.read().status != PeerStatus::Error)
        .map(|e| e.key().clone())
        .collect();
    if let Some(extra) = extra {
        if !present.iter().any(|p| p == extra) {
            present.push(extra.to_string());
        }
    }
    present
}

/// The *effective* connect set: the selector's own picks, OR'd with
/// every present peer that would pick us from its seat. Returns
/// `None` when the cap is disabled.
///
/// The OR is what makes parking flap-free. Ring shortcut picks may be
/// one-way (see `topology::ring`'s `shortcut_asymmetry_is_expected`)
/// — harmless for shelving, but at the transport level a one-way pick
/// would mean one end parks (closes) an edge the other end keeps
/// re-dialing. Keeping the edge when *either* end picks it is
/// symmetric by construction — both ends can evaluate both directions
/// locally because selectors are pure functions, so over a converged
/// presence view they reach the same verdict without a round trip.
fn effective_connect_set(
    state: &Arc<NetworkState>,
    me: &str,
    present: &[String],
) -> Option<HashSet<String>> {
    let topology = state.topology_impl.read();
    let mut connect = topology.select_connect(me, present)?;
    // Reverse picks: for each peer not already in, run the selector
    // from *their* seat over the same universe and keep them if they
    // would keep us.
    let mut universe: Vec<String> = present.to_vec();
    universe.push(me.to_string());
    for peer_id in present {
        if connect.contains(peer_id) {
            continue;
        }
        let their_view: Vec<String> = universe.iter().filter(|p| *p != peer_id).cloned().collect();
        let picks_us = topology
            .select_connect(peer_id, &their_view)
            .is_some_and(|s| s.contains(me));
        if picks_us {
            connect.insert(peer_id.clone());
        }
    }
    Some(connect)
}

/// Connect-set pass: expire ghost parked entries, unpark peers the
/// topology rebalanced back in, and park (after a linger) connected
/// peers the topology rebalanced out.
async fn park_pass(state: &Arc<NetworkState>) {
    let me = state.identity.public_id().to_string();
    let now = Instant::now();

    // Phase 0 — presence decay. Parked entries have no transport to
    // die on; an entry whose announces stopped is a ghost holding a
    // ring slot. Remove before computing the connect set so a dead
    // neighbor's replacement gets picked this pass, not next.
    let expired: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            let silent_ms = match (data.status, data.last_announce_at) {
                (PeerStatus::Parked, Some(at)) => {
                    now.saturating_duration_since(at).as_millis() as u64
                }
                (PeerStatus::Parked, None) => u64::MAX,
                _ => return None,
            };
            (silent_ms > PARKED_PRESENCE_TTL_MS).then(|| e.key().clone())
        })
        .collect();
    for peer_id in &expired {
        state.peers.remove(peer_id);
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "topology",
            format!(
                "parked peer {} presence expired — removing",
                super::short_peer(peer_id)
            ),
            serde_json::json!({ "peer": peer_id, "ttl_ms": PARKED_PRESENCE_TTL_MS }),
        );
        state.emit(MeshEvent::Peer(PeerEvent::Dropped {
            network_id: state.network_id.clone(),
            device_id: peer_id.clone(),
            reason: crate::events::DropReason::HeartbeatTimeout,
            grace_window_ms: 0,
        }));
    }
    if !expired.is_empty() {
        super::phase::recompute(state);
    }

    let present = present_ids(state, None);
    if present.is_empty() {
        return;
    }
    let Some(connect) = effective_connect_set(state, &me, &present) else {
        // Cap disabled (full mesh / star / ring n_connect = 0).
        // Re-dial anything parked under a previous config and clear
        // the timers so nothing lingers half-armed.
        let mut to_unpark = Vec::new();
        for peer_id in &present {
            let Some(peer) = state.peers.get(peer_id) else {
                continue;
            };
            let mut data = peer.state.write();
            data.park_pending_since = None;
            if data.status == PeerStatus::Parked {
                to_unpark.push(peer_id.clone());
            }
        }
        for peer_id in to_unpark {
            unpark_peer(state, &peer_id).await;
        }
        return;
    };

    enum Action {
        Unpark,
        Park,
        None,
    }
    for peer_id in &present {
        let action = {
            let Some(peer) = state.peers.get(peer_id) else {
                continue;
            };
            let mut data = peer.state.write();
            if connect.contains(peer_id) {
                data.park_pending_since = None;
                if data.status == PeerStatus::Parked {
                    Action::Unpark
                } else {
                    Action::None
                }
            } else {
                match data.status {
                    PeerStatus::Parked => Action::None,
                    // A user is (possibly) looking at this peer's
                    // approval card — don't yank it out from under
                    // them. Out-of-set pending approvals only arise
                    // from inbound dials, and resolve to a normal
                    // connected status the sweep handles next pass.
                    PeerStatus::PendingApproval => {
                        data.park_pending_since = None;
                        Action::None
                    }
                    _ => {
                        // Legacy exemption: a handshaken peer that
                        // doesn't speak parking would treat our
                        // teardown as a fault and redial forever.
                        // Leave its connection shelved, like before
                        // the cap existed.
                        let legacy = data.authenticated
                            && !peer_supports(&data.remote_features, Feature::TOPOLOGY_PARK_V1);
                        if legacy {
                            data.park_pending_since = None;
                            Action::None
                        } else {
                            match data.park_pending_since {
                                None => {
                                    data.park_pending_since = Some(now);
                                    Action::None
                                }
                                Some(since)
                                    if now.saturating_duration_since(since).as_millis() as u64
                                        >= PARK_LINGER_MS =>
                                {
                                    Action::Park
                                }
                                Some(_) => Action::None,
                            }
                        }
                    }
                }
            }
        };
        match action {
            Action::Unpark => unpark_peer(state, peer_id).await,
            Action::Park => park_peer(state, peer_id, "connect-set-rebalance").await,
            Action::None => {}
        }
    }
}

/// Demote a connected peer to Parked: replace its entry with a fresh
/// session-less one (a fresh epoch, so the closing session's trailing
/// transport events are recognised as stale and ignored) and close
/// the old transport off the driver task.
async fn park_peer(state: &Arc<NetworkState>, device_id: &str, reason: &str) {
    let Some((_, old)) = state.peers.remove(device_id) else {
        return;
    };
    let (label, capabilities, remote_features) = {
        let data = old.state.read();
        (
            data.label.clone(),
            data.capabilities.clone(),
            data.remote_features.clone(),
        )
    };
    let parked = Arc::new(PeerConnection::new(device_id.to_string(), None));
    {
        let mut data = parked.state.write();
        data.status = PeerStatus::Parked;
        data.label = label;
        data.capabilities = capabilities;
        data.remote_features = remote_features;
        data.last_announce_at = Some(Instant::now());
    }
    state.peers.insert(device_id.to_string(), parked);
    if let Some(session) = old.session.lock().clone() {
        tokio::spawn(async move {
            let _ = session.close().await;
        });
    }
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "topology",
        format!("parked {} ({reason})", super::short_peer(device_id)),
        serde_json::json!({ "peer": device_id, "reason": reason }),
    );
    state.emit(MeshEvent::Peer(PeerEvent::Parked {
        network_id: state.network_id.clone(),
        device_id: device_id.to_string(),
        reason: Some(reason.to_string()),
    }));
    super::phase::recompute(state);
}

/// Promote a parked peer back toward connected: drop the placeholder
/// entry and re-enter the normal dial path. The lex-lower side
/// offers (same glare rule as discovery); the other side announces
/// so the offerer notices us promptly, then answers the offer when
/// it arrives.
async fn unpark_peer(state: &Arc<NetworkState>, device_id: &str) {
    if state.peers.remove(device_id).is_none() {
        return;
    }
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "topology",
        format!(
            "unparking {} (connect-set rebalance)",
            super::short_peer(device_id)
        ),
        serde_json::json!({ "peer": device_id }),
    );
    state.emit(MeshEvent::Peer(PeerEvent::Unparked {
        network_id: state.network_id.clone(),
        device_id: device_id.to_string(),
    }));
    let me = state.identity.public_id().to_string();
    if me.as_str() < device_id {
        super::ensure_peer_session(
            state,
            device_id.to_string(),
            crate::transport::Role::Offerer,
        )
        .await;
    } else {
        super::maybe_reactive_announce(state);
    }
    super::phase::recompute(state);
}

/// Announce-path gate: decide whether a just-announced peer should be
/// dialed or parked, *before* any transport exists. Returns `true`
/// when the announce was fully handled here (peer parked / kept
/// parked) and the caller should skip the dial path.
///
/// Inbound offers are deliberately NOT gated — if a peer dials us
/// despite our view saying "parked", we accept and let the park sweep
/// settle it once views converge. Refusing offers would hard-fail
/// mixed-version fleets and transiently-divergent presence views.
pub(crate) fn park_gate_on_announce(state: &Arc<NetworkState>, device_id: &str) -> bool {
    let me = state.identity.public_id().to_string();
    let present = present_ids(state, Some(device_id));
    let Some(connect) = effective_connect_set(state, &me, &present) else {
        return false;
    };
    if connect.contains(device_id) {
        // In the connect set. If they were parked, the caller's
        // normal dial path (`ensure_peer_session`) upgrades the
        // placeholder.
        return false;
    }
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        if data.status == PeerStatus::Parked {
            // Known parked peer re-announcing: refresh the presence
            // TTL, stay parked.
            data.last_announce_at = Some(Instant::now());
            return true;
        }
        // Connected (or mid-handshake): announces for live entries
        // are handled by the normal path; the sweep owns demotion.
        return false;
    }
    // First sight of an out-of-connect-set peer: track presence,
    // never dial.
    let parked = Arc::new(PeerConnection::new(device_id.to_string(), None));
    {
        let mut data = parked.state.write();
        data.status = PeerStatus::Parked;
        data.last_announce_at = Some(Instant::now());
    }
    state.peers.insert(device_id.to_string(), parked);
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "topology",
        format!(
            "parked {} on announce (out of connect set, {} present)",
            super::short_peer(device_id),
            present.len(),
        ),
        serde_json::json!({ "peer": device_id, "present": present.len() }),
    );
    state.emit(MeshEvent::Peer(PeerEvent::Parked {
        network_id: state.network_id.clone(),
        device_id: device_id.to_string(),
        reason: Some("out-of-connect-set".to_string()),
    }));
    super::phase::recompute(state);
    true
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
    use crate::config::TopologyMode;
    use std::time::Duration;

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

    // ---- park machinery -----------------------------------------------
    //
    // The tests build peer ids relative to the (random, ephemeral)
    // local identity: suffixing the local pubkey produces ids that
    // sort immediately after it, so ring positions are deterministic
    // without knowing the pubkey's value. With n_preferred = 2 and
    // n_connect = 2 over [me, me+"a", me+"b", me+"c", me+"d"], me's
    // connect set is exactly its two ring neighbors: me+"a" (cw) and
    // me+"d" (ccw wrap).

    fn ring_capped_state(suffix: &str) -> Arc<NetworkState> {
        let state = super::super::build_test_state(suffix);
        *state.topology_impl.write() = crate::topology::from_mode(&TopologyMode::Ring {
            n_preferred: Some(2),
            n_connect: Some(2),
        });
        state
    }

    fn insert_peer(
        state: &Arc<NetworkState>,
        device_id: &str,
        status: PeerStatus,
        authenticated: bool,
        features: &[&str],
    ) {
        let peer = Arc::new(PeerConnection::new(device_id.to_string(), None));
        {
            let mut data = peer.state.write();
            data.status = status;
            data.authenticated = authenticated;
            data.remote_features = features.iter().map(|s| s.to_string()).collect();
            data.last_announce_at = Some(Instant::now());
        }
        state.peers.insert(device_id.to_string(), peer);
    }

    fn status_of(state: &Arc<NetworkState>, device_id: &str) -> Option<PeerStatus> {
        state.peers.get(device_id).map(|p| p.state.read().status)
    }

    fn rewind_park_timer(state: &Arc<NetworkState>, device_id: &str, by_ms: u64) {
        let peer = state.peers.get(device_id).expect("peer exists");
        let mut data = peer.state.write();
        data.park_pending_since = Some(
            Instant::now()
                .checked_sub(Duration::from_millis(by_ms))
                .expect("monotonic clock headroom"),
        );
    }

    #[tokio::test]
    async fn announce_gate_parks_out_of_connect_set_peer() {
        let state = ring_capped_state("gate-parks");
        let me = state.identity.public_id().to_string();
        let (pa, pb, pd) = (format!("{me}a"), format!("{me}b"), format!("{me}d"));
        insert_peer(&state, &pa, PeerStatus::Active, true, &["topology_park_v1"]);
        insert_peer(&state, &pd, PeerStatus::Active, true, &["topology_park_v1"]);

        // pb announces. Ring [me, pa, pb, pd]: me's neighbors are pa
        // and pd; pb's neighbors are pa and pd too — nobody picks the
        // edge me↔pb, so the gate parks it without dialing.
        assert!(park_gate_on_announce(&state, &pb));
        assert_eq!(status_of(&state, &pb), Some(PeerStatus::Parked));

        // A ring-neighbor announce is NOT gated.
        let pe = format!("{me}0"); // sorts before pa → becomes cw neighbor…
                                   // ('0' < 'a' in ASCII, and base32 ids are lowercase
                                   // alphanumerics, so me+"0" sits between me and me+"a".)
        assert!(!park_gate_on_announce(&state, &pe));
    }

    #[tokio::test]
    async fn announce_gate_refreshes_parked_presence() {
        let state = ring_capped_state("gate-refresh");
        let me = state.identity.public_id().to_string();
        let (pa, pb, pd) = (format!("{me}a"), format!("{me}b"), format!("{me}d"));
        insert_peer(&state, &pa, PeerStatus::Active, true, &["topology_park_v1"]);
        insert_peer(&state, &pd, PeerStatus::Active, true, &["topology_park_v1"]);
        insert_peer(&state, &pb, PeerStatus::Parked, false, &[]);
        {
            let peer = state.peers.get(&pb).unwrap();
            peer.state.write().last_announce_at = Some(
                Instant::now()
                    .checked_sub(Duration::from_millis(PARKED_PRESENCE_TTL_MS - 5_000))
                    .unwrap(),
            );
        }
        assert!(park_gate_on_announce(&state, &pb), "stays parked");
        let refreshed = state
            .peers
            .get(&pb)
            .unwrap()
            .state
            .read()
            .last_announce_at
            .unwrap();
        assert!(
            refreshed.elapsed() < Duration::from_secs(1),
            "TTL refreshed"
        );
    }

    #[tokio::test]
    async fn park_pass_demotes_only_after_linger() {
        let state = ring_capped_state("linger");
        let me = state.identity.public_id().to_string();
        let (pa, pb, pd) = (format!("{me}a"), format!("{me}b"), format!("{me}d"));
        insert_peer(&state, &pa, PeerStatus::Active, true, &["topology_park_v1"]);
        insert_peer(&state, &pb, PeerStatus::Active, true, &["topology_park_v1"]);
        insert_peer(&state, &pd, PeerStatus::Active, true, &["topology_park_v1"]);

        // First pass arms the linger timer but doesn't park.
        park_pass(&state).await;
        assert_eq!(status_of(&state, &pb), Some(PeerStatus::Active));
        assert!(
            state
                .peers
                .get(&pb)
                .unwrap()
                .state
                .read()
                .park_pending_since
                .is_some(),
            "linger timer armed"
        );
        // Neighbors stay timer-free.
        assert!(state
            .peers
            .get(&pa)
            .unwrap()
            .state
            .read()
            .park_pending_since
            .is_none());

        // Second pass after the linger elapses parks pb.
        rewind_park_timer(&state, &pb, PARK_LINGER_MS + 1_000);
        park_pass(&state).await;
        assert_eq!(status_of(&state, &pb), Some(PeerStatus::Parked));
        assert_eq!(status_of(&state, &pa), Some(PeerStatus::Active));
        assert_eq!(status_of(&state, &pd), Some(PeerStatus::Active));
    }

    #[tokio::test]
    async fn park_pass_exempts_legacy_peers() {
        let state = ring_capped_state("legacy");
        let me = state.identity.public_id().to_string();
        let (pa, pb, pd) = (format!("{me}a"), format!("{me}b"), format!("{me}d"));
        insert_peer(&state, &pa, PeerStatus::Active, true, &["topology_park_v1"]);
        // pb handshook but predates parking — its features lack the flag.
        insert_peer(&state, &pb, PeerStatus::Active, true, &["ring_topology"]);
        insert_peer(&state, &pd, PeerStatus::Active, true, &["topology_park_v1"]);

        park_pass(&state).await;
        rewind_park_timer(&state, &pa, PARK_LINGER_MS + 1_000); // irrelevant: in-set clears it
        park_pass(&state).await;
        park_pass(&state).await;
        assert_eq!(
            status_of(&state, &pb),
            Some(PeerStatus::Active),
            "legacy peer must never be parked"
        );
        assert!(
            state
                .peers
                .get(&pb)
                .unwrap()
                .state
                .read()
                .park_pending_since
                .is_none(),
            "legacy peer's timer stays cleared"
        );
    }

    #[tokio::test]
    async fn park_pass_exempts_pending_approval() {
        let state = ring_capped_state("pending");
        let me = state.identity.public_id().to_string();
        let (pa, pb, pd) = (format!("{me}a"), format!("{me}b"), format!("{me}d"));
        insert_peer(&state, &pa, PeerStatus::Active, true, &["topology_park_v1"]);
        insert_peer(
            &state,
            &pb,
            PeerStatus::PendingApproval,
            true,
            &["topology_park_v1"],
        );
        insert_peer(&state, &pd, PeerStatus::Active, true, &["topology_park_v1"]);

        park_pass(&state).await;
        assert_eq!(status_of(&state, &pb), Some(PeerStatus::PendingApproval));
        assert!(state
            .peers
            .get(&pb)
            .unwrap()
            .state
            .read()
            .park_pending_since
            .is_none());
    }

    #[tokio::test]
    async fn park_pass_expires_silent_parked_entries() {
        let state = ring_capped_state("ttl");
        let me = state.identity.public_id().to_string();
        let pb = format!("{me}b");
        insert_peer(&state, &pb, PeerStatus::Parked, false, &[]);
        {
            let peer = state.peers.get(&pb).unwrap();
            peer.state.write().last_announce_at = Some(
                Instant::now()
                    .checked_sub(Duration::from_millis(PARKED_PRESENCE_TTL_MS + 5_000))
                    .unwrap(),
            );
        }
        park_pass(&state).await;
        assert!(
            !state.peers.contains_key(&pb),
            "ghost parked entry removed after presence TTL"
        );
    }

    #[tokio::test]
    async fn park_pass_unparks_when_rebalanced_in_as_answerer() {
        let state = ring_capped_state("unpark-answer");
        let me = state.identity.public_id().to_string();
        // A single present peer is always inside the connect set
        // (below capacity). Lex-lower than me ('0' < base32 alphabet)
        // → we are the answerer: the entry is dropped and we announce
        // rather than dial, so no fresh entry appears until their
        // offer arrives.
        let p_low = format!("0{me}");
        insert_peer(&state, &p_low, PeerStatus::Parked, false, &[]);
        park_pass(&state).await;
        assert!(
            !state.peers.contains_key(&p_low),
            "parked placeholder dropped; waiting on peer's offer"
        );
    }

    #[tokio::test]
    async fn park_pass_unparks_and_dials_as_offerer() {
        let state = ring_capped_state("unpark-dial");
        let me = state.identity.public_id().to_string();
        // Lex-higher than me → we are the offerer: unpark re-enters
        // the dial path and a fresh (Sighted) session-bearing entry
        // replaces the parked placeholder.
        let pa = format!("{me}a");
        insert_peer(&state, &pa, PeerStatus::Parked, false, &[]);
        park_pass(&state).await;
        assert_eq!(status_of(&state, &pa), Some(PeerStatus::Sighted));
        assert!(
            state.peers.get(&pa).unwrap().session.lock().is_some(),
            "offerer unpark brings up a real session"
        );
    }

    #[tokio::test]
    async fn cap_disabled_unparks_everyone() {
        let state = ring_capped_state("cap-off");
        let me = state.identity.public_id().to_string();
        let pa = format!("{me}a");
        insert_peer(&state, &pa, PeerStatus::Parked, false, &[]);
        // Flip to an uncapped selector at runtime (config edit).
        *state.topology_impl.write() = crate::topology::from_mode(&TopologyMode::FullMesh);
        park_pass(&state).await;
        assert_eq!(
            status_of(&state, &pa),
            Some(PeerStatus::Sighted),
            "previously-parked peer re-dialed once the cap is gone"
        );
    }
}
