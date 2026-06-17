//! Tier 2.5 — per-peer ICE watchdog. Fires at
//! `ICE_DISCONNECTED_RESTART_MS` after a peer's ICE state goes
//! `disconnected` — earlier than the underlying WebRTC stack's
//! own consent-freshness timer would notice a stale network.
//!
//! Recovery goes through [`super::renegotiate_ice`], which does
//! `restart_ice()` *and* sends a fresh offer — a bare `restart_ice()`
//! only re-gathers our own candidates and rotates our ufrag, which the
//! peer never hears about, so the link can't actually come back. The
//! watchdog poll re-drives the (single-flighted) renegotiation while a
//! link stays down; the data channel is preserved across the restart, so
//! a brief blip never tears it down.

use std::sync::Arc;
use std::time::Instant;

use tracing::warn;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;

use super::connection::PeerStatus;
use super::ladder::ConnectionTier;
use super::scheduler::{
    DATA_CHANNEL_OPEN_TIMEOUT_MS, ICE_DISCONNECTED_RESTART_MS, RESTART_TRAFFIC_GRACE_MS,
};
use super::state::NetworkState;
use crate::events::{DiagEntry, DiagLevel, MeshEvent};

/// After this many consecutive ICE failures with zero relay
/// candidates on both sides, surface the no-TURN diagnostic. Three
/// gives the connection a fair chance to recover on its own
/// (signaling races, transient network drops) before we tell the
/// user the topology won't ever work without TURN.
const NO_TURN_DIAG_AFTER_FAILURES: u32 = 3;

/// Periodic poll — checks every active peer's ICE state and
/// triggers `restart_ice()` for any past the disconnected
/// threshold. Cheap to call on every tick: it's an O(N) scan
/// over the peers map with no per-peer locks held across awaits.
pub async fn poll_all(state: &Arc<NetworkState>) {
    let now = Instant::now();
    let candidates: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            if !matches!(data.status, PeerStatus::Active | PeerStatus::Shelved) {
                return None;
            }
            let since = data.ice_disconnected_since?;
            if now.saturating_duration_since(since).as_millis() as u64
                >= ICE_DISCONNECTED_RESTART_MS
            {
                Some(e.key().clone())
            } else {
                None
            }
        })
        .collect();

    for peer_id in candidates {
        // Renegotiate (restart_ice + a fresh offer), not a bare
        // restart_ice — see `engine::renegotiate_ice`. Single-flighted
        // there, so polling every few seconds while a link stays down
        // retries the offer without flooding signaling. Not forced: ICE
        // is genuinely disconnected here, so there's no stale-Connected
        // state to push past.
        super::renegotiate_ice(state, &peer_id, false, "ice-disconnected-watchdog").await;
    }

    // Retry selected-pair classification for any peer whose ICE
    // reached Connected/Completed but whose `selected_pair` is
    // still `None`. The single-shot record on the state callback
    // (`engine::mod::handle_ice_state_change`) can fire before
    // webrtc-rs has flipped the `nominated` bit on the
    // CandidatePair stats — particularly on the controlling
    // (Offerer) side, where the agent only marks the pair
    // nominated after it sends USE-CANDIDATE and receives a
    // success response. Without this retry, the GUI's LAN /
    // STUN / TURN classification stays blank even though packets
    // are flowing — exactly the symptom we kept seeing on the
    // Offerer-side laptop in a working LAN pair. Cheap re-query:
    // skips any peer whose pair is already known, only touches
    // the stats API for peers in `Active`/`Shelved` with no
    // pair recorded yet.
    let need_pair: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            if !matches!(data.status, PeerStatus::Active | PeerStatus::Shelved) {
                return None;
            }
            if data.selected_pair.is_some() {
                return None;
            }
            Some(e.key().clone())
        })
        .collect();
    for peer_id in need_pair {
        super::record_selected_pair(state, &peer_id).await;
    }

    // Live ICE-establishment progress — diagnostic only. For any peer
    // still in `Checking`, emit a one-line snapshot each poll so the user
    // can watch, in real time, how many candidate pairs have reached
    // `succeeded` and whether anything is nominated yet (the only pair
    // fields webrtc-ice actually maintains; see `diag::IcePairSnapshot`).
    // This drives no decisions — the connect-timeout below keys off the
    // data channel, not this — it's purely the "why isn't it connecting"
    // trail. Self-limiting: a peer only sits in Checking briefly before it
    // connects, fails, or hits the connect-timeout.
    let checking: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let session = e.value().session.lock().clone()?;
            if session.ice_connection_state() == RTCIceConnectionState::Checking {
                Some(e.key().clone())
            } else {
                None
            }
        })
        .collect();
    for peer_id in checking {
        super::log_ice_check_snapshot(state, &peer_id, "checking", false).await;
    }

    // Connect-timeout watchdog — the single teardown clock for a
    // *connecting* peer. A session whose data channel hasn't opened within
    // DATA_CHANNEL_OPEN_TIMEOUT_MS of being created isn't going to on this
    // attempt; rebuild it (and re-seed discovery) rather than waiting out
    // webrtc-rs's ~30 s internal ICE timer. Keyed off the reliable
    // milestone — `data_channel_open` — not ICE state, which has been seen
    // to lie in both directions. A peer whose channel already opened is
    // never a candidate here; its liveness is the heartbeat.
    let timed_out: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            if data.data_channel_open {
                return None;
            }
            let started = data.session_started_at?;
            (now.saturating_duration_since(started).as_millis() as u64
                >= DATA_CHANNEL_OPEN_TIMEOUT_MS)
                .then(|| e.key().clone())
        })
        .collect();
    for peer_id in timed_out {
        on_connect_timeout(state, &peer_id).await;
    }

    // Restart-verify watchdog. A peer recovering from an ICE restart stays
    // in the IceRestart tier until *inbound traffic* confirms the path —
    // ICE-Connected alone doesn't (it's been seen Connected on a dead TURN
    // path that delivered nothing for 90 s). Rebuild one whose restart
    // never produced traffic: a short grace once ICE is up (a live path
    // pongs the confirm-ping within an RTT), or the full connect-timeout
    // while it's still re-gathering — the clock is re-stamped to the moment
    // ICE reconnects, so a restart legitimately crossing slow signaling
    // isn't killed early.
    let restart_unconfirmed: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let started = match e.value().state.read().tier {
                ConnectionTier::IceRestart { started } => started,
                _ => return None,
            };
            let ice_up = e
                .value()
                .session
                .lock()
                .as_ref()
                .map(|s| {
                    matches!(
                        s.ice_connection_state(),
                        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed
                    )
                })
                .unwrap_or(false);
            let deadline = if ice_up {
                RESTART_TRAFFIC_GRACE_MS
            } else {
                DATA_CHANNEL_OPEN_TIMEOUT_MS
            };
            (now.saturating_duration_since(started).as_millis() as u64 >= deadline)
                .then(|| e.key().clone())
        })
        .collect();
    for peer_id in restart_unconfirmed {
        on_restart_unconfirmed(state, &peer_id).await;
    }
}

/// A connecting peer whose data channel never opened within the timeout.
/// The attempt failed — rebuild it. (An already-open peer is never a
/// candidate for this; its liveness is the heartbeat.)
///
/// Unlike the old ICE-`Checking` timeout, the data-channel-open milestone
/// is unambiguous, so there's no "succeeded-but-not-nominated" grace to
/// weigh and no nominated-pair heuristic to second-guess: if the channel
/// didn't open, the attempt didn't work. We still surface *why* (the full
/// connectivity-check snapshot) and, when the fingerprint is "no remote
/// candidates ever arrived" (a signaling problem, not a network block),
/// force a throttled relay redial before rebuilding — a wedged relay
/// socket left by a network blip is the usual cause, and redialing is what
/// unblocks candidate delivery for the rebuilt session. The re-announce is
/// rate-limited so a wave of timeouts can't flood the relays.
async fn on_connect_timeout(state: &Arc<NetworkState>, device_id: &str) {
    // While the host is offline (no primary interface) every peer will time
    // out, but tearing them all down now just means re-discovering them a
    // second later when the interface returns. Hold in place — the
    // network-change handler restarts everything once we're back online.
    if state.is_offline() {
        return;
    }

    state.log_diag_with(
        DiagLevel::Warn,
        "ice",
        format!(
            "data channel never opened within {}s for {} — rebuilding",
            DATA_CHANNEL_OPEN_TIMEOUT_MS / 1000,
            super::short_peer(device_id),
        ),
        serde_json::json!({
            "peer": device_id,
            "connect_timeout_ms": DATA_CHANNEL_OPEN_TIMEOUT_MS,
        }),
    );
    // The full snapshot (candidates + per-pair states + a plain-language
    // diagnosis) is the record of why this attempt never completed — log
    // it before the teardown removes the agent.
    super::log_ice_check_snapshot(state, device_id, "connect timed out", true).await;

    // Zero remote candidates is the fingerprint of wedged signaling, not a
    // blocked network: the peer's candidates never crossed the relay (or
    // ours never reached it). The usual cause is a relay socket left a
    // zombie by a network change on one side — held open for minutes
    // because the kernel never saw a FIN/RST.
    //
    // We force a relay redial *only when no other peer is currently up*.
    // This looks conservative but it's load-bearing: a forced relay
    // reconnect on a node tears down every WebRTC peer that node holds —
    // observed directly in the field, where one flaky peer hitting this
    // path took an otherwise-healthy 4-peer box from Active to Alone, all
    // four links resetting in the same 70 ms as the redial (the peer that
    // *didn't* redial stayed stable throughout). So redialing to rescue a
    // single stuck peer while others are live trades one bad link for all
    // of them. When we're already alone there's nothing to lose, and a
    // genuinely-stale socket is the likeliest reason we can't reach
    // anyone — that's the case worth the redial. The throttle still caps
    // it to one per RELAY_RESCUE_MIN_INTERVAL_MS.
    let no_remote = state
        .peers
        .get(device_id)
        .map(|p| p.state.read().diag.remote_candidates.total() == 0)
        .unwrap_or(false);
    let other_live_peers = state
        .peers
        .iter()
        .filter(|e| {
            e.key() != device_id
                && matches!(
                    e.value().state.read().status,
                    PeerStatus::Active | PeerStatus::Shelved
                )
        })
        .count();
    if no_remote {
        if other_live_peers > 0 {
            // Suppressed on purpose — DEBUG so the decision is greppable
            // when chasing a stuck peer, without adding an INFO line to the
            // default stream every time a single link flaps while the rest
            // of the mesh is healthy.
            state.log_diag_with(
                DiagLevel::Debug,
                "signaling",
                format!(
                    "no remote candidates arrived for {} — NOT redialing the relay \
                     ({other_live_peers} other peer(s) live; a forced reconnect would reset them too)",
                    super::short_peer(device_id),
                ),
                serde_json::json!({
                    "peer": device_id,
                    "reason": "no_remote_candidates",
                    "other_live_peers": other_live_peers,
                    "redial": false,
                }),
            );
        } else if state.request_relay_reconnect_throttled() {
            state.log_diag_with(
                DiagLevel::Info,
                "signaling",
                format!(
                    "no remote candidates arrived for {} and we're alone — forcing relay \
                     reconnect (socket likely went stale)",
                    super::short_peer(device_id),
                ),
                serde_json::json!({
                    "peer": device_id,
                    "reason": "no_remote_candidates",
                    "other_live_peers": 0,
                    "redial": true,
                }),
            );
        }
    }

    super::drop_peer(state, device_id, crate::events::DropReason::IceFailed).await;
    // Nudge discovery so we don't wait for the peer's next scheduled
    // announce; rate-limited, so several simultaneous timeouts collapse
    // into a single publish.
    super::maybe_reactive_announce(state);
}

/// A peer whose ICE restart reconnected (or should have) but never produced
/// inbound traffic — the restart didn't actually restore the link. Rebuild
/// rather than ride a dead "connected" peer until the heartbeat notices a
/// minute later. (Real traffic would have promoted it back to Steady in
/// `handle_inbound_frame`, taking it out of this watchdog's sights.)
async fn on_restart_unconfirmed(state: &Arc<NetworkState>, device_id: &str) {
    if state.is_offline() {
        return;
    }
    state.log_diag_with(
        DiagLevel::Warn,
        "ice",
        format!(
            "ICE restart for {} did not restore traffic — rebuilding",
            super::short_peer(device_id),
        ),
        serde_json::json!({ "peer": device_id }),
    );
    super::drop_peer(state, device_id, crate::events::DropReason::IceFailed).await;
    super::maybe_reactive_announce(state);
}

/// Called directly from the ICE state-change handler when ICE
/// reports `Failed`. Skips the watchdog window — we know the
/// connection is gone.
pub async fn on_failed(state: &Arc<NetworkState>, device_id: &str) {
    state.log_diag_with(
        crate::events::DiagLevel::Warn,
        "ice",
        format!("ICE failed for {device_id} — renegotiating"),
        serde_json::json!({ "peer": device_id }),
    );
    maybe_emit_no_turn_diag(state, device_id);
    // The right response to a hard ICE failure is the same as a network
    // change: restart_ice + a fresh offer so both ends re-gather and
    // re-exchange. The old path escalated to a Tier-4 re-handshake, which
    // only re-sends `hello` over the already-dead data channel and can't
    // bring the transport back. Single-flighted in `renegotiate_ice`.
    super::renegotiate_ice(state, device_id, false, "ice-failed").await;
}

/// Inspect the peer's candidate stats after an ICE failure and, if
/// neither side ever produced a relay candidate, surface a
/// human-readable diagnostic pointing at the missing TURN config.
/// Throttled: the `no_turn_diag_emitted` flag stops us re-emitting
/// once per ladder cycle. Reset by the engine's Active transition.
fn maybe_emit_no_turn_diag(state: &Arc<NetworkState>, device_id: &str) {
    let snapshot = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        data.ice_failed_count = data.ice_failed_count.saturating_add(1);
        if data.no_turn_diag_emitted {
            return;
        }
        // Need enough consecutive failures to rule out transient
        // signaling glitches. With zero relay candidates on either
        // side, no amount of retrying will fix the symmetric-NAT
        // case — surface that now.
        if data.ice_failed_count < NO_TURN_DIAG_AFTER_FAILURES {
            return;
        }
        let local_relay = data.diag.local_candidates.relay;
        let remote_relay = data.diag.remote_candidates.relay;
        if local_relay > 0 || remote_relay > 0 {
            return;
        }
        data.no_turn_diag_emitted = true;
        (
            data.ice_failed_count,
            data.diag.local_candidates.host,
            data.diag.local_candidates.server_reflexive,
            data.diag.remote_candidates.host,
            data.diag.remote_candidates.server_reflexive,
        )
    };
    let (failures, local_host, local_srflx, remote_host, remote_srflx) = snapshot;
    let message = format!(
        "ICE failed {failures} times for peer {device_id} with zero relay (TURN) candidates \
         on either side. Direct connectivity isn't reaching this peer — add a TURN server to \
         this network's settings so the engine can fall back to a relay."
    );
    warn!(
        peer = %device_id,
        failures,
        local_host,
        local_srflx,
        remote_host,
        remote_srflx,
        "no TURN configured and ICE keeps failing"
    );
    state.emit(MeshEvent::Diag(DiagEntry {
        ts: crate::engine::state::now_unix_ms(),
        network_id: state.network_id.clone(),
        level: DiagLevel::Warn,
        category: "ice".to_string(),
        message,
        detail: serde_json::json!({
            "peer": device_id,
            "failures": failures,
            "local_candidates": {
                "host": local_host,
                "server_reflexive": local_srflx,
                "relay": 0,
            },
            "remote_candidates": {
                "host": remote_host,
                "server_reflexive": remote_srflx,
                "relay": 0,
            },
            "hint": "add_turn_server",
        }),
    }));
}

/// Renegotiate ICE on every active or shelved peer. Used by the
/// network-change watcher: when the OS reports the primary outbound IP
/// just changed, every existing connection's local candidates are stale
/// and ICE won't notice until its ~30 s consent-freshness timer expires.
/// Pre-empting that here — `restart_ice()` **plus** a fresh offer (see
/// [`super::renegotiate_ice`]) — gets both ends re-gathered and
/// reconnected within seconds instead of half a minute, and the
/// per-peer single-flight keeps the fan-out from flooding signaling.
pub async fn force_ice_restart_all(state: &Arc<NetworkState>) {
    let candidates: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            matches!(data.status, PeerStatus::Active | PeerStatus::Shelved).then(|| e.key().clone())
        })
        .collect();

    for peer_id in candidates {
        // Forced: on a network change ICE often still reads Connected
        // (consent-freshness hasn't fired), so push past the stale state.
        super::renegotiate_ice(state, &peer_id, true, "network-change").await;
    }
}
