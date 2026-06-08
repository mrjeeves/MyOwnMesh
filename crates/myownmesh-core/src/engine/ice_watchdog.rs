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
use super::scheduler::{ICE_CHECKING_TIMEOUT_MS, ICE_DISCONNECTED_RESTART_MS};
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
        super::renegotiate_ice(state, &peer_id, false).await;
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

    // Live ICE-establishment progress. For any peer still in
    // `Checking`, emit a one-line snapshot of the connectivity-check
    // counters each poll so the user can watch — in real time — whether
    // our STUN checks are getting responses. A stuck `resp←0` while
    // `sent→` climbs is the unambiguous fingerprint of UDP being
    // dropped (firewall / VPN / macOS Local Network permission), which
    // no amount of staring at "ICE → Checking" would reveal. Self-
    // limiting: a peer only sits in Checking for the ~30 s before ICE
    // gives up, so this quiets down on its own once it connects or
    // fails.
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

    // Checking-timeout watchdog. A peer that's sat in `Checking` past
    // ICE_CHECKING_TIMEOUT_MS isn't going to connect on this attempt;
    // webrtc-rs would otherwise wait its ~30 s internal timer before
    // flipping to Failed. Tear it down and re-seed discovery so a
    // usable path — e.g. the instant the laptop rejoins a network the
    // peer is actually on — is retried in seconds rather than half a
    // minute. The natural ~15 s cycle plus the shared announce
    // rate-limit keeps this from churning the relays.
    let stuck: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let since = e.value().state.read().ice_checking_since?;
            (now.saturating_duration_since(since).as_millis() as u64 >= ICE_CHECKING_TIMEOUT_MS)
                .then(|| e.key().clone())
        })
        .collect();
    for peer_id in stuck {
        on_checking_timeout(state, &peer_id).await;
    }
}

/// A peer sat in ICE `Checking` past the timeout without connecting.
/// Surface *why* (full check snapshot), then drop it and re-seed
/// discovery so a fresh PeerConnection is built rather than waiting out
/// webrtc-rs's ~30 s internal ICE-failure timer. The re-announce is
/// rate-limited via the shared reactive-announce guard so a wave of
/// timeouts can't flood the relays.
async fn on_checking_timeout(state: &Arc<NetworkState>, device_id: &str) {
    state.log_diag_with(
        DiagLevel::Warn,
        "ice",
        format!(
            "ICE stuck in checking > {}s for {} — rebuilding",
            ICE_CHECKING_TIMEOUT_MS / 1000,
            super::short_peer(device_id),
        ),
        serde_json::json!({ "peer": device_id, "checking_timeout_ms": ICE_CHECKING_TIMEOUT_MS }),
    );
    // The full snapshot (candidates + per-pair STUN counters + a
    // plain-language diagnosis) is the record of why this attempt
    // never completed — log it before the teardown removes the agent.
    super::log_ice_check_snapshot(state, device_id, "stuck in checking", true).await;
    super::drop_peer(state, device_id, crate::events::DropReason::IceFailed).await;
    // Nudge discovery so we don't wait for the peer's next scheduled
    // announce; rate-limited, so several simultaneous timeouts collapse
    // into a single publish.
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
    super::renegotiate_ice(state, device_id, false).await;
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
        super::renegotiate_ice(state, &peer_id, true).await;
    }
}
