//! Connection engine — the runtime that turns the protocol +
//! transport + topology primitives into a working mesh.
//!
//! Each joined network spins up one engine task graph:
//!
//! - **Driver** loop (`run_driver`) — owns the
//!   [`state::NetworkState`] and processes the per-network
//!   command queue, signaling events, and per-peer transport
//!   events serially.
//! - **Scheduler** ticks ([`scheduler`]) — heartbeat, offline
//!   check, reconnect prune, ICE poll. Each tick is named so the
//!   wake detector can attribute a tick gap to the right timer.
//! - **Per-peer transport pumps** — one task per active peer
//!   draining the transport mpsc into the driver via the command
//!   queue.
//!
//! Constants are mirrored from MyOwnLLM's `mesh-client.svelte.ts`
//! and are documented in `CONNECTION-ENGINE.md`. Do not relax them
//! without understanding the corresponding field-discovered bug.

pub mod conn_trace;
pub mod connection;
pub mod governance;
pub mod handshake;
pub mod heartbeat;
pub mod ice_watchdog;
pub mod ladder;
pub mod network_watch;
pub mod phase;
pub mod reconcile;
pub mod scheduler;
pub mod signaling_bridge;
pub mod state;
pub mod wake;

pub use signaling_bridge::{attach_local, attach_nostr};

/// Minimum gap between announces we publish in response to a peer's
/// announce. The engine fires one reflected announce per inbound
/// announce; this floor coalesces a burst of inbound announces (a
/// new joiner triggering N existing peers to all react at once)
/// into a single outbound publish per N-peer wave so we don't put
/// quadratic load on the relay pool.
const REACTIVE_ANNOUNCE_MIN_INTERVAL_MS: u64 = 1_000;

/// Minimum gap between re-offers we send to the same peer while
/// their session is stuck at `Sighted` (PC created, data channel
/// never opened). Coalesces REQ-replay announce bursts into one
/// re-offer per window so we don't pile up SDP renegotiations on
/// the remote PC. Sized small enough that two restart-aligned
/// peers converge inside a handful of seconds.
const REOFFER_MIN_INTERVAL_MS: u64 = 2_000;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::sdp_type::RTCSdpType;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::config::NetworkConfig;
use crate::error::{Error, Result};
use crate::events::{DropReason, MeshEvent, PeerEvent};
use crate::identity::Identity;
use crate::protocol::{
    rpc::{
        CapabilitiesUpdateMessage, RpcRequestMessage, RpcResponseMessage, RpcStreamChunkMessage,
        RpcStreamEndMessage,
    },
    topology::ShelveMessage,
    CapabilityAdvert, MeshMessage,
};
use crate::transport::{Role, Transport, TransportEvent};

use connection::{PeerConnection, PeerStatus};
use ladder::ConnectionTier;
pub use state::{
    InboundAudioSample, InboundVideoSample, NetworkCmd, NetworkState, SignalingInbound,
    SignalingOutbound,
};

/// Spawn the engine for a single joined network. Returns the
/// shared [`NetworkState`] handle plus the join handle of the
/// driver task (waitable for clean shutdown).
pub async fn spawn_network(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let (state, signaling_inbound_rx, cmd_rx) = NetworkState::new(config, identity, transport)?;
    let driver_state = state.clone();
    let handle = tokio::spawn(async move {
        run_driver(driver_state, signaling_inbound_rx, cmd_rx).await;
    });
    Ok((state, handle))
}

/// The engine's main loop. Owns the per-network state and the
/// fan-in mpsc that consolidates signaling, transport, and
/// command events.
pub async fn run_driver(
    state: Arc<NetworkState>,
    mut signaling_inbound: mpsc::UnboundedReceiver<SignalingInbound>,
    mut cmd_rx: mpsc::UnboundedReceiver<NetworkCmd>,
) {
    state.log_diag(crate::events::DiagLevel::Info, "engine", "driver starting");
    // Surface the ICE-server configuration so users can confirm at
    // a glance whether they have any relay coverage. Mirrors
    // MyOwnLLM's pattern: when peers get stuck at ICE-checking with
    // 0 relay candidates, this line is the first thing to point at.
    {
        let cfg = state.config.read();
        let stun_count: usize = cfg.stun_servers.iter().map(|s| s.urls.len()).sum();
        let turn_count: usize = cfg.turn_servers.iter().map(|s| s.urls.len()).sum();
        let turn_summary = if turn_count == 0 {
            "no TURN configured (CGNAT / phone-hotspot will fail to connect)".to_string()
        } else {
            format!("{turn_count} TURN URL(s)")
        };
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "engine",
            format!("ICE servers: {stun_count} STUN URL(s), {turn_summary}"),
            serde_json::json!({
                "stun_count": stun_count,
                "turn_count": turn_count,
                "auto_approve": cfg.auto_approve,
            }),
        );
        drop(cfg);
    }

    // Top-level interval ticks. We hold them across the loop so
    // sleeping happens inside `tokio::select!` — no separate
    // task means a wake-event after a long-sleep tick gap is
    // observable here without coordination.
    let mut heartbeat =
        tokio::time::interval(Duration::from_millis(scheduler::HEARTBEAT_INTERVAL_MS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ice_poll =
        tokio::time::interval(Duration::from_millis(scheduler::ICE_POLL_INTERVAL_MS));
    ice_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut network_watch_tick =
        tokio::time::interval(Duration::from_millis(scheduler::NETWORK_WATCH_POLL_MS));
    network_watch_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut network_watch = network_watch::NetworkWatch::new().await;
    let mut wake_detector = wake::WakeDetector::new();
    // Phase-0 connection tracer. Observes per-peer connection-state
    // transitions after each driver-loop iteration. Zero cost unless a
    // `ctl trace` subscriber is attached or `MYOWNMESH_CONN_TRACE` is
    // set — see `engine::conn_trace`.
    let mut conn_tracer = conn_trace::ConnTracer::new();

    loop {
        tokio::select! {
            biased;

            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                if !handle_command(&state, cmd).await {
                    break;
                }
            }

            sig = signaling_inbound.recv() => {
                let Some(sig) = sig else {
                    warn!(network = %state.network_id, "signaling channel closed");
                    break;
                };
                handle_signaling_inbound(&state, sig).await;
            }

            _ = heartbeat.tick() => {
                wake_detector.observe(Instant::now(), scheduler::HEARTBEAT_INTERVAL_MS);
                heartbeat::tick(&state).await;
                if wake_detector.take_wake_event() {
                    debug!(network = %state.network_id, "wake event observed");
                    wake::on_wake(&state).await;
                }
            }

            _ = ice_poll.tick() => {
                ice_watchdog::poll_all(&state).await;
            }

            _ = network_watch_tick.tick() => {
                network_watch.poll(&state).await;
            }
        }

        // Observe the post-event connection state. Cheap no-op unless
        // someone is watching; never holds a per-peer lock across an
        // await (the handler above has already returned).
        conn_tracer.sweep(&state);
    }

    state.log_diag(crate::events::DiagLevel::Info, "engine", "driver stopping");
    state.shutdown().await;
}

async fn handle_command(state: &Arc<NetworkState>, cmd: NetworkCmd) -> bool {
    match cmd {
        NetworkCmd::Shutdown => return false,
        NetworkCmd::SetTopology(mode) => {
            *state.topology.write() = mode.clone();
            *state.topology_impl.write() = crate::topology::from_mode(&mode);
            ladder::reevaluate_topology(state).await;
        }
        NetworkCmd::ApproveRoster {
            device_id,
            label,
            reply,
        } => {
            let result = state.approve_roster(&device_id, &label).await;
            // A successful approval changed our roster — advertise the new
            // membership so other members converge (the same path the
            // mutual-confirmation handshake takes, here for the explicit
            // user-approve case).
            if result.is_ok() {
                governance::broadcast_roster_summary(state).await;
            }
            let _ = reply.send(result);
        }
        NetworkCmd::RemoveRoster { device_id, reply } => {
            let result = state.remove_roster(&device_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::DropPeer { device_id, reason } => {
            drop_peer(state, &device_id, reason).await;
        }
        NetworkCmd::SendChannelFrame {
            peer,
            channel,
            payload,
            reply,
        } => {
            let result = send_channel_frame(state, &peer, &channel, payload).await;
            let _ = reply.send(result);
        }
        NetworkCmd::BroadcastChannelFrame {
            channel,
            payload,
            reply,
        } => {
            let count = broadcast_channel_frame(state, &channel, payload).await;
            let _ = reply.send(count);
        }
        NetworkCmd::SendRpcRequest {
            peer,
            request,
            reply,
        } => {
            let result = send_rpc_request(state, &peer, request).await;
            let _ = reply.send(result);
        }
        NetworkCmd::BroadcastCapabilities { caps, reply } => {
            let _ = reply.send(broadcast_capabilities(state, caps).await);
        }
        NetworkCmd::TransportEvent {
            device_id,
            epoch,
            event,
        } => {
            handle_transport_event(state, device_id, epoch, event).await;
        }

        // ---- governance ops ----
        NetworkCmd::ProposeTransition { variant, reply } => {
            let result = governance::propose(state, variant).await;
            let _ = reply.send(result);
        }
        NetworkCmd::SignProposal { proposal_id, reply } => {
            let result = governance::sign_proposal(state, &proposal_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::DenyProposal { proposal_id, reply } => {
            let result = governance::deny_proposal(state, &proposal_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::WithdrawProposal { proposal_id, reply } => {
            let result = governance::withdraw_proposal(state, &proposal_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::SpawnSplit { proposal_id, reply } => {
            let result = governance::spawn_split(state, &proposal_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::GovernanceSnapshot { reply } => {
            let _ = reply.send(governance::snapshot(state));
        }
    }
    true
}

/// True when a session has been *connecting* (its data channel never
/// opened) for at least `grace_ms`. A fresh offer arriving on such a
/// session is better answered by a clean rebuild than by renegotiating
/// onto the stuck PC: re-applying `set_remote_description` only re-resets
/// ICE, and when both sides are stuck-and-re-offering it deadlocks (the
/// answerer keeps mis-applying the offerer's offers, the data channel
/// never opens — observed in the field as a peer pinned at Sighted over
/// TURN). The grace lets a legitimately-still-negotiating attempt finish
/// before a re-offer triggers a rebuild, so a burst of re-offers can't
/// churn it.
fn connecting_stuck_past_grace(data: &connection::PeerStateData, grace_ms: u64) -> bool {
    !data.data_channel_open
        && data
            .session_started_at
            .map(|t| t.elapsed() >= Duration::from_millis(grace_ms))
            .unwrap_or(false)
}

async fn handle_signaling_inbound(state: &Arc<NetworkState>, sig: SignalingInbound) {
    match sig {
        SignalingInbound::PeerAnnounced { device_id } => {
            // Whoever holds the lex-lower id initiates so we don't
            // glare on simultaneous discovery. Symmetric across
            // peers because base32 ids sort the same on both ends.
            let me = state.identity.public_id().to_string();
            let role = if me < device_id {
                Role::Offerer
            } else {
                Role::Answerer
            };
            // Cross-relay dedup happens at the Nostr driver layer
            // (see `upstream.rs` item 6 + the driver's
            // `seen_event_ids`), so this fires once per actual
            // periodic re-announce — not once per relay-delivery
            // copy of the same announce. Every announce lands in
            // the log so the user can see signaling is alive even
            // for peers already in steady state; redundant work
            // (re-opening the peer slot) is short-circuited inside
            // `ensure_peer_session` without affecting the log.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "signaling",
                format!(
                    "peer announced: {} (we are {role:?})",
                    short_peer(&device_id)
                ),
                serde_json::json!({ "peer": device_id, "role": format!("{role:?}") }),
            );
            // Reflect every inbound announce with one of our own.
            // The dense `ANNOUNCE_BACKOFF_MS` schedule covers fresh
            // joiners well enough on its own, but it doesn't help a
            // peer that's been in steady-state 60 s cadence for ten
            // minutes — when a new third peer arrives, that
            // steady-state peer's next announce could be up to 60 s
            // away, and meanwhile the joiner only sees whichever
            // existing peer happens to re-announce first (the
            // star-around-first-peer symptom). Reflecting on every
            // received announce guarantees the joiner sees every
            // existing peer in one round-trip, regardless of where
            // each existing peer sits on its announce schedule.
            // Rate-limited globally so N peers all reacting to a
            // join don't produce N^2 publishes.
            maybe_reactive_announce(state);
            // If we already have a session for this peer that's
            // stuck at Sighted (PC created but data channel never
            // opened) and we're the Offerer, re-poke the other
            // side with a fresh offer. webrtc-rs `create_offer`
            // calls `set_local_description` internally, which
            // kicks off a new ICE gathering cycle on the same PC
            // — no teardown needed, the remote handles the
            // renegotiation transparently. Rate-limited per-peer
            // via `last_offer_sent_at` so the announce burst from
            // a REQ replay (we've observed ~14 in one ms) doesn't
            // translate into a fan of fourteen offers. Only fires
            // for `Sighted` so once the channel opens and status
            // advances to `Handshaking` / `Active` / etc. we stop
            // re-offering automatically — no extra teardown
            // logic, no extra timer.
            let reoffer_session = if role == Role::Offerer {
                state.peers.get(&device_id).and_then(|p| {
                    let mut data = p.state.write();
                    if !matches!(data.status, PeerStatus::Sighted) {
                        return None;
                    }
                    let due = data
                        .last_offer_sent_at
                        .map(|prev| {
                            Instant::now().duration_since(prev)
                                >= Duration::from_millis(REOFFER_MIN_INTERVAL_MS)
                        })
                        .unwrap_or(true);
                    if !due {
                        return None;
                    }
                    data.last_offer_sent_at = Some(Instant::now());
                    p.session.lock().clone()
                })
            } else {
                None
            };
            if let Some(session) = reoffer_session {
                match session.create_offer().await {
                    Ok(desc) => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Debug,
                            "signaling",
                            format!("re-offer to {} (stuck at Sighted)", short_peer(&device_id)),
                            serde_json::json!({
                                "peer": device_id,
                                "sdp_bytes": desc.sdp.len(),
                                "reason": "stuck-at-sighted",
                            }),
                        );
                        let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                            device_id: device_id.clone(),
                            sdp: desc.sdp,
                        });
                    }
                    Err(e) => {
                        warn!(peer = %device_id, "re-offer create_offer failed: {e}");
                    }
                }
            }
            // A live peer that re-announced while its ICE is down most
            // likely had its network move — the answerer side of a handoff
            // prods us this way (it re-gathered and can't send us a
            // competing offer). If we're its offerer, renegotiate now so it
            // recovers in place rather than waiting out our own consent
            // timer. Single-flighted inside `renegotiate_ice`.
            if role == Role::Offerer {
                let unhealthy = state
                    .peers
                    .get(&device_id)
                    .and_then(|p| {
                        let session = p.session.lock().clone()?;
                        let status = p.state.read().status;
                        Some(
                            matches!(status, PeerStatus::Active | PeerStatus::Shelved)
                                && !matches!(
                                    session.ice_connection_state(),
                                    RTCIceConnectionState::Connected
                                        | RTCIceConnectionState::Completed
                                ),
                        )
                    })
                    .unwrap_or(false);
                if unhealthy {
                    renegotiate_ice(state, &device_id, false, "announce-unhealthy").await;
                }
            }
            clear_stale_session_if_zombie(state, &device_id).await;
            ensure_peer_session(state, device_id, role).await;
        }
        SignalingInbound::Offer { device_id, sdp } => {
            // If we didn't already start an answerer, do so now.
            let role = Role::Answerer;
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "signaling",
                format!("offer received from {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "sdp_bytes": sdp.len() }),
            );
            clear_stale_session_if_zombie(state, &device_id).await;
            // If our session for this peer has been stuck connecting (data
            // channel never opened) past the grace, this fresh offer is the
            // mutual-renegotiation deadlock: re-applying it onto the stuck
            // PC just re-resets ICE and the channel never opens. Drop the
            // corpse so the offer below builds a clean fresh PC whose data
            // channel — created by the offerer in this very offer — can
            // actually open, aligning our generation to theirs. The grace
            // (via `connecting_stuck_past_grace`) keeps a burst of
            // re-offers from churning a still-negotiating attempt.
            let stuck = state
                .peers
                .get(&device_id)
                .map(|p| {
                    connecting_stuck_past_grace(
                        &p.state.read(),
                        scheduler::RESTART_TRAFFIC_GRACE_MS,
                    )
                })
                .unwrap_or(false);
            if stuck {
                state.log_diag_with(
                    crate::events::DiagLevel::Info,
                    "signaling",
                    format!(
                        "fresh offer for stuck-connecting {} — rebuilding to answer cleanly",
                        short_peer(&device_id)
                    ),
                    serde_json::json!({ "peer": device_id, "reason": "stuck_connecting" }),
                );
                drop_peer(state, &device_id, DropReason::IceFailed).await;
            }
            ensure_peer_session(state, device_id.clone(), role).await;
            apply_remote_sdp(state, &device_id, RTCSdpType::Offer, sdp).await;
            // Build the answer. Extract the session under the lock,
            // drop everything, then await — guards across awaits
            // would make the future non-Send.
            let session = {
                let peer = state.peers.get(&device_id);
                peer.and_then(|p| p.session.lock().clone())
            };
            if let Some(session) = session {
                match session.create_answer().await {
                    Ok(desc) => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Debug,
                            "signaling",
                            format!("answer sent to {}", short_peer(&device_id)),
                            serde_json::json!({ "peer": device_id, "sdp_bytes": desc.sdp.len() }),
                        );
                        let _ = state.signaling_tx.send(SignalingOutbound::Answer {
                            device_id: device_id.clone(),
                            sdp: desc.sdp,
                        });
                    }
                    Err(e) => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Error,
                            "signaling",
                            format!("create_answer failed for {}: {e}", short_peer(&device_id)),
                            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
                        );
                        warn!(peer = %device_id, "create_answer failed: {e}");
                    }
                }
            }
        }
        SignalingInbound::Answer { device_id, sdp } => {
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "signaling",
                format!("answer received from {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "sdp_bytes": sdp.len() }),
            );
            apply_remote_sdp(state, &device_id, RTCSdpType::Answer, sdp).await;
        }
        SignalingInbound::Candidate {
            device_id,
            candidate,
        } => {
            // Classify the inbound candidate so the no-TURN
            // diagnostic has accurate remote-side counts. Record
            // before adding to the session — recording is cheap and
            // the add_ice_candidate await must happen without the
            // peer lock held.
            let kind = crate::transport::classify_candidate_sdp(&candidate.candidate);
            // Decide under the lock whether to apply now or queue
            // for after `set_remote_description`. Trickle ICE
            // candidates routinely arrive a few hundred ms before
            // the answer on a fast network; if we just hand them
            // to webrtc-rs at that point, it rejects with "remote
            // description is not set" and the candidate is gone —
            // including the host candidate that would have closed
            // a LAN pair, leaving the agent to fall back to a
            // peer-reflexive pair and the GUI to mis-paint the
            // link as STUN instead of LAN.
            enum Action {
                Apply(Arc<crate::transport::PeerSession>),
                Queued,
                NoPeer,
            }
            let action = if let Some(peer) = state.peers.get(&device_id) {
                let mut data = peer.state.write();
                data.diag.remote_candidates.record(kind);
                if !data.remote_description_set {
                    data.pending_remote_candidates.push(candidate.clone());
                    Action::Queued
                } else {
                    let session = peer.session.lock().clone();
                    drop(data);
                    match session {
                        Some(s) => Action::Apply(s),
                        None => Action::NoPeer,
                    }
                }
            } else {
                Action::NoPeer
            };
            match action {
                Action::Apply(session) => {
                    if let Err(e) = session.add_ice_candidate(candidate).await {
                        state.log_diag_with(
                            crate::events::DiagLevel::Warn,
                            "ice",
                            format!(
                                "remote {kind:?} candidate rejected by {}: {e}",
                                short_peer(&device_id)
                            ),
                            serde_json::json!({
                                "peer": device_id,
                                "kind": format!("{kind:?}"),
                                "error": e.to_string(),
                            }),
                        );
                        warn!(peer = %device_id, "add_ice_candidate failed: {e}");
                    }
                }
                Action::Queued => {
                    state.log_diag_with(
                        crate::events::DiagLevel::Debug,
                        "ice",
                        format!(
                            "queued remote {kind:?} candidate from {} (awaiting remote SDP)",
                            short_peer(&device_id)
                        ),
                        serde_json::json!({ "peer": device_id, "kind": format!("{kind:?}") }),
                    );
                }
                Action::NoPeer => {}
            }
        }
        SignalingInbound::PeerLeft { device_id } => {
            state.log_diag_with(
                crate::events::DiagLevel::Info,
                "signaling",
                format!("peer left signaling: {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id }),
            );
            drop_peer(state, &device_id, DropReason::UserLeft).await;
        }
    }
}

/// First-and-last-N chars of a peer pubkey for log readability. Long
/// base32 ids drown out the actual message; the prefix + suffix
/// preserves visual identity (same peer always renders the same
/// snippet) without taking up the entire line. `pub(crate)` so the
/// handshake / ladder / watchdog modules render peer IDs in their
/// diag entries the same way.
pub(crate) fn short_peer(id: &str) -> String {
    if id.len() <= 12 {
        return id.to_string();
    }
    format!("{}…{}", &id[..6], &id[id.len() - 4..])
}

/// Emit a presence announce, but only if we haven't already emitted one
/// within `REACTIVE_ANNOUNCE_MIN_INTERVAL_MS`. Every reactive announce
/// — reflecting a peer's announce, re-seeding discovery after a
/// checking-timeout rebuild, kicking discovery on a network change —
/// goes through here so a burst of triggers (a REQ-replay wave, a
/// network handoff dropping several peers at once) can never fan out
/// into a storm of relay publishes. Returns whether the announce was
/// actually emitted. The driver's own steady-state announcer is
/// independent of this and unaffected.
pub(crate) fn maybe_reactive_announce(state: &Arc<NetworkState>) -> bool {
    let mut guard = state.last_reactive_announce_at.lock();
    let now = Instant::now();
    let due = guard
        .map(|prev| {
            now.duration_since(prev) >= Duration::from_millis(REACTIVE_ANNOUNCE_MIN_INTERVAL_MS)
        })
        .unwrap_or(true);
    if due {
        *guard = Some(now);
        drop(guard);
        let _ = state.signaling_tx.send(SignalingOutbound::Announce);
    }
    due
}

/// Re-establish ICE on a *live* peer by renegotiating the SDP — the half
/// `restart_ice()` leaves undone.
///
/// `restart_ice()` rotates our local ICE ufrag/pwd and re-gathers *our*
/// candidates, but on its own it never tells the peer: no fresh offer
/// goes out, so the peer keeps the old credentials, never re-answers, and
/// never sends candidates of its own. The link then sits with our new
/// candidates and zero remote ones and can only recover by a full
/// teardown + rebuild (which lands on TURN). This does the missing half —
/// `restart_ice()` *then* a fresh offer — so both ends re-gather against
/// the new ufrag and reconnect in place, usually within a second or two.
///
/// Glare- and flood-safe:
///   * Only the deterministic *offerer* (lex-lower device id) emits the
///     restart offer, so the two ends can't offer at once. The answerer
///     re-gathers implicitly when the offer lands; meanwhile it nudges the
///     offerer with the (globally rate-limited) reactive announce rather
///     than sending a competing offer.
///   * Single-flighted on `last_offer_sent_at` (`REOFFER_MIN_INTERVAL_MS`)
///     so the network-change watcher, the ICE watchdog, and an inbound
///     announce collapse into one offer per window instead of a storm.
///   * Skipped while a renegotiation is already in flight (ICE
///     `Checking`) — re-issuing `restart_ice()` mid-gather just burns the
///     cycle ("ICE Agent can not be restarted when gathering").
///
/// `force` is set by the network-change watcher: right after the OS swaps
/// the primary interface, ICE still *reads* `Connected` (its
/// consent-freshness timer hasn't fired — that's the whole reason the
/// watcher exists), so we must renegotiate despite the stale "healthy"
/// state. The watchdog / announce callers pass `force = false` and skip a
/// genuinely-connected link.
pub(crate) async fn renegotiate_ice(
    state: &Arc<NetworkState>,
    device_id: &str,
    force: bool,
    trigger: &'static str,
) {
    // No primary interface → a `restart_ice()` here can't bind a socket
    // and only feeds the `Network is unreachable` gather spam. Hold off;
    // the network-change handler drives a fresh restart fan-out the
    // instant the interface returns.
    if state.is_offline() {
        return;
    }
    let session = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let s = peer.session.lock().clone();
        s
    };
    let Some(session) = session else { return };

    // Snapshot the ICE state we're firing from — together with `trigger`
    // this is the instrumentation that answers "what kicked a link that
    // was fine?". A restart from `Connected` (consent-freshness still
    // green) attributed to `network-change` points at a spurious
    // primary-IP flip; one from `Disconnected` attributed to
    // `ice-disconnected-watchdog` is a genuine drop. Without the
    // attribution every restart looks the same in the log.
    let ice_before = session.ice_connection_state();

    match session.ice_connection_state() {
        // Healthy. Unless the caller knows the network just moved
        // (`force`), leave it alone — and opportunistically settle the
        // tier back to Steady if a prior restart has since recovered.
        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed if !force => {
            if let Some(peer) = state.peers.get(device_id) {
                let mut data = peer.state.write();
                data.ice_disconnected_since = None;
                if matches!(
                    data.tier,
                    ConnectionTier::IceRestart { .. } | ConnectionTier::IceWatchdog { .. }
                ) {
                    data.tier = ConnectionTier::Steady;
                }
            }
            return;
        }
        // A gather/connectivity check is already in flight — don't
        // interrupt it, even on a forced network-change pass.
        RTCIceConnectionState::Checking => return,
        _ => {}
    }

    // Single-flight: collapse overlapping triggers into one offer/window.
    let offerer = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        let due = data
            .last_offer_sent_at
            .map(|t| {
                Instant::now().duration_since(t) >= Duration::from_millis(REOFFER_MIN_INTERVAL_MS)
            })
            .unwrap_or(true);
        if !due {
            return;
        }
        data.last_offer_sent_at = Some(Instant::now());
        data.tier = ConnectionTier::IceRestart {
            started: Instant::now(),
        };
        data.diag.ice_restarts += 1;
        state.identity.public_id() < device_id
    };

    // One line per *committed* restart (past single-flight), carrying the
    // trigger, the role, whether it was forced, the ICE state it fired
    // from, and the running restart count. This is the primary instrument
    // for the flapping investigation: tail the log and every renegotiation
    // names its cause. A burst of `trigger=network-change` from
    // `ice_before=Connected` on a healthy box is the signature of the
    // network watcher mis-firing on a multi-homed host.
    let restarts = state
        .peers
        .get(device_id)
        .map(|p| p.state.read().diag.ice_restarts)
        .unwrap_or(0);
    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "ice",
        format!(
            "ICE renegotiation for {} — trigger={trigger}, role={}, forced={force}, from={ice_before:?} (#{restarts})",
            short_peer(device_id),
            if offerer { "offerer" } else { "answerer" },
        ),
        serde_json::json!({
            "peer": device_id,
            "trigger": trigger,
            "role": if offerer { "offerer" } else { "answerer" },
            "forced": force,
            "ice_before": format!("{ice_before:?}"),
            "ice_restarts": restarts,
        }),
    );

    if offerer {
        // Re-gather *our* candidates against a fresh ufrag, then offer them.
        // Only the offerer restarts ICE here. If the answerer also called
        // `restart_ice()` it would put its own agent into gathering, and
        // applying this restart offer on its side then fails with "ICE Agent
        // can not be restarted when gathering" — the glare both ends hit when
        // a network change fires `force_ice_restart_all` on each of them at
        // once. The answerer re-gathers implicitly when it applies this offer
        // (the design this function's header already describes).
        if let Err(e) = session.restart_ice().await {
            // Benign when a gather from a previous trigger is still in flight;
            // the next watchdog poll picks it up once that settles.
            debug!(peer = %device_id, "restart_ice during renegotiate: {e}");
        }
        match session.create_offer().await {
            Ok(desc) => {
                // The single INFO line for this restart is the `trigger=…`
                // line above; the offer/nudge mechanics ride at DEBUG so a
                // renegotiation is one line in the default stream.
                state.log_diag_with(
                    crate::events::DiagLevel::Debug,
                    "ice",
                    format!(
                        "renegotiating ICE with {} — restart offer",
                        short_peer(device_id)
                    ),
                    serde_json::json!({
                        "peer": device_id,
                        "role": "offerer",
                        "sdp_bytes": desc.sdp.len(),
                    }),
                );
                let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                    device_id: device_id.to_string(),
                    sdp: desc.sdp,
                });
            }
            Err(e) => warn!(peer = %device_id, "renegotiate create_offer failed: {e}"),
        }
    } else {
        // Answerer: avoid glare. Deliberately do NOT restart our own ICE —
        // applying the offerer's restart offer is what re-gathers us, and
        // self-gathering here is exactly what makes that offer bounce off our
        // side with "can not be restarted when gathering". Just nudge the
        // offerer to send the restart offer; the reactive announce is globally
        // rate-limited so this can't add signaling load.
        state.log_diag_with(
            crate::events::DiagLevel::Debug,
            "ice",
            format!(
                "ICE renegotiate with {} — nudging offerer",
                short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "role": "answerer" }),
        );
        maybe_reactive_announce(state);
    }
}

async fn ensure_peer_session(state: &Arc<NetworkState>, device_id: String, role: Role) {
    if state.peers.contains_key(&device_id) {
        return;
    }
    let cfg = state.config.read().clone();
    let (session, mut rx) = match state
        .transport
        .open_peer(role, &cfg.stun_servers, &cfg.turn_servers)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            state.log_diag_with(
                crate::events::DiagLevel::Error,
                "transport",
                format!("open_peer failed for {}: {e}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "error": e.to_string() }),
            );
            warn!(peer = %device_id, "open_peer failed: {e}");
            return;
        }
    };
    let session = Arc::new(session);
    let peer = Arc::new(PeerConnection::new(
        device_id.clone(),
        Some(session.clone()),
    ));
    // Start the connect-timeout clock the moment the session exists: if the
    // data channel hasn't opened within DATA_CHANNEL_OPEN_TIMEOUT_MS of
    // now, the attempt is reclaimed and rebuilt (see
    // `ice_watchdog::poll_all`).
    peer.state.write().session_started_at = Some(Instant::now());
    state.peers.insert(device_id.clone(), peer.clone());

    state.emit(MeshEvent::Peer(PeerEvent::Sighted {
        network_id: state.network_id.clone(),
        device_id: device_id.clone(),
    }));
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "peer",
        format!("{} connecting (we are {role:?})", short_peer(&device_id)),
        serde_json::json!({ "peer": device_id, "role": format!("{role:?}") }),
    );

    // For offerer, kick off SDP exchange immediately.
    if role == Role::Offerer {
        match session.create_offer().await {
            Ok(desc) => {
                state.log_diag_with(
                    crate::events::DiagLevel::Debug,
                    "signaling",
                    format!("offer sent to {}", short_peer(&device_id)),
                    serde_json::json!({ "peer": device_id, "sdp_bytes": desc.sdp.len() }),
                );
                let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                    device_id: device_id.clone(),
                    sdp: desc.sdp,
                });
                if let Some(p) = state.peers.get(&device_id) {
                    p.state.write().last_offer_sent_at = Some(Instant::now());
                }
            }
            Err(e) => {
                state.log_diag_with(
                    crate::events::DiagLevel::Error,
                    "signaling",
                    format!("create_offer failed for {}: {e}", short_peer(&device_id)),
                    serde_json::json!({ "peer": device_id, "error": e.to_string() }),
                );
                warn!(peer = %device_id, "create_offer failed: {e}");
            }
        }
    }

    // Per-peer transport-event pump. Forwards every event into
    // the main driver via the command queue so all per-peer state
    // mutation happens serially. Each event is stamped with this
    // session's epoch so the driver can drop events from a torn-down
    // session that's still draining (see `handle_transport_event`).
    let driver_tx = state.cmd_tx.clone();
    let peer_id_for_pump = device_id.clone();
    let session_epoch = peer.epoch;
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if driver_tx
                .send(NetworkCmd::TransportEvent {
                    device_id: peer_id_for_pump.clone(),
                    epoch: session_epoch,
                    event: ev,
                })
                .is_err()
            {
                break;
            }
        }
    });
}

async fn apply_remote_sdp(
    state: &Arc<NetworkState>,
    device_id: &str,
    sdp_type: RTCSdpType,
    sdp: String,
) {
    let session = {
        let peer = state.peers.get(device_id);
        peer.and_then(|p| p.session.lock().clone())
    };
    let Some(session) = session else {
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "signaling",
            format!(
                "remote {sdp_type:?} for {} ignored — no session",
                short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "sdp_type": format!("{sdp_type:?}") }),
        );
        // A late Answer that lost its session: drive a fresh offer instead
        // of waiting out the next announce-driven re-offer.
        if sdp_type == RTCSdpType::Answer {
            reoffer_after_failed_answer(state, device_id).await;
        }
        return;
    };
    let desc = match sdp_type {
        RTCSdpType::Offer => RTCSessionDescription::offer(sdp).ok(),
        RTCSdpType::Answer => RTCSessionDescription::answer(sdp).ok(),
        _ => None,
    };
    if let Some(desc) = desc {
        if let Err(e) = session.set_remote_description(desc).await {
            state.log_diag_with(
                crate::events::DiagLevel::Error,
                "signaling",
                format!(
                    "set_remote_description({sdp_type:?}) failed for {}: {e}",
                    short_peer(device_id)
                ),
                serde_json::json!({
                    "peer": device_id,
                    "sdp_type": format!("{sdp_type:?}"),
                    "error": e.to_string(),
                }),
            );
            warn!(peer = %device_id, "set_remote_description failed: {e}");
            // The common failure here is an Answer arriving when our
            // signaling state has already raced back to `stable` (no
            // pending local offer) — "invalid proposed signaling state
            // transition from stable". A fresh offer re-opens the
            // negotiation cleanly rather than leaving the link wedged
            // until the next announce.
            if sdp_type == RTCSdpType::Answer {
                reoffer_after_failed_answer(state, device_id).await;
            }
        } else {
            // Drain any ICE candidates that arrived ahead of the
            // SDP. The lock comes off before any await — we pull
            // the pending vec out, then apply each candidate
            // outside the guard so the per-peer state lock isn't
            // held across the webrtc-rs add_ice_candidate await.
            let pending = if let Some(peer) = state.peers.get(device_id) {
                let mut data = peer.state.write();
                data.remote_description_set = true;
                std::mem::take(&mut data.pending_remote_candidates)
            } else {
                Vec::new()
            };
            if !pending.is_empty() {
                state.log_diag_with(
                    crate::events::DiagLevel::Debug,
                    "ice",
                    format!(
                        "applying {} queued remote candidate(s) for {}",
                        pending.len(),
                        short_peer(device_id)
                    ),
                    serde_json::json!({ "peer": device_id, "count": pending.len() }),
                );
                for cand in pending {
                    if let Err(e) = session.add_ice_candidate(cand).await {
                        warn!(peer = %device_id, "queued add_ice_candidate failed: {e}");
                    }
                }
            }
        }
    } else {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "signaling",
            format!(
                "remote SDP from {} unparseable as {sdp_type:?}",
                short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "sdp_type": format!("{sdp_type:?}") }),
        );
    }
}

/// An inbound Answer that can't be applied — it arrived after we tore the
/// session down ("no session"), or it raced our signaling state back to
/// `stable` ("invalid proposed signaling state transition from stable") —
/// means our last offer never completed the handshake. Discarding it and
/// waiting for the announce-driven "stuck at Sighted" re-offer costs a full
/// ~15-30 s lap; on a flapping wake that stacks into the multi-lap loop the
/// logs showed. Instead we drive a fresh offer right now: rebuild the
/// session if it's gone, otherwise re-offer in place. Only the offerer
/// sends offers (an Answer is addressed to us as the offerer, but we guard
/// on the same id comparison the rest of the engine uses), it's held off
/// while offline, and it's throttled by `last_offer_sent_at` so a burst of
/// stale answers collapses to a single offer.
async fn reoffer_after_failed_answer(state: &Arc<NetworkState>, device_id: &str) {
    if state.identity.public_id() >= device_id || state.is_offline() {
        return;
    }
    // Resolve the throttle + session under the peer lock, then act
    // outside it (the create_offer / open_peer awaits must not hold it).
    let session = match state.peers.get(device_id) {
        None => None,
        Some(peer) => {
            let due = {
                let mut data = peer.state.write();
                let due = data
                    .last_offer_sent_at
                    .map(|t| {
                        Instant::now().duration_since(t)
                            >= Duration::from_millis(REOFFER_MIN_INTERVAL_MS)
                    })
                    .unwrap_or(true);
                if due {
                    data.last_offer_sent_at = Some(Instant::now());
                }
                due
            };
            if !due {
                return;
            }
            peer.session.lock().clone()
        }
    };
    match session {
        Some(session) => match session.create_offer().await {
            Ok(desc) => {
                state.log_diag_with(
                    crate::events::DiagLevel::Debug,
                    "signaling",
                    format!(
                        "re-offer to {} (answer could not be applied)",
                        short_peer(device_id)
                    ),
                    serde_json::json!({
                        "peer": device_id,
                        "sdp_bytes": desc.sdp.len(),
                        "reason": "failed-answer",
                    }),
                );
                let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                    device_id: device_id.to_string(),
                    sdp: desc.sdp,
                });
            }
            Err(e) => warn!(peer = %device_id, "re-offer create_offer failed: {e}"),
        },
        // Peer gone (or session-less) — rebuild as offerer; that path
        // sends a fresh offer as part of setup.
        None => ensure_peer_session(state, device_id.to_string(), Role::Offerer).await,
    }
}

async fn handle_transport_event(
    state: &Arc<NetworkState>,
    device_id: String,
    epoch: u64,
    event: TransportEvent,
) {
    // Drop events from a stale session. When a peer is rebuilt (drop +
    // re-open for the same device id), the old session's event pump keeps
    // draining for a moment; its trailing `DataChannelClosed` would
    // otherwise call `drop_peer` on the *replacement* session and force an
    // immediate, needless rebuild — the duplicate "data channel closed"
    // lines and the spurious post-HeartbeatTimeout `IceFailed` seen in the
    // field. If the peer is gone entirely, there's nothing to act on
    // either. Either way, ignore the event (TRACE so the drop is still
    // greppable when chasing a transport bug).
    match state.peers.get(&device_id) {
        Some(peer) if peer.epoch == epoch => {}
        _ => {
            trace!(peer = %device_id, epoch, "ignoring transport event from stale/absent session");
            return;
        }
    }
    match event {
        TransportEvent::LocalIceCandidate(Some(cand)) => {
            // Classify before moving `cand` into the signaling
            // message so the no-TURN diagnostic
            // (`ice_watchdog::maybe_emit_no_turn_diag`) has accurate
            // host/srflx/relay counts to report.
            let kind = crate::transport::classify_candidate_sdp(&cand.candidate);
            if let Some(peer) = state.peers.get(&device_id) {
                peer.state.write().diag.local_candidates.record(kind);
            }
            // Debug-level: candidates are noisy (one per
            // host/srflx/relay), so the per-candidate detail lands
            // here and gets summarised when ICE eventually settles.
            // Surfacing them at info would drown out the higher-level
            // state transitions the user actually cares about.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "ice",
                format!(
                    "local {kind:?} candidate → {}: {}",
                    short_peer(&device_id),
                    cand.candidate
                ),
                serde_json::json!({ "peer": device_id, "kind": format!("{kind:?}") }),
            );
            let _ = state.signaling_tx.send(SignalingOutbound::Candidate {
                device_id: device_id.clone(),
                candidate: cand,
            });
        }
        TransportEvent::LocalIceCandidate(None) => {
            // Gathering complete sentinel. Surface as a single info
            // line with a summary of what we ended up offering — if
            // the peer never connects we want the user to see at a
            // glance "we sent 3 host, 1 srflx, 0 relay candidates"
            // so the TURN-needed diagnosis is one read away.
            let (h, s, r) = if let Some(peer) = state.peers.get(&device_id) {
                let data = peer.state.read();
                (
                    data.diag.local_candidates.host,
                    data.diag.local_candidates.server_reflexive,
                    data.diag.local_candidates.relay,
                )
            } else {
                (0, 0, 0)
            };
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "ice",
                format!(
                    "local gathering complete for {} — {h} host · {s} srflx · {r} relay",
                    short_peer(&device_id)
                ),
                serde_json::json!({
                    "peer": device_id,
                    "host": h,
                    "srflx": s,
                    "relay": r,
                }),
            );
        }
        TransportEvent::IceConnectionStateChanged(ice_state) => {
            // Every ICE state lands in the log — these are the
            // single biggest signal of whether NAT traversal is
            // working. "checking → connected" is the happy path;
            // "checking → disconnected → failed" is the no-TURN
            // signature; "new" never advancing means the signaling
            // layer never delivered candidates.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "ice",
                format!("ICE → {ice_state:?} for {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "state": format!("{ice_state:?}") }),
            );
            handle_ice_state_change(state, &device_id, ice_state).await;
        }
        TransportEvent::PeerConnectionStateChanged(pc_state) => {
            // Peer connection state is the higher-level view of the
            // same NAT traversal — useful when ICE reports Connected
            // but PC sticks at Connecting (DTLS handshake issue)
            // or vice versa.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "transport",
                format!("PC → {pc_state:?} for {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "state": format!("{pc_state:?}") }),
            );
            handle_pc_state_change(state, &device_id, pc_state).await;
        }
        TransportEvent::DataChannelOpen => {
            // The reliable "transport is up" milestone — record it so the
            // connect-timeout watchdog knows this session made it, and stops
            // counting it as a connecting peer that might need rebuilding.
            if let Some(peer) = state.peers.get(&device_id) {
                peer.state.write().data_channel_open = true;
            }
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "transport",
                format!(
                    "data channel open with {} — starting handshake",
                    short_peer(&device_id)
                ),
                serde_json::json!({ "peer": device_id }),
            );
            handshake::initiate(state, &device_id).await;
        }
        TransportEvent::DataChannelClosed => {
            state.log_diag_with(
                crate::events::DiagLevel::Warn,
                "transport",
                format!(
                    "data channel closed with {} — dropping peer",
                    short_peer(&device_id)
                ),
                serde_json::json!({ "peer": device_id }),
            );
            drop_peer(state, &device_id, DropReason::IceFailed).await;
        }
        TransportEvent::Message(bytes) => {
            handle_inbound_frame(state, &device_id, bytes).await;
        }
        TransportEvent::VideoSample(sample) => {
            // Same gate as channel frames: the connection's existence
            // (DTLS identity + roster approval) is the authorization;
            // app layers add their own policy on top.
            state.dispatch_video(&device_id, sample);
        }
        TransportEvent::AudioSample(sample) => {
            // Identical gate to video.
            state.dispatch_audio(&device_id, sample);
        }
    }
}

async fn handle_ice_state_change(
    state: &Arc<NetworkState>,
    device_id: &str,
    ice: RTCIceConnectionState,
) {
    // Instrumentation: a breadcrumb on every ICE transition so the log
    // carries the full state trail per peer, not just the headline
    // "connected"/"stuck" lines. `Disconnected` is the one that was
    // invisible before and matters most — it's a consent-freshness drop on
    // a previously-live link (the trigger the disconnected-watchdog then
    // acts on), so it's logged at INFO. `Failed` is left at DEBUG here
    // because `ice_watchdog::on_failed` already emits a WARN for it — no
    // need for two lines on the same event. The other churn states stay at
    // DEBUG to keep the stream readable.
    let level = match ice {
        RTCIceConnectionState::Disconnected => crate::events::DiagLevel::Info,
        _ => crate::events::DiagLevel::Debug,
    };
    state.log_diag_with(
        level,
        "ice",
        format!("{} ICE → {ice:?}", short_peer(device_id)),
        serde_json::json!({ "peer": device_id, "ice_state": format!("{ice:?}") }),
    );

    // Resolve the state transition under the lock, return what the
    // caller should do, then drop the lock before any await.
    let mut confirm_ping = false;
    let escalate_failed = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        data.diag.ice_transitions += 1;
        // ICE state never tears a peer down — it only clears or schedules
        // the in-place restart. Teardown is the data channel's job: a
        // connecting peer whose channel never opens hits the
        // data-channel-open timeout; an open peer that goes silent is
        // reclaimed by the heartbeat; a real close fires DataChannelClosed.
        // We trust webrtc-rs's ICE state here only to *drive recovery*,
        // never to decide a link is dead — it has been observed reporting
        // Failed/Disconnected on links carrying traffic and Connected on
        // links whose channel never came up.
        match ice {
            RTCIceConnectionState::Connected | RTCIceConnectionState::Completed => {
                data.ice_disconnected_since = None;
                // ICE reaching Connected is NOT proof the link carries
                // traffic — webrtc-rs reports Connected on dead TURN paths
                // (a network handoff left three peers "Connected" with zero
                // frames for 90 s). So a peer recovering from a restart does
                // not go Steady here; it stays in the restart tier with the
                // clock re-stamped to now, and we fire one confirm-ping.
                // Only actual inbound traffic — the pong, or any app frame —
                // promotes it to Steady (see `handle_inbound_frame`); if
                // none arrives within the grace, the restart-verify watchdog
                // rebuilds it. Initial connects (tier already Steady) are
                // untouched — they confirm via the handshake.
                if matches!(
                    data.tier,
                    ConnectionTier::IceWatchdog { .. }
                        | ConnectionTier::IceRestart { .. }
                        | ConnectionTier::WakeProbe
                ) {
                    data.tier = ConnectionTier::IceRestart {
                        started: Instant::now(),
                    };
                    confirm_ping = true;
                }
                false
            }
            RTCIceConnectionState::Disconnected => {
                // A consent-freshness drop on a previously-live link. Latch
                // the timestamp + tier so the disconnected-watchdog drives
                // an in-place `renegotiate_ice` (the data channel survives
                // a restart). No teardown.
                if data.ice_disconnected_since.is_none() {
                    data.ice_disconnected_since = Some(Instant::now());
                    data.tier = ConnectionTier::IceWatchdog {
                        since: Instant::now(),
                    };
                }
                false
            }
            RTCIceConnectionState::Failed => {
                // Restart in place rather than tear down: webrtc-rs reports
                // `Failed` even while a nominated pair is succeeding, so a
                // teardown here throws away a working-or-recoverable link.
                // `on_failed` re-gathers and re-offers; if the link is
                // genuinely gone, the data-channel-open timeout (still
                // connecting) or inbound silence (was up) reclaims it.
                true
            }
            _ => false,
        }
    };
    if escalate_failed {
        // Dump the full connectivity-check snapshot *before* the ladder
        // tears the session down — this is the "why did it fail"
        // record: every candidate pair, every STUN check counter, and a
        // plain-language diagnosis the user can act on.
        log_ice_check_snapshot(state, device_id, "ICE failed", true).await;
        ice_watchdog::on_failed(state, device_id).await;
    }
    if confirm_ping {
        // Probe the restarted path with traffic right now instead of
        // waiting up to a heartbeat interval: a live path pongs within an
        // RTT and gets promoted to Steady; a dead one stays unconfirmed for
        // the restart-verify watchdog to rebuild.
        heartbeat::send_ping(state, device_id).await;
    }
    // Once ICE settles, ask the agent which candidate pair it
    // actually chose so the GUI can paint the link type from real
    // data instead of guessing from gathered-candidate counts. We
    // also clear it on Disconnected/Failed/Closed so a stale
    // selection doesn't claim "LAN" while the connection is dead.
    match ice {
        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed => {
            record_selected_pair(state, device_id).await;
        }
        RTCIceConnectionState::Disconnected => {
            // A drop on a previously-checking/active pair: log a concise
            // breadcrumb of the check counters so a flap leaves a trail
            // (was the path ever two-way?) before we clear the pair.
            log_ice_check_snapshot(state, device_id, "ICE disconnected", false).await;
            if let Some(peer) = state.peers.get(device_id) {
                peer.state.write().selected_pair = None;
            }
        }
        RTCIceConnectionState::Failed | RTCIceConnectionState::Closed => {
            if let Some(peer) = state.peers.get(device_id) {
                peer.state.write().selected_pair = None;
            }
        }
        _ => {}
    }
}

/// Ask the peer's ICE agent for its nominated candidate pair and
/// stash it on the peer state. Quiet on `None` — the agent is
/// allowed not to know yet (renegotiation in flight, agent torn
/// down, etc.) and the next state change or the ICE poll will
/// re-query.
pub(crate) async fn record_selected_pair(state: &Arc<NetworkState>, device_id: &str) {
    // Same DashMap-Ref + MutexGuard scoping pattern as the watchdog:
    // pull the cloned `Arc<PeerSession>` into a named local before
    // the inner block returns so the guard drops before the `Ref`
    // does. Without the named binding Rust 2021's trailing-
    // expression scoping keeps the guard alive across the outer
    // borrow check.
    let session = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let session = peer.session.lock().clone();
        session
    };
    let Some(session) = session else { return };
    let pair = session.selected_candidate_pair().await;
    let Some(pair) = pair else { return };
    if let Some(peer) = state.peers.get(device_id) {
        peer.state.write().selected_pair = Some(pair);
    }
    // Summarize the chosen path as a transport word so a glance tells you
    // whether you're going direct or through STUN/TURN — the detail keeps
    // the raw candidate types for the GUI / DEBUG.
    let local = format!("{:?}", pair.local);
    let remote = format!("{:?}", pair.remote);
    let transport = if local.contains("Relay") || remote.contains("Relay") {
        "relayed (TURN)"
    } else if local.contains("Srflx")
        || local.contains("Prflx")
        || remote.contains("Srflx")
        || remote.contains("Prflx")
    {
        "reflexive (STUN)"
    } else {
        "direct"
    };
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "ice",
        format!("{} connected · {transport}", short_peer(device_id)),
        serde_json::json!({
            "peer": device_id,
            "local": local,
            "remote": remote,
            "transport": transport,
        }),
    );
}

/// Pull a live ICE connectivity-check snapshot for `device_id` and log
/// it. This is the core instrument for diagnosing why a peer won't
/// connect: it surfaces every candidate pair the agent formed and,
/// crucially, whether our STUN checks are getting responses — the
/// difference between "signaling never delivered candidates" and "the
/// network is silently dropping our UDP". `full` controls verbosity: a
/// terminal event (ICE failed) dumps every pair plus a plain-language
/// diagnosis at WARN; a periodic progress tick logs a single aggregate
/// line at INFO so it can be watched live without flooding the log.
///
/// The webrtc-rs sibling crates are silenced to ERROR in the default
/// log filter (see `myownmesh/src/main.rs`), so these counters would
/// otherwise be invisible. This lifts the load-bearing ones into our
/// own diag stream where the user — and the GUI Activity tab — see them
/// by default, no `MYOWNMESH_LOG` override required.
pub(crate) async fn log_ice_check_snapshot(
    state: &Arc<NetworkState>,
    device_id: &str,
    context: &str,
    full: bool,
) {
    // Same Ref + MutexGuard scoping dance as record_selected_pair:
    // clone the session out, drop every guard, then await.
    let session = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let session = peer.session.lock().clone();
        session
    };
    let Some(session) = session else { return };
    let snap = session.ice_check_snapshot().await;
    if snap.is_empty() {
        return;
    }
    let detail = serde_json::json!({
        "peer": device_id,
        "context": context,
        "snapshot": snap,
    });
    if full {
        // Concise one-liner at WARN — counts plus the plain-language
        // diagnosis (e.g. "no remote candidates arrived"). This is the part
        // worth seeing on the default stream; the per-candidate / per-pair
        // dump below is deep instrumentation kept behind debug.
        let header = format!(
            "ICE check for {} ({context}): {} local · {} remote · {} pairs · {} succeeded — {}",
            short_peer(device_id),
            snap.local_candidates.len(),
            snap.remote_candidates.len(),
            snap.pairs.len(),
            snap.succeeded_pairs(),
            snap.diagnosis(),
        );
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "ice",
            header,
            detail.clone(),
        );

        // Skip building the (potentially long) candidate/pair dump unless
        // debug logging is actually on — it only ever rendered at debug now.
        if tracing::enabled!(tracing::Level::DEBUG) {
            let mut msg = format!(
                "ICE detail for {} ({context}):\n  local : {}\n  remote: {}",
                short_peer(device_id),
                render_candidate_list(&snap.local_candidates),
                render_candidate_list(&snap.remote_candidates),
            );
            // Per-pair: only `state` and `nominated` are real — webrtc-ice
            // 0.13 leaves the STUN/byte counters at zero (see
            // `diag::IcePairSnapshot`), so printing them was pure noise. Cap
            // the dump: a churning agent can form 150+ pairs. The pairs are
            // pre-sorted nominated→succeeded→active, so the capped head is the
            // informative part; the tail is summarized.
            const MAX_PAIRS_LOGGED: usize = 12;
            for p in snap.pairs.iter().take(MAX_PAIRS_LOGGED) {
                msg.push_str(&format!(
                    "\n  {} ⇄ {} [{}{}]",
                    p.local,
                    p.remote,
                    p.state,
                    if p.nominated { " NOMINATED" } else { "" },
                ));
            }
            if snap.pairs.len() > MAX_PAIRS_LOGGED {
                let hidden = snap.pairs.len() - MAX_PAIRS_LOGGED;
                let failed = snap.pairs.iter().filter(|p| p.state == "failed").count();
                msg.push_str(&format!(
                    "\n  (… and {hidden} more pairs not shown · {failed} failed of {} total)",
                    snap.pairs.len(),
                ));
            }
            state.log_diag_with(crate::events::DiagLevel::Debug, "ice", msg, detail);
        }
    } else {
        let msg = format!(
            "ICE checking {} — {}/{} pairs succeeded · {}",
            short_peer(device_id),
            snap.succeeded_pairs(),
            snap.pairs.len(),
            snap.diagnosis(),
        );
        state.log_diag_with(crate::events::DiagLevel::Debug, "ice", msg, detail);
    }
}

/// Comma-join a candidate list for the snapshot log, or `(none)` when
/// empty so an absent side reads unambiguously rather than as a blank.
fn render_candidate_list(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.join(", ")
    }
}

async fn handle_pc_state_change(
    state: &Arc<NetworkState>,
    device_id: &str,
    pc: RTCPeerConnectionState,
) {
    // A closed connection is a real teardown — drop and let discovery
    // rebuild. Every other PC state, `Failed` included, is a no-op:
    // ICE-`Failed` (`handle_ice_state_change`) already kicks the in-place
    // restart, and teardown of a still-connecting peer comes from the
    // data-channel-open timeout while an already-open peer is reclaimed by
    // inbound silence. (`Failed` used to arm the old checking-timeout; that
    // machinery is gone — ICE/PC state no longer tears anyone down.)
    if pc == RTCPeerConnectionState::Closed {
        drop_peer(state, device_id, DropReason::IceFailed).await;
    }
}

async fn handle_inbound_frame(state: &Arc<NetworkState>, device_id: &str, bytes: Bytes) {
    let msg: MeshMessage = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => {
            warn!(peer = %device_id, "discarding undeserializable frame: {e}");
            return;
        }
    };
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        data.last_recv_at = Some(Instant::now());
        data.diag.bytes_in += bytes.len() as u64;
        data.diag.frames_in += 1;
        // Inbound traffic is the proof a restart actually worked — ICE
        // state isn't (see `handle_ice_state_change`). A frame here
        // promotes a recovering peer back to Steady and clears the ICE
        // disconnect marker, so the restart-verify watchdog leaves it
        // alone. This is the single signal that says "the link is really
        // carrying frames again."
        if matches!(
            data.tier,
            ConnectionTier::IceWatchdog { .. }
                | ConnectionTier::IceRestart { .. }
                | ConnectionTier::WakeProbe
        ) {
            data.tier = ConnectionTier::Steady;
            data.ice_disconnected_since = None;
        }
    }
    match msg {
        MeshMessage::Hello(hello) => handshake::on_hello(state, device_id, hello).await,
        MeshMessage::AuthResponse(resp) => {
            handshake::on_auth_response(state, device_id, resp).await
        }
        MeshMessage::Approve(_) => handshake::on_approve(state, device_id).await,
        MeshMessage::Deny(d) => handshake::on_deny(state, device_id, d).await,
        MeshMessage::Ping(p) => heartbeat::on_ping(state, device_id, p).await,
        MeshMessage::Pong(p) => heartbeat::on_pong(state, device_id, p).await,
        MeshMessage::Shelve(s) => on_shelve(state, device_id, s).await,
        MeshMessage::Unshelve(_) => on_unshelve(state, device_id).await,
        MeshMessage::CapabilitiesUpdate(u) => on_capabilities_update(state, device_id, u).await,
        MeshMessage::RpcRequest(req) => on_rpc_request(state, device_id, req).await,
        MeshMessage::RpcResponse(resp) => on_rpc_response(state, device_id, resp).await,
        MeshMessage::RpcStreamChunk(c) => on_rpc_stream_chunk(state, device_id, c).await,
        MeshMessage::RpcStreamEnd(e) => on_rpc_stream_end(state, device_id, e).await,
        MeshMessage::Channel { channel, payload } => {
            on_channel_frame(state, device_id, channel, payload).await
        }
        MeshMessage::NetworkState(b) => governance::on_state_broadcast(state, device_id, b).await,
        MeshMessage::NetworkStatePropose(m) => governance::on_propose(state, device_id, m).await,
        MeshMessage::NetworkStateAck(m) => governance::on_ack(state, device_id, m).await,
        MeshMessage::NetworkStateSplit(m) => governance::on_split(state, device_id, m).await,
        MeshMessage::RosterSummary(m) => governance::on_roster_summary(state, device_id, m).await,
        MeshMessage::RosterRequest(m) => governance::on_roster_request(state, device_id, m).await,
        MeshMessage::RosterEntries(m) => governance::on_roster_entries(state, device_id, m).await,
        MeshMessage::Unknown => {
            trace!(peer = %device_id, "discarding unknown frame variant");
        }
    }
}

async fn on_shelve(state: &Arc<NetworkState>, device_id: &str, msg: ShelveMessage) {
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        if !data.remote_shelved {
            data.remote_shelved = true;
            state.emit(MeshEvent::Peer(PeerEvent::Shelved {
                network_id: state.network_id.clone(),
                device_id: device_id.to_string(),
                reason: msg.reason,
                by_us: false,
            }));
        }
    }
}

async fn on_unshelve(state: &Arc<NetworkState>, device_id: &str) {
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        if data.remote_shelved {
            data.remote_shelved = false;
            state.emit(MeshEvent::Peer(PeerEvent::Unshelved {
                network_id: state.network_id.clone(),
                device_id: device_id.to_string(),
                by_us: false,
            }));
        }
    }
}

async fn on_capabilities_update(
    state: &Arc<NetworkState>,
    device_id: &str,
    msg: CapabilitiesUpdateMessage,
) {
    if let Some(peer) = state.peers.get(device_id) {
        peer.state.write().capabilities = Some(msg.capabilities.clone());
    }
    state.emit(MeshEvent::Peer(PeerEvent::CapabilitiesChanged {
        network_id: state.network_id.clone(),
        device_id: device_id.to_string(),
        capabilities: msg.capabilities,
    }));
}

async fn on_rpc_request(state: &Arc<NetworkState>, device_id: &str, req: RpcRequestMessage) {
    let Some(rpc) = state.rpc.read().clone() else {
        // No RPC bound yet — send a transient error so the peer
        // doesn't hang on the oneshot.
        let _ = send_to_peer(
            state,
            device_id,
            &MeshMessage::RpcResponse(RpcResponseMessage {
                request_id: req.request_id,
                ok: None,
                error: Some("rpc not bound".into()),
            }),
        )
        .await;
        return;
    };
    let call = crate::rpc::RpcCall {
        from: device_id.to_string(),
        request_id: req.request_id.clone(),
        method: req.method.clone(),
        payload: req.payload.clone(),
        streaming: req.streaming,
    };
    let handler = rpc.handlers.get(&req.method);
    let Some(handler) = handler else {
        let _ = send_to_peer(
            state,
            device_id,
            &MeshMessage::RpcResponse(RpcResponseMessage {
                request_id: req.request_id,
                ok: None,
                error: Some(format!("no handler for '{}'", req.method)),
            }),
        )
        .await;
        return;
    };
    match &*handler {
        crate::rpc::HandlerEntry::Single(h) => {
            let fut = (h.clone())(call);
            let state = state.clone();
            let device_id = device_id.to_string();
            let request_id = req.request_id;
            drop(handler);
            tokio::spawn(async move {
                let resp = fut.await;
                let frame = match resp {
                    Ok(r) => RpcResponseMessage {
                        request_id,
                        ok: Some(r.body),
                        error: None,
                    },
                    Err(e) => RpcResponseMessage {
                        request_id,
                        ok: None,
                        error: Some(e),
                    },
                };
                let _ = send_to_peer(&state, &device_id, &MeshMessage::RpcResponse(frame)).await;
            });
        }
        crate::rpc::HandlerEntry::Stream(h) => {
            let fut = (h.clone())(call);
            let state = state.clone();
            let device_id = device_id.to_string();
            let request_id = req.request_id;
            drop(handler);
            tokio::spawn(async move {
                let mut rx = match fut.await {
                    Ok(rx) => rx,
                    Err(e) => {
                        let _ = send_to_peer(
                            &state,
                            &device_id,
                            &MeshMessage::RpcStreamEnd(RpcStreamEndMessage {
                                request_id,
                                error: Some(e),
                            }),
                        )
                        .await;
                        return;
                    }
                };
                let mut seq = 0u64;
                while let Some(payload) = rx.recv().await {
                    seq += 1;
                    let _ = send_to_peer(
                        &state,
                        &device_id,
                        &MeshMessage::RpcStreamChunk(RpcStreamChunkMessage {
                            request_id: request_id.clone(),
                            seq,
                            payload,
                        }),
                    )
                    .await;
                }
                let _ = send_to_peer(
                    &state,
                    &device_id,
                    &MeshMessage::RpcStreamEnd(RpcStreamEndMessage {
                        request_id,
                        error: None,
                    }),
                )
                .await;
            });
        }
    }
}

async fn on_rpc_response(state: &Arc<NetworkState>, _device_id: &str, resp: RpcResponseMessage) {
    let rpc = match state.rpc.read().clone() {
        Some(r) => r,
        None => return,
    };
    let Some((_, entry)) = rpc.pending.remove(&resp.request_id) else {
        return;
    };
    if let crate::rpc::PendingEntry::Single(tx) = entry {
        let result = if let Some(err) = resp.error {
            Err(err)
        } else {
            Ok(crate::rpc::RpcResponse {
                body: resp.ok.unwrap_or(serde_json::Value::Null),
            })
        };
        let _ = tx.send(result);
    }
}

async fn on_rpc_stream_chunk(
    state: &Arc<NetworkState>,
    _device_id: &str,
    chunk: RpcStreamChunkMessage,
) {
    let rpc = match state.rpc.read().clone() {
        Some(r) => r,
        None => return,
    };
    // Pull the sender out under the DashMap shard lock, drop the
    // ref, then send — sender clone is cheap and avoids holding
    // the ref across the send.
    let sender = rpc
        .pending
        .get(&chunk.request_id)
        .and_then(|entry| match &*entry {
            crate::rpc::PendingEntry::Stream(tx) => Some(tx.clone()),
            crate::rpc::PendingEntry::Single(_) => None,
        });
    if let Some(tx) = sender {
        let _ = tx.send(Ok(chunk.payload));
    }
}

async fn on_rpc_stream_end(state: &Arc<NetworkState>, _device_id: &str, end: RpcStreamEndMessage) {
    let rpc = match state.rpc.read().clone() {
        Some(r) => r,
        None => return,
    };
    if let Some((_, crate::rpc::PendingEntry::Stream(tx))) = rpc.pending.remove(&end.request_id) {
        if let Some(err) = end.error {
            let _ = tx.send(Err(err));
        }
        // Drop the sender so the receiver's loop exits.
        drop(tx);
    }
}

async fn on_channel_frame(
    state: &Arc<NetworkState>,
    device_id: &str,
    channel: String,
    payload: serde_json::Value,
) {
    state.dispatch_channel_frame(&channel, device_id, payload);
}

/// Send a single MeshMessage to one peer. Best-effort: returns an
/// error if the peer is unknown or the data channel isn't open
/// yet. Engine paths use this directly; user-facing channels call
/// the [`NetworkState::send_channel_frame`] wrapper.
pub(crate) async fn send_to_peer(
    state: &Arc<NetworkState>,
    device_id: &str,
    msg: &MeshMessage,
) -> Result<()> {
    let session = {
        let Some(peer) = state.peers.get(device_id) else {
            return Err(Error::Network(format!("peer not found: {device_id}")));
        };
        let session = peer.session.lock().clone();
        session
    };
    let session = session.ok_or_else(|| Error::Transport("session not yet established".into()))?;
    let serialized = serde_json::to_vec(msg).map_err(Error::Serde)?;
    let n = session.send(Bytes::from(serialized)).await?;
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        data.diag.bytes_out += n as u64;
        data.diag.frames_out += 1;
    }
    Ok(())
}

async fn send_channel_frame(
    state: &Arc<NetworkState>,
    peer: &str,
    channel: &str,
    payload: serde_json::Value,
) -> Result<()> {
    send_to_peer(
        state,
        peer,
        &MeshMessage::Channel {
            channel: channel.to_string(),
            payload,
        },
    )
    .await
}

async fn broadcast_channel_frame(
    state: &Arc<NetworkState>,
    channel: &str,
    payload: serde_json::Value,
) -> usize {
    let peers: Vec<String> = state
        .peers
        .iter()
        .filter(|e| {
            let s = e.value().state.read();
            matches!(s.status, PeerStatus::Active) && !s.local_shelved && !s.remote_shelved
        })
        .map(|e| e.key().clone())
        .collect();
    let mut delivered = 0usize;
    for peer in peers {
        if send_to_peer(
            state,
            &peer,
            &MeshMessage::Channel {
                channel: channel.to_string(),
                payload: payload.clone(),
            },
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }
    delivered
}

async fn send_rpc_request(
    state: &Arc<NetworkState>,
    peer: &str,
    request: RpcRequestMessage,
) -> Result<()> {
    send_to_peer(state, peer, &MeshMessage::RpcRequest(request)).await
}

async fn broadcast_capabilities(state: &Arc<NetworkState>, caps: CapabilityAdvert) -> usize {
    let peers: Vec<String> = state
        .peers
        .iter()
        .filter(|e| matches!(e.value().state.read().status, PeerStatus::Active))
        .map(|e| e.key().clone())
        .collect();
    let mut delivered = 0usize;
    for peer in peers {
        if send_to_peer(
            state,
            &peer,
            &MeshMessage::CapabilitiesUpdate(CapabilitiesUpdateMessage {
                capabilities: caps.clone(),
            }),
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }
    delivered
}

/// Engine-side wiring of the documented inbound-recency zombie
/// clearing (`STALE_INBOUND_MS`). When a fresh announce/offer arrives
/// from a peer we still hold but haven't received anything from in
/// longer than the threshold, the existing peer connection is a
/// zombie: applying the new SDP onto it would wedge WebRTC, and
/// `ensure_peer_session` would short-circuit on the stale entry. Drop
/// it first so the inbound signal drives a clean rebuild.
///
/// This is the path that lets a node which was frozen (and torn down
/// by its peers) recover in seconds: once it re-announces on wake and
/// a neighbor's offer comes back, the woken node clears its own stale
/// session here instead of waiting for the next scheduled announce.
///
/// A peer with no recorded inbound yet (`last_recv_at == None`, e.g.
/// mid-first-handshake or stuck at `Sighted`) is left untouched — only
/// a peer that was receiving and then went silent is a zombie; the
/// Sighted-stuck case is handled by the re-offer path instead.
async fn clear_stale_session_if_zombie(state: &Arc<NetworkState>, device_id: &str) {
    let is_zombie = match state.peers.get(device_id) {
        Some(peer) => {
            let stale = match peer.state.read().last_recv_at {
                Some(last) => last.elapsed().as_millis() as u64 > scheduler::STALE_INBOUND_MS,
                None => false,
            };
            if !stale {
                false
            } else {
                // Stale inbound is necessary but not sufficient. A session
                // whose ICE is actively checking or connected — or that we
                // kicked an in-place restart on within the last checking
                // window — is mid-recovery, not a wedged zombie. Dropping it
                // here is exactly what guillotined the restart-before-drop
                // path after a wake: the restart had already re-gathered, but
                // inbound was still pre-wake-stale, so the next announce tore
                // it down and forced a full rebuild storm. Give recovery a
                // full window before the zombie path can reclaim the peer; a
                // genuinely dead session (Failed/Disconnected/New with no
                // restart in flight) still gets cleared as before.
                let recovering = {
                    let restart_in_flight = {
                        let data = peer.state.read();
                        match data.tier {
                            ConnectionTier::IceRestart { started } => {
                                started.elapsed()
                                    < Duration::from_millis(scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS)
                            }
                            ConnectionTier::IceWatchdog { since } => {
                                since.elapsed()
                                    < Duration::from_millis(scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS)
                            }
                            _ => false,
                        }
                    };
                    let ice_live = peer
                        .session
                        .lock()
                        .as_ref()
                        .map(|s| {
                            matches!(
                                s.ice_connection_state(),
                                RTCIceConnectionState::Checking
                                    | RTCIceConnectionState::Connected
                                    | RTCIceConnectionState::Completed
                            )
                        })
                        .unwrap_or(false);
                    restart_in_flight || ice_live
                };
                !recovering
            }
        }
        None => false,
    };
    if is_zombie {
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "signaling",
            format!(
                "clearing stale session for {} before rebuild (no inbound > {} ms)",
                short_peer(device_id),
                scheduler::STALE_INBOUND_MS
            ),
            serde_json::json!({
                "peer": device_id,
                "stale_inbound_ms": scheduler::STALE_INBOUND_MS,
            }),
        );
        drop_peer(state, device_id, DropReason::HeartbeatTimeout).await;
    }
}

pub(crate) async fn drop_peer(state: &Arc<NetworkState>, device_id: &str, reason: DropReason) {
    let removed = state.peers.remove(device_id);
    if let Some((_, peer)) = removed {
        let session = peer.session.lock().clone();
        if let Some(session) = session {
            // Spawn the close so the driver loop never blocks on
            // the WebRTC teardown's potentially-slow path.
            tokio::spawn(async move {
                let _ = session.close().await;
            });
        }
        state.emit(MeshEvent::Peer(PeerEvent::Dropped {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            reason: reason.clone(),
            grace_window_ms: scheduler::RECONNECTING_GRACE_MS,
        }));
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "peer",
            format!("{} dropped ({reason:?})", short_peer(device_id)),
            serde_json::json!({ "peer": device_id, "reason": format!("{reason:?}") }),
        );
    }
    phase::recompute(state);
    ladder::reevaluate_topology(state).await;
}

/// Build a minimal `NetworkState` for unit tests. One process-wide
/// `MYOWNMESH_HOME` is set once (so parallel unit tests don't clobber
/// each other's env var) and each caller passes a unique suffix so
/// their on-disk roster / state files don't collide.
#[cfg(test)]
pub(crate) fn build_test_state(network_id_suffix: &str) -> Arc<NetworkState> {
    use std::sync::OnceLock;
    static HOME: OnceLock<tempfile::TempDir> = OnceLock::new();
    let _ = HOME.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", dir.path());
        dir
    });

    let network_id = format!("unit-test-{network_id_suffix}");
    let config = crate::config::NetworkConfig {
        id: network_id.clone(),
        network_id,
        label: "test".into(),
        kind: Default::default(),
        topology: crate::config::TopologyMode::FullMesh,
        signaling: crate::config::SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        auto_approve: true,
    };
    let identity = Arc::new(crate::identity::Identity::ephemeral());
    let transport = crate::transport::Transport::new().expect("transport");
    let (state, _signaling_in_rx, _cmd_rx) =
        NetworkState::new(config, identity, transport).expect("network state");
    state
}

/// Insert a peer with no WebRTC session and a chosen `last_recv_at`,
/// so a test can exercise the staleness predicate without standing up
/// a real transport.
#[cfg(test)]
pub(crate) fn insert_session_less_peer(
    state: &Arc<NetworkState>,
    device_id: &str,
    last_recv_at: Option<Instant>,
) {
    let peer = Arc::new(PeerConnection::new(device_id.to_string(), None));
    peer.state.write().last_recv_at = last_recv_at;
    state.peers.insert(device_id.to_string(), peer);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn stale_instant() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_millis(scheduler::STALE_INBOUND_MS + 5_000))
            .expect("test host monotonic clock has enough headroom")
    }

    fn pre_connect_timeout_instant() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_millis(
                scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS + 5_000,
            ))
            .expect("test host monotonic clock has enough headroom")
    }

    #[tokio::test]
    async fn connect_timeout_reclaims_a_peer_whose_data_channel_never_opened() {
        // A session created long ago whose data channel never opened is a
        // failed attempt — the connect-timeout watchdog must reclaim it so
        // discovery rebuilds. This is the teardown authority that replaced
        // the ICE-checking timeout; it keys off the reliable milestone.
        let state = build_test_state("connect-timeout-drop");
        insert_session_less_peer(&state, "stuck-peer", None);
        {
            let peer = state.peers.get("stuck-peer").expect("peer present");
            let mut d = peer.state.write();
            d.session_started_at = Some(pre_connect_timeout_instant());
            d.data_channel_open = false;
        }
        ice_watchdog::poll_all(&state).await;
        assert!(
            !state.peers.contains_key("stuck-peer"),
            "a session whose data channel never opened past the deadline must be reclaimed"
        );
    }

    #[test]
    fn connecting_stuck_detection_keys_off_data_channel_and_age() {
        let grace = scheduler::RESTART_TRAFFIC_GRACE_MS;
        let old = Instant::now()
            .checked_sub(Duration::from_millis(grace + 1_000))
            .expect("clock headroom");

        // Fresh session, channel not open yet → still legitimately
        // negotiating, NOT stuck (don't churn a new attempt).
        let fresh = connection::PeerStateData {
            session_started_at: Some(Instant::now()),
            data_channel_open: false,
            ..Default::default()
        };
        assert!(!connecting_stuck_past_grace(&fresh, grace));

        // Old session, channel still never opened → stuck; a fresh offer
        // should rebuild rather than renegotiate onto the corpse.
        let stuck = connection::PeerStateData {
            session_started_at: Some(old),
            data_channel_open: false,
            ..Default::default()
        };
        assert!(connecting_stuck_past_grace(&stuck, grace));

        // Channel opened → never "stuck" regardless of age; liveness is the
        // heartbeat's job from here, and an offer is a real renegotiation.
        let open = connection::PeerStateData {
            session_started_at: Some(old),
            data_channel_open: true,
            ..Default::default()
        };
        assert!(!connecting_stuck_past_grace(&open, grace));
    }

    #[tokio::test]
    async fn restart_verify_rebuilds_a_restart_that_never_carried_traffic() {
        // A peer stuck in IceRestart whose clock is older than the deadline,
        // with no session (so it reads as "ICE not up" → the connect-timeout
        // deadline applies): the restart never confirmed via traffic, so it
        // must be rebuilt. data_channel_open=true keeps the connect-timeout
        // watchdog out of it, isolating the restart-verify path.
        let state = build_test_state("restart-verify-drop");
        insert_session_less_peer(&state, "dead-restart", None);
        {
            let peer = state.peers.get("dead-restart").expect("peer present");
            let mut d = peer.state.write();
            d.data_channel_open = true;
            d.session_started_at = None;
            d.tier = ConnectionTier::IceRestart {
                started: pre_connect_timeout_instant(),
            };
        }
        ice_watchdog::poll_all(&state).await;
        assert!(
            !state.peers.contains_key("dead-restart"),
            "a restart that never confirmed via traffic past the deadline must be rebuilt"
        );
    }

    #[tokio::test]
    async fn restart_verify_spares_a_fresh_restart() {
        // A just-kicked restart must be given time to confirm, not rebuilt
        // on the first poll.
        let state = build_test_state("restart-verify-keep");
        insert_session_less_peer(&state, "fresh-restart", None);
        {
            let peer = state.peers.get("fresh-restart").expect("peer present");
            let mut d = peer.state.write();
            d.data_channel_open = true;
            d.session_started_at = None;
            d.tier = ConnectionTier::IceRestart {
                started: Instant::now(),
            };
        }
        ice_watchdog::poll_all(&state).await;
        assert!(
            state.peers.contains_key("fresh-restart"),
            "a just-kicked restart must be given its grace, not rebuilt immediately"
        );
    }

    #[tokio::test]
    async fn connect_timeout_spares_a_peer_whose_data_channel_opened() {
        // Same old session clock, but the data channel opened — so liveness
        // is the heartbeat's job now, not the connect-timeout's. ICE state
        // could say anything; once the channel is up this watchdog must
        // never touch the peer.
        let state = build_test_state("connect-timeout-keep");
        insert_session_less_peer(&state, "live-peer", None);
        {
            let peer = state.peers.get("live-peer").expect("peer present");
            let mut d = peer.state.write();
            d.session_started_at = Some(pre_connect_timeout_instant());
            d.data_channel_open = true;
        }
        ice_watchdog::poll_all(&state).await;
        assert!(
            state.peers.contains_key("live-peer"),
            "once the data channel has opened, the connect-timeout must never reclaim the peer"
        );
    }

    #[tokio::test]
    async fn zombie_session_cleared_on_stale_inbound() {
        let state = build_test_state("zombie-clear");
        insert_session_less_peer(&state, "peer-zombie", Some(stale_instant()));
        assert!(state.peers.contains_key("peer-zombie"));
        clear_stale_session_if_zombie(&state, "peer-zombie").await;
        assert!(
            !state.peers.contains_key("peer-zombie"),
            "a peer silent past STALE_INBOUND_MS must be dropped so the inbound announce/offer rebuilds it"
        );
    }

    #[tokio::test]
    async fn recently_active_peer_not_cleared() {
        let state = build_test_state("fresh-keep");
        insert_session_less_peer(&state, "peer-fresh", Some(Instant::now()));
        clear_stale_session_if_zombie(&state, "peer-fresh").await;
        assert!(
            state.peers.contains_key("peer-fresh"),
            "a peer that received recently must be kept — in-place ICE recovery, not a full rebuild"
        );
    }

    #[tokio::test]
    async fn peer_without_inbound_not_cleared() {
        let state = build_test_state("none-keep");
        insert_session_less_peer(&state, "peer-handshaking", None);
        clear_stale_session_if_zombie(&state, "peer-handshaking").await;
        assert!(
            state.peers.contains_key("peer-handshaking"),
            "a peer with no inbound yet (mid-handshake / Sighted) must be left for the re-offer path"
        );
    }

    #[tokio::test]
    async fn stale_session_transport_event_is_ignored() {
        let state = build_test_state("epoch-guard");
        insert_session_less_peer(&state, "peer-epoch", Some(Instant::now()));
        let epoch = state.peers.get("peer-epoch").expect("peer present").epoch;

        // A DataChannelClosed pumped in from a torn-down session (epoch no
        // longer current) must not drop the live replacement peer — this is
        // the spurious post-rebuild `IceFailed` we saw amplifying the flap.
        handle_transport_event(
            &state,
            "peer-epoch".to_string(),
            epoch.wrapping_add(1),
            TransportEvent::DataChannelClosed,
        )
        .await;
        assert!(
            state.peers.contains_key("peer-epoch"),
            "a DataChannelClosed from a stale session epoch must be ignored, not drop the live peer"
        );

        // The current session's close is still honored.
        handle_transport_event(
            &state,
            "peer-epoch".to_string(),
            epoch,
            TransportEvent::DataChannelClosed,
        )
        .await;
        assert!(
            !state.peers.contains_key("peer-epoch"),
            "a DataChannelClosed from the current session epoch drops the peer as before"
        );
    }

    #[tokio::test]
    async fn offline_flag_round_trips_and_reports_edges() {
        let state = build_test_state("offline-flag");
        assert!(!state.is_offline(), "a fresh state is online");
        // online → offline: swap returns the previous value (false).
        assert!(!state.set_offline(true));
        assert!(state.is_offline());
        // offline → offline: previous value is true (no edge).
        assert!(state.set_offline(true));
        // offline → online: previous value is true (the returning edge).
        assert!(state.set_offline(false));
        assert!(!state.is_offline());
    }

    #[tokio::test]
    async fn renegotiate_ice_is_a_noop_while_offline() {
        let state = build_test_state("offline-reneg");
        state.set_offline(true);
        // The offline guard sits ahead of every peer-map / session access,
        // so a renegotiation request while offline simply returns — no
        // gather attempt, no panic on a peer that isn't there.
        renegotiate_ice(&state, "ghost-peer", true, "test").await;
        assert!(
            state.peers.is_empty(),
            "renegotiate_ice must not touch state while offline"
        );
    }

    #[tokio::test]
    async fn reoffer_after_failed_answer_is_a_noop_while_offline() {
        let state = build_test_state("offline-reoffer");
        state.set_offline(true);
        // Same guard: a late/stale answer that can't apply must not kick a
        // rebuild while the interface is down.
        reoffer_after_failed_answer(&state, "ghost-peer").await;
        assert!(state.peers.is_empty());
    }

    #[tokio::test]
    async fn stale_peer_mid_ice_restart_is_not_cleared() {
        let state = build_test_state("restart-keep");
        // Inbound is pre-wake-stale (the condition that fires the zombie
        // clear), but an in-place ICE restart is in flight — the session is
        // recovering, not wedged. It must survive: dropping it here is what
        // guillotined the restart-before-drop path after a wake.
        insert_session_less_peer(&state, "peer-restarting", Some(stale_instant()));
        {
            let peer = state.peers.get("peer-restarting").expect("peer present");
            peer.state.write().tier = ConnectionTier::IceRestart {
                started: Instant::now(),
            };
        }
        clear_stale_session_if_zombie(&state, "peer-restarting").await;
        assert!(
            state.peers.contains_key("peer-restarting"),
            "a peer with an in-flight ICE restart must survive the stale-inbound zombie check"
        );
    }
}
