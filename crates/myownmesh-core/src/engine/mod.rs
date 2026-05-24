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

pub mod connection;
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

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};
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
pub use state::{NetworkCmd, NetworkState, SignalingInbound, SignalingOutbound};

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
    info!(network = %state.network_id, "engine driver starting");

    // Top-level interval ticks. We hold them across the loop so
    // sleeping happens inside `tokio::select!` — no separate
    // task means a wake-event after a long-sleep tick gap is
    // observable here without coordination.
    let mut heartbeat =
        tokio::time::interval(Duration::from_millis(scheduler::HEARTBEAT_INTERVAL_MS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut offline_check = tokio::time::interval(Duration::from_millis(
        scheduler::OFFLINE_ROSTERED_CHECK_INTERVAL_MS,
    ));
    offline_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut reconnect_prune = tokio::time::interval(Duration::from_millis(
        scheduler::RECONNECT_PRUNE_INTERVAL_MS,
    ));
    reconnect_prune.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ice_poll =
        tokio::time::interval(Duration::from_millis(scheduler::ICE_POLL_INTERVAL_MS));
    ice_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut network_watch_tick =
        tokio::time::interval(Duration::from_millis(scheduler::NETWORK_WATCH_POLL_MS));
    network_watch_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut network_watch = network_watch::NetworkWatch::new().await;
    let mut wake_detector = wake::WakeDetector::new();

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

            _ = offline_check.tick() => {
                ladder::offline_check_tick(&state).await;
            }

            _ = reconnect_prune.tick() => {
                ladder::reconnect_prune_tick(&state).await;
            }

            _ = ice_poll.tick() => {
                ice_watchdog::poll_all(&state).await;
            }

            _ = network_watch_tick.tick() => {
                network_watch.poll(&state).await;
            }
        }
    }

    info!(network = %state.network_id, "engine driver stopping");
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
        NetworkCmd::TransportEvent { device_id, event } => {
            handle_transport_event(state, device_id, event).await;
        }
    }
    true
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
            ensure_peer_session(state, device_id, role).await;
        }
        SignalingInbound::Offer { device_id, sdp } => {
            // If we didn't already start an answerer, do so now.
            let role = Role::Answerer;
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
                        let _ = state.signaling_tx.send(SignalingOutbound::Answer {
                            device_id: device_id.clone(),
                            sdp: desc.sdp,
                        });
                    }
                    Err(e) => warn!(peer = %device_id, "create_answer failed: {e}"),
                }
            }
        }
        SignalingInbound::Answer { device_id, sdp } => {
            apply_remote_sdp(state, &device_id, RTCSdpType::Answer, sdp).await;
        }
        SignalingInbound::Candidate {
            device_id,
            candidate,
        } => {
            let session = {
                let peer = state.peers.get(&device_id);
                peer.and_then(|p| p.session.lock().clone())
            };
            if let Some(session) = session {
                if let Err(e) = session.add_ice_candidate(candidate).await {
                    warn!(peer = %device_id, "add_ice_candidate failed: {e}");
                }
            }
        }
        SignalingInbound::PeerLeft { device_id } => {
            drop_peer(state, &device_id, DropReason::UserLeft).await;
        }
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
            warn!(peer = %device_id, "open_peer failed: {e}");
            return;
        }
    };
    let session = Arc::new(session);
    let peer = Arc::new(PeerConnection::new(
        device_id.clone(),
        Some(session.clone()),
    ));
    state.peers.insert(device_id.clone(), peer.clone());

    state.emit(MeshEvent::Peer(PeerEvent::Sighted {
        network_id: state.network_id.clone(),
        device_id: device_id.clone(),
    }));

    // For offerer, kick off SDP exchange immediately.
    if role == Role::Offerer {
        match session.create_offer().await {
            Ok(desc) => {
                let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                    device_id: device_id.clone(),
                    sdp: desc.sdp,
                });
            }
            Err(e) => warn!(peer = %device_id, "create_offer failed: {e}"),
        }
    }

    // Per-peer transport-event pump. Forwards every event into
    // the main driver via the command queue so all per-peer state
    // mutation happens serially.
    let driver_tx = state.cmd_tx.clone();
    let peer_id_for_pump = device_id.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if driver_tx
                .send(NetworkCmd::TransportEvent {
                    device_id: peer_id_for_pump.clone(),
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
    let Some(session) = session else { return };
    let desc = match sdp_type {
        RTCSdpType::Offer => RTCSessionDescription::offer(sdp).ok(),
        RTCSdpType::Answer => RTCSessionDescription::answer(sdp).ok(),
        _ => None,
    };
    if let Some(desc) = desc {
        if let Err(e) = session.set_remote_description(desc).await {
            warn!(peer = %device_id, "set_remote_description failed: {e}");
        }
    }
}

async fn handle_transport_event(
    state: &Arc<NetworkState>,
    device_id: String,
    event: TransportEvent,
) {
    match event {
        TransportEvent::LocalIceCandidate(Some(cand)) => {
            let _ = state.signaling_tx.send(SignalingOutbound::Candidate {
                device_id: device_id.clone(),
                candidate: cand,
            });
            if let Some(peer) = state.peers.get(&device_id) {
                let kind = crate::transport::classify_candidate_sdp(
                    &state
                        .peers
                        .get(&device_id)
                        .and_then(|p| {
                            p.session
                                .lock()
                                .as_ref()
                                .map(|s| s.classify_inbound_candidate(""))
                        })
                        .map(|_| String::new())
                        .unwrap_or_default(),
                );
                drop(peer);
                // Stats are recorded inline in the engine so the
                // diag layer can report them later. The
                // classification is best-effort.
                let _ = kind;
            }
        }
        TransportEvent::LocalIceCandidate(None) => {
            // Gathering complete sentinel; signal the peer via a
            // null-candidate marker so they can finalize ICE
            // their side without waiting on a watchdog.
            // (Skipped on the wire today; many implementations
            // tolerate the gathering-complete signal being implicit.)
        }
        TransportEvent::IceConnectionStateChanged(ice_state) => {
            handle_ice_state_change(state, &device_id, ice_state).await;
        }
        TransportEvent::PeerConnectionStateChanged(pc_state) => {
            handle_pc_state_change(state, &device_id, pc_state).await;
        }
        TransportEvent::DataChannelOpen => {
            trace!(peer = %device_id, "data channel open");
            handshake::initiate(state, &device_id).await;
        }
        TransportEvent::DataChannelClosed => {
            drop_peer(state, &device_id, DropReason::IceFailed).await;
        }
        TransportEvent::Message(bytes) => {
            handle_inbound_frame(state, &device_id, bytes).await;
        }
    }
}

async fn handle_ice_state_change(
    state: &Arc<NetworkState>,
    device_id: &str,
    ice: RTCIceConnectionState,
) {
    // Resolve the state transition under the lock, return what the
    // caller should do, then drop the lock before any await.
    let escalate_failed = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        data.diag.ice_transitions += 1;
        match ice {
            RTCIceConnectionState::Connected | RTCIceConnectionState::Completed => {
                data.ice_disconnected_since = None;
                if matches!(
                    data.tier,
                    ConnectionTier::IceWatchdog { .. } | ConnectionTier::IceRestart { .. }
                ) {
                    data.tier = ConnectionTier::Steady;
                }
                false
            }
            RTCIceConnectionState::Disconnected => {
                if data.ice_disconnected_since.is_none() {
                    data.ice_disconnected_since = Some(Instant::now());
                    data.tier = ConnectionTier::IceWatchdog {
                        since: Instant::now(),
                    };
                }
                false
            }
            RTCIceConnectionState::Failed => true,
            _ => false,
        }
    };
    if escalate_failed {
        ice_watchdog::on_failed(state, device_id).await;
    }
}

async fn handle_pc_state_change(
    state: &Arc<NetworkState>,
    device_id: &str,
    pc: RTCPeerConnectionState,
) {
    match pc {
        RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
            drop_peer(state, device_id, DropReason::IceFailed).await;
        }
        _ => {}
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
            reason,
            grace_window_ms: scheduler::RECONNECTING_GRACE_MS,
        }));
    }
    phase::recompute(state);
    ladder::reevaluate_topology(state).await;
}
