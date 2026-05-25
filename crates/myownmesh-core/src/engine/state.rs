//! Shared per-network state. Exposes the operations subsystems
//! (`Channel<T>`, `Rpc`, `MeshHandle`) call to interact with the
//! engine; all per-peer state mutation is funneled through the
//! command queue so the driver loop owns serial access.

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::trace;

use crate::channels::RawChannelFrame;
use crate::config::{NetworkConfig, TopologyMode};
use crate::error::{Error, Result};
use crate::events::{DiagEntry, DiagLevel, DropReason, MeshEvent, MeshPhase, PhaseEvent};
use crate::identity::Identity;
use crate::protocol::{rpc::RpcRequestMessage, CapabilityAdvert};
use crate::roster::Roster;
use crate::rpc::RpcInner;
use crate::topology::Topology;
use crate::transport::{LocalIceCandidate, Transport, TransportEvent};

use super::connection::PeerConnection;

/// Engine command queue entry. Anything that mutates per-peer
/// state, sends a frame, or reconfigures the network goes through
/// here so the driver loop handles it serially.
pub enum NetworkCmd {
    /// Stop the engine and tear down all peer sessions.
    Shutdown,
    /// Switch the topology selector at runtime.
    SetTopology(TopologyMode),
    /// Approve a peer into the roster (and emit the approve frame).
    ApproveRoster {
        device_id: String,
        label: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Remove a peer from the roster and drop any active session.
    RemoveRoster {
        device_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Drop a single peer, surfacing the given reason in the
    /// `Dropped` event.
    DropPeer {
        device_id: String,
        reason: DropReason,
    },
    /// Send a [`crate::protocol::MeshMessage::Channel`] frame to
    /// one peer.
    SendChannelFrame {
        peer: String,
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Broadcast a channel frame to every active peer.
    BroadcastChannelFrame {
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<usize>,
    },
    /// Send an RPC request frame to one peer.
    SendRpcRequest {
        peer: String,
        request: RpcRequestMessage,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Push a new capabilities advert to every active peer.
    BroadcastCapabilities {
        caps: CapabilityAdvert,
        reply: oneshot::Sender<usize>,
    },
    /// Per-peer transport event — pumped in from the per-peer
    /// transport task so the driver loop processes everything
    /// serially.
    TransportEvent {
        device_id: String,
        event: TransportEvent,
    },
}

/// Inbound signaling messages from the signaling task.
#[derive(Debug)]
pub enum SignalingInbound {
    PeerAnnounced {
        device_id: String,
    },
    Offer {
        device_id: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        candidate: LocalIceCandidate,
    },
    PeerLeft {
        device_id: String,
    },
}

/// Outbound signaling messages from the engine to the signaling task.
#[derive(Debug)]
pub enum SignalingOutbound {
    Announce,
    Offer {
        device_id: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        candidate: LocalIceCandidate,
    },
}

/// The shared state for a single joined network. Every long-lived
/// subsystem (driver loop, channels, rpc, handle) holds an
/// `Arc<NetworkState>`. Internally everything uses non-blocking
/// concurrent primitives (DashMap, RwLock, broadcast) so callers
/// don't serialize on a single lock.
pub struct NetworkState {
    pub network_id: String,
    pub identity: Arc<Identity>,
    pub transport: Transport,

    pub config: RwLock<NetworkConfig>,
    pub topology: RwLock<TopologyMode>,
    pub topology_impl: RwLock<Box<dyn Topology>>,

    pub peers: DashMap<String, Arc<PeerConnection>>,
    pub roster: RwLock<Roster>,
    pub current_phase: RwLock<MeshPhase>,

    pub events_tx: broadcast::Sender<MeshEvent>,
    pub channel_subscribers: DashMap<String, broadcast::Sender<RawChannelFrame>>,
    pub rpc: RwLock<Option<Arc<RpcInner>>>,

    pub signaling_tx: mpsc::UnboundedSender<SignalingOutbound>,
    pub signaling_inbound_tx: mpsc::UnboundedSender<SignalingInbound>,
    pub cmd_tx: mpsc::UnboundedSender<NetworkCmd>,

    /// Receiving end of `signaling_tx` — held here so callers can
    /// drain it via [`Self::take_signaling_outbound_rx`] when they
    /// bring up their signaling task.
    signaling_outbound_rx: Mutex<Option<mpsc::UnboundedReceiver<SignalingOutbound>>>,
}

impl NetworkState {
    /// Construct a new network state. Returns the state plus the
    /// inbound signaling receiver and the command-queue receiver
    /// the driver consumes.
    #[allow(clippy::type_complexity)]
    pub fn new(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
    ) -> Result<(
        Arc<Self>,
        mpsc::UnboundedReceiver<SignalingInbound>,
        mpsc::UnboundedReceiver<NetworkCmd>,
    )> {
        let topology_impl = crate::topology::from_mode(&config.topology);
        let roster = crate::roster::load(&config.network_id)?;
        let (events_tx, _) = broadcast::channel(256);
        let (signaling_tx, signaling_outbound_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (signaling_inbound_tx, signaling_inbound_rx) = mpsc::unbounded_channel();
        let state = Arc::new(Self {
            network_id: config.network_id.clone(),
            identity,
            transport,
            config: RwLock::new(config.clone()),
            topology: RwLock::new(config.topology.clone()),
            topology_impl: RwLock::new(topology_impl),
            peers: DashMap::new(),
            roster: RwLock::new(roster),
            current_phase: RwLock::new(MeshPhase::Joining),
            events_tx,
            channel_subscribers: DashMap::new(),
            rpc: RwLock::new(None),
            signaling_tx,
            signaling_inbound_tx,
            cmd_tx,
            signaling_outbound_rx: Mutex::new(Some(signaling_outbound_rx)),
        });
        Ok((state, signaling_inbound_rx, cmd_rx))
    }

    /// Take the outbound signaling receiver so the signaling task
    /// can drain it. Only one consumer is supported; subsequent
    /// calls return `None`.
    pub fn take_signaling_outbound_rx(
        self: &Arc<Self>,
    ) -> Option<mpsc::UnboundedReceiver<SignalingOutbound>> {
        self.signaling_outbound_rx.lock().take()
    }

    /// Emit a top-level mesh event. Silently drops if no
    /// subscribers — the broadcast channel returns an error on
    /// every send-with-zero-listeners, and we'd rather log nothing
    /// than spam on every emit.
    pub fn emit(&self, event: MeshEvent) {
        let _ = self.events_tx.send(event);
    }

    /// Emit a structured diagnostic — both to the tracing layer
    /// (visible in daemon stderr) and to the broadcast channel as
    /// a [`MeshEvent::Diag`] (consumed by the GUI's Activity tab).
    /// Prefer this over a bare `tracing::info!`/`warn!` for events
    /// the user should see in the UI; the helper writes to both
    /// surfaces so operators reading logs and users watching the
    /// GUI stay in sync.
    pub fn log_diag(&self, level: DiagLevel, category: &str, message: impl Into<String>) {
        self.log_diag_with(level, category, message, serde_json::Value::Null);
    }

    /// Variant of [`log_diag`] that carries a structured `detail`
    /// payload alongside the message. Use for events where the GUI
    /// might want to drill into fields (peer id, error code, etc.)
    /// rather than just render the human-readable line.
    pub fn log_diag_with(
        &self,
        level: DiagLevel,
        category: &str,
        message: impl Into<String>,
        detail: serde_json::Value,
    ) {
        let message = message.into();
        match level {
            DiagLevel::Debug => {
                tracing::debug!(network = %self.network_id, category = %category, "{message}")
            }
            DiagLevel::Info => {
                tracing::info!(network = %self.network_id, category = %category, "{message}")
            }
            DiagLevel::Warn => {
                tracing::warn!(network = %self.network_id, category = %category, "{message}")
            }
            DiagLevel::Error => {
                tracing::error!(network = %self.network_id, category = %category, "{message}")
            }
        }
        self.emit(MeshEvent::Diag(DiagEntry {
            ts: now_unix_ms(),
            network_id: self.network_id.clone(),
            level,
            category: category.to_string(),
            message,
            detail,
        }));
    }

    /// Update the per-network phase and emit on change.
    pub fn set_phase(&self, next: MeshPhase) {
        let mut current = self.current_phase.write();
        let prev = *current;
        if prev == next {
            return;
        }
        *current = next;
        drop(current);
        self.emit(MeshEvent::Phase(PhaseEvent::Changed {
            network_id: self.network_id.clone(),
            prev,
            next,
        }));
        self.log_diag(
            DiagLevel::Info,
            "phase",
            format!("phase: {prev:?} → {next:?}"),
        );
    }

    /// Subscribe to a named user channel. Returns a fresh
    /// broadcast::Receiver every call; the engine fan-outs each
    /// inbound channel frame to all subscribers.
    pub fn subscribe_channel(&self, name: &str) -> broadcast::Receiver<RawChannelFrame> {
        if let Some(tx) = self.channel_subscribers.get(name) {
            tx.subscribe()
        } else {
            let (tx, rx) = broadcast::channel(256);
            self.channel_subscribers.insert(name.to_string(), tx);
            rx
        }
    }

    /// Engine-side dispatch: route an inbound channel frame to
    /// the matching subscribers. Silently drops when no
    /// subscribers are registered for the named channel.
    pub fn dispatch_channel_frame(&self, name: &str, from: &str, payload: serde_json::Value) {
        if let Some(tx) = self.channel_subscribers.get(name) {
            let frame = RawChannelFrame {
                from: from.to_string(),
                payload,
            };
            let _ = tx.send(frame);
        } else {
            trace!(channel = name, "no subscriber for channel frame");
        }
    }

    /// Send a channel frame to one peer via the command queue.
    /// Used by [`crate::Channel::send_to`].
    pub async fn send_channel_frame(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendChannelFrame {
                peer: peer.to_string(),
                channel: channel.to_string(),
                payload,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))?
    }

    /// Broadcast a channel frame to every active peer. Returns
    /// the count of peers it was dispatched to.
    pub async fn broadcast_channel_frame(
        &self,
        channel: &str,
        payload: serde_json::Value,
    ) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCmd::BroadcastChannelFrame {
                channel: channel.to_string(),
                payload,
                reply,
            })
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Send an RPC request to one peer. Lower-level than the
    /// `Rpc` facade; `Rpc::call` builds the request, registers
    /// the pending entry, and then calls this.
    pub async fn send_rpc_request(&self, peer: &str, request: RpcRequestMessage) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendRpcRequest {
                peer: peer.to_string(),
                request,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))?
    }

    /// Broadcast a capabilities update to every active peer.
    pub async fn broadcast_capabilities(&self, caps: CapabilityAdvert) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCmd::BroadcastCapabilities { caps, reply })
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Persist `device_id` into the per-network roster. Does NOT
    /// transition any active session — call
    /// [`crate::engine::handshake::send_local_approve`] (or the
    /// higher-level [`crate::JoinedNetwork::roster_approve`])
    /// to actually emit the `approve` frame.
    pub async fn approve_roster(&self, device_id: &str, label: &str) -> Result<()> {
        let mut roster = self.roster.write();
        crate::roster::add_peer_in(&mut roster, device_id, label);
        crate::roster::save(&roster)?;
        Ok(())
    }

    /// Remove a peer from the roster and tear down any session.
    pub async fn remove_roster(&self, device_id: &str) -> Result<()> {
        let mut roster = self.roster.write();
        crate::roster::remove_peer_in(&mut roster, device_id);
        crate::roster::save(&roster)?;
        Ok(())
    }

    /// True if the peer is currently in the roster.
    pub fn is_rostered(&self, device_id: &str) -> bool {
        crate::roster::is_authorized(&self.roster.read(), device_id)
    }

    /// Total count of peers in any state.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Snapshot the current per-peer view as an owned list. The
    /// engine drops behind the lock during this call; callers
    /// should treat the snapshot as instantaneous and re-fetch
    /// for fresh data.
    pub fn peer_snapshot(&self) -> Vec<crate::handle::PeerInfo> {
        self.peers
            .iter()
            .map(|e| {
                let device_id = e.key().clone();
                let data = e.value().state.read();
                let pubkey = crate::signing::pubkey_part(&device_id);
                let device_suffix = crate::identity::display_suffix(pubkey.as_bytes());
                crate::handle::PeerInfo {
                    device_id: device_id.clone(),
                    status: data.status,
                    tier: data.tier,
                    rtt_ms: data.rtt_ms,
                    label: data.label.clone(),
                    capabilities: data.capabilities.clone(),
                    local_shelved: data.local_shelved,
                    remote_shelved: data.remote_shelved,
                    authenticated: data.authenticated,
                    device_suffix,
                    verification_code_received: data.verification_code_received.clone(),
                    verification_code_sent: data.verification_code_sent.clone(),
                    local_approve_sent: data.local_approve_sent,
                    remote_approve_seen: data.remote_approve_seen,
                    needs_turn: data.no_turn_diag_emitted,
                    local_candidates: data.diag.local_candidates.clone(),
                    remote_candidates: data.diag.remote_candidates.clone(),
                }
            })
            .collect()
    }

    /// Per-peer detail. Returns `None` if the peer is not in the
    /// engine's map.
    pub fn peer_info(&self, device_id: &str) -> Option<crate::handle::PeerInfo> {
        let peer = self.peers.get(device_id)?;
        let data = peer.state.read();
        let pubkey = crate::signing::pubkey_part(device_id);
        let device_suffix = crate::identity::display_suffix(pubkey.as_bytes());
        Some(crate::handle::PeerInfo {
            device_id: device_id.to_string(),
            status: data.status,
            tier: data.tier,
            rtt_ms: data.rtt_ms,
            label: data.label.clone(),
            capabilities: data.capabilities.clone(),
            local_shelved: data.local_shelved,
            remote_shelved: data.remote_shelved,
            authenticated: data.authenticated,
            device_suffix,
            verification_code_received: data.verification_code_received.clone(),
            verification_code_sent: data.verification_code_sent.clone(),
            local_approve_sent: data.local_approve_sent,
            remote_approve_seen: data.remote_approve_seen,
            needs_turn: data.no_turn_diag_emitted,
            local_candidates: data.diag.local_candidates.clone(),
            remote_candidates: data.diag.remote_candidates.clone(),
        })
    }

    /// Tear down every active peer session. Called from the
    /// driver's shutdown path.
    pub async fn shutdown(&self) {
        let sessions: Vec<_> = self
            .peers
            .iter()
            .filter_map(|e| e.value().session.lock().clone())
            .collect();
        for s in sessions {
            let _ = s.close().await;
        }
        self.peers.clear();
    }
}

/// Unix epoch milliseconds. Stamped on every [`DiagEntry`] so the
/// GUI's Activity log can render a per-entry HH:MM:SS clock — wall
/// time, not monotonic: the user cares what time it actually was
/// when something happened, not how long after process start.
pub(crate) fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
