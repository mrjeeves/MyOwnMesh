//! Daemon control protocol — line-delimited JSON over a local
//! interprocess socket (unix-domain socket on Unix, named pipe on
//! Windows). `myownmesh ctl …` clients and the GUI both talk to the
//! running daemon via this socket.
//!
//! Wire shape: one JSON object per line. Requests have `op` plus
//! op-specific fields; responses have `ok` (bool) plus
//! op-specific payload, or `error: string` on failure.
//!
//! Most ops are single-shot request → response. The exception is
//! [`Request::EventsSubscribe`], which converts the connection into a
//! one-way server-push stream: the daemon writes one JSON event per
//! line until the client disconnects. The GUI's Tauri backend uses
//! this to forward live mesh events into the frontend.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use interprocess::local_socket::{
    tokio::prelude::*, GenericFilePath, GenericNamespaced, ListenerOptions,
};
use myownmesh_core::{MeshConfig, MeshHandle, NetworkConfig, ServicesConfig, TopologyMode};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::registry::{NetworkRegistry, RemoveResult};
use crate::services::ServiceManager;

/// Default control socket name (Unix abstract or Windows named-pipe
/// segment). Overridable via `config.daemon.control_socket`.
#[allow(dead_code)]
pub fn default_socket_name() -> String {
    "myownmesh.sock".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    NetworksList,
    PeersList {
        network: String,
    },
    RosterList {
        network: String,
    },
    RosterApprove {
        network: String,
        device_id: String,
        label: Option<String>,
    },
    RosterRemove {
        network: String,
        device_id: String,
    },
    TopologySet {
        network: String,
        topology: String,
        hub: Option<String>,
    },
    IdentityShow,
    /// Update the device label. Persists to the on-disk identity
    /// anchor and updates the running daemon's in-memory copy so the
    /// next handshake advertises the new label immediately (no
    /// restart needed). Free-form string; empty clears it.
    IdentitySetLabel {
        label: String,
    },
    /// Generate a fresh random Network ID — base36, 8 chars by
    /// default. Stateless utility; the GUI's "Generate" button on
    /// the AddNetworkModal calls this so we don't replicate the
    /// alphabet / RNG choice in JS.
    NetworkIdGenerate,
    /// Canonicalise a user-typed Network ID. Trims, lowercases,
    /// and validates length / charset; returns the normalised
    /// form. Errors flow through the standard `Response::err`
    /// path so the GUI shows them inline.
    NetworkIdNormalize {
        input: String,
    },
    /// Return the full on-disk `MeshConfig`. Used by the GUI's
    /// import/export flow to surface saved networks (and read-only
    /// fields the registry summary doesn't carry — signaling
    /// relays, STUN/TURN servers, auto-approve).
    ConfigShow,
    /// Add a network: persist to config.json, join via the live
    /// `Mesh` handle, attach signaling, register. Returns the new
    /// network's summary. Fails if either the `id` or `network_id`
    /// already exists in the running daemon.
    NetworkAdd {
        config: NetworkConfig,
    },
    /// Remove a network: take it out of the registry, `leave()` the
    /// engine driver, drop the signaling handle, and persist the
    /// updated config.json. Idempotent — removing an unknown id is
    /// reported as success-with-warning.
    NetworkRemove {
        network: String,
        /// Also purge the network's persisted **governance state + roster** —
        /// a genuine *forget* (e.g. leaving a fleet), not just unloading the
        /// live network. Default `false` so a teardown keeps the signed state
        /// for a later rejoin; only a deliberate leave sets it. Leaving it on
        /// disk is exactly what makes a leave-then-rejoin reload a stale (and
        /// possibly forked) genesis.
        #[serde(default)]
        purge: bool,
    },
    /// Update an already-joined network's config in place. Hot-
    /// reloadable changes (topology / label / auto_approve / roster
    /// path) are applied without dropping any peer; transport-level
    /// changes (signaling relays / STUN / TURN / network_id) rebuild
    /// the network — the ICE config is baked into each
    /// `RTCPeerConnection` at creation, so a STUN/TURN edit only takes
    /// effect on fresh connections. Either way the new config is
    /// persisted to config.json. Fails if the network isn't currently
    /// joined (use `NetworkAdd` for that). This is the path the GUI's
    /// network-settings Save takes to push an edit (a new TURN URL, say)
    /// to a network the daemon already joined on a prior launch.
    NetworkUpdate {
        config: NetworkConfig,
    },
    /// Reconnect a joined network in place — the non-destructive twin of a
    /// `NetworkRemove` + `NetworkAdd`. Redials signaling and renegotiates ICE
    /// without leaving the room or announcing a `Leave`, so peers keep their
    /// sessions and app-level state. `peer` omitted reconnects every peer on
    /// the network; `peer` set reconnects just that one (a per-node refresh).
    /// This is what a GUI "refresh / reconnect" control should call instead of
    /// the destructive remove+re-add. No-op-with-error if the network isn't
    /// currently joined.
    NetworkReconnect {
        network: String,
        #[serde(default)]
        peer: Option<String>,
    },
    /// Deliberately dial exactly one signaling-discovered peer on a joined
    /// network, opening the WebRTC session on demand — the control-socket
    /// surface for [`myownmesh_core::JoinedNetwork::connect_peer`]. This is how
    /// a `Silent` network (which never auto-dials on presence) ever opens a
    /// connection: a daemon-client embedder (e.g. a remote-support node) that
    /// matched a peer's Support ID sends this to dial exactly that one peer.
    /// The local side dials as the offerer, so a Silent peer is reached by the
    /// offer and answers. No-op-with-error if the network isn't currently
    /// joined; `Ok` means the dial was queued, not that the peer connected —
    /// watch the event stream for the outcome.
    NetworkConnectPeer {
        network: String,
        peer: String,
        /// Record a standing dial: the engine redials this peer on
        /// every announce (even on a Silent network) and holds a
        /// never-expiring reconnect intent, persisted with the network
        /// config. The shape a support session needs to survive the
        /// far end sleeping or rebooting.
        #[serde(default)]
        pin: bool,
        /// When > 0, wait up to this long for the peer to reach
        /// ACTIVE and report the real outcome, instead of returning
        /// as soon as the dial is queued.
        #[serde(default)]
        wait_ms: u64,
    },
    /// Open the lowest free media lane (`kind`: "video" | "audio")
    /// toward a connected peer, returning `{ lane }`. Lanes also open
    /// transparently on first write; this is the explicit reservation.
    MediaLaneOpen {
        network: String,
        peer: String,
        kind: String,
    },
    /// Close a media lane toward a peer (idempotent). The track is
    /// removed and the next renegotiation drops its m-line send side —
    /// media capacity is paid only while a session uses it.
    MediaLaneClose {
        network: String,
        peer: String,
        kind: String,
        lane: u8,
    },
    /// Snapshot which infrastructure services this device hosts
    /// (relay / signaling / STUN / TURN): live runtime status plus the
    /// persisted config. The GUI's Services settings section reads this
    /// to render toggles and listen addresses.
    ServicesStatus,
    /// Replace the device's services config wholesale: persist it to
    /// config.json and reconcile the running services (start newly
    /// enabled ones, stop disabled ones, restart reconfigured ones).
    /// Returns the resulting status. The GUI sends the full edited
    /// `ServicesConfig`; the CLI reads the current one, flips a field,
    /// and sends it back.
    ServicesSet {
        services: ServicesConfig,
    },

    /// Subscribe to the live event stream. The connection becomes a
    /// one-way server-push channel after this op; the daemon writes
    /// one JSON-encoded `MeshEvent` (or framing wrapper) per line
    /// until the client closes. Used by the GUI to render live peer
    /// state changes without polling.
    EventsSubscribe,

    /// Subscribe to one network's connection-state transition trace.
    /// Like [`EventsSubscribe`](Request::EventsSubscribe) the
    /// connection becomes a one-way push stream after this op, but it
    /// carries only [`myownmesh_core::ConnTrace`] records — one compact
    /// JSON object per line — for `ctl trace`. Subscribing is what
    /// turns the engine's connection tracer on (it's a no-op while
    /// nobody watches), so this is the Phase-0 debugging entry point.
    TraceSubscribe {
        network: String,
    },

    // ---- closed-network governance --------------------------------
    /// Snapshot the per-network signed governance state — kind,
    /// roles, transition log, pending proposals, splits. The GUI
    /// polls this to render its Governance tab + per-network kind
    /// badge.
    GovernanceState {
        network: String,
    },
    /// Float a kind-change proposal (`open → closed` or
    /// `closed → open`). Engine signs with the local identity,
    /// broadcasts to peers, attempts immediate ratification if the
    /// quorum is already met. Returns the new proposal id.
    GovernanceProposeKindChange {
        network: String,
        /// Target kind. Must differ from the current one.
        to: myownmesh_core::NetworkKind,
        /// Per-device custody second factor, if this device enrolled one for
        /// the network (see the `GovernanceMfa*` ops). Omitted otherwise.
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Float a role-grant proposal.
    GovernanceProposeRoleGrant {
        network: String,
        target: String,
        role: myownmesh_core::Role,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Float a role-revoke proposal.
    GovernanceProposeRoleRevoke {
        network: String,
        target: String,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Float an evict proposal — remove a peer from the closed network's
    /// roster entirely (the propagating lost/stolen-device kick).
    GovernanceProposeEvict {
        network: String,
        target: String,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Float a topology-change proposal: the owner-signed, network-wide
    /// shape (mode, hub set, spoke redundancy) in one transition. Once
    /// ratified it outranks every device's local config topology and
    /// converges through the signed log exactly like roles do — this is
    /// how a node is made an infra hub for the whole network. Closed
    /// networks only; open/silent ones keep the per-device `TopologySet`.
    GovernanceProposeTopology {
        network: String,
        /// Same encoding `TopologySet` takes: `ring`, `star`, `hubs`,
        /// or `full_mesh`.
        topology: String,
        /// Hub spec for `star` (`<device_id>`) / `hubs`
        /// (`id1,id2[,…][:spoke_redundancy]`).
        #[serde(default)]
        hub: Option<String>,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Sign a pending proposal.
    GovernanceSign {
        network: String,
        proposal_id: String,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Deny a pending proposal. Single-shot kill switch.
    GovernanceDeny {
        network: String,
        proposal_id: String,
    },
    /// Withdraw a proposal the local device floated.
    GovernanceWithdraw {
        network: String,
        proposal_id: String,
    },
    /// Spawn a proposer-initiated split. Returns the derived
    /// network id of the new closed network.
    GovernanceSpawnSplit {
        network: String,
        proposal_id: String,
    },
    /// Enroll a per-device TOTP custody lock for `network` on this daemon.
    /// Returns the secret (base32 + `otpauth://` URI for a QR) and the
    /// one-time recovery codes — shown to the user exactly once. Fails if an
    /// enrollment already exists (disable it first).
    GovernanceMfaEnroll {
        network: String,
    },
    /// Whether this device holds a custody enrollment for `network`.
    GovernanceMfaStatus {
        network: String,
    },
    /// Remove the custody lock for `network` — requires a valid code, so the
    /// lock can't be lifted by someone who can't already satisfy it.
    GovernanceMfaDisable {
        network: String,
        code: String,
    },

    // ---- typed-channel + RPC IPC (post-EventsSubscribe) ----------
    //
    // The variants below require the client to have first sent
    // `EventsSubscribe` on the same connection — they install
    // per-client state (handler claims, channel subscriptions,
    // in-flight outbound stream forwarders) that the daemon
    // routes back as `ServerOut` event frames. Sending one on a
    // non-event-subscribed connection returns a `not subscribed`
    // error so the client gets immediate feedback rather than a
    // silent black hole.
    /// Claim a method name on a network. Subsequent peer RPC
    /// calls matching the method are forwarded to the client
    /// identified by `client_id` as `RpcInbound` events on its
    /// event socket. Last-claim-wins: a later register evicts
    /// the previous owner with a `HandlerDisplaced` event.
    /// `streaming = true` installs a streaming handler (chunks
    /// via `RpcStreamChunk` + `RpcStreamEnd`); `false` is
    /// single-shot (`RpcRespond`).
    RpcRegister {
        client_id: crate::ipc::ClientId,
        network: String,
        method: String,
        streaming: bool,
    },
    /// Release a method claim. No-op if not currently held by
    /// this client.
    RpcUnregister {
        client_id: crate::ipc::ClientId,
        network: String,
        method: String,
    },
    /// Resolve an in-flight inbound RPC (single-shot). Matches
    /// by `request_id` regardless of which client originally
    /// received the `RpcInbound`. Either `ok` or `error` should
    /// be set; if both, `error` wins.
    RpcRespond {
        request_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ok: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Push one chunk to an in-flight streaming inbound RPC.
    RpcStreamChunk {
        request_id: String,
        payload: serde_json::Value,
    },
    /// Close an in-flight streaming inbound RPC. After this the
    /// request id is no longer routable; further chunks are
    /// silently dropped. Optional `error` propagates to the
    /// peer as the stream-end's failure reason.
    RpcStreamEnd {
        request_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Make an outbound single-shot RPC. Blocks the daemon's
    /// command socket response on the peer's reply — same shape
    /// as `Rpc::call`.
    RpcCall {
        network: String,
        peer: String,
        method: String,
        payload: serde_json::Value,
    },
    /// Make an outbound streaming RPC. Returns immediately with
    /// the engine-assigned `request_id`; subsequent
    /// `RpcCallStreamChunk` / `RpcCallStreamEnd` events deliver
    /// the chunks on the client's event socket. The `client_id`
    /// identifies which event socket receives the chunks.
    RpcCallStream {
        client_id: crate::ipc::ClientId,
        network: String,
        peer: String,
        method: String,
        payload: serde_json::Value,
    },
    /// Subscribe to a typed channel by name. Inbound channel
    /// frames are forwarded as `ChannelInbound` events on the
    /// `client_id`'s event socket. Multiple clients can
    /// subscribe to the same channel; each gets a copy of every
    /// frame.
    ChannelSubscribe {
        client_id: crate::ipc::ClientId,
        network: String,
        channel: String,
    },
    /// Release a channel subscription. No-op if not currently
    /// subscribed.
    ChannelUnsubscribe {
        client_id: crate::ipc::ClientId,
        network: String,
        channel: String,
    },
    /// Send one frame on a typed channel to a specific peer.
    /// Doesn't require a subscription — sends and subscriptions
    /// are independent.
    ChannelSendTo {
        network: String,
        channel: String,
        peer: String,
        payload: serde_json::Value,
    },
    /// Send a frame on a typed channel under the acknowledged-delivery
    /// contract: queued until the peer's link is up, retransmitted
    /// across session rebuilds, resolved when the peer's engine has
    /// delivered it (or with an error at TTL / terminal failure). The
    /// primitive that replaces application-level retransmit loops.
    ChannelSendReliable {
        network: String,
        channel: String,
        peer: String,
        payload: serde_json::Value,
        /// Milliseconds before an undelivered frame expires (0 = the
        /// engine default).
        #[serde(default)]
        ttl_ms: u64,
    },
    /// Broadcast a frame on a typed channel to every active
    /// peer. Returns the number of peers the send was
    /// dispatched to.
    ChannelSendAll {
        network: String,
        channel: String,
        payload: serde_json::Value,
    },
    /// Replace the network's advertised capabilities. Triggers
    /// a `capabilities_update` broadcast to peers on the next
    /// engine tick.
    CapabilitiesSet {
        network: String,
        capabilities: myownmesh_core::protocol::CapabilityAdvert,
    },

    // ---- video track lane ---------------------------------------------
    /// Write one encoded H.264 access unit (Annex-B, base64) onto the
    /// video track lane to `peer`. The lane is provisioned on every
    /// connection at negotiation, so this works the moment the peer is
    /// up — no renegotiation, no subscription required. `duration_us`
    /// paces the RTP clock (1/fps).
    VideoSend {
        network: String,
        peer: String,
        /// Which of the peer's video lanes to write to (0–7, the lane pool).
        /// Defaults to lane 0, so a client from before the lane pool — which
        /// omits the field — still writes the single original lane.
        #[serde(default)]
        stream: u8,
        duration_us: u64,
        data: String,
    },
    /// Convert this connection into a dedicated **binary media-track pipe**:
    /// after the ack, the client streams length-prefixed binary frames
    /// (`[u32 len][body]`, see [`decode_media_frame`]) — H.264 access units and
    /// Opus frames with no base64 and no per-frame JSON. Nothing else rides
    /// this connection; MJPEG/PCM/route signalling stay on the JSON pipe.
    MediaTrackPipe,
    /// Convert this connection into a dedicated **binary media-source pipe**
    /// for `client_id` (its `EventsSubscribe` id): after the ack, the daemon
    /// pushes length-prefixed inbound media frames (`[u32 len][body]`, see
    /// [`encode_inbound_frame`]) for everything that client is subscribed to —
    /// no base64, no JSON. While registered, inbound media routes here instead
    /// of as base64 `video_inbound`/`audio_inbound` on the event socket.
    MediaSourcePipe {
        client_id: crate::ipc::ClientId,
    },
    /// Route assembled video access units arriving from this network's
    /// peers to this client's event socket as `video_inbound` frames.
    VideoSubscribe {
        client_id: crate::ipc::ClientId,
        network: String,
    },
    /// Release a video subscription. No-op if not subscribed.
    VideoUnsubscribe {
        client_id: crate::ipc::ClientId,
        network: String,
    },

    // ---- audio track lane ---------------------------------------------
    /// Write one encoded Opus frame (base64) onto the audio track lane
    /// to `peer`. Provisioned on every connection exactly like the video
    /// lane — works the moment the peer is up, no subscription required.
    /// `duration_us` is the frame length (20 000 for the canonical Opus
    /// frame); it paces the RTP clock.
    AudioSend {
        network: String,
        peer: String,
        /// Which of the peer's audio lanes to write to (0–7, the lane pool).
        /// Defaults to lane 0 for pre-pool clients, exactly like
        /// [`Request::VideoSend`].
        #[serde(default)]
        stream: u8,
        duration_us: u64,
        data: String,
    },
    /// Route audio frames arriving from this network's peers to this
    /// client's event socket as `audio_inbound` frames.
    AudioSubscribe {
        client_id: crate::ipc::ClientId,
        network: String,
    },
    /// Release an audio subscription. No-op if not subscribed.
    AudioUnsubscribe {
        client_id: crate::ipc::ClientId,
        network: String,
    },

    // ---- self-update -------------------------------------------------
    /// Snapshot the updater's state — current version, channel, policy,
    /// effective release feed, last check, any staged version.
    UpdateStatus,
    /// Force a release-feed check now (ignores the interval cooldown) and
    /// stage a permitted update. Applies on the next daemon start.
    UpdateCheck,
    /// Apply a staged update to disk now (takes effect on next start).
    UpdateApply,
    /// Apply a partial updater-preferences edit (enable, channel,
    /// auto_apply, interval, or a white-label release URL). Returns the
    /// resulting status. Carried as raw JSON deserialised into the
    /// updater's `UpdatePrefs` so the daemon doesn't re-derive the shape.
    UpdateSetPrefs {
        prefs: serde_json::Value,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

/// Resolve the platform-appropriate listener name. On Unix this
/// is `~/.myownmesh/daemon.sock`; on Windows it's a named-pipe
/// segment under the local namespace.
fn resolve_socket(custom: Option<PathBuf>) -> Result<SocketTarget> {
    if let Some(path) = custom {
        return Ok(SocketTarget::Path(path));
    }
    #[cfg(unix)]
    {
        let path = myownmesh_core::dirs::data_dir()
            .context("data_dir")?
            .join("daemon.sock");
        Ok(SocketTarget::Path(path))
    }
    #[cfg(not(unix))]
    {
        Ok(SocketTarget::Name(default_socket_name()))
    }
}

#[derive(Debug)]
enum SocketTarget {
    Path(PathBuf),
    #[allow(dead_code)]
    Name(String),
}

/// Start the control socket listener. Returns when the shutdown
/// broadcast fires.
pub async fn serve(
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    services: Arc<ServiceManager>,
    custom: Option<PathBuf>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let target = resolve_socket(custom)?;
    let listener = bind_listener(&target)?;
    info!(?target, "control socket listening");

    let state = Arc::new(ControlState {
        mesh,
        registry,
        services,
        clients: crate::ipc::ClientRegistry::new(),
    });

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                info!("control socket shutting down");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok(stream) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, state).await {
                                debug!("control client error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("accept failed: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

fn bind_listener(target: &SocketTarget) -> Result<LocalSocketListener> {
    use interprocess::local_socket::Name;
    let name: Name = match target {
        SocketTarget::Path(p) => {
            // Remove stale socket if present so re-binds succeed.
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(p);
            }
            p.as_path()
                .to_fs_name::<GenericFilePath>()
                .context("control socket path → fs_name")?
        }
        SocketTarget::Name(n) => n
            .clone()
            .to_ns_name::<GenericNamespaced>()
            .context("control socket name → ns_name")?,
    };
    ListenerOptions::new()
        .name(name)
        .create_tokio()
        .context("create_tokio")
}

struct ControlState {
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    services: Arc<ServiceManager>,
    clients: crate::ipc::ClientRegistry,
}

async fn handle_client(stream: LocalSocketStream, state: Arc<ControlState>) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("parse: {e}"));
                let line = serde_json::to_string(&resp)? + "\n";
                writer.write_all(line.as_bytes()).await?;
                continue;
            }
        };
        // EventsSubscribe converts the connection into a server-
        // push channel: the daemon writes mesh events plus any
        // IPC-routed frames (RpcInbound, ChannelInbound, ...)
        // until the client disconnects. Allocate a ClientId so
        // subsequent RPC/channel-management requests on OTHER
        // command sockets can target this connection.
        if matches!(request, Request::EventsSubscribe) {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let client = state.clients.register(tx);
            let client_id = client.id;
            // Ack carries the client_id so the caller knows what
            // to pass back on subsequent `client_id`-bearing ops.
            let ack = Response::ok(serde_json::json!({
                "subscribed": true,
                "client_id": client_id.to_string(),
            }));
            let line = serde_json::to_string(&ack)? + "\n";
            writer.write_all(line.as_bytes()).await?;
            let result = run_events_stream(&state, &mut writer, rx).await;
            // Clean up the client's claims regardless of how
            // the stream ended.
            state.clients.unregister(client_id);
            result?;
            break;
        }
        // TraceSubscribe is the same server-push pattern as
        // EventsSubscribe but carries only ConnTrace records and needs
        // no ClientId (it routes nothing back in). An unknown network
        // is reported as a plain error response and the connection
        // stays open for another request.
        if let Request::TraceSubscribe { network } = &request {
            let network = network.clone();
            match state.registry.get(&network) {
                Some(net) => {
                    let ack = Response::ok(serde_json::json!({
                        "subscribed": true,
                        "stream": "conn_trace",
                        "network": network,
                    }));
                    let line = serde_json::to_string(&ack)? + "\n";
                    writer.write_all(line.as_bytes()).await?;
                    let rx = net.state().subscribe_conn_trace();
                    let result = run_trace_stream(&mut writer, rx).await;
                    result?;
                    break;
                }
                None => {
                    let resp = Response::err(format!("unknown network: {network}"));
                    let line = serde_json::to_string(&resp)? + "\n";
                    writer.write_all(line.as_bytes()).await?;
                    continue;
                }
            }
        }
        // MediaTrackPipe converts the connection into a one-way binary stream
        // of media frames (H.264/Opus), exactly the EventsSubscribe pattern but
        // reading instead of writing. After the ack the connection speaks only
        // length-prefixed binary frames — no per-frame JSON or base64.
        if matches!(request, Request::MediaTrackPipe) {
            let ack = Response::ok(serde_json::json!({ "media_track_pipe": true }));
            let line = serde_json::to_string(&ack)? + "\n";
            writer.write_all(line.as_bytes()).await?;
            writer.flush().await?;
            // Recover the buffered reader (it may already hold the first frame).
            let reader = lines.into_inner();
            run_media_track_pipe(&state, reader).await?;
            break;
        }
        // MediaSourcePipe is the reverse: the daemon pushes inbound media frames
        // (binary) to this connection for the named client, instead of base64
        // events on its event socket. Register a sink on that client, then drain
        // it to the wire until either side closes.
        if let Request::MediaSourcePipe { client_id } = &request {
            let client_id = *client_id;
            let Some(client) = state.clients.client(client_id) else {
                let resp = Response::err(format!("unknown client_id: {client_id}"));
                writer
                    .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                    .await?;
                continue;
            };
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            client.set_media_sink(tx);
            let ack = Response::ok(serde_json::json!({ "media_source_pipe": true }));
            writer
                .write_all((serde_json::to_string(&ack)? + "\n").as_bytes())
                .await?;
            writer.flush().await?;
            let reader = lines.into_inner();
            let result = run_media_source_pipe(reader, &mut writer, rx).await;
            client.clear_media_sink();
            result?;
            break;
        }
        let resp = dispatch(&state, request).await;
        let line = serde_json::to_string(&resp)? + "\n";
        writer.write_all(line.as_bytes()).await?;
    }
    Ok(())
}

/// Read length-prefixed binary media frames off a [`Request::MediaTrackPipe`]
/// connection and route each to its peer's track lane — the binary, base64-free
/// twin of the [`Request::VideoSend`]/[`Request::AudioSend`] handlers. Sends
/// nothing back per frame: errors are logged here (rate-limited by the caller's
/// own cadence) rather than answered, which is the whole latency win. Returns
/// when the client disconnects.
async fn run_media_track_pipe<R>(state: &Arc<ControlState>, mut reader: R) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        let mut len_buf = [0u8; 4];
        // A clean EOF (client closed the pipe) ends the loop; a short read is
        // a torn frame and ends it too.
        if reader.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_MEDIA_FRAME_BYTES {
            warn!("media-track frame too large ({len} bytes) — dropping connection");
            return Ok(());
        }
        let mut body = vec![0u8; len];
        if reader.read_exact(&mut body).await.is_err() {
            return Ok(());
        }
        let Some(frame) = decode_media_frame(&body) else {
            warn!("malformed media-track frame ({len} bytes) — skipped");
            continue;
        };
        let Some(net) = state.registry.get(&frame.network) else {
            // The network went away between negotiation and this frame; the
            // viewer reads it as a brief gap and the next IDR recovers.
            continue;
        };
        let dur = std::time::Duration::from_micros(frame.duration_us);
        let result = match frame.kind {
            MEDIA_KIND_VIDEO => {
                net.state()
                    .send_video_sample(&frame.peer, frame.stream, frame.data.into(), dur)
                    .await
            }
            MEDIA_KIND_AUDIO => {
                net.state()
                    .send_audio_sample(&frame.peer, frame.stream, frame.data.into(), dur)
                    .await
            }
            other => {
                warn!("unknown media-track frame kind {other} — skipped");
                continue;
            }
        };
        if let Err(e) = result {
            debug!("media-track send failed: {e}");
        }
    }
}

/// Drain a client's binary media-source sink to its [`Request::MediaSourcePipe`]
/// connection: each `body` (an `encode_inbound_frame` payload) goes out as
/// `[u32 len][body]`. One-way (daemon → client); the only thing read back is
/// EOF, which — like a dropped sink — ends the loop so the caller clears the
/// client's sink and the pumps fall back to base64 events.
async fn run_media_source_pipe<R, W>(
    mut reader: R,
    writer: &mut W,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            biased;
            body = rx.recv() => {
                let Some(body) = body else { return Ok(()) };
                let len = (body.len() as u32).to_le_bytes();
                if writer.write_all(&len).await.is_err() {
                    return Ok(());
                }
                if writer.write_all(&body).await.is_err() {
                    return Ok(());
                }
                if writer.flush().await.is_err() {
                    return Ok(());
                }
            }
            // The client never writes after the handshake, so any completion of
            // this read — a stray byte or (normally) EOF — means it's gone.
            _ = reader.read_u8() => return Ok(()),
        }
    }
}

async fn dispatch(state: &Arc<ControlState>, req: Request) -> Response {
    match req {
        Request::Status => Response::ok(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "device_id": state.mesh.identity().display_id(),
            "joined_networks": state.mesh.joined_network_ids(),
            // How many independent video/audio lanes each peer connection
            // provisions. A client reads this to know how many simultaneous
            // streams to one peer it can send at full quality (the rest fall
            // back to MJPEG); absent means a pre-pool daemon — one lane.
            // The RESOLVED count (honoring MYOWNMESH_MEDIA_LANES), not the
            // compile-time ceiling: a device provisioning 1 lane must not
            // promise 8 — sends on the phantom lanes fail per-frame.
            "media_lanes": myownmesh_core::transport::resolved_media_lanes(),
            // Whether this daemon speaks the binary media pipes (media_track_pipe
            // / media_source_pipe). A capability flag, not a version gate: a
            // client uses the binary path only when this is true, else the base64
            // video_send/audio_send ops. Absent on daemons that predate it.
            "media_pipes": true,
        })),
        Request::IdentityShow => Response::ok(serde_json::json!({
            "device_id": state.mesh.identity().display_id(),
            "pubkey": state.mesh.identity().public_id(),
            "label": state.mesh.identity().label(),
        })),
        Request::IdentitySetLabel { label } => {
            // Persist first; if the disk write fails we want the
            // in-memory copy to still reflect the on-disk reality, so
            // we don't update the live `Identity` on error.
            if let Err(e) = myownmesh_core::identity::set_label(&label) {
                return Response::err(e.to_string());
            }
            state.mesh.identity().set_label(&label);
            Response::ok(serde_json::json!({
                "device_id": state.mesh.identity().display_id(),
                "pubkey": state.mesh.identity().public_id(),
                "label": state.mesh.identity().label(),
            }))
        }
        Request::NetworksList => {
            // Enriched payload: each network includes its phase,
            // topology, and labelling info. The CLI prints whatever
            // it gets; the GUI binds rich fields directly.
            let summaries = state.registry.summaries();
            Response::ok(serde_json::json!({ "networks": summaries }))
        }
        Request::PeersList { network } => match state.registry.get(&network) {
            Some(net) => Response::ok(serde_json::json!({ "peers": net.peers() })),
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterList { network } => match state.registry.get(&network) {
            Some(net) => match net.roster_list().await {
                Ok(list) => Response::ok(serde_json::json!({ "roster": list })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterApprove {
            network,
            device_id,
            label,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .roster_approve(&device_id, label.as_deref().unwrap_or(""))
                .await
            {
                Ok(_) => Response::ok(serde_json::json!({ "approved": device_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterRemove { network, device_id } => match state.registry.get(&network) {
            Some(net) => match net.roster_remove(&device_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "removed": device_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::TopologySet {
            network,
            topology,
            hub,
        } => {
            let mode = match parse_topology(&topology, hub.as_deref()) {
                Ok(m) => m,
                Err(msg) => return Response::err(msg),
            };
            match state.registry.get(&network) {
                Some(net) => {
                    // A ratified TopologyChange owns the shape network-wide;
                    // a local set would silently fork this device off it
                    // (the engine ignores the command as a backstop — the
                    // refusal belongs here where the caller can see it).
                    if let Ok(gov) = net.governance_state().await {
                        if gov.topology.is_some() {
                            return Response::err(
                                "this network's topology is governed by a signed \
                                 owner transition — propose a change instead \
                                 (`networks topology-propose` / GovernanceProposeTopology)"
                                    .to_string(),
                            );
                        }
                    }
                    match net.set_topology(mode).await {
                        Ok(_) => Response::ok(serde_json::json!({ "topology": topology })),
                        Err(e) => Response::err(e.to_string()),
                    }
                }
                None => Response::err(format!("unknown network: {network}")),
            }
        }
        Request::NetworkIdGenerate => Response::ok(serde_json::json!({
            "network_id": myownmesh_core::identity::generate_network_id(),
        })),
        Request::NetworkIdNormalize { input } => {
            match myownmesh_core::identity::normalize_network_id(&input) {
                Ok(n) => Response::ok(serde_json::json!({ "network_id": n })),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::ConfigShow => match MeshConfig::load() {
            Ok(cfg) => Response::ok(serde_json::json!({ "config": cfg })),
            Err(e) => Response::err(e.to_string()),
        },
        Request::NetworkAdd { config } => {
            info!(network = %config.network_id, config_id = %config.id, "control: network_add");
            network_add(state, config).await
        }
        Request::NetworkRemove { network, purge } => {
            info!(%network, purge, "control: network_remove");
            network_remove(state, &network, purge).await
        }
        Request::NetworkUpdate { config } => {
            info!(network = %config.network_id, config_id = %config.id, "control: network_update");
            network_update(state, config).await
        }
        Request::NetworkReconnect { network, peer } => {
            info!(%network, ?peer, "control: network_reconnect");
            network_reconnect(state, &network, peer)
        }
        Request::NetworkConnectPeer {
            network,
            peer,
            pin,
            wait_ms,
        } => {
            info!(%network, %peer, pin, wait_ms, "control: network_connect_peer");
            network_connect_peer(state, &network, &peer, pin, wait_ms).await
        }

        Request::MediaLaneOpen {
            network,
            peer,
            kind,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let Some(kind) = parse_lane_kind(&kind) else {
                return Response::err(format!(
                    "unknown lane kind '{kind}' — expected video | audio"
                ));
            };
            match net.open_media_lane(&peer, kind).await {
                Ok(lane) => Response::ok(serde_json::json!({ "lane": lane })),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::MediaLaneClose {
            network,
            peer,
            kind,
            lane,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let Some(kind) = parse_lane_kind(&kind) else {
                return Response::err(format!(
                    "unknown lane kind '{kind}' — expected video | audio"
                ));
            };
            match net.close_media_lane(&peer, kind, lane).await {
                Ok(()) => Response::ok(serde_json::json!({ "closed": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        // ---- self-update ----
        Request::UpdateStatus => match myownmesh_updater::status() {
            Ok(s) => Response::ok(serde_json::to_value(s).unwrap_or(serde_json::Value::Null)),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateCheck => match myownmesh_updater::check_now(true).await {
            Ok(o) => Response::ok(serde_json::to_value(o).unwrap_or(serde_json::Value::Null)),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateApply => match myownmesh_updater::apply_now() {
            Ok(applied) => Response::ok(serde_json::json!({ "applied": applied })),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateSetPrefs { prefs } => {
            match serde_json::from_value::<myownmesh_updater::UpdatePrefs>(prefs) {
                Ok(p) => match myownmesh_updater::set_prefs(p) {
                    Ok(s) => {
                        Response::ok(serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
                    }
                    Err(e) => Response::err(e.to_string()),
                },
                Err(e) => Response::err(format!("bad update prefs: {e}")),
            }
        }
        Request::ServicesStatus => {
            let status = state.services.status().await;
            let config = state.services.current_config().await;
            Response::ok(serde_json::json!({ "status": status, "config": config }))
        }
        Request::ServicesSet { services } => services_set(state, services).await,
        Request::EventsSubscribe => {
            // Handled by `handle_client` before reaching dispatch.
            // If we somehow get here, surface the bug.
            Response::err("events_subscribe must be handled upstream")
        }
        Request::TraceSubscribe { .. } => {
            // Handled by `handle_client` before reaching dispatch, like
            // events_subscribe.
            Response::err("trace_subscribe must be handled upstream")
        }

        // ---- governance ----
        Request::GovernanceState { network } => match state.registry.get(&network) {
            Some(net) => match net.governance_state().await {
                Ok(s) => Response::ok(serde_json::json!({ "state": s })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeKindChange {
            network,
            to,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::KindChange { to },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeRoleGrant {
            network,
            target,
            role,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::RoleGrant { target, role },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeRoleRevoke {
            network,
            target,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::RoleRevoke { target },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeEvict {
            network,
            target,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::Evict { target },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeTopology {
            network,
            topology,
            hub,
            mfa_code,
        } => {
            let mode = match parse_topology(&topology, hub.as_deref()) {
                Ok(m) => m,
                Err(msg) => return Response::err(msg),
            };
            match state.registry.get(&network) {
                Some(net) => match net
                    .propose_transition(
                        myownmesh_core::TransitionVariant::TopologyChange { to: mode },
                        mfa_code,
                    )
                    .await
                {
                    Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                    Err(e) => Response::err(e.to_string()),
                },
                None => Response::err(format!("unknown network: {network}")),
            }
        }
        Request::GovernanceSign {
            network,
            proposal_id,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net.sign_proposal(&proposal_id, mfa_code).await {
                Ok(_) => Response::ok(serde_json::json!({ "signed": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceDeny {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.deny_proposal(&proposal_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "denied": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceWithdraw {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.withdraw_proposal(&proposal_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "withdrawn": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceSpawnSplit {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.spawn_split(&proposal_id).await {
                Ok(new_id) => Response::ok(serde_json::json!({ "new_network_id": new_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        // ---- custody MFA (per-device, local to this daemon) ----------
        // These act on this daemon's secrets store keyed by network id; they
        // do not require the network to be live in the registry.
        Request::GovernanceMfaEnroll { network } => {
            match myownmesh_core::custody::enroll(&network, &network) {
                Ok(e) => Response::ok(serde_json::json!({
                    "secret": e.secret_b32,
                    "otpauth_uri": e.otpauth_uri,
                    "recovery_codes": e.recovery_codes,
                })),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::GovernanceMfaStatus { network } => Response::ok(serde_json::json!({
            "enrolled": myownmesh_core::custody::is_enrolled(&network),
        })),
        Request::GovernanceMfaDisable { network, code } => {
            match myownmesh_core::custody::disable(&network, &code) {
                Ok(()) => Response::ok(serde_json::json!({ "disabled": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        // ---- RPC handler claims --------------------------------------
        Request::RpcRegister {
            client_id,
            network,
            method,
            streaming,
        } => {
            if state.clients.client(client_id).is_none() {
                return Response::err(format!("unknown client_id: {client_id}"));
            }
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let mode = if streaming {
                crate::ipc::clients::HandlerMode::Stream
            } else {
                crate::ipc::clients::HandlerMode::Single
            };
            let key = (network.clone(), method.clone());
            let prev = state.clients.claim_method(key.clone(), client_id, mode);
            crate::ipc::bridge::install_handler_for_mode(
                &net,
                network.clone(),
                method.clone(),
                mode,
                state.clients.clone(),
            );
            if let Some(prev_owner) = prev {
                crate::ipc::bridge::notify_displaced(
                    &state.clients,
                    prev_owner,
                    client_id,
                    network,
                    method,
                );
            }
            Response::ok(serde_json::json!({ "registered": true }))
        }

        Request::RpcUnregister {
            client_id,
            network,
            method,
        } => {
            let key = (network, method);
            let released = state.clients.release_method(&key, client_id);
            Response::ok(serde_json::json!({ "released": released }))
        }

        // ---- inbound-RPC responses (from IPC handler back to daemon)
        Request::RpcRespond {
            request_id,
            ok,
            error,
        } => {
            let resolved = if let Some(err) = error {
                state.clients.reject_inbound_single(&request_id, err)
            } else {
                state
                    .clients
                    .resolve_inbound_single(&request_id, ok.unwrap_or(serde_json::Value::Null))
            };
            if resolved {
                Response::ok(serde_json::json!({ "resolved": true }))
            } else {
                Response::err(format!("no in-flight inbound RPC for '{request_id}'"))
            }
        }

        Request::RpcStreamChunk {
            request_id,
            payload,
        } => {
            let accepted = state
                .clients
                .push_inbound_stream_chunk(&request_id, payload)
                .await;
            if accepted {
                Response::ok(serde_json::json!({ "delivered": true }))
            } else {
                Response::err(format!("no in-flight inbound stream for '{request_id}'"))
            }
        }

        Request::RpcStreamEnd {
            request_id,
            error: _,
        } => {
            // Note: webrtc-rs's `Rpc::serve_stream` derives the
            // stream-end error from the inner future (Err →
            // `RpcStreamEnd { error }` on the wire). At this
            // layer dropping the sender is the only signal we
            // have — the engine emits `error: None`. Surfacing
            // an explicit error from the IPC client requires
            // sending it as the final chunk before close. A
            // follow-up extension can plumb the wire-level
            // error if needed; for now the close is silent.
            let closed = state.clients.close_inbound_stream(&request_id);
            Response::ok(serde_json::json!({ "closed": closed }))
        }

        // ---- outbound RPC --------------------------------------------
        Request::RpcCall {
            network,
            peer,
            method,
            payload,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            match net.rpc().call(&peer, &method, payload).await {
                Ok(resp) => Response::ok(serde_json::json!({ "response": resp.body })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::RpcCallStream {
            client_id,
            network,
            peer,
            method,
            payload,
        } => {
            let Some(client) = state.clients.client(client_id) else {
                return Response::err(format!("unknown client_id: {client_id}"));
            };
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            // The lib's `call_stream` allocates a request_id
            // internally but doesn't expose it; we mirror its
            // shape and tag chunks on the wire with a fresh
            // daemon-side id so the IPC client can correlate
            // its in-flight calls.
            let request_id = format!("ipc-stream-{}", state.clients.next_call_stream_id());
            let rx = match net.rpc().call_stream(&peer, &method, payload).await {
                Ok(rx) => rx,
                Err(e) => return Response::err(e.to_string()),
            };
            let writer_tx = client.writer_tx.clone();
            let req_id_for_task = request_id.clone();
            tokio::spawn(async move {
                let mut rx = rx;
                while let Some(chunk) = rx.recv().await {
                    match chunk {
                        Ok(payload) => {
                            let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamChunk {
                                request_id: req_id_for_task.clone(),
                                payload,
                            });
                        }
                        Err(err) => {
                            let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
                                request_id: req_id_for_task.clone(),
                                error: Some(err),
                            });
                            return;
                        }
                    }
                }
                let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
                    request_id: req_id_for_task,
                    error: None,
                });
            });
            Response::ok(serde_json::json!({ "request_id": request_id }))
        }

        // ---- typed channels ------------------------------------------
        Request::ChannelSubscribe {
            client_id,
            network,
            channel,
        } => {
            if state.clients.client(client_id).is_none() {
                return Response::err(format!("unknown client_id: {client_id}"));
            }
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let key = (network.clone(), channel.clone());
            let first = state.clients.subscribe_channel(key.clone(), client_id);
            if first {
                crate::ipc::bridge::spawn_channel_pump(
                    &net,
                    network,
                    channel,
                    state.clients.clone(),
                );
            }
            Response::ok(serde_json::json!({ "subscribed": true }))
        }

        Request::ChannelUnsubscribe {
            client_id,
            network,
            channel,
        } => {
            let key = (network, channel);
            state.clients.unsubscribe_channel(&key, client_id);
            // We don't actively tear the pump down — it exits
            // on its next iteration when it sees an empty
            // subscriber list. Keeps the unsubscribe synchronous
            // and free of cross-task signaling.
            Response::ok(serde_json::json!({ "unsubscribed": true }))
        }

        Request::ChannelSendTo {
            network,
            channel,
            peer,
            payload,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let chan = net.channel::<serde_json::Value>(&channel);
            match chan.send_to(&peer, &payload).await {
                Ok(()) => Response::ok(serde_json::json!({ "sent": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::ChannelSendReliable {
            network,
            channel,
            peer,
            payload,
            ttl_ms,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let ttl = if ttl_ms == 0 {
                None
            } else {
                Some(std::time::Duration::from_millis(ttl_ms))
            };
            match net.send_reliable(&peer, &channel, payload, ttl).await {
                Ok(()) => Response::ok(serde_json::json!({ "delivered": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::ChannelSendAll {
            network,
            channel,
            payload,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let chan = net.channel::<serde_json::Value>(&channel);
            match chan.broadcast(&payload).await {
                Ok(count) => Response::ok(serde_json::json!({ "dispatched_to": count })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::CapabilitiesSet {
            network,
            capabilities,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            net.advertise(capabilities);
            Response::ok(serde_json::json!({ "advertised": true }))
        }

        Request::VideoSend {
            network,
            peer,
            stream,
            duration_us,
            data,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let bytes = match data_encoding::BASE64.decode(data.as_bytes()) {
                Ok(b) => b,
                Err(e) => return Response::err(format!("data not base64: {e}")),
            };
            match net
                .state()
                .send_video_sample(
                    &peer,
                    stream,
                    bytes.into(),
                    std::time::Duration::from_micros(duration_us),
                )
                .await
            {
                Ok(()) => Response::ok(serde_json::json!({ "sent": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::VideoSubscribe { client_id, network } => {
            if state.clients.client(client_id).is_none() {
                return Response::err(format!("unknown client_id: {client_id}"));
            }
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let first = state.clients.subscribe_video(network.clone(), client_id);
            if first {
                crate::ipc::bridge::spawn_video_pump(&net, network, state.clients.clone());
            }
            Response::ok(serde_json::json!({ "subscribed": true }))
        }

        Request::VideoUnsubscribe { client_id, network } => {
            state.clients.unsubscribe_video(&network, client_id);
            // The pump exits on its next sample once it sees an empty
            // subscriber list — same passive teardown as channels.
            Response::ok(serde_json::json!({ "unsubscribed": true }))
        }

        Request::AudioSend {
            network,
            peer,
            stream,
            duration_us,
            data,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let bytes = match data_encoding::BASE64.decode(data.as_bytes()) {
                Ok(b) => b,
                Err(e) => return Response::err(format!("data not base64: {e}")),
            };
            match net
                .state()
                .send_audio_sample(
                    &peer,
                    stream,
                    bytes.into(),
                    std::time::Duration::from_micros(duration_us),
                )
                .await
            {
                Ok(()) => Response::ok(serde_json::json!({ "sent": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::AudioSubscribe { client_id, network } => {
            if state.clients.client(client_id).is_none() {
                return Response::err(format!("unknown client_id: {client_id}"));
            }
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let first = state.clients.subscribe_audio(network.clone(), client_id);
            if first {
                crate::ipc::bridge::spawn_audio_pump(&net, network, state.clients.clone());
            }
            Response::ok(serde_json::json!({ "subscribed": true }))
        }

        Request::AudioUnsubscribe { client_id, network } => {
            state.clients.unsubscribe_audio(&network, client_id);
            // Passive pump teardown, exactly like video.
            Response::ok(serde_json::json!({ "unsubscribed": true }))
        }

        // Handled in `handle_client` (they convert the whole connection); never
        // reach the per-request dispatcher.
        Request::MediaTrackPipe => Response::err("media_track_pipe must open its own connection"),
        Request::MediaSourcePipe { .. } => {
            Response::err("media_source_pipe must open its own connection")
        }
    }
}

/// Join a fresh network through the live mesh, attach signaling,
/// register the result, and persist the new config to disk. Each
/// step that mutates daemon-visible state is reversible up to the
/// last point we touch the on-disk config — config.json is updated
/// after the join + attach succeeds so a failed join leaves the
/// saved config untouched.
async fn network_add(state: &Arc<ControlState>, config: NetworkConfig) -> Response {
    // Reject duplicates against the running registry. We rely on
    // the registry's two-key indexing — checking both the local
    // config id and the wire-level network id covers the user
    // trying to add the same network twice (under any alias).
    if state.registry.contains(&config.id) {
        return Response::err(format!("config id '{}' already in use", config.id));
    }
    if state.registry.contains(&config.network_id) {
        return Response::err(format!(
            "network id '{}' already joined under a different config",
            config.network_id
        ));
    }

    // Join the live mesh first — if the engine refuses (bad
    // network id, etc.) we want to know before we touch disk.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => return Response::err(format!("join: {e}")),
    };

    // Take a summary BEFORE handing ownership to the registry so we
    // can return it in the response payload without re-locking.
    let summary = serde_json::json!({
        "config_id": joined.config_id(),
        "network_id": joined.network_id(),
        "label": joined.label(),
        "phase": joined.current_phase(),
        "topology": joined.current_topology(),
    });

    // Attach the signaling driver(s) the network's config selects
    // (Nostr and/or mDNS). A `None` here means the bridge declined
    // (outbound receiver already taken, e.g. by an in-process test
    // driver); the network still works for those.
    let drivers = {
        let net_state = joined.state();
        myownmesh_core::engine::attach_signaling(&net_state)
    };
    if drivers.is_none() {
        warn!(network = %config.network_id, "signaling attach returned no handle");
    }
    state.registry.insert(joined, drivers);

    // Start a relay forwarder for the new network if relay hosting is on,
    // and refresh the service-role advert so the new network advertises
    // what this device hosts.
    state.services.on_network_added(&config.id).await;

    // Persist to disk. We re-load the config rather than rely on
    // the in-memory copy from startup so concurrent edits (a user
    // hand-editing config.json) survive — we append to whatever's
    // on disk now. Best-effort: if save fails, the network is live
    // but won't re-join on next daemon restart. Surface the disk
    // error to the caller so the GUI can show it.
    if let Err(e) = persist_network_add(&config) {
        return Response::err(format!("network joined but config.json save failed: {e}"));
    }

    Response::ok(serde_json::json!({ "added": summary }))
}

/// Leave a live network and remove it from the on-disk config. The
/// remove call returns ownership of the `JoinedNetwork`; we run its
/// `leave()` to flush the engine driver cleanly. The signaling
/// driver dropped inside `registry.remove` tears down its own
/// tasks.
/// Drop a network's persisted **governance state + roster** — the on-disk half
/// of forgetting a network. Best-effort + logged: a leave that can't delete the
/// files isn't worth failing the request over, but leaving them is precisely
/// what made a rejoin reload a stale/forked genesis, so we try.
fn purge_network_state(network_id: &str) {
    if let Err(e) = myownmesh_core::network_state::delete(network_id) {
        warn!(%network_id, "purge: network_state delete failed: {e:#}");
    }
    if let Err(e) = myownmesh_core::roster::delete(network_id) {
        warn!(%network_id, "purge: roster delete failed: {e:#}");
    }
}

async fn network_remove(state: &Arc<ControlState>, key: &str, purge: bool) -> Response {
    let key_owned = key.to_string();
    // Tell peers we're leaving *before* the registry drops the signaling
    // driver — a self-announced `leave` so they tear our session down now
    // instead of waiting out the ~90 s heartbeat timeout. The reconnect
    // button is a leave-then-rejoin, and without this the rejoined device
    // strands peers holding a dead session whose ICE still reports
    // `Connected`. Scoped so the cloned handle is released before `remove`,
    // which would otherwise see it borrowed and report StillBorrowed.
    {
        if let Some(joined) = state.registry.get(key) {
            joined.announce_leave().await;
        }
    }
    match state.registry.remove(key) {
        RemoveResult::Removed(joined) => {
            let config_id = joined.config_id().to_string();
            let network_id = joined.network_id().to_string();
            state.services.on_network_removed(&config_id).await;
            if let Err(e) = joined.leave().await {
                warn!("leave({key_owned}) returned error: {e:#}");
            }
            if let Err(e) = persist_network_remove(&config_id, &network_id) {
                return Response::err(format!("network left but config.json save failed: {e}"));
            }
            if purge {
                purge_network_state(&network_id);
            }
            Response::ok(serde_json::json!({ "removed": config_id }))
        }
        RemoveResult::StillBorrowed => {
            // Engine driver will exit on command-channel drop; we
            // still need to update disk so a restart doesn't
            // re-join. We don't know the network_id since we
            // couldn't unwrap; persist by the key we were given
            // and let the persist helper handle either alias.
            state.services.on_network_removed(&key_owned).await;
            if let Err(e) = persist_network_remove(&key_owned, &key_owned) {
                return Response::err(format!("network removed but config.json save failed: {e}"));
            }
            if purge {
                // We couldn't unwrap the JoinedNetwork, so we only have the key
                // we were given; it doubles as the network id for the alias the
                // caller used (same basis `persist_network_remove` relies on).
                purge_network_state(&key_owned);
            }
            Response::ok(
                serde_json::json!({ "removed": key_owned, "warning": "engine teardown deferred — request was in flight" }),
            )
        }
        RemoveResult::NotFound => Response::err(format!("unknown network: {key_owned}")),
    }
}

/// Reconnect a joined network in place — the non-destructive twin of
/// [`network_remove`] + [`network_add`]. Hands the live `JoinedNetwork` a
/// reconnect request (redial signaling + renegotiate ICE) without leaving the
/// room, so peers keep their sessions and app-level state. `peer` omitted
/// reconnects every peer; `peer` set reconnects just that one (a per-node
/// refresh). Fire-and-forget — the engine driver runs the reconnect, so this
/// returns as soon as the request is queued.
fn network_reconnect(state: &Arc<ControlState>, key: &str, peer: Option<String>) -> Response {
    match state.registry.get(key) {
        Some(joined) => {
            joined.reconnect(peer);
            Response::ok(serde_json::json!({ "reconnecting": key }))
        }
        None => Response::err(format!("unknown network: {key}")),
    }
}

/// Deliberately dial one peer on a joined network — the control-socket wrapper
/// around [`myownmesh_core::JoinedNetwork::connect_peer`]. Single-shot: queues
/// the offerer-side dial on the engine and returns at once (the outcome rides
/// the event stream), so a daemon client on a `Silent` network can open exactly
/// one connection after matching a peer's Support ID.
async fn network_connect_peer(
    state: &Arc<ControlState>,
    key: &str,
    peer: &str,
    pin: bool,
    wait_ms: u64,
) -> Response {
    let Some(joined) = state.registry.get(key) else {
        return Response::err(format!("unknown network: {key}"));
    };
    let result = if pin || wait_ms > 0 {
        // Waited/pinned dial: resolves on ACTIVE (or the deadline). A
        // pin with no wait still uses the waiting path with a minimal
        // deadline so the sticky flag is recorded engine-side; the
        // dial itself keeps going either way.
        let deadline = std::time::Duration::from_millis(wait_ms.max(1));
        match joined.connect_peer_wait(peer, pin, deadline).await {
            Ok(()) => Ok(true),
            Err(e) if wait_ms == 0 => {
                // Caller didn't ask to wait — a deadline miss is not
                // an error, just "still connecting".
                let msg = e.to_string();
                if msg.contains("still pending") {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    } else {
        joined.connect_peer(peer).await.map(|_| false)
    };
    match result {
        Ok(active) => Response::ok(serde_json::json!({
            "connecting": peer,
            "network": key,
            "pinned": pin,
            "active": active,
        })),
        Err(e) => Response::err(e.to_string()),
    }
}

/// Update an already-joined network in place. Hot-reloadable edits
/// (topology / label / auto_approve / roster path) apply without
/// touching live sessions; transport edits (signaling / STUN / TURN /
/// network_id) tear the network down and rejoin under the new config,
/// because the ICE server set is baked into each `RTCPeerConnection`
/// when it's created — there's no way to retrofit a new TURN server
/// onto an existing connection. Either way config.json is rewritten so
/// the change survives a daemon restart.
async fn network_update(state: &Arc<ControlState>, config: NetworkConfig) -> Response {
    // This is update, not add: the network must already be joined.
    let joined = match state
        .registry
        .get(&config.id)
        .or_else(|| state.registry.get(&config.network_id))
    {
        Some(j) => j,
        None => {
            return Response::err(format!(
                "unknown network '{}' — join it with network_add first",
                config.id
            ))
        }
    };

    // Compare the incoming config against the engine's live config to
    // decide hot-apply vs. transport restart.
    let net_state = joined.state();
    let (needs_restart, signaling_changed, network_id_changed) = {
        let current = net_state.config.read().clone();
        (
            myownmesh_core::engine::reconcile::requires_restart(&current, &config),
            current.signaling != config.signaling,
            current.network_id != config.network_id,
        )
    };
    // Name the path taken so a config-driven flap is greppable: a hot-apply
    // keeps every live peer; a restart drops them. Only network_id/signaling
    // force the restart now (STUN/TURN are hot — see `reconcile`).
    info!(
        network = %config.network_id,
        needs_restart,
        signaling_changed,
        network_id_changed,
        "network_update: {}",
        if needs_restart { "transport restart (drops live peers)" } else { "hot-applied in place" }
    );

    if !needs_restart {
        // STUN/TURN / topology / label / auto_approve / roster — apply in
        // place, no peers dropped. ICE servers are read fresh on the next
        // connect, so a credential rotation reaches new connections without
        // tearing down the live ones (see `reconcile::apply_hot`).
        if let Err(e) = myownmesh_core::engine::reconcile::apply_hot(&net_state, config.clone()) {
            return Response::err(format!("apply config: {e}"));
        }
        drop(net_state);
        drop(joined);
        if let Err(e) = persist_network_update(&config) {
            return Response::err(format!("config applied but config.json save failed: {e}"));
        }
        return Response::ok(serde_json::json!({ "updated": config.id, "restarted": false }));
    }

    // Transport restart path. Snapshot the live config FIRST so that if
    // the rejoin under the new config is rejected (a bad TURN URL the
    // daemon won't parse, say) we can restore the network exactly as it
    // was rather than leaving the user with nothing — the roster file
    // survives on disk regardless, but a vanished network with no
    // recovery surface is a footgun. Then release our Arc clones so the
    // registry can reclaim ownership and `leave()` the old driver
    // cleanly rather than reporting StillBorrowed.
    let old_config = net_state.config.read().clone();
    // Same graceful-departure courtesy as network_remove: peers drop our
    // session now rather than waiting out the heartbeat timeout, so the
    // rebuild under the new transport reconnects promptly instead of
    // racing the stale-session recovery path. Emitted while the signaling
    // driver is still live (before the registry remove below drops it).
    joined.announce_leave().await;
    drop(net_state);
    drop(joined);

    match state.registry.remove(&config.id) {
        RemoveResult::Removed(old) => {
            if let Err(e) = old.leave().await {
                warn!("leave during network update returned error: {e:#}");
            }
        }
        RemoveResult::StillBorrowed => {
            warn!(
                network = %config.id,
                "network update: old engine teardown deferred (request in flight)"
            );
        }
        RemoveResult::NotFound => {
            // Raced with a concurrent remove between our get() and
            // here; fall through and re-join fresh from the new config.
        }
    }

    // Re-join under the new transport config. If the daemon rejects it,
    // roll back to the snapshot so the network (and its live session) is
    // restored instead of silently disappearing.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => {
            let rollback = match state.mesh.join(old_config).await {
                Ok(restored) => {
                    let drivers = {
                        let net_state = restored.state();
                        myownmesh_core::engine::attach_signaling(&net_state)
                    };
                    state.registry.insert(restored, drivers);
                    state.services.on_network_added(&config.id).await;
                    " — restored the previous config"
                }
                Err(re) => {
                    warn!(network = %config.id, "network update rollback failed: {re:#}");
                    " — AND rollback failed; re-add it from the Networks tab"
                }
            };
            return Response::err(format!("rejoin with new config: {e}{rollback}"));
        }
    };
    let summary = serde_json::json!({
        "config_id": joined.config_id(),
        "network_id": joined.network_id(),
        "label": joined.label(),
        "phase": joined.current_phase(),
        "topology": joined.current_topology(),
    });
    let drivers = {
        let net_state = joined.state();
        myownmesh_core::engine::attach_signaling(&net_state)
    };
    if drivers.is_none() {
        warn!(network = %config.network_id, "signaling attach returned no handle after update");
    }
    state.registry.insert(joined, drivers);

    // The old network (and its relay forwarder) was torn down; rebind a
    // fresh relay to the new network state if relay hosting is on.
    state.services.on_network_removed(&config.id).await;
    state.services.on_network_added(&config.id).await;

    if let Err(e) = persist_network_update(&config) {
        return Response::err(format!("network updated but config.json save failed: {e}"));
    }
    Response::ok(serde_json::json!({ "updated": summary, "restarted": true }))
}

/// Replace the device services config: persist it, then reconcile the
/// running services. Persist first so a daemon restart re-applies the
/// same config even if the live reconcile partly fails (a failed service
/// start is logged inside `apply`, not surfaced as an error here).
async fn services_set(state: &Arc<ControlState>, services: ServicesConfig) -> Response {
    if let Err(e) = persist_services(&services) {
        return Response::err(format!("services config save failed: {e}"));
    }
    let status = state.services.apply(services).await;
    Response::ok(serde_json::json!({ "status": status }))
}

fn persist_services(services: &ServicesConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    cfg.services = services.clone();
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_add(net: &NetworkConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    // Append only if not already present — covers the case where
    // the user edited config.json by hand between daemon start and
    // this add, and added the same network there too.
    if !cfg
        .networks
        .iter()
        .any(|n| n.id == net.id || n.network_id == net.network_id)
    {
        cfg.networks.push(net.clone());
    }
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_remove(config_id: &str, network_id: &str) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    let before = cfg.networks.len();
    cfg.networks
        .retain(|n| n.id != config_id && n.network_id != network_id);
    if cfg.networks.len() != before {
        cfg.save().map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn persist_network_update(net: &NetworkConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    // Replace the matching record in place (by either alias). If it's
    // somehow absent — e.g. the user hand-deleted it between join and
    // this update — append so the on-disk config still agrees with the
    // now-running engine rather than silently dropping it.
    if let Some(slot) = cfg
        .networks
        .iter_mut()
        .find(|n| n.id == net.id || n.network_id == net.network_id)
    {
        *slot = net.clone();
    } else {
        cfg.networks.push(net.clone());
    }
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Map the wire's lane-kind string onto the transport enum.
fn parse_lane_kind(kind: &str) -> Option<myownmesh_core::transport::webrtc::LaneKind> {
    use myownmesh_core::transport::webrtc::LaneKind;
    match kind {
        "video" => Some(LaneKind::Video),
        "audio" => Some(LaneKind::Audio),
        _ => None,
    }
}

fn parse_topology(name: &str, hub: Option<&str>) -> std::result::Result<TopologyMode, String> {
    match name {
        "ring" => Ok(TopologyMode::Ring { n_preferred: None }),
        "star" => {
            let hub = hub.ok_or_else(|| "star topology requires --hub <device_id>".to_string())?;
            Ok(TopologyMode::Star {
                hub: hub.to_string(),
            })
        }
        "full_mesh" | "fullmesh" => Ok(TopologyMode::FullMesh),
        "hubs" => {
            let list = hub.ok_or_else(|| {
                "hubs topology requires --hub <id[,id…][:redundancy]>".to_string()
            })?;
            let (ids, redundancy) = match list.rsplit_once(':') {
                Some((ids, r)) => (
                    ids,
                    Some(r.parse::<u32>().map_err(|_| {
                        format!("invalid spoke redundancy '{r}' — expected a number")
                    })?),
                ),
                None => (list, None),
            };
            let hubs: Vec<String> = ids
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if hubs.is_empty() {
                return Err("hubs topology requires at least one hub id".into());
            }
            Ok(TopologyMode::Hubs {
                hubs,
                spoke_redundancy: redundancy,
            })
        }
        other => Err(format!(
            "unknown topology '{other}' — expected ring | star | hubs | full_mesh"
        )),
    }
}

/// Stream events to one connected subscriber. Drains two
/// sources concurrently:
///
/// 1. The mesh-wide [`MeshHandle::events`] broadcast — peer /
///    phase / diag entries the engine emits.
/// 2. The per-client mpsc — `ServerOut` frames the IPC bridge
///    (RPC inbound, channel inbound, handler-displaced
///    notifications) pushes for this specific client.
///
/// Returns when the writer breaks (client gone) or both source
/// streams close. Source 1 closes only on daemon shutdown;
/// source 2 closes when the client's `unregister` drops the
/// last sender, which the caller invokes after this function
/// returns.
async fn run_events_stream<W>(
    state: &Arc<ControlState>,
    writer: &mut W,
    mut client_rx: tokio::sync::mpsc::UnboundedReceiver<crate::ipc::ServerOut>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut mesh_rx = state.mesh.events();
    loop {
        tokio::select! {
            biased;
            // Per-client frames first — drains IPC-routed
            // RpcInbound / ChannelInbound / etc.
            maybe_frame = client_rx.recv() => {
                let Some(frame) = maybe_frame else {
                    // Sender dropped — only happens after the
                    // outer handle_client called `unregister`,
                    // which only fires after this returns. In
                    // practice this branch never fires while
                    // the connection is live; treat as benign
                    // shutdown.
                    return Ok(());
                };
                let line = serde_json::to_string(&frame)? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
                if writer.flush().await.is_err() {
                    return Ok(());
                }
            }
            recv = mesh_rx.recv() => match recv {
                Ok(event) => {
                    let frame = crate::ipc::ServerOut::Event { event };
                    let line = serde_json::to_string(&frame)? + "\n";
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        return Ok(());
                    }
                    if writer.flush().await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let frame = crate::ipc::ServerOut::Lagged { skipped: n };
                    let line = serde_json::to_string(&frame)? + "\n";
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
        }
    }
}

/// Stream one network's connection-state transitions to a connected
/// `ctl trace` client. Writes each [`myownmesh_core::ConnTrace`] as a
/// compact JSON object on its own line (clean JSONL for
/// `scripts/merge-traces.py` and `jq`). On broadcast lag — a
/// transition storm outran a slow reader — emits a `{"lagged":N}`
/// marker rather than silently skipping, so a gap in the timeline is
/// always explicit. Returns when the client disconnects or the network
/// shuts down.
async fn run_trace_stream<W>(
    writer: &mut W,
    mut rx: broadcast::Receiver<myownmesh_core::ConnTrace>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        match rx.recv().await {
            Ok(trace) => {
                let line = serde_json::to_string(&trace)? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
                if writer.flush().await.is_err() {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let line = serde_json::to_string(&serde_json::json!({ "lagged": n }))? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

/// Single shared `MeshHandle` storage for the ctl client. Mostly a
/// future-proofing hook so a follow-up can attach per-network
/// state without changing the protocol.
#[allow(dead_code)]
static CTL_STATE: Mutex<Option<Arc<ControlState>>> = parking_lot::const_mutex(None);

// ---- binary media-track pipe frame codec -----------------------------------
//
// Mirror of `allmystuff-protocol`'s codec (keep byte-for-byte identical): the
// frames a [`Request::MediaTrackPipe`] connection carries. Each frame on the
// wire is `[u32 len LE][body]`; `body` is what these encode/parse. Round-trip
// tested below.

/// `kind` byte for an H.264 access unit.
pub const MEDIA_KIND_VIDEO: u8 = 0;
/// `kind` byte for an Opus frame.
pub const MEDIA_KIND_AUDIO: u8 = 1;
/// Defensive cap on one frame body — a corrupt length never allocates more.
pub const MAX_MEDIA_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// One decoded media-track frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFrame {
    pub kind: u8,
    pub stream: u8,
    pub duration_us: u64,
    pub network: String,
    pub peer: String,
    pub data: Vec<u8>,
}

/// Parse a media frame body (the bytes after the `u32` length prefix). Returns
/// `None` on any truncation or non-UTF-8 id — a malformed frame is dropped,
/// never panics.
pub fn decode_media_frame(body: &[u8]) -> Option<MediaFrame> {
    fn rd<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Option<&'a [u8]> {
        let end = p.checked_add(n)?;
        let s = b.get(*p..end)?;
        *p = end;
        Some(s)
    }
    let mut p = 0;
    let kind = rd(body, &mut p, 1)?[0];
    let stream = rd(body, &mut p, 1)?[0];
    let duration_us = u64::from_le_bytes(rd(body, &mut p, 8)?.try_into().ok()?);
    let net_len = u16::from_le_bytes(rd(body, &mut p, 2)?.try_into().ok()?) as usize;
    let network = std::str::from_utf8(rd(body, &mut p, net_len)?)
        .ok()?
        .to_string();
    let peer_len = u16::from_le_bytes(rd(body, &mut p, 2)?.try_into().ok()?) as usize;
    let peer = std::str::from_utf8(rd(body, &mut p, peer_len)?)
        .ok()?
        .to_string();
    let data = body.get(p..)?.to_vec();
    Some(MediaFrame {
        kind,
        stream,
        duration_us,
        network,
        peer,
        data,
    })
}

/// Serialize an inbound frame body (no length prefix). The daemon only encodes
/// (it pushes inbound frames); the client decodes via `allmystuff-protocol`'s
/// `decode_inbound_frame`, kept byte-for-byte identical. Layout:
/// `kind u8 · key u8 · stream u8 · rtp_timestamp u32 · from_len u16 · from ·
/// data…`, integers little-endian.
pub fn encode_inbound_frame(
    kind: u8,
    key: bool,
    stream: u8,
    rtp_timestamp: u32,
    from: &str,
    data: &[u8],
) -> Vec<u8> {
    let from = from.as_bytes();
    let mut out = Vec::with_capacity(9 + from.len() + data.len());
    out.push(kind);
    out.push(key as u8);
    out.push(stream);
    out.extend_from_slice(&rtp_timestamp.to_le_bytes());
    out.extend_from_slice(&(from.len() as u16).to_le_bytes());
    out.extend_from_slice(from);
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod media_frame_tests {
    use super::*;

    /// Local copy of the encoder (the daemon only needs to decode) so the
    /// round-trip can be asserted against the exact layout the client writes.
    fn encode_media_frame(
        kind: u8,
        stream: u8,
        duration_us: u64,
        network: &str,
        peer: &str,
        data: &[u8],
    ) -> Vec<u8> {
        let net = network.as_bytes();
        let peer = peer.as_bytes();
        let mut out = Vec::with_capacity(14 + net.len() + peer.len() + data.len());
        out.push(kind);
        out.push(stream);
        out.extend_from_slice(&duration_us.to_le_bytes());
        out.extend_from_slice(&(net.len() as u16).to_le_bytes());
        out.extend_from_slice(net);
        out.extend_from_slice(&(peer.len() as u16).to_le_bytes());
        out.extend_from_slice(peer);
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn round_trips_video_and_audio() {
        let v = encode_media_frame(
            MEDIA_KIND_VIDEO,
            3,
            33_333,
            "home",
            "peerpub",
            &[1, 2, 3, 9],
        );
        let f = decode_media_frame(&v).expect("decode");
        assert_eq!(f.kind, MEDIA_KIND_VIDEO);
        assert_eq!(f.stream, 3);
        assert_eq!(f.duration_us, 33_333);
        assert_eq!(f.network, "home");
        assert_eq!(f.peer, "peerpub");
        assert_eq!(f.data, vec![1, 2, 3, 9]);

        let a = encode_media_frame(MEDIA_KIND_AUDIO, 0, 20_000, "n", "p", &[]);
        let f = decode_media_frame(&a).expect("decode");
        assert_eq!(f.kind, MEDIA_KIND_AUDIO);
        assert!(f.data.is_empty());
    }

    #[test]
    fn truncation_is_none_not_panic() {
        let body = encode_media_frame(MEDIA_KIND_VIDEO, 1, 1, "home", "peer", &[7, 7, 7]);
        for cut in 0..14 + "home".len() + "peer".len() {
            assert!(decode_media_frame(&body[..cut]).is_none(), "short {cut}");
        }
    }

    /// The `network_connect_peer` op is what a daemon-client embedder sends to
    /// dial one peer on a Silent network. Pin its wire tag + shape: it must
    /// decode from the exact JSON a client writes, and round-trip.
    #[test]
    fn network_connect_peer_request_round_trips() {
        let json = r#"{"op":"network_connect_peer","network":"cec-support","peer":"peerpubkey"}"#;
        let req: Request = serde_json::from_str(json).expect("decode network_connect_peer");
        match &req {
            Request::NetworkConnectPeer {
                network,
                peer,
                pin,
                wait_ms,
            } => {
                assert_eq!(network, "cec-support");
                assert_eq!(peer, "peerpubkey");
                // Wire-additive: an old client's op decodes with the
                // defaults — no pin, no wait.
                assert!(!pin);
                assert_eq!(*wait_ms, 0);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // The `op` tag is the load-bearing discriminator; pin it on re-encode.
        let value = serde_json::to_value(&req).expect("encode");
        assert_eq!(value["op"], "network_connect_peer");
        assert_eq!(value["peer"], "peerpubkey");
        let back: Request = serde_json::from_value(value).expect("re-decode");
        assert!(matches!(back, Request::NetworkConnectPeer { .. }));
    }

    #[test]
    fn inbound_frame_layout_matches_spec() {
        // Guards against drift from allmystuff-protocol's decode_inbound_frame:
        // kind, key, stream, rtp(LE u32), from_len(LE u16), from, data.
        let body = encode_inbound_frame(MEDIA_KIND_VIDEO, true, 2, 0x0001_0203, "ab", &[9, 8]);
        assert_eq!(
            body,
            vec![
                MEDIA_KIND_VIDEO,
                1, // key
                2, // stream
                0x03,
                0x02,
                0x01,
                0x00, // rtp_timestamp LE
                2,
                0, // from_len LE
                b'a',
                b'b', // from
                9,
                8, // data
            ]
        );
    }
}
