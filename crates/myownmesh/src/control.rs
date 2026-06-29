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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
        let resp = dispatch(&state, request).await;
        let line = serde_json::to_string(&resp)? + "\n";
        writer.write_all(line.as_bytes()).await?;
    }
    Ok(())
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
            "media_lanes": myownmesh_core::transport::MEDIA_LANES,
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
                Some(net) => match net.set_topology(mode).await {
                    Ok(_) => Response::ok(serde_json::json!({ "topology": topology })),
                    Err(e) => Response::err(e.to_string()),
                },
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

    // Attach the production signaling driver. A `None` here means
    // the bridge declined (e.g. signaling disabled in config); the
    // network still works for in-process drivers attached by tests.
    let nostr = {
        let net_state = joined.state();
        myownmesh_core::engine::attach_nostr(&net_state)
    };
    if nostr.is_none() {
        warn!(network = %config.network_id, "nostr attach returned no handle");
    }
    state.registry.insert(joined, nostr);

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
                    let nostr = {
                        let net_state = restored.state();
                        myownmesh_core::engine::attach_nostr(&net_state)
                    };
                    state.registry.insert(restored, nostr);
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
    let nostr = {
        let net_state = joined.state();
        myownmesh_core::engine::attach_nostr(&net_state)
    };
    if nostr.is_none() {
        warn!(network = %config.network_id, "nostr attach returned no handle after update");
    }
    state.registry.insert(joined, nostr);

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
        other => Err(format!(
            "unknown topology '{other}' — expected ring | star | full_mesh"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_network_state_drops_state_and_roster() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", tmp.path());
        let net = "purge-test-net";

        // Seed a closed governance state + a rostered member.
        let mut st = myownmesh_core::network_state::NetworkState::empty_for(net);
        st.kind = myownmesh_core::NetworkKind::Closed;
        myownmesh_core::network_state::save(&st).expect("save state");
        let mut roster = myownmesh_core::roster::empty_for(net);
        myownmesh_core::roster::add_peer_in(&mut roster, "peerpubkeyone", "dev");
        myownmesh_core::roster::save(&roster).expect("save roster");

        // Both are on disk.
        assert_eq!(
            myownmesh_core::network_state::load(net).unwrap().kind,
            myownmesh_core::NetworkKind::Closed
        );
        assert!(myownmesh_core::roster::is_authorized(
            &myownmesh_core::roster::load(net).unwrap(),
            "peerpubkeyone"
        ));

        // Purge — the on-disk half of forgetting a fleet.
        purge_network_state(net);

        // Gone: a fresh load returns the empty/open defaults, so a rejoin can't
        // reload a stale (forked) genesis.
        assert_eq!(
            myownmesh_core::network_state::load(net).unwrap().kind,
            myownmesh_core::NetworkKind::Open
        );
        assert!(!myownmesh_core::roster::is_authorized(
            &myownmesh_core::roster::load(net).unwrap(),
            "peerpubkeyone"
        ));
    }
}
