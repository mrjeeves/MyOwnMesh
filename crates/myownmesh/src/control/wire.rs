//! The control protocol's wire vocabulary: what a client may ask for, what
//! comes back, and the realtime advert shapes carried in it.
//!
//! Split out because this is the half a client reimplements. Nothing here
//! opens a socket, holds daemon state, or performs an operation; it is the
//! agreement between the two ends, and the dispatch that acts on it lives
//! beside it rather than around it.

use serde::{Deserialize, Serialize};

use myownmesh_core::realtime as core_realtime;
use myownmesh_core::transport as core_webrtc;
use myownmesh_core::{NetworkConfig, ServicesConfig};

/// Deserialize an MFA field only when the field is present on the wire.
///
/// The `deserialize_with` attribute makes Serde report an absent field as a
/// missing-field error, while this helper deliberately keeps both explicit
/// `null` (`None`) and an explicit string (`Some`) intact.
fn deserialize_present_mfa_code<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

/// Which way units flow on a [`Request::RealtimePipe`] connection.
///
/// One request covers both directions because only the direction differed
/// between the two pipes this replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimePipeDirection {
    /// Client writes units; the daemon routes each to its flow.
    Outbound,
    /// Daemon writes units the client's subscriptions cover.
    Inbound,
}

// A flow's direction and RTP kind are not redeclared here either.
// `Request::RealtimeFlowOpen` carries `RealtimeFlowDirection` and
// `WebRtcRtpKind` directly, so the value a client sends is the value handed to
// core with no daemon-side mapping in between. A local pair of enums with the
// same two variants would read as harmless and would be the place a translation
// bug eventually lives — one `match` arm crossed, and every outbound flow
// becomes an inbound one.
//
// The two come from different layers on purpose. Direction is basal: which way
// units travel is true of any flow and names no media, so it lives in the
// generic vocabulary. RTP kind is a WebRTC fact — it exists because RTP
// allocates a transceiver per kind — so it is spelled `WebRtcRtpKind` and lives
// at the provider edge. A client naming it is unambiguously naming a WebRTC
// thing, which is what stops a fixed audio/video taxonomy leaking back into the
// layer that is supposed to know nothing about media.
//
// [`RealtimePipeDirection`] stays local because it is not the same thing: it
// names a socket's role, and there are no pipes in core.

// Refusal codes are not redeclared here. `myownmesh_core::realtime::
// RealtimeRefusal::code()` is the one source of the stable strings
// (`session_not_current`, `label_in_use`, `flow_refused`,
// `provider_configuration_invalid`),
// and the daemon forwards what it is given. A daemon-side copy of the enum
// would be a second place to add a variant and a silent way to drop one: a new
// core variant would fall through a local `match` to some default string,
// where forwarding `code()` makes the same change a compile error here.
//
// Note the absent `label_space_exhausted`. The caller supplies an exact name
// and the connector claims that one — it never allocates — and there is no
// enumerable space of names to exhaust, so a name is free or in use and nothing
// can be "full" from a request's point of view. How many flows may be open at
// once is a separate question, answered by `flow_refused` from admission.

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
// Request deliberately keeps each wire operation's typed payload together;
// boxing it would alter the funded request layout without changing the wire contract.
#[allow(clippy::large_enum_variant)]
pub enum Request {
    Status,
    NetworksList,
    PeersList {
        network: String,
    },
    RosterList {
        network: String,
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
    /// Create a new Closed network. The daemon mints the creation nonce and
    /// persists the signed bootstrap before registering the runtime.
    NetworkCreateClosed {
        config: NetworkConfig,
    },
    /// Import one exact signed Closed bootstrap under the caller-selected
    /// local config id and an explicit context fence.
    NetworkImportClosed {
        config: NetworkConfig,
        expected_context_id: myownmesh_core::semantic::MeshContextId,
        bootstrap: myownmesh_core::semantic::BootstrapRecord,
    },
    /// Export the verified bootstrap record for a joined Closed network.
    NetworkBootstrapExport {
        network: String,
    },
    /// Export one provider-funded, receive-safe page of canonical semantic
    /// facts.  The cursor is exclusive and the two limits are validated by
    /// the core facade against its receive-frame ceiling.
    SemanticFactPageExport {
        network: String,
        request: myownmesh_core::semantic::SemanticFactPageRequest,
    },
    /// Import one bounded semantic fact page.  Wire deserialization carries
    /// no lease; the joined-network facade reacquires exact provider funding
    /// before reducing the page.
    SemanticFactPageImport {
        network: String,
        page: myownmesh_core::semantic::SemanticFactPage,
    },
    /// Inspect the deterministic semantic identity of one joined network.
    SemanticStateIdentity {
        network: String,
    },
    /// Render a bounded, non-canonical view of the newest facts retained in
    /// the live hot-history cache.
    SemanticRecentFacts {
        network: String,
        request: myownmesh_core::semantic::SemanticRecentFactsRequest,
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
    /// Forget **every** joined network at once — a `NetworkRemove{purge:true}`
    /// for all of them: tear each out of the registry, `leave()` its driver, and
    /// delete its signed governance state + roster from disk. Keeps this device's
    /// identity. Once the answer to this request has been attempted, the daemon
    /// runtime is asked to shut down, so every layer reloads from the now-clean
    /// disk instead of a stale in-memory cache that would re-persist
    /// ("resurrect") what was just removed. A hosted daemon shuts its runtime
    /// down and leaves the host process alive; a standalone one returns so its
    /// service supervisor, or the GUI, brings a fresh daemon back up.
    ForgetAllNetworks,
    /// Factory reset — wipe this device's **entire** state directory
    /// (`~/.myownmesh`, honouring `MYOWNMESH_HOME`): identity, config, and every
    /// network's roster + governance state. The device becomes a brand-new
    /// identity to every peer. Quiesces each network first (so nothing
    /// re-persists mid-wipe), then removes the tree and exits so a fresh daemon
    /// mints a new identity on empty state.
    FactoryReset,
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
    /// Snapshot which infrastructure services this device hosts
    /// (signaling / STUN / TURN): live runtime status plus the
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
    /// Float a role-grant proposal.
    GovernanceProposeRoleGrant {
        network: String,
        target: String,
        role: myownmesh_core::semantic::Role,
        #[serde(deserialize_with = "deserialize_present_mfa_code")]
        mfa_code: Option<String>,
    },
    /// Float a role-revoke proposal.
    GovernanceProposeRoleRevoke {
        network: String,
        target: String,
        #[serde(deserialize_with = "deserialize_present_mfa_code")]
        mfa_code: Option<String>,
    },
    /// Float an evict proposal — remove a peer from the closed network's
    /// roster entirely (the propagating lost/stolen-device kick).
    GovernanceProposeEvict {
        network: String,
        target: String,
        #[serde(deserialize_with = "deserialize_present_mfa_code")]
        mfa_code: Option<String>,
    },
    /// Prepare a new enrollment and return its exact transaction identity.
    /// The enrollment remains prepared until an explicit commit or abort.
    GovernanceMfaPrepare {
        network: String,
    },
    /// Query one exact enrollment transaction without selecting a successor.
    GovernanceMfaQuery {
        network: String,
        transaction_id: String,
    },
    /// Re-deliver the exact material for one prepared transaction.
    GovernanceMfaRedeliver {
        network: String,
        transaction_id: String,
    },
    /// Commit one exact enrollment transaction, idempotently.
    GovernanceMfaCommit {
        network: String,
        transaction_id: String,
    },
    /// Abort one exact enrollment transaction, idempotently.
    GovernanceMfaAbort {
        network: String,
        transaction_id: String,
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
    // `EventsSubscribe` first. That connection becomes server-push-only and
    // returns an unguessable capability; later command connections must present
    // both it and the numeric routing coordinate.
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
        client_capability: String,
        network: String,
        method: String,
        streaming: bool,
    },
    /// Release a method claim. No-op if not currently held by
    /// this client.
    RpcUnregister {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        method: String,
    },
    /// Resolve an in-flight inbound RPC (single-shot). The exact remote
    /// coordinates, response class, local owner capability and private
    /// operation id must all match. Either `ok` or `error` should be set; if
    /// both, `error` wins.
    RpcRespond {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ok: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Push one chunk to an in-flight streaming inbound RPC.
    RpcStreamChunk {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
        payload: serde_json::Value,
    },
    /// Close an in-flight streaming inbound RPC. After this the
    /// request id is no longer routable; further chunks are
    /// silently dropped. Optional `error` propagates to the
    /// peer as the stream-end's failure reason.
    RpcStreamEnd {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
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
        client_capability: String,
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
        client_capability: String,
        network: String,
        channel: String,
    },
    /// Release a channel subscription. No-op if not currently
    /// subscribed.
    ChannelUnsubscribe {
        client_id: crate::ipc::ClientId,
        client_capability: String,
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
    /// contract: resolved when the peer's engine has delivered it, or with an
    /// error. The primitive that replaces application-level retransmit loops.
    ///
    /// The contract is **within one live session**, and that bounds every part
    /// of it. Submission acquires the peer's current session or is refused, so
    /// a frame is never accepted for a peer this node cannot currently reach;
    /// the frame is retained under that session's own lease; and session
    /// replacement, policy revocation, connector replacement or restart resolve
    /// the caller with an error naming what happened rather than carrying the
    /// frame into a session that did not accept it.
    ///
    /// There is therefore no expiry to state and none to configure. A frame
    /// outlives neither its session nor the caller's own await, so the two
    /// things a deadline used to protect against — an undeliverable frame
    /// retained forever, and a caller left waiting on one — cannot happen.
    /// Backpressure is the resource provider refusing the frame's own lease,
    /// which is a real bound rather than a fixed queue depth.
    ChannelSendReliable {
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

    // ---- realtime flows -------------------------------------------------
    //
    // One codec-opaque protocol replaces the separate video and audio lane
    // surfaces. The daemon carries `mime` and `clock_rate` and parses neither;
    // there is no video/audio distinction anywhere below this point, and no
    // fixed per-kind lane pool.
    //
    // There is deliberately no unit-carrying request here. Units ride a binary
    // `RealtimePipe`; putting them in a JSON request would route low-latency
    // media through the reliable path, costing a parse and 33% base64
    // inflation per unit. `VideoSend`/`AudioSend` had no successor for exactly
    // that reason — the pipe is the media path, in both directions.
    /// Declare a realtime flow to `peer` under `flow_label`.
    ///
    /// `flow_label` is a name the caller chose, opaque to the daemon and to
    /// core: it is compared for equality against that session's own table and
    /// never parsed, ordered, or ranged over. The daemon names nothing and
    /// holds no label state. The connector claims that exact name and never
    /// picks another, so the only name failure is `label_in_use`.
    ///
    /// It is scoped to one session and freely reusable after close. There is no
    /// label space and therefore no exhaustion: what bounds a name is its size,
    /// 1..=255 bytes, because the binary pipe length-prefixes it with one byte.
    /// How many may exist at once is admission's question, answered by the
    /// connector's flow policy and the provider's leases.
    ///
    /// Carried here as a string, which is the JSON-representable half of the
    /// byte name core holds. The binary pipe carries the same name as raw bytes.
    ///
    /// `rtp_kind`, `mime`, `clock_rate` and `channels` together select an
    /// encoding *family* among the ones the application-supplied profile
    /// registered — not one registration tuple. Deployed H.264 is five
    /// payload-type/fmtp variants sharing all four values; every one of them is
    /// registered on the `MediaEngine`, and which the connection uses is
    /// settled by SDP negotiation with the peer. A request that named one exact
    /// tuple would therefore fail against any peer that picked a different
    /// variant, which is four of the five.
    ///
    /// All four fields are still needed, because a family is what they jointly
    /// name: a lookup on `mime` alone would fold Opus's channel counts and any
    /// two clock rates into one. `clock_rate` is additionally what makes an
    /// inbound unit's `rtp_timestamp` interpretable, so it is a field rather
    /// than something folded into `mime` and parsed back out.
    ///
    /// **Answers a `flow_capability`, and that is what authorizes everything
    /// afterwards.** The daemon keeps the move-only core flow handle behind it,
    /// owned by the authenticated client. `network`, `peer` and `flow_label`
    /// are what this request *resolves*; none of them is presented again. The
    /// pair they replace was re-resolvable — a client whose session had been
    /// replaced kept writing under `peer + flow_label` and its units were taken
    /// by the successor's flow of the same name, silently, because nothing on a
    /// realtime path is acknowledged per unit.
    ///
    /// `client_id` and `client_capability` are required for the same reason:
    /// the flow has to be owned by somebody, and the owner must be the same
    /// client across the several connections it will use — the flow is opened
    /// here and written on a separate `realtime_pipe`.
    RealtimeFlowOpen {
        network: String,
        peer: String,
        flow_label: String,
        /// The client's `EventsSubscribe` id — a routing coordinate.
        client_id: crate::ipc::ClientId,
        /// Authority minted for that event-stream connection. Possession of
        /// this, not the id beside it, is what owns the flow.
        client_capability: String,
        /// Which way this node carries units on this flow. Stated by the caller
        /// rather than inferred: a flow this node sends on and one it receives
        /// on need different transceiver directions, and inferring from later
        /// traffic would let the first unit decide.
        direction: core_realtime::RealtimeFlowDirection,
        /// A connector primitive, not a codec name: RTP distinguishes audio from
        /// video when allocating a transceiver, independently of which codec
        /// occupies it. Carrying it explicitly is what lets the connector pick a
        /// transceiver without parsing `mime`, so `video/H264` and `video/VP8`
        /// are the same decision here and core never learns either name.
        ///
        /// The JSON spelling stays `"audio"` / `"video"`. Moving this type to
        /// the provider edge changed which Rust module owns it and deliberately
        /// changed nothing a client sends.
        rtp_kind: core_webrtc::WebRtcRtpKind,
        mime: String,
        clock_rate: u32,
        /// 0 for video, 2 for stereo Opus. Part of the family key, not
        /// decoration: two registered families can differ only here.
        channels: u16,
    },
    /// Release a realtime flow and its label. No-op if not open.
    ///
    /// The response is the acknowledgement, and it follows the retirement of the
    /// flow's native half rather than the release of its label. A caller may
    /// therefore close a label and reopen it immediately, knowing the previous
    /// occupant is gone. That ordering is the whole point: acking on the label
    /// release would let a reopen land while the old transceiver or sender was
    /// still alive, which is the one case a caller would have needed the
    /// guarantee for.
    ///
    /// Which is also why a label must stay reserved until this answers. Freeing
    /// it on send and reusing it before the ack reintroduces exactly the ABA
    /// this ordering removes: the peer cannot tell the new flow from the old one
    /// it has not finished tearing down. On a refusal the label stays reserved
    /// too — a close that did not happen has retired nothing.
    ///
    /// Names the flow by the capability `RealtimeFlowOpen` issued, never by
    /// `peer + flow_label`. The coordinate pair is what made a close as
    /// dangerous as a send: a client whose session had been replaced would have
    /// torn down the *successor's* flow of the same name, and the successor
    /// belongs to somebody else. The capability closes the flow it was issued
    /// for or nothing at all.
    ///
    /// The daemon's stored handle is **consumed**, so a second close with the
    /// same capability finds nothing rather than reaching core twice.
    RealtimeFlowClose {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        flow_capability: String,
    },
    /// Open one provider-backed, codec-opaque application flow.  The label is
    /// raw application bytes rather than a daemon-owned string; it is scoped
    /// to the exact session and the returned capability is the only authority
    /// used by the binary pipe afterwards.
    OpaqueFlowOpen {
        network: String,
        peer: String,
        label: Vec<u8>,
        client_id: crate::ipc::ClientId,
        client_capability: String,
        direction: core_realtime::RealtimeFlowDirection,
        mode: core_realtime::OpaqueFlowMode,
        max_unit_bytes: u32,
    },
    /// Change only the ceiling of one exact, already-installed opaque flow.
    /// The identity fields are repeated so the engine can reject any mismatch
    /// against the stored move-only capability before preparing its change.
    OpaqueFlowChange {
        network: String,
        label: Vec<u8>,
        client_id: crate::ipc::ClientId,
        client_capability: String,
        flow_capability: String,
        direction: core_realtime::RealtimeFlowDirection,
        mode: core_realtime::OpaqueFlowMode,
        max_unit_bytes: u32,
    },
    /// Consume one exact opaque-flow capability and await its native/logical
    /// retirement before acknowledging the close.
    OpaqueFlowClose {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        flow_capability: String,
    },
    /// Convert this connection into a binary opaque application pipe. Outbound
    /// frames are `[u32 little-endian body length][raw body]`; inbound frames
    /// are `[u32 little-endian payload length][u8 label length][raw label][raw
    /// body]`. JSON and base64 never carry application bodies. Binding rules
    /// mirror `RealtimePipe`, but the body itself is intentionally not parsed
    /// by the daemon.
    OpaquePipe {
        direction: RealtimePipeDirection,
        network: String,
        #[serde(default)]
        peer: Option<String>,
        #[serde(default)]
        client_id: Option<crate::ipc::ClientId>,
        #[serde(default)]
        client_capability: Option<String>,
        #[serde(default)]
        flow_capability: Option<String>,
    },
    /// Convert this connection into a dedicated **binary realtime pipe**:
    /// after the ack it carries only length-prefixed frames
    /// (`[u32 len][body]`, see [`decode_realtime_send_unit`] and
    /// [`encode_realtime_recv_unit`]) and no JSON.
    ///
    /// `Outbound` reads units from the client and writes each to its flow;
    /// `Inbound` pushes every unit arriving on the bound session, whichever
    /// flow it arrived on — the frame carries the name, so no subscription
    /// selects which flows are delivered.
    ///
    /// **The two directions are bound differently, and the asymmetry is the
    /// point.**
    ///
    /// `Outbound` names its flow by `flow_capability` — the value
    /// `RealtimeFlowOpen` issued — and nothing else. It carries no `peer`,
    /// because a peer selector here would be re-resolved for every unit, which
    /// is precisely the defect: labels are session-scoped and freely reused, so
    /// a pipe that outlived its session went on writing `screen` into whatever
    /// the successor called `screen`, with nothing anywhere acknowledging a unit
    /// and therefore nothing to notice. `network` remains because closing and
    /// sending happen *through* a joined network, not because it selects
    /// anything: the capability already names one exact flow on one exact
    /// session.
    ///
    /// The frame body still carries a `flow_label`, and it still grants nothing.
    /// It is checked against the flow this pipe is bound to and refused if it
    /// disagrees, so a client that muddles its own names hears about it rather
    /// than having units silently rerouted.
    ///
    /// `Inbound` is bound by `network` + `peer`, and that is a different
    /// question: it claims one *session's* whole unit stream, not one flow, and
    /// the stream reader it gets is itself the exact authority — it can only
    /// ever yield units the claiming session's own flow set put there. There is
    /// no coordinate to re-resolve after the claim.
    ///
    /// The binding is also a lifetime, and it is observed rather than
    /// signalled. There is no flow or session event on any socket: a separate
    /// signal would be a second source of truth that can disagree with the
    /// queue, and this is where the end is actually observable. Dropping the
    /// session's `PromotedSession` drops its flow set and
    /// the queued units with it, and each direction learns that from the queue
    /// it already holds:
    ///
    /// - inbound terminates when the session-owned recv queue closes;
    /// - outbound terminates on a closed queue, or on `session_not_current`
    ///   from the synchronous send.
    ///
    /// Either way the pipe ends with the session rather than outliving it,
    /// which would be a send outliving its flow one layer up. The client then
    /// reconnects and may immediately reuse the same names — a name belongs to
    /// the session that claimed it and died with it — so the binding is
    /// re-established per session and never cached per peer.
    ///
    /// Field shapes are validated strictly and a wrong-shaped request is
    /// refused rather than trimmed. `Outbound` requires `network`, `client_id`,
    /// `client_capability` and `flow_capability`, and refuses `peer`;
    /// `Inbound` requires `network`, `peer`, `client_id` and
    /// `client_capability`, and refuses `flow_capability`. Silently ignoring a
    /// field would let a client believe it had bound something the daemon never
    /// recorded — and for `peer` on an outbound pipe that belief is exactly the
    /// one this finding removes.
    RealtimePipe {
        direction: RealtimePipeDirection,
        /// Which joined network the operations run through. Not a selector for
        /// `Outbound`: the flow capability already names one exact flow.
        network: String,
        /// Required for `Inbound`, which claims that session's whole unit
        /// stream. Must be absent for `Outbound`, which names a flow rather
        /// than a peer.
        #[serde(default)]
        peer: Option<String>,
        /// The client's `EventsSubscribe` id. Required for both directions
        /// now: outbound needs it to find the client that owns the flow.
        #[serde(default)]
        client_id: Option<crate::ipc::ClientId>,
        /// Authority minted for the referenced event-stream connection.
        #[serde(default)]
        client_capability: Option<String>,
        /// Required for `Outbound` — the capability `RealtimeFlowOpen` issued
        /// for the exact flow this pipe writes to. Must be absent for
        /// `Inbound`, which is bound to a session rather than a flow.
        #[serde(default)]
        flow_capability: Option<String>,
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

/// One encoding family this daemon has registered, as published to clients.
///
/// A family, not a registration tuple. Deployed H.264 is several payload/fmtp
/// variants sharing these four fields; a flow open names the family and SDP
/// negotiation picks the variant. Publishing payload types would invite a
/// caller to name one, which is not a choice it gets to make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealtimeEncoding {
    /// `audio` or `video` — which transceiver the family occupies.
    pub kind: String,
    pub mime: String,
    pub clock_rate: u32,
    /// 0 for video; 2 for stereo Opus.
    pub channels: u16,
}

/// What this daemon can carry on the realtime path.
///
/// Two facts, and no promise: whether the daemon supports the path at all, and
/// which encoding families it registered. A capacity number would be a promise,
/// because a caller would size its concurrent flows against it — and the
/// directional resource envelopes underneath answer `flow_refused` before any
/// aggregate is reached. Feasibility is learned where it is decided, from the
/// typed refusal on `realtime_flow_open`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealtimeAdvert {
    /// False when no profile was registered: no codecs, so nothing can be
    /// carried. Stated rather than implied by an empty list, so a client can
    /// tell "this build has no realtime path" from "it has one and I could not
    /// read its encodings".
    pub supported: bool,
    /// The registered families, deduplicated. Empty when unsupported.
    pub encodings: Vec<RealtimeEncoding>,
}

impl RealtimeAdvert {
    /// A daemon that registered no realtime profile and can carry nothing.
    pub fn unsupported() -> Self {
        Self {
            supported: false,
            encodings: Vec::new(),
        }
    }

    /// A daemon that registered `encodings`.
    pub fn registered(encodings: Vec<RealtimeEncoding>) -> Self {
        Self {
            supported: true,
            encodings,
        }
    }
}

#[cfg(test)]
mod cutover_tests {
    use super::Request;

    #[test]
    fn retired_member_relay_operations_are_unknown_not_application_aliases() {
        for op in [
            "closed_relay_open",
            "closed_relay_accept",
            "closed_relay_send",
            "closed_relay_recv",
            "closed_relay_close",
            "closed_relay_state",
        ] {
            let value = serde_json::json!({
                "op": op,
                "network": "network",
                "relay": "relay",
                "target": "target",
                "handle": "handle",
                "wait_ms": 1,
                "payload": [1, 2, 3]
            });
            let error = serde_json::from_value::<Request>(value).unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("unknown variant") && message.contains(op),
                "{message}"
            );
        }
        assert!(matches!(
            serde_json::from_value::<Request>(serde_json::json!({"op": "networks_list"})).unwrap(),
            Request::NetworksList
        ));
    }
}
