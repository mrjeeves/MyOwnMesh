//! MyOwnMesh — peer-to-peer mesh networking runtime.
//!
//! `myownmesh-core` is the only crate embedding apps need to depend on.
//! It exposes everything from identity through the connection engine
//! and the high-level [`Mesh`] / [`MeshHandle`] / [`JoinedNetwork`]
//! facade.
//!
//! # Quick tour
//!
//! ```no_run
//! # async fn _ex(
//! #     connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
//! #     semantic_policy: myownmesh_core::config::SemanticPolicyConfig,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! use myownmesh_core::{
//!     ClosedRelayPolicyConfig, Mesh, MeshConfig, NetworkConfig, RoutingPolicyConfig, TopologyMode,
//! };
//!
//! // The process owner supplies the reviewed connector policy explicitly.
//! let mesh = Mesh::open_connector_capable(
//!     MeshConfig::default(),
//!     connector_policy,
//! ).await?;
//! println!("device id: {}", mesh.identity().display_id());
//!
//! // Join a named network. Returns a per-network handle.
//! let net = mesh.join(NetworkConfig {
//!     id: "home".into(),
//!     network_id: "my-mesh".into(),
//!     label: "Home".into(),
//!     kind: Default::default(),                            // Open (default)
//!     scheduler: Default::default(),
//!     // Resource retention is an owner decision; the library supplies no
//!     // hidden production ceiling.
//!     semantic_policy,
//!     routing_policy: RoutingPolicyConfig::default(),
//!     tree: None,
//!     hub: None,
//!     local_observations: None,
//!     event_capacity: 256,
//!     connection_trace_capacity: 512,
//!     topology: TopologyMode::default(),
//!     signaling: Default::default(),
//!     closed_relay: ClosedRelayPolicyConfig::default(),
//!     stun_servers: Default::default(),
//!     turn_servers: Default::default(),
//!     pinned_peers: Vec::new(),
//!     auto_approve: false,
//! }).await?;
//!
//! // Attach a signaling driver.
//! let _drivers = net.attach_signaling()?;
//!
//! // Subscribe to events.
//! let mut events = mesh.events();
//! while let Ok(event) = events.recv().await {
//!     println!("{event:?}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # What's in this crate
//!
//! - [`Identity`] — long-lived ed25519 device identity persisted at
//!   `~/.myownmesh/.secrets/identity.json` (mode 0600 on Unix). The
//!   public key is the Device ID surfaced on the wire.
//! - [`Roster`] — per-network local/UI projection of peer metadata derived
//!   from canonical signed policy. It is not an admission authority: a
//!   reconnect is admitted only when canonical policy permits it and the
//!   explicit `NetworkConfig::auto_approve` setting is enabled.
//! - [`protocol`] — wire format: `hello` / `auth_response` / `approve`
//!   / `deny` / `ping` / `pong` / `shelve` / `unshelve` /
//!   `capabilities_update` / generic RPC frames. See `docs/PROTOCOL.md`.
//! - [`topology`] selectors — FullMesh (default), Ring, Star.
//! - [`transport`] — webrtc-rs wrapper; one [`PeerSession`](transport::PeerSession)
//!   per peer with an event mpsc the engine drains.
//! - [`engine`] — connection engine: hello state machine, heartbeat,
//!   recovery from reliable transport signals (in-place ICE restart
//!   confirmed by inbound traffic, clean rebuild on failure), topology
//!   shelving. See `CONNECTION-ENGINE-FIELD-NOTES.md`.
//! - [`Channel<T>`] — typed publish/subscribe between peers.
//! - [`Rpc`] — generic request/response with streaming.
//!
//! # Trust model
//!
//! Each device owns a long-lived ed25519 keypair. Both sides send a
//! `hello` carrying an independently drawn 32-byte contribution; the
//! `auth_response` is an ed25519 signature over the endpoint-auth
//! transcript, whose fields are length-prefixed under
//! `ENDPOINT_AUTH_DOMAIN_TAG`: the mesh context, the fixed crypto
//! profile, the signer's role, both device IDs, both contributions, and
//! both endpoints' DTLS certificate fingerprints — every paired field
//! in role-canonical order, so the two sides derive identical bytes.
//! Each side verifies its own half as well as the peer's, so a proof is
//! mutual rather than one-directional.
//!
//! Domain separation prevents a signature obtained for one protocol step
//! from being replayed in another. Binding both fingerprints ties the
//! proven identity to *this* transport, so a man-in-the-middle on the
//! (unauthenticated) signaling path can't relay the handshake across two
//! DTLS legs it terminates — it would have to present its own
//! certificate to each leg.
//!
//! A certificate fingerprint is **not** a session-unique exporter,
//! though: two channels between the same pair reusing the same
//! certificates carry the same value. Replay across channels is
//! prevented by the per-attempt contributions, and transfer of an
//! already-issued capability is prevented by connector-incarnation
//! ownership — not by the fingerprints.
//!
//! This is a hard cutover. Endpoint authentication has one transcript and no
//! feature-negotiated fallback: a mismatched profile fails authentication
//! rather than negotiating down, so a downgrade is not attacker-selectable.
//!
//! A user-visible 6-char verification code lets a human
//! eyeball-confirm the handshake over voice/video at first-meeting
//! time; subsequent reconnect approval still requires the exact canonical
//! policy and the explicit `NetworkConfig::auto_approve` setting.
//!
//! # Where to look next
//!
//! - `docs/QUICKSTART.md` — the narrative walkthrough.
//! - `docs/PROTOCOL.md` — every wire frame.
//! - `CONNECTION-ENGINE-FIELD-NOTES.md`: every retained tunable and edge case.
//! - `examples/` — runnable demos
//!   (`cargo run --example two_peer_chat -p myownmesh-core`,
//!   `echo_rpc`, `roster_demo`).
//! - `tests/two_peer_handshake.rs` — the end-to-end integration
//!   test doubles as an executable spec.

pub mod application_gateway;
pub mod channels;
pub mod config;
pub mod connector;
pub mod custody;
pub mod dirs;
pub mod endpoint_auth;
pub mod engine;
pub mod error;
pub mod events;
pub mod handle;
pub mod identity;
pub(crate) mod persist;
pub mod protocol;
pub mod realtime;
pub mod resource;
pub mod roster;
#[cfg(feature = "route-flow-diagnostics")]
pub(crate) mod route_flow;
pub mod rpc;
pub mod runtime;
/// Canonical V4 durable semantic facts.  This is the authority-bearing
/// surface; legacy governance/roster values are adapters and must not mint a
/// second fact identity.
pub mod semantic;
pub mod services;
pub mod signing;
pub mod topology;
pub mod transport;
pub mod verification;

pub use application_gateway::capability_advert_planning_claim;
pub use channels::{Channel, ChannelError, ChannelMessage};
pub use config::{
    AutoUpdateConfig, MeshConfig, NetworkConfig, NetworkKind, NodeServiceConfig,
    RoutingPolicyConfig, ServicesConfig, SignalingLimits, SignalingServerConfig, StunServer,
    StunServiceConfig, TopologyMode, TurnCredential, TurnServer, TurnServiceConfig,
};
pub use engine::conn_trace::ConnTrace;
pub use engine::ladder::ConnectionTier;
pub use engine::signaling_bridge::{
    mdns_connection_identity_planning_claim, mdns_connection_planning_claim,
};
/// The funded peers snapshot, exported at the root beside [`PeerInfo`] because
/// it answers the same question under a different contract: measured before it
/// is built, and refusable at four separate points.
pub use error::{ClosedRelayError, Error, Result};
pub use events::{DiagEntry, DiagLevel, MeshEvent, MeshPhase, PeerEvent};
/// The real-link fixture owner, exported at the root for the same reason the
/// fixture exists: the controls that need it live in another crate.
#[cfg(feature = "transport-lab")]
pub use handle::TransportLabPromotedPeer;
pub use handle::{AuthenticatedProfile, JoinedNetwork, Mesh, MeshHandle, PeerInfo};
pub use identity::{generate_network_id, normalize_network_id, Identity};
pub use myownmesh_signaling::local::LocalBroker;
pub use protocol::CapabilityAdvert;
pub use resource::{
    checked_measure_add, mailbox_measure_serialized, measure_serialized_mailbox_item,
    measure_serialized_mailbox_item_after_funded, prepare_resource_mailbox, resource_mailbox,
    FiniteResourceProvider, FundedArc, FundedWeak, LeasedMap, LeasedMapInsertRefusal,
    LocalApplicationResourceScope, LocalApplicationResourceScopeIssueError, MailboxMeasurement,
    PreparedResourceMailbox, ProcessResourceRoot, ResourceAuthorityClass, ResourceClaim,
    ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceMailboxAdmissionError,
    ResourceMailboxCreateError, ResourceMailboxDelivery, ResourceMailboxItem,
    ResourceMailboxItemBuilder, ResourceMailboxItemError, ResourceMailboxPlanningError,
    ResourceMailboxReceiver, ResourceMailboxSendError, ResourceMailboxSender, ResourcePressure,
    ResourceProvider, ResourceProviderAuthority, ResourceProviderConflict, ResourceProviderPort,
    ResourceReservationState, ResourceScope, ResourceScopeId, ResourceUnavailable,
    RESOURCE_CLASS_COUNT,
};
pub use roster::{AuthorizedPeer, Roster};
pub use rpc::{
    rpc_dispatcher_attachment_planning_claim, rpc_dispatcher_planning_claim, Rpc, RpcCall,
    RpcError, RpcResponse,
};
pub use runtime::attempt::{
    connector_resource_structural_claims, ConnectorCallbackPolicy, ConnectorResourceOwnerPort,
    ConnectorResourceOwnerReport, ConnectorResourceStructuralClaims, MeshConnectorResourceReport,
    MeshConnectorResourceScopeIssueError, RealtimeConnectorPolicy, WebRtcConnectorCapablePolicy,
};
pub use runtime::session_broker::session_reservation_planning_claim_for_correlation;
pub use services::{ServiceAdvert, ServiceRole};
pub use topology::Topology;
#[cfg(feature = "transport-lab")]
pub use transport::{
    transport_lab_connector_fixture_grant, transport_lab_remote_candidate_fixture_grant,
    transport_lab_remote_description_fixture_grant, TransportLabCallbackGrant,
    TransportLabCallbackWorkload, TransportLabRealtimeWorkload,
};
/// Every realtime name at the crate root is `WebRtc`-qualified.
///
/// The generic realtime vocabulary lives in [`realtime`] and names no codec, no
/// media kind and no RTP fact; everything that does is a property of the WebRTC
/// provider and says so in its own name. There is no unqualified spelling and no
/// compatibility alias — a caller names the qualified type or does not compile.
pub use transport::{
    WebRtcConnectorProfile, WebRtcConnectorProfileError, WebRtcRealtimeCodec,
    WebRtcRealtimeFlowOpen, WebRtcRealtimeFraming, WebRtcRealtimeInboundArrival,
    WebRtcRealtimeInboundUnit, WebRtcRealtimeOutboundUnit, WebRtcRealtimeProfile,
    WebRtcRealtimeProfileError, WebRtcRealtimeRtcpFeedback, WebRtcRtpKind,
};

/// App-id used to derive the Trystero room handle. Two MyOwnMesh peers
/// with the same `network_id` and the same app-id meet in the same
/// signaling room; peers with mismatching app-ids never see each
/// other. Overridable via the `MYOWNMESH_TRYSTERO_APP_ID` env var so
/// downstream forks can isolate their fleet.
pub const TRYSTERO_APP_ID: &str = "myownmesh-cloud-mesh-v1";

/// Wire-protocol version for the one current closed profile. A receiver
/// refuses a previous, future, or missing version before endpoint
/// authentication; there is no feature-negotiated or mixed-version fallback.
/// This bump records the incompatible addition of the Closed relay wire set.
pub const PROTOCOL_VERSION: u32 = 2;
