# MyOwnMesh application API (Rust 1.0.0)

This is the source-linked application reference for the `myownmesh-core`
embedding API. It describes the production facade an application can build on,
not the daemon's control protocol. The links point at the implementation so a
release review can distinguish a real method from a conceptual example.

## Support and boundary

The supported application path is:

`Mesh::open_connector_capable*` → `MeshHandle` → `JoinedNetwork`.

The caller owns the handles and decides when to stop using them. MyOwnMesh
owns identity authentication, signaling, ICE, WebRTC, TURN traversal, session
promotion, resource admission, durable semantic storage, and cleanup. The
application owns its payload schemas, application authorization, persistence,
workflow, and user interaction. Authentication proves the endpoint identity;
it does not grant the peer permission to invoke an application operation.

Application data travels on endpoint-authenticated WebRTC, directly or through
configured standard TURN. Hub signaling is discovery/introduction setup only;
it is not a plaintext or ciphertext application relay. Service advertisements
carry endpoint/service metadata, not passwords.

The compatibility promise is for the documented public facade at the selected
1.0.0 release. `#[doc(hidden)]`, `#[cfg(feature = "transport-lab")]`,
`pub(crate)`, engine/runtime modules, and test controls are not supported
embedding APIs even when a build can name them.

The maintained source examples are [`application_bootstrap.rs`](../crates/myownmesh-core/examples/application_bootstrap.rs)
for startup/signaling ownership and [`application_patterns.rs`](../crates/myownmesh-core/examples/application_patterns.rs)
for channels, RPC, streaming, and exact-handle realtime operations. They accept
caller-selected policy and grants; they are deliberately not turnkey capacity
fixtures. In particular, `consume_stream_bounded` visits funded stream chunks
without accumulating an unbounded vector, and `send_and_close_opaque` preserves
open/send/close failures while always awaiting close after a successful open.

## Opening a mesh and funding connector work

`Mesh` is the entry type. A connector-capable mesh requires an explicit,
process-local resource provider and an explicit WebRTC profile:

```rust
use myownmesh_core::{
    ConnectorCallbackPolicy, Mesh, MeshConfig, MeshHandle, ResourceProvider,
    ResourceProviderPort, WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};

async fn open_mesh(
    provider: impl ResourceProvider,
    config: MeshConfig,
) -> myownmesh_core::Result<MeshHandle> {
    let port = ResourceProviderPort::new(provider)?;
    let profile = WebRtcConnectorProfile::new(
        ConnectorCallbackPolicy::elastic_realtime(),
    );
    let policy = WebRtcConnectorCapablePolicy::new(port, profile);
    Mesh::open_connector_capable(config, policy).await
}
```

This uses the exact constructor in [`handle.rs`](../crates/myownmesh-core/src/handle.rs#L105-L115)
and policy types in [`policy.rs`](../crates/myownmesh-core/src/runtime/attempt/policy.rs#L105-L133).
The provider's grant is deployment policy; the library does not invent a
capacity value. `ResourceClaim`, `FiniteResourceProvider`, and
`ResourceProviderPort` are real public building blocks, but the dimensions and
amounts must be selected from the application's workload rather than copied
from a sample.

For a runtime that must not allocate native connectors,
`Mesh::open_infrastructure_only` accepts a resource port and returns a handle
that cannot join a network. For key stores managed by the host, use
`open_connector_capable_with_identity` or
`open_infrastructure_only_with_identity` with an `Arc<Identity>`; the identity
constructor is [`Identity::from_signing_key`](../crates/myownmesh-core/src/identity.rs#L81-L110).
`Identity::ephemeral` is a real constructor for short-lived identities, not a
durable-device replacement.

`ConnectorCallbackPolicy::elastic_data_only()` supports ordinary typed channels,
RPC, and reliable messages, but disables generic opaque and RTP flow admission.
Generic opaque flows use
`ConnectorCallbackPolicy::elastic_realtime()` and do not require a codec
profile. For WebRTC RTP, use that same realtime policy, construct a validated
`WebRtcRealtimeProfile` with `WebRtcRealtimeProfile::new(Vec<WebRtcRealtimeCodec>)`,
then call `WebRtcConnectorProfile::with_realtime_profile(profile)` before
passing the connector policy to `Mesh::open_connector_capable`. The profile,
including its receive-side capability set, must exist before peer connections
are created. A later RTP open can still be refused if the exact registered
kind/MIME/clock-rate/channel tuple is absent; a realtime profile is not a
capacity grant. An infrastructure-only mesh or a connector-capable mesh without
the caller's resource-provider ownership cannot admit an opaque flow.

Useful device-level observations are `MeshHandle::identity`, `device_id`,
`events`, `resource_report`, `connector_resource_report`,
`mesh_connector_resource_report`, and
`local_application_resource_scope`. The report methods are observations, not
ways to mint capacity or bypass admission.

## Network configuration and lifecycle

Use the persisted `MeshConfig::load`/`save` path when the deployment already
has configuration. A production `NetworkConfig` must carry the complete
owner-selected `SemanticPolicyConfig`; production deliberately has no
semantic-policy default. The supported constructor is:

```rust
let mut network = NetworkConfig::from_network_id_with_semantic_policy(
    "home",                 // local config record id
    "my-cool-mesh",         // normalized rendezvous id
    semantic_policy,         // complete policy selected by the owner
);
network.label = "Home mesh".into();
network.turn_servers = configured_turn_servers;
network.introduction = configured_introduction_policy;
let joined = mesh.join(network).await?;
```

The constructor and all `NetworkConfig` fields are defined in
[`config.rs`](../crates/myownmesh-core/src/config.rs#L1771-L1960). It provides
the normal Open shape and defaults for scheduler/topology/STUN/TURN while
leaving the semantic policy explicit. `NetworkConfig::from_network_id` is
test/transport-lab only and must not appear in a shipped application.

`NetworkKind::Open` authenticates ephemeral participation. `Closed` uses the
verified bootstrap and durable governance. `Silent` is an Open shape that does
not auto-dial merely because a peer is sighted. `MeshHandle::join` joins an
existing network; `create_network(config, creation_id)` creates a Closed
network and has the Mesh sign and persist the supplied 32-byte creation input;
the caller does not provide a pre-signed creation record.
`import_network(config, expected_context_id, bootstrap_record)` imports a
Closed network while fencing the expected context. These signatures and the
connector-capable requirement are in [`handle.rs`](../crates/myownmesh-core/src/handle.rs#L250-L340).

After joining, `JoinedNetwork::attach_signaling()` starts the configured
signaling carrier and returns an optional driver owner. The returned owner is
the supported lifecycle-owner exception to the internal engine boundary; keep
it alive for the intended carrier lifetime and await its `shutdown()` before
the joined network is retired. `attach_local`
and `LocalBroker` are transport-lab controls and are intentionally not a
production carrier. STUN/TURN are configured with `StunServer` and `TurnServer`
(`urls`, optional `username`, optional `credential`). An explicit empty TURN
list disables TURN; an omitted field uses the configured project default.

`JoinedNetwork` is cloneable. `leave(self)` consumes one handle and performs
the deliberate departure; `shutdown(&self)` supports shared ownership and is
idempotent. Both await the runtime's actual retirement. Do not use `Drop` as a
delivery or shutdown acknowledgement.

`set_topology(TopologyMode)` queues an explicit runtime topology change; later
engine processing applies it and emits the corresponding events. Do not treat
the method's completion as proof that every peer has already converged.
`TopologyMode::FullMesh`, `Ring`,
`Star`, and `HubTree` describe connection preference, not application routing
or authority. `config_snapshot`, `reconcile_status`, and the raw engine state
are diagnostic/internal surfaces; use persisted `MeshConfig` transactions and
the documented handle methods for application configuration changes.

The signaling configuration selects the configured carrier and its bounded
timing/observation policies. `stun_servers` and `turn_servers` are endpoint
ICE inputs; they do not turn the Hub into an application data path. A TURN
credential is local configuration and must be provisioned through the host's
secret-management process.

## Events, peers, and application authorization

Call `MeshHandle::events()` to receive a Tokio broadcast stream. The outer
`MeshEvent` is `Peer`, `Phase`, or `Diag`; peer events include `Sighted`,
`Authenticated`, `Approved`, `Shelved`, `Unshelved`, `CapabilitiesChanged`,
and `Dropped`. The complete wire shape and fields are in
[`events.rs`](../crates/myownmesh-core/src/events.rs#L19-L209). Broadcast
receivers can lag; `RecvError::Lagged` is an observation that the application
missed history, not a hidden replay request.

`JoinedNetwork::peers()` and `peer(device_id)` are local runtime observations.
`roster_list()` returns the local `AuthorizedPeer` projection. A roster row is
not itself session authority and a label is cosmetic. Use the peer's canonical
device id for selection; do not use display suffixes as identity.

`connect_peer` queues a dial and returns when the command is admitted, not when
the peer is active. `connect_peer_wait(device_id, sticky, timeout)` waits for
the actual active session or a terminal error. If its timeout expires, only the
wait ends: the dial continues, and a `sticky` wait leaves its standing dial
intent armed. `unpin_peer` removes that intent but does not disconnect a live
session. `reconnect` is fire-and-forget.

Authentication and application authorization are separate. After inspecting
the authenticated peer, the application may reject every application request.
For Closed governance, the canonical proposal methods are
`propose_role_grant(target, role, mfa_code)`,
`propose_role_revoke(target, mfa_code)`, and `propose_evict(target, mfa_code)`.
They produce signed semantic `FactId`s only after current authority, context,
and resource admission succeed. MFA is optional in the Rust type but may be
required by the configured deployment policy. Do not mutate `Roster` directly
to grant authority.

## Typed channels

`JoinedNetwork::channel::<T>(name)` returns a cloneable `Channel<T>` where `T`
implements `Serialize + DeserializeOwned + Send + Sync + 'static`.

```rust
#[derive(serde::Serialize, serde::Deserialize)]
struct Greeting { text: String }

let channel = joined.channel::<Greeting>("greetings");
let mut subscription = channel.subscribe()?;
channel.send_to(&peer_id, &Greeting { text: "hello".into() }).await?;
channel.send_to_acked(&peer_id, &Greeting { text: "peer acknowledged".into() }).await?;
let count = channel.broadcast(&Greeting { text: "hello all".into() }).await?;

if let Some(Ok(message)) = subscription.recv().await {
    println!("{}: {}", message.from(), message.body().text);
}
```

The exact implementation and borrow-only `ChannelMessage::{from,body}`
boundary are in [`channels.rs`](../crates/myownmesh-core/src/channels.rs#L136-L365).
`send_to` reports a dispatch result; `send_to_acked` resolves when the current
peer engine acknowledges handing the frame to its application layer. It does
not mean the application has processed or durably persisted the payload. A
session ending before that handoff is an error. `ChannelError` distinguishes network down, peer
not found, serialization/decode failure, transport, lag, resource pressure,
and admission refusal. A decode error retains the funded delivery until the
error is dropped.

`JoinedNetwork::send_reliable(peer, channel, serde_json::Value)` is the
lower-level acknowledged JSON operation. It is not a generic serializer and
does not replace typed channels.

## RPC

`JoinedNetwork::rpc()` returns a cloneable `Arc<Rpc>`. Register a handler with
`serve(method, closure)` or `serve_with_retention_claim`; the closure receives
an `RpcCall { from, request_id, method, payload, streaming }` and returns
`Result<RpcResponse, String>`. `RpcResponse::from_value` and
`RpcResponse::from_serialize` build responses. Registration is resource-backed
for the handler's lifetime; call `forget(method)` to remove the current
registration.

```rust
let rpc = joined.rpc();
rpc.serve("echo", |call| async move {
    Ok(myownmesh_core::RpcResponse::from_value(call.payload))
})?;

let response = rpc.call(
    &peer_id,
    "echo",
    serde_json::json!({ "message": "hello" }),
).await?;
println!("{}", response.body);
```

`call` returns an application-owned `RpcResponse`. `call_stream` returns an
`RpcStream`; its `recv()` yields `RpcStreamChunk` values and ends with `None`,
while `recv_funded()` exposes the funded terminal form for a forwarding layer.
Streaming handlers use `serve_stream` and return the core
`ResourceMailboxReceiver<RpcStreamItem>`, not a plain Tokio receiver. RPC
producers must send `RpcStreamItem::End(Ok(()))`; a producer that simply reaches
EOF is a failed stream, not a clean terminal. For exact replacement ownership,
use `prepare_serve`/`prepare_serve_stream` and then `PreparedRegistration::commit`
or `commit_with`; the resulting `OwnedMethodRegistration` removes only the
registration it installed when dropped, while `detach` deliberately leaves it
installed for `Rpc::forget` or gateway shutdown.
errors include network/session absence, timeout, remote handler errors,
serialization, transport, handler absence, and resource refusal. The full
registration/call signatures are in [`rpc.rs`](../crates/myownmesh-core/src/rpc.rs#L2770-L3230).
For exact owned registration, `prepare_owned_handler` demonstrates
`prepare_serve` → `commit` and the resulting cleanup owner;
`register_empty_stream_handler` demonstrates a funded stream producer with an
explicit `RpcStreamItem::End(Ok(()))`. For a bounded collection pattern, use
`consume_stream_bounded` rather than building an unbounded `Vec`.

Capability metadata is application-defined: `JoinedNetwork::advertise` stores
and sends a `CapabilityAdvert` (`tags`, optional `app_version`, and JSON
`extra`) only across live sessions; `Rpc::capabilities` reads the current
advertisement. Capability tags are hints, not authorization. The receiver must
still authenticate the peer and apply its own application policy.

## Semantic state and bootstrap

The production semantic methods on `JoinedNetwork` are bounded, resumable
storage operations: `import_semantic_fact_page`, `export_semantic_fact_page`,
`semantic_state_identity`, `recent_semantic_facts`, and
`compact_semantic_state`. Closed networks can additionally call
`export_bootstrap_record`; Open and Silent networks deliberately have no
Closed bootstrap record to export. These operations preserve canonical
signatures, context, causal dependencies, and owner-selected limits. A
refused limit is not a partial commit.

## Opaque and WebRTC realtime flows

The generic opaque flow API and the WebRTC provider API are distinct. Opaque
flows carry application-owned bytes without codec interpretation. A request is
constructed with `OpaqueFlowOpen::new(label, direction, mode, max_unit_bytes)`;
the representation ceiling is checked before provider admission. The returned
move-only `RealtimeFlowHandle` is the only authority for `send_opaque_flow`,
`change_opaque_flow`, `realtime_is_current`, and `close_realtime`.

```rust
use myownmesh_core::{OpaqueFlowMode, OpaqueFlowOpen, RealtimeFlowDirection};

let open = OpaqueFlowOpen::new(
    b"events".to_vec(),
    RealtimeFlowDirection::Outbound,
    OpaqueFlowMode::ReliableOrdered,
    4096,
).expect("representation-valid flow request");
```

Use the maintained [`send_and_close_opaque`](../crates/myownmesh-core/examples/application_patterns.rs)
helper from the repository example for the complete operation. It always
awaits close after a successful open and preserves send and close errors
independently; the repository examples are source references, not a published
crate dependency. Copy that control flow rather than sending and dropping an
open flow inline.

The important contract is that a successful open is always followed by an
awaited close, including when sending refuses.

The exact generic vocabulary and refusal codes (`session_not_current`,
`label_in_use`, `flow_refused`, and `provider_configuration_invalid`) are in
[`realtime.rs`](../crates/myownmesh-core/src/realtime.rs#L60-L530). A flow
handle is move-only, session-bound, and not serializable. Do not retain a peer
id plus label and re-resolve it after reconnect; that is intentionally not the
API. `realtime_inbound(peer)` claims one inbound stream. Use
`recv_opaque_flow`, `recv_webrtc_realtime_any`, or the mixed
`recv_realtime_arrival`; `None` means that exact session's stream ended.

WebRTC realtime uses the provider-qualified DTOs:
`WebRtcRealtimeFlowOpen`, `WebRtcRealtimeOutboundUnit`,
`WebRtcRealtimeInboundArrival`, and `WebRtcRtpKind`. A profile must register
the exact kind/MIME/clock-rate/channel capability before opening a flow.
`open_webrtc_realtime`, `send_webrtc_realtime`, and the same exact-handle close
path are the production methods. Codec registration and RTP interpretation
belong to the WebRTC profile, not the generic opaque vocabulary; provider types
are defined in [`provider.rs`](../crates/myownmesh-core/src/transport/webrtc/provider.rs#L40-L275).
The maintained `open_rtp_flow` and `receive_one_rtp` examples show the
caller-supplied profile and exact inbound-stream claim without introducing a
second flow or codec abstraction.

## Custody and enrollment (advanced host/daemon integration)

The public custody API is an advanced host/daemon-facing integration surface,
not an ordinary application data-plane operation. Use
`is_enrolled`, `enroll`, `require`, and `disable` to inspect or change this
device's local enrollment state. For transactional enrollment, use
`enrollment_transaction` and, when the transport-lab recovery feature is
enabled, `prepared_enrollments`; provisional workflows use
`install_provisional_enroll`,
`prepare_or_recover_provisional_enroll`, and
`recover_provisional_enrollments`. `ProvisionalEnrollment` and
`PreparedEnrollment` expose explicit `commit` and `abort` operations and
support restart redelivery. Dropping either prepared value does not mean
abort; finish the transaction deliberately.

These methods are local per-device/per-network signing custody and locking
facilities, not a remote quorum or application-authorization mechanism.
Enrollment can return secret or recovery material: keep it in protected host
storage, never log it, and do not assume a Unix file-permission convention on
Windows. The exact public signatures and ownership rules are in
[`custody.rs`](../crates/myownmesh-core/src/custody.rs#L119-L442).

## Recovery, reports, and failure handling

Treat `Error`, `ChannelError`, `RpcError`, and `RealtimeRefusal` as actionable
typed outcomes. A peer can be sighted or authenticated without being approved;
a connected channel is not by itself an authenticated application session.
Observe `MeshEvent`, `current_phase`, `peers`, and `traffic` rather than
inferring state from a successful queued command. Reconnect can establish a
new session, but old realtime handles and old session-scoped pending RPCs do
not silently transfer to the replacement.

Resource reports expose observations. `ResourceClaim` arithmetic is finite and
checked; a `ResourceLease` is non-cloneable and releases its exact reservation
on drop. Applications should hold a local application scope for their own
resource-backed state when needed, but must not treat a report or scope as
connector authority. Native cleanup failures remain conservative and are
reported rather than converted into a false zero baseline.

The root `myownmesh_core::Result<T>` and `Error` cover configuration, identity,
network, resource, semantic, and transport failures. Preserve the error at the
operation boundary when deciding whether to repair configuration, wait for a
peer, or create a fresh session; do not retry an operation whose documentation
marks its result ambiguous.

## Explicitly not application API

The following are intentionally excluded from the 1.0.0 embedding contract:

- `LocalBroker`, `attach_local`, and every `transport-lab` constructor/helper;
- `#[doc(hidden)]` semantic, parenting, transport, funded-RPC, and retired-flow
  controls;
- `NetworkState`, `engine::*`, `runtime::*`, connector worker/session types,
  raw provider leases, and internal signaling-driver types (the
  `SignalingDrivers` owner returned by `attach_signaling` is the documented
  lifecycle exception above);
- conceptual names in the older contract such as `list_meshes`,
  `mesh_snapshot`, `watch_mesh`, `request_session`, `watch_session`, and
  `open_realtime_flow` when used as if they were methods;
- the removed custom application relay/cipher routes, `ClosedRelay*`,
  `RoutedApplication*`, `application_transport`, and `routing_policy` APIs.

The abstract responsibility and workflow discussion remains in
[`APPLICATION-INTEGRATION.md`](../APPLICATION-INTEGRATION.md). That document
preserves historical evidence and architecture decisions; this file is the
practical source-linked Rust inventory.
