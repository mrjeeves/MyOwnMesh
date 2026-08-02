# MyOwnMesh implementation constraints and invariants

Status: normative implementation contract for [`ARCHITECTURE.md`](ARCHITECTURE.md).

This document states what a conforming implementation must and must not do. It deliberately keeps transport, signaling, connector, and session machinery inside MyOwnMesh while preventing transport placement from becoming semantic authority.
The staged transition of the existing Rust repository is defined in [`TRANSITION-PLAYBOOK.md`](TRANSITION-PLAYBOOK.md).

## 1. Required component boundary

A conforming implementation must expose equivalent responsibilities to:

```text
myownmesh-semantic-core
    canonical durable facts
    Open and Closed durable projection
    durable conflict and compaction rules

myownmesh-durable-store
    fact storage, verification material, semantic bases

myownmesh-signaling-runtime
    durable fact exchange
    ephemeral transport-control exchange
    carrier provenance and availability state

myownmesh-connector-runtime
    discovery, candidate gathering, racing, checks
    relay allocation, transport handshakes
    live measurement, migration, recovery

myownmesh-session-runtime
    endpoint authentication
    channel promotion
    session capability and application packet boundary

connector-profile-*
    direct LAN, ICE, TURN, generic relay,
    Closed member relay, non-IP profiles

myownmesh-application-api
    roster, reachability, session lifecycle,
    authenticated payload operations
```

These may share a process or source repository. The dependency and capability boundaries remain normative.

### 1.1 Prohibited dependency and authority edges

The following are prohibited:

```text
semantic-core -> concrete socket or carrier API
carrier identity -> durable fact authorship
signaling parser -> application delivery effect
application payload API -> durable fact or transport-signal constructor
connector callback -> direct session exposure
working channel -> implicit Device identity
relay allocation -> implicit endpoint authentication
route or candidate identifier -> application authority
durable store opening -> live session reconstruction
```

### 1.2 Test-only semantic-core build

A build with all networking disabled is useful for validating durable semantics, canonical encoding, projection, and compaction. It is not full MyOwnMesh conformance. A usable conforming product also implements signaling, at least one connector profile, endpoint authentication, and the application session boundary.

## 2. Required type separation

### 2.1 Durable semantic objects

The core durable envelope is typed and canonical:

```text
DurableFactContent {
    fact_version,
    mesh_context_digest,
    author_device_id,
    author_public_key,
    recipient_scope,
    domain_kind,
    predecessor_fact_ids,
    body
}

SignedDurableFact {
    content,
    signature
}
```

The core durable union must be closed for the selected mesh profile. Unknown domains, variants, fields, or encodings have no durable state transition.

Durable facts may include:

```text
OpenParticipation
ClosedGovernance
DurableCapabilityGrant
DurableCapabilityRevocation
reviewed OptionalApplicationContractFact
```

### 2.2 Ephemeral signaling objects

Ephemeral transport control is a separate closed union, for example:

```text
EphemeralTransportSignal =
    ConnectIntent
    | ConnectAnswer
    | CandidateHint
    | CandidateUpdate
    | RelayRequest
    | RelayResponse
    | CancelAttempt
    | RecoveryHint
```

The exact union is connector-profile-specific. It must be typed, bounded, and unavailable as a generic application byte carrier.

Ephemeral signals are not automatically:

- durable facts;
- content-addressed history;
- inputs to `Project`;
- roster or governance authority;
- application messages.

A profile may authenticate an ephemeral signal. Authentication strengthens attribution and resource policy for that signal. It does not convert it into durable authority unless a separately defined durable fact transition exists.

### 2.3 Live capabilities

At minimum, the runtime must use non-serializable or otherwise unforgeable local capabilities equivalent to:

```text
CandidateCapability
ConnectedChannelCapability
AuthenticatedChannelCapability
SessionCapability
LocalPrincipalCapability
ResourceReservationCapability
```

Public diagnostic IDs may index these objects, but the public ID alone cannot authorize mutation or use.

### 2.4 Live observations

Transport and reachability observations are local trace state:

```text
TransportObservation {
    candidate_or_channel_capability,
    expected_remote_device_if_known,
    connector_profile,
    state,
    local_observed_at_monotonic,
    measured_values_if_available
}
```

They are not durable participation or authorization facts.

## 3. Durable semantic validation

Every durable fact follows this order:

1. Reserve connection and frame resources before reading protected bytes.
2. Reserve parser bytes and work before decoding.
3. Reject noncanonical and unknown encodings.
4. Reserve hash work, then recompute the Fact ID.
5. Reserve identity and signature work, then derive the Device ID and verify the signature strictly.
6. Verify exact mesh context, scope, domain kind, shape, predecessor set, and protocol maxima.
7. Reserve dependency work before retaining missing-parent state or requesting evidence.
8. Verify the Open or Closed domain rule.
9. Classify as existing or new without visible mutation.
10. For new content, compute the hypothetical durable projection.
11. Reserve storage, materialization, durable-effect, and compaction claims.
12. Atomically commit the fact, proof, durable derived state, reservations, and pending durable effects.

A stricter local budget may refuse otherwise protocol-valid content. The result is local overload, incomplete view, or unavailability. It is not failed authorship or authorization.

## 4. `Project` and durable materialization

`Project` is reserved for deterministic durable semantic derivation:

```text
Project(context, scope, basis, facts) -> DerivedDurableState
```

The following names or implications are prohibited in the basal implementation:

```text
RouteProjection
ProjectedCurrentPath
ProjectedNextHop
GlobalRouteHead
ProjectedOnlineState
```

A cached incremental materialization must equal batch `Project` for equivalent explicit inputs under every covered topological delivery order and duplicate pattern.

Transport observations, candidate state, connector state, current channel state, packet replay state, and application queues are excluded from durable convergence claims.

## 5. Signaling runtime

### 5.1 Required signaling lanes

The signaling runtime must distinguish:

```text
Durable semantic exchange
Ephemeral transport-control exchange
```

Both may use the same carrier connection, but message classification occurs before domain-specific parsing and effect dispatch.

### 5.2 Signaling carriers

A signaling carrier may be:

- Nostr;
- mDNS or DNS-SD;
- WebSocket or another online service;
- direct peer signaling;
- file or shared storage;
- serial, radio, removable media, or another suitable medium.

The implementation must declare which signaling operations each carrier can satisfy. It must not claim that a one-way or delayed medium supplies the liveness of an interactive signaling channel.

### 5.3 Carrier provenance

Accepted durable facts deduplicate by Fact ID. Separately bounded local receipts record which carriers and connection instances delivered them.

Carrier provenance may guide availability policy and diagnostics. It cannot vote on fact validity, fork resolution, Open participation, Closed root selection, or endpoint identity.

### 5.4 Signaling prohibitions

The signaling runtime must not:

- expose a generic application-payload field;
- deliver signaling content as application data;
- synthesize Open withdrawal or Closed removal from disconnect;
- turn service identity into Device identity;
- create an authenticated session directly;
- allocate beyond its own measured bounds.

## 6. Connector runtime

### 6.1 Connector interface

A connector profile must expose equivalent operations to:

```text
start_attempt(local_intent, bounded_hints)
    -> CandidateCapability*

poll_or_receive_candidate(candidate_capability, typed_input)
    -> CandidateUpdate

try_candidate(candidate_capability)
    -> ConnectedChannelCapability
       | CandidateFailure

observe_channel(channel_capability)
    -> TransportObservation

close_candidate_or_channel(capability)
    -> Released
```

The exact API may be asynchronous or event driven.

### 6.2 Speculative work is allowed

An untrusted or partially authenticated hint may create bounded candidate work before durable policy and endpoint authentication complete.

The connector may allocate, under pre-authentication reservations:

- candidate objects;
- sockets and transport objects;
- DNS, STUN, ICE, or connector-specific queries;
- bounded TURN or relay allocation state;
- transport handshake state;
- bounded pre-authentication packet or media quarantine;
- timers, tasks, and observations.

This behavior is conforming and required for usability when it remains inside the pre-authentication envelope.

### 6.3 Pre-authentication prohibitions

Before channel promotion, the connector and transport stack must not:

- expose application payload to an application callback;
- accept a remote application operation;
- send application payload as an authenticated peer;
- create or mutate durable roster or governance state;
- issue an authenticated session handle;
- forward to an arbitrary relay destination;
- start unbounded decoding, queuing, fanout, or task creation.

A media profile may instantiate receivers or transport tracks before promotion. Samples remain in bounded quarantine or are discarded. Full application decode and delivery begin only after promotion unless the owner explicitly approves and measures a smaller safe pre-authentication decode stage.

### 6.4 Candidate racing

The connector may race direct, TURN, generic relay, Closed member relay, and other compatible candidates.

No security rule requires every higher-priority candidate to fail before a relay is attempted. Last-resort-only behavior is an optional local cost policy, not a security predicate.

The connector may select the first channel that satisfies the required operational and promotion conditions, or retain multiple authenticated channels for resilience.

### 6.5 No durable route identity

The connector must not require a durable ledger route object before attempting or using a path.

Local candidate and channel handles may exist for:

- callback correlation;
- resource accounting;
- diagnostics;
- cleanup;
- packet demultiplexing.

They must not become:

- durable mesh authority;
- cross-runtime route truth;
- application authorization;
- a globally current path record;
- a monotonic path generation.

### 6.6 Optional connector-native real-time flows

A connector may expose an optional real-time flow provider after a channel has been promoted into a live authenticated session. A connector may provision bounded native transport objects before promotion when its protocol requires them, but it may not expose or transmit application units before the promotion guard succeeds.

The common boundary may contain types such as:

```text
RealtimeFlowProvider
RealtimeFlowHandle
EncodedRealtimeUnit
RealtimeFlowObservation
```

Those types express only session binding, direction, lifecycle, bounded delivery, and connector capability. They must not assign application meaning.

The basal core must not define or require:

- `LaneKind::Video` or `LaneKind::Audio`;
- H.264, Opus, screen, camera, microphone, or product-specific codec semantics;
- a globally fixed media-lane count;
- track numbers as application or mesh authority;
- a media flow on every connector.

A WebRTC implementation may keep RTP, RTCP, transceivers, native track setup, m-line reuse, and drain behavior inside a WebRTC-specific extension. Application or compatibility adapters map application codec and purpose onto those native flows. A data-only connector that reports no real-time flow capability remains conforming.

During migration, legacy `MediaLaneOpen`, `MediaLaneClose`, `VideoSample`, `AudioSample`, H.264, and Opus APIs may remain only as a compatibility facade over the optional real-time flow provider. No new product behavior may be added to that facade, and it must have a named deletion arc.

## 7. Endpoint authentication and channel promotion

### 7.1 Required endpoint-authentication binding

The endpoint-authentication profile must bind:

- exact local and remote Device IDs;
- exact MeshContext digest;
- exact connected channel or channel exporter;
- fresh contributions from both endpoints;
- ordered endpoint roles;
- negotiated cryptographic profile;
- any connector transcript fields whose alteration could substitute the channel or endpoint.

A signaling account, ICE username, DTLS certificate not bound to the Device ID, TURN credential, IP address, or relay identity cannot substitute for this proof.

### 7.2 Promotion transition

Only the session runtime may promote a connected channel.

The promotion guard must include:

```text
channel is currently live
fresh mutual Device authentication succeeded
mesh context matches exactly
Open or Closed policy currently allows the peer
local principal is authenticated and allowed
post-authentication session resources are reserved
fresh opaque SessionCapability is reserved
```

The promotion state and handle exposure commit atomically or not at all.

### 7.3 Handle use

Every application operation must recheck:

- live `SessionCapability`;
- exact local and remote Device IDs;
- exact mesh context;
- current Open or Closed policy;
- authenticated local principal;
- current authenticated channel set;
- current resource reservation;
- session not closed.

A public session number or diagnostic identifier is never sufficient.

### 7.4 Restart

After runtime restart, old session, channel, candidate, replay-window, and local-principal capabilities are absent. Durable state may guide a new attempt but cannot recreate an old session.

No scalar session generation or durable session high-watermark is required by the basal architecture.

## 8. Open and Closed constraints

### 8.1 Open

A valid self-authored Open participation fact must not require:

- sponsorship;
- owner approval;
- pair permission;
- identity-count vote;
- proof of work;
- application approval.

A valid Open participant or an untrusted hint may begin bounded candidate work. Session promotion still requires exact endpoint authentication and the current Open participation rule.

### 8.2 Closed

Closed promotion requires the exact locally accepted Closed authorization proof selected by the context.

The connector may perform bounded speculative work while Closed proof validation occurs. An unauthorized or unknown endpoint is closed or left unpromoted after the proof result. No application payload is exposed.

Closed governance and relay authorization must not depend on carrier count, arrival order, socket health, or a central signaling service unless the selected Closed profile explicitly adopts such a premise.

## 9. Relays

### 9.1 Infrastructure relay

TURN and a generic opaque relay may carry endpoint packets for one exact A-C session. They are not mesh participants or application endpoints by that function.

### 9.2 Closed member relay

A Closed member relay is allowed when the selected Closed profile permits it.

The relay is visibly attributable to Device B. The basal profile must reject anonymous relay credentials.

Relay eligibility may be:

```text
current Closed authorization for B
+ current signed relay offer from B
+ local policy at A, B, and C
```

A stricter Closed profile may additionally require a durable relay capability granted by the selected governance system.

### 9.3 Relay allocation

A relay allocation must be ephemeral live state and must bind:

- exact mesh context;
- exact endpoints A and C;
- exact relay B or service instance;
- exact allocation capabilities for each endpoint;
- bounded lifetime, buffering, bandwidth, retry, and queue resources.

The allocation must not accept:

- arbitrary host or port supplied in each packet;
- application fanout;
- another relay as recursive destination in the basal profile;
- application plaintext;
- mesh governance or durable fact mutation.

### 9.4 Relay authentication

B may authenticate setup using its Device key or an already authenticated Device channel. A separate relay operational key is optional only for narrower private-key custody and process isolation. It must be visibly delegated by B and must not be anonymous.

Relay packets must use transport or per-allocation packet authentication. B's long-term Device key is not used to sign every packet.

## 10. Handoff and recovery

### 10.1 Endpoint-driven handoff

A handoff is implemented by:

1. keeping the current authenticated channel usable where possible;
2. attempting replacement candidates speculatively;
3. establishing a working replacement channel;
4. performing fresh endpoint authentication or current-session channel key confirmation on that channel;
5. adding the channel to the live authenticated channel set;
6. selecting locally among authenticated channels;
7. closing or retaining old channels according to local policy.

### 10.2 Handoff prohibitions

The basal implementation must not require:

- durable `PathOffer`, `PathAccept`, `PathRetire`, or global `PathID` facts;
- a monotonic path generation;
- a global current-route record;
- relay-to-relay state transfer;
- old-relay authorization of the new relay;
- a simultaneous network-wide cutover.

### 10.3 Replay and delayed callback handling

A replacement channel uses fresh endpoint-authentication or key-confirmation material bound to that channel.

Old control messages may create only bounded duplicate candidate work. Old channel packets fail channel-specific replay and integrity checks. Delayed connector callbacks must present the exact live local capability they mutate.

### 10.4 Suspension and recovery

If no authenticated channel is currently usable, the session is `Suspended`. The connector may continue bounded recovery. The application receives no usable payload operation until an authenticated channel is restored or newly promoted.

## 11. Reachability

The runtime must keep durable participation or authorization separate from local reachability evidence.

At minimum, it should distinguish:

```text
Durable roster state
Signaling responsiveness observation
Candidate connectivity observation
Authenticated channel observation
Application session state
```

Freshness uses local monotonic observation time.

No missing observation, carrier disconnect, expired timer, or failed candidate may synthesize Open withdrawal, Closed removal, or application denial.

A diagnostic API may expose latency, loss, carrier kind, relay identity, and local observation age. Those fields are observations, not authority.

## 12. Persistence and compaction

### 12.1 Durable-only persistence

The durable store may persist:

- accepted durable facts and author proofs;
- derived durable state or materialized indexes;
- verified semantic bases;
- durable pending effect intents;
- bounded delivery provenance where selected.

It must not restore as live authority:

- candidates;
- sockets;
- relay allocations;
- transport channels;
- endpoint-authentication sessions;
- traffic keys;
- packet replay windows;
- reachability observations;
- application session handles;
- local-principal capabilities;
- runtime resource reservations.

### 12.2 Compaction

A replacement durable basis must be:

- sufficient for ordinary durable projection;
- independently verifiable under immutable context and domain commitments;
- sufficient for the adopted future durable continuation contract;
- explicit about unresolved exclusive conflicts.

Predecessor-base storage is optional only when deleting it does not change base verification, durable projection, or permitted durable continuation validation.

Compaction has no route, channel, or reachability meaning.

## 13. Application interface

The ordinary application API must expose:

```text
mesh roster view
reachability and session observations
request_session(mesh_context, remote_device_id)
watch_session(session_operation_or_handle)
close_session(session_handle)
a closed set of payload operations over SessionCapability
optional connector-native real-time flow capability when supported
```

Codec, media role, and product semantics belong to the application or an optional application-facing profile. The core may expose transport-native flow capability, but it must not expose H.264, Opus, screen, camera, or audio meaning as mesh semantics.

The ordinary API must not expose:

- raw durable fact construction;
- raw ephemeral transport-signal construction;
- candidate or route injection;
- relay destination selection;
- signaling publication control;
- endpoint-authentication transcript injection;
- a route graph;
- a persistent session generation as authority.

Carrier diagnostics are separate from peer identity and application authorization.

## 14. Resource model

### 14.1 Pre-authentication resource class

The owner must measure and select finite bounds for:

- accepted connections and half-open handshakes;
- frame and parser bytes;
- durable-fact hash and signature work;
- ephemeral signaling parse work;
- candidate objects;
- sockets and transport objects;
- DNS, STUN, ICE, relay, and connector-specific work;
- pre-authentication media or packet quarantine;
- timers, tasks, callbacks, and diagnostic queues;
- cleanup.

Bounds apply per ingress source where meaningful and globally regardless of identity.

### 14.2 Post-authentication resource class

Separate bounds apply to:

- authenticated sessions;
- application queues;
- media decode and encode;
- relay bandwidth and buffering;
- session recovery;
- application callbacks;
- local handle and subscription state.

A successful pre-authentication reservation cannot be reused as proof that post-authentication capacity exists.

### 14.3 Effect execution

State and effect intents commit before external execution. Every effect carries exact live capabilities and reservations and rechecks them before use. Cleanup effects remain available even when the authority for new work disappears.

## 15. Fundamental invariants

### I1. Hybrid architecture

Durable semantics, signaling, connector work, endpoint authentication, and application sessions are all first-class MyOwnMesh components.

### I2. Transport independence

Transport substitution cannot change the authority or meaning of an accepted durable fact.

### I3. Transport is not removed

A usable networking implementation requires live signaling or discovery where needed, a connector profile, endpoint authentication, and packet carriage.

### I4. Projection is durable derivation only

`Project` never means route creation, route selection, topology truth, or forecasting.

### I5. Open remains open

Open self-participation has no third-party admission predicate.

### I6. Closed alone adds governance authorization

Closed may be fully locked down under its selected proof system.

### I7. Durable and ephemeral signaling are distinct

Transient transport negotiation is not automatically retained as durable history.

### I8. Speculative work is allowed

Untrusted input may cause bounded candidate and handshake work.

### I9. Speculative work is confined

Pre-authentication work cannot create durable authority, application delivery, or an authenticated session handle.

### I10. Work is reserved before allocation

Every protected parser, candidate, socket, relay, handshake, queue, and session allocation is dominated by its resource guard.

### I11. A working socket is not a session

Channel promotion requires exact endpoint authentication, exact context, mesh policy, local principal, resources, and a fresh capability.

### I12. No durable route identity is required

The basal network does not require a ledger route object, global path record, or monotonic path generation.

### I13. Local connector capabilities own callbacks

A delayed callback cannot mutate a replacement object without the exact live capability.

### I14. Carrier is not endpoint identity

Direct, TURN, generic relay, and Closed member relay preserve the same A-C endpoint identity after promotion.

### I15. Closed member relay is visible

The relay is attributable to its Device identity. Anonymous relay attestation is prohibited in the basal profile.

### I16. Relay allocation is exact and bounded

A relay allocation has one exact endpoint pair, no arbitrary destination, no fanout, and finite resources.

### I17. Relay cannot promote or switch

A relay cannot add a channel to an endpoint's authenticated set or authorize a handoff.

### I18. No relay-to-relay handoff dependency

Replacement transport can be established without old-relay to new-relay signaling.

### I19. Handoff is endpoint-driven

Only endpoint authentication or current-session channel confirmation can make a replacement channel usable.

### I20. No global current path

Endpoints may temporarily use different or multiple authenticated channels.

### I21. Signaling and payload are disjoint

No supported signaling operation carries ordinary application payload.

### I21a. Media semantics are not core authority

Connector-native real-time flows may be part of the live session data plane, but codec, media purpose, lane numbering, and product meaning cannot affect mesh identity, durable authority, channel promotion, or session authorization.

### I22. Application payload requires a live session capability

A record, hint, candidate, channel, or relay allocation alone is insufficient.

### I23. Reachability is positive local evidence

Absence, expiry, and transport failure do not synthesize durable roster change.

### I24. Durable store opening does not restore live networking

Sockets, keys, replay state, connectors, observations, and handles start absent.

### I25. Compaction affects durable semantics only

Compaction has no authority over routes or live channel state.

### I26. One owner for each state class

The semantic core owns durable projection, the connector owns candidate and channel state, and the session runtime owns promotion and application session state.

### I27. Adapters cannot bypass owners

Carrier parsers and callbacks enter as typed inputs and cannot mutate another component's state directly.

### I28. Stale effects are suppressed

Effects recheck exact capabilities, policy, and resources before execution.

### I29. Complete eclipse is not claimed solved

The runtime does not claim global completeness or guaranteed revocation freshness without an explicit additional premise.

### I30. Optional contracts are confined

Application consensus or smart-contract domains do not become basal networking requirements.

## 16. Conformance matrix

A release must pass at least the following groups.

### 16.1 Durable semantics

- canonical positive and negative vectors;
- Open permissionless positive controls;
- Closed unauthorized-key negatives;
- delivery-order and duplicate equivalence;
- exclusive-fork confinement;
- compaction equivalence.

### 16.2 Signaling

- durable and ephemeral parser separation;
- carrier identity non-authority;
- no carrier-synthesized roster changes;
- bounded frame, queue, retry, and provenance state;
- no application payload construction.

### 16.3 Speculative transport

- raw hints can create bounded candidate work;
- global resource limits hold under identity rotation;
- malformed and unauthorized inputs cannot cross promotion;
- media and packets remain quarantined before promotion;
- cleanup completes at every failure point.

### 16.4 Promotion

- independently remove every `MayPromote` conjunct;
- endpoint identity mismatch closes the channel;
- cross-context and cross-channel replay fail;
- old durable facts and old control signals do not recreate handles;
- every send and receive rejects stale or foreign-principal capabilities.

### 16.5 Connectors and recovery

- direct, TURN, generic relay, and Closed member relay positive controls;
- candidate racing and first-working-path behavior;
- restrictive-network matrix;
- two authenticated channels active concurrently;
- handoff with no relay-to-relay messages;
- delayed old callbacks cannot mutate replacement state;
- forced old-path failure cannot promote an unauthenticated new path;
- native real-time flows are optional connector capabilities bound to a live session;
- fixed codec and application-media semantics are absent from the basal core;
- pre-promotion track setup cannot reach application delivery.

### 16.6 Relay

- exact endpoint allocation;
- no arbitrary destination or fanout;
- visible member-relay identity;
- anonymous relay credential rejection;
- relay endpoint-substitution negatives;
- measured allocation, buffer, retry, and bandwidth limits.

### 16.7 Reachability and application boundary

- observation age uses local monotonic time;
- failed observations do not mutate roster;
- signaling success with no carrier returns a no-path result;
- application receives no data before promotion;
- explicit application intermediary remains a separate application workflow.

### 16.8 Persistence and crash

- store opening creates no live transport or session state;
- pending effect recovery is idempotent;
- current durable basis is independently reopenable;
- rollback without an independent witness preserves the documented impossibility result.

## 17. Required implementation artifacts

A conforming implementation supplies:

1. package and dependency graph;
2. complete accepted-input and effect inventory;
3. durable canonical test vectors;
4. endpoint-authentication and channel-binding test vectors;
5. connector profile specifications;
6. resource measurement report for every supported target;
7. model or property tests for durable projection and conflict;
8. speculative-work and promotion state model;
9. crash and effect-idempotency model;
10. red-team evidence bundle for the target catalog;
11. proof that application payload cannot reach signaling constructors or effects;
12. proof that no durable route or monotonic path-generation dependency remains in the basal path.

## 18. Owner decisions

The owner must select:

- exact cryptographic profiles;
- Closed governance proof and relay authorization profile;
- signaling and connector profiles;
- required egress and restrictive-network environments;
- pre-authentication and post-authentication resource values;
- session recovery and multi-channel policy;
- reachability display and freshness policy;
- application data-operation set;
- optional durable application contract domains.

Every numeric value requires measurement and review.
