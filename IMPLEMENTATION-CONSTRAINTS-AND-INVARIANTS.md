# MyOwnMesh implementation constraints and invariants

> Current normative cutover (2026-09-09): application data uses endpoint-authenticated WebRTC, directly or through configured standard TURN. Hubs provide discovery/introduction only, never application plaintext or ciphertext transit. This supersedes custom encrypted Hub and Closed-member payload relay requirements. Open/Closed governance is unchanged. Historical exact-head evidence below remains historical; this edit is not an implementation, runtime, or release PASS.

In the current model, packet-relay allocation means configured standard TURN, not a mesh-member payload service. Nostr/signaling relay terminology refers only to its bounded control carrier. Existing accounting-dimension names do not grant payload-forwarding authority.

Status: normative implementation contract for [`ARCHITECTURE.md`](ARCHITECTURE.md).

This document states what a conforming implementation must and must not do. It deliberately keeps transport, signaling, connector, and session machinery inside MyOwnMesh while preventing transport placement from becoming semantic authority.
The staged transition of the existing Rust repository is defined in [`TRANSITION-PLAYBOOK.md`](TRANSITION-PLAYBOOK.md).

## 1. Required component boundary

A conforming implementation must expose equivalent responsibilities to:

```text
myownmesh-semantic-core
    canonical durable facts
    Closed durable authority projection
    Open runtime-participant projection
    durable conflict and compaction rules

myownmesh-durable-store
    fact storage, verification material, semantic bases

myownmesh-signaling-runtime
    durable fact exchange
    ephemeral transport-control exchange
    carrier provenance and availability state

myownmesh-connector-runtime
    discovery, candidate gathering, bounded remote ICE application, checks
    relay allocation, transport handshakes
    live measurement, migration, recovery

myownmesh-session-runtime
    endpoint authentication
    channel promotion
    session capability and application packet boundary

connector-profile-*
    native direct WebRTC, ICE, configured standard TURN,
    non-IP profiles

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

The base durable fact union is Closed authority/governance only:

```text
RoleGrant | RoleRevoke | Evict | MembershipAdmit | EvictionProof |
SelfStandDown | Attestation | Resolution | AuthorityLineageResolution
```

Reviewed application contract facts, if enabled, use a separately selected
domain and are not base Closed authority. Open has zero base durable semantic
facts. Exact-context endpoint authentication and Device-key possession admit
ephemeral Open participation; runtime join, leave, presence, and reconnect
for both Open and Closed remain local observations and never enter semantic
history.

### 2.2 Ephemeral signaling objects

Ephemeral transport control is a separate closed union, for example:

```text
EphemeralTransportSignal =
    ConnectIntent
    | ConnectAnswer
    | CandidateHint
    | CandidateUpdate
    | HubIntroductionRequest
    | HubIntroductionResponse
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
ConnectorCandidateCapability
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

They are not durable facts or authority inputs.

## 3. Durable semantic validation

Every durable fact follows this order:

1. Reserve connection and frame resources before reading protected bytes.
2. Reserve parser bytes and work before decoding.
3. Reject noncanonical and unknown encodings.
4. Reserve hash work, then recompute the Fact ID.
5. Reserve identity and signature work, then derive the Device ID and verify the signature strictly.
6. Verify exact mesh context, scope, domain kind, shape, predecessor set, and protocol maxima.
7. Reserve dependency work before retaining missing-parent state or requesting evidence.
8. Verify the selected Closed governance rule; an Open handshake is an
   ephemeral session gate and never a durable-fact transition.
9. Classify as existing or new without visible mutation.
10. For new content, compute the hypothetical durable projection.
11. Reserve storage, materialization, durable-effect, and compaction claims.
12. Atomically commit the fact, proof, durable derived state, reservations, and pending durable effects.

A stricter local budget may refuse otherwise protocol-valid content. The result is local overload, incomplete view, or unavailability. It is not failed authorship or authorization.

### 3.1 Base-ledger admission and retention

The semantic owner selects finite limits for retained fact count, canonical
encoded bytes, causal-edge count, per-author count/bytes and retained
lifetime, proof-verification work, dependency quarantine, and indexed database
bytes.
These limits are explicit owner policy, not hidden protocol defaults. Before
any mutation, the owner computes the complete candidate delta and refuses the
exact `N+1` fact or dependency if any selected dimension would be crossed.
The refusal occurs before graph, projection, acknowledgement, identity, or
authority change and consumes no retained semantic record.

Missing-parent facts may enter only a bounded quarantine indexed by their
exact dependencies. Quarantine entries, reverse indexes, proof history, and
failure records consume the same finite budget. Duplicate Fact IDs are
semantic no-ops and are rejected or idempotently reported without extending
history;
invalid, unauthorized, or stale inputs likewise cannot change identity or
authority. An eligible-signer quarantine has the same owner-selected count,
byte, per-author, lifetime, and proof-work ceilings as ordinary facts.

The persistent implementation is a local-only indexed SQLite store with one
semantic writer on one dedicated blocking thread and one ordinary SQLite
connection using SQLite's default VFS, WAL journaling, `FULL` synchronous
durability, and an
explicit database plus WAL/reserve ceiling. For the `StorageBytes` dimension,
one process-accounted claim is `B = M + W + S + R`: main database bytes, WAL
bytes, shared-memory/sidecar bytes, and explicit reserve. Named-file
containment or VFS accounting is not backing-disk, filesystem-metadata, or
ENOSPC proof; those remain residuals until an exact provider contract proves
them. Exact proof history is retained until an archive or authority-ratified
checkpoint makes semantic deletion safe. The shipped compaction boundary is
bounded checkpointing only; a full-copy SQLite `VACUUM` requires separately
funded temporary-copy, metadata, and cleanup custody. No timer silently evicts
or prunes semantic history. Per-author retained lifetime caps are cleanup
bounds, not authority expiry: an expired retained entry is settled by its
exact owner path and cannot rewrite a fact.

For owner limits `C` (facts), `B` (bytes), `E` (edges), `A` (per-author), `P`
(proof work), `Q` (quarantine), and `D` (database/WAL bytes), admitted growth
is bounded by the finite vector and its indexed overhead. Failure spam is
bounded by the same vector and per-author ceilings: once the next candidate
would exceed a dimension it is refused before mutation, ACK, or identity
change. A failed cleanup retains its exact charge until an observed terminal
settlement rather than silently freeing or losing accounting.

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

Carrier provenance may guide availability policy and diagnostics. It cannot vote on fact validity, fork resolution, Closed authority selection, or endpoint identity.

### 5.4 Signaling prohibitions

The signaling runtime must not:

- expose a generic application-payload field;
- deliver signaling content as application data;
- synthesize a durable fact, withdrawal authority, or Closed removal from disconnect;
- turn service identity into Device identity;
- create an authenticated session directly;
- allocate or retain protected resources without live provider leases.

## 6. Connector runtime

### 6.1 Connector interface

A connector profile must expose equivalent operations to:

```text
start_attempt(local_intent, bounded_hints)
    -> ConnectorCandidateCapability*

poll_or_receive_connector_candidate(connector_candidate_capability, typed_input)
    -> ConnectorCandidateUpdate

try_connector_candidate(connector_candidate_capability)
    -> ConnectedChannelCapability
       | ConnectorCandidateFailure

observe_channel(channel_capability)
    -> TransportObservation

close_candidate_or_channel(capability)
    -> Released
```

The exact API may be asynchronous or event driven.

One connection attempt may own multiple connector candidates. One WebRTC connector candidate owns one `RTCPeerConnection` and one ICE agent. The ICE agent may own multiple internal ICE candidates and pairs. An internal ICE candidate is typed control input, not a `ConnectorCandidateCapability`.

### 6.2 Speculative work is allowed

An untrusted or partially authenticated hint may create bounded candidate work before durable policy and endpoint authentication complete.

The connector may allocate, under pre-authentication reservations:

- candidate objects;
- sockets and transport objects;
- DNS, STUN, ICE, or connector-specific queries;
- bounded standard TURN allocation state;
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

### 6.4 Bounded remote ICE-candidate application

The current WebRTC connector uses its bounded planner to order and apply the
admitted queued remote ICE candidates. The planner's path identifiers describe
those candidate applications only; they do not prove a production race among
direct WebRTC and configured standard TURN paths; there is no custom member-relay channel family.

ICE may still gather host, server-reflexive, and relay candidates according to
the connector configuration. No security rule requires a higher-priority ICE
candidate to fail before another admitted candidate is applied;
last-resort-only behavior remains an optional local cost policy, not a security
predicate.

Selection of a working connector channel and promotion into an authenticated
session remain separate boundaries. A future cross-connector racer must own and
bound its actual channel candidates rather than treating this remote-candidate
application planner as that implementation.

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

- a fixed video or audio flow kind;
- H.264, Opus, screen, camera, microphone, or product-specific codec semantics;
- a globally fixed media-lane count;
- track numbers as application or mesh authority;
- a media flow on every connector.

A WebRTC implementation may keep RTP, RTCP, transceivers, native track setup, m-line reuse, and drain behavior inside a WebRTC-specific extension. Application or compatibility adapters map application codec and purpose onto those native flows. A data-only connector that reports no real-time flow capability remains conforming.

No compatibility facade over the real-time flow provider exists or may be reintroduced. The `MediaLaneOpen`, `MediaLaneClose`, `VideoSample`, `AudioSample`, and fixed H.264/Opus APIs are deleted; their absence from the public API is a property of the public API itself.

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

**Selected alternatives (Arc 04).** The requirements above are unchanged; this records which permitted alternative is in force and how it is composed.

- *Exact connected channel or channel exporter*: the **channel** alternative was selected, and it is satisfied by composition rather than by any single term. The peer-agreed cryptographic binding term is both endpoints' DTLS certificate fingerprints in role-canonical order. **The fingerprint pair alone does not establish exact-channel binding** — reused certificates make it non-session-unique. Exactness of the overall promotion comes from two further parts: the two fresh bilateral contributions, which bind the transcript to *this attempt*; and the non-transferable, connector-incarnation-owned handoff and capability, which bind the promotion to *this live connector*. The RFC 5705 exporter alternative is **deferred**: it is implemented in `webrtc-dtls` but unreachable, since `DTLSConn.state` and `RTCDtlsTransport::conn()` are both crate-private, so reaching it would require vendoring a third dependency while vendored-tree integrity remains an open gate.
- *Negotiated cryptographic profile*: realised as a closed single-variant selection (`EndpointAuthProfile::V1Ed25519Dtls`), **fixed** by the protocol and taken in `context`, and bound into the transcript as its own signed length-prefixed field. The requirement is met by construction rather than by runtime agreement: no other inhabitant exists, so no caller and no peer can select anything weaker. The one peer-facing input is the `endpoint_auth_v1` advertisement, and it is a **fail-closed compatibility precondition, not a weaker-profile negotiation**: it decides only whether an attempt begins at all. A peer that omits it is refused with a typed incompatible-profile cause before any transcript is assembled and before any signature is produced or verified, so there is no fallback, no downgrade path, no free-form profile string, and no third outcome. That refusal belongs to the setup vocabulary rather than the attempt-terminal one — the gate runs on the inbound Hello before the attempt is reached, so it terminalizes nothing, and what fails the connection closed is the handler's own drop of the exact current peer. Because the selected profile is itself a signed transcript field, an advertisement can never widen or replace what the transcript commits to.
- *Residual, and it is load-bearing*: because the binding term is not session-unique, replay across channels is prevented by the two per-attempt CSPRNG contributions, and transfer or survival of an already-issued capability is prevented by exact connector-incarnation ownership. Ownership does not make an otherwise-valid signature invalid, and the binding does not separate sessions — neither mechanism substitutes for the other.

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

Open has no durable participation fact or durable join/leave predicate. An
exact-context endpoint handshake proving Device-key possession establishes
ephemeral participation without sponsorship, owner approval, pair permission,
identity-count vote, proof of work, or application approval. A valid Open
participant or an untrusted hint may begin bounded candidate work. Session
promotion still requires exact endpoint authentication and current local
runtime policy; join, leave, presence, and reconnect never enter semantic
history.

### 8.2 Closed

Closed promotion requires the exact locally accepted Closed authorization proof selected by the context.

The connector may perform bounded speculative work while Closed proof validation occurs. An unauthorized or unknown endpoint is closed or left unpromoted after the proof result. No application payload is exposed.

Closed governance and endpoint authorization must not depend on carrier count, arrival order, socket health, or a central signaling service unless the selected Closed profile explicitly adopts such a premise.

## 9. Standard TURN and bounded Hub introduction

### 9.1 Endpoint packet carriage

Application data uses native endpoint-authenticated WebRTC directly or through
configured standard TURN. TURN is infrastructure, not a mesh member or an
application endpoint by that function. Device/context authentication and
Open/Closed policy gates remain mandatory independently of ICE success or
TURN credentials.

### 9.2 No Hub/member payload forwarding

Hubs consolidate discovery and bounded introduction only. Neither Hubs nor
ordinary Open/Closed members forward application plaintext or ciphertext.
Existing typed semantic-control and setup/control remain supported signaling
traffic; signaling cannot become an application-data tunnel. If no viable
direct/TURN endpoint transport exists, refuse with the bounded failure result.

### 9.3 Configuration and service boundary

Use `introduction: Option<HubIntroductionPolicyConfig>`. Removed
`closed_relay`, `application_transport`, `endpoint_cipher`, and
`routing_policy` fields and removed wire forms must refuse. No custom
endpoint route cipher or member-relay allocation is an allowed compatibility
path. Native opaque channels, realtime, and RPC remain endpoint operations.

TURN service is distinct even when cohosted with a Hub. Current service
advertisements are URL-only; credentials are locally configured. No protected
credential-distribution mechanism is claimed.

### 9.4 Resource and cleanup custody

Standard TURN/native transport work retains finite owner/provider accounting,
including explicit opaque-dependency residuals and external-service limits.
Do not apply deleted custom route-allocation semantics as if they were a
standard TURN guarantee. Close/cancellation must settle existing owned work
or report retained failure; a timeout alone is not task completion. A proposed
new native-runtime owner is not an implemented architecture requirement.

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

The runtime must keep the durable Closed authority projection separate from
local reachability evidence. Open participation is ephemeral and has no
durable projection.

At minimum, it should distinguish:

```text
Durable roster state
Signaling responsiveness observation
Candidate connectivity observation
Authenticated channel observation
Application session state
```

Freshness uses local monotonic observation time.

No missing observation, carrier disconnect, expired timer, or failed candidate
may synthesize a durable fact, Open runtime withdrawal authority, Closed
removal, or application denial.

A diagnostic API may expose latency, loss, carrier kind, TURN service observation, and local observation age. Those fields are observations, not authority.

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

The shipped operation is bounded checkpointing/reopen verification, not a
funded full-copy rewrite. A checkpoint or WAL truncation may reclaim physical
WAL space only within the single `StorageBytes` claim. A `VACUUM` or equivalent
rewrite is outside this contract until temporary database bytes, metadata,
copy work, and terminal cleanup are separately charged and observed.

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

### 14.1 Normative resource contract

Every protected allocation, retained value, task, queue entry, native object, and scheduled work unit must hold a live finite lease issued by the applicable resource provider. Basal MyOwnMesh defines no fixed semantic cardinality for Mesh runtimes, peers, connector attempts, sessions, or real-time flows.

The resource interface must provide equivalent responsibilities to:

```text
ResourceProvider
    acquire(ResourceClaim, ResourceAuthorityClass)
        -> ResourceLease
         | ResourcePressure(ResourceClass)
         | ResourceUnavailable(ResourceClass)
    transition(live lease, ResourceClaim, ResourceAuthorityClass)
        -> the held claim is replaced exactly, or the transition fails
           and the lease keeps what it already held
    release(exact owner, after that owner's cleanup)
        -> the exact charge returns to the grant
    retain_after_failed_cleanup(exact owner)
        -> the exact charge stays charged, with no live lease behind it

ResourceClaim
    finite quantities by ResourceClass

ResourceLease
    exact provider, claim, owner, and live release authority

ResourceClass
    AccountedMemory
    QueuedBytes
    SocketOrHandle
    NativeTransportObject
    WorkerOrTask
    CallbackOrScheduledWork
    StorageBytes
    StorageObject
    RelayOrProviderAllocation
    ParsingOrCpuWork
    OpaqueDependencyResidual
```

A claim may combine several resource classes. An admitted object's count emerges from the claims and current provider grant. There is no `unlimited` sentinel. Admission is always fallible.

Those four are the whole basal operation set. Retaining a pending demand and requesting retirement from a reclaimable owner are **optional provider extensions**: a provider may offer either, the properties below constrain it when it does, and nothing in basal MyOwnMesh may require, assume, or depend on either being present. The basal interface above is immediate-only: it gives a non-fitting acquisition nowhere to wait, so under it — and so under the shipped provider — such an acquisition is answered at once with typed pressure. A provider that adds the pending-demand extension may retain the demand instead, on the terms P4 states.

The process resource root owns the process grant. Each Mesh runtime receives an AttributionChildScope for accounting, not a new grant. Attempt, candidate, session, and flow owners receive descendant leases. Creating another scope cannot multiply capacity.

The basal requirements on the finite provider are properties, not a scheduling algorithm. A conforming provider must preserve all of:

```text
P1 Domain conservation
    the sum of live and failed-cleanup-retained claims in each resource
    dimension never exceeds the grant actually assigned to the process;
    a claim never exceeds the provider domain it is drawn from

P2 Cleanup ownership
    only the exact owner releases a claim, and only after cleanup; no
    provider, peer, message, or timer can forge a release, and resources
    a cleanup path requires stay retained until that cleanup completes

P3 No minting
    no scope, child scope, or identity creates capacity

P4 Work conservation
    capacity that is neither live nor reserved for an in-flight
    admission is borrowable by any scope that can use it. A provider
    may return immediate typed pressure instead of retaining a demand
    only when the claim does not currently fit. A claim that does fit
    is admitted, unless the refusal is justified by a proven structural
    limit of the provider, by an explicit isolation policy or optional
    local ceiling under P5, or by accounting that is unavailable,
    poisoned, or otherwise unable to prove the admission safe. Every
    such reason is declared. Arbitrary refusal is prohibited and can
    never stand as a hidden limit

P5 Explicit isolation
    every partition, reserved share, or isolation ceiling is explicit
    local policy, never a basal guarantee

P6 Partition non-amplification
    subdividing a fairness root's attribution into more child scopes
    must not increase that root's cumulative selections, or its
    cumulative admitted quantity in any dimension, at any point of the
    provider's decision sequence, and must not move any competing
    root's selection later. One-way only: no equality of outcome is
    implied

P7 Pressure is not authorization
    refusal, pressure, and unavailability are typed resource results,
    never an Open or Closed authorization outcome in either direction

P8 Time is not resource truth
    elapsed duration alone creates, releases, expires, and validates
    nothing
```

`FairnessRoot` and `AttributionChildScope` are closed architectural definitions owned by [`ARCHITECTURE.md`](ARCHITECTURE.md). This document does not restate or narrow them; it uses them exactly as defined there. Where a term below carries additional detail, that detail implements the canonical definition and never competes with it. If the two ever diverge, ARCHITECTURE governs and this document is wrong.

What this document owns is the trusted local mapping and its provenance, the typed provider states, and the provider-specific mechanics that make the canonical properties checkable.

A scope is an accounting subdivision. It is never itself a claimant or a FairnessRoot, and no wording in this document may be read as making it one.

The exact obligation — the causally closed model, the derived-release rule, and the prefix-wise comparison — is stated once in [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md), Note 14.5e. This document does not restate that mathematics and must not carry a second copy of it. What follows are the obligations a conforming implementation and its controls must meet in order to be checkable against it. If this section and Note 14.5e ever disagree, Note 14.5e governs.

Two consequences of that model bind every control written here. Releases are derived from the deterministic owner response rule and are never supplied as fixed inputs, so a control may not script releases in order to manufacture or suppress a difference between the runs. And the comparison is prefix-wise, so a control that compares only final states, only one competitor, only one dimension, or only the terminal decision does not discharge the obligation — amplification can appear and be reabsorbed within a run.

The obligation is one-directional. A control must not require that the subdivided root fare no worse, or that a competing root fare no better; a subdivision that disadvantages the subdivided root or advantages a competitor is conforming. Equality of outcome must never be asserted. A test showing only that some scope is eventually served does not discharge P6.

**Construction A is how the two runs are set up.** A control that compares a baseline run against a subdivided run must build both runs this way, so that attribution mapping is the only difference between them:

```text
Construction A
    identical FairnessRoot set in both runs

    identical AttributionChildScope topology, pre-created in both runs
        before the measured prefix begins

    identical bookkeeping claims, already charged in both runs before
        the measured prefix begins

    stable DemandIds: one demand carries the same identifier in both
        runs

    identical initial provider state at the start of the measured
        prefix

    baseline    maps every demand of A to one already-created
                AttributionChildScope beneath A

    subdivided  maps the same demands across the same already-created
                AttributionChildScopes beneath A

    only the DemandId-to-child-scope mapping differs
```

Because the scope topology and its bookkeeping already exist in both runs before measurement starts, subdivision creates no scope and charges no additional bookkeeping inside the measured prefix. Scope creation is deliberately moved outside the comparison rather than compensated for inside it.

**That normalization is a property of the comparison, not a claim about the world.** Bookkeeping is real, finite, and fallible. Creating an AttributionChildScope consumes resources, is charged like any other work, and can fail. Construction A does not promise unlimited scopes, does not make scope creation free, and must never be read as establishing that bookkeeping can never become a binding constraint. It establishes only that, within the measured prefix, the two runs carry the same bookkeeping and therefore differ solely in attribution.

**The fixed workload includes the environment.** The workload fixes a deterministic, clock-free environment and reducer that interleaves exogenous arrivals with owner-derived actions in a fixed order. No wall-clock time, timer, or scheduler nondeterminism participates. Because releases are owner-derived rather than supplied, this interleaving is what makes the two runs comparable at all.

**Terminal stuttering.** After the last exogenous arrival, the environment continues to step the provider with no new input until both runs reach a terminal state in which no further decision changes anything. The comparison is therefore well defined at every decision index, including indices past the final arrival, and neither run can appear to win merely by ending sooner.

**First control: a bounded decision prefix.** The first required control fixes a finite decision prefix — a bounded number of selection decisions — chosen so that none of the newly admitted demands under comparison releases within that prefix, and it starts from the identical topology and bookkeeping that Construction A requires. The comparison is then well defined without depending on release timing. Within that prefix it is a conformance control: it establishes the three conditions for the decisions it covers, and that is a genuine positive result for the case it covers. It is honestly scoped rather than demoted — it claims nothing about decisions beyond its prefix, is not defined as the longest such prefix, and is not merely a device for exhibiting a failure. It is not globally sufficient, is not a proof of the whole model, and must never be reported as either.

**What P6 does not claim.** Partition non-amplification concerns attribution beneath one FairnessRoot. It is not a real-world identity or claimant-count claim. It does not assert that a real adversary is confined to one FairnessRoot, that distinct roots correspond to distinct people, organizations, devices, or tenants, or that an adversary able to obtain several genuine roots is limited by this property. Sybil resistance, principal admission, and ingress identity are separate problems. P6 does not address them, no P6 control may be cited as evidence about them, and no Sybil or admission control may be cited as evidence for P6.

**Trusted local mapping is allowed and required.** Which local values a deployment maps onto a FairnessRoot is provider and deployment policy. An OS user, a local service account, an authenticated IPC peer, a local principal, or a named local ingress are all admissible choices. This document fixes no universal scheduler model, root taxonomy, or principal enumeration, and P6 requires none.

The mapping is performed by a trusted local verifier, and it may take verified facts as inputs. An authenticated local principal, a verified ingress classification, or another locally established and verified fact may legitimately determine which root a demand is attributed to. P6 does not require the mapping to be independent of the existence of such facts, and a provider that attributes demand per authenticated principal is conforming.

What P6 forbids is claimant control over the root structure itself. No claimant-supplied, peer-supplied, or wire-visible value may directly name, select, split, or multiply a FairnessRoot, and no party may increase the number of roots it is attributed to by asserting something that trusted local verification has not established. The distinguishing test is not "did any claimant-related fact influence the mapping" but "can a claimant, by its own action or assertion, obtain more roots or more turns than the trusted local mapping assigns it". Verified input is permitted; unverified assertion is not.

**Hostile-ingress progress is a separate contract.** P6 says nothing about whether a hostile or misbehaving ingress can delay or starve other work. Progress under hostile ingress is governed by the separate ingress progress and backpressure contract: bounded pre-authentication work, typed backpressure to the producer, and refusal naming an unavailable resource dimension. Neither contract is evidence for the other, and a control for one must not be reported against the other.

Where a provider retains pending demand at all, its cardinality, selection order, and rotation are concrete provider policy. The provider implementation selects them, and any policy preserving P1 through P8 is conforming. No other component may depend on a particular selection order or rotation rule, and conformance tests must assert the properties rather than the schedule.

The provider shipped with basal MyOwnMesh implements neither extension. It is immediate and work-conserving: a claim the remaining grant cannot cover is refused at once with typed, dimension-named pressure. There are no weights, quotas, reserved shares, or partitions; unused process capacity is borrowable across child scopes; and it holds no pending demand, performs no arbitration, keeps no rotation or reclaim cursor, and runs no cooperative-reclaim path, so there is no selection order and no rotation to specify. Subdividing attribution cannot manufacture turns for a root, because there are no turns. Replacing that policy is a provider decision, not a semantic change.

P6 remains basal and unchanged. An AttributionChildScope is not redefined as a FairnessRoot, and P6 is not relaxed to a per-scope guarantee. P6 constrains any provider that does schedule; it is not discharged by a provider that never defers, and no P6 conformance is claimed here. The shipped provider's standing under P1 through P5, P7, and P8 is asserted only where separately supported and is not implied by this paragraph.

Under a provider that implements the retirement extension, a request may go to an exact owner whose lease contract declares that lease reclaimable. Reclaimability is a property of the owner contract, not a provider decision. The provider does not release, revoke, replace, or reuse those claims: the notified owner performs cleanup and releases through lease Drop, or, where cleanup cannot be proven, explicitly transfers the exact charge into failed-cleanup retention. No timer creates, releases, or expires resource truth. Under the shipped provider no such request exists, and the same two outcomes — exact release on Drop after cleanup, or exact retention after failed cleanup — are the only ways a charge ever leaves a lease.

No scheduling or cooperative retirement model guarantees later admission against nonreclaimable admitted pressure, an ignored retirement request, or capacity retained after failed cleanup. A policy that gives cleanup authority the first pending-demand opportunity does not thereby manufacture capacity, and it is not a promise that cleanup can start without its exact claim.

**Immediate pressure only for a non-fitting claim.** Fit is `EffectiveFit`, defined below; it is never evaluated against an external observation `O` or a target `T`. An immediate, nonwaiting acquisition may return typed pressure without creating a pending demand, but only when the exact claim exceeds `EffectiveFit` in some dimension the claim requires. `EffectiveFit` already excludes capacity that is live or reserved for an in-flight admission, so no further subtraction is applied on top of it. A claim that fits must be admitted unless one of exactly three stated conditions holds: a proven structural limit forbids it; an explicit isolation policy or optional local ceiling refuses it; or the accounting needed to prove the admission safe is unavailable, poisoned, or cannot be proven safe. Each of those must be reported as itself, not as ordinary pressure.

Work conservation constrains refusal in the other direction. An immediate path may not refuse a fitting claim in order to hold capacity for an anticipated demand, to smooth one demand source's request rate, or to enforce an undeclared share. Any such withholding is a partition and is conforming only as explicit local isolation policy under P5.

**Narrow provider determinism.** The provider is deterministic only in this exact sense: given identical already-issued `ResourceScopeId` values, identical provider state, and the same operations applied in the same order, it produces the same decisions. Nothing stronger is claimed. Because a `ResourceScopeId` is derived from the allocation address of a fresh process-local scope identity at construction, the identifiers issued by a fresh run generally differ from those of a previous run, and any behavior keyed to their values or ordering may differ with them. Cross-run, cross-process, cross-allocator, and cross-schedule reproducibility is therefore not claimed, and no test may assume it. A determinism control must fix the already-issued identities rather than re-deriving them.

**Committed grant, envelope, backing, and external observation.** Six quantities are distinct and must never be conflated:

```text
S    the sum of live claims and failed-cleanup-retained charges in one
     resource dimension
Gc   the provider-owned committed grant in that dimension
E    an enforceable envelope: an isolation ceiling the provider or host
     can actually enforce against this domain
B    actual reserved or owned backing in that dimension, claimable only
     under an exact guarantee that the resource is held for this domain
T    an explicit owner-selected target in that dimension
O    an external observation of host capacity
```

*`E` is containment, not availability.* An enforceable envelope bounds what this domain can consume. It proves that the domain is contained, so it cannot exceed `E`. It proves nothing whatever about whether capacity up to `E` is available, reserved, or obtainable. An envelope is a ceiling, never a promise, and `E` must never be read as, reported as, or substituted for `B`.

*`B` requires an exact guarantee.* `B` may be claimed only where the resource is actually reserved or owned for this domain under an exact guarantee. An owner-supplied configuration vector, a measurement, a quota, or an envelope is not backing. Absent that exact guarantee, `B` is not claimed at all, and the shortfall is a named Slice C residual.

**Isolation and backing are orthogonal capabilities.** They are not exclusive, and they are not a hierarchy. A provider may claim isolation, or backing, or both, or neither, and it may do so independently per resource dimension. Each claim is licensed only by its own exact proof:

```text
accounting-only
    proves S <= Gc, and claims neither E nor B
    the grant is a bookkeeping commitment this process respects by its
    own arithmetic

isolated
    proves S <= Gc, and additionally claims E: an enforceable envelope
    contains the process. Containment is not availability, so an E
    claim says nothing about whether capacity within it can be obtained

backed
    proves S <= Gc, and additionally claims B: an exact substrate
    contract genuinely reserves the capacity. Reservation is not
    containment, so a B claim says nothing about whether consumption
    beyond it is prevented
```

A provider may hold both claims, and may hold them per dimension: `E` proved in one resource dimension and `B` proved in another is an ordinary configuration, not a contradiction. Any combination is permitted exactly where each premise it names is separately proved. Claiming `E` never licenses a `B` claim, and claiming `B` never licenses an `E` claim. Allocation remains fallible under every label: admission does not imply that the underlying resource can actually be obtained.

Neither claim implies the other in either direction, and neither is a prerequisite for the other. A provider may be backed in one dimension and merely contained in another, or contained in a dimension it does not back. Where a provider makes no claim for a dimension, that dimension is accounting-only regardless of what it claims elsewhere, and the unproved case is a named Slice C residual rather than an assumption. Absent a backing claim, an admission proves bookkeeping and not physical success; absent an isolation claim, it proves neither containment nor success.

**Capacities, charges, and fit.** The exact arithmetic is stated in [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md) and is not restated here. This document carries only the obligations an implementation must meet. If the two disagree, FORMAL governs.

Two charge quantities are distinct and are never conflated, per dimension `d`:

```text
S(d)         live claims plus failed-cleanup-retained charges
R_flight(d)  the aggregate exact capacity reserved for all admissions
             currently in flight; zero when there are none
```

`R_flight` is a distinct symbol, deliberately not `R`. [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md) already uses `R` for the multiset of live lease claims and failed-cleanup-retained claims, including in the P6 material, and that notation is not disturbed here.

`AccountingCapacity(d)` and `EffectiveCapacity(d)` are **absolute** capacities, not remainders. `AccountingCapacity` is the absolute committed grant `Gc` in `d`, narrowed only by an explicit P5 restriction drawn from the closed vocabulary below. `EffectiveCapacity` is `AccountingCapacity` intersected with `E(d)` where `E` is proved for `d`, and with `B(d)` where `B` is proved for `d`, and is still absolute. `EffectiveFit(d)` is the residual actually available to a new claim, clamped at zero.

A claim `q` fits in a dimension exactly when `q <= EffectiveFit(d)`. A composite claim fits only when it fits in every dimension it names; headroom in one dimension never compensates for its absence in another.

Three ordering and shape obligations follow, and an implementation must honour all of them:

- **Subtract charges last.** `S(d)` and `R_flight(d)` are deducted only after `E` and `B` have been intersected in. `E` and `B` are absolute substrate bounds, so intersecting them against a figure from which charges were already deducted would compare a residual against an absolute and silently understate the bound.
- **Deduct `R_flight` as well as `S`.** Without it, concurrent admissions each read the same headroom as free and both proceed.
- **Clamp the residual at zero.** `EffectiveCapacity(d) - S(d) - R_flight(d)` can be negative when a proved premise falls below existing committed use. The clamp keeps `EffectiveFit(d)` well formed and makes the fit test refuse, rather than yielding a negative bound that arithmetic elsewhere might treat as slack.

Each intersection is licensed only by its own independent proof for that exact dimension. An `E` proved for one dimension narrows no other, and a `B` proved for one dimension narrows no other.

*`R_flight` is counted exactly once.* A claim is reserved only after `q(d) <= EffectiveFit(d)` holds in every dimension it names; a failure in any dimension reserves nothing in every dimension. A successful reservation adds the exact `q(d)` to aggregate `R_flight(d)` once per named dimension. Promotion transfers exactly that quantity from `R_flight` into `S`, leaving `S + R_flight` unchanged. Failure or abandonment removes exactly that reservation under the existing ownership and cleanup rules and touches no live charge or other reservation. Owner release after proven cleanup and failed-cleanup retention both leave `R_flight(d)` untouched: release reduces `S(d)` by exactly the released claim, and retention replaces a live claim with the identical retained claim, so neither disturbs a reservation in flight. A reservation is never counted in both `R_flight` and `S`, never counted twice by concurrent admission paths, and never silently dropped from both. A forgotten reservation is a capacity leak, and a double-counted reservation is a spurious refusal; both are defects.

*The closed P5 vocabulary.* An explicit P5 restriction narrowing `AccountingCapacity` is exactly one of:

```text
named local isolation domain
    an explicitly named domain confining a scope to part of the
    dimension

named partition or reserved share
    an explicitly named division of the dimension, or a quantity
    withheld from general admission and held for a named scope

named optional local ceiling or cost boundary
    an explicitly named upper bound below Gc, whether selected for
    policy, appliance, deployment, or cost reasons
```

Each is explicit, named, and recorded, and each names the scope it applies to. There is no generic exclusion category: a restriction that does not fall in one of the three above is not a P5 restriction. Nothing outside this list narrows `AccountingCapacity` — no observation, target, measurement, generic owner preference, workload calibration, anticipated future demand, rate smoothing, inferred restriction, or undeclared product policy. A provider may not introduce any further narrowing of its own: no undeclared reserve, headroom, safety margin, or rounding-down that a deployment did not ask for. An undeclared narrowing is an arbitrary refusal, which P4 forbids.

*Accounting-only equality is valid.* Where a provider proves neither isolation nor backing for a dimension, `EffectiveCapacity(d) = AccountingCapacity(d)` holds, and stating that equality is correct rather than a defect or an omission. It is an honest description of what an accounting-only dimension admits against. It is not a claim that the two are equivalent in strength, and it never converts accounting into containment or backing.

*`O` and `T` are excluded throughout.* Neither an external observation nor a target participates in `AccountingCapacity`, `EffectiveCapacity`, or `EffectiveFit`, in any dimension, under any provider.

*Passing the test is not substrate success.* Satisfying `EffectiveFit` is an admission result. A successful admission against an accounting-only dimension does not guarantee allocator success, kernel success, runtime success, transport success, external-relay success, or hardware success. Where `B` is independently proved for a dimension, the assurance is exactly the `B` premise for that dimension and nothing broader. Everywhere else, and always for the substrate beneath a proved premise, allocation remains fallible: an admitted operation may still fail on the real resource.

*Premise loss narrows capacity and stays work-conserving.* When a proved `E` or `B` premise falls, `EffectiveCapacity` narrows accordingly. Within the headroom that remains above `S + R_flight`, the provider stays work-conserving: it continues to admit claims that fit the narrowed `EffectiveCapacity`, and it does not refuse work merely because a premise moved. A narrowed premise reduces what may be admitted; it does not license withholding capacity that is still genuinely free.

*Typed loss is reported only below `S + R_flight`.* A typed containment-loss, backing-loss, or external-overcommitment state is reported only when the premise falls below `S + R_flight` in that dimension — that is, below what is already committed. A premise that falls but remains at or above `S + R_flight` is reduced headroom, not a loss: it narrows future admission and is reported as capacity, not as a loss condition. Reporting loss on any fall would make ordinary contraction indistinguishable from a real shortfall.

*Unproved is never presented as established.* A provider never presents unproved containment or backing as established, in a result, a report, a log, or a document. An accounting-only committed grant is explicitly an accounting commitment. It is not proof that substrate capacity exists, and it is not proof that an allocation will succeed. Describing it as though it were either is a defect in the description, not a stronger provider.

*The shipped `FiniteResourceProvider` is accounting-only in every dimension.* Its grant is an owner-supplied vector, and an owner-supplied vector is not host backing. It claims no `B`, proves no `E`, and for every dimension `EffectiveCapacity = AccountingCapacity`. Its admissions carry no assurance that the underlying allocation will succeed, and any report that treats an admission as evidence of available or reserved capacity is incorrect.

Being accounting-only is a coherent classification and is not itself a defect. A provider that accounts honestly and claims nothing further is correctly described, not broken, and this section must not be read as faulting it for the absence of `E` or `B` claims it never made.

The shipped provider schedules nothing, so it defers nothing and no P6 conformance is claimed for it. That does not affect the accounting-only classification, and the two remain independent: proving every `E` and `B` mapping in this document would not discharge P6, and discharging P6 would prove no `E` or `B`. The provider still proves neither premise in any dimension.

Separately, it is **not sufficient on its own for final production resource closure**. Production closure additionally requires the independently proved `E` or `B` mappings described below for the dimensions a deployment intends to rely on. Shipping this provider alone must never be reported as having achieved resource closure.

*`O` is inert.* `O` is optional, is a policy input only, and carries no authority. It may be stale, wrong, adversarially influenced, in foreign units, or absent, and a deployment may have no `O` at all. No admission decision reads `O`, no refusal is justified by `O`, and no value derives from `O` automatically.

*`T` is owner-selected.* `T` is an explicit, named owner-policy target. An owner may set `T` directly, with no observation involved. An owner may instead derive `T` through a named policy that consults `O`. There is no mandatory path from `O` to `T` and no control that requires one. A change in `O` never changes `T` by itself: absent an owner decision or an explicitly named policy acting on the owner's behalf, `T` is unchanged.

*`T` requests gradual contraction.* `T` is a request, not an act. It asks `Gc` to descend toward it over time. `T` never lowers `Gc` by itself, never releases a charge, and never refuses an admission on its own authority.

*`Gc` follows only after owner release lowers committed use.* `Gc` is never installed or reduced below `S(d) + R_flight(d)`. `Gc` descends toward `T` only as owner-driven release reduces committed use enough to make each step safe, one safe step at a time. `S(d) + R_flight(d) <= Gc(d)` holds at every instant and implies `S <= Gc`, without exception or window.

*Loss of `B` or `E` is a typed state, and the shortfall is real.* A provider that claimed backing and finds it fallen below `S + R_flight` reports typed backing loss for that dimension; a provider whose envelope no longer contains what is already committed reports typed containment loss. External overcommitment is the corresponding typed classification where applicable. In every case each charge and reservation is retained, no release is forged or inferred, conflicting admission is refused with a typed result naming the dimension, and `Gc` is still not lowered below `S(d) + R_flight(d)`. A premise that falls but remains at or above `S + R_flight` is reduced capacity rather than loss, and is reported as capacity.

A backing proof taken at admission is historical. It does not make physical backing exist later. When backing is lost, substrate availability may genuinely have failed, and this document must not pretend otherwise: charges remain charged and commitments remain owed, but the underlying resource may simply not be there. The typed state names that condition honestly. It must never be read, or reported, as an assurance that every charge is still physically backed.

*Typed reporting requires a live, observing provider.* Every typed state above can be reported only while the process is alive and able to observe its own condition. A fail-stop outcome reports nothing. If the host kills the process — an out-of-memory kill is the ordinary case — there is no typed containment-loss, backing-loss, or external-overcommitment result, because there is no longer anything to emit it. No obligation here may be written or read as a guarantee that resource exhaustion will be observed and reported rather than simply ending the process.

Process death destroys the live in-process capabilities, leases, and accounting state held in that process, and recovery follows ordinary restart semantics rather than any contract in this subsection. That boundary is exactly as wide as the process and no wider. It is not a claim that resources outside the process are released. An external relay or TURN allocation, a peer's view of a session, a file or directory on disk, a kernel object the OS does not reclaim, or any reservation held by another party may outlive the process that charged it. Whether such a resource is reclaimed is a property of that external owner, not of this contract, and no cleanup of external or substrate-owned resources may be claimed on the strength of process death alone.

*Unproved backing is a residual, not an assumption.* Where an adapter cannot prove what actually backs a dimension — allocator slack, native WebRTC state, runtime internals, kernel handles, driver state, external provider allocations — that shortfall is a named Slice C residual. It must not be silently treated as backed, and it must not be counted into `B`.

*P4 fit is `EffectiveFit`.* A claim `q` fits when `q <= EffectiveFit(d)` in every dimension `d` it requires, as defined above. For a dimension where neither containment nor backing is proved, `EffectiveCapacity` equals `AccountingCapacity`, and admission on that accounting basis alone implies nothing about physical success. The test never uses `O` and never uses `T`.

**Slice C handoff: what an `E` or `B` claim requires.** This document does not implement Slice C and states no mapping here. It records only what Slice C must deliver before any `Gc <= E` or `Gc <= B` claim may be made.

Every such claim requires, for each dimension it covers, a mapping between the MyOwnMesh `ResourceClaim` quantity and the substrate quantity actually contained or reserved. The canonical list of what that mapping must satisfy is stated once in [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md) under "What proving `E` or `B` requires", and FORMAL governs it. The conditions are dimension-specific, unit-correct, monotone, coverage, composition, subject alignment, lifetime and loss, and `B` exclusivity. This document does not restate that list as a competing normative block.

Dimensions the owner directive calls out are:

```text
AccountedMemory
SocketOrHandle
WorkerOrTask
StorageBytes
RelayOrProviderAllocation
```

The list is illustrative, not exhaustive. Every other `ResourceClass` dimension is governed by the same rule: it needs its own mapping satisfying every condition before it carries an `E` or `B` claim, and otherwise remains accounting-only and an explicit residual.

The five conditions below are the ones an implementation most often gets wrong, so each is read here in implementation terms. This adds no condition and narrows none; where this reading and FORMAL differ, FORMAL is correct.

- **Coverage.** The mapping accounts for every consumer of that substrate quantity, not only the charged ones. A consumer this model does not charge is included **conservatively**: its use is subtracted from the premise rather than assumed absent. In practice that means a retry, a callback, a buffer grown under load, a dependency's own allocation, and any co-tenant of the same substrate quantity must each be either charged or subtracted. A partially mapped dimension is not a mapped dimension.
- **Composition.** No two `ResourceClass` dimensions, and no two providers, may claim the same substrate quantity. A quantity counted twice is not thereby contained twice or reserved twice. Two dimensions that both map onto the same bytes, handles, or allocations are double-claiming, and so are two providers each treating the same substrate reservation as its own; in both cases the premise is inflated by exactly the overlap.
- **Subject alignment.** The contained or reserved subject is exactly the subject `Gc` is committed for: the same process, the same worker, and the same provider, neither broader nor narrower. A premise measured for a broader subject includes consumption that is not ours, and one measured for a narrower subject omits consumption that is.
- **Lifetime and loss.** The mapping names when it begins, when it ends, and who observes it. Where its loss cannot be observed before a fail-stop, the charge is **retained** and the premise is **not claimed** for that unobservable interval. A substrate may withdraw backing without notice and the process may be killed before detecting it, so a mapping that assumes every loss is seen, or seen early enough to react, is unsound. The charge stays; the premise lapses for exactly the interval that could not be observed.
- **`B` exclusivity.** Reserved capacity is exclusive to that subject. Competing unaccounted use is **conservatively deducted from `B`**, and a shared pool another party may consume from is not `B`. `B` is what remains exclusively ours after every unaccounted competing consumer is subtracted, not the nominal size of the pool we draw from. Where competing use cannot be bounded, no conservative deduction exists, `B` is not established, and the dimension remains accounting-only.

A mapping that fails any condition is not a weaker mapping; it is not a mapping, and the dimension remains accounting-only.

Where no such mapping exists for a dimension, that dimension stays accounting-only and is carried as an explicit residual.

`OpaqueDependencyResidual` is the case to watch, because it is the dimension most likely to be mistaken for a satisfied one. Assigning it a number is not sufficient: being counted, measured, or reported does not make it contained or reserved, since a quantity is neither a containment proof nor a reservation. Absent a mapping meeting the three conditions above — one that names what a single unit of it means and proves dimension-specific, unit-correct monotonicity against the substrate quantity — it remains accounting-only and an explicit residual, carries no `E` or `B` claim, and is never absorbed silently into an aggregate claim. If such a mapping is later supplied, or the dimension is replaced by one that admits it, it becomes eligible on exactly the same terms as any other dimension; nothing here forecloses that.

Until Slice C supplies a mapping satisfying every condition in FORMAL's canonical list for a dimension, that dimension carries no `E` or `B` claim, `EffectiveCapacity` there equals `AccountingCapacity`, and any report must say so.

Contraction releases, revokes, invalidates, and reuses nothing. It never forges a release and never admits a conflicting claim to make room. It may request retirement only from the exact owners whose lease contract declares those leases reclaimable, and such a request releases nothing. It applies only to admission decisions taken after it.

`S(d) + R_flight(d) > Gc(d)` is not a reachable state and must never be described as one, and `S > Gc` follows as the weaker consequence. P1 is not suspended, relaxed, deferred, or evaluated against a historical grant during contraction; conservation holds continuously throughout. Any wording suggesting a window in which committed use exceeds the committed grant is incorrect and must be corrected rather than explained. Contraction is never a reclamation mechanism, and it never strands an in-flight reservation.

A contraction is not an instantaneous probe of current use, and the two must never be substituted for each other. A probe reports committed use `S + R_flight` at an instant and changes nothing; a contraction lowers `Gc`, subject to the floor `S(d) + R_flight(d) <= Gc(d)`, and changes the admission ceiling going forward. A typed containment-loss, backing-loss, or external-overcommitment report is caused by a premise falling below committed use, not by the contraction itself, and it never indicates that `Gc` fell below `S(d) + R_flight(d)`. Reporting a probe as a contraction would let a transient measurement appear to authorize a permanent ceiling change; reporting a contraction as a probe would let a ceiling change appear to be a mere observation.

*Status of these obligations in the shipped provider.* The shipped provider is accounting-only. It takes its grant at construction as an owner-supplied vector, exposes no contraction entry point, models no external observation `O`, selects no target `T`, enforces no envelope `E`, and proves no backing `B`. It therefore exercises none of the obligations in this subsection: there is no target selection to record, no gradual descent of `Gc` to control, no envelope containment to enforce, and no backing claim at admission. Every clause above constrains work that has not been built. None may be reported as a satisfied property, the absence of a contraction path is not evidence that contraction is safe, and an admission by this provider is evidence of bookkeeping only — never that the underlying allocation will succeed.

The current resource classes describe an accounting vocabulary, not proof that every dependency exposes that dimension. Exactness is limited to the quantity actually charged. Allocator slack, native WebRTC state, runtime internals, kernel handles, driver state, and external provider allocations must remain named residuals until the responsible adapter can conservatively claim or isolate them.

### 14.2 Limit classification

Every limit must be classified as exactly one of:

```text
Protocol-shape bound
    required for canonical or valid wire shape

Provider structural limit
    imposed by a transport, codec, kernel, hardware device, or dependency

Runtime resource availability
    a current provider grant consumed through leases

Optional local policy ceiling
    an explicit administrator, cost, isolation, Closed deployment, appliance,
    test, or temporary compatibility restriction
```

An implementation must not turn a measured workload size into a protocol bound, turn an optional policy ceiling into basal semantics, or describe an opaque dependency allocation as exact.

### 14.3 Pre-authentication resource class

Pre-authentication claims include accepted connections and handshakes, parser bytes and work, fact verification work, signaling work, candidate storage, sockets and transport objects, DNS, STUN, ICE and relay work, speculative packet quarantine, callbacks, scheduled work, diagnostics, and cleanup ownership.

The process component is checked regardless of identity. Per-ingress accounting may guide fairness or optional policy, but identity rotation cannot create a new process grant.

### 14.4 Post-authentication resource class

Post-authentication claims include authenticated sessions, application-facing queues, codec work, TURN/native transport buffering, recovery, callbacks, handles, and subscriptions. A successful pre-authentication lease cannot be reused as proof that post-authentication resources exist. Promotion performs an explicit resource transition.

### 14.5 Queue and delayed-work contracts

No queue may grow without leases for its retained storage and scheduled work. Basal MyOwnMesh does not define one universal queue-item count.

```text
connector lifecycle
    fixed non-lossy state transition owner

reliable endpoint stream
    resource-backed bytes plus producer backpressure or typed failure

interactive real-time flow
    provider or application-selected complete-unit pressure semantics

satellite or store-and-forward
    delayed-delivery spool backed by storage leases

raw storage or removable media
    storage-object and storage-byte leases
```

Elapsed time does not create or release a lease. A slow operation may retain its finite claim until an explicit owner transition releases or replaces it. A provider retirement request changes no claim. The exact owner releases through Drop after cleanup, or transfers the charge into failed-cleanup retention when release cannot be proven.

### 14.6 Opaque native and operating-system resources

Every opaque family must be reported as one of:

```text
exactly observable and leasable
conservatively claimable
isolatable in a worker, process, job, cgroup, rlimit, or equivalent domain
observable but not enforceable yet
unobservable residual
```

The implementation must prefer host-enforced resource domains and narrow provider guards where available. It must not substitute a guessed peer or flow count for an unobservable native allocation.

### 14.7 Optional local ceilings

An optional `LocalCeilingPolicy` or equivalent wrapper may impose stricter counts or resource partitions for a locked-down appliance, Closed deployment, carrier cost boundary, compatibility provider, or test.

This wrapper is explicitly optional. It is not required for ordinary V4 construction, it cannot mint authority or capacity, and basal conformance must never assume it is present. Every isolation domain or reserved share it introduces is local policy, not a basal guarantee, and must be reported as such.

### 14.8 Effect execution

State and effect intents commit before external execution. Every effect carries exact live capabilities and leases and rechecks them before use. Cleanup effects remain available even when authority for new work disappears.

## 15. Fundamental invariants

### I1. Hybrid architecture

Durable semantics, signaling, connector work, endpoint authentication, and application sessions are all first-class MyOwnMesh components.

### I2. Transport independence

Transport substitution cannot change the authority or meaning of an accepted durable fact.

### I3. Transport is not removed

A usable networking implementation requires live signaling or discovery where needed, a connector profile, endpoint authentication, and packet carriage.

### I4. Projection is durable derivation only

`Project` never means route creation, route selection, topology truth, or forecasting.

### I5. Open is ephemeral and permissionless

Open self-participation has no durable fact or third-party admission
predicate. Exact-context handshake and Device-key possession authenticate the
runtime participant; join, leave, presence, and reconnect remain outside
semantic history.

### I6. Closed alone adds governance authorization

Closed may be fully locked down under its selected proof system.

### I7. Durable and ephemeral signaling are distinct

Transient transport negotiation is not automatically retained as durable history.

### I8. Speculative work is allowed

Untrusted input may cause bounded candidate and handshake work.

### I9. Speculative work is confined

Pre-authentication work cannot create durable authority, application delivery, or an authenticated session handle.

### I10. Work is reserved before allocation

Every protected parser, candidate, socket, relay, handshake, queue entry, task, native object, and session allocation is dominated by a live finite resource lease.

### I10a. Basal semantic cardinality is open

Basal MyOwnMesh defines no fixed maximum for Mesh runtimes, peers, connector attempts, sessions, or real-time flows. Each new object is admitted by its actual composite claim and may fail with typed resource pressure or unavailability.

### I10b. Child scopes share one finite process grant

Mesh and descendant scopes share one finite process grant. No basal weights, quotas, shares, or partitions exist. Claims never exceed the actual provider domain, no scope mints capacity, unused capacity is work-conservingly borrowable, any isolation or reserved share is explicit local policy, and P6 as formally defined in [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md) Note 14.5e remains the standing obligation. The shipped provider holds no pending demands and rotates over nothing, so subdividing a root's attribution cannot manufacture turns for it; no P6 conformance is claimed on that basis. Only the exact owner releases a claim, after cleanup; no forged release exists, and cleanup retains the resources it requires. Admission remains fallible under admitted pressure or failed-cleanup retention.

### I10c. Time is not resource authority

Elapsed duration alone cannot create, release, expire, or validate a resource lease.

### I11. A working socket is not a session

Channel promotion requires exact endpoint authentication, exact context, mesh policy, local principal, resources, and a fresh capability.

### I12. No durable route identity is required

The basal network does not require a ledger route object, global path record, or monotonic path generation.

### I13. Local connector capabilities own callbacks

A delayed callback cannot mutate a replacement object without the exact live capability.

### I14. Carrier is not endpoint identity

Direct and configured standard TURN WebRTC preserve the same A-C endpoint identity after promotion.

### I15. Hubs are not payload carriers

Hub discovery/introduction never forwards application plaintext or ciphertext.

### I16. TURN work is finite and separately owned

Configured standard TURN allocations retain finite local accounting and
external-service limits; a service URL grants no endpoint authority.

### I17. Infrastructure cannot promote or switch

A Hub or TURN service cannot add a channel to an endpoint's authenticated set
or authorize a handoff.

### I18. No custom relay handoff dependency

Replacement endpoint transport does not depend on custom member-relay state
transfer or a custom route cipher.

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
- lease-backed frame, queue, retry, and provenance state;
- no application payload construction.

### 16.3 Speculative transport

- raw hints can create bounded candidate work;
- process resource grants hold under identity rotation;
- admission continues for another object whenever its exact claim is granted;
- refusal names the unavailable resource class rather than a basal object-count ceiling;
- multiple Mesh scopes cannot multiply the process grant;
- claims never exceed the actual provider domain in any resource dimension;
- unused capacity is work-conservingly borrowable;
- the basal provider has no weights, quotas, reserved shares, or partitions;
- partition non-amplification as defined in [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md) Note 14.5e: the baseline and subdivided runs of one causally closed model, with releases derived rather than scripted, compared prefix-wise on cumulative selections, on cumulative admitted quantity per dimension, and on each competing root's selection index. The control must exhibit both runs and must not require equality of outcome in either direction. This obligation binds any provider that schedules; the shipped provider does not;
- both runs are built by Construction A: identical FairnessRoot set, identical pre-created AttributionChildScope topology, identical already-charged bookkeeping, stable DemandIds, and identical initial state at the start of the measured prefix, with baseline mapping all of A's demands to one already-created child scope, subdivided mapping the same demands across those same already-created scopes, and only the DemandId-to-child mapping differing;
- the workload fixes a deterministic clock-free environment and reducer interleaving exogenous arrivals with owner-derived actions, and both runs stutter to a terminal state so the comparison is defined past the final arrival;
- Construction A's normalization is never reported as a claim that scopes are unlimited, that scope creation is free, or that bookkeeping can never bind; scope creation remains real, finite, charged, and fallible;
- the first partition non-amplification control fixes a bounded decision prefix in which none of the compared newly admitted demands releases and starts from Construction A's identical topology and bookkeeping; it is a conformance result for the case it covers and is never reported as globally sufficient or as a whole-model proof;
- the FairnessRoot mapping is performed by trusted local verification, which may take verified local facts such as an authenticated principal as inputs, while no claimant-supplied, peer-supplied, or wire-visible value can directly name, select, split, or multiply a root, and no unverified assertion increases the roots a party is attributed to;
- no partition non-amplification control is reported as a Sybil, claimant-count, or real-world identity result, and no Sybil or principal-admission control is reported against P6;
- hostile-ingress progress and backpressure are exercised as their own contract and are never reported as fairness evidence, in either direction;
- an immediate nonwaiting acquisition returns typed pressure only for a claim that does not fit in some required dimension, and a fitting claim is refused only under a stated structural limit, an explicit isolation or optional ceiling policy, or accounting that is unavailable, poisoned, or unprovable-safe;
- no immediate path withholds a fitting claim to reserve capacity for anticipated demand, to smooth a rate, or to enforce an undeclared share;
- determinism is exercised only across identical already-issued `ResourceScopeId` values, identical state, and the same ordered operations, and no control assumes cross-run identifier stability;
- `Gc` is never installed or reduced below `S(d) + R_flight(d)`, so the stronger invariant holds continuously, implies `S <= Gc`, and no control may exhibit or describe `S > Gc` or strand an in-flight reservation;
- an external observation `O` is inert and optional: a policy input only, never read by an admission decision, never used as a limit, never justifying a refusal, and never producing any value automatically;
- `T` is an explicit named owner-policy target that an owner may set directly with no observation involved, or derive through a named policy consulting `O`; no path from `O` to `T` is mandatory, no control requires one, and a change in `O` never changes `T` by itself;
- `T` never lowers `Gc`, releases a charge, or refuses an admission by itself;
- `Gc` descends toward `T` only as owner-driven release lowers committed use `S + R_flight`, one safe step at a time;
- a provider that claims backing for a dimension proves `Gc <= B` in that dimension at admission; a provider making no backing claim is not required to, and the unproved case is reported as a Slice C residual rather than assumed;
- typed containment loss, backing loss, or external overcommitment is reported only where the premise falls below `S + R_flight`; in every case all charges and reservations are retained, no release is forged or inferred, conflicting admission is refused with a typed dimension-naming result, and `Gc` is still not lowered below `S + R_flight`;
- no control or document treats an admission-time backing proof as evidence that physical backing still exists later, and none asserts that every charge remains backed once `B` has fallen;
- capacity an adapter cannot prove is backed is a named Slice C residual and is never counted into `B`;
- `AccountingCapacity` and `EffectiveCapacity` are absolute capacities, not remainders: `AccountingCapacity` is `Gc` narrowed only by an explicit restriction from the closed P5 vocabulary, and `EffectiveCapacity` narrows it by `E` only where `E` is proved and by `B` only where `B` is proved, per dimension and independently; where neither is proved the two are equal, and that equality is valid;
- `EffectiveFit` is what `EffectiveCapacity` leaves once `S` and `R_flight` are accounted, and admission requires `q <= EffectiveFit` in every dimension the claim touches;
- `S` and aggregate `R_flight` are distinct; reservation occurs only after the claim fits every named dimension and is all-or-nothing, promotion transfers the exact quantity from `R_flight` to `S`, and failure or abandonment removes only its own reservation, so the reservation is counted exactly once, never held in both, never double-counted, and never silently dropped;
- the only narrowings of `AccountingCapacity` are explicit P5 restrictions drawn from the closed three-category vocabulary — named local isolation domain, named partition or reserved share, named optional local ceiling or cost boundary — each naming its scope, with no generic exclusion category and no undeclared reserve, headroom, safety margin, or rounding-down;
- `S` and `R_flight` are subtracted only after `E` and `B` are intersected in, and the residual is clamped at zero so a fallen premise refuses rather than presenting a negative bound as slack;
- a composite claim fits only when it fits in every dimension it names; headroom in one dimension never compensates for its absence in another;
- on loss of a proved `E` or `B` premise the provider narrows `EffectiveCapacity` and remains work-conserving in the headroom above `S + R_flight`, continuing to admit claims that fit;
- typed containment-loss, backing-loss, or external-overcommitment is reported only where the premise falls below `S + R_flight`; a premise that falls but stays at or above `S + R_flight` is reported as reduced capacity, not as loss;
- `O` and `T` never participate in `AccountingCapacity`, `EffectiveCapacity`, or `EffectiveFit`, in any dimension, under any provider;
- isolation and backing are orthogonal per-dimension capabilities, not exclusive and not a hierarchy: each is licensed only by its own exact proof, neither implies or requires the other, and a dimension with no claim is accounting-only and reported as a Slice C residual;
- `E` is never reported as, or substituted for, `B`, and containment is never presented as availability;
- the shipped `FiniteResourceProvider` is reported as accounting-only in every dimension, because its owner-supplied grant vector is not host backing, and is never reported as sufficient on its own for final production resource closure;
- no provider presents unproved containment or backing as established; an accounting-only committed grant is described as an accounting commitment, never as proof that substrate capacity exists or that an allocation will succeed;
- a successful admission against an accounting-only dimension is never reported as guaranteeing allocator, kernel, runtime, transport, external-relay, or hardware success;
- accounting-only classification is reported as coherent and not itself a defect, and remains true of the shipped provider independently of its P6 standing: discharging P6 proves no `E` and no `B`, and proving either would not have discharged P6;
- every `E` or `B` mapping additionally discharges coverage, composition, subject alignment, lifetime and loss, and `B` exclusivity; a mapping failing any of these is treated as no mapping at all;
- no mapping assumes premise loss is observable in time; undetectable withdrawal followed by fail-stop is treated as the expected worst case;
- every unaccounted competing consumer of the same underlying resource is deducted from `B`, and where competing use cannot be bounded `B` is not established and the dimension remains accounting-only;
- every `Gc <= E` or `Gc <= B` claim rests on a dimension-specific, unit-correct, monotone mapping between the `ResourceClaim` quantity and the substrate quantity contained or reserved; absent that mapping the dimension stays accounting-only and is carried as an explicit residual;
- `OpaqueDependencyResidual` carries no `E` or `B` claim and is never absorbed into an aggregate one absent a mapping satisfying every condition in FORMAL's canonical list, including naming what a single unit of it means; assigning it a number is not sufficient, since being counted or measured does not make it contained or reserved;
- no typed containment-loss, backing-loss, or external-overcommitment result is claimed for a fail-stop outcome; process death destroys live in-process capabilities, leases, and accounting state and is handled by ordinary restart semantics, not by this contract;
- no cleanup of external or substrate-owned resources is claimed on the strength of process death; relay and TURN allocations, peer-held session state, on-disk artifacts, and kernel objects the OS does not reclaim may outlive the process that charged them;
- grant contraction is never exercised as, or substituted for, an instantaneous use probe;
- pressure and refusal never become an authorization result in either direction;
- elapsed time alone creates, releases, expires, and validates nothing;
- a retirement request never releases the claim it targets;
- only the exact owner releases, through Drop after cleanup, or the exact charge enters failed-cleanup retention;
- cleanup retains the resources it requires and cannot depend on a forged release;
- no admission guarantee is claimed against nonreclaimable admitted pressure, ignored retirement, or failed cleanup;
- optional local ceilings, isolation domains, and reserved shares remain explicit wrappers;
- selection order, rotation rule, and pending-demand cardinality are provider policy, so conformance asserts the properties above rather than a particular schedule;
- when the shipped provider policy is in use, no pending demand exists, so there is no selection order and no rotation to depend on, and admission is either immediate or refused with typed dimension-named pressure;
- malformed and unauthorized inputs cannot cross promotion;
- media and packets remain quarantined before promotion;
- cleanup completes at every failure point.

P6 at this disposition: the shipped provider holds no pending demand and keeps no rotation or reclaim cursor, so subdivision cannot manufacture turns and no P6 conformance is claimed for it. P6 binds any provider that does schedule. It must not be reworded into a per-scope guarantee, and the connector-local scheduling-metadata obligation remains a separate claim about capacity authority that does not discharge it.

### 16.4 Promotion

- independently remove every `MayPromote` conjunct;
- endpoint identity mismatch closes the channel;
- cross-context and cross-channel replay fail;
- old durable facts and old control signals do not recreate handles;
- every send and receive rejects stale or foreign-principal capabilities.

### 16.5 Connectors and recovery

- direct and configured standard TURN positive controls, with Hub/member payload refusal controls;
- bounded remote ICE-candidate application ordering, success, refusal, and
  failure behavior; any future cross-connector racing requires its own
  production owner and controls;
- restrictive-network matrix;
- two authenticated channels active concurrently;
- handoff with no relay-to-relay messages;
- delayed old callbacks cannot mutate replacement state;
- forced old-path failure cannot promote an unauthenticated new path;
- native real-time flows are optional connector capabilities bound to a live session;
- fixed codec and application-media semantics are absent from the basal core;
- pre-promotion track setup cannot reach application delivery.

### 16.6 TURN and introduction separation

- endpoint authentication/integrity through configured standard TURN;
- finite allocation, native callback/task ownership, and honest residuals;
- no application plaintext or ciphertext through Hub/signaling handlers;
- removed config and wire forms refuse rather than restoring a custom route;
- cohosted TURN retains distinct service and mesh authority;
- URL advertisements do not imply protected credential exchange.

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
- statement and preflight failures prove the old durable projection without
  claiming rollback from an unobserved transaction drop;
- WAL write/sync and COMMIT-return faults classify the caller-visible result as
  outcome-unknown until exact reopen reconciliation proves old or new;
- post-commit checkpoint/truncate maintenance faults are reported as maintenance
  failures while preserving the already committed durable projection;
- crash cutpoints before commit, during commit, after commit before response,
  and during checkpoint are exercised with bounded stage markers and no sleeps;
- duplicate/no-op delivery leaves projection, usage, and `StorageBytes`
  accounting unchanged, and restart restores the exact Closed projection
  without reviving live Open/Closed sessions or handles;
- no architecture-compliance PASS is recorded from source or unit evidence
  alone; durable runtime runs and their terminal provider baselines are
  required.

## 17. Required implementation artifacts

A conforming implementation supplies:

1. package and dependency graph;
2. complete accepted-input and effect inventory;
3. durable canonical test vectors;
4. endpoint-authentication and channel-binding test vectors;
5. connector profile specifications;
6. resource-provider and integration report for every supported target, giving exactness and residual classification per resource dimension, the host isolation domains used, the concrete scheduling policy the provider implements, and evidence that the policy preserves the basal properties in section 14.1;
7. model or property tests for durable projection and conflict;
8. speculative-work and promotion state model;
9. crash and effect-idempotency model;
10. red-team evidence bundle for the target catalog;
11. proof that application payload cannot reach signaling constructors or effects;
12. proof that no durable route or monotonic path-generation dependency remains in the basal path.
13. restart, corruption, transaction-rollback, WAL-checkpoint, and exact
    provider-baseline controls against the supported bundled SQLite build.

## 18. Owner decisions

The owner must select:

- exact cryptographic profiles;
- Closed governance proof and independent endpoint authorization through direct/TURN transport;
- signaling and connector profiles;
- required egress and restrictive-network environments;
- resource-provider integration and host isolation for each deployment form;
- any optional local ceiling or cost policy;
- session recovery and multi-channel policy;
- reachability display and freshness policy;
- application data-operation set;
- optional durable application contract domains.

These selections are delivered as a provider and integration report, not as a dossier of chosen numbers. The report names each provider and deployment form, states which resource dimensions are exactly observable, conservatively claimable, isolatable in a host-enforced domain, or unobservable residuals, and records the concrete scheduling policy in use with evidence that it preserves the basal properties in section 14.1.

Every numeric protocol or provider limit requires proof from that protocol or provider. Every optional local policy value requires owner review and is never assumed present by basal conformance. Measurements characterize performance, cost, scheduling, regression, and opaque residuals. They do not define universal semantic cardinality.
