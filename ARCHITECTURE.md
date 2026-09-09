# MyOwnMesh fundamental hybrid networking architecture

Status: owner-adopted V4 architecture, as amended by owner review.

This document defines the smallest common architecture for MyOwnMesh discovery, durable mesh semantics, signaling, transport path construction, endpoint authentication, session recovery, and application data delivery.

MyOwnMesh is a **transport-independent hybrid networking system**. Transport independence means that a durable fact does not gain or lose authority because of the medium that carried it. It does not mean that transport is optional, external to the system, or operationally interchangeable. Discovery, signaling, candidate gathering, connectivity checks, relay allocation, congestion behavior, packet carriage, recovery, and reachability remain first-class parts of MyOwnMesh.

The mathematical model is in [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md). Concrete constraints and invariants are in [`IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`](IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md). The application boundary is in [`APPLICATION-INTEGRATION.md`](APPLICATION-INTEGRATION.md).
The existing-repository migration is governed by [`TRANSITION-PLAYBOOK.md`](TRANSITION-PLAYBOOK.md) and [`ARCHITECTURE-OWNERSHIP.md`](ARCHITECTURE-OWNERSHIP.md).

## 1. Canonical end-to-end architecture

![MyOwnMesh end-to-end hybrid networking architecture](diagrams/01-end-to-end-hybrid.svg)

The diagram names production owners, not conceptual placeholders. Its executable
left-to-right path is:

| Diagram stage | Production module |
|---|---|
| daemon and local application boundary | `crates/myownmesh/src/cli/serve.rs`, `control.rs`, `control/dispatch/channel.rs`, `ipc/bridge.rs` |
| typed signaling and LAN discovery | `crates/myownmesh-core/src/engine/signaling_bridge.rs`, `crates/myownmesh-signaling/src/mdns/driver.rs`, and the selected `mdns/discovery/{embedded,system}.rs` backend |
| candidate construction and packet carriage | `crates/myownmesh-core/src/engine/connection.rs`, `transport/webrtc.rs`, and `transport/ice.rs` |
| channel-bound endpoint proof | `crates/myownmesh-core/src/endpoint_auth/task.rs`, `endpoint_auth/transcript.rs`, and `engine/handshake.rs` |
| policy promotion and exact live-session ownership | `crates/myownmesh-core/src/runtime/session_broker/mod.rs`, `runtime/peer_session/slot.rs`, and `engine/state.rs` |
| application delivery | `crates/myownmesh-core/src/application_gateway/channels.rs` and `crates/myownmesh/src/ipc/bridge.rs` |

[`scripts/run-production-e2e.py`](scripts/run-production-e2e.py) executes one
concrete instance of that path with two shipped daemon processes: production
mDNS discovery, direct WebRTC construction, fresh endpoint authentication,
bilateral automatic promotion on an Open network, and acknowledged typed-channel
delivery, followed by owned graceful shutdown of both daemon processes. It
requires an existing binary and an owner-selected finite resource grant; it
neither builds the product nor substitutes `LocalBroker`. A forced child-process
termination or nonzero daemon exit fails the executable contract. Its output is
raw characterization material, not a release-evidence assertion.

The architecture has five cooperating mechanisms:

1. **Durable semantic state** stores and derives long-lived Closed governance meaning. Open participation is runtime-only and does not enter this ledger; any reviewed application contract domain is separate from the base ledger.
2. **Signaling** moves durable facts and ephemeral transport-control messages through any suitable signaling medium.
3. **The connector runtime** performs actual networking work: discovery, candidate gathering, bounded application of admitted remote ICE candidates, connectivity checks, relay allocation, transport handshakes, measurement, migration, and recovery. Configured Hub hints may introduce bounded demand, with direct endpoint connectivity preferred, TURN kept as a distinct ICE service, and any Hub fallback endpoint-encrypted or refused. The current remote-candidate planner is not a claim of automatic cross-family racing.
4. **Endpoint authentication and the session broker** promote a working channel into an application-usable peer session only after exact Device authentication and current mesh policy checks.
5. **Applications** exchange payload only through a live authenticated session capability.

The causal sequence is:

```text
Durable semantic state and typed signaling
        -> bounded connector work
        -> a channel that actually passes packets
        -> fresh endpoint authentication over that channel
        -> Open or Closed policy and local-principal checks
        -> live AuthenticatedPeerSession
        -> application payload
```

No route must become a durable ledger object before the connector may try it.

## 2. Transport independence, not transport removal

![Transport independence without transport removal](diagrams/03-transport-independence.svg)

The upper lane in the diagram is implemented by
`semantic/{fact,verify,store,projection}.rs` and receives typed carrier inputs
through `engine/{signaling_ingress,semantic_ingress}.rs`. The lower lane is
implemented by `engine/signaling_bridge.rs`, `engine/connection.rs`,
`transport/{ice,webrtc}.rs`, `endpoint_auth/task.rs`, and
`runtime/session_broker/mod.rs`. Only the upper lane may create durable
authority; only the lower lane can establish current packet reachability. The
promotion edge between them consumes verified semantic policy without turning a
carrier observation into authority.

For durable semantic facts, equivalent accepted inputs produce equivalent durable state regardless of whether the bytes arrived through Nostr, mDNS, WebSocket, a signaling cache, a file, serial transport, shared storage, removable media, an optical encoding, or another suitable medium.

Formally, if two deliveries produce the same accepted durable fact set under the same context, domain rules, and verified basis, they produce the same durable derived state.

This guarantee does not claim that all media can perform every networking operation. A removable drive can convey a governance fact but cannot provide an interactive endpoint channel. A UDP path can carry real-time packets but may require additional machinery for reliable semantic exchange. Each operation uses a medium or connector profile capable of the liveness, directionality, ordering, latency, and packet behavior that operation requires.

Transport properties affect:

- availability and latency;
- NAT and firewall traversal;
- congestion and loss behavior;
- packet size and fragmentation;
- addressability and multicast capability;
- relay and migration support;
- metadata exposure;
- cost, power, and resource use.

They do not, by themselves, establish Device identity, ephemeral Open participation, Closed authorization, or application authority.

## 3. Durable semantic state

The durable semantic subsystem stores only facts whose meaning must survive transport loss, process restart, reordering, duplication, and delayed delivery.

The base ledger is a durable Closed authority/governance ledger. Its retained
fact classes are:

```text
DurableFact =
    RoleGrant
    | RoleRevoke
    | Evict
    | MembershipAdmit
    | EvictionProof
    | SelfStandDown
    | Attestation
    | Resolution
    | AuthorityLineageResolution
```

`RoleGrant` and `RoleRevoke` retain the governed role state; `MembershipAdmit`
and `Evict` retain the member decision; `EvictionProof` retains the evidence
that makes an eviction admissible; `SelfStandDown` and `Attestation` retain
explicitly typed governance evidence; and `Resolution` plus
`AuthorityLineageResolution` retain the cited heads needed to resolve an
exclusive cell or its complete cross-cell lineage. A concrete Closed profile
may select a smaller set, but every selected class needs an adopted typed
definition. Reviewed application contract facts, if enabled, use a separate
explicitly selected domain and are not base Closed authority. There is no
arbitrary opaque fact body in the base ledger.

Open has zero base durable semantic facts. An Open device participates
ephemerally only after an exact-context handshake proves possession of the
corresponding Device key. Presence, join, leave, reconnect, candidate, and
session observations for both Open and Closed are runtime evidence and never
become semantic history. They may update a local read-only reachability or
roster projection, but they cannot create authority.

Every durable fact has:

- one canonical encoding;
- one content-derived identifier;
- an exact author and signature;
- one exact mesh or contract context;
- exact causal dependencies where required;
- domain-defined conflict and projection rules;
- bounded shape and verification cost.

Durable state is derived by a pure function:

```text
Project(
    mesh_context,
    projection_scope,
    verified_basis,
    accepted_durable_facts
) -> DerivedDurableState
```

In this specification, **projection means deterministic semantic derivation**. It is not forecasting, route construction, topology advertisement, physical reachability, or a networking operation.

`Project` may derive:

- the local Closed authorization view;
- durable capability state;
- explicit ambiguity in an exclusive durable semantic cell;
- optional application contract state.

It does not derive a live route, a working socket, a current relay allocation, a congestion state, or an `Online` boolean.
The local Open runtime-participant view is maintained outside `Project`; Open
topology, join/leave/reconnect, and session lifecycle never create or churn
semantic ledger facts.

### 3.1 Open

Open is permissionless ephemeral self-participation. It has no base-ledger
fact or durable admission record.

```text
Valid exact-context handshake with Device-key possession
    -> the endpoint may participate in the local Open runtime
```

No sponsor, founder, quorum, pair grant, signaling service, application,
identity-count vote, proof of work, or existing participant approves the
Device ID. A live Open session, presence observation, leave, or reconnect is
not written to semantic history and is not an authority input.

Resource pressure may refuse or evict local work. That is a typed resource or availability result, not an authorization denial.

### 3.2 Closed

Closed adds the exact authorization proof selected by the Closed mesh context. Closed may be fully locked down.

The Closed governance commitment may describe a threshold rule, delegation graph, multisignature policy, causal governance rule, or another reviewed decentralized proof system. It does not inherently identify a central server or online authority.

A Closed operation has authority only when the locally accepted Closed governance state proves it. A valid Device signature alone is not Closed admission.

### 3.3 Causality and conflict

Durable causality is a partial order. Two facts may be causally unrelated. Causal concurrency is not itself a conflict.

Each adopted fact domain separately classifies relevant concurrent facts as:

- **Independent**, when they affect different semantic cells.
- **Joinable**, when the domain defines an associative, commutative, and idempotent join.
- **Exclusive**, when incomparable facts compete for one singular semantic cell.

Only exclusive same-cell competitors are a no-go for singular authority. They remain explicit and fail closed until the domain-defined resolution cites the required heads.

### 3.4 Retention and compaction

The Closed ledger retains exact history by default. It may delete semantic
history only after an archive or an authority-ratified checkpoint provides a
verified, independently reopenable basis. A checkpoint must preserve:

- current durable state;
- unresolved exclusive conflicts;
- exact continuation validation required by the adopted domain;
- evidence still required by live guards or pending durable effects.

Facts continue to reference facts. A compaction base is verification evidence,
not an author or causal event. The shipped compaction boundary is bounded
checkpointing only: it may checkpoint or truncate WAL within the owner-funded
StorageBytes claim, but it does not claim a full-copy SQLite `VACUUM`. A full
copy or rewrite requires separately funded custody for its temporary copy,
metadata, and cleanup. Checkpointing is not silent time-based eviction or
semantic pruning, and no wall-clock age alone expires, removes, or rewrites a
fact.

### 3.5 Ledger admission, quarantine, and growth

The owner selects finite ledger limits independently for fact count, encoded
fact bytes, causal-edge count, per-author count/bytes, proof-verification
work, and indexed database bytes. The selected limits are configuration and
are recorded with the store; they are not hidden protocol constants and are
not inferred from an Open or Closed default.

Before every semantic mutation, the reducer computes the complete delta,
including the candidate fact, its encoded bytes, every new causal edge,
author-specific usage, proof work, indexes, and database pages. The exact
`N+1` request is refused before any graph, projection, ACK, identity, or
authority change when any owner-selected limit would be crossed. Refusal is
typed and leaves the prior state unchanged; it cannot be converted into an
identity change or a successful acknowledgement.

A fact whose dependencies are not present enters a finite,
dependency-indexed quarantine only after its own shape and author checks pass.
Quarantine entries and reverse dependency indexes consume the same count,
byte, edge, per-author, proof, and database claims. Duplicate delivery is
idempotent; a dependency failure or proof failure releases that exact
quarantine custody. There is no unbounded retry queue, global event cache, or
timer-based eviction.

The persistent implementation is a local-only indexed SQLite store with one
semantic writer on one dedicated blocking thread and one ordinary SQLite
connection using SQLite's default VFS, WAL journaling, and `FULL` synchronous
durability. SQLite owns file locking, recovery, WAL reuse, and automatic
checkpointing; MyOwnMesh owns semantic admission, quotas, and the writer
lifetime. For the
StorageBytes dimension, one process-accounted claim is `B = M + W + S + R`:
main database bytes, WAL bytes, shared-memory/sidecar bytes, and explicit
reserve. Named-file containment or VFS accounting does not establish backing
disk capacity, filesystem metadata capacity, or ENOSPC behavior; those remain
unobservable or residual until an exact provider contract proves them. Readers
may inspect snapshots, but only the single writer mutates the graph,
quarantine indexes, checkpoint metadata, or retention boundary. A deployment
may choose smaller owner limits, but it may not claim more than the configured
database budget.

For selected limits `C` (facts), `B` (encoded bytes), `E` (edges), `A` (per
author), `P` (proof work), and `D` (database bytes), the worst admitted live
ledger is bounded by the corresponding finite claim vector; an operational
growth estimate is the sum of `C` fact/index records, `B` payload bytes, `E`
edge/index records, and the selected SQLite/WAL/checkpoint overhead inside
`D`. Failure spam is bounded by the same pre-mutation vector and per-author
limits: rejected `N+1` attempts allocate no semantic record, no ACK, and no
new authority. A failed cleanup retains the exact charged claim until an
owner-observed terminal path settles it.

Opening stored durable state never recreates live sockets, channels, keys, reachability observations, connector objects, session handles, or resource reservations from a prior runtime.

## 4. Typed signaling

Signaling is a first-class networking mechanism. It is not merely file movement, and it is not the application data path.

Signaling carries two disjoint categories:

```text
Durable semantic exchange:
    durable signed facts
    inventories and exact dependency requests
    compacted-basis proofs where adopted

Ephemeral transport control:
    connect intent
    offers and answers
    candidates and candidate updates
    relay requests and relay responses
    cancellation and recovery hints
```

Ephemeral transport control is typed, bounded, context-associated where known, and unavailable to ordinary application payload APIs. It is not required to be content-addressed, retained forever, compacted, or projected as durable state.

A signaling message may be authenticated early, late, or not at all depending on its type and connector profile. Lack of early authentication limits the effect to bounded speculative work. It cannot create durable authority or an application session.

Signaling carriers may cache, delay, duplicate, reorder, censor, or reveal control information. Those behaviors affect availability and metadata exposure. They do not replace durable fact validation or endpoint authentication.

## 5. Connector runtime and speculative transport work

The connector owns pathfinding and packet transport. It may start useful work before endpoint identity and Closed authorization are fully proven.

![Usability-first pathfinding with a strict channel-promotion boundary](diagrams/02-channel-promotion-boundary.svg)

The diagram's pre-promotion objects are owned by
`engine/connection.rs` and `transport/webrtc.rs`. The proof task is
`endpoint_auth/task.rs`; its transcript is fixed by
`endpoint_auth/transcript.rs`. `engine/handshake.rs` delivers the verified
result to `runtime/session_broker/mod.rs`, whose exact current slot lives in
`runtime/peer_session/slot.rs`. Application entry points in
`application_gateway/{channels,rpc}.rs` can consume only that promoted slot.
Carrier replacement returns to connector work and must cross the same proof and
promotion boundary again.

An untrusted hint or partially authenticated signal may create only lease-backed speculative state, such as:

```text
ConnectorCandidateCapability
TransportHandle
RelayAllocationToken
ConnectedChannelCapability
TransportObservation
```

The connector may:

- gather local and remote candidates;
- probe addresses;
- open or accept sockets;
- allocate bounded TURN or member-relay state;
- apply admitted queued remote ICE candidates through the bounded connector
  planner;
- perform a transport handshake;
- measure whether packets pass;
- detect failure and clean up.

Those actions are real networking work. Preventing them until the full semantic proof completes would make the network slower and less usable without strengthening endpoint identity.

Before promotion, speculative work may not:

- mutate Open or Closed durable authority;
- expose an authenticated peer-session handle;
- deliver application payload to a consumer;
- send application payload as an authenticated peer;
- select arbitrary relay destinations;
- retain protected state or schedule protected work without a live resource lease.

MyOwnMesh does not maintain a parallel global route table. A connector may keep local ephemeral candidate and channel indexes for operation and diagnostics. Those local identifiers are not ledger facts, peer identity, application authority, or cross-runtime route identifiers.

### 5.1 Attempt, connector, and resource cardinality

One connection attempt is a cancellation and aggregate-resource owner. It may
own several connector candidates, but the current remote-ICE application
planner is not evidence of cross-connector racing. One WebRTC connector
candidate owns exactly one `RTCPeerConnection` and its one ICE agent. That ICE
agent may gather, receive, and check many internal ICE candidates and candidate
pairs.

These relationships describe ownership, not product-wide maximum counts. Basal MyOwnMesh defines no fixed semantic ceiling for Mesh runtimes, peers, attempts, sessions, or real-time flows. A finite host still has finite resources, so creating any of these objects is fallible. Admission succeeds only when the applicable resource provider grants the object's finite composite claim. Refusal is typed resource pressure or unavailability, never an Open or Closed authorization result.

```text
host or process resource provider
    -> grants finite ResourceLease for an exact ResourceClaim
    -> process resource root
        -> Mesh resource scope
            -> attempt, candidate, callback, cleanup, and flow owners

sum of live and failed-cleanup-retained claims in each resource dimension
    <= resource grant currently assigned to the process
```

Mesh scopes attribute use to one finite process grant. Creating another Mesh scope does not create capacity.

Basal MyOwnMesh constrains the finite provider by property, not by algorithm. Any conforming provider must preserve:

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

P6 is stated over fairness roots and attribution child scopes. Both are closed architectural definitions:

```text
FairnessRoot
    the unit of scheduling attribution that a provider serves
    selected locally by the trusted provider or ingress owner that
        installs the grant
    process-local and opaque: never transmitted, never compared across
        processes
    not mintable by the claimant it attributes: no unverified claimant,
        peer, or wire assertion may name, select, split, rotate, or
        multiply one
    not a semantic or durable identity, and not an authentication or
        authorization root or capability; holding one grants nothing

AttributionChildScope
    an accounting and attribution refinement beneath exactly one
        FairnessRoot
    may divide, label, and measure use within that root
    carries no independent scheduling entitlement, and adds no share,
        turn, or service weight to the root beneath which it sits
```

**P6, partition non-amplification.** Subdividing a fairness root's attribution into more child scopes must not increase that root's cumulative selections, or its cumulative admitted quantity in any resource dimension, at any point of the provider's decision sequence, and must not move any competing root's selection to a later decision. The requirement is one-way: a ceiling on what subdivision can gain, not a guarantee that subdivision is free. It implies no equality of outcome, permits the subdivided root to fare worse and a competitor to fare better, and constrains nothing else. The exact model, comparisons, and conformance controls are in [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md).

P6 is silent about who a claimant is. It binds no apparent ingress source to a real-world actor, is not Sybil resistance, and does not decide how many roots an actor receives. It is equally not a progress property: it says nothing about progress, throughput, latency, backpressure, or behavior under hostile ingress, which are separate obligations of the ingress path.

Selection order, rotation rule, and pending-demand cardinality are concrete provider policy, not basal architecture. This architecture selects no scheduler, no fairness-root taxonomy, no weights or quotas, and no mapping from roots to service turns. A resource-provider implementation chooses them and may replace them with any policy preserving P1 through P8. No other subsystem may depend on a particular choice.

A conforming provider satisfies P1 through P8. Whether any particular provider does so is recorded in the implementation and transition documents, not here.

**The committed grant is an accounting commitment.** It is not proof that substrate capacity exists, and not a promise that an allocation will succeed. Containment and reservation are separate premises, each proved per resource dimension, and a provider never presents unproved containment or backing as established. An accounting-only commitment is a coherent basis for admission, and it is not by itself sufficient for final production closure.

**Grant change never forges a release.** The committed grant is not required to be constant. A provider may raise it, and may lower it, but never below committed use, which includes both the charges already held and any reservation held for an admission in flight. No grant change ever releases, revokes, reduces, or reattributes a live claim or a reservation. Only the exact owner releases, after its own cleanup, exactly as P2 requires. A provider may request retirement from an owner whose contract declares that lease reclaimable; the request is sticky, carries no timer, and alters no claim. A measurement never becomes a grant by being taken. The exact treatment of observation, target, containment, backing, committed grant, charged sum, in-flight reservation, capacity, and admission fit is in [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md).

No cooperative mechanism guarantees admission. Capacity held by nonreclaimable admitted work, an ignored retirement request, and failed-cleanup retention can each prevent admission indefinitely. An explicit named P5 local isolation domain, partition or reserved share, or optional local ceiling or cost boundary may impose stricter restrictions for a locked-down appliance, Closed deployment, carrier cost boundary, or test. That wrapper is explicitly optional, is never required for ordinary construction, and is not basal mesh semantics.

Resource limits have four distinct sources:

```text
Protocol-shape bound
    canonical parser or wire validity

Provider structural limit
    actual transport, codec, kernel, or hardware constraint

Runtime resource availability
    currently granted memory, handles, sockets, tasks, storage, and work

Optional local policy ceiling
    explicit administrator, cost, isolation, or compatibility restriction
```

One category cannot be presented as another. Measurements characterize cost and may inform selection of an explicit named P5 restriction; they do not themselves narrow accounting capacity. They do not establish a universal peer, Mesh, attempt, session, or flow count.

An exact lease is exact only for the resource units named by its claim. Native WebRTC, allocator, runtime, kernel, driver, and external relay state that the adapter cannot count remains an explicit residual. A conforming implementation must conservatively claim, isolate, or report that residual. It must not describe a visible Rust allocation or a connector-count proxy as complete native or OS accounting.

```text
one connection attempt
    -> multiple connector candidates

one WebRTC connector candidate
    -> one RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and candidate pairs

DataChannelOpen for that exact live WebRTC connector candidate
    -> ConnectedChannelCapability
    -> not endpoint authentication or session authority
```

An internal `LocalIceCandidate` is typed transport-control input to a WebRTC connector candidate. It is not a connector candidate, an attempt, or an authority capability.

### 5.2 Connector profiles

A connector profile defines the transport-specific work it performs, including:

- candidate discovery and accepted hints;
- connectivity checks and nomination;
- relay allocation;
- packet and stream behavior;
- congestion and flow control;
- migration and recovery;
- live observations and failure reports;
- resource claims.

Profiles may include:

```text
Direct LAN
ICE with STUN and TURN
Bounded encrypted Hub forwarding fallback
Closed member relay
QUIC-native transport
Serial or radio transport
Future non-IP transport
```

A common connector interface does not erase their real operational differences.

## 6. Channel promotion and endpoint session

A working channel is not yet an authenticated peer session.

A channel may be promoted only when:

```text
MayPromoteChannel(channel) :=
    ChannelCurrentlyWorks(channel)
    and FreshMutualDeviceAuthentication(channel)
    and ExactMeshContextBinding(channel)
    and ApplicableOpenOrClosedPolicyAllowsPeer
    and AuthenticatedLocalPrincipalAllowsUse
    and PostAuthenticationResourcesReserved
```

Fresh endpoint authentication binds both Device identities and the exact mesh context to the channel that actually passed traffic. The selected endpoint-authentication profile must prevent replay of an old transcript onto another channel and must derive fresh traffic protection for that channel or session.

The result is a local opaque capability:

```text
AuthenticatedPeerSession {
    opaque_handle_capability,
    mesh_context,
    local_device_id,
    remote_device_id
}
```

Internally, the capability is bound to:

- the authenticated channel or authenticated live-channel set;
- the endpoint-authentication transcript;
- the authenticated local principal;
- current Open or Closed policy state;
- current resource reservations;
- one live runtime incarnation.

It is not reconstructed from stored records, a session number, a route identifier, or a serialized handle.

Every application send, receive, callback, and recovery action rechecks the live capability and current guards.

## 7. Carriers and relays

A session may use:

```text
DirectEndpointCarrier
TurnCarrier
HubEncryptedFallbackCarrier
ClosedMemberRelayCarrier
```

All carriers preserve the same endpoint relationship:

```text
AuthenticatedPeerSession(A, C)
```

Carrier choice changes latency, loss, cost, metadata exposure, and availability. It does not change A or C's Device identity or application authority.

### 7.1 Bounded Hub introduction and encrypted transit fallback

A configured Hub may introduce bounded endpoint demand; it is not an
application payload owner, trust root, membership authority, permanent-peer
grant, or veto over viable direct or alternate paths. A directly usable
endpoint connection is preferred and TURN remains a distinct ICE service.
Introduction may negotiate the direct endpoint channel without making the Hub
a carrier.

If residual Hub transit is selected, it is a separately bounded profile. The
endpoints derive a fresh endpoint-to-endpoint E2E epoch bound to the exact mesh
context and full endpoint keys before payload is usable. The Hub may
copy/forward endpoint ciphertext and observe carrier metadata, but cannot
decrypt or read application plaintext. If the E2E epoch cannot be established,
refuse; never fall back to plaintext. This is the adopted architecture
direction, not a shipped-process or qualification claim.

### 7.2 Closed member relay

The supported Closed member relay is an explicit three-party path, not an automatic A-C transport upgrade. A and B independently discover, endpoint-authenticate, and promote their exact leg; B and C do the same for their exact leg. B remains visibly Device B and is the local canonical relay member. Anonymous attestation is neither required nor desirable.

After both legs are live, the endpoints establish one opaque session through B with the exact control sequence:

```text
A -> B: Open(context, requester=A, relay=B, target=C, session)
B -> C: Offer(same route, requester share)
C -> B: Accept(same route, target share)
B <-> A/C: ClosedRelayData carrying opaque ciphertext
A <-> C: endpoint-local seal/open over the opaque session
```

The route is the complete `(context, requester, relay, target, session)` tuple. Every control and data message is validated against that route before state mutation or forwarding. The endpoint key agreement uses signed ephemeral X25519, HKDF-SHA256, and AES-256-GCM with directional nonce and replay fences. Only A and C hold endpoint session cryptographic state; B forwards `OpaqueRelayPacket` values and cannot read A-C application plaintext.

B's allocation is a provider-backed, move-only resource lease covering two bounded directional relay queues and their retained custody. Admission requires current Closed authorization, exact promoted A-B and B-C session witnesses, the local relay policy, and the exact route. The runtime rejects arbitrary host or port selectors, fanout, recursive relays, and replacement or stale owner generations. A refusal constructs no relay state; expiry, stale ownership, endpoint retirement, queue closure, and shutdown settle the exact allocation and wake bounded waiters.

The relay may drop, delay, reorder, meter, or correlate opaque traffic and observe carrier metadata. Those are availability and metadata effects, not endpoint authority. This profile does not claim automatic candidate racing, relay-to-relay handoff, or a generic promoted A-C WebRTC channel: Open/Offer/Accept and the endpoint cryptographic session are required before application data is usable.

## 8. Closed relay close and shutdown

![Closed member relay explicit setup and terminal close](diagrams/04-closed-member-relay-handoff.svg)

The route vocabulary is `protocol/relay.rs`. Runtime allocation and endpoint
state are owned by `runtime/relay/mod.rs`; engine dispatch and current promoted
leg witnesses are owned by `engine/closed_relay.rs` and
`runtime/peer_session/slot.rs`. Application plaintext enters and leaves only at
the A/C endpoint session. B's production path accepts and emits only route-bound
control plus `OpaqueRelayPacket` ciphertext. `Close`, acknowledgement, exact
generation settlement, waiter wakeup, and driver join are part of the same
runtime owner rather than an external cleanup convention.

Close is also explicit and route-bound. An endpoint sends `Close` through its exact promoted leg; B validates the authenticated sender and exact allocation generation, marks the slot closing, and forwards the canonical close once to the opposite endpoint. The opposite endpoint closes its exact local session and returns the acknowledgement through B. B settles the exact allocation, and the initiator becomes terminal. Duplicate close messages are idempotent for the same terminal tombstone and cannot affect a successor allocation with a reused session identifier.

Shutdown uses the same exact-owner fence. It wakes pending Open/Offer/Accept waiters, checked-out receives, and relay queue operations; it then settles endpoint, accepted, pending, closing, and allocation custody before the driver join completes. No relay or endpoint handle remains usable after its exact owner, route, or generation is stale.

## 9. Reachability and freshness

Reachability is a local evidence vector, not a durable global fact.

A useful view may include:

```text
PeerReachabilityView {
    durable_closed_authorization_projection,
    signaling_response_observation,
    candidate_and_channel_observations,
    authenticated_session_state,
    local_observation_ages
}
```

Evidence strength for current application reachability is approximately:

```text
fresh authenticated session traffic
    stronger than
fresh endpoint-authenticated channel confirmation
    stronger than
fresh transport connectivity check
    stronger than
fresh signed presence response
    stronger than
receipt of cached durable state
```

Freshness is computed from local monotonic observation time. A remote or carrier timestamp does not establish local freshness.

A failed probe or expired observation means `Unknown` or `FailedObservation`. It does not synthesize withdrawal, removal, or application denial.

## 10. Signaling and application payload boundary

The signaling and payload message spaces are disjoint.

- Durable facts contain no application-payload variant.
- Ephemeral transport-control messages contain no generic application bytes.
- Signaling caches do not forward application packets.
- A connector callback cannot directly deliver application payload before channel promotion.
- Application payload requires a live `AuthenticatedPeerSession` capability.

Physical multiplexing does not alter this rule. Signaling, relay control, endpoint authentication, and application packets may share a process, host, socket, or lower transport where a profile permits it, but immutable message classification, parser dispatch, keys, capabilities, queues, and effects remain non-substitutable.

An intentional application intermediary is different. If B terminates an A-B application session, processes plaintext, and authors a new B-C application operation, B is an explicit application endpoint. That is not transparent MyOwnMesh relay behavior.

## 11. Application and session-data-plane boundary

Applications request an exact mesh context and remote Device ID. They do not construct durable facts, transport-control messages, candidates, routes, relay allocations, or endpoint-authentication transcripts.

MyOwnMesh returns:

- a derived roster view;
- bounded reachability observations;
- a live authenticated peer-session capability;
- typed session lifecycle and diagnostics;
- optional connector-native data-plane capabilities bound to that live session.

The basal architecture does not define a `MediaLane`, video lane, audio lane, fixed codec, or fixed lane count. A connector may provide a native real-time flow mechanism, such as WebRTC RTP tracks, because transport-specific low-latency delivery is part of useful networking. MyOwnMesh owns binding that flow to the authenticated session, lifecycle, resource limits, backpressure, and safe delivery. The application owns codec choice, frame format, media purpose, track naming, screen/camera/audio meaning, composition, and product policy.

A connector may provision native track objects before promotion under the bounded speculative-work rules. No encoded frame reaches an application, and no application frame is sent, until the associated session capability is live. Connector-native flow support is optional. A data-only connector remains conforming.

Application authorization begins after session promotion. A mesh session proves the exact peer and context. It does not automatically grant a screen, file, camera, terminal, command, or other application capability.

## 12. Optional causal contracts

The durable semantic subsystem may host reviewed typed application contract domains. Those domains may add consensus, total ordering, blocks, replicated execution, threshold authorization, or economic mechanisms when their application semantics require them.

Those mechanisms remain optional and domain-confined. They do not serialize ordinary pathfinding, reachability, relay allocation, packet carriage, or unrelated mesh facts.

MyOwnMesh is therefore not a transport-removed ledger and not a blockchain-shaped network base. It is a usable hybrid network whose durable semantic component can also support causal contracts.

## 13. Hard architectural invariants

1. **Transport does work but does not create authority.** Transport hints and channels may drive bounded networking work. Device identity and mesh authority still require their exact proofs.
2. **Security gates promotion, not path discovery.** A candidate may be attempted before endpoint authentication. Application use may not.
3. **Open remains open.** Any authentic Device ID may self-participate under the Open rules.
4. **Closed alone adds governance authorization.** Closed can be fully locked down under its selected proof system.
5. **Durable facts and ephemeral transport control are distinct.** Only genuinely persistent meaning enters the durable semantic store.
6. **Projection is durable semantic derivation only.** It does not create or forecast routes.
7. **No route ledger is required.** Candidate, route, channel, and handoff state are live connector state unless a separate application domain explicitly chooses otherwise.
8. **A working socket is not a session.** Endpoint authentication, mesh policy, local principal, and resources are required for promotion.
9. **Carrier is not peer identity.** Direct, TURN, bounded encrypted Hub forwarding, and Closed member relay preserve the same authenticated endpoint relationship.
10. **No anonymous member relay.** A Closed member relay is visibly attributable to its Device identity.
11. **No relay-authorized handoff.** Relays cannot add, select, or retire an application-usable channel.
12. **Signaling and payload remain disjoint.** No ordinary application path can use signaling as a generic message bus.
13. **Reachability is positive local evidence.** Absence or expiry is not revocation.
14. **Work owns resources before use.** Every protected allocation, retained value, task, queue entry, native object, and scheduled work unit holds a live finite lease from the applicable provider.
15. **Semantic cardinality remains open.** Basal MyOwnMesh has no fixed maximum Mesh, peer, attempt, session, or flow count. Admission follows actual resource claims and current provider availability. Refusal is typed resource pressure or unavailability, never an Open or Closed authorization result in either direction.
16. **Resource scopes do not mint capacity.** Child scopes share one finite process grant with no basal weights, quotas, shares, or partitions. The basal guarantees are properties, not an algorithm: claims never exceed the actual provider domain; only the exact owner releases a claim after cleanup, so no forged release exists and cleanup keeps the resources it needs; no scope mints capacity; unused capacity is work-conservingly borrowable; any isolation or reserved share is explicit local policy; and subdividing attribution beneath a fixed fairness root cannot increase that root's cumulative selections or cumulative admitted quantity in any dimension, and cannot move a competing root's selection later, because attribution child scopes refine accounting beneath one fairness root without creating another share or turn. The selection order, rotation rule, and pending-demand cardinality that satisfy those properties are concrete provider policy, not architecture. Capacity becomes reusable only after owner Drop following cleanup. Failed cleanup transfers the exact charge into retention. Nonreclaimable admitted pressure, ignored retirement, and failed cleanup can still prevent admission.
17. **Time is not resource truth.** A slow operation may retain its finite lease indefinitely. Elapsed time alone cannot create, release, or invalidate resources or authority.
18. **One reducer and session broker own promotion and semantic effects.** Adapters and callbacks cannot bypass the guards.
19. **Complete eclipse is not claimed solved.** A carrier can withhold information and deny availability, but cannot forge the missing proofs.

## 14. Owner decisions that remain explicit

Owner review must select and test:

1. Device ID, Mesh ID, and exact mesh-context encodings.
2. Canonical durable-fact encoding, hash, signature profile, and test vectors.
3. The Closed governance proof, conflict, recovery, and compaction rules.
4. The durable fact families and optional application contract domains in each profile.
5. The supported signaling carriers and ephemeral transport-control schemas.
6. Connector profiles and required egress environments.
7. Endpoint-authentication and channel-binding protocols.
8. Direct, TURN, bounded encrypted Hub-forwarding, and Closed member-relay requirements.
9. Resource-provider integration: the provider actually used in each deployment form, its structural limits, its host isolation domains, and any optional local resource ceiling.
10. Reachability observation and local path-selection policies.
11. Session-handle sharing, recovery, and application lifecycle behavior.
12. Measurements used for performance characterization, provider-cost estimation, regression detection, opaque-allocation discovery, and optional deployment policy.

Required measurable evidence is separate from these owner selections. Before
architecture compliance is called complete, durable runs must exercise: scale
and exact `N+1` refusal for Open and Closed paths; Open/Closed separation with
no runtime lifecycle fact; duplicate/no-op delivery with unchanged projection
and storage usage; restart reconstruction of the exact Closed projection with
no revived live handles; bounded checkpoint/reopen behavior; and terminal
provider/resource baselines after success, refusal, failure, and shutdown.
Source inspection or a unit result alone is not a compliance PASS, and this
document records no final PASS without those durable runs.

Item 9 is delivered as a provider and integration report, not as a dossier of chosen numbers. For each provider and deployment form, that report names which resource dimensions the provider exposes exactly, which are conservatively claimable, which are isolatable in a host-enforced domain, and which remain unobservable residuals. It records the concrete scheduling policy that provider implements, together with the evidence that the policy preserves the basal properties in section 5.1.

No numeric product cardinality is inferred from a plausible default. Any numeric protocol or provider limit must be proven by that protocol or provider. Any optional local ceiling requires explicit owner selection and is never assumed present by basal conformance.
