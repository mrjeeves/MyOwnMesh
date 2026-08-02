# MyOwnMesh formal model and proof obligations

Status: formal architecture model and proof obligations for the hybrid networking architecture in [`ARCHITECTURE.md`](ARCHITECTURE.md).

This document separates mathematical claims from the minimal architecture and concrete implementation constraints. These are proof sketches and obligations, not a claim of completed machine verification.

## 1. Model and notation

Let:

```text
M      exact MeshContext
D      finite accepted durable fact set for one projection scope
B      Genesis or one verified durable semantic basis
P      Project(M, scope, B, D), the derived durable state
L      live runtime state
I      one explicit typed input
Q      one bounded resource claim vector
E      one bounded effect set
```

The durable semantic function is:

```text
Project(M, scope, B, D) -> P
```

The live transition function is:

```text
Step(P, L, I) -> PlannedLiveState x Q* x E*
```

The connector runtime has local opaque capabilities:

```text
ConnectorCandidateCapability
ConnectedChannelCapability
AuthenticatedChannelCapability
SessionCapability
```

A capability is unforgeable within the selected runtime model, bound to one runtime incarnation, and not reconstructible from a durable fact or serialized identifier alone.

For one live connection attempt `a`, let `C(a)` be its finite set of connector candidates. Every `c` in `C(a)` has exactly one attempt owner. A WebRTC candidate `c_w` owns one peer connection and one ICE agent. Its internal ICE candidate and pair sets are finite live connector state, not members of `C(a)` and not authority capabilities.

```text
DataChannelOpen(c_w)
and Owns(a, c_w)
and Active(a)
    -> ConnectedChannelCapability(c_w)
```

If `a` is retired before this transition, no delayed callback for any member of `C(a)` may produce a connected-channel capability or mutate the replacement attempt.

### 1.1 Durable facts

For durable fact `f` in domain `d`:

```text
FactID(f) = H(domain_separator_d || CanonicalEncode(f.content))
```

A valid signed durable fact satisfies:

```text
CommonValid(M, f) :=
    Canonical(f.content)
    and RecomputeFactID(f) = f.fact_id
    and DeviceID(f.author_public_key) = f.author_device_id
    and Verify(f.author_public_key, f.fact_id, f.signature)
    and f.mesh_context_digest = Digest(M)
    and DomainShapeValid_d(f)
    and WithinDurableProtocolMaxima_d(f)
```

### 1.2 Causal relation

Let `x ≺ y` mean that `y` directly or transitively names `x` as a required durable predecessor.

Causal concurrency is:

```text
x || y  iff  not (x ≺ y) and not (y ≺ x)
```

The adopted durable domain separately defines:

```text
ConflictKey_d(f)
Relation_d(x, y) in { Independent, Joinable, Exclusive }
```

Two causally concurrent facts are exclusive siblings only when the domain maps both to the same exclusive semantic cell.

### 1.3 Live transport state

A transport hint is any bounded typed input that may inform pathfinding:

```text
TransportHint =
    AddressHint
    | CandidateHint
    | IncomingSocketHint
    | RelayHint
    | ConnectIntent
    | ConnectorSpecificHint
```

A hint is not authority. It may enter `Step` and cause only a member of the pre-authentication effect set:

```text
PreAuthEffect =
    CreateBoundedCandidate
    | OpenBoundedTransport
    | SendBoundedProbe
    | CreateBoundedRelayAllocation
    | PerformBoundedHandshake
    | RecordBoundedTransportObservation
    | CancelOrReleaseCandidate
```

A promoted session effect is separate:

```text
PromoteSession(
    authenticated_channel,
    exact_mesh_context,
    exact_endpoint_ids,
    authenticated_local_principal,
    reserved_resources,
    opaque_session_capability
)
```

### 1.4 Session promotion predicate

For connected channel `c`, local device `A`, remote device `C`, and local principal `u`:

```text
MayPromote(c, M, A, C, u) :=
    ChannelCurrentlyWorks(c)
    and FreshMutualDeviceAuthentication(c, A, C)
    and ChannelBindsExactMesh(c, M)
    and DurablePolicyAllows(P, M, A, C)
    and LocalPrincipalAllows(u, M, A, C)
    and PostAuthResourcesReserved(c, A, C, u)
    and FreshSessionCapabilityReserved(c, A, C, u)
```

`DurablePolicyAllows` means Open self-participation under the Open profile or the selected Closed authorization proof under the Closed profile.

## 2. Assumptions

The cryptographic claims depend on:

1. Canonical encodings are unique for every accepted durable fact and endpoint-authentication transcript.
2. The selected hash has the adopted collision, preimage, and second-preimage security.
3. Device signatures are strictly verified and existentially unforgeable under the adopted assumptions.
4. The endpoint-authentication protocol proves fresh possession of both Device keys and binds them to the exact working channel and mesh context.
5. Session and packet protection provides confidentiality, integrity, role separation, and replay rejection under the adopted assumptions.
6. Opaque local capabilities cannot be forged or reconstructed from serialized public values.
7. Only the reducer, connector runtime, endpoint authenticator, and session broker transitions described by the implementation contract mutate their respective owned state.
8. Every protected allocation is dominated by a successful resource reservation.
9. Honest endpoint private keys and the runtime paths that use them are not compromised.

The availability claims explicitly exclude complete control of every usable signaling or data path by an adversary.

## 3. Durable fact integrity and transport substitution

### Theorem 3.1. Exact durable content integrity

Assume the canonical encoding, hash, and signature premises. A carrier cannot change any accepted durable fact field without either changing the computed Fact ID or forging the author signature for the changed Fact ID.

#### Proof sketch

Every state-deriving field is inside the canonical content. Any field change changes the canonical byte string. Under the hash assumptions, the changed content does not retain the original Fact ID except with negligible probability. The original signature verifies only over the original Fact ID. Therefore the changed fact fails recomputation or signature verification.

### Theorem 3.2. Carrier non-authorship

A carrier account, socket identity, service identity, address, path, or delivery provenance cannot satisfy durable fact authorship unless it also supplies the exact valid Device signature required by `CommonValid`.

#### Proof

Carrier metadata is not an input to `CommonValid`'s authorship predicate. The author is derived from the signed public key and exact Device ID. Therefore carrier identity is irrelevant to authorship.

### Theorem 3.3. Durable semantic transport substitution

Let deliveries `T1` and `T2` produce the same accepted durable fact set `D`, the same exact context `M`, scope, and semantically equivalent verified basis `B`. Then:

```text
Project(M, scope, B, D) under T1
    =
Project(M, scope, B, D) under T2
```

#### Proof

`Project` is a pure function of the listed semantic inputs. Transport identity, delivery order, socket state, and delivery timing are not inputs. Equal explicit inputs produce equal output.

### Corollary 3.4. Transport independence does not imply operational equivalence

The theorem above does not imply that `T1` and `T2` have equal latency, loss, directionality, reachability, bandwidth, metadata exposure, or ability to form a live endpoint channel.

## 4. Durable causality and conflict

### Lemma 4.1. Durable causality is a partial order

If the required predecessor graph is acyclic and predecessor references are exact Fact IDs, then `≺` is irreflexive and transitive. Its reflexive closure is a partial order.

#### Proof

Acyclicity gives irreflexivity. Transitive closure gives transitivity. Exact Fact IDs make ancestry independent of delivery order.

### Theorem 4.2. Common ancestry is insufficient for conflict

Two durable facts that reference a common context or support fact are not exclusive siblings unless the adopted domain maps them to the same exclusive `ConflictKey`.

#### Proof

Causal support and semantic conflict are separate domain functions. A shared support reference does not imply equal conflict keys. Therefore conflict cannot be inferred from common ancestry alone.

### Theorem 4.3. Join-order independence

If the adopted join operator `⊔` is associative, commutative, and idempotent, projection of a finite set of joinable facts is independent of delivery order and duplication.

#### Proof

Associativity removes grouping dependence, commutativity removes order dependence, and idempotence removes duplicate dependence.

### Theorem 4.4. Exclusive sibling confinement

If `x` and `y` are valid, causally incomparable, and occupy the same exclusive semantic cell, then neither may independently supply the singular projected proposition after both are accepted.

#### Proof sketch

The domain projection rule maps an exclusive incomparable head set of cardinality greater than one to `Ambiguous` or another fail-closed result. No arrival, hash, carrier, or identity-count rule is part of the projection. Therefore neither sibling alone supplies the singular proposition.

## 5. Open and Closed authority

### Theorem 5.1. Open permissionlessness

Under the Open rule, any Device key may create its own valid Open participation fact without a third-party authorization input.

#### Proof

The Open participation predicate requires only `CommonValid`, exact Open context, self-authorship, and the Open domain shape. No existing participant, service, application, quorum, or pair grant is an input.

### Theorem 5.2. Open authority confinement

An attacker controlling arbitrarily many Open Device keys cannot author a durable fact as an uncompromised Device ID or resolve another Device ID's exclusive stream solely through identity count.

#### Proof

Each durable fact requires the exact author's signature. Identity count is not an authority or conflict-resolution input. More keys create more self-authored identities but do not yield another key's signature.

### Theorem 5.3. Closed authority confinement

A Device signature that lacks the exact accepted Closed authorization proof cannot create a Closed authority-bearing projection.

#### Proof

The Closed projection predicate is `CommonValid` plus the selected Closed authorization verifier over the accepted Closed governance state. Failure of the additional predicate prevents the authority-bearing projection.

### Corollary 5.4. Closed does not imply a central authority

A Closed governance commitment can encode any reviewed decentralized proof rule. The theorem requires exact proof verification, not a central server or leader.

## 6. Speculative transport work

### Definition 6.1. Pre-authentication work envelope

Let `W_pre` be the owner-selected finite vector of allowed pre-authentication work and retained state. Every speculative transport effect must reserve against `W_pre` before allocation.

### Theorem 6.2. Speculative-work confinement

Assume the reducer and connector effect unions are closed and every pre-authentication effect is resource-guarded. Any untrusted hint can cause at most the reserved pre-authentication effects. It cannot directly create durable authority, an authenticated session capability, or application delivery.

#### Proof

By construction, the only transitions reachable from an untrusted hint before `MayPromote` are members of `PreAuthEffect`. None contains a durable authority mutation, `PromoteSession`, or application-delivery effect. Closed effect unions exclude any alternate path. Resource reservation bounds each reachable effect.

### Corollary 6.3. Bounded early transport allocation is not a security failure

Creating a candidate, socket, relay allocation, transport object, or bounded media quarantine before endpoint authentication is conforming when it remains inside `W_pre` and cannot reach application delivery or authority.

### Theorem 6.4. Identity rotation does not bypass the global pre-authentication bound

If `W_pre` includes a global resource component checked before per-identity accounting, an attacker cannot exceed the global bound merely by using fresh valid or invalid Device identities.

#### Proof

Every allocation consumes the global component independent of identity. The sum of successful reservations cannot exceed the global capacity.

## 7. Channel promotion

### Theorem 7.1. Working transport is insufficient for session authority

A connected socket, successful ICE check, TURN allocation, relay allocation, or transport handshake alone cannot produce an `AuthenticatedPeerSession`.

#### Proof

Each omits one or more required conjuncts of `MayPromote`, including fresh mutual Device authentication, exact mesh binding, durable Open or Closed policy, local-principal admission, post-authentication reservation, or fresh session capability.

### Theorem 7.2. Channel-promotion soundness

If a conforming runtime exposes `AuthenticatedPeerSession(A, C, M)`, then at the exposure transition:

1. A and C were freshly authenticated over the exact working channel;
2. the channel was bound to `M`;
3. the applicable Open or Closed policy allowed the peer under the local accepted durable state;
4. the local principal was authorized;
5. required post-authentication resources were reserved;
6. the exposed handle was a fresh live capability.

#### Proof

`PromoteSession` is the only effect capable of exposing the handle. Its guard is exactly `MayPromote`. Therefore every conjunct held at commit and is rechecked before effect execution.

### Theorem 7.3. Durable evidence cannot reconstruct a live session

Reopening a durable store or replaying old durable facts or ephemeral transport-control messages cannot reconstruct a prior `SessionCapability`.

#### Proof

The capability is created only by the live promotion transition and bound to one runtime incarnation, authenticated channel, principal, and resource reservation. None is derivable from durable facts or old control bytes. Store opening initializes live capabilities empty.

### Theorem 7.4. Replayed control cannot promote a different channel

Assume fresh endpoint challenges and channel binding. Replaying a control transcript from channel `c1` cannot satisfy `FreshMutualDeviceAuthentication(c2)` for a different channel `c2` except by breaking the endpoint-authentication premise.

#### Proof sketch

The endpoint-authentication transcript commits to channel-specific material and fresh endpoint contributions. A transcript for `c1` fails exact binding or freshness verification on `c2`.

## 8. No durable route identity is required

### Theorem 8.1. Route-identifier independence

The session-promotion safety predicate requires a working channel and exact endpoint authentication, but does not require a durable route identifier, global route record, monotonic path generation, or route consensus.

#### Proof

Inspect `MayPromote`. Its inputs are the live channel, exact endpoint proof, mesh context, durable policy, local principal, resources, and live capability. A route identifier is absent. Therefore a route identifier is not necessary for the stated safety property.

### Corollary 8.2. Local connector handles are sufficient for correlation

A connector may correlate asynchronous callbacks and cleanup using unforgeable local candidate and channel capabilities. Those values need no cross-runtime semantic meaning.

### Theorem 8.3. Old callback confinement

If every connector callback carries the exact live local capability for the candidate or channel it mutates, destroying that capability prevents a delayed callback from mutating a replacement candidate or channel.

#### Proof

The replacement has a different unforgeable capability. Exact capability mismatch rejects the delayed callback before mutation.

## 9. Handoff and recovery

Let `V_x` be endpoint `x`'s set of live authenticated channel capabilities for one peer session. Let `Select_x(V_x, observations)` be a local path-selection function.

### Theorem 9.1. Authenticated channel addition is safety preserving

Suppose `V'_x = V_x ∪ {d}` and `d` entered the set only after satisfying the same endpoint-authentication and mesh-binding requirements as the existing channels. Then every channel in `V'_x` is an authenticated A-C channel.

#### Proof

Channels already in `V_x` satisfy the invariant by induction. The sole insertion transition verifies the invariant for `d`. Therefore all members of the union satisfy it.

### Theorem 9.2. Channel removal cannot introduce forgery

If `V'_x = V_x \ {b}`, any packet or operation accepted using `V'_x` was also eligible under a member of `V_x`. Removing a channel cannot add an unauthenticated channel.

### Theorem 9.3. No global switch is required

Safety requires only that each used channel be individually authenticated. It does not require A and C to select one globally current carrier at the same instant.

#### Proof

Application packet acceptance is keyed to the authenticated channel and endpoint-session binding, not to a global carrier variable. Temporary use of two valid channels does not weaken endpoint identity.

### Theorem 9.4. Relay-to-relay signaling is unnecessary for endpoint handoff

A replacement relay D can be authenticated and used through endpoint communication A-D, C-D, and A-C without any B-D state transfer.

#### Proof

D's candidate channel and allocation are independently established. A and C perform fresh endpoint authentication or current-session key confirmation through D. No security predicate requires B's approval, key, or state.

### Theorem 9.5. Forced failure can influence selection but not authorization

An attacker capable of dropping channel B may cause local policy to choose another already authenticated channel D. The attacker cannot add D to the authenticated set or promote an unauthenticated D channel solely by dropping B.

#### Proof

Failure changes live observations and selection input. It does not satisfy the insertion or promotion predicate for D.

## 10. Relay safety

### Definition 10.1. Exact relay allocation

A relay allocation is live bounded state naming one exact endpoint pair and one exact relay instance. It accepts only endpoint-authentication packets or endpoint ciphertext for that pair.

### Theorem 10.2. Relay non-substitution

Assume A-C endpoint authentication and packet protection. A malicious TURN, generic relay, or Closed member relay cannot cause C to accept an application packet as authored by A without breaking endpoint authentication or packet integrity.

#### Proof sketch

The relay lacks A-C endpoint keys. C accepts application data only after verification under keys derived by A and C over an authenticated channel. Relay modification or substitution fails verification.

### Theorem 10.3. Exact-destination confinement

If the relay effect accepts no caller-supplied arbitrary destination and is created only for one exact endpoint pair, a conforming relay operation cannot become a general network gateway or application fanout service.

### Corollary 10.4. Visible member relay identity

A Closed member relay may be authenticated as Device B. Anonymous attestation is unnecessary. Visibility does not weaken the A-C endpoint theorem because B is not an endpoint of the inner A-C session.

### Residual relay powers

The relay may deny, delay, reorder, duplicate, meter, and correlate traffic and may observe packet metadata. These are availability and privacy residuals, not endpoint-authentication failures.

## 11. Signaling and payload noninterference

Let the accepted message alphabets be disjoint:

```text
Σ_durable
Σ_ephemeral_transport_control
Σ_endpoint_authentication
Σ_application_payload
```

### Theorem 11.1. Signaling cannot directly deliver application payload

If signaling parsers and reducers have no effect variant containing application bytes and an application consumer, then a signaling input cannot directly produce application delivery.

#### Proof

No transition in the signaling effect union reaches the application-delivery effect. Closed exhaustiveness of the union excludes another case.

### Theorem 11.2. Application APIs cannot use signaling as a generic message bus

If ordinary application APIs expose no raw durable-fact or ephemeral-signal constructor and the accepted signaling schemas contain no generic application byte field, an ordinary application cannot place its payload into a supported signaling operation.

### Theorem 11.3. Physical multiplexing does not merge semantics

Sharing a process, socket, host, or lower transport does not invalidate noninterference when immutable message classification, parser dispatch, keys, capabilities, queues, and effects remain disjoint.

#### Proof sketch

Security follows from accepted types and reachable effects, not physical placement. The proof requires implementation refinement showing no cross-dispatch path.

### Theorem 11.4. Connector-native real-time flow confinement

Assume a connector-native real-time flow can be created or used by an application only through a live `SessionCapability`, and assume codec, track purpose, and lane labels are not inputs to durable authority, endpoint authentication, or channel promotion. Then creating, receiving, or changing such a flow cannot alter mesh participation, Closed authorization, peer identity, or session admission.

#### Proof

The real-time flow transition consumes an already promoted session capability and produces only data-plane state and bounded payload effects. No transition from the flow state reaches durable semantic projection or session promotion. Codec and application labels are absent from the authority predicates. Pre-promotion native track objects have no application-delivery effect. Therefore real-time flow state can affect availability, latency, resource use, and application delivery only after promotion, but it cannot create or modify authority.

## 12. Reachability evidence

### Theorem 12.1. Positive observation meaning

A valid fresh endpoint-authenticated packet observation proves only that the exact authenticated peer produced traffic verifiable under the current channel keys at the local observation point. It does not prove future reachability.

A valid signed presence response proves only that the exact Device key answered the exact challenge. It does not prove a usable application channel.

### Theorem 12.2. Local freshness integrity

If observation age is computed from local monotonic time recorded at successful local verification, a remote timestamp or carrier timestamp cannot make an old observation appear locally newer.

### Corollary 12.3. Absence is not revocation

Failure to obtain a new observation supplies no signed Open withdrawal or Closed removal and therefore cannot synthesize either durable semantic change.

## 13. Durable retention and storage opening

### Definition 13.1. Sufficient durable semantic basis

A durable basis is sufficient when it preserves the current durable projection, unresolved exclusive conflicts, adopted continuation validation, and durable pending effects without requiring removed history during ordinary operation.

### Theorem 13.2. Compaction equivalence

For every future durable continuation admitted by the domain's fixed continuation contract, evaluation from the verified compacted basis yields the same validation dispositions and durable projection as evaluation from the removed full history.

This is a proof obligation of the compaction profile, not a property of a hash root alone.

### Theorem 13.3. Store-opening non-revival

Opening a valid durable basis can reproduce its durable projection but cannot reproduce prior live transport or session state when live capabilities, keys, replay windows, connector objects, sockets, and reservations are excluded from durable restoration.

### Theorem 13.4. Whole-witness rollback limit

If every witness of a later durable fact is lost and only an older internally valid basis remains, no algorithm using only that basis can distinguish the world in which the later fact existed from the world in which it never existed.

#### Proof

The local input is identical in both worlds. A deterministic or probabilistic algorithm cannot derive information absent from its input with guaranteed correctness.

## 14. Effects and resources

### Theorem 14.1. No unreserved protected work

If every parser, candidate, socket, relay, handshake, media quarantine, session, queue, and effect allocation is dominated by a successful reservation, total allocated work cannot exceed the corresponding configured capacity vector.

### Theorem 14.2. Pre-authentication and post-authentication separation

Allowing bounded pre-authentication allocations does not imply that post-authentication session or application resources may be allocated before `MayPromote`. Separate reservation classes enforce the boundary.

### Theorem 14.3. Stale-effect suppression

If each pending effect carries exact live capabilities and rechecks them before execution, destroying or replacing those capabilities suppresses delayed effects for old candidates, channels, principals, or sessions.

### Theorem 14.4. Crash replay semantic idempotence

If external effect intents have deterministic identities, commit durably before execution, and adapters deduplicate or map duplicates to the same resource, a crash may repeat physical execution but cannot create a second semantic effect.

## 15. Complete eclipse and freshness

### Theorem 15.1. Complete-eclipse indistinguishability

A node receiving no independent evidence cannot distinguish:

```text
World 1: no newer durable fact or usable path exists
World 2: a newer fact or path exists but every available carrier withholds it
```

when both worlds yield the same local input trace.

### Corollary 15.2. No basal global-currentness predicate

The basal architecture cannot honestly claim that a local durable view is globally newest or complete without an additional domain-specific freshness or finality premise.

### Theorem 15.3. Eclipse-safe authenticity

Withholding durable facts or transport hints may preserve a stale local view or deny a connection. It cannot create a valid Device signature, Closed authorization proof, endpoint-authentication transcript, session capability, or application packet authentication.

## 16. Optional causal contract domains

### Theorem 16.1. Application consensus confinement

An application domain may add total ordering, blocks, quorum certificates, replicated execution, proof of work, proof of stake, or another consensus rule. Its results affect only contract instances and bridge rules that explicitly reference that domain.

### Theorem 16.2. Networking independence from optional consensus

Ordinary candidate discovery, channel promotion, reachability observation, relay allocation, and packet carriage need not wait for an unrelated application consensus domain unless the exact mesh policy deliberately makes that domain a promotion predicate.

## 17. End-to-end session theorem

### Theorem 17.1. Hybrid session soundness

Under the stated assumptions, if a conforming application receives and successfully uses `AuthenticatedPeerSession(A, C, M)`, then:

1. the relevant durable Open or Closed policy under the local accepted view allowed A and C;
2. a connector produced a live channel that actually passed the required handshake traffic;
3. A and C were freshly mutually authenticated over that exact channel or authenticated live-channel set;
4. the exact mesh context was bound to the authentication;
5. an authenticated local principal was allowed to use the session;
6. post-authentication resources and a fresh opaque session capability were reserved;
7. application payload did not traverse the signaling effect path;
8. any relay carrier lacked A-C endpoint authority and plaintext under the cryptographic premises.

#### Proof sketch

The durable policy result follows from `Project` and the Open or Closed verifier. The working channel follows from the connector transition. The endpoint, context, principal, resource, and capability properties are conjuncts of `MayPromote`. Application delivery is reachable only through the promoted capability. Signaling noninterference and relay non-substitution provide the final two properties.

## 18. Required mechanized or executable evidence

A concrete implementation must provide:

1. canonical durable-fact and endpoint-transcript test vectors;
2. a complete input and effect inventory;
3. differential tests between batch `Project` and incremental durable materialization;
4. model or property tests for durable conflict classification;
5. bounded speculative-work tests under malformed and identity-rotating input;
6. promotion tests that independently remove every predicate;
7. replay tests across channels, restart, and delayed callbacks;
8. direct, TURN, generic relay, and Closed member-relay equivalence tests;
9. handoff tests with two concurrently authenticated channels and no relay-to-relay protocol;
10. signaling and payload parser/effect reachability analysis;
11. crash tests for reservations and effect intents;
12. compaction equivalence tests for each adopted durable domain;
13. eclipse controls that preserve the impossibility boundary;
14. resource saturation measurements on every supported target.
