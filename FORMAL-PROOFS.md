# MyOwnMesh formal model and proof obligations

> Current normative cutover (2026-09-09): application data uses endpoint-authenticated WebRTC, directly or through configured standard TURN. Hubs provide discovery/introduction only, never application plaintext or ciphertext transit. This supersedes custom encrypted Hub and Closed-member payload relay requirements. Open/Closed governance is unchanged. Historical exact-head evidence below remains historical; this edit is not an implementation, runtime, or release PASS.

In the current model, packet-relay allocation means configured standard TURN, not a mesh-member payload service. Nostr/signaling relay terminology refers only to its bounded control carrier. Existing accounting-dimension names do not grant payload-forwarding authority.

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
G      the finite resource grant currently assigned to one provider domain
Q      one finite resource claim vector
R      the multiset of live lease claims and failed-cleanup-retained claims
       in that provider domain
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

For one live connection attempt `a`, let `C(a)` be its finite live set of connector candidates. Every `c` in `C(a)` has exactly one attempt owner and one finite live claim. A WebRTC candidate `c_w` owns one peer connection and one ICE agent. Its internal ICE candidate and pair sets are finite live connector state, not members of `C(a)` and not authority capabilities. The model fixes no universal maximum for `|C(a)|`, Mesh runtimes, peers, sessions, or flows.

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
    | TurnServiceHint
    | ConnectIntent
    | ConnectorSpecificHint
```

A hint is not authority. It may enter `Step` and cause only a member of the pre-authentication effect set:

```text
PreAuthEffect =
    CreateBoundedCandidate
    | OpenBoundedTransport
    | SendBoundedProbe
    | CreateBoundedTurnAllocation
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
    and (EphemeralOpenHandshakeAllows(c, M, A, C)
         or DurableClosedPolicyAllows(P, M, A, C))
    and LocalPrincipalAllows(u, M, A, C)
    and PostAuthResourcesReserved(c, A, C, u)
    and FreshSessionCapabilityReserved(c, A, C, u)
```

`EphemeralOpenHandshakeAllows` means the exact-context endpoint handshake
proved possession of the participating Device keys. It creates no durable
fact. `DurableClosedPolicyAllows` means the selected Closed authorization proof
is present in the accepted durable governance basis.

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

### Theorem 5.1. Open ephemeral permissionlessness

Under the Open rule, any Device key may establish ephemeral participation
after an exact-context handshake proves key possession, without a third-party
authorization input. Open creates zero base durable semantic facts.

#### Proof

The Open predicate is an endpoint-authentication predicate, not a durable-fact
predicate: it requires exact context and fresh Device-key possession. No
existing participant, service, application, quorum, pair grant, or durable
join/leave/presence record is an input.

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

Let `G_pre` be the finite pre-authentication resource grant currently assigned by the process provider. Let `R_pre` be its live lease multiset. Every speculative transport effect must acquire a finite claim `q` such that `sum(R_pre) + q <= G_pre` before protected allocation or retention.

### Theorem 6.2. Speculative-work confinement

Assume the reducer and connector effect unions are closed and every pre-authentication effect is resource-guarded. Any untrusted hint can cause only effects whose current live resource claims were granted. It cannot directly create durable authority, an authenticated session capability, or application delivery.

#### Proof

By construction, the only transitions reachable from an untrusted hint before `MayPromote` are members of `PreAuthEffect`. None contains a durable authority mutation, `PromoteSession`, or application-delivery effect. Closed effect unions exclude any alternate path. Resource reservation bounds each reachable effect.

### Corollary 6.3. Bounded early transport allocation is not a security failure

Creating a candidate, socket, relay allocation, transport object, or finite media quarantine before endpoint authentication is conforming when every protected object retains its exact lease and cannot reach application delivery or authority.

### Theorem 6.4. Identity rotation does not bypass the global pre-authentication bound

If every claim consumes the process grant before per-identity accounting, an attacker cannot exceed the live process grant merely by using fresh valid or invalid Device identities.

#### Proof

Every allocation consumes the process component independent of identity. For every admitted claim `q`, admission requires `sum(R_pre) + q <= G_pre`. Identity changes do not alter either side of that inequality.

## 7. Channel promotion

### Theorem 7.1. Working transport is insufficient for session authority

A connected socket, successful ICE check, TURN allocation, relay allocation, or transport handshake alone cannot produce an `AuthenticatedPeerSession`.

#### Proof

Each omits one or more required conjuncts of `MayPromote`, including fresh
mutual Device authentication, exact mesh binding, the ephemeral Open
handshake or durable Closed policy, local-principal admission,
post-authentication reservation, or fresh session capability.

### Theorem 7.2. Channel-promotion soundness

If a conforming runtime exposes `AuthenticatedPeerSession(A, C, M)`, then at the exposure transition:

1. A and C were freshly authenticated over the exact working channel;
2. the channel was bound to `M`;
3. the exact Open handshake or applicable Closed policy allowed the peer under
   the local accepted view;
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

#### Implementation note

The theorem and its premise are unchanged. This records only which disjunct the Arc 04 implementation relies on, because the two are not equally load-bearing there.

The channel-specific material selected is the pair of DTLS certificate fingerprints. A certificate fingerprint is not session-unique: if `c1` and `c2` are between the same device pair and reuse the same certificates, the binding term is identical on both, and the *binding* disjunct alone would not refuse the replay. **The freshness disjunct therefore carries the theorem in that implementation**, via the two per-attempt contributions.

Separately, and outside the scope of this theorem, transfer or survival of an already-issued capability across a channel replacement is prevented by connector-incarnation ownership. That is not a strengthening of the binding term: ownership does not make an otherwise-valid signature invalid. Should a true RFC 5705 exporter later replace the fingerprint term, the binding disjunct would become independently sufficient and the two refusal causes should be distinguishable.

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

### Note 9.4. Superseded custom relay handoff theorem

The former member-relay handoff theorem is withdrawn from the current
requirements. Recovery uses endpoint-authenticated native WebRTC with direct
or configured standard TURN paths. It must not require custom member-to-member
relay state transfer. This is a cutover obligation, not new executable recovery
evidence.

### Theorem 9.5. Forced failure can influence selection but not authorization

An attacker capable of dropping channel B may cause local policy to choose another already authenticated channel D. The attacker cannot add D to the authenticated set or promote an unauthenticated D channel solely by dropping B.

#### Proof

Failure changes live observations and selection input. It does not satisfy the insertion or promotion predicate for D.

## 10. Standard TURN boundary; custom relay proofs withdrawn

### Assumption 10.1. Endpoint-authenticated WebRTC

The current model permits direct WebRTC and configured standard TURN packet
carriage. Endpoint authentication binds the actual WebRTC channel to the exact
Device pair and mesh context. WebRTC transport integrity/confidentiality and
correct key custody are explicit cryptographic premises, not consequences of
a TURN credential or service advertisement.

### Conditional argument 10.2. TURN is not an endpoint

Under those premises, a TURN service cannot cause an endpoint to accept
modified application data or gain endpoint plaintext/authority without violating
the endpoint/transport protection. It may deny service or observe traffic
metadata. This argument does not prove availability, allocation cleanup,
credential security, or concrete implementation conformance.

### Withdrawn 10.3–10.4. Custom allocation and member-identity claims

The custom exact-destination relay-allocation theorem and visible-member-relay
corollary are no longer current requirements. Standard TURN is not modeled as
the deleted mesh route/allocation protocol. No custom Hub or Closed-member
payload cipher, plaintext forwarding exception, or ciphertext tunnel is
permitted.

### Current proof and evidence boundary

Hub introduction and existing typed semantic-control must be shown disjoint
from application payload dispatch. Removed config/wire forms must refuse.
TURN service cohosting does not grant mesh authority; URL-only advertisements
and locally configured credentials do not establish protected credential
distribution. Direct/TURN endpoint tests and negative Hub/signaling payload
tests remain required; this documentation edit establishes no new test PASS.

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

Failure to obtain a new observation supplies no runtime Open departure or
Closed removal fact and therefore cannot synthesize either durable semantic
change.

## 13. Durable retention and storage opening

### Definition 13.1. Sufficient durable semantic basis

A durable basis is sufficient when it preserves the current durable projection, unresolved exclusive conflicts, adopted continuation validation, and durable pending effects without requiring removed history during ordinary operation.

The base ledger is durable Closed authority/governance only. Runtime join,
leave, presence, and reconnect for Open and Closed are excluded from the
durable fact set. The owner selects finite ceilings for retained fact count,
canonical bytes, causal edges, per-author count/bytes, proof-verification
work, eligible-signer quarantine, total proof history, and local-only indexed
SQLite plus WAL/reserve bytes. The store has one semantic writer and `FULL`
synchronous durability. A candidate whose full delta is the exact `N+1` in any
dimension is refused before mutation, acknowledgement, identity, or
authority change. Duplicate delivery is a semantic no-op.

Quarantine is dependency-indexed and bounded by the same claims. Per-author
retained lifetime is an explicit cleanup cap, not silent authority expiry.
Exact proof history remains until an archive or authority-ratified checkpoint
permits semantic deletion. The shipped compaction contract is bounded
checkpointing only; it does not claim a full-copy `VACUUM` without separately
funded temporary-copy, metadata, and cleanup custody. No timer deletes or
silently prunes semantic history. These finite ceilings bound ordinary growth
and failure spam because rejected attempts retain no new fact, while failed
cleanup keeps its exact charged claim until terminal observation.

### Theorem 13.2. Pre-mutation quota refusal

Let `U` be the retained ledger usage vector and `q` the complete candidate
delta across count, bytes, causal edges, per-author usage and lifetime, proof
work, quarantine, and indexed database/WAL-reserve bytes. If any selected
dimension of `U + q` exceeds its owner-selected ceiling, the candidate is
refused before the semantic reducer mutates the graph, projection,
acknowledgement, identity, or authority. A duplicate Fact ID is a semantic
no-op and creates no new history.

#### Proof sketch

Admission computes every named component before commit. The reducer has no
successful transition after a failed component check, so the graph and its
projection remain unchanged. Since quarantine and proof records use the same
vector, repeated failure cannot bypass the bound through a side structure.

### Theorem 13.3. Compaction equivalence

For every future durable continuation admitted by the domain's fixed continuation contract, evaluation from the verified compacted basis yields the same validation dispositions and durable projection as evaluation from the removed full history.

This is a proof obligation of the compaction profile, not a property of a hash root alone.

### Theorem 13.4. Store-opening non-revival

Opening a valid durable basis can reproduce its durable projection but cannot reproduce prior live transport or session state when live capabilities, keys, replay windows, connector objects, sockets, and reservations are excluded from durable restoration.

### Theorem 13.5. Whole-witness rollback limit

If every witness of a later durable fact is lost and only an older internally valid basis remains, no algorithm using only that basis can distinguish the world in which the later fact existed from the world in which it never existed.

#### Proof

The local input is identical in both worlds. A deterministic or probabilistic algorithm cannot derive information absent from its input with guaranteed correctness.

### Note 13.6. Durable commit outcome boundary

Atomic publication proves that a successfully reopened store exposes either
the prior valid basis or the complete new basis; it does not make every
caller-visible SQLite error a rollback witness. A statement or preflight
failure is old only when explicit rollback or exact reopen verification proves
that result. A WAL write/sync failure or `COMMIT` return error is
outcome-unknown until reopen compares context, projection commitment,
generation, indexed rows, provisional custody, and proof records against the
old and expected new bases. A checkpoint or truncation failure after COMMIT is
a maintenance failure over an already committed semantic result, not evidence
that the result was rolled back. Corrupt or mismatched reopen is a recovery
failure, not a guessed old state.

## 14. Effects and resources

### Theorem 14.1. No unreserved protected work

If every parser, candidate, socket, relay, handshake, media quarantine, session, queue entry, task, native object, and effect allocation is dominated by a successful finite lease, then the sum of live claims cannot exceed the provider grant.

#### Proof

The provider grants claim `q` only when component-wise checked addition proves `sum(R) + q <= G`. Owner Drop after proven cleanup removes exactly the claim held by that lease. Failed-cleanup retention replaces the live lease claim with the same exact retained claim, so it does not reduce `sum(R)`. Failed subtraction or addition cannot create capacity and instead poisons the affected accounting domain. Induction over grant, release, and failed-cleanup-retention transitions preserves `sum(R) <= G`.

This theorem covers only quantities actually charged to `R`. It does not prove that allocator slack, native WebRTC allocations, OS handles, runtime internals, driver state, or external provider allocations are represented. Those require a conservative claim, an isolation boundary, or an explicit residual report.

For the `StorageBytes` dimension, the process-accounted claim is one composite
quantity, `B = M + W + S + R`, covering main database bytes, WAL bytes,
shared-memory/sidecar bytes, and explicit reserve. Named-file containment or
VFS accounting does not by itself prove backing disk capacity, filesystem
metadata capacity, or ENOSPC behavior; those remain residuals unless an exact
provider mapping proves them. This storage equation is an accounting claim and
must not be confused with the backing quantity `B` defined in Theorem 14.5f
without a dimension label.

### Theorem 14.2. Pre-authentication and post-authentication separation

Allowing bounded pre-authentication allocations does not imply that post-authentication session or application resources may be allocated before `MayPromote`. Separate reservation classes enforce the boundary.

### Theorem 14.3. Semantic cardinality need not be fixed

Assume each live product object owns a finite nonzero composite claim and the provider enforces `sum(R) <= G`. Then no fixed Mesh, peer, attempt, session, or flow count is required to preserve resource safety.

#### Proof

Admission depends on the next claim and remaining resources, not on the product-object count. One large object may consume more of `G` than many small objects. Any number of objects may coexist while their summed claims fit. The next object fails with typed pressure when its claim does not fit.

### Theorem 14.4. Child scopes cannot multiply capacity

If every child scope reserves from the same process provider and scope creation grants no resources, adding Mesh scopes cannot increase `G` or permit `sum(R) > G`.

### Theorem 14.5. Work-conserving borrowing preserves safety

Allowing one child to consume capacity unused by another preserves `sum(R) <= G` because both claims are charged to the same finite process grant. No basal weight, quota, reserved share, or partition is needed for this inequality. This theorem proves resource safety only. It does not prove eventual admission.

### Theorem 14.5a. Demand arbitration preserves safety

Assume a provider may retain unsatisfied requests as pending demands and may select among them by any selection policy. Holding, ordering, selecting, or moving a pending demand does not change `R`. A successful grant adds its exact claim only after proving the resulting sum does not exceed `G`. Therefore arbitration changes service order without creating capacity or weakening `sum(R) <= G`.

The theorem is independent of the selection policy. It fixes no authority ordering, rotation rule, queue discipline, or per-scope pending-demand cardinality, and no other proof in this document depends on such a rule. A concrete provider must declare its own selection policy and show only that the policy does not mutate `R`.

### Theorem 14.5b. Indefinite leases, unrestricted borrowing, and guaranteed later admission are incompatible

Assume a valid lease may remain live indefinitely, the provider may not revoke
it, and one scope may borrow every currently unused unit. The provider cannot
also guarantee that a later request from another scope will be admitted.

#### Proof

Let scope A borrow the remaining grant and retain every lease. Let scope B then
request a nonzero claim in any exhausted dimension. Admitting B would violate
`sum(R) <= G`. Releasing A would revoke a valid lease. Waiting for A provides no
bounded admission guarantee because A may remain valid indefinitely. At least
one premise must change. A deployment that requires guaranteed cross-scope
admission must reserve capacity, isolate scopes, or use an owner contract that
explicitly makes borrowed work reclaimable.

This impossibility result is a prerequisite for any cooperative provider policy. A provider policy may weaken the nonrevocation premise only for leases whose owner contract explicitly declares them reclaimable. It does not claim that every live lease is reclaimable.

### Theorem 14.5c. Retirement requests cannot forge release

Suppose a pending demand does not fit. The provider may notify the exact owners of reclaimable leases whose claims contribute to the deficit. Notification changes no member of `R`. Capacity becomes reusable only after an owner finishes cleanup and drops the exact lease. If cleanup cannot be proven, transferring the exact claim into failed-cleanup retention keeps that claim charged. Therefore a retirement request cannot make `sum(R)` understate known live or unreleased resources.

A deterministic selection policy yields a defined service order, not eventual admission. A nonreclaimable lease may retain capacity indefinitely. A reclaimable owner may ignore a retirement request. Failed cleanup may retain the exact charge indefinitely. No timer resolves any of these cases, so the model makes no stronger liveness claim.

### Note 14.5d. Provider policy is not mesh semantics

Theorems 14.1 through 14.5c constrain any conforming resource provider: conservation of `sum(R) <= G`, explicit owner-held cleanup, honest retention of unreleasable charges, typed pressure rather than authorization, and fallible admission. They deliberately fix no scheduling algorithm.

A concrete provider may additionally adopt an exact pending-demand cardinality, an authority ordering over demand classes, and a rotation rule among equal-class scopes. Such a rule is one provider policy. It is not a universal mesh semantic, is not a proof obligation of this model, and no result above becomes unsound if a different conforming provider selects demands differently.

### Note 14.5e. Partition non-amplification beneath a fixed FairnessRoot is a separate provider obligation

Provider conformance also requires that subdividing one fixed fairness root's attribution cannot increase that root's cumulative selections or cumulative admitted quantity in any dimension at any decision prefix, and cannot move a competing root's selection to a later decision. The requirement is one-way and imposes no equality of outcome.

`FairnessRoot` and `AttributionChildScope` are used here exactly as the closed definitions in [`ARCHITECTURE.md`](ARCHITECTURE.md) fix them, and are not redefined. This note needs only two consequences of those definitions: a root is the unit of scheduling attribution the provider serves, and a child scope refines accounting beneath exactly one root while adding no share, turn, or service weight. How a deployment maps local facts onto roots is trusted-mapping policy and belongs to the implementation contract, not to this model.

**The model.** The comparison is made in a causally closed model, so that attribution is the only difference between the two runs.

```text
Roots        a fixed finite set of FairnessRoots, the same in both runs

Topology     a fixed AttributionChildScope topology beneath those
             roots, identical in both runs, created before the
             measured prefix begins

Bookkeeping  the provider's own scope-record claims for that topology,
             identical in both runs, already charged before the
             measured prefix begins

Initial      one initial provider state, including Gc in every
             resource dimension

Demands      a finite set of demands under stable DemandIds; each
             carries its exact claim by dimension, its authority class,
             and its reclaimability under its owner contract

Schedule     one deterministic, clock-free environment and reducer rule
             fixing the interleaving of exogenous arrivals with
             owner-derived actions

Owners       one deterministic owner response rule, fixed in advance,
             mapping work actually admitted to that owner's subsequent
             actions

Releases     not free inputs: every release is derived by applying the
             owner response rule to the work actually admitted
```

Nothing outside this list may differ between the runs. Because releases are derived rather than supplied, the model is causally closed: the comparison cannot invent a release and then charge the provider for its consequences.

An ordered sequence of arrivals is not by itself sufficient. Ordering the arrivals leaves free how they interleave with the actions owners take in response to admitted work, and that freedom alone can move a selection. The deterministic clock-free schedule rule fixes that interleaving. It is clock-free because a wall-clock dependence would reintroduce a difference that is neither attribution nor workload.

**Construction A.** Both executions begin from the same already-created structure: the same fairness roots, the same attribution child-scope topology beneath `A`, the same bookkeeping claims already charged for that topology, and the same demands under stable `DemandId`s. All of it exists before the measured prefix begins.

The two runs then differ in exactly one function:

```text
baseline     every demand of A maps to one already-created child scope
             beneath A

subdivided   the same demands map across the same already-created child
             scopes beneath A
```

Only the `DemandId -> AttributionChildScope` mapping differs. No scope is created, destroyed, or charged inside the measured prefix. This is what isolates subdivision as the variable: were scopes created during the prefix, a difference could be explained by scope-creation cost or by a different topology rather than by attribution, and the comparison would not be measuring P6.

**The comparison.** Comparison is prefix-wise. Let `k` index decision prefixes, that is the provider's decision points in order, and let `d` range over resource dimensions.

```text
for every decision prefix k:

    cum_selections(A, subdivided, k)
        <= cum_selections(A, baseline, k)

    cum_admitted(A, subdivided, k, d)
        <= cum_admitted(A, baseline, k, d)     for every dimension d

for every root B != A, and every demand b of B:

    select_pos(b, subdivided) <= select_pos(b, baseline)
```

`cum_selections` and `cum_admitted` are cumulative over the prefix, so a subdivided root may not gain early and repay later; the bound holds at every `k`, not only at the end.

`select_pos(b, run)` is the index of `b`'s selection within that run's ordered sequence of provider decisions, and is `infinity` when `b` is never selected in that run. The index is over decisions, not over selection events. Counting only selection events would let a provider insert non-selection decisions ahead of a competitor's selection and leave its measured position unchanged while it is in fact served later. The competitor bound is stated over every root other than `A`, not one distinguished competitor.

The infinity convention keeps delay a single observable. A demand selected in the baseline and unselected in the subdivided run moves from a finite position to `infinity`, so it is delayed without bound and excluded by the same comparison, with no separate rule about how many demands a competitor is selected for.

The obligation is one-way throughout. `A` faring worse is permitted. A competitor faring better is permitted, including additional selections, since a demand unselected in the baseline sits at `infinity` and no position exceeds it. Competitor admitted quantity is unconstrained in either direction. Subdivision may freely change how charges are labelled, measured, and reported.

**Terminal stuttering.** The two runs need not have the same length. Comparison is still made at every prefix index `k`, under the convention that once a run terminates its cumulative values remain constant at their final values, and a demand never selected in that run remains at `infinity`. A shorter run therefore stutters at its terminal state rather than becoming undefined, so no comparison is ill-formed or vacuous merely because one run ended first.

**First conformance control.** Take a finite decision prefix over which none of the compared newly admitted demands release. Check the comparisons above across that prefix, for `A` and for every other root. Excluding releases of the compared work removes the confound in which a release, rather than the partition, explains a difference. A later generalization may lift the restriction by carrying the deterministic owner automaton through the prefix, so that releases remain derived rather than free.

**Scope-bookkeeping cost.** A provider scope record is a real resource. It is finite, it is charged, and acquiring it may fail. Nothing in this note says otherwise, and nothing here promises that a provider can support unlimited scopes.

Construction A does not make that cost disappear; it holds it equal. The topology and its bookkeeping claims are identical in both runs and already charged before the measured prefix, so bookkeeping cannot explain any difference the comparison observes. That normalization exists solely to isolate attribution within this comparison. It is not a claim that bookkeeping is free, unbounded, or exempt from admission.

Outside the comparison, a scope record is charged like any other claim under P1 through P5. A provider may refuse to create one exactly as it may refuse any other claim, and that refusal is an ordinary typed resource result, not a P6 violation. A comparison whose two runs start from different topologies or different accounted bookkeeping positions is not Construction A and does not test P6.

This is a fairness obligation on a provider, not a corollary of any theorem above. This document does not prove it and supplies no scheduler, root taxonomy, weighting, or turn mapping that would.

**Nonclaims.** The obligation is a one-way bound on attribution, not an identity property over the world.

- it does not bind apparent ingress sources into one real-world claimant;
- it is not a proof of Sybil resistance, and no Sybil-resistance claim may be derived from it;
- it does not determine how many fairness roots an actor should receive.

If a provider maps two apparent sources to two fairness roots, the obligation says nothing about whether those sources are one actor. It constrains only what re-attribution beneath an already-fixed root can achieve. The root set is an input to this model, not a result of it: how roots are selected is trusted-mapping policy in the implementation contract, and no conclusion about it may be drawn from this note.

The obligation is also not a progress property. It says nothing about progress, throughput, latency, or backpressure, and nothing about behavior under hostile ingress. Those are separate concerns of ingress admission and backpressure design. Satisfying the obligation neither implies nor requires progress under hostile ingress, and no liveness claim follows from it.

The conservation and impossibility results are independent of it in both directions. Theorems 14.1 through 14.5c neither prove the obligation nor depend on it: `sum(R) <= G` holds regardless of which demand is served next, because selection and rotation do not change `R`. Conversely, discharging the obligation cannot strengthen any liveness claim disclaimed in 14.5b and 14.5c. No safety result in this document may be cited as evidence that the obligation holds.

### Theorem 14.5f. Arbitrary capacity loss preserves conservative accounting, not necessarily physical backing

Six quantities are distinguished in each resource dimension. Conflating any two of them is the error this theorem exists to exclude, and the sharpest of those confusions is between an envelope that merely contains and a backing that actually reserves.

```text
O    observation: an inert measurement. It is a reading and nothing
     else. O alone changes nothing: it sets no grant, authorizes
     nothing, and causes no transition. O may be absent entirely, and
     a provider is complete without it

T    target: an explicit owner-selected contraction target, set by a
     named, recorded owner policy. T may be set directly, or derived
     by a named policy that considers O among its inputs. It is never
     set automatically merely because O changed, and T does not
     require O to exist. When T < Gc, that records a request for
     gradual contraction, which proceeds only as owner releases lower S

E    envelope: an enforceable isolation ceiling, such as a cgroup, job
     object, process limit, appliance boundary, or provider allocation
     class. E is containment, not availability: it bounds what the
     process may consume, and exceeding it is prevented from outside.
     E does not reserve anything and does not promise that capacity
     within it can be obtained

B    backing: capacity actually reserved for or owned by this process,
     asserted only where an exact substrate contract genuinely
     guarantees it. B is availability, not containment. Absent such a
     contract there is no B, and a provider must not synthesize one
     from an envelope, an observation, or an assumption

Gc   committed grant: an accounting commitment against which every
     live claim was admitted. It is bookkeeping. It is not proof that
     substrate capacity exists, and not a promise that an allocation
     will succeed

S    charged sum: live claims plus failed-cleanup-retained claims

R_flight(d)
     in-flight admission reservation in dimension d: the aggregate
     exact capacity reserved for all admissions currently in flight,
     and zero when none is in flight. This is a distinct symbol from
     the global `R`
     used elsewhere in this section for the multiset of live and
     failed-cleanup-retained lease claims; the two are never
     interchanged
```

The rules relating them are:

```text
S <= Gc always
Gc moves toward T downward only after owner release has lowered
    committed use; Gc is never set below S(d) + R_flight(d), so
    contraction never strands a reservation held for an admission in
    flight
a provider that claims isolation proves Gc <= E
a provider that claims backing proves Gc <= B at the moment of
    admission
P4 fit is EffectiveFit, defined below; O and T are never inputs to it
```

Capacity is stated absolutely and reduced to a residual only at the end.

**Capacity and fit.** Both capacities are absolute. Only the final step produces a residual, and every quantity is per resource dimension.

```text
AccountingCapacity
    the absolute committed grant Gc in that dimension, narrowed only by
    an explicit P5 restriction drawn from the closed vocabulary below.
    It is a capacity, not a residual: no charge has been subtracted
    from it

EffectiveCapacity
    AccountingCapacity, intersected with E in that dimension where E is
    proved, and with B in that dimension where B is proved. Still
    absolute

EffectiveFit(d)
    max(0, EffectiveCapacity(d) - S(d) - R_flight(d))
    the residual actually available to a new claim in dimension d
```

A claim `q` fits in a dimension exactly when `q <= EffectiveFit` in that dimension. A composite claim fits only when it fits in every dimension it names; headroom in one dimension never compensates for its absence in another.

The intersections are independent, and each applies only where its premise is proved in that dimension:

```text
neither proved   EffectiveCapacity = AccountingCapacity
E proved only    EffectiveCapacity = AccountingCapacity intersect E
B proved only    EffectiveCapacity = AccountingCapacity intersect B
both proved      EffectiveCapacity = AccountingCapacity
                                     intersect E intersect B
```

Subtracting `S(d)` and `R_flight(d)` last is deliberate. `E` and `B` are absolute substrate bounds, so intersecting them with a figure from which charges had already been deducted would compare a residual against an absolute and silently understate the bound.

`R_flight(d)` is subtracted so that concurrent admissions cannot each read the same headroom as free. It aggregates the exact capacity reserved for every admission currently in flight, so a second admission sees the first one's reservation already deducted, and is zero when none is in flight.

The `max(0, ...)` clamp is not cosmetic. `EffectiveCapacity(d) - S(d) - R_flight(d)` can be negative when a proved premise falls below existing committed use. The clamp keeps `EffectiveFit(d)` a well-formed residual and makes the fit test refuse, rather than yielding a negative bound that arithmetic elsewhere might treat as slack.

`O` and `T` participate nowhere in this computation. An observation is not a bound, and a contraction target is not a bound; admitting against either would admit against a quantity no one committed.

Admission remains fallible in every case. A successful fit does not guarantee that the allocator, kernel, runtime, transport, external relay, or hardware will succeed. Narrowing capacity by a proved premise does not convert an accounting result into a guarantee of execution.

**The closed P5 vocabulary.** An explicit P5 restriction narrowing `AccountingCapacity` is exactly one of:

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

Each is explicit, named, and recorded. Nothing outside this list narrows `AccountingCapacity`: no observation, target, measurement, generic owner preference, workload calibration, anticipated future demand, rate smoothing, inferred restriction, or undeclared product policy. An undeclared narrowing is an arbitrary refusal, which P4 forbids.

**Provider labels.** `E` and `B` are distinct and orthogonal premises. Containment does not imply reservation, and reservation does not imply containment. The labels below name which premises a provider has proved. They are not a ladder, and a provider need not fit exactly one of them.

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

A provider may hold both claims, and may hold them per dimension: `E` proved in one resource dimension and `B` proved in another is an ordinary configuration, not a contradiction. Any combination is permitted exactly where each premise it names is separately proved. Claiming `E` never licenses a `B` claim, and claiming `B` never licenses an `E` claim.

A provider that cannot prove `E` must not describe itself as isolated, and a provider that cannot prove `B` must not describe itself as backed. Establishing `E` or `B` for a real substrate is an obligation discharged outside this document; nothing here is evidence that any provider has established either.

**What proving `E` or `B` requires.** A claim of `Gc <= E` or `Gc <= B` in a dimension requires a mapping between the `ResourceClaim` quantity this model charges and the substrate quantity actually contained or reserved. That mapping must be:

```text
dimension-specific   established for that resource dimension, not
                     inferred from another dimension
unit-correct         relating the charged unit to the substrate unit
                     without silent conversion or reinterpretation
monotone             a larger charged quantity never maps to a smaller
                     substrate quantity
coverage             the mapping accounts for every consumer of that
                     substrate quantity, not only the charged ones. A
                     consumer this model does not charge is included
                     conservatively, by subtracting its use from the
                     premise rather than assuming it absent. A
                     partially mapped dimension is not a mapped
                     dimension
composition          no two ResourceClass dimensions, and no two
                     providers, may claim the same substrate quantity.
                     A quantity counted twice is not thereby contained
                     twice or reserved twice
subject alignment    the contained or reserved subject is exactly the
                     subject Gc is committed for: the same process,
                     worker, and provider, neither broader nor narrower
lifetime and loss    the mapping names when it begins, when it ends,
                     and who observes it. Where its loss cannot be
                     observed before a fail-stop, the charge is
                     retained and the premise is not claimed for that
                     unobservable interval
B exclusivity        reserved capacity is exclusive to that subject.
                     Competing unaccounted use is deducted from B, and
                     a shared pool another party may consume from is
                     not B
```

Where no such mapping exists for a dimension, that dimension remains accounting-only, or an explicit named residual, and no `E` or `B` claim may be made for it. An `OpaqueDependencyResidual` does not become `E` or `B` by being given a number: a quantity that is merely recorded is neither contained nor reserved. Establishing these mappings for a real substrate is an obligation discharged outside this document.

Accounting-only is a coherent provider label, and a provider bearing it can satisfy the accounting model and theorems of this section. That is a claim about this model alone. It is not a claim that such a provider satisfies P1 through P8, or P6, which are established separately and are not discharged by bearing this label. Accounting alone is in any case not sufficient for final production closure, which additionally requires the containment or reservation premises that accounting does not supply.

**Claim.** `S(d) + R_flight(d) <= Gc(d)` is invariant in every dimension `d`, across every transition, including arbitrary change in `O`, `T`, `E`, or `B`. Since `R_flight(d) >= 0`, this implies `S <= Gc`. No change in observation, target, envelope, or backing releases, reduces, or reattributes any claim or any reservation.

#### Proof

Initially `S(d) + R_flight(d) <= Gc(d)` in every dimension, with `R_flight(d)` zero. Consider each transition.

**Reservation.** A claim `q` is reserved only after `q(d) <= EffectiveFit(d)` holds in every dimension `q` names. Where the provider claims containment or backing, `EffectiveCapacity(d)` already incorporates `E` or `B`, so those premises are enforced by the same test rather than by a separate check. Reservation then adds `q(d)` to the aggregate `R_flight(d)` exactly once, in each dimension `q` names. Since

```text
q(d) <= EffectiveFit(d)
      = max(0, EffectiveCapacity(d) - S(d) - R_flight(d))
      <= Gc(d) - S(d) - R_flight(d)
```

because `EffectiveCapacity(d) <= AccountingCapacity(d) <= Gc(d)` and the induction hypothesis makes `Gc(d) - S(d) - R_flight(d)` non-negative. The resulting `S(d) + R_flight(d) + q(d)` therefore does not exceed `Gc(d)`, so the invariant is preserved. A claim failing the test in any dimension it names is reserved in no dimension and adds nothing anywhere.

**Promotion.** When an in-flight admission succeeds, exactly `q(d)` moves from `R_flight(d)` to `S(d)`: `R_flight(d)` decreases by exactly `q(d)` and `S(d)` increases by exactly `q(d)`. Committed use `S(d) + R_flight(d)` is therefore unchanged, and the invariant is preserved with no re-check required. Promotion moves a quantity between two accounts; it does not create one.

**Failure or abandonment.** When an in-flight admission does not complete, exactly the reserved `q(d)` is released from `R_flight(d)`, and nothing else is touched. Release follows the ownership and cleanup rules already stated: the reservation's own owner releases it, no live claim in `S` is affected, and no other reservation is disturbed. Committed use decreases by exactly `q(d)`, so the invariant is preserved.

**Owner release.** Release after proven cleanup reduces `S(d)` by exactly the released claim and leaves `Gc(d)` and `R_flight(d)` unchanged.

**Failed-cleanup retention.** Replaces a live claim with the identical retained claim, leaving `S(d)` and `R_flight(d)` unchanged.

**Raising `Gc`.** Preserves the invariant trivially.

**Lowering `Gc`.** Permitted only to some `Gc'(d)` with `S(d) + R_flight(d) <= Gc'(d)`, so it preserves the invariant by construction, leaves every in-flight reservation covered, and cannot strand one.

**Observation, target, envelope, backing.** A change in `O` changes no member of `R`, no `S`, no `R_flight`, no `Gc`, no `T`, no `E`, and no `B`: it is inert by definition. A change in `T` changes no member of `R`, no `S`, no `R_flight`, and does not itself move `Gc`; it records an owner-selected contraction target that `Gc` may approach later, and downward only as owner release lowers committed use. A fall in `E` narrows what the process is permitted to consume, and a fall in `B` reduces what is actually reserved by the substrate; neither changes `S`, `R_flight`, or `Gc`, because neither is a charge or a reservation in this model. External premise loss is treated separately below and is not an accounting transition.

Every transition preserves `S(d) + R_flight(d) <= Gc(d)`, so by induction it holds in every reachable state, and `S <= Gc` follows.

**Why the excluded state is excluded.** Setting `Gc` below `S` would require either releasing claims the provider does not own, contradicting P2 and Theorem 14.5c, or leaving a charge unattributed, contradicting P1 and Theorem 14.1. The contraction floor forbids both, and forbids more: `Gc` is never set below `S(d) + R_flight(d)`, which is at or above `S(d)`, so an in-flight reservation cannot be stranded either.

**Premise loss.** A proved premise may fall. What follows depends on where it falls relative to committed use, and the model distinguishes two regimes per dimension.

```text
premise >= S(d) + R_flight(d)
    residual headroom remains, and it is usable. EffectiveFit(d) is
    recomputed against the reduced premise and stays non-negative, so
    ordinary admission continues within it. This condition alone
    requires no loss report

premise < S(d) + R_flight(d)
    the premise is now below committed use. The provider reports a
    typed containment-loss, backing-loss, or external-overcommitment
    result, and admits no new work that would conflict with the
    shortfall in that dimension
```

In both regimes every charge in `S(d)` and every reservation in `R_flight(d)` is retained. Nothing is released, revoked, reduced, or written off, and no release is inferred or forced: a premise falling is not a release, and `Gc` is not lowered below `S(d) + R_flight(d)`. The provider may request retirement only from exact owners whose contracts declare their leases reclaimable, and it releases nothing itself. Above all it does not pretend the capacity exists, and no part of a shortfall is reported as available.

The first regime matters as much as the second. A premise that falls but still covers committed use has not created a shortfall, and treating every fall as an emergency would refuse work the provider can honor while reporting a loss that has not occurred.

**What reporting can and cannot cover.** Reporting is required exactly while the process is alive and the condition is observable to it. Those two qualifications are not evasions; they mark the boundary of what any in-process report can claim.

A fail-stop event is outside that boundary. If the substrate terminates the process, as an out-of-memory kill does, there is no report: the process does not survive to make one, its live capabilities are destroyed with it, and recovery is ordinary restart semantics rather than a resource transition in this model. No obligation here is discharged by reporting after such an event, and none is violated by failing to report one.

Backing loss also has a consequence the accounting cannot repair. Substrate availability may fail: work already admitted against a grant that is no longer reserved may fail in execution even though its claim remains correctly charged. This model does not promise otherwise. Conservative accounting guarantees that charges remain exactly attributed to the accounting commitment; it does not turn that commitment into a physical guarantee or promise that the substrate will supply it. That is the exact sense in which arbitrary capacity loss preserves conservative accounting and not physical backing.

**`O` is never a grant.** An observation is not `T`, not `E`, not `B`, and not `Gc`, and it sets none of them. A named owner policy may consider `O` among its inputs when choosing `T`, but nothing is set automatically because `O` changed, and no path from `O` to `T` is required to exist: a provider with no observation at all is complete, and `T` may be set directly. P4 fit is `EffectiveFit(d)` exactly as defined above, and is not restated here. Neither `O` nor `T` participates in it at any step. A measurement showing apparent headroom is not evidence that a claim fits.

**Safety, not liveness.** Nothing here bounds how long `Gc` remains above `T`, above `E`, or above `B`. `Gc` follows `S` downward only as owners release, and no timer, notification, or external pressure compels an owner to release. If owners never release, `Gc` never reaches `T`. This is consistent with Theorems 14.5b and 14.5c and adds no progress claim. A deployment that must be able to honor a fall in `E` or `B` immediately reserves or isolates in advance under Theorem 14.6; it cannot obtain that guarantee afterwards by revoking. Every result of observation, target change, envelope loss, or backing loss is a typed resource event and never an authorization result.

### Theorem 14.6. Optional ceiling confinement

An optional local ceiling wrapper may refuse a claim that the provider could grant. It cannot approve a claim the provider refused, so it can reduce availability but cannot increase capacity or create mesh authority.

The same bound holds for an optional local isolation policy that confines a scope to a subset of the grant. Both remain explicitly optional deployment policy. No theorem in this section requires either one, and installing either cannot make an unsound provider sound.

### Theorem 14.7. Time independence

If lease transitions are caused only by explicit owner actions or provider reclamation allowed by the claim contract, elapsed time alone cannot change `R`. A slow operation therefore retains its finite claim without acquiring more authority or capacity.

### Theorem 14.8. Stale-effect suppression

If each pending effect carries exact live capabilities and rechecks them before execution, destroying or replacing those capabilities suppresses delayed effects for old candidates, channels, principals, or sessions.

### Theorem 14.9. Crash replay semantic idempotence

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

1. the exact Open handshake or relevant Closed policy under the local accepted
   view allowed A and C;
2. a connector produced a live channel that actually passed the required handshake traffic;
3. A and C were freshly mutually authenticated over that exact channel or authenticated live-channel set;
4. the exact mesh context was bound to the authentication;
5. an authenticated local principal was allowed to use the session;
6. post-authentication resources and a fresh opaque session capability were reserved;
7. application payload did not traverse the signaling effect path;
8. any configured TURN carrier lacked A-C endpoint authority and plaintext under the stated WebRTC cryptographic premises; no Hub/member payload path was used.

#### Proof sketch

The durable Closed policy result follows from `Project`; the Open result
follows from the exact endpoint handshake. The working channel follows from
the connector transition. The endpoint, context, principal, resource, and
capability properties are conjuncts of `MayPromote`. Application delivery is
reachable only through the promoted capability. Signaling noninterference and
the conditional TURN boundary provide the final two properties.

## 18. Required mechanized or executable evidence

A concrete implementation must provide:

1. canonical durable-fact and endpoint-transcript test vectors;
2. a complete input and effect inventory;
3. differential tests between batch `Project` and incremental durable materialization;
4. model or property tests for durable conflict classification;
5. bounded speculative-work tests under malformed and identity-rotating input;
6. promotion tests that independently remove every predicate;
7. replay tests across channels, restart, and delayed callbacks;
8. direct and configured standard TURN endpoint tests, plus refusal of custom Hub/member payload paths;
9. endpoint recovery tests without a custom member-relay handoff protocol; no concurrent-channel implementation claim is inferred;
10. signaling and payload parser/effect reachability analysis;
11. crash tests for reservations and effect intents;
12. compaction equivalence tests for each adopted durable domain;
13. eclipse controls that preserve the impossibility boundary;
14. elastic-provider controls for grant, pressure, exact release, child-scope borrowing, pending demand under the provider's own declared selection policy, retirement requests to reclaimable owners, ignored retirement, failed-cleanup retention, slow work, and storage-backed work;
15. resource characterization and opaque-residual reports on every supported target;
16. deterministic durable-store controls for statement/preflight refusal, WAL
    write and sync faults, ambiguous COMMIT return, post-COMMIT checkpoint
    maintenance failure, crash cutpoints, and exact reopen reconciliation,
    recording old/new/outcome-unknown without claiming rollback from an
    unobserved transaction drop;
17. architecture-compliance evidence that includes bounded Open/Closed scale,
    exact `N+1` refusal, lifecycle no-op delivery, exact Closed restart, and
    terminal provider baselines. Source inspection or unit evidence alone is
    not a final compliance PASS.
