# MyOwnMesh architecture owner playbook

Status: execution and ownership contract for the adopted transport-independent
hybrid networking architecture.

Repository identity:

```text
upstream source:       mrjeeves/MyOwnMesh
architecture-owned repository: nathanfraske/MyOwnMeshSecurityReview
```

The upstream and architecture-owned histories remain separate provenance
references. This playbook governs the architecture-owned repository and does
not authorize a clean-room rewrite.

## 1. Mission

The architecture preserves the working, field-tested network while enforcing
the adopted authority model, state ownership, and cross-subsystem boundaries.

The owner formula is:

```text
retain the working mechanism
    -> enforce its typed owner boundary
    -> route production callers through that owner
    -> exclude conflicting authority paths
```

The first product objective is a working end-to-end session on the new promotion boundary:

```text
existing signaling
    -> existing WebRTC/ICE transport work
    -> ConnectedChannelCapability
    -> channel-bound mutual Device authentication
    -> current Open or Closed policy
    -> principal-bound SessionCapability
    -> one existing application payload operation
```

Everything else builds outward from that vertical slice.

## 2. Non-negotiable constraints

1. **Preserve the working network.** WebRTC, ICE recovery, Nostr, mDNS, STUN/TURN, native RTP media transport, daemon, GUI, installer, updater, diagnostics, and field-derived tests are assets. Fixed H.264, Opus, video, audio, and lane semantics are application profile behavior, not basal architecture.
2. **Usability first, promotion secure.** Untrusted hints may cause bounded speculative networking work. They may not create durable authority, deliver application data, or promote a session.
3. **Transport independence, not transport removal.** The connector remains first-class and does real discovery, racing, measurement, path selection, and recovery.
4. **No durable route ceremony.** Ordinary candidates, routes, current path, handoff, and reachability remain live connector/session state.
5. **One state class, one owner.** No `Arc<Mutex<GlobalState>>`, replacement engine grab bag, or global command/event enum.
6. **Open remains open.** Resource control cannot become disguised admission.
7. **Closed alone adds governance authorization.** Existing `auto_approve`, local roster mutation, or transport state cannot satisfy it.
8. **No unbounded or plaintext ordinary mesh forwarding.** Any Hub fallback is an explicit bounded path carrying endpoint ciphertext or refusing; a Closed relay remains an exact allocation carrying opaque endpoint packets.
9. **No translation layer owns product behavior.** Typed boundaries keep one state owner and expose only the capabilities required by their caller.
10. **Do not invent numeric budgets.** Instrument the complete path, measure supported targets, and surface values for owner review.
11. **Own properties, not magnitudes.** This package fixes the *properties* of resource ownership. Capacity magnitudes come from a named provider supplied by the deployment or embedder, never from a document, default, or library constant. A concrete provider's arbitration algorithm is that provider's policy, not a basal architectural requirement.

## 3. Source-of-truth document set

Read in this order:

1. [`ARCHITECTURE.md`](ARCHITECTURE.md), the minimal system shape.
2. [`APPLICATION-INTEGRATION.md`](APPLICATION-INTEGRATION.md), the product-facing boundary.
3. [`IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`](IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md), the concrete implementation contract.
4. [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md), the proof obligations.
5. [`red-teams/MESH-ATTACK-VECTORS.md`](red-teams/MESH-ATTACK-VECTORS.md), source findings and adversarial gates.
6. [`ARCHITECTURE-OWNERSHIP.md`](ARCHITECTURE-OWNERSHIP.md), conflict and upstream policy.
7. [Final state-owner mapping](CURRENT-TO-TARGET-MIGRATION-MATRIX.md).

No implementation PR may redefine a term already fixed by these documents.

## 4. Repository and branch governance

### Step 4.1. Verify source provenance

1. Add or verify `upstream` points to `mrjeeves/MyOwnMesh`.
2. Fetch current upstream and record its exact commit.
3. Classify the difference from the fork using `ARCHITECTURE-OWNERSHIP.md`.
4. Preserve or port only U0/U1 changes that satisfy the ownership policy.
5. Run the full existing workspace and GUI checks.
6. Record the exact source identity for every published build and evidence run.

### Step 4.2. Establish repository roles

Recommended roles:

```text
upstream/main
    read-only tracking reference

main
    architecture-owned, continuously buildable product branch

change/<owner>-<scope>
    one bounded owner change or tightly coupled vertical slice

repro/<case-id>
    isolated red-team or field-failure reproduction only
```

Branch names are workflow labels, not semantic authority. An owner change
must preserve the final owner graph and its evidence boundary.

### Step 4.3. Install the fundamental documents

Place this package at repository root, preserving the canonical names:

```text
ARCHITECTURE.md
FORMAL-PROOFS.md
IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md
APPLICATION-INTEGRATION.md
TRANSITION-PLAYBOOK.md
ARCHITECTURE-OWNERSHIP.md
CURRENT-TO-TARGET-MIGRATION-MATRIX.md
red-teams/MESH-ATTACK-VECTORS.md
diagrams/*
```

Do not retain a competing architecture document under another canonical name.

## 5. Ownership operating model

### 5.1. Runtime supervision

The per-network runtime supervisor serializes lifecycle events and owns only
node startup, shutdown, and configuration routing. It may:

- start and stop owned nodes;
- route commands through narrow typed ports;
- surface node events through typed application DTOs;
- preserve carrier and session behavior while ownership remains explicit.

It may not make domain decisions. Its state is lifecycle coordination only.

### 5.2. Node boundaries

Keep node boundaries narrow and prove state ownership before extracting a crate.
The architecture-owned modules and actor/task owners are:

```text
runtime/semantic
runtime/signaling
runtime/attempt
runtime/session_broker
runtime/peer_session
runtime/reachability
runtime/relay
connector
endpoint_auth
capability
resource
application_gateway
```

An extraction or ownership change is complete only after:

- the owner has exclusive state custody;
- its ports are stable;
- callers use the owner boundary;
- dependency direction is proven by tests.

### 5.3. Universal PR contract

Every architecture change must state:

```text
State class moved:
Sole owner:
Ownership boundary:
New typed inputs:
New typed outputs:
Capability boundary added or changed:
Pre-auth and post-auth resource effects:
Boundary/API callers:
Positive controls:
Negative controls:
Red-team cases:
Performance measurements:
Documentation updated:
```

A change fails review if it adds a new `NetworkCmd`, global event, helper module,
or shared mutable map without proving why the owning node cannot own the
operation directly.

## 6. Final node ownership

| Node | Sole mutable state | Source families | Must never own |
|---|---|---|---|
| Semantic Node | accepted durable facts, Open projection, Closed projection, durable grants/revocations, policy guards, verified durable basis | `semantic/*`, `engine/governance.rs`, persistence | sockets, candidates, traffic keys, application queues |
| Signaling Node | carrier connections, durable anti-entropy, ephemeral-control routing, bounded carrier provenance | `engine/signaling_bridge.rs`, Nostr, mDNS, LocalBroker | roster decisions, endpoint identity, application delivery |
| Attempt Node | one attempt's candidates, speculative permits, race policy, cancellation, ephemeral correlation | `ensure_peer_session`, reconnect intents, signaling offer/answer flow | durable facts, application payload, session authority |
| Connector Worker | native connector state, a live connected channel, and optional connector-native data-plane providers | `transport/webrtc.rs`, ICE/TURN code | mesh authorization, application codec or product meaning |
| Endpoint Auth Task | fresh channel-bound Device-authentication transcript, the closed crypto profile, and the sole issuance of `AuthenticatedChannelCapability` (`endpoint_auth/`) | `engine/handshake.rs`, `signing.rs` | Open/Closed policy, application authorization, wire frames, peer-registry effects, the channel-binding term |
| Session Broker | atomic promotion, current policy guard, principal binding, post-auth permits, capability minting | authenticated approval/policy result | packet loops, candidate gathering, durable governance |
| Peer Session Node | authenticated channels, traffic/replay state, session data-plane capabilities, application queues, recovery and local path selection | peer state, heartbeat, ladder, reliable delivery, media-flow ownership | durable fact construction, global topology authority, codec or screen/camera/audio semantics |
| Reachability Node | local signaling, candidate, channel, and session observations with local age | connection tracer, traffic recency, heartbeat, carrier diagnostics | participation or authorization |
| Relay Node | exact route-bound generations, endpoint/accepted/pending/closing custody, and bounded opaque directional allocations and queues | `engine/closed_relay.rs`, `runtime/relay`, Closed network control path | endpoint keys, application parsing, fanout |
| Application Gateway | local principal, IPC connections, public handle leases, subscriptions | daemon control, `handle.rs`, GUI facade | internal SessionCapability construction, connector control |
| Runtime Supervisor | node lifecycle and configuration routing | current driver/service manager | domain state or authorization decisions |

## 7. Closure and evidence gates

The accepted owner graph is evaluated through atomic runtime, authority,
durability, relay, resource, and release gates. The coverage checklist in 7.4
maps those concerns to the final owners; it does not create additional product
variants or ownership paths.

### 7.1. Live runtime owner boundary

Endpoint Auth consumes the channel-bound transcript, the Session Broker
performs atomic promotion, and the application gateway exposes only live
session capabilities. Connector/session edges expose product-neutral opaque
real-time flows. This boundary is confined to MyOwnMesh; downstream
applications consume the gateway and do not define mesh authority. No second
authority path is retained for a caller that lacks a live session capability.

Exit condition:

```text
working direct, TURN, and any bounded encrypted Hub-fallback connectors preserve the same remote Device identity
exact endpoint authentication plus current policy and a local principal mint a live SessionCapability
a generic MyOwnMesh application operation succeeds only through that session
connected but unauthenticated channels deliver nothing
authenticated but policy-denied channels deliver nothing
replacement and restart invalidate the session
optional realtime flows carry opaque encoded units without basal product semantics
all MyOwnMesh application paths use the session boundary
no pre-V4 authority path or mixed-version fallback remains
no operation has an authority bypass
```

### 7.2. Authority, durability, relay, and closure

This gate covers typed durable-semantic and ephemeral-transport lanes, Open and
Closed semantics with their governance rules, opaque infrastructure,
bounded encrypted Hub-fallback and Closed-member relay profiles, durable store
reopening/compaction, provider resource closure, and the release owner graph.
Unbounded or plaintext ordinary forwarding, obsolete governance, dead APIs,
and parallel authority paths are absent. The
closure gate in 7.3 makes these final-state requirements verifiable rather than
asserted.

#### 7.2.1. Evidence ledger

[The owner and evidence ledger](MACRO-SLICE-2-ENTRY-LEDGER.md) indexes the
owner graph and its closure evidence. It is not an architecture source of
truth, and its recorded evidence does not imply execution on a later source
head. Any explicitly pending platform or runtime evidence remains a stop
condition for the corresponding release claim.

### 7.3. Repository Closure and Nodularity Gate

The final conformance gate for the repository. It introduces no product
semantics: every item it requires is an exclusion, consolidation, or move to
the owner that holds the state. Nothing here can be satisfied by adding a
parallel layer.

The gate is met only when all of the following are absent from the repository:

```text
no LegacyV1 path or mixed-version fallback
no parallel translation layer with product behavior
no obsolete protocol variant or config field
no dead permit, constructor, feature or public re-export
no old peer-string / socket / route authority bypass
no stale direct-send or media-lane API
no dead-code #[allow(dead_code)] keeping removed design alive
no obsolete CI job, regex guard, mutation harness or evidence dossier
no unused dependency
no duplicate mutable truth beside the accepted capability owner
no application or transport semantics in the wrong architectural node
no grab-bag module owning unrelated state classes
canonical documentation describes the code that actually remains
```

Two of those are easy to satisfy dishonestly and are therefore stated exactly.
"No duplicate mutable truth" means one owner per mutable state class, not one
owner plus a cache that agrees today. "Canonical documentation describes the
code that actually remains" means the current contract and nothing else: a
comment recording what a file used to contain is not documentation of what
remains, and a removed variant does not keep a grave marker in production
source.

### 7.4. Final coverage checklist

| Final area | Owner/disposition |
| --- | --- |
| Runtime foundation, Endpoint Auth, Session Broker, Attempt, Peer Session, Reachability, and Connector | Integrated owner graph; evidence is evaluated at the named runtime boundary. |
| Typed signaling lanes, Open semantics, Closed semantics, relay profiles, durable persistence, and resource closure | Integrated authority/data-plane owners; no alternate authority or forwarding path. |
| Release rollout, daemon, GUI, installer, updater, and platform behavior | Operational owners; platform evidence remains governed by the explicit release ledger. |
| Causal-contract/application domains | Optional application-domain surface; outside the core completion gate. |

## 8. Test and evidence program

### 8.1 Compile-time boundaries

Require compile-fail or visibility tests proving:

- application code cannot construct signaling records or connector control;
- connector code cannot mint SessionCapability;
- signaling code cannot deliver application data;
- relay code cannot access endpoint traffic keys;
- public IDs cannot reconstruct local capabilities;
- durable semantic code imports no transport runtime.

### 8.2 Pure semantic tests

Cover canonical encoding, signatures, exact context, Open self-participation, Closed proof confinement, independent/joinable/exclusive concurrency, compaction equivalence, and store-opening non-revival.

### 8.3 Deterministic networking simulation

Build fakes for signaling carriers, connectors, connected channels, relay, time, entropy, resources, and fault injection. Exercise every callback order, duplicate, cancellation, crash boundary, and policy invalidation relevant to promotion and recovery.

### 8.4 Real integration matrix

Preserve and expand current cross-platform and field scenarios:

- direct LAN;
- Nostr signaling;
- mDNS signaling;
- TURN;
- network change;
- sleep/wake;
- stale ICE state while traffic flows;
- apparently connected transport with no traffic;
- media;
- daemon and GUI IPC;
- process restart;
- mixed-version behavior is refused; incompatible protocol versions are refused by the protocol gate.

### 8.5 Performance evidence

Measure at minimum:

```text
time to first hint
time to first candidate
time to first connected channel
time to endpoint authentication
time to policy result
time to promoted session
time to first application byte
recovery time by failure class
pre-auth bytes, tasks, sockets, and CPU
post-auth queue and media costs
cleanup time and retained state
```

Do not collapse these into one connection time, because the architecture separates them intentionally.

These measurements are required, and they are never capacity. Producing them is
an obligation for every change that touches a resource path; omitting them is
a defect. That obligation does not let any observation set, justify, or imply
a grant, ceiling, budget, or admissible-object count. Performance
characterization is also not correctness evidence: a control passes only
against a named commit in CI, and a favorable measurement never stands in for
that.

**A passing CI run proves only what it has controls for, and only about the commit it ran on.** Accepted CI at exact head `7e2ba9e`, and at `6a22911` before it, is runtime non-regression evidence only: retained runtime behavior still runs as accepted at that commit. **Once the branch moves past a head, its run becomes prior-head evidence** — it describes a commit that is no longer current and carries no claim about the new head. In neither case does such a run prove P6 partition non-amplification, grant contraction over `S`, `Gc`, `O`, `T`, `E`, or `B`, hostile-ingress progress or backpressure, an enforceable isolation envelope, an actual reserved guarantee, or Slice C closure. No control for any of those exists at those heads, so the runs cannot have exercised them, and no part of those results may be cited toward them. State this limit wherever such a run is cited as evidence.

## 9. Upstream intake

1. Fetch upstream on a regular owner-selected cadence and before every release.
2. Create an `intake/` branch at the exact upstream commit.
3. Classify each commit U0-U5.
4. Merge U0 and proven U1 changes.
5. For U2, port the failure reproduction, test, and mechanism into the architecture owner. Do not merge a legacy state owner.
6. Reject U3 behavior with a written invariant reference.
7. Send U4 to owner review with measured tradeoffs.
8. Update the ownership matrix when a path's final owner changes.

A field fix is not lost because its old module is rejected. The bug reproduction and mechanism are preserved in the correct owner.

## 10. Stop conditions

Stop the change and surface an owner decision when:

- a claimed protocol or provider limit has not been proven;
- a proposed optional local ceiling lacks owner review;
- the selected Closed proof profile lacks owner-selected values or supporting evidence;
- a competing design presents a real usability/security tradeoff;
- the change would silently reinterpret existing durable authority;
- a current field behavior cannot be reproduced or explained;
- a state class cannot be assigned one owner without changing product semantics;
- a translation layer would need permanent product behavior;
- a supported platform or required transport profile regresses;
- the proposed change would reintroduce a durable route, global current path, or transport-removed design.

## 11. Definition of architecture-complete

The architecture is complete when all of the following are true:

1. the connector attempts and races viable transport paths under bounded speculative resources;
2. a working channel is not application authority;
3. exact mutual Device authentication is bound to the working channel;
4. Open or Closed policy and local-principal admission gate promotion;
5. every application send, receive, callback, optional real-time flow operation, and recovery action uses a live SessionCapability;
6. signaling and application payload types are disjoint;
7. durable semantics are transport-independent, while transport remains first-class;
8. Open has no hidden sponsor or pair-permission gate;
9. Closed alone carries governance authorization;
10. unbounded or plaintext ordinary mesh-member payload forwarding is absent; only explicitly owned bounded encrypted Hub fallback and Closed-member relay profiles may forward endpoint ciphertext;
11. relays use exact bounded opaque allocations;
12. handoff is endpoint-driven, with no route ledger or relay-to-relay requirement;
13. reachability is useful local evidence, not authority;
14. store opening restores durable state but no live networking capability;
15. every protected resource family has a live lease, a named provider, typed pressure behavior, and an explicit exactness or residual classification, with the resource property gate satisfied and no arbitration algorithm required of a conforming provider;
16. every mutable state class has one owner;
17. the legacy driver, runtime coordination grab bags, authority bypasses, and parallel product-behavior translation layers are absent, and the Repository Closure and Nodularity Gate in 7.3 is met in full;
18. the full conformance and red-team suite passes on built artifacts;
19. supported deployment, GUI, daemon, installer, updater, and platform behavior remains accepted by the owner.

## 12. Owner-selected decisions that remain explicit

The playbook does not invent deployment-specific values or evidence for:

- local-principal authentication and evidence per platform;
- the installed resource provider, the origin of its capacity, its retention behavior, and its arbitration policy;
- which of `E` and `B` the provider claims in each dimension, and what proves each independently;
- the contraction policy: whether any `O` is collected at all, the named owner policy that sets or derives `T`, and what establishes `E` or `B` where either is claimed;
- the FairnessRoot selection rule, including which trusted provider or ingress owner selects a root and how roots are separated;
- each external dependency accounting boundary: typed owner hook, external isolation boundary, conservative over-charge, or disclosed non-enforcement;
- whether the optional local ceiling set is absent or enabled, and every value in it when enabled;
- optional local resource, queue, retry, timeout, cache, cost, isolation, and bandwidth policy values;
- required restrictive-network connector profiles;
- mixed-version protocol is refused at the protocol gate (hard cutover);
- application data-operation set and optional connector-native real-time flow contract;
- performance regression tolerances;
- release cohort and rollback policy.

Each optional policy is surfaced with measurements and concrete alternatives for owner review. Measurements do not define basal product cardinality. Structural counts are not deployment-capacity recommendations, universal protocol limits, or evidence of exact physical resource quantity.
