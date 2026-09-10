# MyOwnMesh hybrid-networking red-team catalog

> Current normative cutover (2026-09-09): application data uses endpoint-authenticated WebRTC, directly or through configured standard TURN. Hubs provide discovery/introduction only, never application plaintext or ciphertext transit. This supersedes custom encrypted Hub and Closed-member payload relay requirements. Open/Closed governance is unchanged. Historical exact-head evidence below remains historical; this edit is not an implementation, runtime, or release PASS.

Status: target conformance and source-audit catalog for the restored hybrid networking architecture.

This catalog supersedes architecture-dependent pass conditions that required every connector exchange to be a durable signed record, prohibited all transport allocation before Device authentication, or required durable route, path, negotiation-generation, or session-generation state.

The current-source findings remain source findings. Their target interpretation is updated to match [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

Reviews `4865297956` at `378dd82` and `4869373979` at `f58dab6` are cited in this catalog as provenance for wording corrections. A review identifier is never execution evidence, and no pass condition here is satisfied by citing one.

## 1. Target security boundary

The target permits bounded useful networking work before endpoint admission:

```text
untrusted hint or typed transport signal
    -> bounded candidate, socket, relay, probe, and handshake work
```

The target forbids crossing the promotion boundary without every exact predicate:

```text
working channel
+ fresh mutual Device authentication
+ exact MeshContext binding
+ applicable Open or Closed policy
+ authenticated local principal
+ post-authentication resource reservation
+ fresh opaque SessionCapability
    -> AuthenticatedPeerSession
```

The base durable fact families are Closed authority/governance only:
`RoleGrant`, `RoleRevoke`, `Evict`, `MembershipAdmit`, `EvictionProof`,
`SelfStandDown`, `Attestation`, `Resolution`, and
`AuthorityLineageResolution`. Open has zero base durable semantic facts.
Exact-context handshake and Device-key possession establish ephemeral Open
participation. Runtime join, leave, presence, and reconnect for both Open and
Closed are live observations, never semantic history. Reviewed application
contract domains remain explicitly separate. Ordinary candidates, route
selection, path handoff, connectivity checks, relay allocation liveness, and
packet flow are live connector state.

The owner selects finite fact-count, canonical-byte, causal-edge, per-author
count/bytes and retained lifetime, proof-work,
eligible-signer-quarantine, total-proof-history, and indexed SQLite/WAL-reserve
ceilings. The exact `N+1` delta is refused before any
semantic mutation, ACK, identity, or authority change. Duplicate delivery is
a semantic no-op. Exact history remains until an archive or
authority-ratified checkpoint permits deletion; checkpoint and `VACUUM` are
physical reclamation only and no timer silently prunes semantic history.

Signaling includes both durable semantic exchange and ephemeral transport control. Neither category carries ordinary application payload.

## 2. Evidence labels

| Label | Meaning |
|---|---|
| Source-confirmed | The accepting control flow is present in the pinned source and the named guard is absent on that path |
| Runtime-reproduced | The isolated harness produced the observation and retained its evidence |
| Target obligation | The restored architecture requires the test; implementation status is not asserted |
| Source behavior, conforming under bounds | The source behavior is allowed only if it stays inside the stated target boundary |
| Policy decision | The owner must select a measurable policy or value before numeric pass or fail |
| Hardened | The repair and its positive and negative controls pass against the same reproduction |

## 3. Harness isolation

Every reproduction must:

1. use an approved sandbox, loopback-only process, or isolated virtual network;
2. use fresh temporary identities, mesh contexts, stores, ports, and process directories;
3. avoid production identities, sockets, services, and credentials;
4. record source commit, build features, dependency checksums, exact command line, process IDs, addresses, ports, and selected resource limits;
5. impose wall-clock, process, memory, file, queue, and network limits;
6. terminate and verify every child process;
7. retain redacted positive controls, inputs, outputs, resource samples, and cleanup evidence.

No case may target a public relay, production TURN service, production node, or another person's device.

## 4. Threat actors

The suite includes:

- an unauthenticated signaling sender;
- a fresh authentic Open identity;
- a fresh authentic key without Closed authorization;
- an admitted malicious endpoint;
- a carrier that drops, delays, reorders, duplicates, injects, replays, or censors;
- a malicious TURN service or Hub attempting forbidden application forwarding;
- a restrictive network;
- a malicious or unprivileged local application principal;
- identity rotation intended to bypass per-identity resource accounting;
- endpoint or connector callbacks delivered late or out of order.

Complete availability under total eclipse is not claimed.

## 5. Historical source finding reinterpretation

The table retains the source baseline and evidence recorded in the preceding catalog. Its deletion and closure statements describe that historical baseline, not verification of the 2026-09-09 cutover. The current requirement is exclusion of all custom Hub/member application transit, including ciphertext; HYB-027–031 below define replacement obligations without claiming execution. Historical classifications follow:

| ID | Source observation | Restored target interpretation | Priority |
|---|---|---|---|
| RTM-001 | Legacy shaped-topology code can route application payload through ordinary mesh members | Closed by deletion. Arc 03 isolated the source under a `legacy_v1` subtree behind a feature and deprecated explicit construction, and recorded that structural isolation is not a type-level exclusion proof. The subtree, the feature, and the routing runtime are now gone, so the exclusion is absence rather than isolation, and a compile-fail control asserts the runtime cannot be named from the public API | Critical |
| RTM-002 | Optional `RelayService` forwards application payload through an ordinary mesh member | Closed by deletion. The relay service, its runtime, and the member-relay service role and advert field no longer exist. The daemon hosts no per-network relay owner, refuses `services.relay` at startup and through live reconfiguration, and never advertises a relay role, so there is no member through which application payload can be forwarded. Any application payload through a mesh member would still violate the endpoint-only data invariant | Critical |
| RTM-003 | Carrier input allocates transport before Device validation | Not automatically a defect. It fails only if work is unbounded, mutates durable authority, delivers application data, or promotes a session | High conditional |
| RTM-004 | Closed auto-approve admits a fresh unrostered key | Still a defect | Critical |
| RTM-005 | Directed application sends bypass admission | Still a defect | Critical |
| RTM-006 | Local roster mutation lacks proved principal and Closed authority | Still a defect | Critical |
| RTM-007 | Nostr origin is not bound to Device ID | Still a durable-authorship defect | Critical |
| RTM-008 | Nostr presence takeover creates victim Leave | Still a defect | Critical |
| RTM-009 | mDNS spoofs presence, Leave, and transport hints | Semantic spoofing and unbounded work are defects; bounded transport hints are allowed | High conditional |
| RTM-010 | Peer-wide Leave tears down a newer session | Still a defect | High |
| RTM-011 | Signaling has unbounded pre-upgrade and slow-consumer work | Still a defect | High |
| RTM-012 | Media transport objects exist before endpoint admission | Object creation is allowed under bounds; application delivery, outbound payload, or unbounded decode before promotion are defects | Critical conditional |
| RTM-013 | Governance signatures omit state-deriving context | Still a defect | Critical |
| RTM-014 | Concurrent governance delivery silently forks | Still a defect | High |
| RTM-015 | Split adoption does not prove derivation | Still a defect where such operation exists | High |
| RTM-016 | Governance persistence and anti-entropy are unbounded | Still a defect | High |
| RTM-017 | Reliable delivery permits unbounded peer keys and bytes | Still a defect | High |
| RTM-018 | Global queues and RPC work lack total bounds | Still a defect | High |
| RTM-019 | IPC routing labels are capabilities | Still a defect | High |
| RTM-020 | Required restrictive-network connector profiles are unsupported | Reachability gap against owner-selected requirements | High when required |
| RTM-021 | Adversarial TURN must not gain endpoint authority or plaintext | Target obligation | High |
| RTM-022 | Revocation, cleanup, crash, and effect races lack one model | Still a critical obligation | Critical |
| RTM-023 | Bounded negotiation begins without pair permission | Positive control, not a defect | None |
| RTM-024 | Replay after cache or deduplication eviction | Durable replay and live-capability non-revival remain obligations; old control may cause bounded candidate work | High |
| RTM-025 | Legacy state reconstructs connection policy | Persisted mesh authority must not choose application relationships; local connector policy is allowed | High |
| RTM-026 | Free-form negotiation fields carry application data | Still a defect | High |
| RTM-027 | Open authority survives migration into Closed | Still a defect | Critical |
| RTM-028 | Connected censoring relay suppresses fallback | Availability weakness; connector policy must not equate socket health with useful progress | High |
| RTM-029 | Carrier provenance is stripped | Still an availability and diagnostics weakness | High |

## 6. Superseded target assumptions

The restored target does not require:

```text
every offer, answer, or candidate to be a durable fact
durable PathOffer or PathAccept facts
a global PathID or current-path record
monotonic negotiation, session, relay, or path generations
a durable session anchor before transport work
common durable-fact validation before any candidate allocation
relay use only after exhaustive failure of all other candidates
relay-to-relay handoff signaling
```

Tests whose only failure condition is the absence of those constructs are removed or rewritten.

## 7. Durable semantic tests

### HYB-001. Canonical durable fact integrity

Alter every state-deriving durable field, Fact ID, author key, signature, mesh context, scope, predecessor set, and canonical encoding.

**Pass:** Only the exact canonical signed positive control reaches durable projection. Invalid input creates no accepted durable receipt, durable head, or durable effect.

### HYB-001a. Ledger quota and quarantine boundary

Fill each owner-selected ledger dimension to `N`, then submit valid `N+1`
fact, causal-edge, per-author, proof-history, eligible-signer, quarantine,
and database/WAL-reserve candidates, including a duplicate Fact ID and a
semantic no-op.

**Pass:** The complete delta is refused before graph, projection, ACK,
identity, or authority mutation. Missing-parent candidates use only the
bounded dependency index; duplicate and no-op candidates do not extend exact
history. Per-author retained lifetime caps and proof-work limits are enforced
without timer deletion. SQLite remains local-only, single-writer, WAL/FULL,
and physical checkpoint/`VACUUM` reclamation cannot delete semantic history
without an archive or authority-ratified checkpoint. Failed cleanup retains
the exact charge.

### HYB-002. Carrier non-authorship

Deliver a valid A-authored fact through a B-controlled carrier and a B-authored carrier envelope that claims A.

**Pass:** The valid fact remains authored by A. The carrier claim grants no authorship.

### HYB-003. Open ephemeral permissionless positive control

Have a fresh Device key complete an exact-context endpoint handshake proving
key possession, without publishing a durable participation record.

**Pass:** It may participate ephemerally without sponsor, pair grant,
identity vote, or application approval, subject only to endpoint protocol
validation and local resource admission. No durable fact, join, leave, or
presence record is created.

### HYB-004. Closed unauthorized key

Use a valid Device signature from a key absent from the accepted Closed governance state.

**Pass:** It cannot create Closed participation or promote a Closed session. Bounded harmless observation may occur only under the selected explicit rule.

### HYB-005. Durable concurrency classification

Create independent, joinable, and exclusive concurrent facts under the adopted domains.

**Pass:** Independent facts project independently, joinable facts satisfy the declared join, and exclusive same-cell siblings fail closed. Common ancestry alone does not create a fork.

### HYB-006. Durable compaction equivalence

Compare full-history and compacted-basis validation and projection for every covered future continuation.

**Pass:** Validation disposition and durable state are equivalent. Compaction does not affect live path or reachability state.

### HYB-007. Store opening

Open the same durable basis after normal restart, long storage, copy, and transport through different media.

**Pass:** Durable projection is identical. No candidate, socket, channel, key, replay window, observation, or session handle is restored.

### HYB-008. Open-to-Closed separation

Replay an Open handshake/observation and application-like claims into a Closed
context.

**Pass:** Only the selected Closed governance proof supplies Closed authority.

## 8. Signaling tests

### HYB-009. Durable and ephemeral parser separation

Send every durable fact to the ephemeral control parser and every ephemeral control message to the durable parser.

**Pass:** Cross-class inputs are rejected or treated as bounded unknown input. No parser retries an input under another semantic class after rejection.

### HYB-010. No application payload in signaling

Attempt to place a marked application byte string into every public durable and ephemeral signaling constructor, unknown field, extension map, padding field, candidate field, and relay-control field.

**Pass:** Ordinary application APIs cannot construct such messages. Unknown or opaque fields are rejected. A compromised endpoint's covert timing or valid-value channel is not represented as a supported payload path.

### HYB-011. Carrier-synthesized leave

Disconnect signaling carriers, remove mDNS advertisements, and send service-authored Leave messages.

**Pass:** Carrier events affect delivery and transport observations only. They
cannot synthesize a durable Open fact, runtime withdrawal authority, Closed
removal, or session closure.

### HYB-012. Connected censoring carrier

Keep one signaling socket healthy while withholding required facts or transport-control responses.

**Pass:** Socket health alone is not reported as complete progress. Independent carriers may be attempted under owner policy. Total eclipse remains an availability limit.

### HYB-013. Provenance retention

Deliver the same durable fact and different dependency subsets through several carriers.

**Pass:** Durable state deduplicates by Fact ID while bounded local provenance remains distinguishable. Provenance does not vote.

## 9. Speculative transport tests

### HYB-014. Raw hint creates bounded candidate work

Supply raw mDNS, address, incoming socket, offer, candidate, and relay hints from unknown and unauthorized sources.

**Pass:** The runtime may create bounded candidates, sockets, relay allocations, or handshake state. It does not mutate durable authority, expose application data, or exceed pre-authentication budgets.

### HYB-015. Identity-rotation resource attack

Use many fresh keys and unauthenticated hints to create candidate work.

**Pass:** The one process resource grant dominates per-identity attribution. Every admitted unit owns a finite lease, typed pressure stops new work when the applicable dimension is unavailable, and cleanup releases only its exact claims.

### HYB-016. Candidate racing

Make direct and configured standard TURN candidates complete in different orders and with different quality. A Hub is not a third application carrier.

**Pass:** The connector may use the first or locally preferred promotable channel. No durable route record or exhaustive-failure proof is required.

### HYB-017. Restrictive-network matrix

Exercise every owner-required egress profile.

**Pass:** A supported connector establishes a promotable channel or returns a bounded typed no-path result. Signaling success is not reported as a data path.

### HYB-018. Pre-authentication real-time flow quarantine

Establish connector-native real-time transport objects and send valid-rate and over-rate encoded units before Device authentication and promotion.

**Pass:** No unit reaches the application and no outbound application unit is sent. Pre-authentication parse, buffer, decode, and task work remain within selected bounds. Track or receiver setup alone is not a failure.

### HYB-018A. Media-profile confinement

Inventory every core, connector, application, daemon, and IPC type that names video, audio, H.264, Opus, screen, camera, microphone, lane count, lane number, or track purpose. Exercise one data-only connector and the WebRTC real-time flow provider.

**Pass:** Codec and media-purpose semantics are absent from durable authority, signaling authority, endpoint authentication, and channel promotion. The WebRTC connector may retain native RTP/RTCP mechanics and connector-local lane policy. Applications receive encoded real-time units only through a live session capability. A connector without the real-time flow extension remains conforming.

### HYB-019. Candidate callback after replacement

Delay callbacks from a destroyed candidate or channel until a replacement exists.

**Pass:** Exact local capability mismatch prevents the old callback from mutating the replacement.

## 10. Channel-promotion tests

### HYB-020. Promotion predicate matrix

Independently omit or alter:

- working channel state;
- local and remote Device identities;
- endpoint-authentication transcript;
- channel binding;
- MeshContext;
- Open or Closed policy;
- local principal;
- post-authentication reservation;
- fresh session capability.

**Pass:** Session exposure occurs only when every exact predicate holds.

### HYB-021. Working socket is not authority

Complete TCP, QUIC, ICE, DTLS, TURN, or relay setup without MyOwnMesh endpoint authentication.

**Pass:** No authenticated peer-session handle or application delivery occurs.

### HYB-022. Claimed Device mismatch

Begin from a hint claiming Device C but authenticate Device D on the channel.

**Pass:** The attempt fails for C. It may be reclassified as D only through an explicit policy path that does not smuggle the original claim into authority.

### HYB-023. Cross-channel transcript replay

Record a valid endpoint-authentication transcript on channel X and replay it on channel Y.

**Pass:** Channel binding and freshness reject it.

### HYB-024. Restart non-revival

Persist all allowed durable state, restart, and replay old signaling and transport-control bytes.

**Pass:** No old candidate, channel, traffic key, replay state, principal capability, or session handle is reconstructed.

### HYB-025. Directed application send before promotion

Exercise messages, RPC, media, datagrams, and every application send API in every pre-promotion state.

**Pass:** No application bytes reach the remote or local application consumer.

### HYB-026. Current policy loss

After promotion, accept an applicable runtime Open departure or Closed removal
and race it against queued sends and callbacks.

**Pass:** New protected use fails after the committed policy change. Cleanup remains possible. A later re-add or re-presentation requires a newly valid session promotion, not revival of the old handle.

## 11. TURN and forbidden member-transit tests

These are current required controls, not new execution PASS claims. Historical
HYB-028/029/030 member-relay cases are superseded; their prior results remain
attached to their original source and profiles.

### HYB-027. Adversarial standard TURN

Drop, delay, duplicate, reorder, truncate, or modify WebRTC-protected packets
and attempt endpoint substitution.

**Pass:** Endpoint authentication/integrity remain required. TURN cannot gain
application plaintext or endpoint authority under the stated WebRTC premises;
denial and metadata observation remain residuals.

### HYB-028. Configured TURN positive control

Prevent direct connectivity in an isolated authorized testbed and configure a
standard TURN service. Establish the endpoint WebRTC session.

**Pass:** Exact endpoint-authenticated application bytes reach the intended
endpoint through TURN, not a Hub/member or signaling payload tunnel. Record
actual selected-path evidence; do not infer TURN use from configuration alone.

### HYB-029. Removed custom route surface refusal

Present removed `closed_relay`, `application_transport`, `endpoint_cipher`,
and `routing_policy` config fields and removed wire messages.

**Pass:** Refusal occurs without starting a compatibility member relay/cipher.
The current optional `introduction` policy supplies no payload authority.

### HYB-030. Hub/signaling payload injection

Attempt both plaintext and ciphertext forwarding through Hub discovery,
introduction, setup/control, and typed semantic-control handlers.

**Pass:** No application tunnel is created. When cohosted, standard TURN remains
a distinct service; its URL advertisement and locally configured credentials
do not constitute implemented protected credential distribution.

### HYB-031. TURN candidate selection

Race configured TURN with a slow direct candidate under bounded local policy.

**Pass:** Selection does not require a signed exhaustion proof, does not grant
endpoint authority, and never falls back to Hub/member application forwarding.

## 12. Handoff and replay tests

### HYB-032. Endpoint-driven B-to-D handoff

Use B, then establish D while B remains active.

**Pass:** A and C authenticate D's channel and may use `{B, D}` before selecting D. No B-D signaling is required.

### HYB-033. Forged switch request

Have B, D, or a signaling carrier send `switch now`, `current route`, or equivalent messages.

**Pass:** No such message directly changes the authenticated channel set or local selected carrier.

### HYB-034. Forced old-path failure

Drop all B traffic while advertising D.

**Pass:** Failure may trigger candidate work or selection of an already authenticated D channel. It cannot promote unauthenticated D.

### HYB-035. Old-channel packet replay on new channel

Replay B-channel packets and endpoint-authentication messages through D.

**Pass:** Channel-specific keys, binding, and replay state reject them.

### HYB-036. Delayed old-channel close

Deliver a late B close or failure callback after D is active.

**Pass:** It affects only B's exact local channel capability and cannot close D or the peer session unless no authenticated channel remains and policy closes the session.

### HYB-037. Concurrent bidirectional carrier choice

Let A temporarily send over D while C still sends over B.

**Pass:** Both directions remain secure when each used channel is independently authenticated. No global simultaneous switch is required.

## 13. Signaling and payload boundary tests

### HYB-038. Cross-protocol listener confusion

Co-locate signaling, standard TURN, Hub introduction, and application service endpoints. Send each message type to every wrong listener.

**Pass:** No cross-parser or cross-effect substitution occurs. Co-location claims no physical compromise isolation that deployment does not provide.

### HYB-039. Ordinary member forwarding

Establish A-B and B-C sessions but no A-C session. Ask A to send application data to C through ordinary mesh APIs.

**Pass:** Neither plaintext nor ciphertext is forwarded by the mesh/Hub. A-C requires its own promoted direct/TURN session or an explicit application intermediary.

### HYB-040. Explicit application intermediary positive control

Make B an application endpoint for A-B and B-C.

**Pass:** B may process and reauthor application operations under application policy. The system reports two sessions, not a transparent carrier.

## 14. Reachability tests

### HYB-041. Presence is not path

Receive a fresh signed presence response while every data connector fails.

**Pass:** Reachability view shows the exact evidence classes and returns no viable peer transport.

### HYB-042. Path is not durable authority

Keep a working authenticated channel while delivering a durable withdrawal or Closed removal.

**Pass:** The transport may physically exist, but application use follows the current policy guard. Transport existence does not rewrite durable state.

### HYB-043. Local freshness

Replay old observations with fresh remote or carrier timestamps.

**Pass:** Local age remains based on the original local verification time.

## 15. Resource and crash tests

### HYB-044. Pre-authentication guard ordering

Deny each reservation before its protected parser, candidate, socket, relay, handshake, media quarantine, timer, task, or queue allocation.

**Pass:** No protected allocation occurs first.

### HYB-045. Post-authentication guard ordering

Allow a working authenticated channel but deny session, application queue, media, or handle resources one at a time.

**Pass:** Promotion or the protected operation fails without leaking application data.

### HYB-046. Crash around promotion

Crash before and after endpoint authentication, reservation, handle commit, and application notification.

**Pass:** Recovery exposes either no session or one complete valid session state. No partial handle or duplicated semantic exposure exists.

### HYB-047. Crash around external effects

Crash after an external transport or signaling action but before effect completion commit.

**Pass:** Deterministic effect identity and adapter idempotency prevent duplicate semantic effects. Cleanup remains possible.

### HYB-048. Complete eclipse control

Run identical local traces where a newer durable fact or better path exists but is withheld, and where it does not exist.

**Pass:** The runtime does not falsely claim to distinguish the worlds. It still rejects forged authority and unauthenticated sessions.

### HYB-049. Cooperative shared-grant pressure

Let one Mesh scope borrow the last grantable units with reclaimable speculative work. Submit overlapping cooperative demands from another scope and from each authority class.

**Pass:** The provider creates no weight, quota, share, or new capacity. It requests retirement from the exact speculative owner but does not release the claim. The selected demand acquires only after the owner drops the exact lease. Those are the basal properties. The shipped `FiniteResourceProvider` implements them by giving `Cleanup`, then `Admitted`, then `Speculative` the next turn and rotating equal-authority FairnessRoots, so that under this provider no root reacquires indefinitely ahead of an equal-authority root's outstanding demand. That exact order, that rotation, and the non-reacquisition behavior they produce are this provider's concrete policy, and the control asserts them as provider evidence rather than as universal provider conformance.

**Not covered here — covered by a separate P6 control.** This vector submits demands from distinct trusted roots, so it exercises root rotation only, not scope rotation, and it remains insufficient for P6 on its own. It does not itself exercise P6 partition non-amplification, also called subdivision monotonicity: run one fixed input workload twice — a finite root set, one initial provider state including `Gc`, one identical arrival sequence, each arrival's exact claim, authority class, and reclaimability, and one deterministic owner response rule, with releases derived rather than scripted — under one shared construction in which both executions have identical pre-existing roots, identical `AttributionChildScope` topology, identical bookkeeping charges, and stable DemandIds, and only the DemandId-to-scope mapping differs, with root `A`'s demands under one scope in the baseline and the same DemandIds spread across several scopes beneath that same root in the subdivided execution, both stepped by one deterministic clock-free reducer that interleaves exogenous arrivals and owner-derived actions and permits terminal stuttering. Compare prefix-wise at every provider decision point: `A`'s cumulative selections must not exceed baseline, `A`'s cumulative admitted quantity must not exceed baseline in every dimension, and every competitor demand's selection position must be no later than its baseline position, with absence counted as infinity. The shipped `FiniteResourceProvider` now keys its rotation cursor and reclaim cursor to the `FairnessRoot` rather than to process-local scope identities, so an `AttributionChildScope` beneath one root introduces no additional rotation key and the previously disclosed counterexample is removed. Controls for that comparison are **landed in the working tree, with no execution result claimed here**: they run against the live provider over an ordered trace of cooperative-admission dispositions on the non-failing path, with a negative fixture forcing scope-keyed selection that the oracle must reject. A superseded selection-only test was previously described as the formal control; that was an overclaim and was withdrawn. Those controls fix a bounded decision prefix that begins from an identical state in both executions and in which none of the compared newly admitted demands releases. Construction A isolates bookkeeping by holding the already-created topology and its already-charged claims identical before the prefix begins; a comparison that creates or charges different scope state in either execution is not this control. Scope state is finite and fallible, so neither the property nor its control promises unlimited scopes. P6 is one-way, so the control asserts no equality of outcome, no share ratio, and no scheduler, claims nothing about eventual admission, throughput, or latency, is not Sybil resistance for a real-world claimant or actor that legitimately holds several roots, rests on no real-world claimant identity premise, and is not a hostile-ingress progress or backpressure result; those remain the separate obligations of the ingress and pre-authentication vectors in this catalog. Root assignment itself remains trusted local policy: the local provider or ingress owner may use facts it has verified or authenticated, including an authenticated principal or an isolated ingress path, as mapping input, while no claimant-supplied or wire-visible value may directly name, select, split, or multiply a root and no party may increase the number of roots it is attributed to by asserting something. The mapping need not be independent of verified facts; it must be independent of unverified assertion. `FairnessRoot` and `AttributionChildScope` are used here with the closed architectural definitions owned by [`../ARCHITECTURE.md`](../ARCHITECTURE.md), which governs them: a `FairnessRoot` is the unit of scheduling attribution a provider serves, selected locally by the trusted provider or ingress owner and not mintable by the claimant it attributes; an `AttributionChildScope` refines accounting beneath exactly one `FairnessRoot` and creates no additional root, share, turn, or service weight. [`../IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`](../IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md) owns the trusted local mapping and the typed provider status built on those definitions. Per-scope rotation evidence, including this vector's, must still not be presented as evidence for P6. The P6 result is bounded: not a whole-model proof; scoped to cooperative admission on the non-failing path and no wider; working-tree scope rather than exact-head or hosted CI, with no execution result claimed here and citation requiring exact-state local verification and exact-head hosted evidence recorded externally; with test-side logical DemandIds bound at issue, variant-specifically by provider-minted demand key or exact per-call decision-log index; and claiming no deployed multi-root mapping, since production has one scheduling root beneath which child subdivision cannot multiply turns, cross-root production fairness is not claimed, future trusted-root assignment belongs to its owning provider or ingress arc, and additional trusted-root minting and the cross-root exercises are `#[cfg(test)]` only.

### HYB-050. Slow valid lease

Keep a valid lease live without completing its operation while other scopes request the same exhausted dimension.

**Pass:** Elapsed time does not expire or revoke the lease. Without real pressure, no reclaim request occurs. Under overlapping cooperative pressure, only an explicit request to the registered speculative owner may begin cleanup. The test does not use a timeout as resource truth.

### HYB-051. Cleanup reservation under full pressure

Admit a connector with its cleanup obligation reserved, fill the remaining shared grant with speculative work, then force connector close.

**Pass:** The exact connector cleanup is submitted without acquiring a new speculative permit, and provider notification never releases another owner's live lease. Those are the basal properties. The shipped `FiniteResourceProvider` additionally gives a cleanup-class demand the next structural turn ahead of admitted and speculative demand, so under this provider a cleanup-class demand is not deferred indefinitely behind admitted or speculative demand. That turn order and the non-deferral behavior it produces are this provider's concrete policy, not universal provider conformance.

### HYB-052. Reclaim completion and retained failure

Saturate a dimension with one registered speculative owner. Request the same dimension from another scope, then exercise successful cleanup, demand cancellation, ignored retirement, and failed cleanup separately.

**Pass:** Successful cleanup releases only the exact selected claim and lets the pending demand retry. Cancellation removes the demand without releasing the owner. Ignored retirement leaves the demand pending. Failed cleanup retains the exact charge and returns typed pressure. No timer, provider-side release, or fabricated capacity appears.

### HYB-053. Native and OS residual denial

Set a modeled native or OS dimension to deny new use, then exercise native WebRTC construction, ICE sockets, TURN selection, cleanup-executor startup, and dependency-created tasks separately.

**Pass:** Each operation is either blocked by an actual claim in that dimension or reported as an explicit residual with its isolation boundary. A configured grant field that the adapter never consumes is not accepted as enforcement evidence.

## 16. Cross-case proof obligations

A conformance claim must also show:

1. every public parser and constructor maps to one closed accepted type;
2. every state mutation has one owning component;
3. every external effect is reachable only through a committed guarded plan;
4. pre-authentication work cannot reach application delivery;
5. channel promotion has no alternate bypass path;
6. carrier identity never substitutes for Device identity or Closed authority;
7. no durable path ledger or monotonic path/session generation remains a basal dependency;
8. durable `Project` excludes live transport observations;
9. application payload cannot reach durable or ephemeral signaling constructors;
10. relays have exact destinations and finite resources;
11. delayed callbacks and stale local capabilities are rejected;
12. store opening reconstructs no live networking authority;
13. every numeric bound is classified as protocol shape, provider structure, runtime grant, or explicit owner policy;
14. every cross-scope progress claim is limited to registered reclaimable speculative pressure whose exact owner completes cleanup;
15. every claimed native or OS dimension has an exercised adapter hook, otherwise it remains an explicit residual;
16. every resource statement is classified as a basal property required of any installed provider port or as concrete arbitration policy of the shipped provider, and a concrete-policy pass is never presented as universal provider conformance;
17. immediate refusal is constrained by work conservation: typed pressure replaces retention only for a claim that does not fit, and a fitting claim is admitted except under a proven structural limit, an explicit isolation policy or optional local ceiling, or accounting that is unavailable, unsafe, or poisoned. Capacity is absolute per dimension and reduced to a residual only at the end, as [`../FORMAL-PROOFS.md`](../FORMAL-PROOFS.md) defines and governs: `AccountingCapacity(d)` is the committed grant `Gc(d)` narrowed only by an explicit P5 restriction; `EffectiveCapacity(d)` intersects it with `E(d)` where `E` is proved and `B(d)` where `B` is proved; and `EffectiveFit(d)` is `max(0, EffectiveCapacity(d) - S(d) - R_flight(d))`, where `S(d)` is the charged sum and `R_flight(d)` the aggregate exact capacity reserved for all admissions currently in flight, zero when none is in flight and never interchanged with FORMAL's global `R` for the lease-claim multiset. A claim fits exactly when it fits in every dimension it names, with no cross-dimension compensation. `O` and `T` participate nowhere, and apparent headroom in a measurement is not evidence that a claim fits. An explicit P5 restriction is exactly one of three closed forms — a named local isolation domain, a named partition or reserved share, or a named optional local ceiling or cost boundary — each explicit, named, and recorded. Nothing else narrows `AccountingCapacity`: no observation, target, measurement, generic owner preference, workload calibration, anticipated future demand, rate smoothing, inferred restriction, or undeclared product policy, and an undeclared narrowing is an arbitrary refusal that P4 forbids. A successful fit is an accounting result only and guarantees no allocator, kernel, runtime, transport, external-relay, or hardware success. Refusal never reserves capacity for an anticipated demand or enforces an undeclared share;
18. contraction keeps seven per-dimension quantities distinct: `S` the committed charge, `R_flight` the aggregate exact capacity reserved for admissions currently in flight, `Gc` the committed grant admission is checked against, `E` an enforceable containment ceiling that caps consumption and promises no availability, `B` capacity actually reserved for and owned by the provider, `T` an owner-selected target, and `O` an external observation. `E` and `B` are orthogonal premises; a provider may prove either, both, or neither per dimension, and one proving neither is accounting-only there. `S(d) + R_flight(d) <= Gc(d)` holds at every instant in every dimension and implies `S <= Gc`, so `S > Gc` is never exhibited or described and a grant contracts only down to the floor `S(d) + R_flight(d)`, never stranding an in-flight reservation. `O` is inert and authorizes nothing. `T` is owner-selected, either named directly or derived by a named, recorded policy that may consider an optional `O`, with no mandatory path from `O`, and by itself it lowers no grant, releases no charge, and refuses no admission. `Gc` follows `T` downward only after owner-driven release lowers committed use enough to make each step safe. A provider claiming `B` proves `Gc <= B` at admission and one claiming `E` proves `Gc <= E`, each under the Slice C mapping requirement; premise loss has two regimes: while `premise >= S(d) + R_flight(d)` residual headroom remains usable, `EffectiveFit(d)` is recomputed against the reduced premise, ordinary admission continues within it, and no loss report is required; once `premise < S(d) + R_flight(d)` the provider reports a typed containment-loss, backing-loss, or external-overcommitment result and admits no new work conflicting with the shortfall in that dimension. In both regimes every charge and every in-flight reservation is retained, nothing is released, revoked, reduced, or written off, no release is inferred or forced, and `Gc` is still not lowered below `S(d) + R_flight(d)`. Those states are conservative accounting, never an assurance that physical backing exists, and a typed report exists only while the process is alive and the condition is observable to it: process death emits no typed result and destroys the live in-process capabilities that would have carried one, recovery is an ordinary restart, and no claim is made that external reservations, provider-side allocations, or retained cleanup obligations outside the process necessarily vanish with it. Every `Gc <= E` or `Gc <= B` claim requires a Slice C mapping between the charged `ResourceClaim` quantity and the substrate quantity contained or reserved, satisfying all eight obligations: dimension-specific; unit-correct; monotone; coverage of every consumer of that substrate quantity, with uncharged consumers included conservatively by subtracting their use from the premise; composition, so no two `ResourceClass` dimensions and no two providers claim the same substrate quantity; subject alignment to exactly the subject `Gc` is committed for, the same process, worker, and provider; lifetime and loss, naming when the mapping begins, when it ends, and who observes it, with the charge retained and the premise unclaimed for any interval whose loss cannot be observed before a fail-stop; and `B` exclusivity, with competing unaccounted use deducted from `B` and a shared pool another party may consume from not being `B`. A dimension with no such mapping stays accounting-only as an explicit named Slice C residual, and `OpaqueDependencyResidual` does not become `E` or `B` by being given a number, because a quantity that is merely recorded is neither contained nor reserved. Bearing the accounting-only label is a claim about the accounting model alone: it does not establish P1 through P8 or P6, and accounting alone is not sufficient for final production closure. The shipped provider proves neither premise, is accounting-only in every dimension, and proves `S <= Gc` and nothing more. No control in this catalog exercises contraction, `O`, `T`, `E`, or `B`, and none may be cited as if it did;
19. P6 partition non-amplification is stated over one fixed input workload with derived releases and compared prefix-wise. It asserts no equality of outcome, no share ratio, no scheduler, no root taxonomy, no timer behavior, and no real-world claimant or Sybil identity premise, and no control for hostile-ingress progress or backpressure may be cited toward it or against it.

## 17. Evidence bundle

Each completed runtime case retains:

```text
case.json
commands.txt
processes.txt
ports.txt
inputs/
state-before.json
state-after.json
events.jsonl
stdout.log
stderr.log
resource-samples.csv
result.md
```

`result.md` states reproduced, not reproduced, blocked by harness defect, source precondition false, or fixed with repair and negative-control evidence.
