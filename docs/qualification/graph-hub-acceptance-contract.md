# Graph/Hub coordinated correction and acceptance contract

Status: implementation plan, not qualification evidence. The operator approved
this correction wave after the whole-unit evaluation. Existing PR HOLD and
independent verification/audit requirements remain in force.

This document complements `graph-hub-performance-recipe.md`; it does not make
optional scale or platform measurements mandatory. Historical passing tests
remain attributed to their original source manifests and executables.

## Ownership and shared boundaries

Only the named owner edits each file set during implementation. Interface
changes are coordinated between owners before use, without overlapping edits.

| Owner | Exclusive files, relative to repository root | Outcome |
| --- | --- | --- |
| Shannon | `crates/myownmesh-core/src/semantic/causal.rs` | Retry outcome isolation, hot/cold journal ownership, complete valid fixtures |
| Dijkstra | `crates/myownmesh-core/src/engine/{state,mod,parenting}.rs`, `crates/myownmesh-core/src/handle.rs` | Real adapter integration and narrowly scoped test facades |
| Hilbert | `crates/myownmesh-core/src/engine/routing.rs`, `crates/myownmesh-core/src/topology/{mod,tree}.rs`, `crates/myownmesh-core/src/config.rs` | Bounded accepted-parent preference and early configuration rejection |
| Karp | `crates/myownmesh-core/src/engine/{local_observation,hub,tick}.rs` | Exact observation lifecycle support and bounded discovery observations |
| Erdos | `crates/myownmesh-core/tests/hub_tree_routing.rs` | Production-shaped accepted-tree, fallback, discovery and lifecycle controls |
| Curry | `crates/myownmesh-core/tests/{closed_member_opaque_relay,closed_member_relay_production}.rs` | Relay owner replacement and exact provider conservation |
| Church | `crates/myownmesh-core/tests/{semantic_projection_compaction_differential,semantic_group_commit_controls}.rs` | Independent semantic oracle and real durable-boundary integration |
| Tarjan | `crates/myownmesh-core/src/semantic/store.rs`, `crates/myownmesh-core/src/engine/governance.rs` | Durable failure/unknown-outcome and projection recovery controls |
| Diffie | `scripts/run-graph-hub-qualification.py`, `scripts/tests/test_run_graph_hub_qualification.py` | Finite frozen-candidate execution and evidence checks |
| Payne | No writes | Independent contract and frozen-candidate verification |
| Manager | This document, final acceptance manifests/evidence, `crates/myownmesh-core/src/resource/provider.rs` | Coordination, integration, read-only provider cardinalities, serialized execution and reconciliation |
| Turing | No writes | Independent final audit after verification, at the exact pushed head |

The state/handle owner is the sole integrator of public diagnostic or failure
seams. Diagnostic snapshots expose observations, never owner tokens, mutation
authority, signed witnesses, or unrestricted state access. Failure injection
is test-only and scoped to the exact owner, not a process-global switch.

The definite durable-failure control executes SQL delta application before
failing immediately before COMMIT; merely refusing before mutation does not
prove transactional rollback. The ambiguous control commits and then loses
the result, exercising production reconciliation. Both are one-shot hooks for
the next nonempty semantic transaction; double arming is refused.

### Post-f70689e audit correction ownership

The final audit found persistent typed authority selection missing from the
153-test runtime selection. For this correction only, the following disjoint
partition supersedes the implementation table above; all other source files
remain frozen unless the manager explicitly coordinates a required interface.

| Owner | Exclusive files | Outcome |
| --- | --- | --- |
| Shannon | `crates/myownmesh-core/src/semantic/causal.rs` | Persistent typed selector semantics, bounded hot/cold ownership, projection impact and transaction controls |
| Curry | No current writes; lifecycle fixture handed off to Manager | Completed valid T/U/F1/F2 fixture and order-independent wire replay; compilation/runtime pending |
| Tarjan | `crates/myownmesh-core/tests/semantic_authority_selection_durability.rs`, `crates/myownmesh-core/src/semantic/store.rs` | Actual cold compaction/checkpoint/reopen, canonical same-snapshot provenance validation and exact state conservation |
| Manager | Acceptance contract, selector manifests, evidence, `crates/myownmesh-core/tests/semantic_projection_controls.rs`, `crates/myownmesh-core/src/engine/state.rs` | Lifecycle-oracle and bounded history-loader integration, complete target census, serialized build/runtime and outcome reconciliation |

Payne remains the independent semantic verifier; Turing remains the final
independent exact-head auditor. Neither implements this correction.

### Post-173 grouped correction ownership and decision

The complete 163-pass/10-fail run and one unchanged-library diagnostic are
reconciled before this batch. Only Shannon edits `semantic/causal.rs`, Curry
edits `tests/semantic_projection_controls.rs`, and Erdos edits
`tests/hub_tree_routing.rs` (all beneath `crates/myownmesh-core`).
Manager owns this contract, manifests and evidence. Store, runtime adapters
and the passing cold-durability fixture remain frozen.

For RoleGrant, RoleRevoke and ordinary Resolution, intrinsic no-op detection
uses the signed candidate's causal history, consistently with the existing
typed AuthorityLineageResolution rule. A concurrent fact absent from that
history cannot make a valid operation redundant. A grant already effective,
a revoke already absent, or an empty/suppressed resolution conflict in the
candidate's own history remains a refusal with no retained mutation. This
does not relax signature, lineage, cited-head, authorization, resource or
quarantine-signer checks, or change other body kinds without new evidence.

Permutation fixtures must distinguish a refused ineligible signer from an
eligible missing-dependency waiter. Preserve the exact refusal and graph
conservation. If a test exercises every first-delivery order, explicitly
model bounded redelivery of only those refused signed bodies after their
dependencies arrive; do not claim they were retained in quarantine or
that convergence happened without redelivery. Baseline and final signed
sets and fresh full projections must match. Do not drop hard schedules.

Keep obsolete payload selectors of typed-losing history as exact negative
controls. Subsequent positive membership continuation uses a genuinely new
admission after regrant, never resurrection of the losing membership row.
Stale-resolution controls must first prove a real current conflict.

HubTree no-shortcut assertions distinguish discovery-only Sighted entries
from authenticated native links. Use the fixed five-node adjacency at both
payload boundaries: exact positive current-worker witnesses for the four
intended edges, and no authenticated peer or selected native worker for
every other pair. Drop observation witnesses before terminal baselines.

### Post-174 historical-membership closure

The 168-pass/six-fail candidate and unchanged-library diagnostic reproduce
old, typed-rejected membership M as the visible value both during a later
Q/R authority fork and after a later typed selector chooses R. This is not
permission for M to return, or for the new Q to remain effective when Q loses.
The following exclusive partition supersedes the prior batch during this
correction: Shannon owns only `semantic/causal.rs`; Curry owns only
`tests/semantic_projection_controls.rs`; Tarjan owns only
`tests/semantic_authority_selection_durability.rs` (all under
`crates/myownmesh-core`). Manager owns this contract, manifests and evidence.
Other production files require an explicitly coordinated interface change.

Typed-selector exclusions must compose across subsequent unresolved forks
and subsequent selected continuations. Ordinary causal ancestry through a
selector's losing-parent edge cannot restore that loser's authority. The
absence of one public selected branch during an unresolved fork does not
erase earlier applicable restrictions. Genuinely new post-selector acts stay
eligible at their own valid stages; this is not a blanket post-selector denial.

Raw maximal cell heads must remove indirectly dominated hidden heads, even
when production authoring cites only the currently projected heads. Preserve
the same signed bodies. Keep the ordinary direct-head fast path and use
bounded exceptional ancestry evidence without an unconditional whole-history
scan or full graph rebuild. Preflight pricing, sparse original index/projection
ownership, delta application, rollback/Drop, cold rebuild and canonical
checkpoint validation must implement the same corrected invariants.

Finite controls use M/V/S/N/Q/R/T2/U2 and later valid continuations. Check
before Q, after Q, after R, after T2 and after U2/future: M remains excluded;
Q is effective only before its own fork/losing selection; raw ancestry heads
are truly maximal; and projection, roots, retained bodies and authority agree.
Use an independent traversal of signed dependencies for expected raw heads:
`Projection::from_graph` alone also reads maintained indexes. Cover the same
mutations through single/aggregate commit, explicit rollback/Drop and actual
cold compaction/checkpoint/reopen. Keep existing permutation counts and
distinct-owner/redundant-ancestor discriminators.

The four remaining fixture corrections preserve ineligible-signer refusal,
intrinsic no-op refusal, genuine malformed/stale-resolution checks and both
peers' Closed-session prerequisites. They do not weaken production authority
or turn suppressed history into a positive fixture. No grant/cap, wire/schema,
optional platform/scale or release expansion is part of this correction.

### Post-175 selector-winner impact and measured workload envelope

The latest full matrix passed 173/175 cells. The final winner-of-competing-
selectors control exposes correct authority/relevance and full reduction but
stale cached Role/ Membership cells. A typed selector's immediate predecessors
can themselves be cell-less selectors: walking only their reverse descendants
omits the underlying branch ancestors. For this exceptional transition, the
impact set must include all affected subject participants and descendants,
including borrowed staged canonical participants. Use the same complete set
for sparse preimages, incremental/deferred updates and emitted projection
deltas. Do not repair only the final cache or change the authority predicate.

Preserve the exact S/alternative/winner signed transcript. Assert the prior
conflict and final V role/membership values, unchanged unrelated cells, M's
continued exclusion, and the losing selector's exclusion from relevant
contexts. Cover both selector orders, direct admission, single journal
commit/rollback/Drop and aggregate in-batch selectors from the original fork,
with actual delta entries and existing bounded hot/cold history controls.
Shannon owns only `semantic/causal.rs` for this correction. All integration
test files remain frozen; manager owns manifest, contract and evidence.

The separate gate160 timeout has now been classified by an unchanged-library
diagnostic: every one of its 720 signed arrival orders and all assertions
completed successfully in 149.84 seconds. Its 120-second limit was insufficient
for this finite debug workload. Set only gate160 to a finite 240-second envelope
(about 90 seconds above the measured complete run); keep all 720 schedules,
assertions, build settings, other cell deadlines and resource caps unchanged.
No fixture optimization, automatic retry or performance claim follows from
this measurement. The diagnostic does not retroactively pass the original
timed-out cell; the next frozen whole matrix must pass the revised manifest.

## Semantic outcome and ownership contract

| Boundary | Required result |
| --- | --- |
| Canonical/signature/context or unknown-signer preflight refusal | No retained input or lasting hydration side effects |
| Eligible signer with missing dependencies | Bounded quarantine of the exact signed body and missing set |
| Dependency-complete authorized input | Exact admission and indexed transitive retry under the shared allowance |
| Retried dependent with a definitive candidate-relative authorization rejection | No authorization bypass and no veto over an otherwise valid parent; exact dependent removal/refusal attribution |
| Capacity/internal failure | Preserve the documented transactional boundary and exact rollback; do not disguise it as semantic rejection |
| Exact replay, including hydrated history | No durable mutation; commit, explicit rollback and Drop release their owned transient state |
| Definite durable failure | Restore graph, indexes, counters, provisional custody and projection to the corresponding baseline |
| Commit outcome unknown | Reconcile exact durable identities before further publication; never blindly retry the write |
| Durable success followed by projection-cache save failure | Canonical history remains authoritative; recovery converges without misleading success/refusal or stale authority |

Keep the existing separate delta limits: rows <= B+1, promoted <= B, and
removed <= B. They are not a combined changed-row theorem. Shared retry
allowance includes terminal removals and transitive frontiers. Refunded
failed-input allowance is not an all-CPU bound. Preparatory indexed closure
work remains separately bounded by retained policy.

Fixture construction must separate generic support parents from each
subject's AuthorityUse predecessors. Validate the complete legitimate graph
before staging the intentional out-of-order schedule. Intentionally invalid
rows must state the exact invalid property and preserve unrelated accounting.
Export ordering is not an admission schedule; replay actual exported bodies
against the recorded input transcript and retain the independent oracle.

Typed AuthorityLineage selection persists through regrant and every later
ordinary authority use. A unique causally maximal typed selector governs its
complete relevant ancestry; unresolved or incomparable selectors must not
silently select a winner. Ordinary payload-local Resolution does not select
authority lineage. Preserve selected-loser suppression, sparse projection
preimages/deltas and full-recomputation equality through T/U/F1/F2, both branch
arrival orders, and genuine cold retirement/checkpoint/reopen. Wire decoding
alone is not durable reopen. A fix may not retain unbounded whole history or
rebuild the whole projection merely to conceal missing incremental impacts.

Cold selector provenance is a bounded derived cache, not a new authority
source. Retained live subject/fact rows carry the relevant typed-selector
context and required canonical reachability, with actual signed selector and
selected-branch witnesses. Every retained record is charged to existing index
and checkpoint policy and pruned with its live owner. Rebuild and journal
rollback preserve these records without discarding a cold summary while
replaying earlier rows. Being an ancestor of a frontier through a losing
selector edge is not proof of a valid post-selector continuation.

On restore, the store validates both soundness and required coverage against
canonical signed rows/dependencies in the same SQLite snapshot. Unkeyed cache
hashes cannot establish selector authority. Missing, obsolete or forged
provenance takes the existing validating replay fallback; unconditional
checkpoint rejection is not a substitute for correct live cold behavior.
This exceptional validation has bounded work under existing policy, not a
constant-time or performance-improvement claim.

Runtime single and aggregate admission must request the required bounded
canonical ancestry for a new typed-selector context even when its immediate
parents are resident. Merge those roots into the existing history read under
the publication/owner fence; in-batch facts remain journal-overlay inputs,
not already-admitted store roots. Include selectors awakened from quarantine.
Preserve ordinary missing-dependency quarantine semantics: strict admitted
root completeness is a checkpoint-validation requirement, not a blanket
rejection of unknown ingress parents.

## Tree, observation and lifecycle contract

- An accepted parent is a current, unexpired, exact-owner relationship, not
  merely a connected or configured candidate. It enters preferred routing
  without overriding direct delivery or separately authorized alternatives.
- Cover both directions of the four-hop tree. Do not assume a routing root
  knows a remote leaf's accepted fallback parent without an actual bounded
  source of that information. Resolve any necessary route-state interface
  explicitly; do not conceal the gap with a specially lucky fixture.
- Distinguish absent preferred hubs from connected hubs that refuse parent
  slots. Connected-candidate ranking already supports the former. The latter
  must not suppress the accepted lower-ranked parent's preferred service.
- No warm-backup wire expansion, unlimited fanout, blanket parent permission
  veto, or retry after an ambiguous application write is introduced.
- Discovery continues with a healthy parent, advances beyond the first page,
  has independent minimum spacing, and cannot recurse through immediate
  replies. Bound output and retained state; report registry-scan CPU honestly.
- Observation outcomes come from actual operations and are advisory. Exact
  record/operation generations fence replacement and late completion. A
  diagnostic refusal never changes ordinary networking or semantic authority.
- Terminal acknowledgements are not assumed to be final lease-drop fences.
  Compare provider baselines at equivalent ownership lifetimes, separately
  from connector reports, sticky measurement precision and OS observations.

## Finite acceptance matrix

Every row needs exact selector names and positive expected counts in the final
machine-readable manifest. A missing required selector is a missing gate, not
a zero-test success. Newly added selectors are recorded after source freeze.

| Cell | Required evidence |
| --- | --- |
| Fixture preconditions | Valid authority/dependency schedules, canonical identities/configuration, matching exact finite grants, and explicit intended negative cases before costly setup |
| Causal transaction | Valid and unauthorized dependent cases; single/aggregate transitive chains; mixed removals/promotions; B/N+1 refusal; hot/cold replay, commit, rollback and Drop with full-state equality |
| Semantic differential | Whole target: exact export integrity, authority/projection/state commitments, valid schedules, negative schedules, compaction and reopen |
| Persistent authority selection | Whole nonoptional `semantic_projection_controls` target, including `authority_lineage_selection_round_trips_and_regrant_is_future_only`, plus exact new causal and actual durable-lifecycle controls; full projection oracle at every meaningful continuation boundary |
| Durable boundary | Whole group target plus nonempty real precommit failure, commit ambiguity/reconciliation and projection-save recovery controls |
| Proof delivery | Recipe-required pending-history and restart selectors, exact fact/body/link sets and footprint bounds |
| Observation/Trickle/Hub | Component policy, clock, generation, pressure, lifecycle, cursor and rate controls |
| Accepted HubTree | Real authenticated registration, capacity refusal, exact four-hop payload/hops, accepted lower-ranked fallback, owner replacement and expiry |
| Exploration/non-veto | Healthy-parent paged discovery and spacing; independent direct/alternate route success; genuine no-route; no ambiguous resend |
| Relay/identity | Both real relay targets, identity controls, actual owner replacement, unchanged payload/refusal checks and provider conservation |
| Compatibility | Whole workspace/all-target build; existing legacy Hubs/tree planners, topology routing, daemon registry and exact transport-retirement controls |

## Execution and correction discipline

1. Finish the coordinated source wave and cheap fixture precondition controls.
   Check all cross-file interfaces together. Collect compile/setup corrections
   as one integration batch; a failure before exercising the intended boundary
   supplies no production behavior evidence.
2. Freeze the complete source/test/document manifest. Run one serialized
   `cargo build --locked --workspace --all-targets --tests --features transport-lab --keep-going`
   build, recording its executable artifacts and hashes. This compiles test
   harnesses without executing them and collects errors from independent
   targets instead of stopping at the first target. Set `CARGO_BUILD_JOBS=1`
   on this Windows host to bound compiler concurrency. Any compile failure
   still means zero runtime evidence; all targets must compile before runtime.
3. Validate the exact finite selector manifest against those binaries. Execute
   immutable binaries sequentially under the shared worktree resource lease.
   Record source/binary hashes before and after, phase, exit, counts and logs.
4. Continue independent runtime cells after a test failure; do not edit or
   rebuild between them. Stop on provenance corruption, unknown execution
   outcome, or an unsafe shared-state condition. Never automatically retry.
5. Review the complete failure set once. Each next correction must identify
   the violated contract and predicted change in evidence, not merely change
   an assertion. Repeated setup failure calls for revisiting the fixture as a
   whole, not extending the same diagnostic loop.
6. Only verified evidence from one candidate advances to publication and the
   independent exact-pushed-head audit. Then preserve HOLD for operator review.

The 1k/10k scale selectors remain optional matched-baseline measurements.
No native 5,000-process, million-row, NAT/TURN, OS-memory or hosted-green claim
follows from this local correctness matrix.
