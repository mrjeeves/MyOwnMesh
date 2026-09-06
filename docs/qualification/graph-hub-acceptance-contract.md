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
