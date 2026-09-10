# Graph and hub performance qualification recipe

This is the bounded qualification recipe for the current V4 semantic/relay
unit. It is an evidence recipe, not a release claim. Run the same commands,
profile, home isolation, and serialized-test setting for baseline and
candidate. Record, before each run:

- source revision, complete dirty-file manifest, and the source-tree hash;
- executable path and SHA-256 (and the peer executable SHA-256 for a two-daemon
  run);
- OS, architecture, CPU/RAM, filesystem, Rust/SQLite versions, feature set,
  timezone, and UTC start/end times; and
- the exact command, selector, profile, policy limits, and artifact directory.

Execute the command examples through the durable runner, with `--locked`,
`--features transport-lab`, and `--test-threads=1` added where absent below.
Retain the full libtest selector and require a positive executed-test count;
zero matching tests is not a pass. The examples describe intended gates, not
results. The first integrated compilation (`d8d9b418`) failed before any test
ran; its retained diagnostic artifact is
`target/qualification-evidence/graph-hub-compile-d8d9b418.json`.

A same-binary baseline is useful for calibrating instrumentation only. It is
not candidate evidence. A candidate comparison requires different recorded
source and executable identities. Keep semantic, topology, relay, and process
artifacts separate; do not merge their counters or slopes.

## 1. Semantic correctness and cost

Run these deterministic controls first (one serialized Cargo invocation per
test binary in the manager's runner):

```text
cargo test -p myownmesh-core --lib indexed_projection_matches_reference_and_rollback_restores_indexes -- --nocapture
cargo test -p myownmesh-core --lib rebuild_reconciles_loader_mutated_scalar_accounting -- --nocapture
cargo test -p myownmesh-core --lib authority_impact_stays_sparse_and_matches_full_projection -- --nocapture
cargo test -p myownmesh-core --lib cold_history_retirement_keeps_constant_live_state_and_hydrates_exact_dependencies -- --nocapture
cargo test -p myownmesh-core --test semantic_projection_compaction_differential --features transport-lab semantic_project_and_incremental_compaction_converge -- --exact --nocapture
cargo test -p myownmesh-core --test durable_proof_delivery_r3 r3_many_pending_deliveries_preserve_unrelated_links_and_footprints -- --exact --nocapture
cargo test -p myownmesh-core --test durable_proof_delivery_r3 r3_restart_preserves_adopted_graph_self_eviction_and_pending_receipt -- --exact --nocapture
cargo test -p myownmesh-core --lib digest_writer_preserves_json_bytes_and_propagates_serializer_errors -- --nocapture
```

The causal controls must compare a selected subject's reference projection,
authority heads, admitted/unresolved counters, dependency-edge count, and
`derived_index_bytes`/logical index residency. A rebuild or rollback must
restore every scalar and index exactly. The differential control must compare
the exported `(FactId, admitted, canonical signed-content bytes)` sequence,
state/projection commitments, selected authority heads, and conflict heads
after every fixed arrival order and after compaction/reopen. The digest-writer
control is the streaming identity check: hash the stream and canonical JSON
bytes and require byte-identical digests; serializer failure must remain an
error.

For proof history, capture the pending records before terminal-history growth.
After each history case, require the exact sorted pending row set and exact
FactId link set, while terminal rows may grow only by the deliberately seeded
records. `r3_many_pending_deliveries_preserve_unrelated_links_and_footprints`
also checks record/link counts, serialized limits, materialized signed bodies,
and durable footprint. Do not report its terminal-history count as a pending
count.

Optionally run only the representative existing scale selectors, if the
release budget makes them feasible:

```text
cargo test -p myownmesh-core --test semantic_ledger_scale --features transport-lab semantic_ledger_scale_n_1k -- --exact --ignored --nocapture
cargo test -p myownmesh-core --test semantic_ledger_scale --features transport-lab semantic_ledger_scale_n_10k -- --exact --ignored --nocapture
```

These selectors emit admission totals/percentiles, phase counters, provider
baselines, SQLite main/WAL/SHM/journal peaks and post-compaction sizes, plus
optional Linux process RSS/CPU/I/O. Treat the 250k+ seeded 2,000-admission tail
as a different workload. Use the runner's matched-tail estimator only with
positive, contiguous window metadata and exact count/total reconciliation;
reject the legacy mixed seeded/unseeded marginal slope. Do not require a
1-million sweep or a six-million-factor matrix for this framework recipe.

## 2. Clock/reset and local pressure controls

The pure Trickle controls are the deterministic timing contract:

```text
cargo test -p myownmesh-core --lib policy_rejects_unbounded_or_zero_dimensions -- --nocapture
cargo test -p myownmesh-core --lib start_samples_half_open_range_and_separate_deadlines -- --nocapture
cargo test -p myownmesh-core --lib interval_doubles_and_caps_without_deadline_spin -- --nocapture
cargo test -p myownmesh-core --lib reset_budget_and_minimum_preserve_repair_need -- --nocapture
cargo test -p myownmesh-core --lib backwards_clock_and_retirement_fence_mutation -- --nocapture
cargo test -p myownmesh-core --lib local_change_resets_even_at_imin_without_using_attack_budget -- --nocapture
```

Require monotonic-clock regression, overflow, retirement, reset-budget, and
minimum-interval refusal without state mutation. For local aggregate pressure
and retirement, run
`aggregate_updates_are_bounded_and_provider_funded` and
`expiry_regression_overflow_and_stale_ticket_are_refused`; require exact
provider restoration and no stale ticket/record admission. These are
clock-free/unit controls, not network latency measurements.

## 3. Hubs and routing

The canonical hub selector defines `N` members, `H` unique hubs, redundancy
`R`, at most `(N-H)*R` spoke-hub edges plus `H*(H-1)/2` hub-tier edges, and a
bounded next-hop output. Run the existing 5,000-hub controls:

```text
cargo test -p myownmesh-core --lib large_hub_prefix_matches_reference_without_large_retained_ranking -- --nocapture
cargo test -p myownmesh-core --lib large_peer_selection_computes_one_spoke_assignment -- --nocapture
cargo test -p myownmesh-core --lib next_hops_respects_explicit_limit_without_growing_with_connected_input -- --nocapture
cargo test -p myownmesh-core --lib next_hops_are_bounded_stable_and_self_free_with_duplicate_input -- --nocapture
cargo test -p myownmesh-core --test topology_routing bounded_route_fails_over_and_preserves_exact_once_delivery -- --exact --nocapture
```

The first two controls use `H=5,000` and `R=3`, and require exactly three
canonical assignments with no large retained ranking. Record `H`, `R`, the
derived edge bound, observed selected-edge count, rendezvous work count, and
maximum serialized/next-hop output. The current controls prove reference
selection and bounded output, but do not expose one integrated 5,000-hub
edge/work counter or a 5,000-row `NetworksList` response. That is an explicit
qualification gap; do not label the two-hub `NetworksList` order control
(`v4_r3_daemon_prepared_rows_follow_the_canonical_config_order`) as a 5,000-hub
result. The registry's
`v4_r3_daemon_the_networks_work_ceiling_covers_every_fixed_field` remains the
fixed-row/work-ceiling contract.

The additional `canonical_5000_member_plan_is_symmetric_bounded_and_stable`
control instead uses 16 hubs and 4,984 spokes with redundancy 2, for 10,088
undirected edges. Do not confuse this member-count case with the 5,000-hub
ranking case above. Both describe legacy `Hubs`, whose configured hub tier
remains fully connected.

### Shallow tree and parent registration

`HubTree` is separate from legacy `Hubs`. Run the two pure topology controls:

```text
cargo test --locked -p myownmesh-core --features transport-lab --lib topology::tree::tests::five_thousand_member_primary_tree_is_bounded -- --exact --nocapture --test-threads=1
cargo test --locked -p myownmesh-core --features transport-lab --lib topology::tree::tests::five_thousand_member_planner_bounds_work_and_preserves_roster_order -- --exact --nocapture --test-threads=1
cargo test --locked -p myownmesh-core --features transport-lab --lib engine::parenting::tests:: -- --nocapture --test-threads=1
cargo test --locked -p myownmesh-core --features transport-lab --test identity_rotation_isolation -- --nocapture --test-threads=1
cargo test --locked -p myownmesh-core --features transport-lab --test hub_tree_routing hub_tree_routes_without_parent_service_and_fails_without_exit_path -- --exact --nocapture --test-threads=1
cargo test --locked -p myownmesh-core --features transport-lab --test hub_tree_routing hub_tree_real_wire_parenting_route_capacity_and_discovery -- --exact --nocapture --test-threads=1
cargo test --locked -p myownmesh-core --features transport-lab --test hub_tree_routing hub_tree_connected_full_prefix_uses_live_out_of_prefix_parent -- --exact --nocapture --test-threads=1
```

The primary-tree model has one root, 16 hubs, and 4,983 leaves: 4,999 primary
edges. These are planner/component gates, not 5,000 native processes and not
proof of runtime attachment. Separately verify that actual authenticated
registration precedes use of a retained parent relationship, capacity refusal
creates no relation,
the captured remote parent's replacement invalidates pending work, and
expired replies cannot adopt even before a maintenance tick. The four-hop
leaf-to-hub-to-root-to-hub-to-leaf route must use the existing authenticated
send/receive path. Configuring a routing root conveys no semantic authority.

Storm/exploration gates must distinguish count from rate: bounded pages and
one outstanding request alone do not prevent an immediate-reply loop. Prove
independent minimum query spacing plus jitter, no response-triggered reset of
that spacing, finite aggregate inbound reply work, no recursive forwarding,
and continued scheduled queries with a healthy parent. A bounded recipient
page must advance through the eligible identity set, not rotate an already
truncated first page. Failed sends must not pin that cursor.

Generic routed application admission remains separate from parent-slot
admission: it requires the existing signed context/origin/hop validation,
membership policy, exact promoted application session, forwarding policy,
and finite routing/provider limits. Absence of a parent relation must not
silently add a new authorization veto to that existing service.

Non-veto acceptance is separate from the preferred-edge count. Exercise a
refusing/full parent with a usable direct destination, a usable alternative
hub, and an independently permitted routed path. Each must remain available
without granting the failed parent control over the alternative's admission.
Also exercise the genuine dead-end case with no other route. Require exact
owner/session checks and finite per-attempt resource/rate limits in every
case; no automatic retry after an ambiguous application write. Compare the
actual accepted parent with the planner's preferred candidates, and show that
paced fallback can reach an eligible candidate outside a failed preferred
prefix. A pure 5,000-member selector test does not establish these properties.

The `hub_tree_routes_without_parent_service_and_fails_without_exit_path`
control uses three live peers, an absent root and
preferred hub, one lower-ranked connected hub, and zero parent child slots.
It checks received routed and direct payloads before removing every source
exit and requiring a pre-send no-route failure. It is not a successful parent
registration, four-hop primary-tree, discovery-convergence, or 5,000-process
test. Its live-session resource report is not a full provider/OS-memory audit.

For adapter funding, record a disjoint root/backing, child-scope, pending, and
relation-node partition. Planning a full relation budget is not permission to
reserve that whole budget and charge every inserted relation again. Require
refusal before the corresponding retained allocation, exact one-node growth,
duplicate no-growth, and final-owner baseline restoration. These checks do
not substitute for exact-generation terminal cleanup or OS-memory evidence.

Until the runtime adapter and these gates execute successfully, report
`HubTree runtime qualification pending`, not a functional tree PASS.
The current bounded local executions, including the two additional real-wire
controls above, are recorded in [the local evidence ledger](graph-hub-local-evidence.md).
Their PASS is not shipped-process, field, OS-memory or final-audit qualification.

`bounded_route_fails_over_and_preserves_exact_once_delivery` is the real
topology path: retain route choice, fallback, exact-once delivery, and live
resource baseline separately from hub-selector CPU work.

## 4. Local aggregate and real relay evidence

Use the existing production-shaped Closed relay controls after the semantic
and hub controls:

```text
cargo test -p myownmesh-core --test closed_member_relay_production closed_members_relay_through_production_local_broker -- --exact --nocapture
cargo test -p myownmesh-core --test closed_member_opaque_relay closed_members_exchange_opaque_payloads_only_through_relay -- --exact --nocapture
```

Require the authenticated Closed projection, exact route/identity and
generation evidence, Open/Accept/Close terminal evidence, first opaque payload,
and provider/resource baseline. A refusal must occur before retained relay
state grows. These are qualification regressions, not a substitute for the
hub 5,000-node gap above.

Report two accounting planes independently:

1. **Canonical logical/provider:** semantic counters and index bytes, causal
   edges, proof rows/links, provider `ResourceClaim`/reservation/scope
   snapshots, and exact baseline-to-terminal deltas.
2. **OS/disk observation:** SQLite main/WAL/SHM/journal files, process RSS/HWM,
   CPU and I/O where supported, and filesystem/disk limits.

Never infer OS memory or disk capacity from a provider claim, and never infer
provider conservation from a file-size sample. Preserve failed-run stdout,
stderr, JSON metrics, source identity, and terminal status; an unavailable
platform counter is `null`/unavailable, not zero. The resulting report must
list every selector run, its artifact path and binary SHA, the exact baseline
pairing, the H/R gap status, and any refusal or unsupported measurement.
