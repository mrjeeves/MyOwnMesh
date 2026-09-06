# Graph / Hub candidate: local verification record

This is a **local candidate verification record**, not release approval or a
final exact-head audit. The working branch is
`macro/02-authority-durability-relay`, based on
`bf08d2c378a5fb3c20a8099488ff13cac8a16a78`. PR #7 remains open, draft, unmerged,
and on HOLD. Independent final audit and pushed-head evidence are pending.

## Current local result: 153 selections, 153 pass / 0 fail

Run `9cf2e327-8ff4-4211-a08f-1953edbbaf8f` completed successfully at
2026-09-06 07:47:09 UTC. The locked, single-job workspace/all-target test build
passed in 510.235 seconds with `build-finished: success`, producing 46 test
executables. All 153 exact selections ran one test each and passed, with zero
failed or ignored tests. This is an all-target compilation and a selected
153-test runtime matrix, not an exhaustive execution of every compiled test.

Report: `target/qualification-evidence/graph-hub-wave1-full-matrix-authority-lifetime-compile-corrected.json`
(1509990 bytes; SHA256
`FF70A137DE944C796BBB8D30381293A365D28AB3A739D7B8D52B8D86C3B7511D`).
Harness source identity:
`2faf97020b3a10d657d64622b69e09b60f542a52e02b093cd537a4ef26595b38`.
All 307 source checkpoints, all 611 recorded source files, and all 46 current
executables matched their recorded identities. Before/after cell binary
hashes matched; all retained streams were complete and untruncated, with no
callback errors. The build used the retained cache and `CARGO_BUILD_JOBS=1`;
no stack override was used. These timings are execution provenance, not a
baseline/candidate performance comparison.

| Executed boundary | Current result |
| --- | --- |
| Causal transaction and projection | 49 causal selectors pass, including four transitive promotions and full rollback/Drop (044), the same-body ready-leaf full oracle (149), and deep ordinary authority-fork invalidation in both orders (150). |
| Durable semantics | Whole differential target 4/4 and group-commit target 7/7 pass, including actual nonempty pre-COMMIT rollback and committed-but-unknown outcome reconciliation/reopen. Governance persistence controls also pass. |
| Proof history | Both recipe selectors pass with exact pending bodies/links/footprints and restart behavior. Their telemetry does not expose a provider ledger; no provider conservation claim follows from those selectors. |
| Accepted HubTree | Real bidirectional four-hop routing, capacity refusal, connected/full preferred-prefix fallback, healthy-parent continuation pages, live-owner replacement, finite accepted expiry and paced reattachment pass (140/141). |
| Relay and terminal custody | Both real relay targets pass, including stale W0 typed refusal, current-owner payloads, shutdown and the stated provider/resource-report baselines. Preallocation refusal and admitted-install shutdown controls pass (147/148). |
| Parenting components | Exact-key expiry/reacceptance, bounded cleanup and child-local backup capacity ownership pass (151-153). No production warm-backup wire attachment is claimed. |

Payne independently verified the complete report/source/binary/selector custody
and semantic runtime evidence (assignment
`manager:af656064-04c1-4b74-9dfb-3f47da657004`): bounded PASS.
Church independently verified parenting, HubTree, relay and shutdown evidence
(assignment `manager:e3ce1571-197b-4b23-802e-59fab11ed1ce`): bounded PASS.
Neither implemented the surfaces in their verification lane or reran tests.
The provider task view remains stale and rejected same-ID completion updates;
these are actual delivered outcomes, not a claim that its board was repaired.

The tested tree was still a dirty candidate on the recorded base commit.
Publication-stage verification must bind it to the exact pushed working-branch
head, followed by Turing's separate independent audit. PR draft/HOLD remains.
This is local Windows debug `transport-lab` evidence, not shipped-process,
field/NAT/TURN, hosted-green, 5,000-process, OS-memory or speedup qualification.
The E2E parenting snapshot generation is a table allocation cursor; exact
accepted remote relation generation is covered only by component controls.
Directory scans remain O(N), and transactional retry allowance is not a total
CPU bound. The sections below preserve superseded results and diagnoses;
their pending/failing statements are historical, not the current disposition.

## Previous verification attempt: 153-selection build failed, zero runtime tests

Run `e200abec-3263-43d1-a9ff-8de1222796c2` completed at
2026-09-06 07:25:09 UTC. The keep-going all-target compiler census exited 101
after 939.163 seconds with two E0308 errors in the new parent expiry control.
Both calls passed an existing `ParentDeviceKey` through a conversion accepting
`DeviceId`. No runtime cell ran; prior source-review assurances did not establish
compiler acceptance. The complete compiler streams (375683 stdout / 26963
stderr bytes) were untruncated, callback errors were empty, and before/after
source custody matched `5b76980c0f1ac54819542a4459bee5b983bf5fef035e0dfcc6f9534f6629dca2`.

Report: `target/qualification-evidence/graph-hub-wave1-full-matrix-authority-lifetime.json`
(SHA256 `C924C104F865094C6315462BBD9DD52BD8E4C1B0FABE71DA5FEDC3C8331818D2`).
Manager integration removes only those two redundant conversion calls, preserving
the actual child key, before/exact-expiry assertions, provider checks and all
production behavior. The next gate retains the same 153 selectors, single-job
compiler, build/runtime bounds and default stack, using this attempt's build
cache. The corrected result is recorded above; this failed attempt contributes
zero runtime evidence.

## Previous whole-candidate result: 149 selections, 146 pass / 3 fail

Run `7a9534ee-6a14-47d8-83d6-09d19e7b5e32` completed at
2026-09-06 06:31:33 UTC. The locked single-job workspace/all-target build
passed in 1237.468 seconds and emitted all 46 test executables. All 149 exact
selections ran one test each: 146 passed and three failed. All 299 source
checkpoints and all before/after executable hashes matched. Every cell exited;
all retained streams are complete and untruncated. No stack override was used.
This is a failed candidate, not acceptance or independent final audit.

Report: `target/qualification-evidence/graph-hub-wave1-full-matrix-seed-ownership.json`
(SHA256 `E4D22070AFCDD963B7A22C4377524F9EE6F879673850B34DCEEACBF2239755CB`).
Harness source identity:
`071a3ea339eb2620e6211151ced532c7f599e68c25d180f9cbb1e9d72407a030`.

| Cell | Executed result and reconciled cause |
| --- | --- |
| 149 | Valid same-body leaf/trigger siblings expose an ordinary authority-fork projection invalidation defect. Both incremental insertion orders retain the earlier sibling's role cell, although both branches cease to be authoritative. Independent source review shows impact discovery traverses prior branch cells only for explicit resolution. The full `Projection::from_graph` oracle, not the reference graph's incremental cache, must establish the parent-only final projection. Leaf rollback/Drop assertions below the mismatch were not reached. |
| 137 | The spawned opaque scenario no longer overflows its stack and reaches real W1 replacement after links and payload controls. The retained log explicitly reports `ClosedRelay(Carrier)` for stale W0 data, so the exact `Owner` assertion fails. Production send erases the stale-owner refusal into carrier failure; no stale send success or authority bypass is demonstrated. |
| 140 | Real four-hop/discovery control passes its paired continuation-page checks, then fails accepted-parent expiry. Both accepted relation paths assign `u64::MAX`; the lab snapshot already filters by current time, but accepted age is effectively disabled. Pending-only maintenance and the raw primary retry guard must be reconciled with finite accepted lifetime. |

Cell044 now passes exact four transitive promotions, five admitted rows,
full-reference projection/commitment and explicit rollback/Drop. Production
relay cell138 passes payload, owner replacement, shutdown and provider baselines.
Lower-ranked fallback cell141 and the corrected exact terminal storage/pump
baseline cell148 pass. The whole differential target passes 4/4; group-commit
controls pass 7/7 and durable proof controls pass 2/2. These are this candidate's
executed results, not inherited evidence from another binary.

The complete three-failure review releases one disjoint production correction
wave: Shannon owns causal impact/preimages and true full-oracle controls;
Dijkstra owns parenting/state/handle and its real-wire test for finite relation
lifetime, cleanup and paced reattachment; Curry owns Closed Relay send taxonomy
and its opaque test. Existing semantic authority, generic-route non-veto,
typed refusal, resource bounds and default-stack requirements remain unchanged.
Manager owns integration/evidence and serialized whole-matrix verification.
No further run starts until all three coherent implementations are frozen.
Independent verification and Turing's exact pushed-head audit remain pending.

Integration review of the first causal handoff (`E89CBD39...`) found that
starting only at maximal authority heads still misses earlier facts on an
invalidated branch. A valid A->B->C chain followed by sibling D from A leaves
B outside that impact set. Payne independently confirmed the missing cell,
preimage and delta coverage before another build; the same causal assignment
is correcting the complete branch and the original ready-leaf full oracle.
Church's separate finite-parent source review found a wrong-key expiry test
and child-side backup relations incorrectly counted as accepted children.
The same owner is correcting the exact-key control and both counter ownership
boundaries, with a focused component regression. This does not add production
backup attachment: the runtime adapter still emits Primary only. The real-wire
snapshot generation proves registration progress; exact accepted relation
generation is a separate component assertion.
The assembled correction uses the complete indexed subject-participant set
on the exceptional fork path; staged cold rows may conservatively trigger
that bounded sweep and are not claimed to be maximal heads. Manager integration
also gives the original ready-leaf control a fresh full oracle on both admission
paths, explicit parent-only projection and exact retained fact IDs. The parenting
owner corrected the actual child-key expiry probe and both backup counter
boundaries. Their frozen review closures remain distinct from runtime proof.
The prepared next manifest retains all 149 selections and adds four exact
fork/accepted-expiry/backup-ownership controls (153 total). None has corrected-
candidate runtime evidence yet; the previous 146/149 result above remains the
latest execution. After scoped formatting passed, Payne verified the two causal
source/control closures at `7C71ECCA...`; Church verified the exact-key expiry
and backup ownership closures at `3E43507E...`. Both reviews were read-only and
explicitly excluded compiler/runtime or whole-unit acceptance. The next gate
is one locked single-job all-target build followed by all 153 exact selections
without intervening edits, using the unchanged 1,800-second build envelope and
existing per-cell runtime limits.

## Previous whole-candidate result: 148 selections, 144 pass / 4 fail

At this previous checkpoint, the five-owner correction batch was frozen for verification,
not qualified. Manager integration corrected the new wrapper's Result return,
preserved the reused trigger value, gave the ready leaf an explicit fresh-target
authority witness with same-body reference admission, and reused equal-cost
signature corruption. The seed-leaf rollback/Drop control is a separate exact
selector so it executes independently of the larger frontier test. The next
manifest has 149 cells, retaining every previous selection and runtime bound.

Run `aac2802c-a5e3-4b74-bc70-b24f5784b4d8` completed at
2026-09-06 05:48:58 UTC. The warm-cache, locked single-job all-target build
passed in 77.710 seconds and emitted all 46 test executables. All 148 exact
selections started one test each; 144 passed and four failed. All 297 source
checkpoints matched and all before/after binary hashes matched; every cell
terminated and all retained streams were untruncated. This remains a failing
candidate, not release qualification.

Report: `target/qualification-evidence/graph-hub-wave1-full-matrix-build-budget.json`
(SHA256 `C7B79F48D27931CAEFA94D4BBC3BE28587E1DB58F8996C3E313A4950F0168CE2`).
Harness source identity:
`3c57219fbe231eafe581f62ce94a52350dea8cd53a2c450355183abc91a87eac`.

| Cell | Current result and evidence ceiling |
| --- | --- |
| 044 | Valid same-body reference and B1 rollback checks passed, but B4 normalized promotions were two instead of four. Independent source review found the aggregate baseline omits initial-ready seeds themselves, affecting both normalized promotion records and outer rollback. The later B4 rollback assertion was not reached. |
| 137 | Opaque relay still overflows its stack at the first real link. Changing Tokio scheduler flavor did not move the stack-pinned root test future off the libtest thread. No new global stack setting is accepted. |
| 140 | Real tree control reached discovery assertions, then compared latest-bound and latest-accepted cursor fields from potentially different operations. Receiver checks remain operation-correlated; this diagnostic comparison was not. |
| 148 | Real post-construction install/pump shutdown joined and released callbacks. The baseline erroneously retained the pre-existing semantic storage lease: final usage correctly lost StorageBytes 837779344, one reservation bookkeeping residual and one reservation, with all other dimensions unchanged. |

Production relay cell138 now passes, including all three network shutdowns
and exact provider baselines (1.029 seconds). Its identity-tagged shutdown
logs reach zero peers, mutations, tasks, pumps and pending pump registrations.
The connected-full-prefix/lower-parent cell141 and root terminal baseline also
pass (2.222 seconds). Pre-allocation shutdown refusal cell147 passes. These
results do not retroactively prove the exact await that caused the earlier
uninstrumented timeout.

The complete grouped diagnosis releases five disjoint correction owners:
Shannon for causal seed ownership and lifetime controls; Curry for a small
opaque-test wrapper with a heap-owned spawned scenario; Dijkstra for the
exact semantic-storage terminal baseline; Karp for same-accepted-operation
discovery metadata; Erdos for its real-wire assertions. The discovery proof
retains actual continuation-page progress rather than deleting the cursor
requirement. Manager integration/verification remains in progress, with no
new run until all owners freeze. Independent final verification and Turing's
exact pushed-head audit remain pending.

## Previous grouped build deadline (superseded)

Run `5c3e02e1-c491-4397-8f01-7a28f14942f8` did **not** reach runtime.
The build hit its 1,200-second envelope after 1,200.458 seconds; there were
zero test cells, no parsed compiler errors, no Cargo JSON/callback errors,
and both retained streams were complete (365,756 stdout / 30,615 stderr bytes).
Cargo emitted 38 test executables versus 46 in the previous successful build.
New executables were still arriving through 05:34:27 UTC, three seconds before
termination at 05:34:30; this is evidence of ongoing build progress, not a
demonstrated compiler stall. The before/after source hash stayed
`7b77b522082d6735b60fbe8620fd0df47fc5fc6b996dba47b591326182a7a1ee`.
The complete report is
`target/qualification-evidence/graph-hub-wave1-full-matrix-grouped-corrected.json`
(SHA256 `A0D0FC60A6665DADE34DD2BEDA32092DA96A0B05F036D9C271DB28917CA51946`).
No Cargo/rustc/link process remained at the manager's terminal inspection.
Diffie's independent read-only review confirmed known process-tree termination,
completed readers, matching source custody, and continued artifact progress.
The 38 test executables are an exact subset of the previous 46, with eight test
executables and two examples left unfinished. The next whole-matrix gate changes
only the build envelope from 1,200 to 1,800 seconds, retaining the existing warm
cache from this same-source attempt, single-job compilation, all 148 selectors,
default stack, runtime timeouts and assertions. This is not cold-build performance
evidence. No all-target or runtime acceptance follows until the complete gate
finishes successfully.

The four post-matrix implementation lanes are frozen: Shannon corrected the
complete causal frontier witness schedule and added same-body reference
admission; Erdos refreshed post-attachment observations and added exact-family
teardown diagnostics; Curry priced six overlapping native endpoints in both
relay fixtures and matched their multi-thread runtimes; Dijkstra retained one
shutdown mutation permit across production construction/install/pump handoff,
including speculative offers. None of these corrections has runtime proof yet.

Manager integration adds a test-only pump-count accessor, corrects the shutdown
test's unit-return handling, and puts local identity/custody counts into the
actual shutdown log text (structured GUI details alone are not retained console
evidence). The two exact shutdown selectors extend the manifest to 148 cells;
the native post-construction selector is explicitly selected with `--ignored`.
It exercises the production install/pump seam, not a deterministic pause inside
the full asynchronous `ensure_peer_session` allocation. The root-family
teardown residual remains unresolved until execution identifies its custody.

Manager-owned coordination/integration/verification remains in progress. The
next gate is one scoped format followed by one locked single-job all-target
build and the whole frozen 148-cell matrix, with default stack settings and no
edits between cells. Independent verification and Turing's exact pushed-head
audit remain pending. The provider task view is stale, and same-ID assignment
completion updates have been refused as not manager-owned; those refusals are
not successful task-board reconciliation.

## Previous whole-candidate result: 2026-09-06

Qualification remains **BLOCKED**. Run
`665488b3-ad5e-430a-a5d8-0ab02004523a` completed the locked, single-job,
workspace/all-target test-harness build successfully in 32.486 seconds, then
attempted all 146 manifest selections without edits between them. There were
139 passing cells and seven failing cells, including two zero-match selections.
This is not a full workspace runtime sweep or release approval.

The retained report is
`target/qualification-evidence/graph-hub-wave1-full-matrix-import-corrected.json`,
SHA256 `0247B56492399A57B5C33B19261EC4851E7D451B50A1AC85ACC22AD229E4E67A`.
Its complete source manifest is
`e0b7eb83d5019344287a40744034d81cb64ee21a817a28169042d49cf7571279`.
All 293 source checkpoints matched, all executed binary before/after hashes
matched, all cells exited, and no cell log was truncated. The build recorded
46 executable test artifacts. The core binary SHA256 was
`D30FFA52C9EF78F150F60ADA3C44CE30AD417A4E98EFAE36D69B3194C199DC5E`.

| Failed cell | Observed failure | Qualification boundary |
| --- | --- | --- |
| 044 | Frontier fixture signing returned `InvalidAuthorityUse` | Grandchild author predecessor was not a direct parent; intended retry-boundary assertions were not reached |
| 119, 120 | Incorrect governance module paths matched zero tests | Exit zero was correctly rejected; these are manifest errors, not passing tests |
| 137 | Opaque relay test overflowed its stack during first-link setup | No replacement or shutdown evidence from this cell |
| 138 | Production relay timed out at Alice network shutdown | Lifecycle completion failed; exact internal await was not identified by this log |
| 140 | Cached H1 parenting snapshot reported zero children | Snapshot preceded leaf attachment; four-hop payload assertions were not reached |
| 141 | Root mesh terminal active items were nine instead of zero | Accepted lower-ranked parent assertions were reached, but terminal custody did not return to baseline; resource family was not printed |

Positive groups on that exact candidate include all four differential tests,
all seven group-commit tests (including real precommit rollback and ambiguous
commit reconciliation), two identity tests, two proof-delivery controls, two
daemon registry controls, the existing topology-routing control, and the
HubTree direct/alternate/non-veto control. Passing prefixes of a failed test
do not qualify its later lifecycle stages.

Supplemental runs `c1db5d26-9a5c-4cac-b312-132f91e12473` and
`4c792d34-1676-4a1e-b1c9-b5c8ba20967f` each passed exactly one governance
control using the correct `engine::governance::governance_projection_controls`
module path. Both used the same core binary, rehashed unchanged before and
after execution. They do not rewrite the original 139/7 matrix result.

Stack-only diagnostic `8b308dcd-7d13-4530-bb2f-274c0c9b2bec` used the unchanged
opaque binary with `RUST_MIN_STACK=16777216`. It crossed both real-link setup
boundaries and the preceding relay payload/max/oversize assertions, then
failed during W1 connector construction: native objects in use four, capacity
four, requested one. The fixture still declared four connector endpoints
although two original bilateral links overlap a third replacement link.
This establishes an additional workload mismatch; the enlarged stack is not
an accepted production fix. No global stack override is part of qualification.

The next coordinated correction covers legal complete fixture construction,
the six-endpoint replacement workload, current parenting observations,
precise per-mesh cleanup diagnostics, and the source-identified shutdown
admission gap around connector construction and event-pump registration.
The latter is a production race requiring deterministic verification; the
existing shutdown log does not prove that it caused the observed timeout.
Six non-root transport witnesses cannot explain the root-mesh residual in
cell 141, so that earlier explanation is rejected rather than treated as a fix.
These corrections are in progress and have no compiled/runtime verdict yet.

## Historical local results (superseded snapshots)

The records below predate the whole-candidate result above. References to a
latest run or current failure within them describe that historical snapshot,
not the present working tree or acceptance state.

All runs below used Windows x64, `transport-lab`, locked dependencies, and
serialized tests. Every reported test count is positive; the explicitly
selected ignored test actually executed. Failed predecessor runs remain
retained and are not counted as successful evidence.

| Run | Executed result | Scope |
| --- | --- | --- |
| `659fab76-c229-46b9-8cbb-c948e8cd60dc` | 74 passed, 0 failed, 0 ignored; 23.68 s | Focused semantic, local-observation, parenting, Trickle/pacer, wire, selector, routing, configuration, and pending-proof controls |
| `f289c160-f878-44a6-a7a0-819526326a47` | 1 passed; 2.03 s | Actual HubTree alternate/direct/no-exit routing discriminator |
| `5390383a-8775-493f-9e1a-e9872c667018` | 2 passed; 0.08 s | Identity replacement isolation |
| `55985386-0afe-4b1e-963c-600408bdc7c6` | 1 passed; 1.72 s | Existing authenticated routing/failover regression |
| `b3bf3203-e4ce-49f1-bd24-1777eacc4c51` | 1 passed; 0.81 s | Actual Closed production relay, bilateral payloads, three network shutdowns |
| `5f2c2556-64fc-4561-9307-2f57d9bb37be` | 1 passed, 0 ignored; 0.63 s | Explicit real same-identity replacement and exact transport-terminal facade |
| `8474e207-3730-44dc-a7d4-31f3e077b612` | 1 passed, 0 ignored; 1.05 s | Sparse authority-impact reference projection control |
| `b35124f0-a2a9-4dbd-970c-f68c6777a79b` | 1 passed, 0 ignored; 1.89 s | Durable restart preserves adopted graph, self-eviction and pending receipt |
| `b1d6ee95-b83c-4722-ac79-6cb20ea628a3` | 2 passed, 0 ignored; 0.14 s | Library registry canonical-order and fixed-field allocation controls |
| `ab187cae-132d-4a3a-8ce6-cfafa081ccb7` | 1 passed, 0 ignored; 7.64 s | Pending-proof delivery preserves unrelated links and bounded terminal-history footprints |
| `c815ab1c-0aef-41d6-b54d-b6712b7aa5f6` | 1 passed, 0 failed, 0 ignored; 0.00 s | Closed-relay fixture planner component accounting, public capacity-input sensitivity and overflow refusal |
| `71b84458-cf07-4b51-b46c-238d00fd0a3a` | 2 passed, 0 failed, 0 ignored; 1.03 s | Full opaque-relay lifecycle and synthetic live/history/precision helper controls |
| `3985b1b7-6689-4c1c-9976-375c74c840c0` | 4 passed, 0 failed, 0 ignored; 12.76 s | Whole differential target: export reconstruction/integrity, unresolved custody, and semantic projection/compaction/lifecycle convergence |
| `41649652-1169-4f4a-b875-01c61873c6c8` | **6 passed, 2 failed**, 0 ignored; 1.31 s; exit 101 | Focused causal retry controls; the gate remains failed, with both failing assertions detailed below |

The first twelve successful runs contain 88 distinct passing selectors. The
two latest runs add ten distinct positive observations, but the current causal
gate still has two failures, including a previously passing selector. These
historical observations across different compiled snapshots are not a count
of currently green tests, a full workspace suite, or a performance result.

The first five runs used build `644eea94-7a9c-4a1c-a30f-eb69818a30bc`:

- Dirty-source manifest:
  `4dd41e68e250f9d763031d60add0afd4120a5d28eff4dd2a771ec0c12a18d2a6`.
- Core test binary SHA-256:
  `4FCECF914846178083995BA1F27A0F664E74894A3D1A67C9178D5A59D045F2A6`.
- HubTree binary SHA-256:
  `B668371675C63108D4A8BBDFA0C55CF2CC0DF272BF58BD4B841935493C1CA98C`.
- Identity binary SHA-256:
  `9473D01BAB64D5501A92A5882A4F5CD9921B4BACF91ED8C1C5E8808C7AAAFE45`.
- Topology binary SHA-256:
  `B2F865E40A1DE200FE9612C0420C2809D6025A1EB50CCCEB964AFA6A406B329C`.
- Closed-relay binary SHA-256:
  `ADC298197B746BE2BBC9C9884541E039B0B185E0CF388B57539D4D8B819B11C4`.

Only the new `cfg(test)` replacement fixture was corrected afterward; no
production code changed between these two test snapshots. The replacement and
sparse authority-impact tests
used core-only build `a27af28c-2feb-4866-9cd2-e2bc7f1c1716`:

- Dirty-source manifest:
  `7ce7b1e9d44f6e8333d95beb46e7f187b0bb5b802417892aab62ec75012cb193`.
- Core test binary SHA-256:
  `758880C7799FCADD1F4232DCE0BC34628FE59B3B0D13A98D7F3A8C37CE269C52`.

The durable restart test used integration build
`3e3d41c3-f3a4-44e1-acf8-6b5a01519e19`, with source manifest
`084ab95b6f8fe8feb812d89cf92c5c9784e6f34c1d1854b53a53e9338937b534`
and durable-proof test binary SHA-256
`003B5DC8945D9E8482ADC801AD25A3435375EB4DD3CB7A283EAC4CC65258A33F`.
Its full local artifact is `graph-hub-restart-b35124f0.json` in the directory
below.

The corrected registry library run `b1d6ee95-b83c-4722-ac79-6cb20ea628a3`
used `myownmesh-18fd668ff69f37fa.exe`, SHA-256
`519D480F5C1E31468F3D9EA264A9D0227DEE53C5E955AD15DFCF5087996FDEEA`.
The pending-proof run `ab187cae-132d-4a3a-8ce6-cfafa081ccb7` used build
`dbfcad67-1192-466a-a88d-94c4666a9b39` and durable-proof binary SHA-256
`5507D22F1302BAC6B5ABED08D449CC24A3C828C8DB3DAA89318F139E7673CC42`.
Both used source manifest
`02b22b532112766ce220a8f3ecdfe18732c02d2b8a846c5634d5d6accc107632`.
Their complete local artifacts are `graph-hub-registry-b1d6ee95.json` and
`graph-hub-pending-ab187cae.json` in the directory below.

The planner test used build `73838d5b-e9d2-4e0a-9139-f14502b3c5fb`
and dirty-source manifest
`d301b159f83e639dd378e71c2d7596a57c53fb9a51d9ead93ad100bfde7a3fad`.
Its core binary SHA-256 is
`9DB9BFDCADA4E575C8457FF2AFC2032E37D0FD440501EDBB08619CF623A1AD68`.
Complete artifacts are `graph-hub-planner-build-73838d5b.json` and
`graph-hub-planner-c815ab1c.json`. The same build's two integration tests
failed as detailed below; their results are not included in the passing count.

The whole opaque-relay target passed using build
`d01cca39-0952-49a3-8c7f-b6b5d91a2236`, source manifest
`3c41e973a5ff0a5c8d804d20053d309a1edfb2a2a8228f37a78abdb47dc0622f`,
and binary SHA-256
`C0BF96EA4B7DEA77D28AB60BB4CF6096BE7B129D11FBABB62A096F92B25B1CE7`.
Both the real relay test and the synthetic helper test executed. The latter
intentionally catches failed assertions; its panic-hook stderr is expected,
and the terminal result is two passes, not a hidden test failure.
Complete artifacts are `graph-hub-fixtures-build-d01cca39.json` and
`graph-hub-opaque-71b84458.json`.

The latest retry and differential runs used build
`b114d524-9e8d-4998-b1f5-2c47a8222e81`, which passed compilation in 1m 11s
with warnings, no errors, and complete retained logs. Its dirty-source manifest is
`37622b0ecd546e5a71d0b33cd43eecb18c47f88d43f4b012f11ef3431806825d`.
The exact core binary SHA-256 is
`EBB80483FEBCD9A91AA7BC7DCC01D3F3744FB7F817E644E99CCA2C334CD2542F`;
the differential binary SHA-256 is
`DEE43965C07BC75F9E82A8D7298C032131A1D6C96225D1608B3A64391DE116A8`.
The five missing-authority stderr markers in the successful differential run
are expected negative controls; all four tests executed and passed.
Full artifacts are `graph-hub-retry-build-b114d524.json`,
`graph-hub-retry-41649652.json`, and `graph-hub-differential-3985b1b7.json`.

The manager inspected complete retained stdout/stderr and terminal state for
each result. Local raw JSON artifacts are under `target/qualification-evidence/`
as `graph-hub-components-659fab76.json`, `graph-hub-hub_tree-f289c160.json`,
`graph-hub-identity-5390383a.json`, `graph-hub-topology-55985386.json`,
`graph-hub-relay-b3bf3203.json`, `graph-hub-facade-5f2c2556.json`, and
`graph-hub-authority-8474e207.json`.
The build artifacts are `graph-hub-terminal-build-644eea94.json` and
`graph-hub-fixture-build-a27af28c.json`. These are local retained artifacts,
not yet published download links.

## What the non-veto discriminator establishes

With the configured root and preferred hub absent, a lower-ranked connected
hub with zero parent child slots carries the authenticated A → B → C payload.
The test then exercises direct A → C delivery after A–B removal, and a
pre-send no-route refusal after every source exit is removed. Payload checks
are exact-once; shutdown restores the tested live-session resource baselines.

Removal is an **injected exact transport-channel terminal notification** using
witnesses captured before closing the links. It is not proof of natural
callback-loss convergence. The separate replacement test establishes that
stale W0 cannot retire current W1, while current W1's final-channel terminal
removes the final owner/session. It completed with 40 callback observations
constructed and 40 dropped. The Closed relay completed with 62 constructed
and 62 dropped. Those counts are lifecycle evidence, not physical heap sizes.

Parent-slot admission and generic authenticated routed application admission
are distinct. Hub resource refusal does not add a global parent-relation veto
to otherwise permitted direct or alternate routes. Existing authentication,
membership, forwarding and resource limits still apply. An uncertain write
does not authorize a new fallback send.

## Historical qualification boundaries and retained limitations

The current result above supersedes the setup/runtime failures in this
historical ledger. Its accounting, performance and field-evidence limitations
remain applicable unless explicitly closed by a named current control.

- Workspace/all-target check `f6441cf5-96bb-43e3-9899-0f050d58f798` failed
  with E0063: `open_config` in `semantic_ledger_scale.rs` omitted the new
  optional `tree` field. Its complete local diagnostic artifact is
  `target/qualification-evidence/graph-hub-workspace-f6441cf5.json`.
  Adding only `tree: None` to that fixture closed the compiler error.
  Rerun `0df846ac-279a-44ec-a617-3e33874dd8ca` passed in 2.91 s, with warnings;
  its complete local artifact is `graph-hub-workspace-0df846ac.json` in the
  same directory. This is a compatibility check, not an all-target runtime pass.
- The required additional regression queue is not green:
  `fc32931a-6630-4a8b-b9d3-94c7cbfc02ff` failed with a StorageBytes grant
  refusal (requested 837,779,344; capacity 268,435,456);
  `941ab117-4e78-41bc-8f21-40ff8b8b6176` failed when the terminal-history
  fixture attempted an already-effective role grant; and
  `6c6d9efc-41c6-4f39-8100-678227eb7e6a` failed with opaque-relay
  `QueuePressure`. The exact default SQLite storage envelope replaced the stale
  fixture budget, and the terminal-history fixture now begins with a real
  Controller transition rather than repeating its seeded Member role.
  The pending-proof rerun `ab187cae-132d-4a3a-8ce6-cfafa081ccb7` passed.
  Differential rerun `b16d7222-cd0e-4fef-bb86-4aad684922ab` now reaches a
  projection-commitment mismatch: its independent fixture still computes a
  flat SHA-256 while production uses the versioned Patricia-Merkle commitment.
  A version-correct independent batch oracle was added and independently
  source-checked. Run `42aff4c5-d4ac-4b3e-8077-d194352d4d20` compiled and
  executed but failed in 2.94 s because a submitted signed fact was not
  retained by the reducer. Its full artifact is
  `graph-hub-differential-42aff4c5.json`. A bounded diagnostic preserves the
  original error and identifies the next run's input: run
  `6a338434-6674-4602-95de-79227f3d97e3` failed in 2.78 s on
  `closed-order ordinal=1 prefix=4 kind=primary role=grant_member`.
  This is the reverse import order. Source diagnosis identified the intended
  `QuarantineSignerNotEligible` gate: the controller-authored member grant
  arrives before the controller's authorizing grant. The fixture correction
  now uses signer-eligible positive schedules and separately requires exact
  refusal/no mutation when authority is missing. Signed facts and the
  production custody gate remain unchanged. Run
  `3ce9b723-edd7-4de4-b4bf-caf307a99c3e` still failed in 0.44 s, now at
  the reference-graph `admit` helper assertion on line 95. Its preceding
  missing-authority diagnostic belongs to the expected negative control,
  not the failing assertion. This predecessor did not pass; the corrected
  target later passed in run `3985b1b7-6689-4c1c-9976-375c74c840c0`. Its artifact is
  `graph-hub-differential-3ce9b723.json`, with binary SHA-256
  `B885A35E6E51DBEB31E95FF589E2A097BA8C204496120C86AD4AC33AFB1CFE30`
  from build `d01cca39-0952-49a3-8c7f-b6b5d91a2236`.
  One unchanged-binary diagnostic run with `RUST_BACKTRACE=1`,
  `be39ee6d-bf64-4913-8e22-395d0bb79c4f`, failed in 4.10 s at a different
  assertion: ordinal 1's post-primary comparison reported three admitted
  production facts versus seven in the reference. It did not reproduce the
  reference replay assertion. Source inspection also establishes that export
  merges admitted and quarantined facts in ID order, not admission order;
  blindly replaying that order is not a valid authority-order guarantee.
  Source inspection identifies a separate retry-contract difference: the
  journaled production path processes one ready frontier, while the direct
  reference drains newly unblocked transitive waiters. Repairs were made
  on disjoint files: exported signed bodies replayed in recorded input order
  with exact custody checks, and journaled transitive settlement with a
  cumulative retry allowance, existing separate durable-delta vector limits,
  and exact rollback. The retry allowance must not
  restart for each frontier. The corrected differential target now passes;
  two focused causal controls still fail as detailed below. The earlier
  failing count alone was not the source diagnosis. Full logs remain in the
  durable run service; the local bounded summary is
  `graph-hub-differential-be39ee6d-summary.json`. The diagnostic run used the
  corrected schedule's recorded binary; an earlier stale-schedule explanation
  was rejected against the build identity. Its logs identify the post-primary
  comparison in ordinal 1, not an exact prefix number.
  The corrected mixed-export fixture has independent source verification at
  SHA-256 `6EEBAA5ACB0B20054FA9DD23029579004B6176E6D485120FCCE0B49557011187`.
  Independent review blocked the first retry patch on moved projection
  ownership, aggregate retry budgets resetting per input, and stale/incomplete
  boundary controls. Those source corrections subsequently passed review;
  a retained full projection clone was not used as an ownership fix.
  The revised source captures sparse preimages before consuming the unique
  projection and carries the transactional retry allowance across inputs.
  Review found that its new budget test refused the input count before ever
  reaching retry work; mutation-sensitive mixed removal/promotion and remaining
  rollback controls were corrected and independently source-verified at
  causal SHA-256
  `1F54A42868EBA1DF8B6C5640D5095A61557A42ADA4BE120569E0BBA3E0BF70EB`.
  Final test fixes preserve moved-value ownership and corrupt signatures
  without changing their canonical encoded byte/edge cost. Scoped format run
  `b21f3b1d-4fec-4c9f-b871-a9d26a0036ba` passed with empty complete logs;
  its artifact is `graph-hub-retry-format-b21f3b1d.json`.
  Build `b114d524-9e8d-4998-b1f5-2c47a8222e81` passed, and the whole
  differential target passed four tests. Focused run
  `41649652-1169-4f4a-b875-01c61873c6c8` passed six controls but failed two:
  `aggregate_journal_evolves_graph_and_attributes_promotions` expected two
  normalized aggregate promotions at line 9709 and observed zero;
  `aggregate_preplanning_work_tracks_ready_frontier_without_extra_promotion`
  did not match its expected ReadyBatch refusal at line 9391.
  Source normalization counts promotion only for a row quarantined at the
  aggregate's initial boundary; within-group promotion attribution is in the
  per-input delta. The first failing assertion conflates those contracts.
  The second fixture's actual trigger outcome remains under bounded diagnosis.
  Neither failure is waived, and the causal gate remains incomplete.
  Existing limits remain separate:
  rows at most B+1, promoted IDs at most B, and removed IDs at most B. These do
  not establish a combined B+1 changed-ID limit. Refunding an input's allowance
  on rollback is transactional accounting, not a bound on CPU already spent;
  preparatory indexed-closure traversal remains bounded by quarantine policy.
  Its full artifact is `graph-hub-differential-6a338434.json`.
  Opaque rerun `1d54cb5b-b7f4-47df-8768-a7681e7965cc`
  identifies the unexpected `QueuePressure` at the first valid
  `open Alice-to-Carol relay`, before payload delivery. No queue or timeout
  limit has been enlarged. Source inspection identified a missing
  `RelayOrProviderAllocation` dimension in that fixture's grant. A pure
  fixture planner now exposes separately charged roots and dynamic claims.
  Its 21 relay units are a conservative five-open construction allowance,
  not a measured peak; the pending-handshake allowance is separately one
  concurrent reservation. Independent source review passed the arithmetic
  but blocked qualification because the planner substituted encoded string
  lengths for acquisition-time decoded key-share capacities. An explicit
  capacity input, full application-message JSON boundary witness and
  independent reservation-bookkeeping assertions have now been added.
  Public-planner capacity sensitivity and overflow controls were added after
  review found that raw-helper-only controls could miss a hardcoded planner
  input. Independent closure source review and planner test `c815ab1c` passed.
  Production charging, limits and immediate-overlap lifecycle checks are
  unchanged. Opaque run `b63dcf62-bd57-45da-9fb7-6e299a64828e` now reaches
  the final live-custody comparison after the relay lifecycle and three
  network shutdowns, but fails in 1.05 s because Alice's `measurement_inexact`
  flag is `true` rather than baseline `false`. Source diagnosis confirms
  this is sticky, scope-wide historical precision metadata, set by real
  transport observations and not reset when leases finish. The fixture
  correction now requires monotonic precision metadata plus a non-vacuous
  post-transport observation, while keeping exact live custody comparisons.
  Independent source review also caught a stale synthetic reset expectation;
  its correction explicitly permits acquiring sticky imprecision, rejects
  resetting it in either resource family, and keeps no-activity checks strict.
  Whole-target rerun `71b84458-cf07-4b51-b46c-238d00fd0a3a` passed both
  tests in 1.03 s, including the real five-open lifecycle, exact payload and
  stale/successor controls, all three shutdowns and final live-custody checks.
  The failed predecessor remains in `graph-hub-opaque-b63dcf62.json`.
  Complete local artifacts are `graph-hub-differential-fc32931a.json`,
  `graph-hub-pending-941ab117.json`, and `graph-hub-opaque-6c6d9efc.json`.
- Registry run `8515b1f3-3a7e-42a5-add6-882c4ac35dc0` exited zero but
  selected **zero tests** because it targeted the CLI binary. It is not a
  pass. The registry tests belong to the `myownmesh` library target; corrected
  run `31d72b70-ec4d-4b61-a53d-c31a103056ca` executed two tests: canonical
  order passed, but the fixed-field control expected three allocations where
  the complete row correctly measures six (three nonempty row strings plus
  root text, hub-slot backing and hub text). A test-only accounting correction
  and a separate topology-only three-allocation control passed in library
  rerun `b1d6ee95-b83c-4722-ac79-6cb20ea628a3`; production measurement is unchanged.
- Successful runtime parent registration, the full four-hop primary-tree
  route, and healthy-parent discovery convergence are not established by the
  three-peer non-veto test. Source checks and component tests are not substitutes.
- The 5,000-member tests are pure planner/work controls, not 5,000 processes.
- Directory page construction retains only a bounded page plus one identity,
  but scans the current owner registry: per accepted query CPU work is O(N).
  Reply-rate admission bounds accepted query frequency, not constant per-query
  CPU work. No bounded scan-work or allocation-free claim is made.
- No baseline/candidate CPU, RSS, allocation, SQLite growth, disk, or net-memory
  improvement is claimed. Logical provider claims and OS measurements remain
  separate accounting planes.
- No field/NAT/TURN/platform matrix or hosted-green status is established here.
- Implementer handoffs and independent bounded source verification are
  complete for the corrected controls; Turing's final independent audit and
  exact pushed-head verification/publication are still required before this
  unit is presented for operator review. The existing HOLD remains in force.

See [the qualification recipe](graph-hub-performance-recipe.md) for the
declared gates and [the design](../GRAPH-AND-HUB-DESIGN.md) for invariants.
