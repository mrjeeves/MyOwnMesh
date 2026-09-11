# Graph / Hub candidate: local verification record

This is a **local verification and audit record**, not release approval.
The working branch is `macro/02-authority-durability-relay`. PR #7 remains
open, draft, unmerged, and on HOLD.

## Current disposition: candidate175 verified; exact-pushed-head audit pending

The corrected candidate completed all175 selected checks in run
`9d5d46d1-cb5d-4001-86c6-a4c703befe29` at 2026-09-06 18:47:43 UTC,
exit0. Locked all-target compilation passed in550.258 seconds, with parsed
Cargo `build-finished: success=true` and47 test executables. Every native
cell ran exactly one test, passed one, failed zero and ignored zero.
The report is
`target/qualification-evidence/graph-hub-wave1-full-matrix-selector-winner-impact-contract-corrected.json`,
SHA256 `0EFA5A22206049AD5B17740BF13E1B9BC960D51F186838618816A181B2DC0413`.

Manager and independent verifier Payne rehashed all612 recorded source files
and all47 executables: zero mismatches. All351 source checkpoints and175
before/after executable hashes agree. Canonical source digest:
`e396d54eb0f56c6287f65c1f30fc4c24a70e93d1c3a73c24f61f535e633635de`;
canonical selector manifest digest:
`39a89f4cca8eb2ee5a0dca0fea154f687c4ec63e50aa016b25d156b955e7315e`.
All175 required/manifest/executed selector tuples match. No capture is
truncated, no callback error or unknown terminal outcome occurred, and no
compiler error or Cargo JSON parse error was observed. This is tested dirty
candidate evidence recorded at parent HEAD `f70689e1d64883458ad204d8d0b9f9b76bee9666`,
not yet an immutable published-head result.

Executed closure includes gate175 (9.949 seconds): final competing-selector
winner, exact Role/Membership delta entries, independent signed ancestry
heads, both selector orders, single/aggregate hot/cold commit/rollback/Drop.
The formerly timed-out gate160 completes all720 orders in126.228 seconds
under the measured240-second envelope. Cold lifecycle155 passes22.485 seconds;
provenance170, canonical snapshot171, tamper fallback172, pristine restore173
and candidate-relative NoOp174 all pass. No assertion or permutation was
removed to obtain these results.

Actual native hub/relay checks also pass:137 opaque relay3.006 seconds;
138 production LocalBroker relay1.069;139 no-parent/alternate/no-exit routing
1.172;140 real parenting, bidirectional four-hop payload, bounded discovery,
replacement and expiry3.980;141 connected full-prefix fallback2.326.
The adjacency control checks all20 directed pairs at both payload boundaries.
Alternate direct installation in139 is explicit, not automatic unreliable-hub
learning. Exact provider conservation is asserted by relay/component tests;
mesh report baselines are not relabelled as external OS accounting.

Independent verification stages are complete: Payne
(`manager:a4dac58e-6041-407a-b500-cdfdd84b5fb9`) reports bounded
SOURCE/RUNTIME/CUSTODY PASS; Church
(`manager:fbda62d0-0616-4075-ac6c-efdabf001e73`) reports bounded actual
HubTree/relay/lifetime PASS. Neither implemented the surfaces they verified.
Their completed task updates encountered the recorded app projection/update
fault; these are actual completed handoffs, not pending implementation.

Publication integrates the exact nine-file correction, then binds a clean
pushed-head175 run and Turing's separate final audit to that new commit.
Until those finish, this is not final unit acceptance. Historical `f70689e`
audit BLOCK and CI34020595984 failure remain correctly attributed below.
No hosted-green, multi-machine/NAT/scale, OS-memory or automatic recovery
claim is added. Withholding's usability/reliability effect is distinct from
a demonstrated authorization violation; no new withholding audit is opened.
PR7 stays OPEN, draft, unmerged and on HOLD throughout publication.

## Historical correction evidence

### Selector-winner run setup correction: zero compilation or runtime

Run `fa4a7cbb-42fe-439c-8e15-ee140da0b784` stopped after0.997 seconds
with `stale_source`, exit2. Its fatal error is exactly: acceptance contract
does not match its manager-supplied hash. Build is null, binary list and cell
list are empty: **zero compilation and zero runtime checks occurred**.
Wrapper stdout129/stderr0 are complete and untruncated. Retained report
`target/qualification-evidence/graph-hub-wave1-full-matrix-selector-winner-impact.json`
has SHA256 `EB6EB7B6BADF844D126FE93E9E174AC1ACA17D8DF863C6AF92835EBAA6FF342D`.

Manager updated the acceptance contract but left its old444A8550 hash in
the manifest. The current contract independently hashes to
`3C60B328A6B0C7696063F84437209484428AEEF5D5B5B6A52B2DB2563E8D05D5`.
Correct only that recorded hash; no Rust, selector, assertion, deadline or
authority change. Validate the actual file hash as well as manifest shape
before restarting on a separate report:
`target/qualification-evidence/graph-hub-wave1-full-matrix-selector-winner-impact-contract-corrected.json`.
The previous schema-only validation did not establish external file custody.
This is manager setup bookkeeping, not another behavior failure or a passing
qualification. All implementers remain complete/frozen.

### Selector-winner impact candidate integrated for whole175 verification

Shannon completed the sole causal-file correction and existing175 control
extension under `manager:c874481d-4941-42ec-8eda-94c8dde2441f`.
Unformatted handoff SHA256 was
`06528F32D9C17CBE68953ABC51E26B697FADC94160F12EDD7ED04A18BA40D05C`.
Manager inspected the helper extraction, shared pre/post-mutation impact
path, exact delta assertions, both selector orders and hot/cold single and
aggregate commit/rollback/Drop. The new exceptional helper unions declared
seeds, existing subject participants and matching borrowed staged rows before
the existing descendant walk. Ordinary nonlinear conditions and ordinary
Role Resolution behavior are preserved; no authority/relevance/NoOp, retained
map, cap or API change is included.

Scoped rustfmt run `68468141-5398-49dc-8725-923a49f21ff4` passed exit0
with empty, complete logs. Formatted causal SHA256:
`CD39C7C2E3020A082EE14521F53A0EE24993B15C5CA21BDE61A46C7266827770`.
Manager rehashed the prior report's612 source files: only causal.rs and the
three manager-owned qualification documents/manifest differ. Projection and
durability integration files, all other production files and the harness
remain unchanged. Source inspection and formatting are not compiler or runtime
acceptance.

The next serialized gate retains all175 exact selectors and existing warm
cache with CARGO_BUILD_JOBS=1; only gate160 has the measured240-second envelope.
It writes the separate report
`target/qualification-evidence/graph-hub-wave1-full-matrix-selector-winner-impact.json`.
Shannon is complete/frozen, all other workers remain idle, and manager owns
whole-matrix execution and custody. No source/docs/test edits or additional
implementation lanes are released during that run. Independent verification
and Turing's exact-pushed-head audit remain required after a successful gate.

### Whole175 follow-through: complete720 diagnostic pass; one impact repair active

Diagnostic run `38bf0eea-e10d-4048-aa6d-f43e0cebc471` completed successfully
at 2026-09-06 18:10:44 UTC: exit0, one passed, zero failed/ignored, native
149.84 seconds (149.901 seconds durable elapsed). Manager read all three
cursor-paged log segments: stdout203/stderr165866 bytes, complete and
untruncated. All720 start records and all720 completion records are contiguous
and ordered; every completed schedule ends with ten admitted facts and no
refused bodies remaining. Final phase totals in seconds are snapshot14.680,
admit45.241, retry29.368, redelivery3.413, and final checks35.729, with call
counts4320/4320/5148/216/720. These partial phase timings do not account for
every overhead and are not a performance benchmark.

Current causal, integration fixture, core rlib, diagnostic source and binary
were rehashed after the run and match their pre-run identities. Diagnostic
binary SHA256 is
`6A6B760BE487A9A0140D45712DBF1BD9A5F6F319DD4B7F9BE5677A54B556E5DF`.
The compact retained evidence is
`target/qualification-evidence/projection-progress-diagnostic-full175-evidence.json`,
SHA256 `C8EAB40E480B476C02AD4F10D412FDEB63743C9AC8FA5A39CCFB2861D9B469E0`.
This proves completion of the unchanged 720-order workload with all assertions;
it does not retroactively turn the original matrix timeout into a pass.

The measured149.84-second workload explains why120 seconds was insufficient.
Manager changes ONLY gate160's deadline to240 seconds (about90 seconds above
the measured complete run). No schedules, assertions, resource caps, stack,
jobs or other deadlines change. Both integration fixture files stay frozen;
there is no speculative test-driver optimization or automatic retry.

The sole remaining demonstrated production defect is gate175's final
winner-of-competing-selectors impact omission, described below. Shannon owns
exclusive `semantic/causal.rs` correction and the exact direct/single/aggregate,
hot/cold ownership controls under assignment
`manager:c874481d-4941-42ec-8eda-94c8dde2441f` (implementation in progress).
Manager owns the contract, manifest, evidence and subsequent integration.
Payne/Curry diagnoses are complete; Tarjan's durable fixture remains frozen.
One coupled production file is the useful implementation lane; extra owners
would overlap it. After one coherent source freeze: serialized whole175
verification, independent verification, publication/exact-head audit by
Turing, then operator HOLD. No new whole-matrix run is active yet.

### Latest whole175 runtime: 173 pass, one projection mismatch, one timeout

Run `3a413fc1-411e-4082-953e-3ed78abc5cc8` terminated with exit1 at
2026-09-06 17:56:54 UTC. The unchanged 175-cell manifest genuinely executed:
**173 passed, two did not pass**. The warm-cache all-target build passed in
10.666 seconds, with Cargo `build-finished: success=true` and 47 test
executables. This supersedes the compile-only attempt below, not the final
audit BLOCK or PR HOLD.

Report:
`target/qualification-evidence/graph-hub-wave1-full-matrix-historical-membership-compile-corrected.json`,
SHA256 `2AAF9ADF0744775D93557988207D26A2069956164B6D6C2348F9D3AF206A51FE`.
Manager rehashed all 612 source files and 47 executables, reconciled all
351 source checkpoints and all 175 before/after binary hashes: no mismatch.
Source digest is
`c7350a8d4f53a39043ffd4cb3555d5cc06890156bc609a224d0bc3d31454d5a6`.
HEAD/ref remain `f70689e1d64883458ad204d8d0b9f9b76bee9666` /
`macro/02-authority-durability-relay`; this is the dirty corrected candidate,
not a new published commit. Build and cell logs are complete, untruncated,
and without callback errors. There are 174 normal exits and one known timeout,
not an unknown terminal outcome.

| Gate | Exact terminal evidence and remaining question |
| --- | --- |
| 175 | `historical_membership_exclusion_survives_later_selectors_and_cold_journals`: exit101 after 6.572 seconds, one assertion failure at causal.rs:9689 comparing cached projection with fresh reduction. Cached Membership(C) is a two-fact conflict and Role(C) is absent; full reduction has the same one fact as both Membership(C) and Role(C). This is a cell-content difference, not only commitment representation. The helper has multiple callers; exact failing stage and impact/preimage implications are under read-only diagnosis. |
| 160 | `self_authored_membership_resolution_is_order_independent_after_role_regrant`: terminal timeout after 120.356 seconds, post-kill exit1. Complete stdout contains only running-one/test-start; stderr is empty. No native assertion failure or completed permutation count was observed. Finite 720-schedule work versus a stuck operation must be distinguished before changing any acceptance deadline. |

Executed passes now include the extended real durable membership lifecycle
155 (19.315 seconds), both-peer session lifecycle 154 (2.195), distinct-owner
later-selector continuation 161 (2.985), truthful incomplete/stale controls
162/166, and prior ineligible-refusal permutations 158. Provenance/cold
rollback 170, same-snapshot canonical closure 171, checksum-valid tamper
fallback 172, pristine checkpoint 173, and candidate-relative NoOp
journal/hydration 174 also passed. These results do not qualify failed 175
or unfinished 160, and are not independent verification or release approval.

Manager coordination plan: terminal custody inspection complete; complete
two-failure diagnosis in progress; no Rust edits or blind reruns. Payne owns
read-only gate175 diagnosis (`manager:a986fd45-f036-4c7f-9a4f-d0653b8e9a8e`),
Curry owns read-only gate160 timeout diagnosis
(`manager:78181a58-f98c-4ad3-b313-935bf2da8b64`). Shannon's causal and Tarjan's
durability implementations remain complete/frozen. Manager owns the evidence
ledger and any justified unchanged-library diagnostic. Two independent
failure groups are useful now; extra implementation lanes would duplicate work.
Both diagnoses have now completed. Payne proved the failure is the final
winner-of-competing-selectors sub-control: V is the only fixture fact that
can supply both the observed role and membership values. The preceding main
historical-membership, hot/cold journal/aggregate, and provenance controls
therefore completed before the final failure. The helper's assertions after
the failing cache comparison remain unexecuted at that final boundary.
Manager inspected the same source path: typed resolution seeds the reverse
impact walk with cell-less selector predecessors, omitting their earlier
M/V branch cells. Full reduction and relevant-selector decisions are correct;
the common impact family used by preimages, updates and deltas is incomplete.
The bounded correction must cover those subject participants at every ownership
boundary, retaining the exact final winner and all prior controls.

Curry established bounded 720-order driver loops, but source alone does not
measure their cost. Manager prepared an ignored diagnostic copy of the CURRENT
integration target, adding only per-order progress and cumulative timing for
snapshot, admit, retry, redelivery and final checks. All signed bodies,
assertions and 720 schedules are unchanged. Diagnostic build
`312b35b8-c98a-459c-a5c7-05dd172db65f` passed in 8.902 seconds with empty,
complete logs. It links the unchanged Cargo-built core rlib
`0681AD337900280BCC4D621964C9A66383B9A348047103D5B3CCDD8282D4753D`.
Diagnostic source
`target/qualification-evidence/projection-progress-diagnostic-full175.rs`
has SHA256 `AEA52F5A0C9B2B550E6DA79558A877405F4B3FBD4BABAD888C77F842EF958D26`.
One finite 240-second diagnostic envelope allows observation of the complete
workload or the last progressing order, not acceptance at a relaxed timeout.
The committed selector deadline remains 120 seconds. No production repair
or further whole-matrix run is released before this discriminator completes.

Shannon and Tarjan remain frozen; Payne and Curry are now complete/idle.
The app's task projection still exposes stale entries; both exact same-ID
completion updates were again refused as not assigned. Actual completed
outcomes are recorded here without duplicate completion tasks.

### Whole175 compile-only failure and exact fixture correction

Run `f147876f-6a33-4851-9277-ca40260212e4` completed at
2026-09-06 17:41:26 UTC with `build_failed`. Cargo exited101 normally after
561.725 seconds, with `build-finished: false`; it did not time out.
**Zero runtime cells executed.** Cargo emitted 46 test-executable artifacts,
but there is no complete all-target compilation or behavioral acceptance.
The retained report is
`target/qualification-evidence/graph-hub-wave1-full-matrix-historical-membership.json`,
SHA256 `98D9285EFDEE0FF6DC6664BA65D7EF65593073E473462BC9E12DDDC0DAA9D77D`.
Build stdout/stderr (376813/31616 bytes) and wrapper logs are complete and
untruncated, without capture errors. All612 recorded source files rehash
correctly; source start and after-build digest both equal
`d9cf976667930953b66313485f1d46314ad3b2cb07eda27c9eed253d0fc5a4c4`.

The compiler reports two E0382 errors in projection integration tests:
the new assertions read `membership_continuation.id` after that SignedFact
was moved into the candidates array (lines1164 and1457). A bounded census
found the same post-move access at1563. Manager replaced exactly these three
references with the already captured Copy `membership_continuation_id`.
No fact is cloned or re-signed; assertion expectations and production remain
unchanged. This is a compile correction, not a new semantic repair or test pass.

Scoped format `4513e9c9-4104-443a-88c5-03d510514a7f` passed with empty,
complete logs. Projection integration SHA256 is now
`645397FDE9E20E665A539F61CB837705264E933546EC48256886493372A279AA`.
Causal `8F633E96...` and durability `E029BAA9...` remain unchanged. The same
175-cell manifest, resources, stack settings and deadlines are retained.
The next run uses the existing warm build cache and a separate report:
`target/qualification-evidence/graph-hub-wave1-full-matrix-historical-membership-compile-corrected.json`.
Independent runtime verification and final audit remain pending.

### Prior runtime candidate: 168/174; historical membership revival reproduced

Run `4ea317ef-60b7-445e-8d41-7a4591eba664` completed on
2026-09-06 at 17:03:45 UTC. Locked workspace/all-target compilation passed
in 511.476 seconds (`build-finished: success`, 47 test executables, zero
compiler errors). All 174 exact cells executed: **168 passed, six failed**.
Report `target/qualification-evidence/graph-hub-wave1-full-matrix-candidate-noop.json`
has SHA256 `5DC6B72593F79EA05F8EF89901C405012E5EC151A0B1B87CDE30FA2DF9DDBFC2`.
Manager rehashed all 612 recorded source files and 47 binaries, reconciled
all 349 source checkpoints and all before/after cell hashes: zero mismatches.
Build and runtime captures are complete, with no truncation, capture errors
or unknown terminal outcomes. Source digest:
`4e4b871a98ba5f7a6a53c13548dc204bc134386212f4aaa607db5b9b7e686cc8`.

Executed passes include concurrent candidate-relative NoOp journal/hydration
control 174 (11.309 seconds), all 720 authority arrival permutations in 157
(90.908 seconds), recursive resolution 165, concurrent tier 168, second-order
payload 159, both HubTree controls 140/141, both real relay controls, and all
selected cold/store lifecycle gates 155 and 170–173. These are bounded runtime
results, not whole-unit acceptance or a final independent audit.

The complete six-failure assessment is now:

| Gate | Observed boundary and disposition |
| --- | --- |
| 154 | U session expected true from controller role alone; selected-R leaves the remote's only grant suppressed. Fixture must assert both peers' role, lineage and membership prerequisites at every stage. |
| 158 | Exact `QuarantineSignerNotEligible` for O before G in schedule `[1,0,2]`; remaining fixture driver needs explicit dependency-bound redelivery, retaining the no-mutation refusal. |
| 160 | Old rejected membership M becomes the projected value after the new Q/R authority fork. Runtime-confirmed production defect. |
| 161 | Old rejected M becomes the projected value after later T2 selects R and U2 regrants authority. Same coupled production defect. |
| 162 | Candidate with only one causal head returns `NoOp("resolution has no live conflict")` before incomplete-resolution validation. Preserve this negative and construct a genuinely conflicted incomplete control. |
| 166 | Purported independent successor revoke was authored after admitting the successor grant. Fixture must author both from the same unchanged baseline before asserting conflict/stale-head refusal. |

Two diagnostic copies linked the unchanged full174 Cargo-built core rlib
`D5D8EBA9A96531D8A1A8D8E773D089DA4D3636091211451FB73C4F584CDBC2BD`.
No production or signed-body changes were made for these reproductions.
Gate162 diagnostic build `6b55a04a-a2de-42f6-9da1-68a9f5e43cbc` passed;
test `d6dad88d-8198-46f1-8027-5eb7061cc4a6` ran one and failed one, exit101,
with the exact NoOp above and complete 275/339-byte stdout/stderr.

Membership diagnostic build `9ce7af4f-28ae-4a34-a783-0fc0df278836` passed
in 6.343 seconds. The first diagnostic-only compile attempt `75ddb546...`
failed on tuple syntax for a struct variant; correcting that helper did not
change production. Test `0dcba933-f1c5-452b-969f-93eb4450d0f8` ran two and
failed two, exit101, native runtime 0.97 seconds, complete 484/2741-byte
stdout/stderr. It prints the exact identities:

- 160: cached and fresh-full membership both select old M `dubnmvd...`;
  independent signed-dependency ancestry gives sole maximal raw head Q
  `jabcjn...`, not M.
- 161: cached and fresh-full both select old M `tjp7s7...`; independent
  signed-dependency ancestry gives sole maximal raw head Q `4bh4dt...`.

The fresh projection reducer uses maintained cell indexes, so its agreement
with the cached projection does not refute this bug. Source review identifies
two coupled gaps: direct-only maximal-head removal retains indirectly
dominated M; historical typed-selector exclusions are skipped at a later
unresolved fork and are not composed into a later selected branch's ancestry.
The diagnostic establishes membership projection revival, not an observed
unauthorized network session. Full diagnostic custody, arguments and logs are
retained in `target/qualification-evidence/projection-diagnostics-full174-evidence.json`.
Membership diagnostic executable before/after SHA256:
`CCCA57F70C22C7BC21379F647B2D8A74B2A5339A1F491069E89A223E21B6EF49`.

One coherent correction has completed source integration; none is yet
compiled or qualified:

- Shannon (`manager:159c867f-bedb-4d40-b1a6-2443db0a2f1a`), causal.rs only:
  frozen implementation `B2B9BCC3...` shares signed indirect-head domination
  between mutation and preflight pricing; relevant earlier typed restrictions
  remain enforced during later forks and selected continuations. Canonical
  restore and cold hydration use the same context-completeness contract.
  New gate175 covers private authority/raw-index checks, independent ancestry,
  pricing, hot/cold single/aggregate commit/rollback/Drop and checkpoint omission.
- Curry (`manager:213df0f0-765c-4f22-b9bf-1e3944c10ebf`), projection integration
  test only: frozen implementation `A898707A...` closes all four fixture
  preconditions and adds the independent ancestry oracle to the same signed
  M/Q sequences. Manager added explicit unchanged-ID/full-projection checks
  around the retained one-head NoOp negative. No weaker losing-M assertions.
- Tarjan (`manager:e66156c6-a6c5-451d-a3b3-3a9fd4a99dd8`), authority durability
  test only: implementation handed off at SHA256
  `BE4AA266FC2360DDC7C790C0DAA90C71C00F498C9899D23196910C2B09B05B33`.
  Manager checked the bounded source extension: existing gate155 retains its
  four scenarios and one Mesh/provider, then adds the two-selector membership
  transcript (16 rows before reopen, 17 afterward). Both M/V and Q/R are
  authored from shared unchanged baselines; Q does not directly cite old M.
  It checks independent signed-ancestry maxima, exact live/export/projection
  identities, the two-endpoint session predicate and roster at every admission.
  Named F2 must first be hot, later absent from the complete hot observation
  but present in SQLite export, then support an actual post-reopen write.
  Both consumed leaves must restore exact provider custody. The original
  13-row helper bounds remain; only the new extension uses explicit17.
  No new selector, store/state API, provider grant or timeout is needed.
  This is source integration only; expanded gate155 has not run.

Scoped rustfmt run `52e085f7-47e4-4448-9d3b-4db238d20ad0` passed with empty,
complete logs. Final candidate source hashes after formatting/integration:

| File beneath crates/myownmesh-core | SHA256 |
| --- | --- |
| src/semantic/causal.rs | `8F633E967D42218819C0FC2C3B334A39B33D4344EBAE3C6E3D033A70E9B0F676` |
| tests/semantic_projection_controls.rs | `B4A53BF7011A7F7D287E4436389E56098B6E662035E13925F222E8722BD00F9E` |
| tests/semantic_authority_selection_durability.rs | `E029BAA99619EC91858D8145313C476CD90693DABB3209C5C8A82605F6289B4B` |

The manifest now retains all174 prior cells and adds exact gate175,
`semantic::causal::tests::historical_membership_exclusion_survives_later_selectors_and_cold_journals`,
first so the coupled behavior runs immediately after compilation. Gate155
retains its name and existing 180-second bound with the extended transcript.
The next whole175 result will be retained separately as
`target/qualification-evidence/graph-hub-wave1-full-matrix-historical-membership.json`.
Existing warm target cache, CARGO_BUILD_JOBS=1, 1800-second build bound and
all prior cell budgets remain unchanged. No result is claimed before execution.

Manager owns integration, contract/manifest/evidence and serialized execution.
Payne and Curry's read-only diagnoses are complete. Same-ID task completion
updates still encounter the app's ownership mismatch; no duplicate completion
tasks were created. Independent verification and Turing's exact-pushed-head
audit remain required after successful execution. No HOLD or CI disposition
has changed.

### Historical full173 result and subsequent candidate-NoOp batch

The subsequent persistent-selector correction is still unqualified. Its
complete run `45cfe48d-8e77-4e92-b20f-95bcfb38cc01` finished at
2026-09-06 16:08:38 UTC: locked workspace/all-target compilation passed in
1382.275 seconds, with `build-finished: success`, 47 test executables and no
compiler errors. All 173 exact selections executed: **163 passed, 10 failed**.
Report:
`target/qualification-evidence/graph-hub-wave1-full-matrix-selector-provenance-manifest-corrected.json`
(SHA256 `629A144596932C75653ECA7612330D5141DF5DAFDDDDFB1A6E4878A16C166EF0`).
Manager verified all 347 source checkpoints, rehashed all 612 recorded source
files and 47 executables, and checked every before/after cell binary hash:
zero mismatches. All build/cell output is complete and untruncated, with no
callback-capture errors or unknown terminal outcomes. This is real runtime
evidence, not the earlier manifest-validation refusal.

New boundary results are executed PASS: actual selected-branch cold
compaction/reopen/hydration (gate 155, 14.19 seconds), causal continuation /
competing selectors / cold restore / rollback (170, 1.88 seconds), canonical
same-snapshot signed closure (171, 0.22 seconds), checksum-valid tamper
refusal plus canonical fallback (172, 1.74 seconds), and positive clean
checkpoint restore without ordered admission replay (173, 0.20 seconds).
Each ran exactly one test with exit 0. These bounded passes do not override
the ten remaining failures or constitute independent final audit approval.

The complete failure set has been reconciled from three read-only diagnoses
and one manager-owned diagnostic. The latter copies the integration target,
changes only admission/retry assertion diagnostics (each result evaluated
once), and links the unchanged Cargo-built library. No production rebuild,
signed-body change or expected-outcome change was needed.

Diagnostic build `36a5e97c-f5f8-4d5b-90fc-bead91d3a751` succeeded in
9.65 seconds with empty complete logs. Test
`cebcff8e-972b-41b2-aa93-d6bd7e971c17` ran exactly the three hidden-error
selectors: 0 passed, 3 failed, exit 101, 2.05 seconds native runtime, complete
598/4106-byte stdout/stderr. Exact results:

- 154: schedule T/R/O/M/G rejects controller O before its grant with
  `QuarantineSignerNotEligible`.
- 157: permutation G/O/R/Q/F/N rejects F before regrant N with the same
  ineligible-signer refusal. The fixture incorrectly expected quarantine.
- 159: order O/M/E/R/Q rejects independent Owner-authored R with
  `NoOp("role revoke targets an absent role")`. R's signed causal history
  has the controller grant and no M/E; this is receiver-arrival-relative
  no-op detection, not an intrinsically redundant revoke.

Retained diagnostic source:
`target/qualification-evidence/projection-admission-diagnostic-full173.rs`,
SHA256 `4D416198C4DBE88DCF69EDB4F9F06600B2BB9633570B4DCB000A5DF9488D476C`.
Executable before/after SHA256:
`F297800A422F2393070B119A4EEDD3BA1F978AE39B873986C9AF3D715AE2D5DD`.
The core rlib before/after SHA256 is
`607C500002B75F23BB9753522974B7E973B6AEEBD6198FA92BD688A670BB29E9`.
The diagnostic evidence JSON alongside it records dependency hashes, exact
arguments and complete logs. This evidence diagnoses failures, not acceptance.

Payne's source review separates gates 165/168 (valid concurrent ordinary
Resolution/RoleGrant rejected using receiver-current state) from obsolete
fixture positives in 160/161 (ordinary selection of a typed-losing historical
membership row). Gate 158's empty membership cell truthfully takes NoOp
precedence. Gate 166's purported competing grant is a redundant causal
successor; its intended stale-head negative needs a real current conflict.

Erdos established that `peer()` includes discovery-only Sighted entries.
The observed gate 140 registry-presence failure is not evidence of a native
shortcut. The retained log does not identify the precise referral or peer
authentication fields. The correction will check authenticated/current
native-worker adjacency at both payload boundaries, not mere registry
absence, without changing production routing.

One grouped implementation batch is now active:

- Shannon, assignment `manager:7714215c-264c-4161-abe5-b24e7ac2b142`:
  causal.rs implementation complete, manager-source-inspected at SHA256
  `029CB1ECEC53A71568D4D155256E5F811C19C177F31F0F7732417A9D7E194791`.
  The production helper now evaluates intrinsic NoOp in candidate history
  for RoleGrant, RoleRevoke and ordinary Resolution; both callers still
  classify missing dependencies before invoking it. Existing authorization
  and ineligible-signer refusal paths are unchanged. New exact gate 174,
  `candidate_relative_noops_preserve_concurrent_role_operations_across_journals`,
  covers same-body concurrent pairs, intrinsic refusals, both orders,
  full-projection oracles, single/aggregate journals and retired history.
  This is source integration, not compile/runtime PASS.
- Curry, assignment `manager:a1ba44cd-d936-4303-b60e-66e33a7f5f17`:
  complete projection-fixture source handed off at SHA256
  `0D78F41EA2C4F16A085686D5E36088CEBD41889F7267D0C792EB9995C755388B`.
  Both obsolete historical Q selectors are now exact negative controls;
  positive membership continuations are newly authored after regrant.
  Redelivery checks canonical dependencies, not just generic parent fields.
  Manager integration corrected one missing borrow and bounded settling
  of eligible quarantined prerequisites before dependency-complete
  redelivery, at all four fixture drivers. This is test scheduling, not
  production retention or authorization. All 15 selectors remain.
- Erdos, assignment `manager:11ad0f69-218f-455f-b903-6b8256da67c3`:
  HubTree source correction complete and manager-inspected; all 20 directed
  pairs checked at both payload boundaries, with every witness dropped
  locally. SHA256
  `A95B073BB93C684AB2E9571463D297E79F5D361EF5DAA05ECC5BB52E05A63E23`.
  Compilation and runtime remain unverified for this change.
- Manager: all three source handoffs integrated; the 174-selector matrix is
  prepared for one frozen serialized build/runtime run after scoped format
  and actual harness-manifest validation. No corrected runtime result yet.
  Payne's diagnosis
  is complete; independent verification and Turing's final audit remain
  later gates, not implementation roles.

Grouped format `743d10ea-e61b-40b4-b86c-53850409e1e5` and the final
manager fixture format `0edd72cc-a620-46fd-b00a-5ae5528b754a` both
succeeded with empty complete logs. Actual harness validation
`d817428a-daea-45d8-88a7-776f4df31559` succeeded with 174 cells.
Final pre-build source hashes:

- causal.rs: `6680CB021571F68425AE28373EFC8F58EB206276A32AD3E21D66FC567A9438CC`.
- projection controls: `8EE9BCD6BF05F462E8C2595C85AE0F12A772084AD12A0C9AD0866C8F829FC299`.
- HubTree test: `A95B073BB93C684AB2E9571463D297E79F5D361EF5DAA05ECC5BB52E05A63E23`.

The next report is create-new
`target/qualification-evidence/graph-hub-wave1-full-matrix-candidate-noop.json`.
Its build retains one job, the finite 1800-second envelope and the existing
warm target cache; no cold-build performance claim follows. Source, tests
and documents are frozen during execution. The report, not this pre-run
record, determines the eventual result.

The provider task projection is stale and same-ID completion updates for
the completed diagnosis assignments were rejected as not manager-owned.
Actual transitions and exact new assignment IDs are recorded here; no
duplicate completion tasks were manufactured. There is no exposed own-plan
updater, so manager integration remains explicitly in progress in this
record. This is not unit completion. PR #7 remains draft and on HOLD.

Turing's independent final audit of pushed head
`f70689e1d64883458ad204d8d0b9f9b76bee9666` found a HIGH persistent typed
authority-selection defect. The selected branch is recovered only from an
immediate dependency of the current authority head. A valid resolution,
regrant, then ordinary future authority use can therefore forget the
selection. The audit also identified the related one-layer cold-retention
gap. The unit is not complete; the prepared local-PASS publication draft
must not be used as completion evidence.

Manager diagnostic run `257ed24d-0c2f-425c-9e0c-267b12a85ff9` reproduces
selection loss against the unchanged built library from this head. All six
signed G/O/R/T/U/F operations were admitted as `Inserted`. Selection was
present after T and U, then `None` after F. The exact test ran once and failed
in 0.11 seconds, exit 101, with complete untruncated 258/707-byte stdout/stderr.
The probe's old-target role remained `None`; this run does not itself prove
permission revival, full-projection divergence, or cold/reopen loss.

The standalone diagnostic is retained at
`target/qualification-evidence/authority-selection-probe-f70689e.rs`
(SHA256 `CB9B65D1E727A3E99E58EFD4C87CD131EBDE2E2E8F0BE7950825D925E10D8A6C`).
Its executable SHA256 is
`15D4525676A15B4A370A60446907B9D26561842628D4D0DA1AAD96AACE9CE53F`;
it links the already-built core library, SHA256
`9CBAEB4567A153FFC4D3BF0DF412BFC4B406DF27580FBE13022EEEDB258E5056`.
Build `3c3e0476-69a3-4e8c-9e71-0b58cf4fe20b` passed using the native library
paths recorded by Cargo. Its predecessor stopped at a missing native search
path and supplied no runtime evidence.

The existing omitted selector
`authority_lineage_selection_round_trips_and_regrant_is_future_only`
failed earlier in run `83eaeff4-04e9-42e8-a8fc-53a0fa35c870`: an empty-cell
ordinary Resolution returned `NoOp("resolution has no live conflict")`, not
the fixture's expected `IncompleteResolution`. It never reached the reported
defect. Its replay also requires correcting positional assumptions about
FactId-sorted export order. These are grouped test repairs, not authorization
changes or a substitute for the positive-path reproduction above.

Clean-head run `dada4d7d-8c7f-4780-9813-fa9aa9f1edba` did pass all 153
selected tests with 46 compiled test executables. Its report is
`target/qualification-evidence/graph-hub-f70689e-full153.json`, SHA256
`9F4C6D08C1C8994516EDD4A769DD393E6C63F0AEA950663574CE67AE85C0D6C2`.
That selection omitted the existing lifecycle test and does not override the
final audit BLOCK. Exact-head CI workflow `34020595984` separately failed:
three GUI protocol census jobs, Direct/native warning-denied compilation,
and Avahi warning-denied compilation; both daemon cross-builds passed.
Neither failed native backend job reached its runtime gate.

The current same-unit correction assigns causal persistence/cold ownership to
Shannon, complete hot/wire lifecycle controls to Curry, and actual durable
compaction/checkpoint/reopen controls to Tarjan on disjoint files. Manager
owns integration and serialized verification. Independent verification and
Turing's new exact-pushed-head audit remain required before completion.

The prepared manifest now contains 173 exact cells: the prior 153 plus all 15
`semantic_projection_controls` tests and the real durable authority-selection
lifecycle control, the new causal provenance/rollback control, and three
store checkpoint/ancestry controls. The
previously omitted lifecycle runs first, followed by the durable and causal
controls, after the all-target compiler gate. This manifest is
prepared, not executed. Manager integration corrected the hot fixture's
cached-only oracle and selected-operation role expectation, and returned
the causal duplicate-field/loser-fence/accounting issues and the durability
fixture's missing future operations/live oracle together to their owners.
Run `40213c9f-6099-4509-9e84-5033573aa6bc` stopped at manifest validation
with `harness_error`, exit 2, before any Cargo build or runtime cell. The
manager's 16 added integration selections used Cargo's target-kind spelling
`test` instead of this harness schema's `integration`, in both the required
list and cells. All 32 field occurrences are corrected together. This is a
manager-owned qualification setup error, not production failure evidence.

The earlier pair-only `(frontier, selected)` prototype was source-blocked: once
selector ancestry is cold, it cannot prove continuation eligibility, and
trusting arbitrary frontier ancestors includes the losing branch. The manager
has selected a bounded per-live-row typed-provenance design with canonical
store validation on restore. Shannon owns causal metadata/rollback/rebuild;
Tarjan owns the store resolver and the revised 13-fact real durable lifecycle
test. Shannon has replaced the pair prototype and frozen causal source at
`CB9DB29DFF792CBE32B661C4D3757C1D7276EC3A6F7859136D688C5B0EB3751B`.
This is an uncompiled implementation handoff, not an independent source or
runtime PASS. No partial source handoff is treated as a passing implementation. The
full-reduction lab accessor is used by both integration oracles; ordinary
default-feature replay coverage remains separate from that lab-only oracle.

The causal/store interface is now agreed: checkpoint restore resolves roots
derived from resident signed facts, independently of serialized provenance,
and validates signed closure in one SQLite read snapshot. Shannon's agreed
restore/root interfaces and final metadata shape are landed. Tarjan has
completed dependent checksum-valid forgery and omission controls plus the
positive validated-checkpoint path. His unformatted store handoff hash is
`3A0FC669510C7C4DDE30DCEB120FEEFDCD91CCD1A71A4F91F4CDF996F8B5D806`;
the durable lifecycle fixture hash is
`A121A5B289291949E65D134A0D18E232A221087A2604AE46F362E12108E81389`.
All three implementation owners are frozen and idle. Manager integration
confirmed the agreed same-snapshot resolver and preserved generic ingress
lookup semantics; independent verification remains after execution.
Manager has wired additional selector-provenance roots into both production
single and aggregate history lookups under their existing publication/owner
fences. In-batch IDs remain overlay-owned; ordinary unknown-parent quarantine
is unchanged. This adapter is source-integrated, not compiled or runtime
verified. The expanded manifest includes the final store controls. Scoped
formatting and the serialized all-target build/full matrix are the next
gate; no new implementation lanes are opened during execution. Typed
AuthorityLineageResolution no-op checks are candidate-relative so genuine
competing selectors can both be admitted and remain fail-closed; ordinary
role and payload no-op rules are unchanged. This behavior is in the frozen
causal control and still requires runtime evidence.

Scoped formatting run `b5160423-0099-46b4-818b-c43f60f24e7d` completed
successfully with exit 0 and complete empty stdout/stderr. It formatted only
the five changed Rust files. The prepared execution uses the retained cache,
`CARGO_BUILD_JOBS=1`, the existing 1800-second build budget and unchanged
per-cell bounds. Its report path is
`target/qualification-evidence/graph-hub-wave1-full-matrix-selector-provenance.json`
retains the manifest refusal above. The corrected manifest is checked with
the unchanged harness's own `validate_spec` before the next full run; the
Rust source and all 173 selector names, counts and timeouts are unchanged.
Validation run `e976da05-6c8f-41ba-aabe-8b245380091e` passed with exit 0,
complete 128-byte stdout and empty stderr, accepting all 173 cells through
the actual harness validator. The corrected full-run report will be
`target/qualification-evidence/graph-hub-wave1-full-matrix-selector-provenance-manifest-corrected.json`.

## Previous prepublication result: 153 selections, 153 pass / 0 fail

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
their pending/failing statements are historical. The current disposition is
the final audit BLOCK recorded above.

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
