# Arc 02 authority and resource spine red team

Status: executable controls for Arc 02A and the Arc 02B remote-candidate observation pilot.

This catalog tests a bounded source and runtime claim. It does not claim complete production resource coverage, selected budgets, production session promotion, or WebRTC and ICE agent accounting.

## Run

```powershell
$arc02Target = "C:\Users\Admin\.allmystuff-sandbox-stage\myownmesh-v4-arc02b-target"
$env:CARGO_TARGET_DIR = $arc02Target
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

function Invoke-Checked([scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

Invoke-Checked { cargo fmt --all -- --check }
Invoke-Checked { cargo check --workspace --all-targets -j 16 }
Invoke-Checked { cargo clippy -p myownmesh-core --all-targets -j 16 -- -D warnings }
Invoke-Checked { cargo test -p myownmesh-core --lib v4_arc02 -j 16 }
Invoke-Checked { cargo test -p myownmesh-core --doc -j 16 }
Invoke-Checked { python scripts/check-v4-arc02-compiler-boundaries.py }
Invoke-Checked { python scripts/check-v4-arc02-spine.py }
Invoke-Checked { python scripts/check-v4-arc02-spine.py --negative-controls }
Invoke-Checked { python scripts/check-v4-arc01-inventory.py }
Invoke-Checked { python scripts/check-v4-arc01-inventory.py --negative-controls }
```

The compiler check creates a temporary Cargo project and runs `cargo check --offline`. The focused Rust tests are in-process. These commands do not start a MyOwnMesh runtime, signaling service, listener, or integration binary.

Recorded result on 2026-08-01: every command passed. The focused suite passed 28 tests, the doctest suite passed 10 tests, the compiler harness passed 1 positive control and 10 cause-matched rejection controls, and all defined Arc 02 and Arc 01 mutations were rejected.

## 1. Candidate ownership attacks

### RT-02B-01: restore copied peer state

Attack: add `Clone` to the `PeerStateData` derive or add a manual `Clone` implementation.

Expected result: the source gate rejects the change. A caller must not copy the private candidate queue or its observation owners through a copied state snapshot.

Runtime control: `v4_arc02_candidate_queue_observes_items_strings_and_container_separately` moves the candidate into the queue and then into a drain.

### RT-02B-02: expose the queue

Attack: make `pending_remote_candidates` public or change it from `PendingRemoteCandidateQueue`.

Expected result: the source gate rejects the field shape. Every queue mutation must remain behind the observation owner.

### RT-02B-03: clone the inbound candidate

Attack: replace the moved queue insertion with `candidate.clone()`.

Expected result: the source gate rejects the clone. The queued value and its lease must have one move path.

### RT-02B-04: bypass one application path

Attack: remove `apply_pending_remote_candidate` from either the immediate path or the post-SDP drain path.

Expected result: the source gate rejects any count other than the two reviewed production call sites.

### RT-02B-05: end observation before the await

Attack: drop the candidate observation before `apply(candidate).await` or remove the post-await drop sequence.

Expected result: the source gate rejects the lifetime shape.

Runtime controls:

- `v4_arc02_cancelling_candidate_application_releases_its_observation` polls a pending application, confirms the lease is active, cancels the future, and confirms cleanup.
- `v4_arc02_candidate_application_releases_on_success_and_failure` proves both completed outcomes return active use to zero.

### RT-02B-06: drop queued work

Attack: remove a peer or replace its session while candidates remain queued.

Expected result: ownership drop releases both candidate and queue-container leases.

Runtime controls:

- `v4_arc02_peer_replacement_releases_queue_while_retired_arc_survives` replaces the map owner while retaining another `Arc` to the retired peer.
- `v4_arc02_peer_removal_releases_queue_while_removed_arc_survives` removes the map owner while retaining both the original and returned `Arc` values.
- `v4_arc02_dropping_peer_releases_queued_candidate_observations` proves ordinary owner drop cleanup.

## 2. Measurement attacks

### RT-02B-07: conflate logical and retained bytes

Attack: restore one generic byte field or derive both values from `String::len()`.

Expected result: the resource shape gate requires `logical_bytes` and `retained_bytes`. The source gate also requires candidate string capacity reads.

Runtime controls:

- `v4_arc02_logical_and_retained_bytes_are_independent_axes` uses different live fixture values for each axis.
- `v4_arc02_candidate_queue_observes_items_strings_and_container_separately` creates strings with live spare capacity and checks both dimensions.

### RT-02B-08: hide spare queue capacity

Attack: remove the queue container lease or omit `Vec::capacity() * size_of::<PendingRemoteCandidate>()`.

Expected result: the source gate rejects the queue shape or retained-byte calculation. The reported value is Rust `Vec` capacity in bytes, not allocator metadata or process RSS.

Runtime control: the queue test confirms that dropping the candidate while retaining the drain leaves only the container's retained bytes active. Dropping the drain then returns active use to zero.

Interpretation control: candidate count comes from `ResourceUse.items`. Lease count includes the separate queue-container owner and is not a candidate count.

### RT-02B-09: double count inline slots

Attack: add wrapper or candidate inline size to each candidate lease while retaining the separate queue-capacity observation.

Expected result: this is a review failure. The approved measurement contract assigns inline slots to the queue container and string allocations to each candidate. The source gate checks the reviewed calculation inputs, but this semantic review remains necessary if the formula changes.

## 3. Scope attacks

### RT-02B-10: skip an ancestor

Attack: change an ancestor update loop to `self.path.iter().skip(1)`.

Expected result: the mutation gate rejects it.

Runtime control: `v4_arc02_leaf_observation_updates_all_four_scopes` checks process root, Mesh runtime, exact context, and peer connection before and after lease drop.

### RT-02B-11: leak across sibling contexts

Attack: reuse one context scope for unrelated joined contexts.

Expected result: `v4_arc02_sibling_contexts_do_not_observe_each_other` fails. The Mesh and process reports may aggregate both contexts, but one exact context report must not include its sibling.

### RT-02B-12: detach a Mesh runtime

Attack: create a standalone accountant in `Mesh::open_with_identity` instead of descending from the process root.

Expected result: the source mutation gate rejects the detached wiring.

### RT-02B-13: add a second process-global observer

Attack: add another static accountant, `OnceLock`, lazy static, or thread-local resource root.

Expected result: the source gate requires exactly one typed process observation root and rejects the additional state.

## 4. Existing Arc 02A authority attacks

The same mutation suite continues to reject:

- public authority fields or constructors;
- wrapped, aliased, parenthesized, raw-identifier, macro-generated, or second-implementation mints;
- forbidden `Clone`, `Copy`, serialization, `Default`, and conversion traits;
- alternate runtime witness constructors;
- legacy wrapper extraction and trait bypasses;
- crate-root, module-path, conditional-module, and Cargo library-target redirection;
- missing compile-fail controls or boundary documents;
- policy, permit, capability, filesystem, process, or network behavior in the observer.

The compiler harness accepts one public type-path control and requires ten forbidden expressions to fail with the expected Rust error code, type-specific fragments, and primary probe line.

## 5. Pass meaning

A complete pass proves only the checked code and source properties for Arc 02A and Arc 02B. It does not prove:

- a numeric resource budget;
- resource admission or enforcement;
- a production `PreAuthAttemptPermit` issuer;
- all production allocations are observed;
- WebRTC or ICE agent retention is observed;
- arbitrary memory corruption safety;
- Arc 02 completion.

The handoff boundary is explicit: the candidate lease ends when `add_ice_candidate(...).await` returns. Retention inside webrtc-rs needs a later Connector Worker observation.
