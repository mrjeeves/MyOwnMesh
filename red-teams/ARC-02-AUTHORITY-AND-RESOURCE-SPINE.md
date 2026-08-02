# Arc 02 authority and resource spine red team

Status: executable controls for Arc 02A, Arc 02B, and the corrective Arc 02C revision.

This catalog proves bounded source, type, ownership, runtime-cleanup, and measurement claims. It does not claim complete production resource coverage, selected production budgets, a production session mint, or WebRTC internal accounting.

## Run the focused gate

```powershell
$arc02Target = "C:\Users\Admin\.allmystuff-sandbox-stage\myownmesh-v4-arc02c-target"
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
Invoke-Checked { cargo clippy --workspace --all-targets -j 16 -- -D warnings }
Invoke-Checked { cargo test -p myownmesh-core --lib v4_arc02 -j 16 -- --nocapture }
Invoke-Checked { cargo test -p myownmesh-core --doc -j 16 }
Invoke-Checked { python scripts/check-v4-arc02-compiler-boundaries.py }
Invoke-Checked { python scripts/check-v4-arc02-spine.py }
Invoke-Checked { python scripts/check-v4-arc02-spine.py --negative-controls }
Invoke-Checked { python scripts/check-v4-arc01-inventory.py }
Invoke-Checked { python scripts/check-v4-arc01-inventory.py --negative-controls }
```

The compiler harness creates a temporary offline Cargo project. The source and mutation checks start no listener.

## 1. Peer owner attacks

### RT-02C-01: bypass the registry

Attack: restore a public `DashMap<String, Arc<PeerConnection>>` on `NetworkState`, or mutate the inner map outside `PeerRegistry`.

Expected result: the source gate rejects the raw owner or escaped mutation.

Reason: no caller may replace, remove, or clear a peer without retiring its compatibility queue.

### RT-02C-02: replace without retirement

Attack: replace a peer and retain an external `Arc` to the old peer while skipping `discard_pending_remote_candidates`.

Expected result: the mutation gate rejects the missing retirement. The runtime replacement test requires active candidate use to return to zero while the old `Arc` remains alive.

### RT-02C-03: remove without retirement

Attack: remove a peer, retain the returned and external `Arc` values, and skip queue retirement.

Expected result: the mutation gate and removal runtime test fail the attack.

### RT-02C-04: clear or shut down without retirement

Attack: clear the registry without visiting every current peer first.

Expected result: the mutation gate rejects the clear. `v4_arc02_shutdown_retires_queue_while_external_peer_arc_survives` holds an external peer `Arc`, calls `NetworkState::shutdown`, and requires the network-instance candidate report to return to zero.

### RT-02C-05: copy live peer ownership

Attack: restore `PeerStateData: Clone`, expose the pending queue, or add the queue to `PeerStateSnapshot`.

Expected result: the source and mutation gates reject each change. The public snapshot may copy diagnostic values, but not mutable queue ownership or observation leases.

## 2. Observer attacks

### RT-02C-06: grow metadata per active lease

Attack: restore a `BTreeMap<Instant, ...>`, `Vec`, or another active-lease collection in `FamilyState`.

Expected result: the source gate requires fixed arrays for closed families and constant-space family metadata. The mutation gate inserts an active timestamp map and must reject it.

### RT-02C-07: restore the hierarchy hot-path mutex

Attack: add a transaction mutex to `ResourceAccountant` or a shared `Hierarchy` lock around rollup updates.

Expected result: the source gate rejects the observer shape. Diagnostic cross-scope snapshots do not require global linearizability.

### RT-02C-08: claim an unknown oldest lifetime

Attack: report the start of a remaining lease after the previously oldest lease ends without storing enough information to know it.

Expected result: `v4_arc02_bounded_oldest_tracking_stops_claiming_exactness` requires `oldest_active_lifetime` to become `None` and `oldest_active_lifetime_inexact` to become true while another lease remains.

### RT-02C-09: panic on measurement overflow

Attack: add `expect`, `unwrap`, or `panic!` to production resource measurement.

Expected result: the source and mutation gates reject the panic path. Runtime controls require saturation and an inexact report for overflow or unsupported measurement.

### RT-02C-10: conflate logical and retained bytes

Attack: derive both axes from string length, omit string capacity, or omit queue-container capacity.

Expected result: the candidate measurement controls fail. Candidate values and container storage remain separate observations.

### RT-02C-11: skip an aggregation owner

Attack: skip the process root or another ancestor during a leaf update.

Expected result: the hierarchy mutation and four-scope runtime test fail. Sibling network instances must remain isolated at their own reports.

### RT-02C-12: misstate network-instance attribution

Attack: rename the live network-instance scope to an exact Mesh Context without binding an immutable context identity, or infer carrier, ingress, attempt, or known-origin identity from that rollup path.

Expected result: architecture review fails. The source gate requires `NetworkInstanceResourceScope`; orthogonal attribution needs its own typed owner.

## 3. Attempt reservation attacks

### RT-02C-13: consume the attempt into the first candidate

Attack: store `PreAuthAttemptPermit` directly inside `CandidateCapability`.

Expected result: the protected authority field shape changes and the source gate rejects it. The runtime control requires two simultaneous candidate children from one attempt aggregate.

### RT-02C-14: allocate before reservation

Attack: invoke the allocation closure and ask the aggregate for a child afterward.

Expected result: the source gate rejects the ordering. `v4_arc02_candidate_allocation_runs_only_after_child_reservation` observes an active child from inside the allocation closure and proves that a refused claim never calls the closure.

### RT-02C-15: lose exact attempt ownership

Attack: replace the candidate's local `Arc<AttemptOwnership>` with a peer string, runtime value alone, or another public label.

Expected result: the protected field shape and public-ID conversion controls reject it. Runtime tests use `Arc::ptr_eq` to verify the issuing attempt and aggregate.

### RT-02C-16: exceed the aggregate

Attack: issue a child whose componentwise claim would exceed the attempt capacity.

Expected result: child creation returns `None`, the allocation closure does not run, and active reservation state does not exceed capacity.

### RT-02C-17: reopen capacity after an inconsistent release

Attack: keep two child reservations live, corrupt aggregate active use below one child's claim, and drop that child. Then drop the remaining child or request another admission.

Expected result: the first inconsistent release preserves the last active value and poisons the aggregate. The second release cannot reduce that value, and every later admission is refused.

## 4. Candidate observation attacks

### RT-02C-18: clone the inbound candidate

Attack: clone the candidate into the pending queue.

Expected result: the source mutation rejects the clone. Queueing and draining move the candidate and its lease.

### RT-02C-19: end observation before asynchronous application

Attack: drop the candidate observation before `add_ice_candidate(...).await` completes.

Expected result: source order and runtime success, failure, and cancellation controls fail the attack.

### RT-02C-20: mistake the raw API for a guarded port

Attack: claim complete candidate admission because the two current engine call sites use the observation helper, while `PeerSession::add_ice_candidate(LocalIceCandidate)` remains public.

Expected result: review fails. Arc 02C records this as a temporary bypass. Arc 03 must make the port connector-private and capability-consuming. The checker is not expanded to hide this API fact.

## 5. Authority attacks retained from Arc 02A

The same compiler and mutation suites continue to reject:

- public capability fields or constructors;
- public-ID conversions;
- `Clone`, `Copy`, serialization, deserialization, or `Default` for authority types;
- wrapped, aliased, raw-identifier, parenthesized, macro-generated, attribute-generated, descendant-module, or second-implementation mints;
- alternate runtime witness constructors;
- raw legacy adapter extraction;
- crate-root, module-path, conditional-module, or Cargo library-target redirection;
- a working connected channel used as a promoted session.

## 6. Full repository and platform gate

The corrective commit also requires:

```powershell
Invoke-Checked { cargo test --workspace --no-fail-fast -j 16 }
Invoke-Checked { cargo test -p myownmesh-core --test two_peer_handshake -j 16 -- --nocapture }
Invoke-Checked { cargo test -p myownmesh-signaling --tests -j 16 }
Invoke-Checked { cargo test -p myownmesh-core transport::webrtc::tests -j 16 }
$env:MYOWNMESH_ARC02_BENCH_ITERATIONS = "100000"
Invoke-Checked { cargo test --release -p myownmesh-core --lib v4_arc02_observer_overhead_measurement -j 16 -- --ignored --nocapture }
Invoke-Checked { cargo test --release -p myownmesh-core --lib v4_arc02_candidate_observer_metadata_measurement -j 16 -- --ignored --nocapture }
Remove-Item Env:\MYOWNMESH_ARC02_BENCH_ITERATIONS
```

The benchmark iteration count is a recorded measurement workload, not a production budget or pass threshold. Supported-platform CI remains the authority for Linux x86-64, macOS arm64, Windows x86-64, riscv64 musl, and aarch64 musl.

### Recorded corrective run

The local corrective gate ran on 2026-08-01 from base commit `b0134d446ae94bc3b5e6e730c8019b924765d416`.

| Environment | Checked result |
|---|---|
| Windows 11 Pro 10.0.26200, x86-64, Rust 1.88.0 | Format, workspace all-target check, workspace all-target Clippy with warnings denied, focused Arc 02 runtime tests, doctests, compiler boundaries, source gates, mutation controls, and release observer measurements passed. |
| Ubuntu 24.04 under WSL2, x86-64, Rust 1.88.0 | Complete workspace tests, the two-peer handshake and channel exchange, signaling tests, mDNS discovery, self-hosted relay tests, and WebRTC data, Opus, and H.264 tests passed. |
| Supported-platform CI | Must run against the pushed corrective revision. Local results do not substitute for the GitHub platform matrix. |

The Windows release observer measurement used an Intel Core i9-10850K with 10 cores and 20 logical processors. Three 100,000-operation samples measured one four-scope begin plus drop at 244 ns, 234 ns, and 241 ns per operation. These are raw samples, not a performance requirement.

The exact source after the fail-closed aggregate correction produced one additional 100,000-operation sample at 322 ns per operation. It is kept separate because it is one sample, not an extension of the earlier three-sample run.

The same optimized binary reported these fixed in-memory sizes in bytes:

| Type or fixed state | Bytes |
|---|---:|
| Family observation state | 168 |
| One scope state for all closed families | 5,384 |
| One locked scope inner value | 5,392 |
| Resource accountant handle | 24 |
| Observation lease | 88 |
| Local ICE candidate header | 80 |
| Candidate observation lease wrapper | 88 |
| Pending candidate plus observation | 168 |
| Pending candidate queue header | 112 |
| Pending candidate drain header | 120 |
| Empty vector header used by the queue | 24 |

String allocations and spare vector capacity remain separate retained-byte observations. The header sizes do not claim total heap retention. No measured number in this section selects a capacity or pass threshold.

## 7. Pass meaning

A complete pass proves only the checked revision and named runtime paths. It does not prove:

- a selected numeric resource budget;
- full production resource admission;
- every frame, parser, socket, ICE, STUN, TURN, DNS, callback, task, timer, relay, or WebRTC allocation is guarded;
- WebRTC internal retained memory is measured;
- the raw candidate API is connector-private;
- a production `ConnectedChannelCapability` exists;
- Arc 03 is complete.
