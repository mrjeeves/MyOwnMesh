# Arc 03 WebRTC Connector Worker Red Team

Status: executable catalog for the first Arc 03 ownership slice. Passing this file does not mark Arc 03 complete.

## 1. Socket-free Windows gate

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\Admin\.allmystuff-sandbox-stage\cargo-target-myownmesh-v4-arc03"
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

cargo fmt --all -- --check
cargo check -p myownmesh-core --all-targets -j 16
cargo clippy -p myownmesh-core --all-targets -j 16 -- -D warnings
cargo test -p myownmesh-core --lib v4_arc03 -j 16 -- --nocapture --test-threads=1
cargo test -p myownmesh-core --lib v4_arc02_attempt_issues_multiple_candidate_children_from_one_aggregate -j 16 -- --nocapture
cargo test -p myownmesh-core --lib v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed -j 16 -- --nocapture
python scripts/check-v4-arc03-compiler-boundaries.py
```

These controls open no listener and change no firewall rule. The compiler script builds an external temporary crate. It requires the raw candidate call to fail as private and worker construction to fail as non-public for the expected compiler causes.

`check-v4-arc02-spine.py` is intentionally not a current-head gate. It fingerprints the frozen Arc 02 type names and ownership sites that Arc 03 is replacing. The frozen parent remains `0484f7f0987e5d1c488b30ac21e46f1925ea65cb`; the two named Arc 02 behavior controls above run again on this head to prove the preserved aggregate properties.

## 2. Real WebRTC controls in WSL

These tests create local `RTCPeerConnection` objects. Run them in Ubuntu 24.04 under WSL2 so Windows does not show a firewall prompt.

```powershell
wsl.exe -d Ubuntu-24.04 -- bash -lc "cd '/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition' && CARGO_TARGET_DIR=/tmp/myownmesh-v4-arc03-target cargo test -p myownmesh-core --lib v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives -- --ignored --nocapture --test-threads=1"

wsl.exe -d Ubuntu-24.04 -- bash -lc "cd '/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition' && CARGO_TARGET_DIR=/tmp/myownmesh-v4-arc03-target cargo test -p myownmesh-core --lib v4_arc03_offerer_observes_data_channel_handlers -- --ignored --nocapture --test-threads=1"

wsl.exe -d Ubuntu-24.04 -- bash -lc "cd '/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition' && CARGO_TARGET_DIR=/tmp/myownmesh-v4-arc03-target cargo test -p myownmesh-core --lib v4_arc03_stale_transport_event_cannot_mutate_replacement_worker -- --ignored --nocapture --test-threads=1"

wsl.exe -d Ubuntu-24.04 -- bash -lc "cd '/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition' && CARGO_TARGET_DIR=/tmp/myownmesh-v4-arc03-target cargo test -p myownmesh-core --lib silent_active_session_rebuilt_on_reannounce -- --ignored --nocapture --test-threads=1"

wsl.exe -d Ubuntu-24.04 -- bash -lc "cd '/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition' && CARGO_TARGET_DIR=/tmp/myownmesh-v4-arc03-target cargo test -p myownmesh-core --lib probe_answered_by_traffic_keeps_the_session -- --ignored --nocapture --test-threads=1"
```

The shutdown control retains external peer and worker `Arc`s, then verifies queue release, registry removal, and rejection of later candidate input. The replacement control retains worker A, installs worker B under the same device id, waits for A's dependency state to become `Closed`, and replays A's stamped open event against B.

The observation fixtures print the instrumented counts. They are not complete dependency allocation reports.

The final revision also reran `silent_active_session_rebuilt_on_reannounce` and `probe_answered_by_traffic_keeps_the_session` in WSL. Both passed.

## 3. RT-03-01: confuse ICE input with connector authority

Attack: treat one `LocalIceCandidate` as one `ConnectorCandidateCapability`.

Expected result: the types remain distinct. No public conversion exists. A connector capability names a complete peer-connection candidate.

Controls:

- external compiler boundary script;
- `v4_arc03_connector_candidate_claim_rejects_zero_and_mislabeled_resources`;
- `v4_arc02_attempt_issues_multiple_candidate_children_from_one_aggregate`.

## 4. RT-03-02: retire before promotion

Attack: retain several candidate capabilities, retire the attempt, then promote one.

Expected result: every candidate still awaiting in that race becomes inactive. Later allocation and promotion fail.

Controls:

- `v4_arc03_attempt_retirement_invalidates_every_connector_candidate`;
- `v4_arc03_retired_attempt_refuses_later_candidate_allocation`;
- `v4_arc03_connected_channel_rejects_retired_attempt`;
- `v4_arc03_rejected_open_retires_callback_admission`.

## 5. RT-03-03: retire after promotion

Attack: promote candidate A, leave candidate B awaiting, then retire the attempt race.

Expected result: A remains the connected-channel winner. B cannot accept another event or promote.

Control: `v4_arc03_attempt_retirement_preserves_winner_and_invalidates_awaiting_loser`.

Open attack: attempt retirement does not yet wake a silent awaiting worker, drain its queue, cancel its in-flight dependency work, close its native peer connection, or release its reservation. Production admission must remain disabled until that signal is wired and tested.

## 6. RT-03-04: cross the channel authority boundary

Attack: deliver protocol bytes before `DataChannelOpen`, or treat a connected-channel capability as media authority.

Expected result: the admitted state rejects protocol bytes before promotion. It allows protocol bytes after promotion only so endpoint authentication can consume them. It rejects media in both admitted states.

Control: `v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability`.

Production remains on the legacy compatibility state, so this control is an enabling-path proof, not production enforcement.

## 7. RT-03-05: substitute resource families

Attack: pay for a candidate with unused capacity from another family, or claim zero or multiple transport objects.

Expected result: componentwise admission rejects substitution and invalid transport cardinality.

Controls:

- `v4_arc03_resource_families_cannot_substitute_for_each_other`;
- `v4_arc03_connector_candidate_claim_rejects_zero_and_mislabeled_resources`.

Open attack: one transport item with omitted or false ICE, callback, task, queue, and byte quantities still passes the scaffold constructor. It is not a production permit.

## 8. RT-03-06: reopen a corrupted aggregate

Attack: corrupt active aggregate state below a live child's claim, release that child, and request another reservation.

Expected result: the aggregate becomes poisoned, keeps conservative consumption, and refuses later admission.

Control: `v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed`.

Actual `std::sync::Mutex` poison behavior is source-audited but does not yet have a panic-based executable control.

## 9. RT-03-07: retain or race remote candidates

Attack: retain a queued candidate through replacement or shutdown, or cancel while candidate application is pending.

Expected result: explicit worker retirement drains the queue. The first-polled application future loses its local observation when retirement wins. Later input is rejected.

Controls:

- `v4_arc03_candidate_queue_is_connector_owned_and_observed`;
- `v4_arc03_candidate_apply_observation_survives_await_and_cancellation`;
- `v4_arc03_retirement_cancels_inflight_candidate_observation`;
- WSL shutdown control.

Open attack: queue insertion and retirement have a source-defined lock order, but no contention test executes both orders. Cancellation does not prove rollback of dependency side effects.

## 10. RT-03-08: replay a stale worker event

Attack: replay worker A's stamped event after worker B replaces it under the same device id.

Expected result: worker identity and registry installation identity reject A. B remains unchanged. A's native peer connection receives a close request.

Controls:

- `v4_arc03_callback_stamp_requires_exact_live_worker`;
- `v4_arc03_stale_transport_event_cannot_mutate_replacement_worker` in WSL;
- `v4_arc03_stale_message_owner_cannot_mutate_replacement_peer`.

## 11. RT-03-09: revive an old owner token

Attack: replace a peer, reinstall the same retired peer object, or reinstall the current object.

Expected result: each real installation has a fresh stamp. A retired object is rejected. Installing the current object is idempotent. Old tokens cannot remove or mutate the current installation.

Controls:

- `v4_arc03_stale_owner_cannot_remove_replacement_peer`;
- `v4_arc03_retired_peer_arc_cannot_be_reinstalled`;
- `v4_arc03_installing_current_peer_arc_is_idempotent`;
- `v4_arc03_current_effect_linearizes_before_replacement`.

## 12. RT-03-10: bypass the worker

Attack: call raw candidate application or construct the internal worker from an external crate.

Expected result: the compiler rejects both operations for the expected visibility cause.

Control: `python scripts/check-v4-arc03-compiler-boundaries.py`.

Open bypasses:

- public `Transport::open_peer` constructors;
- internal `Deref<PeerSession>`;
- production `CompatibilityBypass`.

## 13. RT-03-11: hide unsupported measurements

Attack: overflow a platform-sized conversion or claim exact retained sizes that the dependency does not expose.

Expected result: conversion saturates without panic and marks the observation inexact. WSL observations remain visibly inexact.

Controls:

- `v4_arc03_unsupported_candidate_measurement_is_inexact_not_a_panic`;
- both WSL observation fixtures.

Open reporting defect: one family-specific inexact measurement currently marks every family at that scope inexact.

## 14. RT-03-12: deadlock registry scans or exact effects

Attack: replace a registry entry from a scan callback, or race replacement with an exact-owner effect.

Expected result: scan callbacks run after DashMap guards are released. Replacement waits for an exact-owner synchronous effect and cannot redirect it into the new peer.

Controls:

- `v4_arc03_registry_scan_releases_map_guard_before_peer_callback`;
- `v4_arc03_current_effect_linearizes_before_replacement`.

The scan test uses a two-second harness watchdog. It is not a runtime threshold or service limit.

## 15. RT-03-13: manufacture approval or activate a replacement

Attack: treat a successful local approval send as proof that the peer approved, or replay an old owner's completed approval facts against a replacement connection.

Expected result: only an inbound `Approve` records remote consent. A successful local send records only local data-channel acceptance and re-evaluates the exact current owner. It cannot prove remote receipt or set the remote-consent fact. Activation requires authentication, local send acceptance, and actual remote approval on the same current owner. Approved events, waiter completion, and reliable outbox sends remain bound to that owner.

Controls:

- `v4_arc03_remote_approve_before_local_send_acceptance_converges`;
- `v4_arc03_local_approve_without_remote_consent_stays_pending`;
- `v4_arc03_stale_owner_cannot_activate_replacement`;
- `v4_arc03_reliable_flush_requires_authenticated_admission`;
- `v4_arc03_stale_message_owner_cannot_mutate_replacement_peer`.

## 16. Peer-scan measurement

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\Admin\.allmystuff-sandbox-stage\cargo-target-myownmesh-v4-arc03"
$env:MYOWNMESH_ARC03_PEER_SCAN_COUNTS = "5,24,32"
$env:MYOWNMESH_ARC03_PEER_SCAN_ROUNDS = "10000"

cargo test -p myownmesh-core --release v4_arc03_peer_registry_scan_scaling -- --ignored --nocapture --test-threads=1
```

The peer counts come from existing repository fixtures. The repetition count is measurement workload only.

Four preliminary release-mode observations, one pre-hardening observation, and one final frozen-revision observation were collected on Windows 11 Pro with Rust 1.88.0 and an Intel Core i9-10850K. Values below are nanoseconds per peer. Each pair is `legacy,specialized` for counts `5`, `24`, and `32` respectively.

```text
run 1: 2069.248,2166.102 | 522.730,501.118 | 522.466,476.822
run 2: 2366.842,2126.984 | 603.537,602.984 | 598.253,491.139
run 3: 2466.060,2251.156 | 673.573,759.556 | 579.594,435.551
run 4: 2227.458,2462.536 | 747.085,569.369 | 553.433,581.175
run 5, before final approval hardening: 1718.248,1998.390 | 552.825,462.955 | 389.503,374.491
run 6, final frozen revision: 1816.284,1884.766 | 516.957,502.551 | 416.283,368.217
```

The complete test output also verified the expected peer cardinality on every iteration. Results vary in both directions at these small fixture sizes, so they do not justify a performance claim. No pass threshold is selected here.

The ignored metadata-size control reported `LocalIceCandidate=80`, `CandidateObservationLease=88`, `PendingRemoteCandidate=168`, `PendingRemoteCandidateQueue=112`, `PendingRemoteCandidateDrain=120`, and `Vec` header `=24` bytes on the same target. These are Rust value sizes, not complete retained-memory measurements for dependency-owned allocations.

## 17. Hostile-input cases that must still fail review

The following attacks do not yet have an acceptable production control:

- fill the raw callback queue with data or media before retirement;
- fill the global engine command queue with stamped stale payloads;
- cancel an attempt while asynchronous peer allocation is partially complete;
- cancel an awaiting attempt with no later event and observe whether all work stops;
- force repeated replacement or removal and accumulate native close tasks;
- make one dependency close stall sequential shutdown;
- use the public raw transport constructors to bypass Arc 03 ownership;
- rely on family reports after one unrelated inexact measurement;
- send media through the legacy compatibility path before the future provider and authenticated application gate are separated.

Arc 03 production admission must stay disabled while these remain open.

## 18. Preservation gate

Before merge approval, the pushed revision must pass:

- complete workspace formatting, check, Clippy, tests, and doctests;
- the existing two-peer handshake integration test;
- direct and TURN connector controls;
- mDNS and Nostr signaling controls;
- reconnect and recovery controls;
- data-channel, H.264, Opus, and native RTP controls;
- supported-platform CI.

Source inspection confirms that the existing components remain present. It does not prove behavior preservation. No end-to-end WebRTC-over-TURN test was found during this slice, so TURN preservation must not be overstated.

### Final branch observations

The final isolated Ubuntu 24.04 run passed the complete workspace test and doctest suite. It also passed ten consecutive `two_peers_handshake_over_mdns_only` runs and all five explicit WebRTC or reconnection controls listed above. Windows formatting, workspace check, Clippy, doctests, compiler-boundary controls, and the focused Arc 02 and Arc 03 controls are separate gates.

An earlier cold Linux workspace run produced one timeout in `two_peers_handshake_over_mdns_only`, and one of three immediate workspace-filtered repetitions also timed out. The retained output did not identify whether discovery, directed signaling, handshake, approval delivery, or replacement stalled. The test now retains a bounded event and connection-trace history plus final peer state when it times out.

Source review during that investigation found two concrete approval-state defects: a successful local send did not re-evaluate an earlier remote approval, while reusing the old inbound handler would have manufactured remote consent. The final code separates remote-consent recording from activation evaluation and adds exact-owner controls. The later passes establish the final branch result, but they do not prove that either source defect caused the earlier carrier timeout.
