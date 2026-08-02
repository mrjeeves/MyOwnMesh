# Arc 03 WebRTC connector ownership red team

Status: executable review record for draft PR #112. Passing these controls does not authorize merge or select a production resource budget.

## 1. Socket-free Windows gate

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\Admin\.allmystuff-sandbox-stage\cargo-target-myownmesh-v4-arc03"
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

cargo fmt --all -- --check
cargo check --workspace --all-targets -j 16
cargo clippy --workspace --all-targets -j 16 -- -D warnings
cargo test -p myownmesh-core --lib v4_arc03 -j 16 -- --nocapture --test-threads=1
cargo test -p myownmesh-core --lib v4_arc02_attempt_issues_multiple_candidate_children_from_one_aggregate -j 16 -- --nocapture
cargo test -p myownmesh-core --lib v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed -j 16 -- --nocapture
python scripts/check-v4-arc03-compiler-boundaries.py
```

These controls open no listener and change no firewall rule. Real socket tests run under Ubuntu 24.04 in WSL2.

## 2. Real WebRTC controls in WSL

Set the repository and target directory once:

```powershell
$repo = "/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition"
$target = "/tmp/myownmesh-v4-arc03-wsl"
```

Run the ownership and cancellation controls:

```powershell
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_cancelled_construction_closes_partial_native_peer -- --ignored --nocapture --test-threads=1"

wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_cancelled_delivered_result_closes_native_peer_before_release -- --ignored --nocapture --test-threads=1"

wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives -- --ignored --nocapture --test-threads=1"

wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_stale_transport_event_cannot_mutate_replacement_worker -- --ignored --nocapture --test-threads=1"

wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_offerer_observes_data_channel_handlers -- --ignored --nocapture --test-threads=1"
```

Run the real TURN-selected endpoint test:

```powershell
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-services --test turn_webrtc_endpoint_auth -- --nocapture --test-threads=1"
```

The TURN control must report one selected Relay-to-Relay candidate pair at each endpoint, observe authentication before approval, and deliver exact typed endpoint data from the expected authenticated sender in both directions.

## 3. RT-03-01: confuse ICE input with connector authority

Attack: treat one `LocalIceCandidate` as one `ConnectorCandidateCapability`, construct a worker externally, or call raw candidate application.

Required result: types and visibility reject each bypass. A connector capability names a complete peer-connection candidate.

Controls:

- `check-v4-arc03-compiler-boundaries.py`;
- `v4_arc03_connector_candidate_claim_rejects_zero_and_mislabeled_resources`;
- `v4_arc02_attempt_issues_multiple_candidate_children_from_one_aggregate`.

## 4. RT-03-02: cancel during native construction

Attack: pause immediately after `RTCPeerConnection` allocation or after the complete result reaches the caller, then cancel the parent.

Required result: attempt retirement fences publication. The owned task closes the partial or completed native peer before releasing its candidate reservation. Callback and task observations return to zero after cleanup.

Controls:

- `v4_arc03_reservation_precedes_allocation_and_retirement_fences_result`;
- `v4_arc03_cancelled_construction_closes_partial_native_peer` in WSL;
- `v4_arc03_cancelled_delivered_result_closes_native_peer_before_release` in WSL.

The existing 30-second connection-attempt window also bounds how long construction can park the network driver. A timed-out owned constructor remains responsible for closing any later result.

## 5. RT-03-03: deadlock promotion and retirement

Attack: acquire connector authority during promotion while another path retires the attempt.

Required result: no path nests connector authority with the attempt-transition mutex. The candidate enters private `Promoting`, releases connector authority, transitions the attempt, then publishes.

Controls:

- `v4_arc03_promotion_does_not_nest_connector_and_attempt_transitions`;
- `v4_arc03_promotion_and_retirement_have_one_linearized_order`.

## 6. RT-03-04: keep losing work alive

Attack: retire an attempt while a losing worker is silent, queued, or awaiting dependency work.

Required result: retirement wakes the receiver, rejects later events, drains remote candidates, cancels local awaits, and closes the native peer. Candidate and connected claims remain held through successful native close. A close error is reported and retains the claim conservatively.

Controls:

- `v4_arc03_attempt_retirement_wakes_and_reclaims_silent_candidate`;
- `v4_arc03_attempt_retirement_invalidates_every_connector_candidate`;
- `v4_arc03_retirement_cancels_inflight_candidate_observation`;
- `v4_arc03_attempt_retirement_preserves_winner_and_invalidates_awaiting_loser`.
- `v4_arc03_retired_candidate_claim_waits_for_cleanup_completion`.

## 7. RT-03-05: smuggle backlog through callbacks

Attack: prequeue a hostile event, block another callback, retire or replace the worker, then drain the engine path.

Required result: the raw callback mailbox retains at most one event. Producers await capacity and wake on retirement. Each worker processes one ordered event handler at a time, outside `NetworkCmd`. Every event retains the exact worker stamp.

Controls:

- `v4_arc03_callback_queue_applies_awaited_backpressure_at_its_floor`;
- `v4_arc03_retirement_wakes_producer_blocked_by_full_callback_queue`;
- `v4_arc03_engine_handoff_allows_one_outstanding_event_per_worker`;
- `v4_arc03_retirement_stops_event_pump_before_stale_callback_queueing`;
- `v4_arc03_stale_transport_event_cannot_mutate_replacement_worker` in WSL;
- shutdown WSL control.

Residual attack: many hostile attempts can create many separately bounded workers. Independently suspended dependency callbacks can also retain payloads outside the mailbox. Arc 03 has no owner-approved anonymous-ingress or process attempt capacity and must not claim process-wide denial-of-service admission.

## 8. RT-03-06: retain or race remote candidates

Attack: retain candidates through replacement or shutdown, or cancel while candidate application is pending.

Required result: the worker owns the queue and observation leases. Retirement drains the queue and cancels the local await. Dependency side effects that completed before cancellation are not claimed rolled back.

Controls:

- `v4_arc03_candidate_queue_is_connector_owned_and_observed`;
- `v4_arc03_candidate_apply_observation_survives_await_and_cancellation`;
- `v4_arc03_retirement_cancels_inflight_candidate_observation`.

Residual attack: the pre-SDP candidate `Vec` is measured but has no owner-approved item or retained-byte admission limit.

## 9. RT-03-07: carry one undifferentiated reservation

Attack: promote a candidate while retaining construction-only resource claims forever, or corrupt aggregate subtraction and reopen capacity.

Required result: promotion atomically transfers the opening claim to the connected claim. Candidate-only work is released. Inconsistent release poisons the aggregate, preserves conservative use, and refuses later admission.

Controls:

- `v4_arc03_promotion_atomically_releases_candidate_only_claims`;
- `v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed`;
- `v4_arc03_resource_families_cannot_substitute_for_each_other`.

Residual attack: the structural claim is not a complete capacity model for dependency-owned sockets, ICE pairs, DNS, STUN, TURN, memory, or tasks.

## 10. RT-03-08: bypass Endpoint Auth Task

Attack: replay or duplicate `DataChannelOpen`, start authentication from the raw engine arm, or retain a connected capability after peer retirement.

Required result: only the exact live candidate can produce one `ConnectedChannelCapability`. A move-only handoff binds it to the exact connector incarnation before it enters `EndpointAuthTask`. A task from another connector in the same runtime is rejected. Peer cleanup releases the task only after native close succeeds.

Controls:

- `v4_arc03_data_channel_open_requires_live_exact_candidate`;
- `v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability`;
- `v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives` in WSL.

## 11. RT-03-09: activate through a stale owner

Attack: replace owner A with B at roster persistence, then let A finish authentication or approval.

Required result: A cannot persist roster membership, broadcast governance, resolve waiters, clear reconnect state, flush application frames, or emit approval for B.

Controls:

- `v4_arc03_replacement_before_roster_persistence_cancels_activation_commit`;
- `v4_arc03_stale_message_owner_cannot_mutate_replacement_peer`;
- `v4_arc03_reliable_flush_requires_authenticated_admission`;
- `v4_arc03_current_effect_linearizes_before_replacement`.

## 12. RT-03-10: manufacture consent

Attack: treat a successful local `Approve` send as proof that the remote peer consented.

Required result: only inbound `Approve` records remote consent. Authentication, local send acceptance, and inbound consent must converge on the same exact current owner.

Controls:

- `v4_arc03_remote_approve_before_local_send_acceptance_converges`;
- `v4_arc03_local_approve_without_remote_consent_stays_pending`.

## 13. RT-03-11: retain native ownership after replacement

Attack: retain external peer and worker `Arc`s, replace or remove the registry owner, then use the retained objects.

Required result: current-owner authority, endpoint-auth capability, queued candidates, and callback acceptance retire. The native peer receives an explicit close request. The retained object cannot be reinstalled.

Controls:

- `v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives` in WSL;
- `v4_arc03_retired_peer_arc_cannot_be_reinstalled`;
- `v4_arc03_installing_current_peer_arc_is_idempotent`;
- `v4_arc03_stale_owner_cannot_remove_replacement_peer`.

## 14. RT-03-12: leak application data across the boundary

Attack: send application or media bytes before exact endpoint authentication and bilateral activation, or carry endpoint payload through signaling.

Required result: the engine admits only endpoint-authentication protocol before activation. Media is discarded before assembly or event creation. TURN remains an ICE carrier for the same endpoint-authenticated session. Signaling never becomes an endpoint data path.

Controls:

- `v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability`;
- `v4_arc03_reliable_flush_requires_authenticated_admission`;
- `turn_webrtc_endpoint_auth` in WSL.

## 15. Compiler boundary

`python scripts/check-v4-arc03-compiler-boundaries.py` requires:

- the positive capability ownership probe to compile;
- raw candidate application to fail for the expected privacy cause;
- external worker construction to fail for the expected visibility cause;
- raw `Transport::open_peer` to be absent from the production API.

The last control covers the default API surface. An explicit `transport-lab` feature remains capable of enabling the lab constructor and must not be represented as an impossible production opt-in.

The script cause-matches each negative control. An unrelated compiler error is not a pass.

## 16. Preservation matrix

Before merge approval, the exact pushed revision must pass:

- workspace formatting, check, Clippy, tests, and doctests;
- direct two-peer handshake and typed data;
- real TURN-selected WebRTC endpoint data;
- mDNS and Nostr signaling;
- reconnect and recovery;
- data channel, H.264, Opus, and native RTP controls;
- the repository's unchanged supported-platform CI matrix.

The supported matrix is Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl compile, and Linux ARM64 musl compile. A skipped mDNS test must be reported as skipped, not passed.

## 17. Review blockers that remain explicit

The following claims must fail review on this arc:

- complete hostile-ingress resource admission;
- process-wide worker or attempt bounds;
- a bounded pre-SDP candidate queue;
- complete retained-memory or dependency-owned resource accounting;
- a production numeric budget selected without owner evidence;
- supported-platform preservation before CI runs on the exact final commit;
- removal of unrelated legacy payload routing elsewhere in the repository.

These residuals do not reopen compatibility access or route authority. They define the exact boundary for the next audit.
