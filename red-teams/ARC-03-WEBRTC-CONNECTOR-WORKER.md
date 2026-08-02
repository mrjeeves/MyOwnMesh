# Arc 03 WebRTC connector ownership red team

Status: executable review record for draft PR #112. Passing these controls does not authorize merge or select a production resource budget.

## 1. Socket-free Windows gate

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\Admin\.allmystuff-sandbox-stage\cargo-target-myownmesh-v4-arc03"
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

cargo fmt --all -- --check
cargo check --workspace --all-targets -j 16
cargo clippy --workspace --all-targets -j 16 -- -D warnings
cargo test -p myownmesh-core --lib v4_arc03_ -j 16 -- --nocapture --test-threads=1
cargo test -p myownmesh-core --lib v4_arc02_attempt_issues_multiple_candidate_children_from_one_aggregate -j 16 -- --nocapture
cargo test -p myownmesh-core --lib v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed -j 16 -- --nocapture
python scripts/check-v4-arc03-compiler-boundaries.py
```

These controls open no listener and change no firewall rule. Socket-bearing tests run under Ubuntu 24.04 in WSL2.

## 2. Real WebRTC controls in WSL

```powershell
$repo = "/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition"
$target = "/tmp/myownmesh-v4-arc03-wsl"

wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_cancelled_construction_closes_partial_native_peer -- --ignored --nocapture --test-threads=1"
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_cancelled_delivered_result_closes_native_peer_before_release -- --ignored --nocapture --test-threads=1"
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_construction_runtime_shutdown_is_bounded_and_fail_closed -- --ignored --nocapture --test-threads=1"
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_background_construction_failure_closes_partial_native_peer -- --ignored --nocapture --test-threads=1"
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives -- --ignored --nocapture --test-threads=1"
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_stale_transport_event_cannot_mutate_replacement_worker -- --ignored --nocapture --test-threads=1"
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_offerer_observes_data_channel_handlers -- --ignored --nocapture --test-threads=1"
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-services --test turn_webrtc_endpoint_auth -- --nocapture --test-threads=1"
```

The TURN control must select Relay-to-Relay pairs. The positive path authenticates before admission and carries typed endpoint data in both directions. The negative path authenticates without bilateral admission and rejects endpoint data, lane creation, and real-time sample delivery.

## 3. RT-03-01: self-issued resource capacity

Attack: let an attempt create the capacity that admits its own connector.

Required result: `admit_single_connector_candidate` can define only the structural claim. Reservation requires an injected `ConnectorResourceOwnerPort`. No production default or inferred capacity exists.

Controls:

- `v4_arc03_reservation_precedes_allocation_and_retirement_fences_result`;
- `v4_arc03_connector_candidate_claim_rejects_zero_and_mislabeled_resources`;
- compiler-boundary checker;
- source check for `Transport::with_connector_resource_owner` before admitted construction.

## 4. RT-03-02: cancel partial or delivered construction

Attack: cancel after native allocation, after result delivery, during caller-runtime shutdown, or after the owned construction task fails.

Required result: one cleanup owner follows every result. Callback authority retires, partial work is fenced, native close is attempted once, and the reservation releases only after proven close success.

Controls:

- `v4_arc03_cancelled_construction_closes_partial_native_peer` in WSL;
- `v4_arc03_cancelled_delivered_result_closes_native_peer_before_release` in WSL;
- `v4_arc03_construction_runtime_shutdown_is_bounded_and_fail_closed` in WSL;
- `v4_arc03_background_construction_failure_closes_partial_native_peer` in WSL;
- `v4_arc03_cleanup_owner_outlives_caller_runtime_shutdown`;
- `v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed`.

## 5. RT-03-03: fail or stall native close

Attack: return a close error, never complete close, fail cleanup startup, or add duplicate connected claims after poison.

Required result: the owner reaches a terminal visible poison state within its configured deadline. The process resource report stays consumed and poisoned. Later admission fails. No claim is forgotten or silently reused.

Controls:

- `v4_arc03_native_close_error_poison_is_visible_and_refuses_reuse`;
- `v4_arc03_native_close_timeout_is_bounded_visible_and_fail_closed`;
- `v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed`;
- `v4_arc03_duplicate_connected_claims_remain_explicit_when_cleanup_poisoned`;
- source search rejecting `mem::forget` in Arc 03 ownership code.

## 6. RT-03-04: deadlock promotion and retirement

Attack: retire the attempt or connector at each transition point around promotion.

Required result: connector authority and attempt transition are never nested. Each race has one linearized winner, and the losing candidate is cleaned.

Controls:

- `v4_arc03_promotion_does_not_nest_connector_and_attempt_transitions`;
- `v4_arc03_promotion_and_retirement_have_one_linearized_order`;
- `v4_arc03_connector_retirement_before_promotion_rejects_and_cleans`;
- `v4_arc03_attempt_retirement_preserves_winner_and_invalidates_awaiting_loser`.

## 7. RT-03-05: reorder Endpoint Auth handoff and close

Attack: release Endpoint Auth provenance before native close, close before that handoff releases, or retire the peer while an external owner survives.

Required result: the exact connected claim remains visible until both native cleanup and handoff ownership allow release. No ordering double-releases or hides it.

Controls:

- `v4_arc03_endpoint_handoff_release_before_native_close_releases_once`;
- `v4_arc03_native_close_before_endpoint_handoff_release_keeps_claim_visible`;
- `v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives` in WSL.

## 8. RT-03-06: smuggle callback backlog

Attack: fill one callback class, prequeue stale events, block a producer, then retire or replace the connector.

Required result: each callback class has its own owner-selected bound. Filling one class cannot consume another class's mailbox. Full-mailbox producers wake on retirement. Exact incarnation stamps reject stale events.

Controls:

- `v4_arc03_control_callback_contention_honors_configured_bound`;
- `v4_arc03_data_callback_contention_honors_configured_bound`;
- `v4_arc03_audio_callback_contention_honors_configured_bound`;
- `v4_arc03_video_callback_contention_honors_configured_bound`;
- the four callback-capacity independence tests;
- `v4_arc03_retirement_wakes_producer_blocked_by_full_callback_queue`;
- `v4_arc03_retirement_stops_event_pump_before_stale_callback_queueing`;
- `v4_arc03_stale_transport_event_cannot_mutate_replacement_worker` in WSL.

These tests prove shape and enforcement, not operational sufficiency. The owner must measure workload-specific capacities. The current biased receive order also needs measurement under mixed sustained load.

The ignored measurement requires owner-supplied inputs and reports each class separately:

```powershell
$env:MYOWNMESH_ARC03_CALLBACK_CAPACITY = "<owner-supplied>"
$env:MYOWNMESH_ARC03_CALLBACK_SAMPLES = "<owner-supplied>"
cargo test -p myownmesh-core --lib v4_arc03_measure_callback_classes_without_selecting_a_budget -- --ignored --nocapture --test-threads=1
```

## 9. RT-03-07: retain remote candidates

Attack: retain pre-SDP candidates through cancellation, replacement, or shutdown.

Required result: the connector owns the queue and observation lease. Retirement drains queued items and cancels local apply awaits. Dependency side effects completed before cancellation are not claimed rolled back.

Controls:

- `v4_arc03_candidate_queue_is_connector_owned_and_observed`;
- `v4_arc03_candidate_apply_observation_survives_await_and_cancellation`;
- `v4_arc03_retirement_cancels_inflight_candidate_observation`.

Residual: the queue is observed but does not yet have an owner-approved item or retained-byte admission limit.

## 10. RT-03-08: carry one undifferentiated reservation

Attack: keep construction-only claims after connection or reopen capacity after inconsistent subtraction.

Required result: promotion atomically transfers opening resources to connected resources. Inconsistent release poisons the owner and preserves conservative use.

Controls:

- `v4_arc03_promotion_atomically_releases_candidate_only_claims`;
- `v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed`;
- `v4_arc03_resource_families_cannot_substitute_for_each_other`.

## 11. RT-03-09: bypass Endpoint Auth provenance

Attack: replay `DataChannelOpen`, use a task from another connector, start the handshake from the raw engine arm, or retain provenance after retirement.

Required result: one exact live candidate produces one connected capability. The engine hands it to the exact Endpoint Auth task before authentication begins. Duplicate, stale, or cross-connector values fail.

Controls:

- `v4_arc03_data_channel_open_requires_live_exact_candidate`;
- `v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability`;
- `v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives` in WSL;
- compiler-boundary checker.

Arc 03 proves provenance ownership only. It does not claim Endpoint Auth resource admission or transcript verification.

## 12. RT-03-10: use worker possession as real-time authority

Attack: call lane or real-time send operations with only `&WebRtcConnectorWorker`, use a capability from another connector, or activate delivery before session admission.

Required result: the narrow worker methods require the exact codec-neutral `ConnectorRealtimeFlowCapability`. The temporary legacy issuer checks current peer admission and exact Endpoint Auth provenance.

Controls:

- core relay-selection negative control;
- `v4_arc03_outbound_application_send_requires_current_session_admission`;
- TURN unapproved-session negative control in WSL;
- source checker for capability-consuming lane, send, and reaper signatures;
- stale-owner and shutdown controls.

`LaneKind`, H.264, Opus, video, and audio remain in the compatibility adapter. They are not basal capability semantics.

## 13. RT-03-11: activate through a stale owner

Attack: replace owner A with B at roster persistence, then let A finish authentication or approval.

Required result: A cannot persist roster membership, broadcast governance, resolve waiters, clear reconnect state, flush application frames, or emit approval for B.

Controls:

- `v4_arc03_replacement_before_roster_persistence_cancels_activation_commit`;
- `v4_arc03_stale_message_owner_cannot_mutate_replacement_peer`;
- `v4_arc03_reliable_flush_requires_authenticated_admission`;
- `v4_arc03_current_effect_linearizes_before_replacement`.

## 14. RT-03-12: manufacture consent

Attack: treat local connector send success as proof of remote approval.

Required result: only inbound `Approve` records remote consent. Authentication, local send acceptance, and inbound approval must converge on the same exact owner.

Controls:

- `v4_arc03_remote_approve_before_local_send_acceptance_converges`;
- `v4_arc03_local_approve_without_remote_consent_stays_pending`.

## 15. RT-03-13: treat TURN selection as authority

Attack: use Relay-to-Relay pair selection as endpoint identity, session admission, or real-time-flow admission.

Required result: selected-pair diagnostics grant no authority. The positive TURN path still requires endpoint authentication and bilateral admission. The negative TURN path remains connected and authenticated but cannot deliver endpoint data or real-time work without admission.

Controls:

- `v4_arc03_relay_selection_is_not_authentication_or_session_admission`;
- `turn_selected_session_authenticates_endpoints_before_bidirectional_data` in WSL.

TURN remains an ICE carrier for one endpoint session. Signaling remains signaling-only.

## 16. Compiler boundary

`python scripts/check-v4-arc03-compiler-boundaries.py` must prove the expected privacy or visibility cause for each negative compile probe. An unrelated compiler error is not a pass.

The checker covers raw candidate application, external worker construction, raw peer constructors in the default API, non-cloneable ownership state, capability production boundaries, and all six real-time-flow consumer signatures.

## 17. Preservation matrix

Before merge approval, the exact pushed head must pass:

- workspace formatting, check, Clippy, tests, and doctests;
- direct two-peer handshake and typed data;
- real TURN-selected endpoint data and its negative controls;
- mDNS and Nostr signaling;
- reconnect and recovery;
- data channel, H.264, Opus, and native RTP controls;
- Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl CI.

A skipped test is reported as skipped, not passed.

## 18. Review blockers

Reject these claims on Arc 03:

- complete hostile-ingress resource admission;
- complete retained-memory or dependency-owned resource accounting;
- bounded pre-SDP candidate admission;
- an operational callback capacity selected from the structural tests;
- Endpoint Auth transcript verification or resource admission;
- supported-platform preservation before exact-head CI;
- removal of unrelated legacy payload routing elsewhere in the repository.
