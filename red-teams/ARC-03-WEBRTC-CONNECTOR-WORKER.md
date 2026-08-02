# Arc 03 WebRTC connector ownership red team

Status: executable review record for draft PR #112. Passing these controls does not authorize merge or select a production resource budget.

## 1. Socket-free Windows gate

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\Admin\.allmystuff-sandbox-stage\cargo-target-myownmesh-v4-arc03"
$env:CARGO_INCREMENTAL = "0"
$env:CARGO_PROFILE_DEV_DEBUG = "0"
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

After preserving the logs, remove the dedicated build cache with:

```powershell
cargo clean --target-dir $env:CARGO_TARGET_DIR
```

## 2. Real WebRTC controls in WSL

```powershell
$repo = "/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition"
$target = "/tmp/myownmesh-v4-arc03-wsl"

wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_cancelled_construction_closes_partial_native_peer -- --ignored --nocapture --test-threads=1"
wsl.exe -d Ubuntu-24.04 -e bash -lc "cd '$repo' && CARGO_TARGET_DIR='$target' cargo test -p myownmesh-core --lib v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim -- --ignored --nocapture --test-threads=1"
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

Required result: `admit_single_connector_candidate` can define only the structural claim. `ProcessResourceRoot` installs one connector owner for the process and issues one unforgeable child scope per live Mesh runtime. Admission updates the process aggregate and exact child together. One Mesh cannot consume every process slot unless the owner explicitly gives that child the same ceiling. External code cannot construct either authority. No production default or inferred share exists.

Controls:

- `v4_arc03_reservation_precedes_allocation_and_retirement_fences_result`;
- `v4_arc03_connector_candidate_claim_rejects_zero_and_mislabeled_resources`;
- `v4_arc03d_process_root_shares_one_connector_limit_across_mesh_runtimes`;
- `v4_arc03d_process_root_rejects_a_conflicting_policy`;
- `v4_arc03d_concurrent_process_policy_installation_has_one_winner`;
- `v4_arc03e_mesh_scope_requires_the_single_installed_process_owner`;
- `v4_arc03e_mesh_ceiling_isolates_children_inside_the_process_cap`;
- `v4_arc03e_concurrent_children_never_oversubscribe_either_ceiling`;
- `v4_arc03e_failed_cleanup_retains_the_exact_process_and_mesh_claim`;
- `v4_arc03e_final_failed_cleanup_scope_drop_keeps_unrelated_capacity_usable`;
- compiler-boundary checker;
- cause-matched rejection of external `ConnectorResourceOwnerPort::new`.

## 4. RT-03-02: cancel partial or delivered construction

Attack: cancel after native allocation, after result delivery, while the runtime owner performs cancel-and-join shutdown, or after the owned construction task fails. A confirmed close must release the exact claim. A failed or unconfirmed close must retain only that claim without poisoning unrelated process capacity.

Required result: one cleanup owner follows every result. Callback authority retires, partial work is fenced, native close is attempted once, and the reservation releases only after proven close success.

Controls:

- `v4_arc03_cancelled_construction_closes_partial_native_peer` in WSL;
- `v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim` in WSL;
- `v4_arc03_cancelled_delivered_result_closes_native_peer_before_release` in WSL;
- `v4_arc03_construction_runtime_shutdown_is_bounded_and_fail_closed` in WSL;
- `v4_arc03_background_construction_failure_closes_partial_native_peer` in WSL;
- `v4_arc03_cleanup_owner_outlives_caller_runtime_shutdown`;
- `v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed`.

## 5. RT-03-03: fail or stall native close

Attack: return a close error, never complete close, fail cleanup startup, or add duplicate connected claims.

Required result: the owner reaches a terminal visible per-connector failure within its configured deadline. That connector's exact claims remain consumed. `accounting_poisoned` stays false and other process slots remain usable. Only inconsistent aggregate arithmetic or synchronization poisons the process owner. No claim is forgotten or silently reused.

Controls:

- `v4_arc03_native_close_error_retains_only_its_exact_claim`;
- `v4_arc03_native_close_timeout_is_bounded_visible_and_fail_closed`;
- `v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed`;
- `v4_arc03_duplicate_connected_claims_remain_exact_and_local`;
- `v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed`;
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
- `v4_arc03_failed_native_close_before_endpoint_handoff_release_retains_exact_claim`;
- `v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives` in WSL.

## 8. RT-03-06: smuggle callback backlog

Attack: fill one callback class, prequeue stale events, block a producer, then retire or replace the connector.

Required result: control and endpoint data have separate owner-selected mailboxes. Every codec-neutral real-time flow has independent bounded queue state under the connector aggregate. Audio and video remain WebRTC adapter names. The owner supplies scheduler weights. Every continuously ready class receives a bounded service opportunity. Control and endpoint-data sends retain reliable bounded backpressure. Real-time handling removes expired whole units synchronously and refuses a complete arriving unit when its exact flow queue is still full. It does not wait one full deadline per stale unit. Exact incarnation stamps reject stale events.

Controls:

- `v4_arc03_control_callback_contention_honors_configured_bound`;
- `v4_arc03_data_callback_contention_honors_configured_bound`;
- `v4_arc03_audio_callback_contention_honors_configured_bound`;
- `v4_arc03_video_callback_contention_honors_configured_bound`;
- `v4_arc03_endpoint_data_and_realtime_callback_capacity_are_independent`;
- `v4_arc03_scheduler_gives_each_ready_class_a_bounded_service_turn`;
- `v4_arc03_realtime_flows_have_independent_bounded_queues`;
- `v4_arc03_expired_realtime_unit_is_dropped_whole_without_enqueue_wait`;
- `v4_arc03_realtime_flow_retirement_drains_its_owned_queue`;
- `v4_arc03_endpoint_and_realtime_units_have_independent_limits`;
- `v4_arc03_realtime_byte_claims_precede_fragment_and_output_retention`;
- `v4_arc03_guarded_video_refuses_fragment_before_retention`;
- `v4_arc03_guarded_video_reordered_unit_transfers_exact_output_claim`;
- `v4_arc03_guarded_video_in_progress_limit_is_connector_wide_across_tracks`;
- `v4_arc03_cancelled_realtime_output_work_releases_its_claim`;
- `v4_arc03_realtime_accounting_corruption_fails_closed`;
- `v4_arc03_retirement_wakes_producer_blocked_by_full_callback_queue`;
- `v4_arc03_retirement_stops_event_pump_before_stale_callback_queueing`;
- `v4_arc03_stale_transport_event_cannot_mutate_replacement_worker` in WSL.

These tests prove shape and enforcement, not operational sufficiency. The owner must measure workload-specific capacities, scheduler weights, real-time unit limits, retained bytes, in-progress units, and useful lifetimes under mixed sustained load.

The ignored measurement requires workload-shape inputs, not production policy values. It reports raw per-event and per-flow observations. The derived finite laboratory envelope is not a proposed default:

```powershell
$env:MYOWNMESH_ARC03_OBSERVE_SAMPLES = "<scenario sample count>"
$env:MYOWNMESH_ARC03_OBSERVE_FLOWS = "<scenario flow count>"
$env:MYOWNMESH_ARC03_OBSERVE_PAYLOAD_BYTES = "<scenario payload size>"
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

Required result: one exact live candidate produces one connected capability. `DataChannelOpen` proves only a working channel eligible for Endpoint Auth. The engine hands the capability to the exact Endpoint Auth task before authentication begins. It does not prove application reachability. Duplicate, stale, or cross-connector values fail.

Controls:

- `v4_arc03_data_channel_open_requires_live_exact_candidate`;
- `v4_arc03_cross_connector_endpoint_auth_and_realtime_capabilities_are_rejected`;
- `v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability`;
- `v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives` in WSL;
- compiler-boundary checker.

The scheduler has an additional exact lifecycle barrier. `Message` remains in the bounded endpoint-data mailbox until the exact `DataChannelOpen` transition commits and the current peer installs its Endpoint Auth task. `DataChannelClosed` can still pass before open. Replacement at the commit fence retires the losing connector and drops its retained endpoint queue.

Controls:

- `v4_arc03_endpoint_protocol_waits_for_committed_open_despite_scheduler_cursor`;
- `v4_arc03_close_can_retire_before_uncommitted_endpoint_protocol`;
- `v4_arc03_retirement_drops_uncommitted_endpoint_protocol_and_its_observation`;

Arc 03 proves provenance ownership only. It does not claim Endpoint Auth resource admission or transcript verification.

## 12. RT-03-10: use worker possession as real-time authority

Attack: call lane or real-time send operations with only `&WebRtcConnectorWorker`, use a capability from another connector, or activate delivery before session admission.

Required result: the narrow worker methods require the exact compatibility-only `ConnectorRealtimeFlowCapability`. The temporary legacy issuer checks current peer admission and exact Endpoint Auth provenance. The report must not describe this value as the final flow contract. A later flow capability must be session-bound, principal-bound, policy-guarded, and independently resource-reserved.

Controls:

- core relay-selection negative control;
- `v4_arc03_cross_connector_endpoint_auth_and_realtime_capabilities_are_rejected`;
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

## 16. RT-03-14: re-enable ordinary-member payload forwarding

Attack: route an endpoint channel through shaped-topology forwarders, flood endpoint payload through ordinary members, or interpret an inbound relay-shaped wrapper as a V4 endpoint route.

Required result: the V4 engine does not call `routing::send_routed`, `routing::broadcast_flood`, or `routing::on_relay_frame`. Directed endpoint data uses one exact endpoint session. Broadcast sends once to each directly connected endpoint. RTM-001 remains open until the legacy routing module and compatibility surface are removed or separately dispositioned.

The connector-capable V4 daemon also rejects `services.relay.enabled` at startup and through live service reconfiguration. RTM-002 remains open because the legacy `RelayService` construction surface is still present outside that daemon entry path.

Arc 03 remains blocked on an explicit owner choice:

1. Fence the historical routing and relay surface into a typed V1 compatibility package that future V4 session capabilities cannot reach, with deletion retained for Arc 12.
2. Accept immediate breaking removal and typed no-direct-session plus partial-fanout behavior.

This branch does not silently select immediate removal.

Controls:

- compiler-boundary source checks for all three forbidden V4 calls;
- `v4_daemon_policy_rejects_ordinary_member_payload_relay`;
- direct and TURN-selected endpoint positive controls;
- RTM-001 and RTM-002 remain open in `MESH-ATTACK-VECTORS.md`.

## 17. RT-03-15: start an ownerless daemon

Attack: start the daemon without resource policy, then discover that every connector is refused only after the service is running.

Required result: configuration-only `embedded::start` starts only an explicitly infrastructure-only daemon or returns the typed `EmbeddedStartError::MissingConnectorResourcePolicy`. Only `start_connector_capable` can start a connector-capable daemon. Infrastructure-only startup requires node participation to be disabled, and later node enablement is rejected before persistence. `myownmesh serve` selects the infrastructure form when node participation is disabled. When it is enabled, the command requires the complete owner-selected `MYOWNMESH_CONNECTOR_*` vector and rejects every missing, zero, or invalid value before startup. No policy value is inferred.

Controls: `ownerless_start_returns_typed_missing_policy_error`, `infrastructure_start_requires_node_participation_disabled`, `ownerless_mesh_rejects_network_join_with_typed_policy_error`, `infrastructure_runtime_rejects_later_node_enable_without_mutation`, and the three `connector_capable_serve_*` parser tests.

## 18. Compiler boundary

`python scripts/check-v4-arc03-compiler-boundaries.py` must prove the expected privacy or visibility cause for each negative compile probe. An unrelated compiler error is not a pass.

The checker covers raw candidate application, external worker construction, raw peer constructors in the default API, private real-time capability construction, private resource-owner construction, and all six real-time-flow consumer signatures. Runtime ownership and cleanup behavior is established by the named executable tests above, not by these compiler probes.

## 19. Preservation matrix

Before merge approval, the exact pushed head must pass:

- workspace formatting, check, Clippy, tests, and doctests;
- direct two-peer handshake and typed data;
- real TURN-selected endpoint data and its negative controls;
- mDNS and Nostr signaling;
- reconnect and recovery;
- data channel, H.264, Opus, and native RTP controls;
- Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl CI.

A skipped test is reported as skipped, not passed.

## 20. Review blockers

Reject these claims on Arc 03:

- complete hostile-ingress resource admission;
- complete retained-memory or dependency-owned resource accounting;
- bounded pre-SDP candidate admission;
- an operational callback capacity selected from the structural tests;
- Endpoint Auth transcript verification or resource admission;
- supported-platform preservation before exact-head CI;
- removal of RTM-001, RTM-002, or their legacy modules;
- final session-bound real-time flow authority;
- production daemon policy values before owner review.
