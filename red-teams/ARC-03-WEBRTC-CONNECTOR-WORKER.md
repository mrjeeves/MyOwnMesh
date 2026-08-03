# Arc 03 WebRTC connector ownership red team

Status: executable review record for fork draft PR #4. Passing this record does not authorize merge or select a production resource value.

## 1. Isolation and commands

Run native and socket-bearing checks only inside Ubuntu 24.04 on WSL. Do not run Windows test binaries. This avoids contact with active MyOwnMesh instances and avoids per-binary Windows Firewall prompts.

```powershell
$repo = "/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition"
$target = "/tmp/mom-arc03g-red-team"
$common = "cd '$repo' && env CARGO_TARGET_DIR='$target' CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0"

wsl.exe -d Ubuntu-24.04 -- bash -lc "$common /root/.cargo/bin/cargo fmt --all -- --check"
wsl.exe -d Ubuntu-24.04 -- bash -lc "$common /root/.cargo/bin/cargo check --workspace --all-targets -j 16"
wsl.exe -d Ubuntu-24.04 -- bash -lc "$common /root/.cargo/bin/cargo clippy --workspace --all-targets -j 16 -- -D warnings"
wsl.exe -d Ubuntu-24.04 -- bash -lc "$common /root/.cargo/bin/cargo test --workspace --all-targets -j 16 -- --test-threads=1"
wsl.exe -d Ubuntu-24.04 -- bash -lc "$common PATH=/root/.cargo/bin:/usr/bin:/bin python3 scripts/check-v4-arc03-compiler-boundaries.py"
```

After retaining the logs, remove only the exact WSL target:

```powershell
wsl.exe -d Ubuntu-24.04 -- rm -rf /tmp/mom-arc03g-red-team
```

## 2. RT-03-01: manufacture connector capacity

Attack: construct a worker, process owner, Mesh child, or candidate capability without the owner-selected process and exact-Mesh reservation.

Required result: external code cannot construct those authorities. One process aggregate and one exact child update atomically. A conflicting process policy and over-ceiling child both fail closed.

Controls:

- `v4_arc03d_process_root_shares_one_connector_limit_across_mesh_runtimes`
- `v4_arc03e_mesh_ceiling_isolates_children_inside_the_process_cap`
- `v4_arc03e_concurrent_children_never_oversubscribe_either_ceiling`
- cause-matched compiler rejections for private resource and worker constructors

## 3. RT-03-02: cancel native construction

Attack: cancel after native allocation, after result delivery, during runtime shutdown, or after background construction failure.

Required result: one close owner owns every partial or delivered result. Successful close releases the claim. A returned close error retains the exact claim. Caller cancellation cannot cancel owner cleanup.

Controls:

- `v4_arc03_cancelled_construction_closes_partial_native_peer`
- `v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim`
- `v4_arc03_cancelled_delivered_result_closes_native_peer_before_release`
- `v4_arc03_construction_runtime_shutdown_is_bounded_and_fail_closed`
- `v4_arc03_background_construction_failure_closes_partial_native_peer`

## 4. RT-03-03: turn time into cleanup truth

Attack: stall native close, cancel a waiter, or try to reclaim capacity because a duration passed.

Required result: close stays `Closing` until the native dependency returns. No timer, timeout state, or observation window exists on the V4 close path. A successful return releases the exact claim. A returned error records `Failed` and retains that claim.

Controls:

- `v4_arc03g_native_close_has_no_timer_and_waiter_cancellation_does_not_cancel_owner`
- `v4_arc03_native_close_success_releases_exact_candidate_claim`
- `v4_arc03_native_close_error_retains_only_its_exact_claim`
- source rejection of the removed timeout names and `Unproven`

Residual: a dependency that never returns leaves the connector visibly `Closing` and its finite claim consumed. Arc 03 does not invent a duration that changes this truth.

## 5. RT-03-04: overflow or lose cleanup execution

Attack: start more cleanup owners than the process can admit, close after a caller runtime shuts down, or fail the cleanup executor boundary.

Required result: one process cleanup executor owns close work. Its queue is bounded by the process candidate ceiling. No close creates a thread or runtime. Refused executor work becomes visible failure with conservative exact retention.

Controls:

- `v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed`
- `v4_arc03_cleanup_owner_outlives_caller_runtime_shutdown`
- `v4_arc03_terminal_cleanup_failure_cannot_be_overwritten_by_start`

## 6. RT-03-05: operate after close

Attack: queue or invoke endpoint data and real-time callbacks after close, force the scheduler toward real-time, send endpoint data, write a real-time unit, or open a track after close commitment.

Required result: one fence orders all application-affecting connector operations. Real-time delivery becomes false at close start. The exact close event may be delivered once, but no later application event or native operation is accepted.

Controls:

- `v4_arc03f_close_fence_rejects_a_blocked_causally_later_message`
- `v4_arc03f_close_fence_rejects_callback_invoked_after_close_commit`
- `v4_arc03g_close_retires_realtime_before_forced_realtime_dispatch`
- `v4_arc03g_close_fence_rejects_endpoint_send_realtime_write_and_lane_open` in WSL

## 7. RT-03-06: reorder channel authority

Attack: place the scheduler cursor on endpoint data while `DataChannelOpen` and the first handshake message are both queued. Replace or retire the connector before the open transition commits.

Required result: endpoint protocol data stays in its bounded mailbox until the exact channel-open transition commits. The first handshake is retained, not discarded. Retirement drops it and releases its observation.

Controls:

- `v4_arc03_endpoint_protocol_waits_for_committed_open_despite_scheduler_cursor`
- `v4_arc03_close_can_retire_before_uncommitted_endpoint_protocol`
- `v4_arc03_retirement_drops_uncommitted_endpoint_protocol_and_its_observation`

## 8. RT-03-07: starve callback classes or flows

Attack: saturate control, endpoint data, and several real-time flows independently.

Required result: control and endpoint data have distinct bounded mailboxes. Every admitted real-time flow has its own bounded queue. Weighted scheduling gives each ready class and flow a bounded service opportunity.

Controls:

- `v4_arc03_scheduler_gives_each_ready_class_a_bounded_service_turn`
- `v4_arc03_realtime_flows_have_independent_bounded_queues`
- callback-class contention tests for control, endpoint data, audio compatibility, and video compatibility

No queue capacity or scheduler weight is accepted as a production value by these structural tests.

## 9. RT-03-08: let inbound real-time work starve outbound

Attack: consume every inbound flow and byte reservation, then request authorized outbound work. Repeat in the opposite direction. Corrupt one domain's arithmetic.

Required result: inbound and outbound flow counts and byte ceilings are separate beneath one total ceiling. Poisoning one real-time byte domain does not invent capacity and does not poison the other domain.

Controls:

- `v4_arc03f_inbound_and_outbound_flow_slots_cannot_starve_each_other`
- `v4_arc03_realtime_accounting_corruption_fails_closed`
- policy tests that reject an aggregate smaller than its domain ceilings

## 10. RT-03-09: retain unbounded real-time work

Attack: send oversized fragments, too many fragments, multiple incomplete units, a silent incomplete unit, reordered units, and saturated complete-unit queues.

Required result: every retained byte is claimed first. Structural per-flow bounds stop growth. Complete units use deterministic `DropNewest`. There is no real-time timer, deadline, expiry task, or useful-lifetime authority.

Controls:

- `v4_arc03_realtime_byte_claims_precede_fragment_and_output_retention`
- `v4_arc03f_realtime_fragment_count_is_structurally_bounded`
- `v4_arc03f_in_progress_unit_limit_is_enforced_per_flow`
- `v4_arc03f_silent_partial_unit_retains_only_its_finite_claim_until_owner_drop`
- `v4_arc03f_complete_realtime_unit_has_no_wall_clock_expiry`
- source rejection of `realtime_useful_lifetime` and H.264 timer APIs

## 11. RT-03-10: release bytes while payloads survive

Attack: dequeue a complete real-time event, copy it to downstream receivers, and drop the first copy.

Required result: one shared exact lease follows the payload. Capacity releases only when the final owned copy drops.

Controls:

- `v4_arc03f_realtime_bytes_follow_payload_clones_through_downstream_queues`
- `v4_arc03_guarded_video_reordered_unit_transfers_exact_output_claim`
- `v4_arc03_cancelled_realtime_output_work_releases_its_claim`
- `v4_arc03_realtime_flow_retirement_drains_its_owned_queue`

## 12. RT-03-11: create codec tracks from generic policy

Attack: enable generic real-time ownership without a compatibility profile, provide an impossible H.264 and Opus lane vector, or fail native track attachment after flow admission.

Required result: generic enablement creates no media tracks. Only an explicit validated `LegacyWebRtcMediaProfile` may request the temporary tracks. It must fit the outbound flow ceiling. A new outbound owner exists before attachment and rolls back if attachment fails.

Controls:

- `v4_arc03g_generic_realtime_policy_does_not_request_media_tracks`
- `v4_arc03g_legacy_video_and_audio_require_two_preprovisioned_flows`
- `v4_arc03f_data_only_connector_allocates_no_realtime_tracks` in WSL
- `v4_arc03f_track_attach_failure_rolls_back_outbound_flow_owner` in WSL

## 13. RT-03-12: flood pre-SDP candidates

Attack: send unique candidates before SDP, duplicate them, delay SDP, cancel candidate application, replace the connector, or shut down.

Required result: duplicates are detected before queue reservation. Each retained candidate must fit both the owner-selected item and exact payload-byte ceilings. The lease survives delayed application and releases on completion, cancellation, replacement, or drop.

Controls:

- `v4_arc03g_candidate_queue_deduplicates_before_retention_and_enforces_both_bounds`
- `v4_arc03g_candidate_queue_claim_survives_delayed_apply_and_releases_on_cancellation`
- `v4_arc03g_candidate_queue_replacement_releases_displaced_claims`
- `v4_arc03_retirement_cancels_inflight_candidate_observation`

## 14. RT-03-13: corrupt aggregate accounting

Attack: underflow or overflow a process, Mesh, candidate, connected, or real-time transition. Deliver duplicate connected claims.

Required result: checked arithmetic preserves conservative consumption and refuses admission in the affected owner. A known close failure retains only its exact claim. Duplicate connected claims remain explicitly owned by cleanup. No `mem::forget` path exists.

Controls:

- `v4_arc03_duplicate_connected_claims_remain_exact_and_local`
- `v4_arc03e_failed_cleanup_retains_the_exact_process_and_mesh_claim`
- `v4_arc03e_final_failed_cleanup_scope_drop_keeps_unrelated_capacity_usable`
- `v4_arc03_promotion_atomically_releases_candidate_only_claims`

## 15. RT-03-14: bypass Endpoint Auth provenance

Attack: replay `DataChannelOpen`, use a task or real-time capability from another connector, or treat worker possession as admission.

Required result: the exact live candidate produces one `ConnectedChannelCapability`. That capability moves into the exact `EndpointAuthTask`. Cross-connector capability use fails. Arc 03 does not claim transcript verification or authenticated session authority.

Controls:

- `v4_arc03_data_channel_open_requires_live_exact_candidate`
- `v4_arc03_cross_connector_endpoint_auth_and_realtime_capabilities_are_rejected`
- `v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability`
- compiler checks for exact capability-consuming compatibility operations

## 16. RT-03-15: turn relay selection into authority

Attack: use a TURN-selected pair as endpoint identity, Endpoint Auth, application admission, or real-time admission.

Required result: TURN remains only an ICE carrier for the same endpoint session. Positive and negative controls cross the same Endpoint Auth boundary as a direct path.

Controls:

- `v4_arc03_relay_selection_is_not_authentication_or_session_admission`
- `turn_selected_session_authenticates_endpoints_before_bidirectional_data` in WSL

## 17. RT-03-16: reach LegacyV1 forwarding from V4

Attack: call shaped routing or ordinary-member application relay from the V4 connector, engine, Endpoint Auth task, daemon, or a future V4 capability.

Required result: the `legacy-v1` feature, explicit deprecated `LegacyV1Runtime`, and crate-private marker are all required. Normal V4 construction cannot create the marker. Surviving public compatibility facades are deprecated. New V4 code must compile with deprecated use denied.

Controls:

- compiler-boundary source checks for the feature, runtime, private marker, and V4 exclusion
- `v4_daemon_policy_rejects_ordinary_member_payload_relay`
- feature-only `legacy_v1_runtime_explicitly_enables_one_daemon_channel_relay`

Residual: RTM-001 and RTM-002 remain open while frozen source is present. Named deletion remains Arc 12 after downstream migration.

## 18. RT-03-17: start without policy

Attack: start a participating daemon without connector policy, silently turn infrastructure-only startup into participation, or infer missing media values.

Required result: connector-capable and infrastructure-only constructors are distinct. Infrastructure-only startup requires participation disabled. Later participation fails without mutation. Missing or inconsistent connector policy fails before network-capable startup.

Controls:

- `infrastructure_start_requires_node_participation_disabled`
- `ownerless_mesh_rejects_network_join_with_typed_policy_error`
- `infrastructure_runtime_rejects_later_node_enable_without_mutation`
- `data_only_connector_policy_requires_no_realtime_values`
- cause-matched compiler rejection for ambiguous Mesh open

## 19. Measurement and approval boundary

[`scripts/measure-v4-arc03g.ps1`](../scripts/measure-v4-arc03g.ps1) records raw queue occupancy, service delay, payload size, in-progress bytes, connector concurrency, close duration, process CPU, and retained memory for direct, TURN, data-only, H.264, Opus, multi-flow, reconnect, multi-peer, multi-Mesh, close-success, close-error, and candidate-burst scenarios. Every workload shape and repeat count is explicit. It proposes no default or production policy value. Missing coverage must be reported as a residual, not filled with a synthetic number.

Before review, the exact pushed head must pass formatting, workspace checks, Clippy, tests, doctests, compiler-boundary checks, native direct and TURN controls, and the unchanged Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl matrix.

Reject claims of complete hostile-ingress admission, complete native dependency memory accounting, Endpoint Auth verification, final session authority, final generalized flow authority, final codec policy, LegacyV1 removal, or supported-platform preservation before exact-head evidence exists.
