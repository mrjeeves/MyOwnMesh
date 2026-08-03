# Arc 03 WebRTC connector ownership red team

Status: executable review record for fork draft PR #4. Passing these controls does not authorize merge or select a production resource value.

## 1. Local execution boundary

Run Rust checks inside Ubuntu 24.04 on WSL. Do not execute Windows socket-bearing test binaries. This keeps the native tests isolated from running MyOwnMesh instances and avoids per-binary Windows Firewall prompts.

```powershell
$repo = "/mnt/c/Users/Admin/MyOwnMesh Security Audit/MyOwnMeshV4Transition"
$target = "/tmp/mom-arc03f-red-team"
$common = "cd '$repo' && env CARGO_TARGET_DIR='$target' CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0"

wsl.exe -d Ubuntu-24.04 -- bash -lc "$common /root/.cargo/bin/cargo fmt --all -- --check"
wsl.exe -d Ubuntu-24.04 -- bash -lc "$common /root/.cargo/bin/cargo check --workspace --all-targets -j 16"
wsl.exe -d Ubuntu-24.04 -- bash -lc "$common /root/.cargo/bin/cargo clippy --workspace --all-targets -j 16 -- -D warnings"
wsl.exe -d Ubuntu-24.04 -- bash -lc "$common /root/.cargo/bin/cargo test --workspace --all-targets -j 16 -- --test-threads=1"
wsl.exe -d Ubuntu-24.04 -- bash -lc "$common PATH=/root/.cargo/bin:/usr/bin:/bin python3 scripts/check-v4-arc03-compiler-boundaries.py"
```

After logs are retained:

```powershell
wsl.exe -d Ubuntu-24.04 -- rm -rf /tmp/mom-arc03f-red-team
```

The cleanup target above is exact and limited to the WSL temporary directory used by these commands.

## 2. RT-03-01: self-issued capacity

Attack: let a connection attempt manufacture the capacity that admits its own connector.

Required result: the process owner installs capacity once. Each Mesh runtime receives an unforgeable child scope. Candidate admission consumes both scopes atomically. The structural claim cannot create capacity.

Controls:

- `v4_arc03d_process_root_shares_one_connector_limit_across_mesh_runtimes`;
- `v4_arc03e_mesh_scope_requires_the_single_installed_process_owner`;
- `v4_arc03e_mesh_ceiling_isolates_children_inside_the_process_cap`;
- `v4_arc03e_concurrent_children_never_oversubscribe_either_ceiling`;
- `v4_arc03d_process_root_rejects_a_conflicting_policy`;
- `v4_arc03d_concurrent_process_policy_installation_has_one_winner`;
- compiler rejection of external `ConnectorResourceOwnerPort::new`.

## 3. RT-03-02: cancel construction at every ownership boundary

Attack: cancel before native allocation completes, after native allocation, after result delivery, during runtime shutdown, or after a background construction failure.

Required result: one close owner follows every partial and delivered result. The opening claim exists before native allocation. Confirmed native close releases it. Failed or unproven close retains only that exact claim.

WSL controls:

- `v4_arc03_cancelled_construction_closes_partial_native_peer`;
- `v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim`;
- `v4_arc03_cancelled_delivered_result_closes_native_peer_before_release`;
- `v4_arc03_construction_runtime_shutdown_is_bounded_and_fail_closed`;
- `v4_arc03_background_construction_failure_closes_partial_native_peer`.

## 4. RT-03-03: manufacture cleanup truth from time

Attack: never complete native close, return a native error, fail cleanup startup, or retain duplicate connected claims.

Required result:

- native success releases exact claims;
- native error reports `Failed` and retains exact claims;
- passage of the owner observation limit reports `Unproven` and retains exact claims;
- elapsed time never proves protocol, authentication, session, or resource state;
- known per-connector cleanup disposition does not poison unrelated aggregate capacity;
- inconsistent aggregate arithmetic does poison later admission;
- duplicate claims remain in an explicit cleanup-owned collection.

Controls:

- `v4_arc03_native_close_success_releases_exact_candidate_claim`;
- `v4_arc03_native_close_error_retains_only_its_exact_claim`;
- `v4_arc03f_native_close_observation_limit_does_not_prove_failure`;
- `v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed`;
- `v4_arc03_duplicate_connected_claims_remain_exact_and_local`;
- `v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed`;
- source search for `mem::forget` in Arc 03 ownership code.

The native-close observation value remains an owner decision. This red team does not approve one.

## 5. RT-03-04: deadlock promotion and retirement

Attack: force every order between attempt retirement, candidate promotion, connector retirement, Endpoint Auth handoff, replacement, and native close.

Required result: connector authority and attempt transition are not held in reverse nested order. Each race has one linearized winner. Losing candidates are retired and cleaned.

Controls:

- `v4_arc03_promotion_does_not_nest_connector_and_attempt_transitions`;
- `v4_arc03_promotion_and_retirement_have_one_linearized_order`;
- `v4_arc03_connector_retirement_before_promotion_rejects_and_cleans`;
- `v4_arc03_attempt_retirement_preserves_winner_and_invalidates_awaiting_loser`;
- `v4_arc03_endpoint_handoff_release_before_native_close_releases_once`;
- `v4_arc03_native_close_before_endpoint_handoff_release_keeps_claim_visible`;
- `v4_arc03_failed_native_close_before_endpoint_handoff_release_retains_exact_claim`.

## 6. RT-03-05: reorder data-channel open, endpoint bytes, and close

Attack: place the scheduler on endpoint data, queue `DataChannelOpen` with the first handshake frame, then close or replace at each interleaving. Invoke another callback after close has committed. Block a message callback on a full mailbox while close commits.

Required result:

- endpoint protocol does not reach the engine before the exact open transition commits;
- the first queued handshake frame is retained and delivered after commitment;
- close remains deliverable before open commitment;
- once close commits, no causally later message enters a mailbox;
- after close is delivered, the receiver services nothing else;
- retirement drops retained endpoint bytes and their observations.

Controls:

- `v4_arc03_endpoint_protocol_waits_for_committed_open_despite_scheduler_cursor`;
- `v4_arc03_close_can_retire_before_uncommitted_endpoint_protocol`;
- `v4_arc03_retirement_drops_uncommitted_endpoint_protocol_and_its_observation`;
- `v4_arc03f_close_fence_rejects_a_blocked_causally_later_message`;
- `v4_arc03f_close_fence_rejects_callback_invoked_after_close_commit`;
- `v4_arc03_stale_transport_event_cannot_mutate_replacement_worker` in WSL.

## 7. RT-03-06: starve a callback class

Attack: keep control, endpoint data, and multiple real-time flows continuously ready. Set the scheduler cursor against the expected next class.

Required result: owner-selected weighted rotation gives each admitted ready class a bounded service opportunity. Control and endpoint data retain independent bounded backpressure. Each real-time flow has an independent bounded queue.

Controls:

- `v4_arc03_scheduler_gives_each_ready_class_a_bounded_service_turn`;
- `v4_arc03_control_callback_contention_honors_configured_bound`;
- `v4_arc03_data_callback_contention_honors_configured_bound`;
- `v4_arc03_endpoint_data_and_realtime_callback_capacity_are_independent`;
- `v4_arc03_realtime_flows_have_independent_bounded_queues`;
- `v4_arc03_retirement_wakes_producer_blocked_by_full_callback_queue`;
- `v4_arc03_retirement_stops_event_pump_before_stale_callback_queueing`.

Capacity one is a structural test value only. It is not evidence of operational sufficiency.

## 8. RT-03-07: retain an incomplete real-time unit forever

Attack: send an H.264 start fragment and then remain silent. Send too many fragments, an oversized fragment, too many simultaneous units, or a unit above the byte bound. Transition the RTP timestamp, reset the adapter, close the track, revoke the flow, retire the connector, or replace the owner.

Required result:

- no timer, deadline, timer task, timer wheel, or elapsed-time expiry controls assembly;
- a silent flow retains only its finite admitted claim;
- exact fragment, fragment-count, unit, in-progress-unit, and connector-accounted byte bounds apply before retention;
- concrete ownership transitions release the partial unit;
- the H.264 packet ceiling remains a compatibility hard stop, not the generic byte budget.

Controls:

- `v4_arc03f_silent_partial_unit_retains_only_its_finite_claim_until_owner_drop`;
- `v4_arc03f_realtime_fragment_count_is_structurally_bounded`;
- `v4_arc03f_in_progress_unit_limit_is_enforced_per_flow`;
- `v4_arc03f_guarded_video_in_progress_limit_is_independent_per_flow`;
- `v4_arc03_realtime_byte_claims_precede_fragment_and_output_retention`;
- `v4_arc03_guarded_video_refuses_fragment_before_retention`;
- compiler-boundary source check rejecting elapsed-time authority in `h264.rs`.

## 9. RT-03-08: use elapsed time as complete-unit queue authority

Attack: queue a complete unit, wait longer than an arbitrary interval, then service it. Saturate the same flow and a different flow.

Required result: complete units remain governed by exact per-flow capacity and deterministic `DropNewest`. Elapsed time does not revoke a unit. Saturating one flow cannot consume or discard another flow's queue.

Controls:

- `v4_arc03f_complete_realtime_unit_has_no_wall_clock_expiry`;
- `v4_arc03_realtime_flows_have_independent_bounded_queues`;
- `v4_arc03_realtime_flow_retirement_drains_its_owned_queue`;
- source check rejecting `realtime_useful_lifetime`.

## 10. RT-03-09: starve inbound or outbound flows

Attack: consume every inbound flow slot and attempt outbound track creation, then reverse the direction. Fail native track attachment. Reap a transient lane after successful, failed, or already-absent native removal.

Required result: inbound quarantine and outbound compatibility have separate owner-selected flow counts under one byte aggregate. The outbound owner exists before native attachment. Attachment failure rolls it back. Successful or already-complete reaping releases it. Native removal failure retains it.

Controls:

- `v4_arc03f_inbound_and_outbound_flow_slots_cannot_starve_each_other`;
- `v4_arc03f_track_attach_failure_rolls_back_outbound_flow_owner` in WSL;
- `lanes_are_lifecycle_managed_not_pre_pooled` in WSL;
- `pinned_lane_drains_but_is_never_reaped` in WSL;
- `v4_arc03f_data_only_connector_allocates_no_realtime_tracks` in WSL.

## 11. RT-03-10: release bytes at dequeue while copies survive

Attack: dequeue a real-time event, clone it into downstream broadcast receivers, and drop the original while one clone remains.

Required result: one shared payload lease follows every clone. Connector-accounted capacity releases only when the last owned copy drops. Queue-container capacity remains a separate observation.

Controls:

- `v4_arc03f_realtime_bytes_follow_payload_clones_through_downstream_queues`;
- `v4_arc03_guarded_video_reordered_unit_transfers_exact_output_claim`;
- `v4_arc03_cancelled_realtime_output_work_releases_its_claim`;
- `v4_arc03_realtime_accounting_corruption_fails_closed`.

## 12. RT-03-11: retain remote candidates after ownership ends

Attack: queue pre-SDP candidates, cancel during application, replace the connector, or shut down.

Required result: the connector owns the queue and observation lease. Retirement drains queued candidates and cancels local apply waits. Work already retained inside the ICE dependency is not relabeled as connector-owned memory.

Controls:

- `v4_arc03_candidate_queue_is_connector_owned_and_observed`;
- `v4_arc03_candidate_apply_observation_survives_await_and_cancellation`;
- `v4_arc03_retirement_cancels_inflight_candidate_observation`.

Residual: the pre-SDP candidate queue is observed but does not yet have an owner-approved enforced item and byte limit.

## 13. RT-03-12: carry construction claims after connection

Attack: promote while retaining candidate-only work, or reopen capacity after inconsistent subtraction.

Required result: promotion performs an explicit resource transition. Candidate-only claims release. Connected claims remain. Inconsistent arithmetic preserves conservative use and refuses later admission.

Controls:

- `v4_arc03_promotion_atomically_releases_candidate_only_claims`;
- `v4_arc03_resource_families_cannot_substitute_for_each_other`;
- `v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed`.

## 14. RT-03-13: bypass Endpoint Auth provenance

Attack: replay `DataChannelOpen`, use a task or real-time capability from another connector, call media operations with worker possession alone, or activate delivery before admission.

Required result: one exact live connector produces one `ConnectedChannelCapability`. It moves into the exact `EndpointAuthTask`. Arc 03 proves provenance ownership only. It does not claim transcript verification, authenticated session authority, or final real-time flow authority.

Controls:

- `v4_arc03_data_channel_open_requires_live_exact_candidate`;
- `v4_arc03_cross_connector_endpoint_auth_and_realtime_capabilities_are_rejected`;
- `v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability`;
- `v4_arc03_outbound_application_send_requires_current_session_admission`;
- compiler checks for capability-consuming lane and send signatures.

## 15. RT-03-14: activate through a stale owner

Attack: replace owner A with B at roster persistence, then let A finish authentication or approval.

Required result: A cannot persist roster membership, emit owner-derived governance, resolve waiters, clear reconnect state, flush application frames, or approve on behalf of B.

Controls:

- `v4_arc03_replacement_before_roster_persistence_cancels_activation_commit`;
- `v4_arc03_stale_message_owner_cannot_mutate_replacement_peer`;
- `v4_arc03_reliable_flush_requires_authenticated_admission`;
- `v4_arc03_current_effect_linearizes_before_replacement`.

## 16. RT-03-15: treat TURN selection as authority

Attack: use Relay-to-Relay ICE selection as endpoint identity, endpoint authentication, application admission, or real-time admission.

Required result: TURN remains an ICE carrier for one endpoint session. The positive path still performs endpoint authentication and bilateral application admission. The negative path can select TURN and authenticate but cannot carry endpoint data, create a lane, or send a real-time unit without admission.

Controls:

- `v4_arc03_relay_selection_is_not_authentication_or_session_admission`;
- `turn_selected_session_authenticates_endpoints_before_bidirectional_data` in WSL.

## 17. RT-03-16: reach LegacyV1 forwarding from V4

Attack: invoke shaped routing or ordinary-member payload relay from a V4 connector, engine, Endpoint Auth task, or future V4 capability.

Required result:

- `send_routed`, `broadcast_flood`, `on_relay_frame`, and `RelayService::start` require the sealed `LegacyV1CompatibilityProfile`;
- the profile has no `Default` and no conversion from a V4 capability;
- V4 connector, engine, and Endpoint Auth sources do not reference the profile;
- connector-capable daemon startup rejects legacy payload relay;
- RTM-001 and RTM-002 remain open until Arc 12 removes the compatibility source.

Controls:

- compiler-boundary source checks for all frozen legacy entry points;
- `v4_daemon_policy_rejects_ordinary_member_payload_relay`;
- direct and TURN endpoint controls.

## 18. RT-03-17: start an ambiguous or ownerless daemon

Attack: start a connector-capable daemon without a policy, silently create an infrastructure-only Mesh that later joins, or infer missing media policy values.

Required result:

- connector-capable and infrastructure-only constructors are distinct;
- ownerless `embedded::start` does not exist;
- infrastructure-only startup requires node participation disabled;
- later node enablement fails before mutation;
- real-time `Disabled` requires no media values;
- real-time `Enabled` requires every value and rejects inconsistent combinations;
- ambiguous `Mesh::open` and `Mesh::open_with_identity` fail to compile.

Controls:

- compiler-boundary source check rejecting ownerless `embedded::start`;
- `infrastructure_start_requires_node_participation_disabled`;
- `ownerless_mesh_rejects_network_join_with_typed_policy_error`;
- `infrastructure_runtime_rejects_later_node_enable_without_mutation`;
- `data_only_connector_policy_requires_no_realtime_values`;
- parser rejection controls;
- cause-matched compiler rejection for ambiguous Mesh open.

## 19. Measurement reproduction

The measurement program requires workload shape rather than production policy values:

```powershell
.\scripts\measure-v4-arc03f.ps1 `
    -Scenario all `
    -Samples <sample-count> `
    -Flows <flow-count> `
    -PayloadBytes <payload-bytes> `
    -MultiPeerCount <peer-count> `
    -MultiMeshCount <mesh-count> `
    -CandidatesPerMesh <candidate-count>
```

It builds each selected test before measurement, then records raw connector-owned observations plus `/usr/bin/time -v` data from the exact test executable. It proposes no capacity, weight, observation limit, or flow value.

## 20. Preservation and rejection boundary

Before owner review, the exact pushed head must pass:

- formatting, workspace check, Clippy, tests, and doctests;
- compiler-boundary controls with exact expected error causes;
- native direct WebRTC and media controls;
- TURN-selected positive and negative controls;
- mDNS, Nostr, reconnect, and recovery controls;
- Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl CI.

Reject these Arc 03 claims:

- complete hostile-ingress resource admission;
- complete allocator-retained or native dependency memory accounting;
- bounded pre-SDP candidate admission;
- production policy values selected from structural tests;
- Endpoint Auth transcript verification or resource admission;
- final authenticated session or generalized real-time flow authority;
- RTM-001 or RTM-002 removal;
- supported-platform preservation before exact-head CI.
