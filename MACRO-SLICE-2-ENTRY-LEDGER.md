# Owner and evidence ledger

Evidence baseline: fork `main` merge commit
`c79ea09cc577bfb3953cf532b2dd555229f7e12c`. Prior owner review:
[4945363089](https://github.com/nathanfraske/MyOwnMeshSecurityReview/pull/6#pullrequestreview-4945363089).

This is an owner and evidence index, not an architecture source of truth. It
records the named owners, bounded units, and exact closure evidence for the
authority, durability, relay, and resource work. A closure item is discharged
only by naming the exact commit and control that closes it. Explicitly pending
platform or runtime evidence remains pending and is never inferred from a
source declaration.

This ledger does not record a final architecture-compliance PASS. Historical
per-item discharge labels below identify source or focused-control closure;
durable runtime qualification remains pending until the required scale,
Open/Closed separation, no-op, restart, crash, and terminal-baseline runs are
available.

## Canonical ledger invariant

This ledger records the implemented boundary: the base durable ledger contains
Closed authority/governance facts only. Its retained classes are `RoleGrant`,
`RoleRevoke`, `Evict`, `MembershipAdmit`, `EvictionProof`, `SelfStandDown`,
`Attestation`, `Resolution`, and `AuthorityLineageResolution`; an explicitly
adopted application contract domain remains separate. Open has zero base
durable semantic facts. Exact-context handshake and Device-key possession
authenticate ephemeral Open participation. Runtime join, leave, presence, and
reconnect for both Open and Closed never enter semantic history.

The semantic owner selects finite fact-count, canonical-byte, causal-edge,
per-author count/bytes and retained lifetime, proof-work,
eligible-signer-quarantine, total-proof-history, and indexed SQLite/WAL-reserve
ceilings. It computes the full delta before every
mutation and refuses the exact `N+1` before changing the graph, projection,
ACK, identity, or authority. Duplicate delivery is a semantic no-op. Missing
dependencies use bounded dependency indexes; exact history remains until an
archive or authority-ratified checkpoint permits semantic deletion. SQLite is
local-only, single-writer, WAL-backed, and `FULL` synchronous. One dedicated
blocking worker owns one ordinary SQLite connection; SQLite's default VFS owns
locking, recovery, WAL reuse, and checkpoints while the semantic layer owns
admission and quotas. The
StorageBytes claim is one process-accounted quantity, `B = M + W + S + R`, for
main database, WAL, shared-memory/sidecar, and explicit reserve bytes. Named
files or VFS accounting do not prove backing disk, filesystem metadata, or
ENOSPC behavior. The shipped compaction boundary is bounded checkpointing
only; a full-copy `VACUUM` requires separately funded temporary-copy,
metadata, and cleanup custody. Timers never silently prune semantic history.
These finite ceilings bound ordinary growth and failure spam, while failed
cleanup retains its exact charge until observation.

## Recorded closure items

Every item recorded here has a named owner and an explicit closure condition;
none lacks a named owner.

**R1, R2 and R3 entered this ledger 2026-08-16** under the operator review
directive for PR #7. That directive fixed the review scope; it was not evidence
of closure. The discharge record at the end of this file names the exact
closing commit and control for each item.

**R4 was not part of that acceptance and is not claimed to be.** R4 is a
pre-existing defect found while proving the ingress boundary; it is recorded
separately for provenance and its discharge is not an operator acceptance of
the original defect.

R4 was discharged at
`0237f9e02df3ab21131c5612c1b231050c860cc4`; no unresolved R4 choice remains
at the 7.3 gate. A discharge is evidence that the defect is closed, and it is
not a ratification of R4 by the operator.

### R1 — durable semantic owner/store

The durable semantic owner is the single writer for one semantic slot. Its
cross-process lease is held for the owner lifetime, its snapshot combines the
canonical fact graph, projection commitment, provisional custody, and proof
records, and publication is atomic. A live replacement cannot open the slot;
after a hard-dead owner the kernel-owned lease is released and the next owner
can reopen and continue from the last complete snapshot.

The closing implementation is the durable-store sequence `f2a0f31` (store),
`d6dd84d` (semantic facts and provisional custody), `1a8285b` (durable proof
outbox), and hardening in `f29207d`, `eaba95b`, and `57ca3c5`, integrated at
`55bafe5`.

Closing controls are
`semantic::store::child_process_contention_and_hard_death_release_the_writer`,
`semantic::store::lifetime_owner_blocks_second_open_then_reopens_for_append`,
`semantic::store::lifetime_owner_preserves_deterministic_graph_and_proof_union`,
`durable_semantic_restart::closed_network_restart_restores_the_committed_semantic_graph`,
and
`durable_semantic_restart::shutdown_fences_stale_state_before_same_slot_reopen_and_append`.
These cover live-owner exclusion, hard-death reopen, graph/custody/proof union,
restart reconstruction, and stale-owner shutdown fencing.

Owner: the durable semantic store owner.

Status: discharged at `55bafe5`.

### R2 — hard process death can strand a provisional enrollment

An MFA enrollment is a client-owned `Prepare` -> material delivery -> exact
`Commit` transaction. `Prepare` creates provisional material; delivery,
including `Wrote::Sent`, does not commit the enrollment. Only an explicit
`Commit` for the exact transaction settles it. `Query`, `Redeliver`, and
`Abort` recover an uncertain delivery, with `Abort` releasing only the exact
matching provisional record. A process death between the atomic save and
delivery can still leave material whose secret and recovery codes were never
delivered.

Owner: the durable-state owner. The contract is durable provisional recovery,
not a retry protocol or custody transaction framework.

The package-level regression control
`crates/myownmesh/tests/custody_recovery_r2.rs::v4_r2_child_hard_death_distinguishes_prepared_from_delivered_enrollment`
now drives both sides of the boundary with a real child process and pipe
barriers: a prepared enrollment is hard-stopped before its acknowledgement,
while a delivered enrollment is acknowledged before the child keeps it. The
Startup validates durable custody before listener exposure. Owner lease and
process nonce are diagnostic/live-handle fences only: neither expires, reclaims,
nor settles a durable `Prepared` record. `Prepared` survives process
death/restart and changes only by exact explicit `Commit` or `Abort`. Legacy
`Disable` refuses `Prepared`; exact `Abort` is the transaction route that
permits a fresh successor, and exact `Commit` transitions to `Committed`.
These controls are the shipped CLI transaction boundary and its exact
recovery controls; their exact-head evidence is recorded below.

Closing controls are
`crates/myownmesh/tests/ctl_mfa_transaction_r2.rs::shipped_ctl_mfa_prepare_commit_query_redeliver_and_stale_successor_are_exact`,
`crates/myownmesh/tests/custody_recovery_r2.rs::v4_r2_cross_process_prepare_race_returns_one_exact_prepared_record`,
`crates/myownmesh/tests/custody_recovery_r2.rs::v4_r2_child_hard_death_distinguishes_prepared_from_delivered_enrollment`,
`crates/myownmesh-core/src/custody.rs::tests::v4_r2_prepare_recovers_exact_existing_prepared_material`,
`crates/myownmesh-core/src/custody.rs::tests::v4_r2_concurrent_prepare_callers_share_one_prepared_material`,
`crates/myownmesh-core/src/custody.rs::tests::v4_r2_prepare_refuses_committed_until_explicit_abort`,
`crates/myownmesh-core/src/custody.rs::tests::v4_r2_prepare_explicit_abort_permits_fresh_successor`, and
`crates/myownmesh-core/src/custody.rs::tests::v4_r2_disable_refuses_prepared_material_until_explicit_abort`.
Together they exercise exact client-owned Prepare/Commit/Query/Redeliver/Abort
transactions, concurrent identity, hard-death and restart custody, and stale
successor fencing. The shipped CLI Prepared-disable refusal is covered by
`crates/myownmesh/tests/ctl_mfa_transaction_r2.rs::shipped_ctl_mfa_prepare_commit_query_redeliver_and_stale_successor_are_exact`;
the shipped CLI unit controls are the `ctl.rs` MFA controls listed below, and
the exact integration discriminator and external evidence are recorded below.

The shipped CLI unit controls are
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_enroll_displays_and_flushes_material_before_commit`,
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_lost_commit_ack_queries_exact_committed_transaction`,
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_prepared_query_retries_one_exact_commit`,
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_ambiguous_retry_queries_once_after_second_ambiguous_commit`,
`crates/myownmesh/src/cli/ctl.rs::tests::malformed_material_never_reaches_commit`,
and
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_transaction_subcommands_preserve_exact_wire_mapping`.
The exact integration discriminator is
`crates/myownmesh/tests/ctl_mfa_transaction_r2.rs::shipped_ctl_mfa_prepare_commit_query_redeliver_and_stale_successor_are_exact`.

The exact Unix listener ACL controls are
`crates/myownmesh/src/control/listener.rs::tests::unix_control_endpoint_is_verified_as_exact_owner_only_socket`,
`crates/myownmesh/src/control/listener.rs::tests::unix_control_replaces_an_owned_stale_socket`,
`crates/myownmesh/src/control/listener.rs::tests::unix_control_refuses_non_socket_without_mutation`,
`crates/myownmesh/src/control/listener.rs::tests::unix_control_refuses_symlink_without_mutation`, and
`crates/myownmesh/src/control/listener.rs::tests::unix_control_refuses_an_accessible_unrelated_parent_without_chmod`.
The Windows DACL/SID controls are
`crates/myownmesh/src/control/listener.rs::tests::windows_pipe_dacl_names_current_token_user_not_owner_rights`,
`crates/myownmesh/src/control/listener.rs::tests::windows_current_user_pipe_connects_and_is_accepted`,
`crates/myownmesh/src/cli/ctl.rs::tests::windows_ctl_verifies_same_user_pipe_server_before_request`, and
`crates/myownmesh/src/cli/ctl.rs::tests::windows_ctl_refuses_mismatched_or_unverifiable_server_sid`.

Status: source/control closure recorded at exact source head
`3556a9a5a509b6773898213870f289e6dbb1ff5b`; hosted CI
`33245879472` completed all six jobs green, including shipped CLI
transport-lab success on Linux, macOS, and Windows, and Turing's exact-head
source review was recorded. The full unread-response shipped-daemon choreography
is Unix-gated; Windows is covered by exact cross-process custody, DACL/SID
controls, and hosted build/test, not identical crash choreography. This is not
final durable architecture qualification.

### R3 — an offline evicted Device receives a durable proof delivery

Current members still refuse an evicted Device and cannot re-admit it: the
signed eviction converges among current members, `log_evicted` is true, the
roster mirror removes it, and `current_policy_admits` returns false, so
auto-approve cannot fire. The Device's own stand-down is now a typed durable
proof publication. The sender persists an exact `Pending` record before any
carrier send, whose fact IDs are the canonical selected-head causal closure;
materialization is not admission and cannot itself emit the proof.

The receiver admits only the exact context, target, delivery ID, and complete
fact closure. Admission updates the semantic graph and projection, then emits
one matching typed `ProofAck`; the sender settles only that exact record and
keeps the `Settled` terminal tombstone across a second reopen. A reconnect
rebinds the record to the current authenticated owner/binding, while a stale
E0 is superseded before the canonical E1 replay. Generic W0/W2 carrier
attempts refuse without consuming the demand; the separately funded W1
sidecar owns D and an exact W1 settlement retires only W1, preserving W0/W2
and the provider baseline.

The closed-network reconnect control remains
`crates/myownmesh-core/tests/closed_network_governance.rs::evicted_offline_device_learns_on_reconnect_and_stands_down`.
The durable proof lane and its transport-lab controls are the implementation
boundary, not a retry timer or a best-effort denial protocol.

The exact R3 controls are
`crates/myownmesh-core/tests/durable_proof_delivery_r3.rs::r3_pending_proof_is_persisted_before_send_and_replayed_after_restart`,
`crates/myownmesh-core/tests/durable_proof_delivery_r3.rs::r3_stale_e0_is_superseded_before_e1_reconnect_replay`,
and
`crates/myownmesh-core/tests/closed_network_governance.rs::evicted_offline_device_learns_on_reconnect_and_stands_down`.

Owner: the typed durable-semantic Signaling Node lane together with the durable
semantic proof owner.

Status: source/control closure recorded at integration head `6d71567`; hosted
CI `33229628657` completed the listed jobs and Turing's exact-head source audit
was recorded. Durable runtime qualification remains pending.

### AuthorityLineage - bounded persistent closure record

**Status: FROZEN at integration head `6d71567`.** Hosted CI
`33229628657` completed the listed jobs and Turing's exact-head typed source
audit was recorded. These controls do not amend the R1 discharge, establish
durable runtime qualification, or turn an unresolved HOLD into an acceptance.

This is a separate, bounded semantic record accompanying the R3 boundary; it
does not create another state owner or widen the transport lane.
`FactBody::AuthorityLineageResolution` is the only persistent cross-cell
selector for a multi-head AuthorityUse lineage. Ordinary
`FactBody::Resolution` remains a same-cell selector (including Role cells) and
cannot select cross-cell authority heads. A distinct-author Membership payload
Resolution remains payload-local and cannot join Role lineage. Self-authored
Closed Membership retains its author AuthorityUse edge and must fork with a
concurrent Role revoke; an application payload Resolution remains payload-local
and adds no persistent subject lineage. An unresolved fork stays fail-closed
and its losing RoleGrant remains inactive. The exact integration-head commit,
hosted run, and typed-audit evidence are `6d71567`, `33229628657`, and Turing's
source review, respectively; none is final durable architecture qualification.

Within the AuthorityLineage boundary, `FactGraph::selected_authority_branch`
chooses the unique causally maximal matching typed selector in the sole
current-head ancestry, independently of FactId or parent traversal order. Zero
matching selectors or multiple incomparable maximal selectors fail closed;
redundant ancestor parents cannot revive an older selector.

Both stale-selector controls choose a bounded deterministic valid redundant-
support T2 and assert `R.id > T2.id`. Canonical sorted parents plus the old
`Vec::pop` traversal would visit `R` to the older T0 first, while the fixed
selector chooses the newer maximal T2.

The closure is evidenced by
`authority_lineage_selection_survives_cross_cell_forks_and_rejects_losers`,
`membership_resolution_does_not_select_authority_lineage_branch`,
`finite_authority_fork_requires_complete_resolution_before_regrant`,
`cross_cell_resolution_cannot_select_a_role_authority_fork`,
`cross_cell_payload_resolution_preserves_authority_fork_in_any_arrival_order`,
`payload_resolution_does_not_join_a_transitive_role_fork`,
`second_order_payload_resolution_cannot_join_the_role_authority_fork`,
`second_order_payload_fork_converges_without_authority_join`,
the open-runtime payload-fork control, and the
`720`-permutation projection control
`finite_authority_fork_projection_converges_for_every_arrival_permutation`,
`self_authored_membership_keeps_a_role_authority_fork_explicit`, and
`self_authored_membership_resolution_is_order_independent_after_role_regrant`,
`stale_selector_follows_newer_typed_role_resolution`, and
`stale_selector_arrival_converges_with_distinct_owner_and_redundant_ancestor`
(12 schedules).
Together they persist exact role-cell authority selection, reject payload
resolution as an AuthorityUse selector while retaining only local witnesses,
require complete typed resolution before regrant, preserve the self-authored
Membership authority edge, keep the loser inactive, reject stale selectors,
and prove the 12-schedule stale-selector, 120-permutation, and 720-permutation
controls.

The exact shipped typed-selector controls are
`crates/myownmesh-core/tests/semantic_fact_controls.rs::authority_use_fork_requires_explicit_typed_selection_across_arrival_orders`,
`crates/myownmesh-core/tests/semantic_projection_controls.rs::authority_lineage_selection_round_trips_and_regrant_is_future_only`,
`crates/myownmesh-core/tests/semantic_projection_controls.rs::stale_selector_arrival_converges_with_distinct_owner_and_redundant_ancestor`,
and
`crates/myownmesh-core/src/semantic/causal.rs::FactGraph::selected_authority_branch`.

### R4 — driver-side pre-normalization attributes a departure to the named device

**Pre-existing. Discovered while proving the ingress boundary; neither
introduced nor, at that point, fixed by it.** Both network drivers normalized
`SignalingMessage::Announce` and `SignalingMessage::Leave` into their own
presence and withdrawal reports before the boundary saw them, taking the
body-supplied `peer_id` while doing so — mDNS for leave, Nostr for both. A
hostile peer could therefore publish a departure naming a third party's Device
ID, and it reached `drop_peer` as that third party's, tearing down the receiving
device's live local session with them.

**Addressed by the signaling + semantic-ingress boundary. The three counts are
not equals, and saying so is the point:**

1. **The report no longer names a third party on mDNS, and mDNS is no longer
   trusted to name one at all.** `mdns/driver.rs` attributes a normalized leave
   to `frame.from` — the same field its announce already used, and the same one
   its own peer table is keyed on. **Narrows the surface; mDNS only.** It does
   not help on Nostr, where the departure still carries the body `peer_id`.

   The exact-head review found the deeper error: browse resolve, expiry and
   goodbye were labelled `CarrierObserved`, but the device id in every one of
   them is parsed from the advertisement TXT record, which any LAN participant
   may write with any value. An attacker could advertise a victim's Device ID
   and then withdraw it. **All mDNS presence and withdrawal is now
   `SenderClaimed`**, which leaves the in-process `LocalBroker` as the only
   producer of `CarrierObserved` anywhere in the system. A driver leaves that
   state by gaining an authenticated binding between what it observed and the
   device key, not by observing more carefully.
2. **Attribution travels with the report, unchanged, to the one place that
   reads it.** `SignalingRuntime` retains nothing and decides nothing about a
   withdrawal: an earlier revision held one back while some other attach still
   observed the device, and that availability map was deleted rather than
   repaired (see the boundary section). **Narrows nothing on its own; it
   preserves the evidence.** A hostile Nostr payload naming a third party is
   delivered to the engine as a `PeerLeft` for that third party, on every
   network shape, single-carrier or not. Nothing before the engine stops it, and
   nothing before the engine is asked to — which is why count 3 is the one that
   closes the effect.
3. **The engine barrier: a sender-claimed withdrawal selects no session in any
   state. This is the count that holds on every carrier and closes the
   body-target effect outright.** `PeerLeft` is reachability evidence, and
   `engine/mod.rs` reads *attribution* before liveness. A `SenderClaimed`
   withdrawal is teardown-inert — it retires nothing, whatever state the named
   session is in — so the delivered Nostr withdrawal of count 2 reaches the
   engine and selects nothing. Only a `CarrierObserved` withdrawal may retire
   anything, and only an attempt that never became a session: **the predicate is
   the promoted `SessionCapability` itself**, not the transport booleans
   underneath one. A promoted session is retired by an exact channel failure or
   the authenticated `SessionControl::Depart` over that very session, and by
   nothing else.

   **This count was liveness-only when it was first written, and that was
   wrong.** Guarding on `authenticated && data_channel_open` alone left a
   sender-claimed departure able to retire a third party's
   authenticated-but-channel-closed session — a session in recovery, which is
   when it is least able to defend itself. Attribution, not liveness, is what
   makes the body-claimed target inert rather than merely narrowed.

**The guard window is closed, not narrowed.** An earlier revision defined "live"
as `authenticated && data_channel_open`, which left a real window: a session
whose channel had closed while recovery or replacement was in progress failed the
conjunction and could be retired by a carrier's own observation. That state
belongs to the Peer Session and connector-recovery owners, so the predicate on
both sides of the lifecycle is now `PeerConnection::holds_promoted_session` —
graceful departure may only depart a session that exists, and a carrier
withdrawal may not retire one. A closed channel no longer changes either answer.

**Stale-replacement safety, on both sides.** The withdrawal arm takes the peer
owner token, reads promotion through that same token, and retires with
`drop_peer_if_current`. Graceful departure now does the same: it selects
`PeerRegistry::owners_snapshot()` and never re-resolves a Device ID again, so a
replacement installed before the send, during the awaited send, or after it is
neither sent a goodbye meant for its predecessor nor torn down in its place.
Nothing on either path touches the roster or the member log.

**Control coverage, and the two controls prove different things.** Every
withdrawal now reaches the engine — the runtime's availability map, which used to
hold one back while another attach still observed the device, was removed rather
than repaired — so what the engine's arm does with a delivered withdrawal is the
whole rule. `v4_m2_a_carrier_withdrawal_selects_only_an_unpromoted_attempt` in
`engine/mod.rs` proves it over the in-process carrier, the only one that can
produce a carrier-observed report at all: a sender-claimed departure selects
nothing however healthy the transport looks, and a carrier-observed withdrawal
does cancel an unpromoted attempt — which makes it a rule about attribution
rather than an arm that has stopped dropping anything.
`v4_m2_a_third_party_lan_claim_creates_no_session_and_moves_nothing_durable`
proves the network carrier's shape, where both directions are claimed: a LAN
participant may write any device id into a TXT record, and neither the announce
naming a stranger nor the withdrawal naming a victim yields a promoted session or
changes the roster version, roster size, transition log or member log — compared
before and after, not enumerated. A claimed announce *may* leave an unpromoted
attempt behind it, because an announce paces a dial; that is the cost of a
connection that will not authenticate, and it is not an admission.

**The promoted half cannot be proven without a connector, and is not
counterfeited.** Only a real connector mints a `SessionCapability`, so
`v4_m2_a_carrier_withdrawal_cannot_retire_a_promoted_session` lives behind
`transport-lab` with the rest of the promotion controls. It is `#[ignore]`d,
because it opens a native WebRTC object, so **the ordinary `transport-lab` CI job
compiles it and does not run it**; no scheduled job executes it. Its only
execution to date is the explicit manager run `ef44f52a`. **Neither the
default-feature job nor the ordinary `transport-lab` job covers the
promoted-session side of this boundary**, which is disclosed here rather than
left to be discovered, and "CI runs it" is not claimed. The alternative — a fixture writing a promotion field the
product cannot produce — would assert against a session that does not exist. The
default-feature control keeps its durable assertions throughout: the device stays
a signed member, stays rostered, and stays admissible. Neither control subsumes
the other, and only the second speaks to the Nostr-only case above.

**The remaining boundary is explicit.** On an unauthenticated carrier the
sender attribution is still a field the sender wrote — `frame.from` on mDNS,
`envelope.from` and `peer_id` on Nostr. Nothing in signaling can fix that, and
nothing in signaling needs to: what it can still buy is a cancelled dial attempt
against a device that is not yet a session — which is what a withdrawal is
allowed to mean — and, for a carrier's own observation only, the guard window
above. Endpoint authentication and policy
remain the only things that admit a device, and no signaling effect can grant,
revoke, or record membership.

**The cost of the correction, stated rather than discovered later: Nostr has no
`CarrierObserved` withdrawal path at all.** Every Nostr departure is a decoded
payload — a peer's own `leave`, or an intelligent relay reporting that a peer's
socket closed, both carrying a body-supplied device id that neither the relay nor
the event author is authenticated to. All of them are therefore `SenderClaimed`
and retire nothing. **Prompt carrier-driven session retirement is intentionally
unavailable on a relay-only network**, and exact connector closure, the
authenticated `SessionControl::Depart`, or the heartbeat timeout is the backstop.
That is slower than the relay hint used to be, and it is the price of the hint
not being aimable: a relay report was exactly as forgeable as any other payload.
**mDNS has no `CarrierObserved` path either, and this correction removed the
last one it had.** Browse resolve, expiry and goodbye all take the device id from
an advertisement's TXT record, so the daemon observing a record appear or vanish
establishes that *a record* moved, not whose device it names. The in-process
`LocalBroker` is the only producer of `CarrierObserved` anywhere in the system,
because it is the only one that stamps the registered id of the handle that sent
rather than reading an id out of something a sender wrote. On every network
carrier, prompt carrier-driven retirement is therefore unavailable by design, and
exact connector closure, the authenticated `SessionControl::Depart`, or the
heartbeat timeout is the backstop.

Status: **discharged at
`0237f9e02df3ab21131c5612c1b231050c860cc4`** — "Complete signaling and semantic
ingress ownership", parent `ee8f5b98622ddbfe2c4307294113f9ddd2c73d8e`, 15 source
and test files at +1713/-870, adding `engine/semantic_ingress.rs`. This ledger is
deliberately not in that commit, so the evidence does not contain its own claim.

**Two prior discharges are superseded, and both are kept here rather than
overwritten**, because a finding that was closed twice on insufficient evidence
is worth being able to read back.
`0b9b5b2c5be60f8204aa2fef4e14259e5d385611` guarded on liveness alone, so a
sender-claimed departure could retire a third party's
authenticated-but-channel-closed session — a session in recovery, which is
exactly when it is least able to defend itself.
`7fb4708d01895269b4aff809857b9d6ffe88d6ad` moved attribution ahead of liveness
and bound the decision to one exact `PeerOwnerToken`, which closed the aimable
half but left two holes the exact-head review of `ee8f5b9` found: the mDNS driver
still labelled a sender-chosen TXT Device ID `CarrierObserved`, so an attacker
could advertise a victim's id and then withdraw it; and the retirement predicate
was still the transport booleans rather than the promoted session. Neither
survives in `0237f9e0…` — every mDNS report is `SenderClaimed` there, and the
predicate is a promoted `SessionCapability` — and the three controls named in the
discharge record below are present in that commit and are what close it.

## Signaling and semantic-ingress ownership boundary

This section records the final boundary established by the reviewed change. It
is an owner contract, not a queue of work or a sequence of pending units.

`engine/signaling_ingress.rs` is the Signaling Node's ephemeral-transport
ingress: the only place a carrier observation is admitted, and the only place it
becomes an engine domain value. Admission happens before domain parsing, bounded
carrier provenance is retained, and the admission is an exhaustive match with no
wildcard arm, so a new carrier variant cannot compile until someone states what
it is — and a variant carrying a durable signed fact has no kind to choose.

**There is no durable-semantic *signaling* variant, and none is pretended.** No
carrier variant carries a durable signed fact, so an uninhabited durable arm on
the signaling union would have been a tag whose other value nothing can hold.

The durable half lives where the sender is known. `engine/semantic_ingress.rs`
is the Semantic Node's ingress: accepted typed signed facts and fact bundles
enter one closed typed `DurableSemanticIngress`; `NetworkStateBroadcast` is only
a non-authoritative inventory hint, and deleted roster/transition wire messages
are not part of this lane. A separate reducer applies accepted facts under the
exact `PeerOwnerToken` the session belongs to. The type wraps a private enum,
so the only way to obtain one is the module's `admit`, and `admit` is total over
`MeshMessage` with no wildcard — a new durable message is a compile error until
it is classified. Its outcome is a two-variant `SemanticAdmission`, not a
`Result`: "not a durable fact" is the ordinary case rather than an error, and a
`Result` would have put a whole `MeshMessage` in an `Err` on the way past every
non-durable live frame. Boxing that would have bought an allocation per frame in
front of the entire inbound path; the enum moves the frame and allocates nothing. The two ownerships are therefore disjoint by construction:
unauthenticated carrier ingress carries no durable fact and has no kind that
could, and durable ingress is reachable only from a promoted session.

`SignalingRuntime` is the owner on the signaling side. It owns exactly two
things: an opaque process-local `CarrierInstance` minted per attach, and
cross-carrier de-duplication whose every retained key is funded by the finite
provider rather than capped by a constant. **It retains no untrusted record.** An
earlier revision kept a per-device availability map keyed by attacker-chosen
device ids and bounded by an invented constant; it was removed rather than
repaired, which closes the flood that evicted real peers and the stale-attach
suppression together, and leaves a detaching carrier with nothing to clean up.

A key is committed only where the engine's mailbox actually **accepted** the
value. The send reports three outcomes — accepted, dropped, engine gone — rather
than a keep-pumping boolean, because a boolean conflates "the driver carries on"
with "the engine has it": under that reading a first offer refused by local
pressure still left its key behind, and the retransmission meant to rescue the
attempt was swallowed as a duplicate of something nobody received. That is the
defect `a_refused_offer_leaves_no_dedup_history_and_its_retransmission_lands`
exists to catch, and it caught it.

The Peer Session lifecycle owner is unchanged: an authenticated
`SessionControl::Depart` sent over the exact live session, consumed only under
that session's owner, with no target Device ID because the session defines its
endpoints. A carrier withdrawal is reachability evidence and cannot retire a
promoted session; `announce_leave` may still emit the carrier hint, but it
carries no teardown authority and the fixed departure wait is gone.

**Both driver queues are gone rather than sized, in both directions.**

*Inbound.* A driver used to push decoded reports into an unbounded channel that a
bridge pump drained, and that stretch was unaccounted memory an unauthenticated
carrier filled at its own rate. Drivers now take a
`myownmesh_signaling::InboundSink` — an opaque closure — and carry each report
through the engine's funded admission on their own task. Local pressure is lossy
and never a teardown signal; only a gone consumer stops a driver.

*Outbound.* The mirror defect, and the one a single whole-queue lease did not
close. The bridge used to translate each engine event into the driver's type and
push that translation into a second unbounded channel, with one standing
`SIGNALING_DRIVER_QUEUE_CLAIM` acquired for "the queue". That named the subsystem
without bounding it: the translations are the allocations, the depth is how many
exist at once, and one claim says nothing about that number however long it is
held. Drivers now take a `myownmesh_signaling::OutboundSource` and **pull**; the
translation is built at the moment the driver asks for one, from the engine's
own per-driver funded mailbox, which already admitted the pre-translation value.
Nothing is ever queued in a translated form, so there is no queue lease —
`SIGNALING_DRIVER_QUEUE_CLAIM`, `acquire_driver_queue_owner`, `OwnedQueue`,
`start_with_queue_owner` and `join_with_queue_owner` are all deleted rather than
kept as vestigial accounting for a queue that no longer exists.

Both seams are opaque callbacks or traits over plain values, so the signaling
crate still learns no resource vocabulary and still works standalone.

Excluded from this signaling boundary: application payload in signaling,
unrelated domain state, and any generic framework. Durable proof delivery,
relay controls, route identity, path generation, persistence, and terminal
acknowledgements belong to their named owners and are not reintroduced as
signaling state.

### External dependencies and evidence boundaries

Both the engine→driver and driver→engine seams are queueless now: a driver pulls
its outbound values through an `OutboundSource` and offers its inbound reports to
an `InboundSink`, so nothing is retained in a translated form on either side.

Carrier libraries and the separately deployed signaling service may retain
their own internal buffers outside the core provider dimensions. Those
allocations remain the owning dependency's accounting boundary and are not
silently reclassified as core custody.

<!-- Historical dependency notes retained only as provenance; the final owner and
     evidence boundary is the matrix below.
  carrier→engine path**: a LAN participant's multicast lands here before the
  It is left open because bounding it belongs to the driver's own work model —
  not on this node's carrier→engine path at all.

caller may opt into — `LocalBroker::join`, `InboundSink::from_unbounded`,
`UnboundedSource` — which do build unbounded channels, but only for a standalone
than hiding a buffer inside a driver — the choice appears in the source of
-->

## Exact resource matrix for the remaining carrier/server state

This matrix is an accounting boundary, not a claim that every allocation in a
carrier library is already provider-metered. A row names the retaining state,
its producer and consumer, the exact admission/refusal point, and the owner
that releases it. Provider dimensions are named only where a provider seam
exists; backend-owned queues and a separately deployed relay are explicitly
marked **no provider** rather than assigned guessed byte prices.

| State class | Producer | Consumer | Provider scope / dimensions | Admission / refusal | Queued / executing / terminal / shutdown owners | Pressure control | Provider baseline |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **mDNS discovery / resolve:** backend `DiscoveryEvent`; resolved `PeerEntry` and `key_to_peer`; directed `OwnedSignal<String>` | Embedded backend `Discovery::start_with_custodian` (system DNS-SD uses its native `Discovery::start`); `run_browse` TXT/SRV resolution; engine `OutboundSource` | `run_browse` parser and peer maps; engine `InboundSink<MdnsInbound>`; per-connection writer | Discovery, alias, and directed-delivery ownership is bounded by the configured discovery limits and any attached provider lease; dependency allocations remain the dependency boundary | `wire::parse_advert`, room/version/address validation, configured peer/queue caps, and sink acceptance. Invalid/full records drop; a full/closed directed queue drops its owned line | Backend owns discovery events; `Shared.peers`/`key_to_peer` own resolved state; writer owns queued `OwnedSignal`. `MdnsDriverHandle::stop` cancels, unregisters/shuts down discovery, and joins tasks before dropping owners | Configured discovery/resolve/queue limits and checked generations; provider admission precedes engine-mailbox retention | Attached engine ownership returns to its pre-arrival baseline after invalid/full/drop and stop; dependency-owned allocations require dependency evidence |
| **Nostr replay / parsing:** inbound WebSocket frame and decoded `Value`/`NostrEvent`; exact directed attempt, session, relay-entry, and correlation records | Relay socket read; `DeliveryStore::admit`; `open_session` | `handle_inbound_frame` and `InboundSink<NostrInbound>`; `run_relay_session`; `DeliveryStore` retry/reconnect state | Attached `DeliveryProvider` scope is one attempt, one relay session, and one `(attempt, session)` entry. `DeliveryRetention` names encoded-event, attempt, relay, session, and opaque dependency claims | 256-KiB frame cap, JSON/envelope/kind/tag checks, and sink acceptance precede retention. Provider refusal precedes map insertion/frame encoding; a refused relay does not consume the live attempt demand | Socket task parses/writes; exact attempt owns source/correlation; each relay session owns session/relay-entry leases. Accepted, typed refusal, replacement, ACK, cancellation, and shutdown settle exact owners; driver stop cancels sessions and store | No pre-parse dedup ring or unbounded refusal queue; provider admission is per attempt/session/relay and reconnect rebinds exact current identity | Attached provider `in_use` returns to pre-admission baseline after refusal, ACK, replacement, or shutdown; provider-backed start is required for production capacity |
| **Relay per-connection I/O / replay:** server `ConnEntry`, bounded outbound queue, subscriptions, stored replay deque, per-REQ replay vector | `HubInner::handle_event` fan-out; `HubInner::handle_req` stored-plus-live replay; client frames | Per-connection writer; `serve_conn`; `handle_req` sends replay and `EOSE` | Self-hosted `server.rs` is a separate deployment with **no MyOwnMesh `FiniteResourceProvider` scope**. Its limits are server policy/OS accounting, not mesh dimensions | Bounded `try_send`; rate/filter/subscription/message limits reject or drop. Replay dedupes and truncates to `MAX_REPLAY_PER_REQ`; storage admits only replayable events under its cap | `HubInner` owns connection/subscription/presence state; writer owns queued frames; connection owns replay output until send. Unregister and hub shutdown release exact state | `MAX_STORED_EVENTS = 8192`, 15-minute retention, `MAX_REPLAY_PER_REQ = 500`, queue 128, and per-connection limits | No mesh-provider baseline is claimed; baseline is configured store/presence plus empty per-connection queue after pruning |
| **Server registration / shutdown:** listener accept, `conns`, `ip_counts`, presence ownership, IDs, shutdown watch | Listener accepts socket; `HubInner::register` creates `ConnEntry` | `serve_conn` reader/writer; `HubInner::unregister` removes exact connection and current presence ownership | **No provider:** relay has no semantic mesh slot or attached finite resource scope. OS listener/socket/runtime allocations are outside mesh dimensions | `max_connections_per_ip` refusal sends bounded NOTICE then closes; shutdown, failed upgrade, or closed socket never enters `conns`; successful registration is the sole record admission | `HubInner` owns registration/IP/presence maps; `serve_conn` owns socket; writer owns queue; unregister is terminal cleanup; shutdown watch ends readers and writers | Default `max_connections_per_ip = 64`, plus message/rate/subscription/filter ceilings and OS listener admission | No mesh-provider delta is promised. Server baseline is zero connections, empty IP/presence maps, no writer queues after shutdown; deployment-level OS accounting remains HOLD |

**R1 and HOLD are preserved.** R1 remains source/control-discharged at
`55bafe5`; this matrix does not reopen it or claim final architecture
qualification. Dependency-owned mDNS and self-hosted-relay
allocations remain qualified until their owning dependency or deployment
supplies a typed, independently verified accounting boundary. The Nostr
production path requires an attached `DeliveryProvider`; standalone adapters
do not establish a production capacity claim.

## Required durable qualification controls

The following controls are required before this ledger can record final
architecture compliance. Each must use finite owner grants, real durable
storage or shipped processes as applicable, deterministic stage markers, and
terminal provider/resource observations; source inspection, a focused unit
test, or a successful build is not a substitute.

- **Scale and refusal:** exercise Open and Closed workloads through the
  configured scale and the exact `N+1` refusal, proving refusal before
  mutation and release to baseline.
- **Open/Closed separation:** prove Open join, leave, presence, reconnect, and
  session activity create no durable semantic fact, while Closed governance
  facts persist through the bounded indexed transaction path.
- **No-op and duplicate delivery:** deliver the same accepted input again and
  prove unchanged projection, fact/index counts, StorageBytes accounting, and
  provider usage.
- **Restart and crash reconciliation:** reopen the exact Closed slot after
  clean restart and deterministic pre-COMMIT, COMMIT-boundary, post-COMMIT,
  and checkpoint cutpoints; classify old, new, or outcome-unknown without
  claiming rollback from an unobserved error.
- **Terminal baseline:** after success, typed refusal, malformed input,
  failed cleanup, and shutdown, observe every owned process/provider claim at
  its expected baseline or retained failed-cleanup state. No orphan task,
  queue, handle, WAL, or sidecar may be omitted from the observation.

Until these durable runs are recorded with exact commands, heads, and
outcomes, this ledger remains an evidence index with qualification pending.

## Scope ceiling

No repository-wide discovery pass, unrelated downstream application work,
custody-only file-lock subsystem, generic transaction framework, or unrelated
application-domain work is admitted by this ledger. Closed-relay route
identity, allocation generation, and terminal custody belong to the final
relay owner and are part of the architecture contract.
No work in AllMyStuff, CEC Support, or another repository is part of this
architecture package.

The canonical documents describe the contract that remains. Exact closing
commits, controls, and review records remain the durable evidence for each
discharge; this table is an index to that evidence, not its sole copy.

## Discharge record

| Closure item | Discharged at | Closing control |
| --- | --- | --- |
| R1 | `55bafe5` (closing subset: `f2a0f31`, `d6dd84d`, `1a8285b`, `f29207d`, `eaba95b`, `57ca3c5`) | `semantic::store::child_process_contention_and_hard_death_release_the_writer`, `semantic::store::lifetime_owner_blocks_second_open_then_reopens_for_append`, `semantic::store::lifetime_owner_preserves_deterministic_graph_and_proof_union`, `durable_semantic_restart::closed_network_restart_restores_the_committed_semantic_graph`, `durable_semantic_restart::shutdown_fences_stale_state_before_same_slot_reopen_and_append` |
| R2 | `3556a9a5a509b6773898213870f289e6dbb1ff5b` (hosted CI `33245879472`; Turing exact-head source review) | `crates/myownmesh/tests/ctl_mfa_transaction_r2.rs::shipped_ctl_mfa_prepare_commit_query_redeliver_and_stale_successor_are_exact`, `crates/myownmesh/tests/custody_recovery_r2.rs::v4_r2_cross_process_prepare_race_returns_one_exact_prepared_record`, `crates/myownmesh/tests/custody_recovery_r2.rs::v4_r2_child_hard_death_distinguishes_prepared_from_delivered_enrollment`, `crates/myownmesh-core/src/custody.rs::tests::v4_r2_prepare_recovers_exact_existing_prepared_material`, `crates/myownmesh-core/src/custody.rs::tests::v4_r2_concurrent_prepare_callers_share_one_prepared_material`, `crates/myownmesh-core/src/custody.rs::tests::v4_r2_prepare_refuses_committed_until_explicit_abort`, `crates/myownmesh-core/src/custody.rs::tests::v4_r2_prepare_explicit_abort_permits_fresh_successor`, `crates/myownmesh-core/src/custody.rs::tests::v4_r2_disable_refuses_prepared_material_until_explicit_abort`, `crates/myownmesh/src/control/listener.rs::tests::unix_control_endpoint_is_verified_as_exact_owner_only_socket`, `crates/myownmesh/src/control/listener.rs::tests::unix_control_replaces_an_owned_stale_socket`, `crates/myownmesh/src/control/listener.rs::tests::unix_control_refuses_non_socket_without_mutation`, `crates/myownmesh/src/control/listener.rs::tests::unix_control_refuses_symlink_without_mutation`, `crates/myownmesh/src/control/listener.rs::tests::unix_control_refuses_an_accessible_unrelated_parent_without_chmod`, `crates/myownmesh/src/control/listener.rs::tests::windows_pipe_dacl_names_current_token_user_not_owner_rights`, `crates/myownmesh/src/control/listener.rs::tests::windows_current_user_pipe_connects_and_is_accepted`, `crates/myownmesh/src/cli/ctl.rs::tests::windows_ctl_verifies_same_user_pipe_server_before_request`, and `crates/myownmesh/src/cli/ctl.rs::tests::windows_ctl_refuses_mismatched_or_unverifiable_server_sid`; full unread-response shipped-daemon choreography is Unix-gated, not identical Windows crash choreography |
| R3 | `6d71567` (hosted CI `33229628657`; Turing source review) | `crates/myownmesh-core/tests/durable_proof_delivery_r3.rs::r3_pending_proof_is_persisted_before_send_and_replayed_after_restart`, `crates/myownmesh-core/tests/durable_proof_delivery_r3.rs::r3_stale_e0_is_superseded_before_e1_reconnect_replay`, `crates/myownmesh-core/src/engine/mod.rs::v4_b2_speculative_proof_ack_is_bound_to_exact_w1`, `crates/myownmesh-core/tests/closed_network_governance.rs::evicted_offline_device_learns_on_reconnect_and_stands_down` |
| R4 | `0237f9e02df3ab21131c5612c1b231050c860cc4` (supersedes `7fb4708d01895269b4aff809857b9d6ffe88d6ad`, which supersedes `0b9b5b2c5be60f8204aa2fef4e14259e5d385611`) | `v4_m2_a_carrier_withdrawal_selects_only_an_unpromoted_attempt` (default feature), `v4_m2_a_third_party_lan_claim_creates_no_session_and_moves_nothing_durable` (default feature), `v4_m2_a_carrier_withdrawal_cannot_retire_a_promoted_session` (`transport-lab`) |
