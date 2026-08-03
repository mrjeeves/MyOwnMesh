# V4 Arc 03 WebRTC connector ownership

Status: corrective Arc 03F implementation candidate on `arc/03-webrtc-connector-worker`. Fork PR #4 remains draft and unmerged. Arc 03 is not merge-approved.

Arc 03F parent: `e5d5fded10da2c069f0d0e931ff7e198a9559d2c`

## 1. Scope

Arc 03 puts the existing WebRTC connector behind explicit process, Mesh-runtime, attempt, candidate, cleanup, and Endpoint Auth owners. It keeps the existing ICE, STUN, TURN, DTLS, direct-path, native RTP, H.264, Opus, mDNS, Nostr, reconnect, and recovery machinery.

This arc does not add route identities, durable connector records, path generations, pair permissions, authentication before pathfinding, Endpoint Auth transcript verification, authenticated session authority, application flow policy, or codec policy. It does not move Arc 03 responsibilities into `PeerStateData`, `NetworkCmd`, or `NetworkState`.

Endpoint payload is carried only by an exact endpoint WebRTC session. TURN may carry that session as the selected ICE path. Signaling never carries endpoint payload.

## 2. Cardinality and owners

```text
one ProcessResourceRoot
    -> one process connector resource owner
    -> one explicit child scope for each live Mesh runtime

one Mesh connector child scope
    -> one owner-selected hard candidate ceiling
    -> no implicit borrowing from another Mesh scope

one connection attempt
    -> multiple connector candidates

one connector candidate
    -> one RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and candidate pairs

DataChannelOpen from the exact live connector
    -> ConnectedChannelCapability
    -> EndpointAuthTask owns connected-channel provenance
```

`ConnectorCandidateCapability` names a complete connector candidate. It does not name one trickled `LocalIceCandidate`.

`admit_single_connector_candidate` defines the structural claim but cannot create capacity. `ProcessResourceRoot` installs one process policy, then issues an unforgeable child scope from an explicit per-Mesh policy. Admission updates the process aggregate and exact child under one mutex. A conflicting process policy is rejected. External code cannot construct either authority.

## 3. Explicit policy

The public connector policy has no `Default`. The owner must choose:

- maximum active candidates for the process;
- maximum active candidates for the exact Mesh runtime;
- control callback capacity;
- endpoint-data callback capacity;
- control and endpoint-data scheduler weights;
- whether real-time connector compatibility is disabled or enabled;
- when enabled, the real-time scheduler weight;
- maximum encoded real-time unit bytes;
- maximum inbound and outbound active flows per connector;
- queue capacity for each admitted real-time flow;
- maximum inbound fragment bytes;
- maximum inbound fragments per unit;
- maximum simultaneous in-progress units per flow;
- maximum connector-accounted real-time bytes;
- the native-close observation limit.

The disabled form contains no invented media values. The enabled form rejects internally inconsistent vectors, including a fragment limit above the unit limit or an aggregate byte bound that cannot hold one guarded input and one guarded output.

The native-close observation limit only bounds how long the cleanup owner observes the dependency in that operation. It does not prove close success, close failure, protocol state, authentication state, session state, or resource release. Arc 03F proposes no production value for it.

## 4. Reserve before allocation

Production construction has one order:

```text
request an exact Mesh child reservation
    -> atomically reserve process and child opening claims
    -> create the cleanup owner
    -> start owned asynchronous construction
    -> allocate RTCPeerConnection
    -> attach it to the cleanup owner
    -> install callbacks and connector machinery
    -> recheck attempt liveness
    -> publish the worker or start cleanup
```

The reservation exists before native construction. Cancellation after native allocation, cancellation after result delivery, runtime shutdown, and construction failure all reach the same cleanup owner. Partial and delivered results have one close owner. Raw `Transport::open_peer*` construction remains test-only or `transport-lab` only.

## 5. Transition order

Attempt allocation, promotion, and retirement share one attempt-transition mutex. Connector promotion does not hold connector authority while acquiring that mutex:

1. Move the candidate to private `Promoting` state under connector authority.
2. Release connector authority.
3. Perform the attempt transition.
4. Release the attempt-transition mutex.
5. Reacquire connector authority and publish the result.

This establishes one promotion or retirement order without a reverse nested lock path. Retirement wakes blocked callbacks and candidate application, fences later work, drains connector-owned queues, retires losing candidates, and starts native cleanup.

## 6. Cleanup and accounting truth

Promotion replaces candidate-only claims with the exact connected claims. Duplicate connected claims remain in an explicit cleanup-owned collection. No claim is forgotten or overwritten.

Aggregate accounting corruption and native cleanup disposition are distinct:

- If process or Mesh aggregate arithmetic can no longer be proved, the applicable owner is poisoned, conservative consumption remains, and later admission is refused.
- If native close returns an error, only that connector's exact claims are retained and reported as failed cleanup. Unrelated process capacity remains usable.
- If the owner observation limit passes before native close returns, only that connector's exact claims are retained and reported as unproven. Elapsed time does not convert uncertainty into failure or success.
- A confirmed native close releases the exact candidate and connected claims.

Visible `Failed` and `Unproven` states prevent invisible leakage and unsafe reuse. Retained claims remain consumed until a later cleanup owner can prove release or the process exits.

## 7. Callback lifecycle and scheduling

The connector has three generic callback classes:

- control;
- endpoint data;
- codec-neutral real-time flow.

Control and endpoint data have independent bounded mailboxes. Every admitted real-time flow has its own bounded queue. The receiver uses owner-selected weighted rotation. Each continuously ready admitted class receives a bounded service opportunity.

The exact data channel has a source-side lifecycle fence. `DataChannelClosed` commits that fence once. A callback that reaches the fence afterward cannot enter any connector mailbox. A callback already blocked on a full endpoint mailbox is woken and refused when close commits. The receiver returns no event after delivering close.

Endpoint protocol data may be queued before `DataChannelOpen`, but it cannot reach the engine until the exact open transition commits. Scheduler cursor position cannot reorder that authority transition. The first retained handshake frame remains available after commitment.

## 8. Structurally bounded real-time work

Real-time compatibility has separate inbound quarantine and outbound flow domains under one connector aggregate. One domain cannot consume every flow slot in the other. Audio, video, H.264, and Opus names remain inside the WebRTC compatibility adapter.

Inbound partial units are bounded by:

- exact flow ownership;
- maximum fragment bytes;
- maximum fragments per unit;
- maximum unit bytes;
- maximum simultaneous in-progress units per flow;
- maximum connector-accounted real-time bytes;
- the H.264 adapter's fixed packet-count hard stop.

No timer, deadline, elapsed-time expiry, timer task, or timer wheel owns partial-unit release. A partial unit releases on timestamp transition, explicit reset, track closure, flow revocation, connector retirement, replacement, or ordinary owner drop. A silent flow may retain only its already admitted finite claim.

Complete units use a bounded per-flow queue and the explicit deterministic `DropNewest` rule. There is no `realtime_useful_lifetime` input. Final recovery, retransmission, FEC, latest-unit, or application quality policy remains outside Arc 03.

The real-time byte lease moves into the queued event. Copies delivered through downstream broadcast queues retain the same lease until the last copy drops. Queue dequeue does not release capacity while a payload is still owned downstream.

Outbound compatibility acquires its flow owner before attaching or reviving a native track. Track attachment failure rolls the new owner back. A transient lane releases its flow owner only after native track removal succeeds or the track is already absent. Failed native removal retains the exact flow claim until connector cleanup.

## 9. Endpoint Auth boundary

`DataChannelOpen` proves that the exact connector has a working channel eligible for Endpoint Auth. It does not prove endpoint identity, bilateral application admission, application reachability, or session authority.

The exact candidate becomes `ConnectedChannelCapability`, which moves into `EndpointAuthTask`. `EndpointAuthTask` is the mandatory connected-channel provenance owner. Arc 03 does not implement transcript verification or authenticated-session capability production.

`ConnectorRealtimeFlowCapability` is a compatibility-only capability. The existing WebRTC adapter requires it for lane and encoded-unit operations. Possession of `&WebRtcConnectorWorker` is insufficient. The final generalized real-time authority belongs to a later session-bound, principal-bound, policy-guarded, independently reserved design.

## 10. LegacyV1 compatibility

Arc 03F adopts the compatibility-preserving transition:

- historical shaped routing and payload relay require an explicit sealed `LegacyV1CompatibilityProfile`;
- that profile has one frozen value and no `Default`;
- V4 connector, engine, and Endpoint Auth paths cannot obtain or consume it;
- connector-capable daemon startup rejects the legacy relay service;
- removal remains scheduled for Arc 12 after downstream replacement paths exist.

RTM-001 and RTM-002 remain open because the frozen source still exists. Arc 03 does not claim repository-wide removal. The compiler-boundary checker proves only that current V4 paths do not reach the compatibility profile.

## 11. Daemon and library construction

The supported daemon forms are explicit:

- `embedded::start_connector_capable(config, policy)`;
- `embedded::start_infrastructure_only(config)`.

The ownerless `embedded::start(config)` form does not exist, so an old caller cannot silently become infrastructure-only.

Infrastructure-only startup requires node participation to be disabled and rejects later node enablement without connector policy. Connector-capable `myownmesh serve` requires every owner-selected environment value and fails before startup when any value is missing, zero, invalid, or internally inconsistent.

The corresponding library forms are `Mesh::open_connector_capable`, `Mesh::open_connector_capable_with_identity`, `Mesh::open_infrastructure_only`, and `Mesh::open_infrastructure_only_with_identity`. Ambiguous `Mesh::open` and `Mesh::open_with_identity` do not exist.

## 12. Mechanical ownership modules

Arc 03F separates these responsibilities without changing ICE or media behavior:

- `runtime/attempt/admission.rs`: reserve-before-allocation and promotion;
- `runtime/attempt/lifetime.rs`: attempt lifetime and liveness;
- `transport/webrtc/callback.rs`: callback classes, close fence, and scheduler;
- `transport/webrtc/realtime.rs`: generic flow queues and byte leases;
- `transport/webrtc/cleanup.rs`: native close and conservative claim retention;
- `transport/webrtc/media.rs`: legacy media-lane adapter;
- `transport/webrtc/h264.rs`: structurally bounded H.264 assembly.

`PeerSession` does not implement `Deref`. Production native connector creation remains behind `WebRtcConnectorWorker`.

## 13. Measurement program

[`scripts/measure-v4-arc03f.ps1`](../../scripts/measure-v4-arc03f.ps1) runs raw callback-flow, direct, TURN-selected, media, reconnect, multi-peer, and multi-Mesh scenarios inside WSL. Workload sizes are explicit inputs. It uses one isolated target directory with incremental compilation and test debug information disabled. Each test binary is built before measurement, then the exact executable is run directly so compiler work does not contaminate workload CPU or memory observations.

The callback-flow and multi-Mesh observers derive finite laboratory envelopes from the requested workload shape. They print raw queue age, occupancy, payload size, flow count, in-progress units, connector counts, and retained connector-accounted bytes. Direct and TURN controls print raw lifecycle timing. `/usr/bin/time -v` supplies process elapsed time, CPU use, and maximum resident memory for every scenario.

These results are observations, not production defaults. Native dependency retention outside the connector-owned queues remains separately identified rather than being relabeled as exact connector accounting.

## 14. Approval boundary

Arc 03 remains draft and unmerged until:

1. The exact pushed head passes formatting, check, Clippy, workspace tests, doctests, compiler-boundary checks, and the red-team record.
2. The unchanged Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl matrix passes on that exact head.
3. The owner reviews measured production values for every policy field.
4. Native direct and TURN-selected positive and negative controls pass on the exact source revision.
5. The owner accepts the frozen LegacyV1 transition and the native-close observation disposition.

Arc 03 does not claim complete hostile-ingress admission, dependency-owned memory accounting, Endpoint Auth transcript verification, Endpoint Auth resource admission, final session authority, or removal of RTM-001 and RTM-002.
