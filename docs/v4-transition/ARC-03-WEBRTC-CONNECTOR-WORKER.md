# V4 Arc 03 WebRTC connector ownership

Status: corrective Arc 03E implementation candidate on `arc/03-webrtc-connector-worker`. PR #112 remains draft and unmerged. Arc 03 is not merge-approved until the exact pushed head passes the supported-platform matrix, the owner reviews production policy values, and the legacy transition decision in section 11 is resolved.

Frozen Arc 02C parent: `0484f7f0987e5d1c488b30ac21e46f1925ea65cb`

## 1. Scope

Arc 03 puts the existing WebRTC connection path behind explicit process, attempt, connector, cleanup, and Endpoint Auth owners. It preserves ICE, STUN, TURN, DTLS, direct paths, native RTP, H.264, Opus, mDNS, Nostr, reconnect, and recovery behavior.

This arc does not add route identities, durable connector records, path generations, pair permissions, authentication before pathfinding, Endpoint Auth transcript verification, durable session semantics, or codec policy. It does not add Arc 03 responsibilities to `PeerStateData`, `NetworkCmd`, or `NetworkState`.

## 2. Cardinality and ownership

```text
one ProcessResourceRoot
    -> one process connector resource owner
    -> one explicit child scope for each live Mesh runtime

one Mesh connector child scope
    -> one owner-selected hard candidate ceiling
    -> no borrowing from another Mesh scope

one connection attempt
    -> multiple connector candidates

one connector candidate
    -> one RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and candidate pairs

DataChannelOpen from the exact live connector
    -> ConnectedChannelCapability
    -> EndpointAuthTask owns connected-channel provenance
```

`ConnectorCandidateCapability` names one complete connector candidate. It does not name a trickled `LocalIceCandidate`.

`admit_single_connector_candidate` defines the structural claim. It cannot create capacity. `ProcessResourceRoot` installs the process policy once, then issues an unforgeable child scope from an explicit per-Mesh policy. A second Mesh runtime shares the process aggregate but receives a different child scope. Admission updates the process and exact child under one mutex. A conflicting process policy is rejected with `ConnectorResourcePolicyConflict`. External code cannot construct either authority.

## 3. Owner-selected policy

The public policy has no `Default`. The process owner must supply all of these values:

- maximum active connector candidates for the process;
- maximum active connector candidates for the exact Mesh runtime;
- control callback capacity;
- endpoint-data callback capacity;
- control, endpoint-data, and real-time scheduler weights;
- maximum encoded real-time unit bytes;
- maximum active real-time flows per connector;
- bounded queue capacity for each admitted real-time flow;
- maximum inbound real-time fragment bytes;
- maximum simultaneous in-progress real-time units;
- maximum retained real-time bytes per connector;
- useful lifetime for a queued real-time unit;
- native close timeout.

No daemon or library path infers these values. The values remain owner decisions until measurement and review establish production settings.

## 4. Reserve before allocation

Production construction follows this order:

```text
request an exact Mesh child reservation
    -> atomically reserve the process and child opening claim
    -> create the cleanup owner
    -> start owned asynchronous construction
    -> allocate RTCPeerConnection
    -> attach it to the cleanup owner
    -> install callbacks and connector machinery
    -> recheck attempt liveness
    -> publish the worker or start cleanup
```

The reservation exists before native construction. Cancellation after native allocation, result delivery, owner-controlled runtime shutdown, or construction failure starts the same cleanup owner. The runtime owner cancels and joins construction before destroying its executor. The cleanup owner then fences callbacks, drains connector-owned pending candidates, wakes blocked work, and retires the native peer. A confirmed close releases the reservation. A failed or unconfirmed close retains only that connector's exact claim.

Raw `Transport::open_peer*` construction remains available only to tests or the explicit `transport-lab` feature.

## 5. Lock order and retirement

Attempt allocation, promotion, and retirement share one attempt-transition mutex. Connector promotion does not hold connector authority while acquiring that mutex:

1. Move the candidate to private `Promoting` state under connector authority.
2. Release connector authority.
3. Perform the attempt transition.
4. Release the attempt-transition mutex.
5. Reacquire connector authority and publish the result.

Attempt retirement releases its transition mutex before notifying connector work. A promoted winner is no longer an awaiting race candidate. Retirement cleans losing candidates without revoking an already transferred connected winner.

## 6. Accounting failure and cleanup failure

The opening claim contains one transport object, one connector-construction work item, and one owned task slot. The connected claim contains one transport object and one owned cleanup task slot. Promotion atomically replaces the opening claim with the connected claim.

There are two different failure classes:

- Aggregate accounting corruption means the total can no longer be proved. Examples include inconsistent subtraction and a poisoned accounting mutex. The process owner sets `accounting_poisoned`, preserves conservative consumption, and refuses later admissions.
- A known native cleanup failure belongs to one exact connector. Close error, close timeout, cleanup-runtime failure, or cleanup-thread failure retains that connector's exact claims and returns a visible terminal error. It does not poison unrelated process slots. The retained claim continues to consume capacity.

Duplicate connected claims are kept in an explicit collection. They are never forgotten or overwritten. If native close succeeds, the exact retained claims release. If close fails, those claims remain held.

## 7. Callback classes, flows, and backpressure

The generic connector has three callback classes:

- control;
- endpoint data;
- codec-neutral real-time flow.

Audio and video names exist only in the WebRTC compatibility adapter. The generic connector has no connector-wide real-time mailbox. Each admitted codec-neutral flow owns an independent bounded queue under the connector aggregate. A saturated video, monitor, or camera flow cannot consume or discard another flow's queue.

The receiver uses an owner-weighted rotating scheduler. A ready class can consume only its current service quantum before the scheduler advances. Empty classes are skipped. This gives every continuously ready admitted class a bounded service opportunity. No weight is built into production code.

Control and endpoint-data callbacks use bounded reliable backpressure and race their waits against connector retirement. Real-time queue insertion is synchronous. It first discards whole units whose useful lifetime has expired, then either retains the complete arriving unit or refuses that complete unit when the exact flow queue is full. It never waits one full deadline for each stale unit. Final `DropNewest`, `DropOldest`, latest-unit, recovery-unit, retransmission, or FEC policy belongs to the later session-bound application flow contract.

Ordinary endpoint frames use `MAX_ENDPOINT_FRAME_BYTES`. Encoded real-time units use the separate owner-supplied `max_realtime_unit_bytes`. Their accounting paths are also separate: endpoint bytes use `FrameBytes`, while encoded real-time units use `MediaQuarantine`. An H.264, HEVC, AV1, or other access unit is not constrained by the ordinary endpoint-frame limit unless the owner independently selects the same numeric value. Inbound fragment retention, in-progress assembly, assembled output, and outbound native write all acquire their applicable byte claim before the protected allocation or queueing boundary.

The fixed H.264 packet-count ceiling remains a compatibility hard stop. It is not the byte budget.

## 8. Data channel and Endpoint Auth

`DataChannelOpen` proves that the exact connector has a working channel eligible for Endpoint Auth. It does not prove application reachability, endpoint identity, bilateral admission, or session authority.

The exact candidate is consumed into `ConnectedChannelCapability`, then moved into `EndpointAuthTask`. `EndpointAuthTask` is the mandatory connected-channel provenance owner. Arc 03 does not claim Endpoint Auth resource admission or transcript verification.

Before peer admission, the engine accepts only the existing Endpoint Auth protocol. Application messages and real-time delivery remain blocked.

The callback scheduler cannot release an endpoint protocol frame until the exact `DataChannelOpen` transition has committed and the Endpoint Auth task has been installed on the current peer owner. Close and retirement events remain deliverable before that transition. Replacement at the commit fence retires the losing connector and drops its retained endpoint protocol queue.

## 9. Real-time compatibility capability

`ConnectorRealtimeFlowCapability` is a temporary connector compatibility capability. It proves only that the current legacy admission path authorized connector-native real-time work on one exact live connector.

It is not the final generalized real-time-flow contract. That later contract must be session-bound, principal-bound, policy-guarded, and independently resource-reserved. Arc 03 does not define or mint that final authority.

The existing WebRTC adapter requires the compatibility capability for lane open, lane close, encoded send, and lane reaping. Possession of `&WebRtcConnectorWorker` is insufficient. H.264, Opus, audio, video, and lane names remain compatibility details rather than basal capability semantics.

## 10. Endpoint path and legacy forwarding

The V4 channel path sends endpoint data only to the selected endpoint session. A broadcast performs one direct endpoint-session send per connected peer. The V4 engine no longer invokes `routing::send_routed`, `routing::broadcast_flood`, or `routing::on_relay_frame`.

TURN selection does not change this boundary. TURN is an ICE carrier for the exact endpoint session, not a MyOwnMesh application relay. Signaling and endpoint payload do not share a logical service.

RTM-001 remains an outstanding legacy violation until the old shaped-topology routing module and its compatibility surface are removed or separately dispositioned. Arc 03 does not claim that every historical repository path is endpoint-to-endpoint merely because the V4 connector path no longer calls that module.

RTM-002 separately tracks the optional `RelayService`, which forwards opaque application payload through an ordinary member. The connector-capable V4 daemon rejects an initially enabled relay with a typed service-policy error, and live service reconfiguration rejects it before persistence. The public legacy relay type remains in the repository, so RTM-002 stays open until that direct construction surface is removed or separately fenced.

## 11. Legacy transition decision

The V4 connector path cannot call `send_routed`, `broadcast_flood`, `on_relay_frame`, or `RelayService`. Historical compatibility surfaces still exist outside that path. The owner must choose one disposition before Arc 03 is merge-approved:

1. Fence the historical routing and relay surface into an explicit V1 compatibility package that future V4 session capabilities cannot reach. Keep deletion scheduled for Arc 12.
2. Remove the surface now as an accepted breaking change, with typed no-direct-session and partial-fanout behavior.

This draft selects neither option. RTM-001 and RTM-002 remain open. Immediate breaking removal is not inferred.

## 12. Daemon startup

`embedded::start_connector_capable` is the explicit connector-capable daemon entry point. `embedded::start_infrastructure_only` starts without connector authority only when node participation is disabled. Configuration-only `embedded::start` selects that infrastructure form or returns the typed `EmbeddedStartError::MissingConnectorResourcePolicy`.

An infrastructure-only daemon rejects later node enablement before persistence. This prevents an ownerless daemon from silently entering a state that refuses every native connector. No startup path invents policy values.

The `myownmesh serve` command is usable in both forms. With node participation disabled it calls `start_infrastructure_only`. With node participation enabled it requires the complete owner-selected connector policy vector through the documented `MYOWNMESH_CONNECTOR_*` environment inputs and calls `start_connector_capable`. A missing, zero, or invalid value fails before daemon startup.

## 13. Public construction surface

`ConnectorCapableResourcePolicy` contains the process policy and the exact per-Mesh policy. `Mesh::open_with_connector_resource_policy` and `Mesh::open_with_identity_and_connector_resource_policy` install or reuse the process policy, then issue a fresh child scope. `Transport::with_connector_resource_policy` uses the same `ProcessResourceRoot`. `MeshHandle::connector_resource_report` reports the process aggregate. `MeshHandle::mesh_connector_resource_report` reports the exact runtime child.

`Mesh::open` and `Mesh::open_with_identity` support infrastructure-only library use. A network join through either handle returns the typed `Error::ConnectorPolicyRequired` before any network runtime is created.

`PeerSession` has no `Deref` implementation. The worker exposes narrow connector methods. Raw peer constructors remain test or lab surfaces.

## 14. Observation harness

The ignored `v4_arc03_measure_callback_classes_without_selecting_a_budget` harness requires workload-shape inputs only: sample count, flow count, and payload bytes. It derives a finite laboratory envelope large enough to observe that workload and prints raw per-event queue age, active-flow count, queue occupancy, service delay, payload size, in-progress assembly count, retained bytes, and drops. That envelope is not a production policy and is not proposed as a default.

Native direct, TURN-selected, cancellation, reconnect, multi-peer, and multi-Mesh controls remain separate so each result names the exact path it exercised. Timing or capacity evidence from one scenario is not generalized to another.

## 15. Proof boundary and merge blockers

Deterministic controls cover process-global and exact-Mesh admission, conflicting policies, reserve-before-allocation, promotion and retirement ordering, successful close, exact-claim retention after close failure, cleanup timeout, cleanup startup failure, weighted callback service, per-flow backpressure, separate endpoint and real-time limits, Endpoint Auth provenance, lifecycle ordering, stale replacement, and V4 rejection of legacy forwarding calls.

Socket-bearing controls in WSL cover native construction cancellation, owner-controlled runtime shutdown, direct WebRTC behavior, and the real TURN-selected positive and negative endpoint paths.

Arc 03 remains draft and unmerged until all of these conditions hold:

1. The exact pushed head passes formatting, check, Clippy, tests, doctests, compiler-boundary checks, and the red-team record.
2. The unchanged Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl matrix passes on that exact head.
3. The owner reviews measured production values for every policy field listed in section 3.
4. The WSL socket tests pass on the exact source revision.
5. The owner resolves the legacy transition choice in section 11.

Arc 03 does not claim complete hostile-ingress admission, complete dependency-owned resource accounting, a bounded pre-SDP candidate queue, Endpoint Auth transcript verification, Endpoint Auth resource admission, final real-time session authority, or removal of RTM-001 and RTM-002.
