# V4 Arc 03 WebRTC connector ownership

Status: corrective Arc 03D implementation candidate on `arc/03-webrtc-connector-worker`. PR #112 remains draft and unmerged. Arc 03 is not merge-approved until the exact pushed head passes the supported-platform matrix and the owner supplies reviewed production policy values.

Frozen Arc 02C parent: `0484f7f0987e5d1c488b30ac21e46f1925ea65cb`

## 1. Scope

Arc 03 puts the existing WebRTC connection path behind explicit process, attempt, connector, cleanup, and Endpoint Auth owners. It preserves ICE, STUN, TURN, DTLS, direct paths, native RTP, H.264, Opus, mDNS, Nostr, reconnect, and recovery behavior.

This arc does not add route identities, durable connector records, path generations, pair permissions, authentication before pathfinding, Endpoint Auth transcript verification, durable session semantics, or codec policy. It does not add Arc 03 responsibilities to `PeerStateData`, `NetworkCmd`, or `NetworkState`.

## 2. Cardinality and ownership

```text
one ProcessResourceRoot
    -> one process connector resource owner
    -> shared by every Mesh runtime in the process

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

`admit_single_connector_candidate` defines the structural claim. It cannot create capacity. Only the owner installed in `ProcessResourceRoot` can reserve that claim. A second Mesh runtime requesting the same policy shares the installed owner. A conflicting policy is rejected with `ConnectorResourcePolicyConflict`. External code cannot construct `ConnectorResourceOwnerPort` directly.

## 3. Owner-selected policy

The public policy has no `Default`. The process owner must supply all of these values:

- maximum active connector candidates for the process;
- control callback capacity;
- endpoint-data callback capacity;
- codec-neutral real-time callback capacity;
- control, endpoint-data, and real-time scheduler weights;
- maximum encoded real-time unit bytes;
- real-time enqueue deadline;
- native close timeout.

No daemon or library path infers these values. The values remain owner decisions until measurement and review establish production settings.

## 4. Reserve before allocation

Production construction follows this order:

```text
request a process reservation
    -> reserve the opening claim
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

## 7. Callback classes and backpressure

The generic connector has three callback classes:

- control;
- endpoint data;
- codec-neutral real-time flow.

Audio and video names exist only in the WebRTC compatibility adapter. They share the generic real-time mailbox and do not appear in `ConnectorCallbackMailboxCapacities`.

The receiver uses an owner-weighted rotating scheduler. A ready class can consume only its current service quantum before the scheduler advances. Empty classes are skipped. This gives every continuously ready admitted class a bounded service opportunity. No weight is built into production code.

Control and endpoint-data callbacks use bounded reliable backpressure and race their waits against connector retirement. Real-time callbacks use the owner-supplied enqueue deadline. A real-time callback that cannot enter its queue before that deadline is dropped as the newest unit. This is a compatibility contract, not the final application flow contract.

Ordinary endpoint frames use `MAX_ENDPOINT_FRAME_BYTES`. Encoded real-time units use the separate owner-supplied `max_realtime_unit_bytes`. Their accounting paths are also separate: endpoint bytes use `FrameBytes`, while encoded real-time units use `MediaQuarantine`. An H.264, HEVC, AV1, or other access unit is not constrained by the ordinary endpoint-frame limit unless the owner independently selects the same numeric value.

## 8. Data channel and Endpoint Auth

`DataChannelOpen` proves that the exact connector has a working channel eligible for Endpoint Auth. It does not prove application reachability, endpoint identity, bilateral admission, or session authority.

The exact candidate is consumed into `ConnectedChannelCapability`, then moved into `EndpointAuthTask`. `EndpointAuthTask` is the mandatory connected-channel provenance owner. Arc 03 does not claim Endpoint Auth resource admission or transcript verification.

Before peer admission, the engine accepts only the existing Endpoint Auth protocol. Application messages and real-time delivery remain blocked.

## 9. Real-time compatibility capability

`ConnectorRealtimeFlowCapability` is a temporary connector compatibility capability. It proves only that the current legacy admission path authorized connector-native real-time work on one exact live connector.

It is not the final generalized real-time-flow contract. That later contract must be session-bound, principal-bound, policy-guarded, and independently resource-reserved. Arc 03 does not define or mint that final authority.

The existing WebRTC adapter requires the compatibility capability for lane open, lane close, encoded send, and lane reaping. Possession of `&WebRtcConnectorWorker` is insufficient. H.264, Opus, audio, video, and lane names remain compatibility details rather than basal capability semantics.

## 10. Endpoint path and legacy forwarding

The V4 channel path sends endpoint data only to the selected endpoint session. A broadcast performs one direct endpoint-session send per connected peer. The V4 engine no longer invokes `routing::send_routed`, `routing::broadcast_flood`, or `routing::on_relay_frame`.

TURN selection does not change this boundary. TURN is an ICE carrier for the exact endpoint session, not a MyOwnMesh application relay. Signaling and endpoint payload do not share a logical service.

RTM-001 remains an outstanding legacy violation until the old shaped-topology routing module and its compatibility surface are removed or separately dispositioned. Arc 03 does not claim that every historical repository path is endpoint-to-endpoint merely because the V4 connector path no longer calls that module.

RTM-002 separately tracks the optional `RelayService`, which forwards opaque application payload through an ordinary member. The connector-capable V4 daemon rejects an initially enabled relay with a typed service-policy error, and live service reconfiguration rejects it before persistence. The public legacy relay type remains in the repository, so RTM-002 stays open until that direct construction surface is removed or separately fenced.

## 11. Daemon startup

`embedded::start` now returns the typed `EmbeddedStartError::MissingConnectorResourcePolicy`. `embedded::start_with_connector_resource_policy` is the explicit connector-capable daemon entry point.

This prevents an ownerless daemon from silently creating a Mesh that later refuses every native connector. No startup path invents policy values.

## 12. Public construction surface

`Mesh::open_with_connector_resource_policy` and `Mesh::open_with_identity_and_connector_resource_policy` install or reuse the process policy. `Transport::with_connector_resource_policy` uses the same `ProcessResourceRoot`. `MeshHandle::connector_resource_report` exposes active candidates and aggregate accounting poison state.

`Mesh::open` and `Mesh::open_with_identity` still support ownerless library use, but their transports cannot allocate native connectors. Daemon startup does not use those paths.

`PeerSession` has no `Deref` implementation. The worker exposes narrow connector methods. Raw peer constructors remain test or lab surfaces.

## 13. Proof boundary and merge blockers

Deterministic controls cover process-global admission, conflicting policies, reserve-before-allocation, promotion and retirement ordering, successful close, exact-claim retention after close failure, cleanup timeout, cleanup startup failure, weighted callback service, class-specific backpressure, separate endpoint and real-time limits, Endpoint Auth provenance, stale replacement, and V4 rejection of legacy forwarding calls.

Socket-bearing controls in WSL cover native construction cancellation, owner-controlled runtime shutdown, direct WebRTC behavior, and the real TURN-selected positive and negative endpoint paths.

Arc 03 remains draft and unmerged until all of these conditions hold:

1. The exact pushed head passes formatting, check, Clippy, tests, doctests, compiler-boundary checks, and the red-team record.
2. The unchanged Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl matrix passes on that exact head.
3. The owner reviews measured production values for every policy field listed in section 3.
4. The WSL socket tests pass on the exact source revision.

Arc 03 does not claim complete hostile-ingress admission, complete dependency-owned resource accounting, a bounded pre-SDP candidate queue, Endpoint Auth transcript verification, Endpoint Auth resource admission, final real-time session authority, or removal of RTM-001 and RTM-002.
