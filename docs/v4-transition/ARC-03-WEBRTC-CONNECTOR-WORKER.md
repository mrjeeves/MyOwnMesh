# V4 Arc 03 WebRTC connector ownership

Status: Arc 03G corrective candidate on `arc/03-webrtc-connector-worker`. Fork PR #4 remains draft and unmerged. Arc 03 is not merge-approved.

Arc 03G parent: `5ca7143d1fcd828242d02220ebaf5206e7a98658`

## 1. Scope

Arc 03 puts the existing WebRTC connector behind explicit process, Mesh runtime, attempt, candidate, callback, cleanup, and Endpoint Auth owners. It preserves the existing ICE, STUN, TURN, DTLS, direct path, native RTP, H.264, Opus, mDNS, Nostr, reconnect, and recovery implementations.

This arc does not add route identities, durable connector records, path generations, pair permissions, authentication before pathfinding, Endpoint Auth transcript verification, authenticated session authority, application flow policy, or final codec policy. It does not add Arc 03 responsibilities to `PeerStateData`, `NetworkCmd`, or `NetworkState`.

Endpoint payload uses an exact endpoint WebRTC session. TURN may be the selected ICE carrier for that session. Signaling never carries endpoint payload.

## 2. Cardinality and authority

```text
one ProcessResourceRoot
    -> one process connector resource owner
    -> one child scope for each live Mesh runtime

one Mesh connector child scope
    -> one owner-selected candidate ceiling
    -> no implicit borrowing from another Mesh scope

one connection attempt
    -> multiple connector candidates

one WebRTC connector candidate
    -> one RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and pairs

DataChannelOpen from the exact live connector
    -> ConnectedChannelCapability
    -> EndpointAuthTask owns connected-channel provenance
```

`ConnectorCandidateCapability` represents one complete connector candidate, not one trickled `LocalIceCandidate`. The attempt defines its structural claim but cannot manufacture capacity. Admission updates the process aggregate and exact Mesh child under one mutex. External code cannot construct either resource owner.

## 3. Owner-selected policy

The public connector policy has no `Default`. A connector-capable owner supplies:

- process and per-Mesh candidate ceilings;
- pre-SDP candidate item and payload-byte ceilings;
- control and endpoint-data mailbox capacities;
- control and endpoint-data scheduler weights;
- disabled or enabled generic real-time ownership;
- when enabled, the real-time scheduler weight, flow counts, per-flow queue count, structural unit limits, and independent inbound, outbound, and total byte ceilings.

No native-close timeout exists. No elapsed duration changes resource, protocol, authentication, or cleanup truth. The disabled real-time form carries no media values. The enabled form creates no H.264, Opus, video, or audio tracks.

The temporary H.264 and Opus adapter requires a separate, explicit `LegacyWebRtcMediaProfile`. Its constructor validates the lane identity space and pre-provisioned lane counts. Attaching it to a connector policy also proves that the generic outbound-flow ceiling can own every pre-provisioned track. The normal V4 daemon does not construct this profile.

## 4. Reserve before retention and allocation

Production connector construction follows this order:

```text
request exact Mesh child capacity
    -> atomically reserve process and Mesh claims
    -> create one cleanup owner
    -> start owned asynchronous construction
    -> allocate RTCPeerConnection
    -> attach it to the cleanup owner
    -> install callbacks and connector state
    -> recheck attempt liveness
    -> publish the worker or start cleanup
```

Cancellation after native allocation, cancellation after result delivery, runtime shutdown, and construction failure all reach the same close owner. Raw `Transport::open_peer*` construction is limited to tests and `transport-lab`.

Before remote SDP exists, duplicate candidates are rejected before queue reservation. A new candidate must reserve one item and its exact retained payload bytes before insertion. Replacement, cancellation, shutdown, queue drain, and completed application drop that exact reservation.

## 5. Transition and lock order

Attempt allocation, promotion, and retirement share one attempt-transition mutex. Connector promotion never holds connector authority while acquiring it:

1. Move the candidate into private `Promoting` state under connector authority.
2. Release connector authority.
3. Perform the attempt transition.
4. Release the attempt-transition mutex.
5. Reacquire connector authority and publish or retire the result.

Attempt retirement may notify connector retirement only after its transition lock is released. This removes the reverse lock edge.

## 6. Close ownership and truth

One `ConnectorCloseOwner` owns every private, delivered, cancelled, installed, and partially constructed native connector result. Close begins by disabling real-time delivery, committing the operation fence, retiring callback identity, draining connector-owned queues, and waiting for operations that entered before the fence.

Close execution uses one bounded process cleanup executor. The executor has one OS thread, one current-thread Tokio runtime, and a queue bounded by the already selected process candidate ceiling. It does not create a thread or runtime per close.

The close owner remains `Closing` until `RTCPeerConnection::close()` returns. Cancelling a caller that waits for close does not cancel owner cleanup.

- A successful native close releases the exact candidate and connected claims.
- A returned native-close error retains only that connector's exact claims and reports `Failed`.
- An accounting transition that cannot be proved poisons only the applicable accounting owner or real-time byte domain and refuses later admission there.
- No timeout, observation window, or caller cancellation creates a terminal cleanup fact.

## 7. Application-affecting operation fence

The same close fence covers inbound callbacks, endpoint sends, real-time writes, lane operations, track creation, SDP work, candidate application, and ICE restart. Operations that entered before close may finish before native close begins. Operations that arrive after close commitment fail before reaching the native or compatibility owner.

`DataChannelClosed` commits the fence before it enters the control mailbox. Real-time delivery becomes false at the same boundary. The receiver may deliver the exact close event, then delivers nothing later. Endpoint protocol data that arrived before `DataChannelOpen` remains in its bounded mailbox but cannot reach the engine until the exact open transition commits.

## 8. Bounded real-time ownership

The generic real-time owner has independent inbound and outbound domains beneath one total connector ceiling. Each admitted flow has its own bounded queue. A ready-flow scheduler gives each flow a bounded service opportunity. One saturated flow cannot replace or discard another flow's retained units.

Inbound partial units are bounded by exact flow ownership, fragment bytes, fragment count, unit bytes, simultaneous in-progress units, and the inbound byte ceiling. H.264 also retains its fixed packet-count compatibility hard stop. No timer, deadline, expiry task, or useful-lifetime value owns release. A partial unit releases on a concrete stream event such as timestamp transition, discontinuity, reset, track closure, flow revocation, replacement, connector retirement, or owner drop.

Complete units use a bounded per-flow queue and deterministic `DropNewest`. Their byte lease moves with the queued event and remains owned through downstream copies. Dequeue alone does not release the lease.

Outbound compatibility acquires the exact outbound flow owner before native track attachment or revival. Attachment failure rolls back a new owner. A transient lane releases its owner only after the track is removed or proved absent. A failed native removal retains the exact claim for connector cleanup.

## 9. Endpoint Auth boundary

`DataChannelOpen` proves that the exact connector has a working channel eligible for Endpoint Auth. It does not prove endpoint identity, transcript validity, bilateral application admission, reachability, or session authority.

The exact candidate becomes `ConnectedChannelCapability`, which moves into `EndpointAuthTask`. Arc 03 proves only the connected-channel provenance handoff. Endpoint Auth transcript verification and `AuthenticatedChannelCapability` production belong to Arc 04.

`ConnectorRealtimeFlowCapability` is temporary compatibility authority for the existing WebRTC media adapter. It is exact to one connector and requires Endpoint Auth task provenance before issue. It is not the final generalized application flow contract.

## 10. LegacyV1 boundary

Historical application routing and ordinary-member relay remain available only under the `legacy-v1` feature. The feature exposes an explicit deprecated `LegacyV1Runtime`. That runtime owns a crate-private marker required by every legacy routing entry point. The normal V4 engine, connector, Endpoint Auth task, daemon constructor, and runtime cannot construct the marker.

The legacy source remains frozen for downstream migration. Its public facade is deprecated and its named removal remains Arc 12. RTM-001 and RTM-002 therefore remain open until deletion. Arc 03 claims isolation from new V4 paths, not repository-wide removal.

## 11. Daemon and library forms

Supported daemon construction is explicit:

- `embedded::start_connector_capable(config, policy)`;
- `embedded::start_infrastructure_only(config)`;
- feature-gated deprecated `embedded::start_connector_capable_with_legacy_v1(config, policy, runtime)` for the frozen adapter.

Infrastructure-only startup requires node participation to be disabled. Later node enablement fails without changing runtime state. Connector-capable startup rejects missing, zero, invalid, or inconsistent owner values before joining.

The library forms are `Mesh::open_connector_capable`, `Mesh::open_connector_capable_with_identity`, `Mesh::open_infrastructure_only`, and `Mesh::open_infrastructure_only_with_identity`. Ambiguous ownerless open forms do not exist.

## 12. Mechanical modules

- `runtime/attempt/admission.rs`: attempt admission and promotion
- `runtime/attempt/lifetime.rs`: attempt lifetime and cancellation
- `runtime/attempt/policy.rs`: owner-selected policy types and validation
- `runtime/attempt/resource_owner.rs`: process and Mesh accounting plus cleanup executor
- `transport/webrtc/callback.rs`: callback classes, fence, and scheduler
- `transport/webrtc/realtime.rs`: flow queues and exact byte leases
- `transport/webrtc/cleanup.rs`: native close and conservative retention
- `transport/webrtc/media.rs`: temporary H.264 and Opus lane adapter
- `transport/webrtc/h264.rs`: structurally bounded H.264 assembly

`PeerSession` does not implement `Deref`. Production native connector creation stays behind `WebRtcConnectorWorker`.

## 13. Evidence and approval boundary

The red-team record and [`scripts/measure-v4-arc03g.ps1`](../../scripts/measure-v4-arc03g.ps1) report exact test names, commands, raw distributions, and residuals. Measurements are observations only. They do not select production policy values. Native dependency memory remains separate from connector-owned exact accounting.

Arc 03 remains draft and unmerged until the exact pushed head passes the unchanged supported-platform matrix, native direct and TURN controls, workspace checks, compiler-boundary controls, and owner review. The arc does not claim complete hostile-ingress admission, native dependency memory accounting, Endpoint Auth verification, final session authority, final generalized flow authority, or removal of RTM-001 and RTM-002.
