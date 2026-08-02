# V4 Arc 03 WebRTC connector ownership

Status: corrective implementation candidate on `arc/03-webrtc-connector-worker`. PR #112 remains draft and unmerged. Arc 03 is not merge-approved until the exact pushed head passes the supported-platform matrix and the owner supplies reviewed production resource-policy values.

Frozen Arc 02C parent: `0484f7f0987e5d1c488b30ac21e46f1925ea65cb`

## 1. Scope

Arc 03 puts the existing WebRTC connection path behind explicit resource, attempt, connector, cleanup, and Endpoint Auth owners. It preserves the existing ICE, STUN, TURN, DTLS, direct path, native RTP, H.264, Opus, mDNS, Nostr, reconnect, and recovery behavior.

This arc adds no route identity, durable connector record, path generation, pair permission, application relay, or authentication-before-pathfinding rule. It adds no Arc 03 responsibilities to `PeerStateData`, `NetworkCmd`, or `NetworkState`.

## 2. Cardinality and owner chain

```text
process resource owner
    -> admits one structural connector-candidate claim

one connection attempt
    -> may own multiple connector candidates

one WebRTC connector candidate
    -> one RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and candidate pairs

DataChannelOpen from the exact live connector
    -> ConnectedChannelCapability
    -> EndpointAuthTask owns connected-channel provenance
    -> existing endpoint authentication and bilateral admission
    -> optional codec-neutral ConnectorRealtimeFlowCapability
```

`ConnectorCandidateCapability` names one complete connector candidate. It never names a trickled `LocalIceCandidate`.

`admit_single_connector_candidate` defines the structural claim and creates an attempt. It cannot admit its own capacity. `PreAuthAttemptPermit` receives a `ConnectorResourceOwnerPort`, and only that external port can reserve a candidate. The port is shared by the process transport and reports its live candidate count and poison state.

The public owner policy has no `Default`. The owner must provide:

- the maximum active connector-candidate count;
- separate control, endpoint-data, audio, and video callback mailbox capacities;
- a nonzero native-close deadline.

The implementation does not infer or manufacture those values.

## 3. Attempt transition and lock order

`AttemptLifetime` is the cancellation owner for one candidate race. Allocation, promotion, and retirement use one synchronous attempt-transition mutex.

Connector promotion uses a non-nested transition:

1. Move the candidate into private `Promoting` state under connector authority.
2. Release connector authority.
3. Perform the attempt transition.
4. Release the attempt-transition mutex.
5. Reacquire connector authority and publish the result.

Attempt retirement releases its transition mutex before notifying watchers. No production path acquires connector authority while holding attempt transition and then acquires those locks in reverse elsewhere.

A promoted winner is no longer an awaiting race candidate. Retiring the attempt invalidates and cleans losing candidates without revoking the connected winner.

## 4. Reserve before allocation

Production construction follows this order:

```text
request reservation from process resource owner
    -> reserve exact structural child claim
    -> create the one connector cleanup owner
    -> start owned asynchronous construction
    -> allocate RTCPeerConnection privately
    -> attach it to the same cleanup owner
    -> install callbacks and existing connector machinery
    -> recheck exact attempt liveness
    -> publish worker or start cleanup
```

The resource guard exists before the construction task, native peer, callback mailboxes, parser work, or candidate work that it protects. Unknown input can reach this owner under anonymous-ingress and process policy. It does not require a Device identity or Closed-mesh authorization.

The same `ConnectorCloseOwner` follows partial, delivered, cancelled, and installed results. Cancellation after native allocation and cancellation after result delivery both start that owner. Caller-runtime shutdown cannot cancel the cleanup attempt because the close owner uses its own bounded cleanup runtime. The native dependency may still fail to close after its original runtime disappears; that outcome reaches visible poison and conservative retention at the configured deadline.

Raw `Transport::open_peer*` construction is absent from the default production API. It remains available only to unit tests or the explicit `transport-lab` feature.

## 5. Cleanup ownership and close failure

Connector retirement fences callback acceptance, wakes blocked producers and silent workers, cancels local awaits, drains the owned remote-candidate queue, retires losing candidates, and starts the one native close owner.

Successful native close is the only path that releases the connector claim and attached connected claims. The cleanup owner applies the owner-supplied close deadline and produces one terminal result for all waiters.

Close error, timeout, cleanup-runtime build failure, or cleanup-thread start failure produces an explicit `Poisoned` terminal state. In that state:

- the resource owner remains conservatively consumed;
- the report remains visibly poisoned with a nonzero active candidate count;
- later candidate admission is refused;
- the failed allocation is never treated as reusable capacity.

Duplicate connected claims are retained in an explicit poisoned collection. No duplicate path uses `mem::forget`. Adding another claim cannot overwrite a terminal cleanup failure or strand waiters.

The failure is bounded in time by the supplied close deadline. Capacity remains unavailable for the process lifetime because native cleanup was not proven. The leak is visible and bounded by the owner policy, not silent or reusable.

## 6. Resource transition

The exact structural opening claim contains:

- one transport object;
- one connector-construction work item;
- one owned task slot.

The connected claim contains one transport object and one owned task slot for eventual cleanup. Promotion atomically replaces the opening claim with the connected claim. It releases construction-only work without exposing an unreserved interval.

An inconsistent aggregate transition or release poisons the resource owner, preserves conservative consumption, and refuses later admission. Production resource measurement contains no `expect` or panic path.

These are structural claims, not a complete WebRTC memory model. Dependency-owned sockets, ICE pairs, DNS, STUN, TURN, allocator overhead, and internal ICE-agent queues still need measured policy work where the dependency exposes usable observations.

## 7. Callback mailboxes

Each connector has four independent bounded mailboxes:

- control;
- endpoint data;
- audio;
- video.

The process resource owner supplies each capacity separately. Backpressure in one class cannot occupy another class's mailbox. Producers await capacity and race that await against connector retirement, so retirement wakes a producer blocked on a full mailbox.

The receiver currently prefers control, then endpoint data, then audio, then video when several classes are ready. The deterministic tests prove isolation and backpressure for every class. They do not prove an operationally sufficient capacity or starvation bound. Capacity and workload suitability remain measured owner decisions.

Connector events do not enter the general `NetworkCmd` queue. Every event carries the exact worker incarnation, and stale queued events cannot mutate a replacement worker.

The pre-SDP remote-candidate queue remains observation-only. Its items, logical bytes, retained bytes, and `Vec` container capacity are observed separately. Arc 03 does not claim that observation is an admission limit.

## 8. Exact peer ownership

Every registry installation has a process-local installation stamp. `PeerOwnerToken` contains that stamp and cannot be recreated from a Device ID, label, or diagnostic epoch.

Synchronous exact-owner effects use `PeerRegistry::with_current`. Asynchronous work captures the exact token and rechecks it before committing state or sending an owner-derived message.

The activation commit stays inside the exact-owner fence through roster persistence. A forced replacement at that boundary proves that the stale owner cannot persist membership, broadcast governance, resolve waiters, clear reconnect state, flush application frames, or emit `Approved` for the replacement.

Only inbound `Approve` records remote consent. A successful local send records only local connector acceptance. Authentication, local send acceptance, and inbound approval must all belong to the same current owner before activation.

## 9. Endpoint Auth and real-time flow

`DataChannelOpen` consumes the exact live connector candidate. A move-only handoff binds the resulting `ConnectedChannelCapability` to the exact connector incarnation and places it in `EndpointAuthTask`.

`EndpointAuthTask` is the mandatory connected-channel provenance owner. Arc 03 does not claim that it has admitted endpoint-authentication resources or verified the Arc 04 transcript. Those remain Arc 04 work.

The legacy authenticated and mutually-approved state transition may request a `ConnectorRealtimeFlowCapability` through the installed Endpoint Auth task. Issuance checks all of these facts:

- the peer is the current registry owner;
- the peer is authenticated and Active or Shelved;
- the Endpoint Auth task belongs to the exact live connector;
- the connector is not retired.

The capability is codec-neutral. It grants one exact connector-native real-time flow and names no media kind, lane, codec, H.264, Opus, video, or audio semantic. The existing media adapter consumes that capability for lane open, lane close, real-time send, and lane reaping.

Possessing `&WebRtcConnectorWorker` is insufficient for those operations. A capability from another connector, including another connector in the same runtime, is rejected. Outbound application frames also check current session admission before any direct send or shaped-topology fallback.

Before general peer admission, the existing engine admits only endpoint-authentication protocol. Application messages remain blocked. Remote audio is dropped before event creation and remote video is dropped before access-unit assembly.

## 10. Public construction surface

`Mesh::open_with_connector_resource_owner` and `Mesh::open_with_identity_and_connector_resource_owner` install an explicit process resource owner. `MeshHandle::connector_resource_report` exposes its current state.

The older `Mesh::open` and `Mesh::open_with_identity` paths select no hidden policy. They can construct the mesh runtime, but native connector allocation is refused until an owner port is installed through the explicit constructor. This preserves source compatibility without manufacturing production capacity.

`PeerSession` has no `Deref` implementation. The worker exposes narrow connector methods. The raw peer constructors remain test or lab surfaces.

## 11. TURN-selected endpoint proof

The Linux integration test starts the repository's real TURN server on an ephemeral loopback port and forces both WebRTC transports to relay-only selection through the lab feature. The test supplies explicit test-only resource policies. Those fixture values are not production recommendations.

The positive control requires, for both endpoints:

- `Authenticated` before `Approved`;
- the expected endpoint identity;
- bilateral admission;
- a selected Relay-to-Relay ICE pair;
- typed endpoint data delivered in both directions.

The negative control creates a second relay-selected pair with endpoint authentication but no bilateral admission. It proves that relay selection cannot authorize typed endpoint data, real-time sample delivery, or lane creation.

A socket-free core negative control also assigns a Relay-to-Relay diagnostic pair to unauthenticated and pending peers. Neither state satisfies session admission or produces a real-time-flow capability.

Signaling uses the existing local test broker. Endpoint payload uses the ordinary endpoint session. TURN is the selected ICE carrier, not a MyOwnMesh application relay, and signaling carries no endpoint data.

## 12. Executed proof boundary

The local deterministic controls cover:

- external resource-owner admission before allocation;
- multi-candidate attempt ownership and retirement;
- non-nested attempt and connector transitions;
- atomic candidate-to-connected resource transfer;
- successful close, close error, close timeout, caller-runtime shutdown, and cleanup-start failure;
- construction cancellation during caller-runtime shutdown and background-task failure;
- explicit duplicate-claim poison retention;
- Endpoint Auth handoff release before and after native close;
- independent control, endpoint-data, audio, and video backpressure;
- stale peer replacement at roster persistence;
- codec-neutral real-time-flow gating;
- relay diagnostics having no authentication or admission authority.

Socket-bearing cancellation, native WebRTC preservation, and the real TURN proof run in the isolated Linux harness. Exact commands and attack statements are in `red-teams/ARC-03-WEBRTC-CONNECTOR-WORKER.md`.

## 13. Merge blockers

Arc 03 must remain draft and unmerged until:

1. The exact pushed head passes the unchanged Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl CI matrix.
2. The owner reviews measured production values for candidate count, the four callback mailboxes, and native-close deadline.
3. The isolated Linux socket tests pass on the exact source revision.
4. The source inventory, compiler-boundary checker, and red-team record match the exact source.

Arc 03 does not claim complete hostile-ingress resource admission, complete retained-memory accounting, a bounded pre-SDP candidate queue, Endpoint Auth transcript verification, or Endpoint Auth resource admission.
