# V4 Arc 03 WebRTC connector ownership

Status: code-complete review candidate on `arc/03-webrtc-connector-worker`. PR #112 remains draft and unmerged. Merge approval still requires the exact final supported-platform CI matrix and owner review of the remaining resource-policy boundary.

Frozen Arc 02C parent: `0484f7f0987e5d1c488b30ac21e46f1925ea65cb`

## 1. Scope

Arc 03 moves the existing WebRTC path behind explicit attempt, connector, and endpoint-authentication owners. It preserves the existing ICE, STUN, TURN, DTLS, direct path, native RTP, H.264, Opus, mDNS, Nostr, reconnect, and recovery mechanisms.

This arc does not add route identities, durable connector records, path generations, pair permissions, application relaying, or authentication before pathfinding. It does not move Arc 03 state into `PeerStateData`, `NetworkCmd`, or `NetworkState`.

## 2. Cardinality and owner chain

```text
one connection attempt
    -> multiple connector candidates

one WebRTC connector candidate
    -> one RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and candidate pairs

DataChannelOpen for the exact live connector candidate
    -> ConnectedChannelCapability
    -> EndpointAuthTask
    -> existing endpoint authentication
    -> admitted peer session
```

`ConnectorCandidateCapability` names one complete connector candidate. It never names a trickled `LocalIceCandidate`.

One `PreAuthAttemptPermit` owns an aggregate reservation and can issue several child reservations. Each child remains tied to the exact attempt that created it. Candidate promotion consumes that child into one connected-channel capability. The capability is still not Device identity, mesh admission, session authority, or application authority.

## 3. Attempt transition and lock order

`AttemptLifetime` is the cancellation owner for one candidate race. Allocation, promotion, and retirement use one synchronous attempt-transition mutex.

Connector promotion does not nest the connector-authority mutex with the attempt-transition mutex:

1. Move the candidate into private `Promoting` state under the connector mutex.
2. Release the connector mutex.
3. Perform the attempt transition.
4. Release the attempt-transition mutex.
5. Reacquire the connector mutex and publish the result.

Attempt retirement also releases the transition mutex before notifying watchers. This removes the reverse lock edge between attempt transition and connector authority.

A promoted winner is no longer an awaiting race candidate. Retiring the attempt invalidates and cleans losing candidates without revoking the connected winner.

## 4. Reserve-before-allocation

Production WebRTC construction now follows this order:

```text
reserve connector child
    -> start owned asynchronous construction
    -> allocate RTCPeerConnection privately
    -> install callbacks, media primitives, and connector data channel
    -> recheck exact attempt liveness
    -> publish worker or close the private result
```

Dropping the caller while construction is pending drops `AttemptLifetime`, but it does not abandon the native constructor. The owned construction task receives every partial or complete result. A retired result is closed before its child reservation is released.

Construction is included in the existing 30-second connection-attempt window. A dependency constructor that does not return can no longer park the network driver indefinitely. Timing out the caller retires the attempt; the owned constructor closes any result that later arrives.

Once `RTCPeerConnection` exists, an ordinary construction error retires callbacks, awaits native close, and only then returns the error to the reservation owner. A drop fallback requests cleanup if the executor itself tears down the owned task. This fallback is not used as proof of ordinary cleanup completion.

## 5. Connector and cleanup ownership

`WebRtcConnectorWorker` owns:

- the `PeerSession` and native peer connection;
- one process-local connector incarnation;
- connector authority and promotion state;
- the pre-SDP remote-candidate queue;
- callback mailbox and ordered per-worker event handling;
- its resource-observation scope;
- explicit native shutdown.

The worker receiver owns `AttemptLifetime` and watches both attempt and connector retirement. Retirement wakes a silent worker, fences callbacks and in-flight operations, drains queued candidates, retires an unpromoted candidate, and starts native close. A single close owner runs that close once and provides one shared completion result to every explicit waiter.

The unpromoted candidate claim and the connected claim remain attached to the cleanup owner until `RTCPeerConnection::close` succeeds. A reported close error retains those claims conservatively and fails the waiter. Native close retires the callback gate before awaiting the dependency. A callback blocked on the one-slot queue therefore wakes instead of deadlocking shutdown. Retaining an external `Arc<PeerConnection>` or `Arc<WebRtcConnectorWorker>` does not retain current-owner authority or the endpoint-authentication capability after cleanup.

## 6. Exact peer ownership

Every registry installation has a process-local installation stamp. `PeerOwnerToken` contains that stamp and cannot be reconstructed from a Device ID, label, or diagnostic epoch.

Synchronous exact-owner effects use `PeerRegistry::with_current`. Replacement cannot pass an effect that already owns the current registry entry. Asynchronous work captures the exact token and rechecks it before committing state or sending an owner-derived message.

The activation commit remains under the exact-owner fence through roster persistence. A forced replacement at that boundary proves the old owner cannot:

- persist roster membership;
- emit owner-derived governance messages;
- resolve connection waiters;
- clear reconnect state;
- flush reliable application frames;
- emit `Approved` for the replacement.

Only an inbound `Approve` records remote consent. A successful local send records only local data-channel acceptance. Authentication, local send acceptance, and actual remote approval must all belong to the same current owner before activation.

## 7. Queue and callback bounds

The connector callback mailbox has the algebraic lossless floor of one retained event. Producers await that bounded mailbox. Retirement subscribes before checking current state, competes with the await, and wakes blocked callbacks without a lost-wakeup interval.

Each connector worker processes its own event stream in order. Connector events do not enter `NetworkCmd` or its unbounded general command queue. The worker cannot begin the next handler while its current handler is pending. Stale events retain their exact worker stamp and cannot mutate a replacement.

This is a per-worker bound. It does not bound the total number of hostile attempts or workers in the process. That requires owner-approved anonymous-ingress and process capacities, which Arc 03 does not invent.

The pre-SDP candidate queue remains observation-only. No owner-approved candidate item or byte limit exists, so this arc does not call that queue an admission guard.

## 8. Candidate-to-connected resource transition

The candidate child has two explicit claims:

- opening claim: one transport object and one connector-construction work item;
- connected claim: one transport object.

Promotion atomically changes the aggregate from the opening claim to the connected claim. It releases candidate-only construction work and retains the live transport claim. An inconsistent aggregate transition poisons the aggregate, preserves conservative consumption, and refuses later admission.

These claims encode ownership and exact structural cardinality. They are not a complete hostile-ingress budget. Dependency-owned sockets, ICE pairs, DNS, STUN, TURN, allocator overhead, and internal tasks are not fully measurable through the current dependency API.

## 9. Endpoint authentication and delivery

`DataChannelOpen` must consume the exact live connector candidate. A move-only handoff binds the resulting `ConnectedChannelCapability` to the exact connector incarnation and moves it into `EndpointAuthTask`. The engine arm cannot begin the existing authentication handshake without that task, and `PeerConnection` rejects a task produced by any other connector, including one from the same runtime.

Duplicate or stale opens cannot mint another capability. Peer retirement fences the task immediately, awaits native close through the shared cleanup owner, then releases the task's connected child reservation even if another `Arc<PeerConnection>` survives.

Before authenticated activation:

- protocol input is limited to the existing endpoint-authentication path;
- application messages remain blocked by the engine admission gate;
- remote audio is discarded before event creation;
- remote video is discarded before H.264 access-unit assembly;
- duplicate or non-connector data channels are closed;
- duplicate connector-native media tracks are stopped.

After activation, the existing application and connector-native media behavior remains unchanged.

## 10. Compatibility and API surface

The production compatibility peer and `CompatibilityBypass` state are removed. Production construction uses the admitted connector owner.

`PeerSession` no longer implements `Deref`. The worker exposes only explicit connector ports. Raw `Transport::open_peer` constructors are absent from the default production API and available only to unit tests or an explicit `transport-lab` feature. The feature is a lab escape hatch, not a claim that a dependent crate cannot deliberately enable it. External crates cannot call raw candidate application or construct a worker.

## 11. TURN-selected endpoint proof

The Linux integration test in `myownmesh-services` starts the repository's real TURN server on an ephemeral loopback port and forces both WebRTC transports to relay-only selection through a lab-only constructor.

The test requires, for both endpoints:

- `Authenticated` before `Approved`;
- exact authenticated peer identity;
- active bilateral approval;
- a selected Relay-to-Relay ICE pair;
- typed endpoint data delivered in both directions.

Signaling is provided by the existing local test broker. The endpoint payload uses the ordinary authenticated peer-session path. TURN is the selected ICE carrier, not a MyOwnMesh mesh relay, and signaling does not carry the endpoint data.

## 12. Executed proof boundary

The Arc 03 controls cover:

- multi-candidate attempt ownership and retirement;
- reserve-before-allocation and cancellation after native allocation;
- non-nested promotion and retirement transitions;
- atomic candidate-to-connected resource transition;
- silent-worker wakeup and loser cleanup;
- callback backpressure, blocked-producer retirement, and ordered per-worker handling outside `NetworkCmd`;
- cancellation both after native allocation and after construction-result delivery;
- stale prequeued events, replacement, shutdown, and retained external owners;
- exact-owner activation through roster persistence;
- exact-incarnation Endpoint Auth Task ownership and reservation-through-close release;
- compiler-enforced raw API boundaries;
- real TURN-selected authenticated endpoint data.

Exact commands and attack statements are maintained in `red-teams/ARC-03-WEBRTC-CONNECTOR-WORKER.md`.

## 13. Remaining review boundary

The implementation must not receive merge approval until:

1. The exact pushed head passes the unchanged Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl CI matrix.
2. The owner reviews measured hostile-ingress and process capacity requirements in a later resource-policy arc. Arc 03 records observations and enforces structural ownership, but it does not fabricate those values.
3. Any later attempt to enable aggregate production resource admission covers the number of attempts and workers, the pending candidate queue, dependency-owned work, and cleanup backlog. Per-worker queue bounds alone are not a process-wide denial-of-service control.
4. Callback mailbox depth does not count payloads retained by independently suspended dependency callbacks. Those producers require dependency-level measurements or a later process policy before any process-wide memory claim is valid.

No code in this arc claims those unresolved values or expands the architecture to compensate for them.
