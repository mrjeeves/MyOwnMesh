# V4 Arc 03 WebRTC Connector Worker

Status: first ownership and compatibility slice implemented. Arc 03 is not complete. This branch is ready for audit, not merge approval.

Branch: `arc/03-webrtc-connector-worker`

Frozen Arc 02C parent: `0484f7f0987e5d1c488b30ac21e46f1925ea65cb`

## 1. Scope

This slice places the existing WebRTC session behind an engine-owned `WebRtcConnectorWorker`. It does not replace ICE, STUN, TURN, DTLS, direct paths, native RTP, H.264, Opus, mDNS, Nostr, reconnect behavior, or the recovery ladder.

Production still runs through an explicit compatibility state. The admitted V4 state is test-only. This distinction is important: the branch proves ownership primitives and selected race controls, but it does not yet enforce V4 admission on production connections.

## 2. Cardinality

```text
one connection attempt
    -> multiple connector candidates

one WebRTC connector candidate
    -> one complete RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and candidate pairs

DataChannelOpen for an active candidate
    -> ConnectedChannelCapability
    -> not endpoint identity, mesh admission, session authority, or application authority
```

`ConnectorCandidateCapability` names one complete connector candidate. It never names a trickled `LocalIceCandidate`.

One attempt permit can issue several candidate capabilities from one aggregate reservation. Each candidate owns a separate child reservation. The claim constructor requires exactly one `TransportObject` item. That check establishes only the fixed object cardinality. It does not yet establish complete ICE, callback, task, queue, socket, or byte requirements.

## 3. Attempt transition

`AttemptLifetime` is the unique cancellation owner for one candidate race. Each candidate is self-bound to the attempt that issued it, so there is no API that accepts a candidate and an independently supplied lifetime.

Allocation, promotion, and retirement use the same synchronous transition lock. A candidate retired before promotion cannot produce `ConnectedChannelCapability`. Promotion consumes the candidate capability into the connected-channel capability.

The promoted winner is no longer an awaiting candidate. Retiring the attempt invalidates candidates still in the race but does not revoke the winner that already completed the capability transition. This follows the V4 formal transition from `ConnectorCandidateCapability` to `ConnectedChannelCapability` and permits the attempt controller to end the remaining race.

The current allocation closure is synchronous. Real peer-connection construction is asynchronous, so production admission cannot use this closure without reopening a retirement race. Arc 03 still needs an async-safe two-phase allocation protocol. No registry operation may run while the attempt transition is held.

An attempt retirement watch value exists and retains retirement for late subscribers. It is not yet connected to the worker event pump or in-flight WebRTC operations. Awaiting workers reject later events after cancellation, but cancellation does not yet wake and clean a silent loser by itself.

## 4. Connector ownership

`WebRtcConnectorWorker` owns:

- the existing `PeerSession` and `RTCPeerConnection` wrapper;
- one process-local callback incarnation;
- the remote-description flag;
- the pending remote-candidate queue;
- the connector resource-observation scope;
- an explicit compatibility or admitted authority state.

The engine opens the worker through `Transport::open_connector_peer`. The worker is internal. External code cannot construct it.

`PeerSession::add_ice_candidate` is private to the WebRTC module. The engine can submit a remote candidate only through the worker. A candidate is moved into `PendingRemoteCandidate`, and its observation lease remains owned while queued and while the asynchronous dependency call is pending.

Worker retirement competes with remote SDP application, remote candidate application, and worker-owned sends. If local retirement wins, the local future and its observation are dropped. This is local cancellation, not transactional rollback. The dependency may already have performed an irreversible side effect before the cancellation branch wins.

Queue insertion checks worker activity while holding the queue lock. Retirement marks the worker inactive before taking that same lock and draining the queue. The source therefore defines one order for insertion and drain. A contention test is still required before treating that source argument as an executed race proof.

## 5. Callback and peer ownership

Every WebRTC event carries the exact process-local worker incarnation. A retired worker cannot accept a stamped event, and worker retirement wakes its receiver.

Every registry installation also receives a fresh process-local installation stamp. `PeerOwnerToken` contains that stamp. It does not rely on the public device id or the diagnostic epoch. Removing and attempting to reinstall the same retired peer object does not revive an old token. Reinstalling the currently installed object is an idempotent no-op.

Synchronous event effects use `PeerRegistry::with_current`, which shares the registry mutation lock. Replacement cannot pass an in-progress exact-owner effect. Asynchronous paths retain the exact token, operate on the captured worker, and recheck the token before committing state or sending an owner-specific message.

Replacement retires worker A before any retained owner can use A as current. It also schedules `RTCPeerConnection::close` for A. A real WSL control retains A, installs B, verifies that A reaches `Closed`, and proves A's retained `DataChannelOpen` event cannot mutate B.

The native close claim is deliberately narrow. Source proves that MyOwnMesh requests and awaits the dependency close operation. It does not prove that a retained `Arc<RTCPeerConnection>` releases every wrapper, callback closure, or allocation.

Approval state also commits through the exact peer owner. Only an inbound `Approve` records remote consent. A successful local `Approve` send records only that the current data channel accepted the bytes for transmission, not that the peer received them. The engine then evaluates authentication, local send acceptance, and actual remote approval together. This handles either approval order without manufacturing consent. A retired owner's facts, event, waiter completion, or reliable outbox cannot cross into its replacement.

## 6. Data-channel boundary

The admitted test state rejects protocol bytes before `DataChannelOpen`. A successful open consumes the exact candidate into `ConnectedChannelCapability`. It does not authenticate the endpoint.

After the channel transition, raw protocol bytes may reach the existing endpoint-authentication broker. Application messages remain subject to the engine admission gate. Media events stay suppressed in the admitted state because connected-channel authority is not application-media authority.

Production remains on `CompatibilityBypass`, which preserves the legacy handshake and media path and creates no V4 capability. The compatibility state must be removed only after real resource admission, attempt cancellation, endpoint-auth handoff, and the optional real-time provider boundary are implemented.

## 7. Resource observations

The worker currently observes these explicit ownership sites:

- one peer-connection wrapper;
- five peer-connection callbacks;
- four additional data-channel callbacks when a local data channel exists;
- sender-drain tasks;
- remote media pump tasks;
- the engine event-pump task;
- queued candidate values and queue capacity;
- remote SDP work;
- remote candidate application work.

The real WSL fixtures observed one transport object, five callbacks, and two sender-drain tasks for an answerer. The offerer fixture observed one transport object, nine callbacks, and two sender-drain tasks. All retained allocation values remain explicitly inexact.

These observations do not establish complete WebRTC resource use. `webrtc-rs` does not expose complete retained sizes for its ICE agent, internal pairs, sockets, DNS, STUN, TURN, callbacks, and tasks. A family-specific inexact measurement also currently marks every family in that resource scope inexact. That reporting behavior must be separated from scope-wide mutex-poison conservatism before reports can support production capacities.

The code contains no production capacity or pass threshold. The owner must review measured or conservative requirements before any permit becomes production authority.

## 8. Compatibility surfaces

The following bypasses remain intentionally visible:

- `Transport::open_peer` and `Transport::open_peer_with_config` are public raw constructors;
- `WebRtcConnectorWorker` still dereferences internally to `PeerSession` for legacy behavior;
- the raw callback queue and global engine command queue are unbounded;
- peer replacement and removal can create unadmitted close tasks;
- shutdown awaits dependency closes sequentially;
- the admitted worker constructor is test-only.

These are Arc 03 blockers, not accepted end-state behavior.

## 9. Proven on this branch

The executable controls prove the following bounded claims:

- one attempt can own multiple connector candidates under one aggregate;
- fixed candidate claims reject zero, mislabeled, and multiple transport objects;
- resource families cannot substitute for one another;
- the Arc 02C aggregate remains closed after a synthetic inconsistent release;
- synchronous allocation, promotion, and retirement have one transition order;
- retirement prevents later allocation and later promotion by awaiting candidates;
- a promoted winner remains valid when the remaining attempt race retires;
- the retirement watch retains its value for late subscribers;
- admitted workers reject protocol bytes before the connected-channel transition;
- connected-channel authority does not admit media delivery;
- queued-candidate observations survive queueing and asynchronous application;
- local retirement cancels a first-polled candidate application future;
- callback stamps reject another or retired worker;
- installation stamps reject stale cleanup and stale messages;
- only an inbound approval establishes remote consent;
- either approval order converges after authentication without inventing peer consent;
- a retired owner cannot activate its replacement;
- reliable post-activation sends require authenticated admission and the exact current owner;
- an exact-owner synchronous effect completes before replacement;
- a retired peer object cannot be reinstalled;
- raw candidate application and worker construction are inaccessible to an external crate.

The red-team catalog records the exact commands, real WSL controls, and unproved cases.

## 10. Remaining Arc 03 work

Arc 03 is not complete until all of these are resolved:

1. Replace synchronous constructor admission with an async-safe allocation protocol that reserves before allocation and cancels or retires all partial results.
2. Define complete per-family resource claims, present measured requirements to the owner, and obtain finite owner-approved capacities.
3. Connect attempt retirement to awaiting worker wakeup, queue drain, in-flight work cancellation, native close, and reservation release.
4. Replace unbounded callback and command queues with admitted bounded ownership and test hostile prequeued backlog.
5. Move the production WebRTC path from `CompatibilityBypass` to real `PreAuthAttemptPermit` and `ConnectorCandidateCapability` ownership.
6. Move endpoint-auth initiation out of the raw `DataChannelOpen` arm and hand `ConnectedChannelCapability` to the next owner.
7. Split optional real-time media from the basal connector and require authenticated application authority before delivery.
8. Resolve the public raw constructors and narrow or remove the internal `Deref<PeerSession>` compatibility surface.
9. Bound and observe replacement, removal, and shutdown cleanup.
10. Pass direct, TURN, mDNS, Nostr, reconnect, handshake, data-channel, H.264, Opus, native RTP, full workspace, and supported-platform preservation gates.

This slice adds no route id, path generation, durable negotiation record, authentication-before-pathfinding rule, application relay, resource threshold, or new signaling behavior.
