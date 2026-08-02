# V4 Arc 02 capability and resource spine

Status:

- Arc 02A is the approved compile-time foundation at commit `b2c09872a400d07f6f626d5a1c887ac90b6c2f9c`.
- Arc 02B is the remote-candidate observation pilot at commit `b0134d446ae94bc3b5e6e730c8019b924765d416`.
- Arc 02C is the corrective owner, accounting, and API revision carried by this document.
- Arc 02 stops after Arc 02C. Arc 03 wraps the existing WebRTC path as the first Connector Worker.
- Production resource budgets and complete allocation coverage are not implemented.

Branch: `arc/02-capability-resource-spine`

Arc 02C parent: `b0134d446ae94bc3b5e6e730c8019b924765d416`

Arc 02C changes no signaling protocol, candidate content, ICE configuration, transport selection, endpoint authentication, application delivery, listener, or firewall policy.

## 1. Required change record

| Field | Arc 02C result |
|---|---|
| Owned state changed | Current peer ownership moves behind private `PeerRegistry`. Candidate observation metadata changes from per-active-lease storage to fixed-size state. |
| Ports changed | `NetworkState.peers` is no longer public. `PeerConnection::new` remains engine-only. `PeerStateData` remains non-clonable. `PeerStateSnapshot` and `PeerConnection::snapshot` provide an owned diagnostic view. |
| Capability transition changed | One `PreAuthAttemptPermit` owns one aggregate reservation and may create several candidate capabilities. Each candidate carries a child reservation and exact attempt ownership. |
| Legacy path retained | The existing candidate queue and public raw `PeerSession::add_ice_candidate(LocalIceCandidate)` call remain temporary compatibility paths. |
| Architecture invariants exercised | One mutable owner, move-only authority, guard before protected allocation, bounded accounting metadata, honest inexact reporting, and no identity prerequisite for future anonymous-ingress admission. |
| Red-team cases exercised | Registry bypass, replacement, removal, clear, shutdown, copied state, unbounded metadata, global mutex, measurement panic, reservation order, and public-ID authority reconstruction. |
| Performance and resource measurements | The observer benchmark records elapsed time and fixed metadata sizes. It has no pass threshold and selects no production budget. |
| Upstream classification | Not applicable. This is an owner-directed V4 transition correction. |
| Owner decision required | Every production resource capacity and performance tolerance remains owner-selected after measurement. |

## 2. Peer ownership

The old owner was a public `DashMap<String, Arc<PeerConnection>>` on `NetworkState`. Any caller with field access could insert, replace, remove, or clear a peer without retiring the private pending-candidate queue.

The new owner is `PeerRegistry`. Its internal `DashMap` and mutation lock are private. Engine code can request owned read snapshots. Only the registry can:

- install a peer;
- replace a peer;
- remove a peer;
- retire every peer during clear or shutdown.

Every exit path calls `discard_pending_remote_candidates` before map ownership ends. Registry drop repeats the retirement rule as a fallback. The shutdown control keeps an external `Arc<PeerConnection>` alive and proves that the candidate report returns to zero before that external reference is dropped.

## 3. Bounded observer

Production observations roll up through this runtime ownership path:

```text
process root
  -> live Mesh runtime
    -> live joined network instance
      -> attempt or peer connection
```

The joined network instance is not called an exact Mesh Context. The current object is not bound to an immutable context identity. Carrier, ingress source, attempt, and known-origin accounting remain orthogonal dimensions.

The observer now has:

- fixed arrays for the closed pre-authentication and post-authentication families;
- constant metadata for each family;
- no per-active-lease map;
- no hierarchy-wide transaction mutex;
- one lock per sampled scope.

Begin, replacement, and completion update each scope independently. Cross-scope diagnostic snapshots are not globally linearizable. A report may briefly observe an ancestor and descendant at different points in one update. Authority and enforcement never depend on those diagnostic snapshots.

Exact oldest-lease reporting is possible while the oldest known lease remains active. If that lease ends while another remains, constant-space state cannot recover the next-oldest timestamp. The report then returns no exact oldest lifetime and sets `oldest_active_lifetime_inexact`. Other exact counters remain exact. The flag resets when the family becomes empty.

## 4. Measurement behavior

`ResourceUse` retains four independent axes:

- items;
- logical bytes;
- retained bytes;
- tasks.

Remote-candidate logical bytes are current string lengths. Retained bytes are current string capacities. Queue-container retained bytes are `Vec` capacity multiplied by the wrapper size. These values do not include allocator metadata, stack use, WebRTC internal retention, or process RSS.

Every platform-size conversion and sum is checked. An overflow or unsupported conversion saturates the affected counter and marks the report inexact. Production resource-measurement code contains no `expect`, `unwrap`, or panic path.

## 5. Attempt and candidate reservation

The corrected authority shape is:

```text
PreAuthAttemptPermit
  owns exact AttemptOwnership
  owns one AggregateReservation
      -> CandidateCapability A
           owns exact AttemptOwnership
           owns CandidateReservation A
      -> CandidateCapability B
           owns exact AttemptOwnership
           owns CandidateReservation B
```

The attempt permit is not cloned and is not consumed into the first candidate. `allocate_candidate` acquires a child claim before it invokes the allocation closure. If the aggregate cannot admit the child, the closure does not run. Dropping the candidate returns its active claim.

Aggregate release is fail closed. If a child claim cannot be subtracted consistently, the aggregate keeps its last active value, enters an explicit poisoned state, and rejects later admissions. A poisoned mutex has the same result. Neither condition resets active use or restores capacity.

This is an enforceable local reservation primitive when a resource owner supplies a finite capacity. Arc 02C supplies no production capacity and does not route the current connector through it. No numeric value is inferred from a plausible default.

## 6. Guard placement and unknown input

A resource guard belongs before the allocation it protects. Queue insertion is not an acceptable substitute. The target boundary order remains:

1. anonymous-ingress and global guard before accepting protected frame storage;
2. parser guard before decoding;
3. attempt aggregate before attempt-owned work;
4. child candidate guard before candidate allocation;
5. connector-work guard before socket, ICE, STUN, TURN, DNS, task, timer, or callback allocation;
6. separate post-authentication guards before session and application resources.

Unknown input must be eligible for bounded pre-authentication admission without a Device identity and without Closed authorization. Identity and mesh policy may refine attribution later. They cannot be prerequisites for the global or anonymous-ingress component.

The current repository does not satisfy every item in this list. Arc 02C proves the candidate allocation ordering in the new attempt primitive and keeps the production observer labeled as observation only. Frame, parser, candidate, and connector production ports move under their real guards when their owning arcs migrate and the owner approves measured capacities.

## 7. Candidate compatibility boundary

The private production wrapper remains:

```rust
struct PendingRemoteCandidate {
    candidate: LocalIceCandidate,
    observation: CandidateObservationLease,
}
```

The inbound candidate moves into the wrapper. The observation follows queueing, draining, immediate application, success, failure, cancellation, replacement, removal, shutdown, and ordinary drop.

`PeerSession::add_ice_candidate(LocalIceCandidate)` remains a public raw compatibility bypass. Arc 03 must make it connector-private and capability-consuming. The Arc 02 source checker checks the two reviewed observed call sites, but it does not pretend that source counting compensates for a public raw API.

## 8. Public API changes

The public changes introduced across Arc 02B and Arc 02C are intentional:

- `PeerStateData` no longer implements `Clone` because cloning live queue ownership would duplicate the wrong state boundary.
- `PeerConnection::new` is engine-only because construction assigns runtime resource ownership.
- `NetworkState.peers` is engine-private because registry mutation must retire compatibility state.
- `PeerStateSnapshot` is a clonable owned view with no pending queue or observation lease.
- `PeerConnection::snapshot`, `NetworkState::peer_snapshot`, and `NetworkState::peer_info` provide read-only compatibility surfaces.

The snapshot is diagnostic state, not authority. Mutating an owned snapshot cannot alter the live peer.

## 9. Proof boundary

Arc 02C proves the following checked properties:

- all peer install, replacement, removal, clear, shutdown, and registry-drop paths retire pending candidates;
- shutdown cleanup is independent of external peer `Arc` lifetime;
- observer metadata is structurally bounded by closed arrays and constant family state;
- no hierarchy-wide observer mutex exists;
- unsupported measurement saturates and remains visible as inexact;
- a single attempt can own multiple candidate capabilities under one aggregate;
- candidate allocation happens after child reservation;
- a refused claim cannot execute the allocation closure;
- a candidate is bound to the exact attempt and aggregate that issued it;
- an inconsistent child release poisons its aggregate, preserves conservative active use, and refuses later admissions while another child remains live;
- copied live peer state and public queue ownership remain rejected;
- public labels cannot construct authority types.

These properties do not prove complete production resource coverage, a selected budget, or a production `ConnectedChannelCapability` path.

## 10. Verification gate

The executable catalog is [`red-teams/ARC-02-AUTHORITY-AND-RESOURCE-SPINE.md`](../../red-teams/ARC-02-AUTHORITY-AND-RESOURCE-SPINE.md). The complete gate includes formatting, workspace Clippy, workspace tests, the focused compiler and mutation controls, two-peer integration, signaling, connector and media tests, the release observer measurements, and supported-platform CI.

Build artifacts use an isolated Cargo target under `C:\Users\Admin\.allmystuff-sandbox-stage`. The focused source and compiler checks start no listener. Integration tests that bind loopback are identified separately in the recorded evidence.

### Corrective verification record

The local run on 2026-08-01 used the held base commit `b0134d446ae94bc3b5e6e730c8019b924765d416`. Windows 11 Pro with Rust 1.88.0 passed format, all-target workspace check, all-target workspace Clippy with warnings denied, focused Arc 02 tests, doctests, compiler boundaries, both source gates, and both mutation suites. Ubuntu 24.04 under WSL2 with Rust 1.88.0 passed the complete workspace suite and the named two-peer, signaling, mDNS, relay, data-channel, Opus, and H.264 paths. The socket-heavy tests ran in WSL2 so they could use an isolated network namespace without creating Windows firewall rules.

On an Intel Core i9-10850K, three Windows release samples of 100,000 four-scope observation begin and drop operations measured 244 ns, 234 ns, and 241 ns per operation. Fixed state measured 168 bytes per family, 5,384 bytes per scope state, 5,392 bytes per locked scope inner value, 24 bytes per accountant handle, and 88 bytes per observation lease. The private candidate path measured 168 bytes for a pending candidate plus observation and 112 bytes for the queue header. The executable red-team record contains the complete type-size table and the limits on interpreting it.

After the fail-closed aggregate correction, one additional exact-source release sample measured 322 ns per four-scope begin and drop operation. The fixed type-size results were unchanged. This additional sample is recorded separately rather than merged into the earlier three-sample set.

These values are observations from one machine and one build profile. They are not product budgets, service limits, or acceptance thresholds. Supported-platform CI remains required on the pushed revision.

## 11. Arc 03 handoff

Arc 03 has one product goal: preserve the existing WebRTC connection path while making its successful output a `ConnectedChannelCapability`.

Arc 03 must:

- make the raw candidate application port connector-private and capability-consuming;
- move final candidate and connector-work ownership out of the `PeerStateData` compatibility queue;
- preserve current direct and TURN behavior;
- preserve media and signaling behavior through compatibility adapters;
- produce no application authority from a working channel;
- avoid expanding Arc 02 into a general resource-accounting framework.
