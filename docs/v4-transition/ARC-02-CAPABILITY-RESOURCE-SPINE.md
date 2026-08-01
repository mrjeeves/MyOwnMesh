# V4 Arc 02 capability and resource spine

Status:

- Arc 02A is the approved compile-time capability and resource-accounting foundation at commit `b2c09872a400d07f6f626d5a1c887ac90b6c2f9c`.
- Arc 02B implements the remote-candidate observation pilot described here.
- Arc 02 is not complete.
- Resource enforcement is not implemented.

Branch: `arc/02-capability-resource-spine`

Arc 02B parent: `b2c09872a400d07f6f626d5a1c887ac90b6c2f9c`

No signaling protocol, candidate content, ICE configuration, transport selection, endpoint authentication, application delivery, listener, or firewall behavior changed in Arc 02B.

## 1. Arc 02A boundary

Arc 02A added ten target-owned authority and permit types, closed pre-authentication and post-authentication resource families, RAII observation leases, compiler rejection controls, and source mutation controls.

It did not redirect production authority transitions or production resource owners. In particular, no production `SessionCapability` mint exists.

Capability possession is the authority fact. `RuntimeIncarnation` does not grant, revoke, or refresh authority. It only prevents an already-held capability from being used against a replacement runtime object. A future authority-consuming operation must compare the capability's witness with the current runtime object.

## 2. Arc 02B change contract

| Required field | Arc 02B result |
|---|---|
| State class moved | Remote ICE candidate observation follows the existing candidate owner. The queue remains a temporary compatibility owner. |
| Old owner | Public `PeerStateData.pending_remote_candidates: Vec<LocalIceCandidate>`. |
| New temporary owner | Private `PendingRemoteCandidateQueue`, containing move-only `PendingRemoteCandidate` values. |
| Final owner | Attempt Node or Connector Worker in a later migration arc. |
| Production path redirected | Pre-SDP queue insertion, post-SDP immediate application, and post-SDP queue drain. |
| Authority change | None. Observation grants no authority. |
| Enforcement change | None. No numeric limit or rejection path was added. |
| Resource scopes | Process root, live Mesh runtime, exact mesh context, and peer connection. |
| Byte measurements | Logical content bytes and retained Rust capacity bytes are separate. |
| Container measurement | Queue allocation capacity is observed separately from candidate-owned strings. |
| Compatibility deletion gate | Move the queue into Attempt Node or Connector Worker after a real `PreAuthAttemptPermit` is required before insertion. |

## 3. Fixed observation hierarchy

Production observations use this exact path:

```text
process root
  -> live Mesh runtime
    -> exact joined mesh context
      -> attempt or peer connection
```

A peer observation updates all four reports. A sibling mesh context does not see another context's leaf observations. A sibling peer does not see another peer's observations. The process root is global only for aggregation and has no policy or authority operation.

`Mesh::open_with_identity` creates one Mesh runtime scope. Every context joined through that handle descends from it. A direct `NetworkState::new` caller gets a new Mesh runtime scope below the same process root. Each `PeerConnection` gets a child of its exact context.

The resource primitive uses one transaction lock per hierarchy. Begin, replacement, and completion update every scope in the leaf path before another report or observation transaction can enter. Child scopes are not stored in a global registry.

## 4. Separate byte meanings

`ResourceUse` records:

- items;
- logical bytes;
- retained bytes;
- tasks.

For one `LocalIceCandidate`, logical bytes are the current byte lengths of:

- `candidate`;
- `sdp_mid`, when present;
- `username_fragment`, when present.

Retained candidate bytes are the capacities of those same owned strings. The inline `LocalIceCandidate` and wrapper storage is not counted again per item.

The queue container is a separate observation:

```text
Vec capacity * size_of::<PendingRemoteCandidate>()
```

That measurement includes occupied slots and spare `Vec` capacity. It has zero logical bytes and zero items, so it does not duplicate candidate count or candidate content. These are Rust capacity bytes derived from the live `String` and `Vec` owners. They are not allocator usable-size measurements and do not include allocator metadata, stack use, or process RSS. No allocator growth factor or plausible capacity is invented.

The active item count is the candidate count. The active lease count is the count of observation owners, so a nonempty queue has one container lease in addition to its candidate leases. Completed lease count must not be interpreted as completed candidate count.

## 5. Candidate ownership and lifetime

The production wrapper is:

```rust
struct PendingRemoteCandidate {
    candidate: LocalIceCandidate,
    observation: CandidateObservationLease,
}
```

The inbound candidate is moved into this wrapper. It is not cloned into the queue. `PeerStateData` no longer implements `Clone`, and its queue field is private.

Before remote SDP is set, the wrapper moves into the private queue. Draining moves the queue allocation, candidate values, candidate leases, and container lease out of `PeerStateData` without holding the peer lock across an await.

After remote SDP is set, the candidate is wrapped and applied immediately. Both paths call the same asynchronous observation helper. The helper keeps the lease alive until `add_ice_candidate(...).await` returns.

RAII cleanup covers:

- successful application;
- failed application;
- cancellation while application is pending;
- explicit queue retirement during peer removal or session replacement, even while another `Arc` keeps the retired peer alive;
- dropping an ordinary queue, drain, candidate, peer, or runtime owner.

When `add_ice_candidate(...).await` returns, the queue-owned or caller-owned observation ends. Any memory or work retained internally by the WebRTC ICE agent is outside this pilot and needs a separate Connector Worker observation.

## 6. What the pilot proves

The implementation and focused tests prove these bounded claims:

- logical and retained bytes are independent axes;
- one leaf observation updates all four required scopes;
- sibling contexts remain isolated;
- candidate values and queue container capacity are measured separately;
- queue drain preserves both leases;
- success, failure, cancellation, peer replacement, peer removal, peer drop, and ordinary drop end observations;
- the immediate and queued application paths both use the observed helper;
- a source mutation that restores cloning, exposes the queue, clones the inbound candidate, bypasses an observed application path, skips the process root, or adds another global observer is rejected.

These are code and test properties. They are not a measured production budget and do not establish complete allocation coverage.

## 7. Production coverage boundary

Arc 02B covers one canonical slice:

| Owner | Observed quantity | Covered lifetime |
|---|---|---|
| Remote candidate value | Item, logical string bytes, retained string capacity | Wrapper creation through application completion, cancellation, or drop |
| Pre-SDP queue container | Retained `Vec` capacity | First insertion through drain completion or drop |
| Scope rollup | Candidate family totals | Peer, exact context, Mesh runtime, and process root |

It does not cover:

- the signaling inbound or outbound channel containers;
- candidate parsing or signature work before the engine receives `LocalIceCandidate`;
- WebRTC, ICE, STUN, TURN, DNS, socket, timer, callback, or task internals;
- post-authentication resources;
- any other Arc 01 resource record;
- queue enforcement or admission.

A zero report outside the pilot still means that no instrumented caller reported activity. It does not prove zero process use.

## 8. Verification

Build and test artifacts use an isolated Cargo target under `C:\Users\Admin\.allmystuff-sandbox-stage`. The compiler-boundary harness uses a temporary offline Cargo project. No listener or integration binary is started.

The executable attack catalog is [`red-teams/ARC-02-AUTHORITY-AND-RESOURCE-SPINE.md`](../../red-teams/ARC-02-AUTHORITY-AND-RESOURCE-SPINE.md).

The final Arc 02B run on 2026-08-01 produced these results:

| Check | Recorded result |
|---|---|
| `cargo fmt --all -- --check` | Passed. |
| `cargo check --workspace --all-targets -j 16` | Passed. |
| `cargo clippy -p myownmesh-core --all-targets -j 16 -- -D warnings` | Passed. |
| `cargo test -p myownmesh-core --lib v4_arc02 -j 16` | 28 passed, 0 failed. |
| `cargo test -p myownmesh-core --doc -j 16` | 10 passed, 0 failed. |
| Compiler-boundary harness | 1 positive type-path control and 10 cause-matched rejection controls passed. |
| Arc 02 source gate | Passed. |
| Arc 02 mutation gate | Every defined mutation was rejected. |
| Arc 01 inventory gate | Passed with 106 source units, 1,562 declaration members, 1,681 source surfaces, 75 semantic markers, and 111 resource records. |
| Arc 01 mutation gate | Every defined mutation was rejected. |

Every command in the recorded run passed. The executable red-team sequence checks each native exit code before starting the next command.

## 9. Nonclaims and next gate

This slice does not claim that:

- Arc 02 is complete;
- resource accounting is implemented across production;
- a numeric budget has been selected;
- a `PreAuthAttemptPermit` is acquired before work begins;
- WebRTC or ICE agent retention is measured;
- a production `SessionCapability` mint exists;
- runtime replacement invalidates capability possession by itself.

The next gate is to make a real `PreAuthAttemptPermit` mandatory before candidate queue insertion and to move final ownership out of `PeerStateData`. That later change must use measured values approved by the owner. Arc 02B supplies observations only.
