# V4 Arc 01 state and effect inventory

Status: complete as a record of the source at commit `2a04e29e0a4c09b95a4914972018850ddb2cbacb`.

This arc changes no product behavior and deletes no code. It establishes the ownership record that later implementation arcs must reduce. No listener, peer connection, firewall rule, or live MyOwnMesh instance was started while producing this record.

## Evidence and completeness rule

The machine-readable inventory is [`arc-01-inventory.json`](arc-01-inventory.json). Its checker is [`check-v4-arc01-inventory.py`](../../scripts/check-v4-arc01-inventory.py).

Run it from the repository root:

```powershell
python scripts\check-v4-arc01-inventory.py
python scripts\check-v4-arc01-inventory.py --negative-controls
```

The passing baseline contains:

| Input class | Recorded count | Snapshot SHA-256 |
|---|---:|---|
| Production Rust source units | 98 | `cc7038543291f2bd96019b6a100b0820a7d20bd46e530618e6ea4683753e32fa` |
| Production Rust declaration members | 1,415 | `29a37b0ba3f2f27dadfbdef841af3c833d37d6c18d64acba784a1f8e47f42479` |
| Callable, callback, parser, queue, task, write, network, external-service, process, and static-state surfaces | 1,582 | `a61b4df1b5462e101b0807be95fd0868cebd9076f698428a92de8362ea5bd84a` |
| Hand-reviewed semantic anchors | 75 | Exact source anchors, scopes, ordering, and expected counts |
| Structured resource anchors | 111 | Exact allocation, collection, task, and body-buffer anchors with required metric classes |

The scanner removes `cfg(test)` items and inventories the remaining Rust in workspace crates, crate build scripts, and the Tauri Rust client. It records declaration bodies and members, named callable bodies, trait callables, registered transport callbacks, mutable statics, constructors, parser entries, queues, tasks, filesystem writes, socket operations, buffered stream reads, external carrier and HTTP calls, child processes, and public action APIs. The full-source fingerprint covers outer attributes, visibility, and source constructs that are not represented as separate declaration members. Each discovered declaration or surface must match exactly one ownership rule.

This is an exact source-shape record, not a claim that every runtime branch is reachable or exploitable. The semantic anchors cover important chains that cannot be inferred from a call name alone. Dynamic reproduction remains part of the applicable red-team arc.

## Ownership result

The assignment counts are records, not architectural sizing targets.

| Target or disposition | Declaration members | Effect surfaces |
|---|---:|---:|
| Application Gateway | 341 | 149 |
| Attempt Node | 29 | 11 |
| Connector Worker | 43 | 70 |
| Endpoint Auth Task | 22 | 8 |
| Peer Session Node | 73 | 50 |
| Reachability Node | 173 | 52 |
| Relay Node | 36 | 40 |
| Runtime Supervisor | 54 | 17 |
| Semantic Node | 117 | 106 |
| Session Broker | 12 | 7 |
| Signaling Node | 190 | 271 |
| Application client domain | 52 | 72 |
| Connector infrastructure domain | 15 | 14 |
| Operational infrastructure (U0) domain | 106 | 251 |
| Delete | 23 | 25 |
| Split | 64 | 341 |
| Decision: OD-CODEC-FLOW-BOUNDARY | 38 | 53 |
| Decision: OD-DEVICE-KEY-CUSTODY | 13 | 33 |
| Decision: OD-LEGACY-SILENT-MIGRATION | 1 | 0 |
| Decision: OD-LEGACY-TOPOLOGY-MIGRATION | 2 | 0 |
| Decision: OD-NETWORK-RECOVERY-OWNER | 1 | 1 |
| Decision: OD-SERVICE-ADVERT | 10 | 11 |

The decision-bound declaration members consist of 38 codec and media-flow members, 13 Device-key members, one legacy `Silent` variant, two legacy governed-topology members, one network-recovery policy member, and ten mixed service-advert members. Decision-bound effect surfaces consist of 53 media-flow effects, 33 Device-key effects, one network-recovery policy effect, and 11 service-advert effects.

The detailed assignment remains in the JSON. The checker validates these aggregate counts against the exact assignment rules so this prose cannot silently become a second stale list.

## Current structures that must split

The current `engine::NetworkState` combines at least ten target domains. The exact field assignment is recorded mechanically. The important splits are:

- durable roster, governance, network context, and eviction compatibility state to Semantic Node;
- signaling channels and carrier state to Signaling Node;
- speculative reconnect and connection-wait state to Attempt Node;
- transport and local connection preference to Connector Worker;
- reliable post-promotion delivery to Peer Session Node;
- observations and diagnostics to Reachability Node;
- public subscriptions and compatibility callbacks to Application Gateway;
- lifecycle and configuration to Runtime Supervisor;
- Device identity to the unresolved key-custody boundary;
- `cmd_tx` and `routing_seen` to deletion with the monolithic bus and ordinary forwarding path.

The same rule applies to `PeerStateData`. Endpoint authentication, policy promotion, candidate work, connector state, session recovery, observations, and application metadata cannot remain one lock-protected record. `PeerStateData::is_admitted` is not a target authorization primitive. The target authorization fact is possession of an unforgeable `SessionCapability` minted by Session Broker.

`NetworkCmd` and `MeshMessage` also have no single valid owner. The inventory assigns each current variant to its eventual destination and marks the global containers for splitting. A new global variant is therefore not acceptable feature work after this arc.

## Source-confirmed security and boundary findings

These findings are confirmed from the current input source. Items that depend on operating-system reachability or a hostile network service still require dynamic reproduction before final severity is assigned.

### 1. Pre-authentication media reaches application subscribers

WebRTC sessions provision media before endpoint authentication, and their track pumps emit `VideoSample` and `AudioSample` events. The engine dispatches those events to application subscribers without an admission or session-capability check at [`engine/mod.rs`](../../crates/myownmesh-core/src/engine/mod.rs#L1840). Endpoint authentication begins only after the data channel opens at [`engine/mod.rs`](../../crates/myownmesh-core/src/engine/mod.rs#L1794).

This is a direct Arc 05 and Arc 06 blocker. Transport may perform bounded work before authentication, but application delivery may not occur before Session Broker promotion.

### 2. Ordinary members forward application payload and may assert an origin

The current fallback routing path wraps application data, forwards it through ordinary members, and accepts an asserted source when the topology identifies the carrier as a forwarder. The acceptance and re-forwarding path is in [`engine/routing.rs`](../../crates/myownmesh-core/src/engine/routing.rs#L142). A failed direct send enters this path from [`engine/mod.rs`](../../crates/myownmesh-core/src/engine/mod.rs#L2656).

This is not the target Relay Node. It has no exact A-to-C allocation and no authenticated A-to-C channel behind the forwarding member. The migration matrix already assigns this code no target. Its reproductions may be retained, but the production behavior is scheduled for deletion.

### 3. Public interfaces expose internal state and Device signing authority

`JoinedNetwork::state` returns the shared internal `NetworkState` at [`handle.rs`](../../crates/myownmesh-core/src/handle.rs#L607). `Identity::signing_key` returns a reference to the Device private signing key at [`identity.rs`](../../crates/myownmesh-core/src/identity.rs#L132).

These surfaces bypass the intended Application Gateway and capability transitions. Arc 02 must ensure that public labels and public handles cannot create or recover higher-authority capabilities. Device key custody remains a named owner decision rather than being assigned to a convenient consumer.

### 4. Speculative resources are not globally confined

An Open-mesh announcement or inbound offer can create native WebRTC work before endpoint authentication. Candidates received before remote description are appended to `pending_remote_candidates` at [`engine/mod.rs`](../../crates/myownmesh-core/src/engine/mod.rs#L802). The transport event queue and several signaling queues are unbounded. RPC streaming also uses an unbounded queue and detached request tasks.

This does not add Closed-mesh authorization to Open meshes. It requires resource permits for untrusted speculative work. The exact numeric limits remain owner-selected values backed by measurements, so Arc 02 instruments resource families without inventing enforcement values.

### 5. Nostr inbound events are trusted beyond their proven carrier facts

The Nostr driver parses a relay-supplied `NostrEvent` and dispatches its content at [`nostr/driver.rs`](../../crates/myownmesh-signaling/src/nostr/driver.rs#L906). Within that function it does not call the available `NostrEvent::verify`, bind the signed room tag to the active room, consume the `EVENT` subscription identifier, or bind the Nostr key, envelope sender, and nested peer identifier. It also inserts the event ID into the dedup cache before the signaling envelope has parsed and passed its domain checks.

A hostile relay can therefore inject or alter ephemeral control and reachability claims within the current driver. V4 leaves early carrier authentication as a profile decision. Effect confinement is not optional. Regardless of that decision, unproven carrier claims cannot directly mutate a current attempt, a live session, or a peer-indexed route. Current peer-left, room capability, and candidate effects do so without an explicit bounded speculative-work contract.

### 6. Signaling departure claims can close another peer's current work

The core bridge takes the inner `peer_id` from a `Leave` message rather than binding the effect to carrier provenance at [`signaling_bridge.rs`](../../crates/myownmesh-core/src/engine/signaling_bridge.rs#L255). Core then treats `PeerLeft` as sufficient to drop the named peer at [`engine/mod.rs`](../../crates/myownmesh-core/src/engine/mod.rs#L852). The Nostr and mDNS drivers repeat the inner-identifier behavior.

This is an availability and provenance defect. It does not let the sender pass endpoint authentication, but it can tear down or disturb another peer's live work. A carrier withdrawal must become an observation correlated to the applicable attempt or session, not a semantic leave conclusion.

### 7. The self-hosted signaling server binds presence to a claimed Device label

The self-hosted server verifies a Nostr event signature, then takes the Device label from the event content at [`server.rs`](../../crates/myownmesh-signaling/src/server.rs#L602). The signature proves the event's Nostr key, not that the signed `from` string is the corresponding MyOwnMesh Device. The connection becomes the live owner of that claimed Device label. When it disconnects, the server signs and broadcasts a synthesized `leave` naming the claimed Device at [`server.rs`](../../crates/myownmesh-signaling/src/server.rs#L415).

An adversary with any valid Nostr key can therefore claim another Device label on the self-hosted service and make a disconnect produce a valid relay-signed departure for that victim. Endpoint authentication still blocks session promotion. The availability mutation is the defect, and it requires a split between carrier connection ownership and Device-scoped effects.

### 8. Signaling negotiation has no end-to-end current-work correlation

The wire Offer and Answer variants contain `offer_id`, but core `SignalingInbound` and `SignalingOutbound` do not. The bridge discards inbound IDs, creates a different Offer ID independently for each attached carrier, and emits Answers with an empty ID at [`signaling_bridge.rs`](../../crates/myownmesh-core/src/engine/signaling_bridge.rs#L78). Candidate has no ID and Leave contains only `peer_id` at [`lib.rs`](../../crates/myownmesh-signaling/src/lib.rs#L47).

The current Offer and Answer fields therefore do not correlate a negotiation through the engine. Delayed offers, answers, candidates, and departures cannot be bound to the work that produced them. This does not create authentication authority, but stale signaling can disturb current work and make exact cleanup impossible. The target needs opaque local attempt or session correlation. A public Device label alone is insufficient.

### 9. mDNS connection identity is a claimed label

The first inbound mDNS frame's unauthenticated `from` value becomes the connection-map key at [`mdns/driver.rs`](../../crates/myownmesh-signaling/src/mdns/driver.rs#L411). Later frames need not retain that value, and `Leave.peer_id` is accepted independently. A local-network attacker can replace a peer's signaling route, receive directed signaling for that claimed identifier, or emit a peer-left observation.

Endpoint authentication can still prevent final session promotion. The issue is that current pre-auth routing and availability effects are not confined to harmless, bounded hints.

### 10. The self-hosted signaling server accepts generic NIP-01 content

The server accepts, stores, filters, and fans out arbitrary signed Nostr events, not only the closed MyOwnMesh signaling schema, at [`server.rs`](../../crates/myownmesh-signaling/src/server.rs#L595). Unknown filter keys are nonrestrictive.

If this remains a MyOwnMesh signaling service, it is a payload bypass. If generic NIP-01 hosting is a desired product, it needs a separately named service contract, ingress, queues, limits, and security review. That product decision is left open.

### 11. Daemon control has no explicit local-principal proof

The daemon accepts local control connections, parses a `Request`, and dispatches it without an application principal, peer credential, or per-operation authorization boundary at [`control.rs`](../../crates/myownmesh/src/control.rs#L690). `ClientId` values are monotonic routing labels, and `MediaSourcePipe` can replace the media sink associated with a supplied client identifier at [`control.rs`](../../crates/myownmesh/src/control.rs#L776).

Actual cross-user reach depends on the operating-system socket ACL or Unix permissions and must be reproduced on supported systems before severity is finalized. The source boundary itself is absent. Arc 02 can define `LocalPrincipalCapability`; the operating-system binding mechanism is an owner decision.

### 12. Release-workflow clients accept checksum-only updates

The committed release workflow does not set `MYOWNMESH_RELEASE_PUBKEY`. Workflow-built clients therefore take the updater's checksum-only verification branch. A locally reachable control client can change the feed URL, and the feed supplies both the artifact and checksum. The update path also joins release and asset strings into filesystem paths without the required containment proof at [`myownmesh-updater/src/lib.rs`](../../crates/myownmesh-updater/src/lib.rs#L999).

This is operational U0 work, not mesh-architecture scope, but it is security-relevant and recorded so it is not lost. The end-to-end replacement chain should be reproduced before final severity and remediation scope are selected.

### 13. Stored Device identity does not prove public-key consistency

`decode_anchor` derives the signing key from `secret_key` but accepts the separately stored public identifier without comparing it to the derived verifying key at [`identity.rs`](../../crates/myownmesh-core/src/identity.rs#L224). A corrupt or modified anchor can report one Device ID while signing with another key.

The consistency check belongs with the selected identity foundation. It is independent of the open question about which private boundary owns key custody.

## Resource inventory

The source scanner records 19 unbounded channel constructions, and every one has exactly one structured resource record. The audited collections and work sources also include:

- peer, connection, subscription, pending-request, candidate, and presence maps or vectors;
- one task per control or signaling connection in several paths;
- mDNS native browse, registration, and resolution threads, plus the embedded browse pump;
- STUN listener, serving task, packet buffer, and retained task lifetime;
- RPC handlers and streaming tasks without a complete lifetime budget;
- updater response bodies that are materialized without a wrapper-level byte budget;
- configurable signaling limits where zero disables the limit;
- TURN credential, listener, relay-port, allocation-socket, and lifetime boundaries without an established wrapper-level global resource budget.

The existing fixed capacities are evidence of current behavior, not automatically approved V4 values. `OD-RESOURCE-LIMITS` requires measured owner selection. Arc 02 may count items, bytes, tasks, and lifetimes, but it may not enforce fabricated defaults.

## Owner decisions retained without guessing

The full questions are in the JSON. The unresolved decisions are:

1. Device secret-key custody.
2. Codec and connector-native real-time-flow ownership.
3. Legacy `Silent` migration.
4. Legacy governed-topology migration.
5. Mixed service-advert decomposition.
6. Numeric resource limits.
7. Generic NIP-01 service disposition.
8. Low-level signaling API visibility.
9. Operating-system binding for `LocalPrincipalCapability`.
10. Early signaling authentication and its allowed speculative-work vector.
11. Ownership of network-change recovery policy after observation is separated from restart effects.

These are explicit decision records, so the Arc 01 rule against guessed assignments is satisfied. None requires inventing a value to install the Arc 02 capability types and resource instrumentation. Key custody becomes blocking before Arc 04 can claim a complete Endpoint Auth boundary. Codec ownership becomes blocking before the media compatibility adapter is removed. Numeric resource values become blocking before enforcement is enabled.

## Boundary documents

Arc 01 creates no target implementation module. The inventory therefore records an empty `target_modules` list and requires no new `BOUNDARY.md` yet. Starting in Arc 02, every target module added to that list must contain a boundary document or the checker fails.

## Arc 01 gate result

- Every mechanically discovered declaration member and effect has exactly one target, deletion/split disposition, or named owner decision.
- No item has two final owners.
- Payload bypasses, ordinary forwarding, authority mutations, and unbounded queues are recorded.
- No product code was deleted or changed.
- The exact baseline and input fingerprints are recorded.

Arc 02 may begin. Its scope is private-constructor capabilities, forbidden-conversion tests, compatibility wrappers, and observation-only resource accounting. It must not change transport behavior or choose unmeasured resource limits.
