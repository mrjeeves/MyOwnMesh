# Current-to-target migration matrix

Status: living ownership map for the transition of `mrjeeves/MyOwnMesh` into the adopted hybrid architecture.

The current paths below are based on the inspected `v0.3.2`/current-main repository shape. Before each migration arc, the implementer must verify that the path and behavior still exist on the exact source commit.

| Current path or subsystem | Valuable mechanism to retain | Target owner | Treatment | Exit gate |
|---|---|---|---|---|
| `crates/myownmesh-core/src/identity.rs` | Device key and Device ID implementation | Identity foundation | Retain, pin canonical behavior and test vectors | All identity use goes through one typed API |
| `signing.rs` | Domain-separated Ed25519 signing helpers | Durable semantics and Endpoint Auth, separately | Split by protocol domain; do not create a generic signer service | No cross-domain signing call accepts an arbitrary domain string from a caller |
| `verification.rs` | Human verification code UX | Application/Endpoint Auth presentation | Retain as non-load-bearing presentation | No authorization predicate depends on the code |
| `roster.rs` | Persistence and user workflow | Semantic Node compatibility input | Replace as authority; retain migration reader and UI workflow | Open and Closed projections come only from new semantic state |
| `network_state.rs` | Fixtures, persistence lessons, governance UI concepts | Closed semantic domain | Replace semantic model; explicitly migrate or reject old state | No legacy transition/log field authorizes a target session |
| `protocol/mod.rs` and submodules | Existing frame compatibility and tests | Separate typed lanes | Split into durable exchange, ephemeral transport control, endpoint/session control, and application frames | One global wire enum no longer supplies cross-lane dispatch authority |
| `topology/` | Useful connection preference algorithms | Connector/local policy | Demote to optional local connection-selection policy | Topology never grants authority or creates ordinary forwarding |
| `transport/webrtc.rs` | WebRTC, ICE, DTLS, native RTP/RTCP tracks, transport callbacks | WebRTC Connector Worker plus optional WebRTC Real-time Flow Provider | Wrap first, then split channel and flow boundaries | Connector produces `ConnectedChannelCapability`; flow provider is usable only through a promoted session |
| `MediaLaneOpen` / `MediaLaneClose` commands | Application-facing lane lifecycle mixed into `NetworkCmd` | Temporary compatibility facade over `RealtimeFlowProvider` | Migrate, then delete | No lane command remains in the global engine command surface |
| `LaneKind`, `VideoSample`, `AudioSample`, H.264 and Opus constants | Codec and media-purpose semantics inside core transport types | Application/media profile; WebRTC-specific encoded-flow adapter | Generalize out of basal core | Core owns encoded flow lifecycle, not codec or screen/camera/audio meaning |
| `MEDIA_LANES`, pre-provisioning, drain grace, m-line reuse | WebRTC performance and lifecycle policy | WebRTC Real-time Flow Provider | Retain as connector-local policy, measure, and hide from mesh authority | Other connectors need not implement or emulate WebRTC lanes |
| `engine/mod.rs` driver | Serial event ownership and field-tested orchestration | Temporary compatibility supervisor | Decompose incrementally | Deleted after all state classes have sole owner nodes |
| `engine/state.rs` / `NetworkState` / `NetworkCmd` | Existing public surface and serialized mutation seam | Multiple target nodes | Split by state ownership; no new variants except migration scaffolding | No shared grab-bag state or global command enum remains |
| `engine/connection.rs` | Per-peer transport bookkeeping | Attempt Node and Peer Session Node | Split pre-auth and post-auth state | No object simultaneously owns candidate and application-session authority |
| `engine/handshake.rs` | Channel-bound mutual Device authentication and approval timing lessons | Endpoint Auth Task and Session Broker | Extract; remove mesh-policy decisions from cryptographic proof | Authenticated channel and policy promotion are separate typed transitions |
| `engine/heartbeat.rs` | Inbound-traffic liveness evidence | Peer Session and Reachability Nodes | Retain and relocate | No heartbeat result mutates durable participation |
| `engine/ice_watchdog.rs` | Field-tested ICE restart behavior | WebRTC Connector / Peer Session recovery | Retain and relocate | Recovery operates on live channels, not durable route state |
| `engine/network_watch.rs` | OS network-change recovery | Connector runtime | Retain and relocate | Network changes cause bounded recovery only |
| `engine/ladder.rs` | Cheapest-to-most-disruptive recovery ordering | Peer Session recovery policy | Retain as local policy, remove authority semantics | Every tier acts only on authenticated/live transport objects |
| `engine/wake.rs` | Resume detection | Reachability and Peer Session recovery | Retain | Wake never synthesizes leave or roster changes |
| `engine/reconcile.rs` | Config-triggered restart behavior | Runtime Supervisor and Connector Node | Split by owned configuration | No global stop/start is used for an unrelated local change |
| `engine/reliable.rs` | Delivery semantics and retransmission experience | Application session data service | Refactor behind `SessionCapability`; globally bound | Unknown peer strings cannot create unbounded durable outboxes |
| `engine/routing.rs` | Failure reproductions only | None in target | Delete ordinary member forwarding | No production caller and red-team CAS ordinary-forwarding negative passes |
| `engine/signaling_bridge.rs` | Existing Nostr/mDNS fan-in/out and dedup | Signaling Node | Replace with typed ports and retained provenance | Durable and ephemeral lanes are classified before domain parsing |
| `engine/governance.rs` | Governance interaction workflows and tests | Closed Semantic Node | Replace authority semantics | Closed projector is pure and current policy guards come from it |
| `engine/traffic.rs` | Traffic counters and observations | Reachability / diagnostics | Retain only as local evidence | No counter is an authorization input |
| `engine/scheduler.rs`, `tick.rs` | Named timer behavior and operational tuning | Owning nodes | Partition timers by owner | No global ticker mutates unrelated state |
| `channels.rs` | Typed pub/sub API | Application facade over Peer Session | Retain API where compatible; require live session capability internally | All sends and deliveries cross promotion boundary |
| `rpc.rs` | RPC API and streaming behavior | Application facade over Peer Session | Retain API where compatible; bound tasks and queues | No RPC is dispatched pre-promotion |
| `handle.rs` | `Mesh`, `JoinedNetwork`, and embedder compatibility | Application Gateway facade | Adapt gradually | Public IDs are not internal capabilities |
| `events.rs` | Diagnostics and embedder events | Narrow node event DTOs | Split; retain compatibility mapper temporarily | No global event enum authorizes another subsystem |
| `services/relay.rs` | Operational relay code and tests | Exact Relay Node or removed | Replace fanout/plaintext forwarding with exact opaque allocation | Relay has exact A-C allocation, finite bounds, no application parsing |
| `myownmesh-signaling` Nostr driver | Production signaling carrier, reconnect knowledge | Signaling Adapter | Retain behind lane contract | Carrier identity never becomes Device authority |
| `myownmesh-signaling` mDNS driver | LAN discovery and local signaling | Discovery/Signaling Adapter | Retain bounded hints and control exchange | Withdrawal cannot synthesize durable leave |
| `LocalBroker` | Deterministic in-process transport | Test and local signaling adapter | Retain | Same typed-lane behavior as network adapters |
| `myownmesh-signaling` server | Self-hosted signaling | Signaling service | Retain, bound every resource, remove semantic leave synthesis | Socket lifecycle affects only carrier observations |
| `myownmesh-services` STUN/TURN | Working infrastructure | Connector infrastructure | Retain | Service cannot become Device or application authority |
| daemon control socket | Deployment and administration surface | Application Gateway / local-principal boundary | Retain transport, replace routing-label authority | Every privileged operation uses an authenticated principal capability |
| GUI | Existing operator UX | Application client | Retain and adapt API | GUI never constructs raw signaling or authority proofs |
| updater, installer, service manager, release packaging | Operational product infrastructure | Existing crates | Retain unless independently improved | Architecture migration does not regress supported deployment lifecycle |
