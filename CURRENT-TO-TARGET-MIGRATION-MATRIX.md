# V4 architecture ownership matrix

> Current normative cutover (2026-09-09): application data uses endpoint-authenticated WebRTC, directly or through configured standard TURN. Hubs provide discovery/introduction only, never application plaintext or ciphertext transit. This supersedes custom encrypted Hub and Closed-member payload relay requirements. Open/Closed governance is unchanged. Historical exact-head evidence below remains historical; this edit is not an implementation, runtime, or release PASS.

Status: final ownership map for the adopted hybrid architecture of
`mrjeeves/MyOwnMesh`.

The paths below identify source families and their final owners. Source
references provide provenance; execution, audit, and platform evidence are
separate and are never inferred from an ownership declaration.

## Implemented canonical authority boundary

V4 durable authority is the semantic `FactGraph`, persisted by
`DurableSemanticStore`, and composed of verified `SignedFact` records.
`FactBody::RoleGrant`, `FactBody::RoleRevoke`, and `FactBody::Evict` are
the exact ordinary governance facts. `NetworkCmd::ProposeRoleGrant`,
`NetworkCmd::ProposeRoleRevoke`, and `NetworkCmd::ProposeEvict` are typed
authoring requests that must pass semantic verification; they are not an
alternate authority store. Same-cell `FactBody::Resolution` and cross-cell
`FactBody::AuthorityLineageResolution` remain distinct typed selectors.

`NetworkKind` is configuration/profile shape, while topology and mesh
context are outside ordinary fact authority. Roster and peer-registry data
are non-authoritative projections. The former `NetworkState` transition,
quorum, split, and serialized-roster authority model is removed and cannot
authorize a session, membership change, or application operation.

There is no Hub or Closed-member application-forwarding exception. Endpoint
application channels use native authenticated WebRTC directly or configured
standard TURN. Hubs consolidate bounded discovery/introduction only. TURN is
a separate service even if cohosted; current advertisements carry URLs and
credentials remain locally configured, not protected credential distribution.

The cutover configuration is `introduction: Option<HubIntroductionPolicyConfig>`.
Removed `closed_relay`, `application_transport`, `endpoint_cipher`, and
`routing_policy` config/wire surfaces must refuse. The removal disposition
below is normative, not a claim that pending builds or tests have passed.

| Source path or subsystem | Owned capability | Final owner | Final disposition | Invariant |
|---|---|---|---|---|
| `crates/myownmesh-core/src/identity.rs` | Device key and Device ID implementation | Identity foundation | Canonical identity implementation | All identity use goes through one typed API |
| `signing.rs` | Domain-separated Ed25519 signing helpers | Durable semantics and Endpoint Auth, separately | Split by protocol domain; do not create a generic signer service | No cross-domain signing call accepts an arbitrary domain string from a caller |
| `verification.rs` | Human verification code UX | Application/Endpoint Auth presentation | Presentation-only surface | No authorization predicate depends on the code |
| `roster.rs` | Non-authoritative display/projection shape | Semantic projection only | Projection-only data required by callers | Open and Closed projections come only from verified semantic facts |
| `network_state.rs` | None from the legacy authority model | Excluded legacy authority | No transition/quorum/split/serialized-roster authority | No legacy field authorizes a session, member, or application operation |
| `protocol/mod.rs` and submodules | Wire framing needed by typed lanes | Separate typed lanes | Keep only durable exchange, ephemeral transport control, endpoint/session control, and application frames | One global wire enum supplies no cross-lane dispatch authority |
| `topology/` | Useful connection preference algorithms | Connector/local policy | Demote to optional local connection-selection policy | Topology never grants authority or creates ordinary forwarding |
| `transport/webrtc.rs` | WebRTC, ICE, DTLS, native RTP/RTCP tracks, transport callbacks | WebRTC Connector Worker plus optional WebRTC Real-time Flow Provider | Wrap first, then split channel and flow boundaries | Connector produces `ConnectedChannelCapability`; flow provider is usable only through a promoted session |
| `MediaLaneOpen` / `MediaLaneClose` commands | Application-facing lane lifecycle mixed into `NetworkCmd` | Realtime flow operations on `JoinedNetwork` | Absent from the global engine command surface | Realtime flow lifecycle is owned by `JoinedNetwork` |
| `LaneKind`, `VideoSample`, `AudioSample`, H.264 and Opus constants | Codec and media-purpose semantics inside core transport types | Application-supplied realtime profile; WebRTC-specific encoded-flow adapter | Core does not own codec or screen/camera/audio meaning | Encoded flow lifecycle is separate from application media semantics |
| `MEDIA_LANES`, pre-provisioning, drain grace, m-line reuse | WebRTC performance and lifecycle policy | WebRTC Real-time Flow Provider | Shared application-stated flow ceiling | Other connectors need not implement WebRTC lane policy |
| `engine/mod.rs` driver | Serial runtime orchestration | Runtime supervisor | Runtime orchestration only; governance uses exact typed requests | No legacy state class remains an authority owner |
| `engine/state.rs` / `NetworkState` / `NetworkCmd` | Runtime coordination only | Runtime supervisor plus DurableSemanticStore/FactGraph | Runtime coordination is separate from semantic authority; governance uses exact typed ProposeRoleGrant/ProposeRoleRevoke/ProposeEvict requests | No runtime snapshot/quorum field is an authority source |
| `engine/connection.rs` | Per-peer transport bookkeeping | Attempt Node and Peer Session Node | Split pre-auth and post-auth state | No object simultaneously owns candidate and application-session authority |
| `engine/handshake.rs` | Channel-bound mutual Device authentication and approval timing | Endpoint Auth Task and Session Broker | The live `Hello`/`AuthResponse` path signs and verifies the sole `endpoint_auth` transcript; `accept_peer_proof` is the sole promotion transition. Mesh-policy decisions remain outside the proof. No execution or audit result is inferred here. | Authenticated channel and policy promotion are separate typed transitions |
| `engine/heartbeat.rs` | Inbound-traffic liveness evidence | Peer Session and Reachability Nodes | Local reachability evidence | No heartbeat result mutates durable participation |
| `engine/ice_watchdog.rs` | ICE restart behavior | WebRTC Connector / Peer Session recovery | Connector/session recovery policy | Recovery operates on live channels, not durable route state |
| `engine/network_watch.rs` | OS network-change recovery | Connector runtime | Bounded connector recovery | Network changes cause bounded recovery only |
| `engine/ladder.rs` | Cheapest-to-most-disruptive recovery ordering | Peer Session recovery policy | Local recovery policy without authority semantics | Every tier acts only on authenticated/live transport objects |
| `engine/wake.rs` | Resume detection | Reachability and Peer Session recovery | Reachability/session signal | Wake never synthesizes leave or roster changes |
| `engine/reconcile.rs` | Config-triggered restart behavior | Runtime Supervisor and Connector Node | Split by owned configuration | No global stop/start is used for an unrelated local change |
| `engine/reliable.rs` | Delivery semantics and retransmission experience | Application session data service | Session-capability-bound delivery | Unknown peer strings cannot create unbounded durable outboxes |
| Former application forwarding in `engine/routing.rs` | No current payload capability | Removed profile | Retain only independently required bounded setup/typed semantic-control in its own owner | Discovery/introduction cannot authorize payload forwarding |
| `engine/signaling_bridge.rs` | Existing Nostr/mDNS fan-in/out and dedup | Signaling Node | Typed ports with retained provenance | Durable and ephemeral lanes are classified before domain parsing |
| `engine/governance.rs` | Governance interaction workflows and tests | Closed Semantic Node | Author and verify canonical RoleGrant/RoleRevoke/Evict facts and typed lineage selectors | Closed projection is pure; policy guards consume verified FactGraph state |
| `engine/traffic.rs` | Traffic counters and observations | Reachability / diagnostics | Retain only as local evidence | No counter is an authorization input |
| `engine/scheduler.rs`, `tick.rs` | Named timer behavior and operational tuning | Owning nodes | Partition timers by owner | No global ticker mutates unrelated state |
| `channels.rs` | Typed pub/sub API | Application facade over Peer Session | Public typed channel surface with live session capability internally | All sends and deliveries cross promotion boundary |
| `rpc.rs` | RPC API and streaming behavior | Application facade over Peer Session | Public RPC surface with bounded tasks and queues | No RPC is dispatched pre-promotion |
| `handle.rs` | `Mesh`, `JoinedNetwork`, and embedder API | Application Gateway facade | Public gateway surface over typed capabilities | Public IDs are not internal capabilities |
| `events.rs` | Diagnostics and embedder events | Narrow node event DTOs | Node-scoped diagnostic DTOs | No global event enum authorizes another subsystem |
| Former `engine/closed_relay.rs`, runtime payload relay, and custom endpoint cipher | No current payload capability | Removed profile | Superseded by direct/configured standard TURN WebRTC; removed config/wire refuses | No custom Hub/member application transit, including ciphertext |
| `myownmesh-signaling` Nostr driver | Production signaling carrier and reconnect knowledge | Signaling Adapter | Typed signaling lane with bounded provider-backed delivery | Carrier identity never becomes Device authority |
| `myownmesh-signaling` mDNS driver | LAN discovery and local signaling | Discovery/Signaling Adapter | Bounded hints and typed control exchange | Withdrawal cannot synthesize durable leave |
| `LocalBroker` | Deterministic in-process transport | `transport-lab` signaling adapter only | Retain only as an explicitly feature-gated integration control; never advertise as a production carrier or field proof | Exercises the bounded typed-lane ingress/authentication/promotion shape without substituting for a production adapter |
| `myownmesh-signaling` server | Self-hosted signaling | Signaling service | Bounded signaling service without semantic leave synthesis | Socket lifecycle affects only carrier observations |
| `myownmesh-services` STUN/TURN | Working infrastructure | Connector infrastructure | Infrastructure service | Service cannot become Device or application authority |
| daemon control socket | Deployment and administration surface | Application Gateway / local-principal boundary | Authenticated local-principal transport | Every privileged operation uses an authenticated principal capability |
| GUI | Existing operator UX | Application client | Client of the application gateway | GUI never constructs raw signaling or authority proofs |
| updater, installer, service manager, release packaging | Operational product infrastructure | Existing operational crates | Operational infrastructure | Deployment lifecycle remains separate from mesh authority |

## Executable production migration contract

The architecture is exercised through public production process and control
boundaries, not by a second architecture embedded in a fixture. The maintained
full-process entry point is [`scripts/run-production-e2e.py`](scripts/run-production-e2e.py).
It intentionally covers one finite path; other advertised carriers and platform
profiles retain their own qualification matrices.

| Sequence | Current production entry or owner | Target contract exercised by the runner | Harness observation |
|---|---|---|---|
| 1. Admit two processes | `crates/myownmesh/src/main.rs` -> `cli/serve.rs` | two isolated daemon owners, each supplied the complete finite `MYOWNMESH_RESOURCE_GRANT` and explicit connector realtime policy | control `status` answers from both exact local-principal sockets |
| 2. Discover and exchange control | `myownmesh-signaling/src/mdns/driver.rs` plus selected discovery backend; `engine/signaling_bridge.rs` | typed LAN signaling only; no Nostr, `LocalBroker`, public STUN, or TURN substitute | daemon logs and the peer snapshots retained after both peers are sighted |
| 3. Construct a channel | `engine/connection.rs`, `transport/ice.rs`, `transport/webrtc.rs` | bounded production ICE/WebRTC connector work creates the channel that actually carries the proof | each peer snapshot retains its selected candidate pair |
| 4. Authenticate and promote | `endpoint_auth/{task,transcript}.rs`, `engine/handshake.rs`, `runtime/session_broker/mod.rs` | fresh channel-bound Device proof followed by bilateral Open auto-approval and exact current-session promotion | both snapshots report the opposite Device as authenticated and `active` |
| 5. Bind the local consumer | `control.rs`, `ipc/clients.rs`, `control/dispatch/channel.rs` | an `EventsSubscribe` capability owns B's exact channel subscription | subscription acknowledgement is consumed in memory; its bearer capability is not persisted |
| 6. Deliver application data | `application_gateway/channels.rs`, `ipc/bridge.rs` | A uses `ChannelSendReliable`; B receives the exact `ChannelInbound` frame through its promoted session | redacted request response, B event JSONL, and exact token match |
| 7. Settle owners | daemon shutdown plus connector/session/control owners | event socket closes; both daemon process groups receive bounded graceful shutdown and every registered connector/session/control owner reaches its join boundary | both processes report `forced: false` and `returncode: 0` in the neutral run manifest; the child-only kill backstop is cleanup-only and fails the contract if used |

A zero harness exit states only that this executable contract reached its
declared terminal. It is not, by itself, a platform, performance, packaging, or
release claim. The harness never manufactures resource amounts, installs a
dependency, builds a binary, edits a user's normal home, or deletes the
preserved run directory.
