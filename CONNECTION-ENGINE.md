# Connection engine

The mesh's resilience comes from a layered connection engine whose
recovery is driven by **reliable transport signals** — the data channel
and inbound traffic — not by webrtc-rs's ICE connection state, which lies
in both directions (it reports `Failed` / `Disconnected` on links that are
carrying traffic, and `Connected` with a "nominated, succeeded" pair on
links whose data channel never opened). The design began as a port of
MyOwnLLM's `src/mesh-client.svelte.ts`, but has since **diverged through
field testing** on a Mac / Windows / Linux rig: the old re-handshake
(Tier 4) and room-rejoin (Tier 5) loops are gone — re-handshaking over a
dead channel can't work — replaced by an in-place ICE restart *confirmed
by inbound traffic*, with a clean rebuild as the fallback. This file is
the spec the engine — under `crates/myownmesh-core/src/engine/` — must
hit. The constants are load-bearing edge-case handling; don't relax one
without understanding why it's there.

> **Debugging connection-state reliability?** See
> [`docs/DEBUGGING-CONNECTIONS.md`](docs/DEBUGGING-CONNECTIONS.md) for
> the connection tracer (`myownmesh ctl trace`), the cross-machine
> timeline merger, and the reproduction scenarios — the measure-first
> tooling for finding where the several liveness signals disagree.

## The four layers

The engine runs four independent state machines that compose:

1. **Signaling (Nostr).** Manages the relay socket pool. Tracks
   active REQ subscriptions and replays them on reconnect (see
   [`upstream` item 1][upstream]). Emits "discovered peer" events
   when a peer's announce shows up.

2. **WebRTC + ICE.** Per-peer `RTCPeerConnection`-equivalent. Owns
   ICE candidate gathering, the DTLS handshake, and the data
   channel. Watches `iceConnectionState`; treats `disconnected` as
   transient (see [`upstream` item 2][upstream]).

3. **Cryptographic handshake.** ed25519 mutual auth via the
   `hello` → `auth_response` exchange, with the 6-char verification
   code as the user-facing anchor. Hello frames retry on a
   schedule (see [Tunables](#tunables)); a watchdog tears down the
   transport if no `auth_response` arrives within
   `HANDSHAKE_TIMEOUT_MS`.

4. **App protocol.** Frames after the connection becomes ACTIVE:
   `ping`/`pong` heartbeats, `shelve`/`unshelve` topology
   negotiation, `capabilities_update`, generic RPC, and embedder-
   defined typed channels.

Each layer fires events upward; the next-higher layer decides
whether the event is a normal transition or a fault to recover from.

## The recovery ladder

Ordered cheapest → most disruptive. On per-peer trouble the engine tries
to recover the link **in place**; only when that fails to restore traffic
does it rebuild. ICE-state changes drive *recovery actions* — never
teardown (see [Teardown authority](#teardown-authority)). The tier names
survive on `ConnectionTier` for the GUI; `Rehandshake` / `RoomRejoin` are
retained as wire/UI variants but the engine no longer produces them.

| Tier | Trigger | Action | Notes |
|------|---------|--------|-------|
| **1. Steady** | Inbound frame arrives | Reset `last_recv_at`; if the peer was recovering, promote it back (`tier → Steady`). | Inbound traffic is the one signal that *confirms* a link is really carrying frames. |
| **2. Wake probe** | Wake event (OS or tick gap > `WAKE_DETECTION_THRESHOLD_MS`) | Ping all peers; any that don't answer within `WAKE_PROBE_DELAY_MS` (1.5 s) are **rebuilt**. | Catches resume-from-sleep where heartbeats were paused. |
| **2.5. ICE watchdog** | Per-peer `iceConnectionState == disconnected` | After `ICE_DISCONNECTED_RESTART_MS` (1 s), **renegotiate ICE** in place: `pc.restart_ice()` *and* a fresh offer (`renegotiate_ice`), re-driven each `ICE_POLL_INTERVAL_MS`. | A bare `restart_ice()` only re-gathers our candidates + rotates our ufrag; the peer never hears about it, so the offer is the other half. The data channel survives. |
| **3. ICE restart + traffic-confirm** | Network change (primary IP moved) or ICE failed | `renegotiate_ice` per peer, forced past the stale `Connected` a just-moved interface reports. When ICE reconnects, fire a confirm-ping and wait for **inbound traffic** to prove the path carries frames — `Connected` alone doesn't. Traffic → `Steady`. | Recovers a Wi-Fi↔cellular handoff in place, in seconds. Only the deterministic offerer emits the offer (no glare); single-flighted so the watchdog + network-watch don't flood signaling. |
| **4. Rebuild** | A restart that reached `Connected` but got no traffic within `RESTART_TRAFFIC_GRACE_MS` (10 s); a session whose data channel never opened within `DATA_CHANNEL_OPEN_TIMEOUT_MS` (30 s); a closed data channel; or inbound silence past the heartbeat. | Drop the peer; discovery builds a fresh `RTCPeerConnection` (fresh DTLS + data channel). On the answerer side, a fresh offer for a stuck-connecting peer rebuilds to align generations. | The in-place restart is fragile across some handoffs (webrtc-rs reports `Connected` on a dead TURN path); a clean rebuild is the reliable fallback. Replaces the old re-handshake / room-rejoin loops. |
| **6. Stop + Start** | Signaling / STUN / TURN config edit | Reconcile teardown + fresh start, immediately. | Triggered only by user action — never automatic recovery. |

## Teardown authority

The ladder *recovers* a link; what decides a link is **dead** is
deliberately narrow and keyed only off reliable signals — never
webrtc-rs's ICE connection state, which has been observed reporting
`Failed` / `Disconnected` on links carrying traffic and `Connected` (with
a "nominated, succeeded" pair) on links whose data channel never opened. A
peer is torn down and rebuilt by exactly three things:

1. **Connect-timeout** — a session whose **data channel never opened**
   within `DATA_CHANNEL_OPEN_TIMEOUT_MS` of creation. The data-channel
   `open` event (DTLS + SCTP genuinely up) is the one unambiguous
   "we connected" milestone, so this is the single clock for a
   *connecting* peer. It replaced the old ICE-`Checking` timeout and its
   succeeded-but-not-nominated grace window.
2. **Data-channel close** — a `DataChannelClosed` / PC-`Closed` event, the
   authoritative transport-dead signal for an *open* peer.
3. **Inbound silence** — no frame received past the heartbeat grace
   (zombie clearing), the liveness backstop for an *open* peer.

Everything else — ICE `Disconnected` / `Failed`, a stale nominated pair —
only ever *schedules an in-place restart* (`renegotiate_ice`); it never
tears a peer down on its own.

## Tunables

Live in `crates/myownmesh-core/src/engine/scheduler.rs` as `pub const`s.

```
HANDSHAKE_TIMEOUT_MS                = 30_000              // tear-down if no auth_response in 30s
HANDSHAKE_HELLO_RETRY_SCHEDULE_MS   = [5_000, 7_000, 10_000]

HEARTBEAT_INTERVAL_MS               = 30_000              // ping cadence on active connections
HEARTBEAT_TIMEOUT_MS                = 30_000              // silence past TIMEOUT + WAKE_DETECTION → rebuild
WAKE_DETECTION_THRESHOLD_MS         = HEARTBEAT_INTERVAL_MS * 2  // 60s tick gap = "we slept"
WAKE_COALESCE_MS                    = 2_000               // dedupe wake events fired close together
WAKE_PROBE_DELAY_MS                 = 1_500               // tier-2 probe wait

ICE_DISCONNECTED_RESTART_MS         = 1_000               // tier-2.5 watchdog: how long Disconnected before restart
ICE_POLL_INTERVAL_MS                = 3_000               // ICE watchdog poll + renegotiation retry cadence
NETWORK_CHANGE_RESTART_COOLDOWN_MS  = 5_000               // coalesce the IP-flip burst of one handoff (offline edges exempt)

DATA_CHANNEL_OPEN_TIMEOUT_MS        = 30_000              // connecting peer: rebuild if the data channel never opens
RESTART_TRAFFIC_GRACE_MS           = 10_000              // after ICE reconnects: rebuild if no inbound traffic confirms
RELAY_RESCUE_MIN_INTERVAL_MS        = 30_000              // throttle for the "0 remote candidates" forced relay redial
STALE_INBOUND_MS                    = (signaling crate)   // inbound-silence threshold for zombie clearing on a fresh offer
RECONNECTING_GRACE_MS               = 90_000              // reconnect-skip-approval grace window (surfaced in Dropped)

SIGNALING_DIAG_HEARTBEAT_MS         = 5 * 60 * 1000       // periodic "all relays OK" diag emit
NETWORK_WATCH_POLL_MS               = 3_000               // network-change watcher poll cadence
DEFAULT_SIGNALING_REDUNDANCY        = 5                   // five relays at once

DEFAULT_RING_N_PREFERRED            = 3                   // 2 neighbors + 1 shortcut (TopologyMode assoc const, config.rs)

DIAG_MAX                            = 80                  // diag ring buffer cap
```

## Edge cases handled

Field-discovered behaviors the engine implements — many pinned down on
the Mac / Windows / Linux rig with the connection tracer. The comments in
the source files carry the rationale; this section is the index.

- **Traffic confirms recovery, not ICE.** When an in-place ICE restart
  reaches `Connected`, the engine does *not* declare the peer recovered —
  webrtc-rs reports `Connected` on dead TURN paths that carry no frames.
  It fires a confirm-ping and waits for inbound traffic; only a received
  frame promotes the peer back to `Steady`. No traffic within the grace →
  rebuild. (`handle_ice_state_change` / `handle_inbound_frame` /
  `ice_watchdog`.)

- **Silence rebuilds; it never re-handshakes.** A live channel keeps
  `last_recv_at` fresh via the heartbeat pong, so silence past the window
  means the *transport* is dead — re-sending `hello` over it can't work.
  The heartbeat and wake-probe paths drop + rebuild instead.

- **Stuck answerer rebuilds on a fresh offer.** The offerer creates the
  data channel, so an answerer whose data channel never opened can't fix
  itself by renegotiating onto the stuck PC (it just re-resets ICE — a
  mutual-re-offer deadlock that pins the peer at Sighted over TURN). A
  fresh offer for a connecting peer past the grace drops the stuck PC and
  builds a clean one to answer, aligning generations.

- **Offline edges are never coalesced.** The network-watch restart
  cooldown folds the IP-flip *burst* of one handoff into a single restart
  — but going offline, and especially the interface *returning*, always
  run the full handler (force relay redial + ICE restart + clear the
  offline latch). Coalescing the return was a bug that left the engine
  deaf and forced the slow rebuild path.

- **Outbound signaling buffered across a relay reconnect.** A network
  change forces the relay to redial at the same instant it publishes the
  ICE-restart offers; without buffering they're dropped into the
  reconnecting socket and the peer never hears them. The next relay up
  replays them (bounded + TTL'd). Dual of inbound subscription-replay.

- **Link-local addresses filtered from ICE gathering.** `fe80::/10` and
  `169.254/16` can't be bound without a scope id, so the agent failed one
  bind at a time — a dozen per gather. An `ip_filter` drops them up front
  (ULAs, RFC-1918, and globals are kept).

- **Subscription replay on Nostr reconnect.** Without this, a
  network swap (wifi → hotspot) silently stalls re-handshake for
  ~90 s because the new socket has no relay-side REQ state.
  Implemented natively in
  `crates/myownmesh-signaling/src/nostr/relay.rs::SubscriptionReplay`;
  see `crates/myownmesh-signaling/src/upstream.rs` item 1.

- **ICE-disconnected is transient.** Treating `connectionState ==
  disconnected` as `live` would block re-handshake on the side
  that didn't itself swap networks for 15-30 s. Engine considers
  it transient and starts the 7.5 s grace immediately.

- **Inbound-recency zombie clearing.** Even with the above, ICE
  consent freshness can take longer than the heartbeat
  cadence to detect a dead path. The engine tracks
  last-inbound-message-per-peer; gaps > 25 s mark the prior
  connection a zombie regardless of `connectionState` and let
  the next announce drive a fresh handshake.

- **Offer-pool flush on peer drop.** Pre-warmed WebRTC offers
  carry the gathered ICE candidates from when they were created;
  after a local network change they're unanswerable. On any peer
  drop, the engine drains the pool (throttled to once / 10 s) so
  the next checkout produces a fresh offer with current
  candidates.

- **State-transition logging.** Trystero defaults to one log per
  announce per relay (≈ 1 log / s / peer). Engine logs only on
  lifecycle transitions (`fresh → offering → connected → ...`)
  plus stuck-thresholds at 15 / 30 / 60 s of waiting for an
  answer. Per-event logs are suppressed by default.

- **Hello retry schedule.** Three hellos at 5 / 7 / 10 s — not
  exponential; we want the second attempt fast (5 s, before the
  user gets impatient) but back off after that to avoid filling
  the data channel with retries when the other side is genuinely
  not coming back.

- **Verification-code regen on each hello.** Codes are
  per-handshake, not per-peer. Replaying an old hello with a
  reused code is rejected by the engine on second sight to
  defeat a slow attacker who recorded one user-approval.

- **Tier 2.5 fires before the consent-freshness timeout.** The ICE
  watchdog at 1 s beats webrtc-rs's ~5 s consent-freshness reconnect
  attempt; the engine repairs in place rather than destroying the data
  channel.

## Invariants the engine maintains

1. **No coordinator.** Every topology decision is local and
   deterministic. Two peers running the same algorithm over the
   same sorted input agree on shelving without a round trip.

2. **Authenticate first, approve second.** The ed25519 signature
   check happens before any user-facing prompt; the user only
   ever sees an approval request for a peer who's already proven
   they own the keypair they claim.

3. **Roster is the only persistent trust.** Verification codes
   are ephemeral. Long-term "I know this peer" lives entirely in
   `~/.myownmesh/mesh/rosters/{network_id}.json`.

4. **Per-network isolation.** Rosters, approvals, and topology
   selectors are per-`network_id`. Switching networks atomically
   swaps to the new roster — no cross-contamination.

5. **Forward-compatible frames.** Receivers silently drop
   unknown `kind` values rather than failing the stream. New
   message kinds gate at the [`features`][features] matrix.

## Anti-patterns

Do not:

- **Add a global retry budget.** Per-peer, per-tier budgets are
  what keep one bad peer from preventing recovery of healthy
  peers.

- **Coalesce diag logs at the engine layer.** Embedders may want
  every transition for an Activity log; let them filter.

- **Mix sleeping and tokio timers.** Use `tokio::time::interval`
  / `tokio::time::sleep` exclusively so the wake detector
  triggers correctly on `Instant` discontinuities.

- **Bypass the topology selector.** Adding "but just for this
  one peer" logic that doesn't go through `select_preferred`
  breaks the symmetry property and produces orphaned shelves.

[upstream]: ./crates/myownmesh-signaling/src/upstream.rs
[features]: ./crates/myownmesh-core/src/protocol/features.rs
