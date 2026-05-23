# Connection engine

The mesh's resilience comes from a layered connection engine and a
7-tier reconnection ladder, both ported in spirit from MyOwnLLM's
`src/mesh-client.svelte.ts` (which itself is documented in
`MyOwnLLM/CONNECTION-ENGINE.md`). This file is the spec the Rust
port — under `crates/myownmesh-core/src/engine/` — must hit. Every
constant and timing decision here is load-bearing edge-case
handling discovered through MyOwnLLM's field operation; don't
relax one without understanding why it's there.

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

## The reconnection ladder

Seven tiers ordered cheapest → most disruptive. On any per-peer
trouble the engine starts at Tier 1 and escalates only when the
prior tier fails to recover.

| Tier | Trigger | Action | Notes |
|------|---------|--------|-------|
| **1. Steady** | App message arrives | Reset `last_recv_at`. | No-op recovery path. |
| **2. Wake probe** | Wake event (OS or tick gap > `WAKE_DETECTION_THRESHOLD_MS`) | Ping all peers + wait `WAKE_PROBE_DELAY_MS` (1.5 s). | Catches resume-from-sleep where heartbeats were paused. |
| **2.5. ICE watchdog** | Per-peer `iceConnectionState == disconnected` | After `ICE_DISCONNECTED_RESTART_MS` (1 s), call `pc.restart_ice()`. | **Fires before Trystero's 5 s timeout** — the whole point of having this tier. |
| **3. ICE restart** | Wake probe finds all peers silent | Per-PC `pc.restart_ice()` with `ICE_RESTART_RECOVERY_MS` (4 s) grace. | Avoids tearing down the data channel if ICE can recover in place. |
| **4. Re-handshake** | Silence > `HEARTBEAT_TIMEOUT_MS + WAKE_DETECTION_THRESHOLD_MS` (~75 s) or Tier 3 failed | Per-peer `hello` cycle on `REHANDSHAKE_BACKOFF_MS_SCHEDULE` (2 / 5 / 10 / 20 / 30 s) with `REHANDSHAKE_JITTER_FRACTION` (±20 %) jitter. Up to `REHANDSHAKE_RESCUE_ATTEMPTS` (3) rounds. | Jitter prevents the thundering-herd retry when two peers wake simultaneously. |
| **5. Room rejoin** | Three Tier-4 rounds failed, OR rostered peer offline > `OFFLINE_ROSTERED_CHECK_INTERVAL_MS` (60 s) | Trystero room `leave` + `joinRoom`. Backed off via `REDISCOVERY_BACKOFF_SCHEDULE_MS` (90 s / 3 min / 5 min / 10 min). | Throttle prevents relay-spam after persistent failure. |
| **6. Stop + Start** | Signaling / STUN / TURN config edit | Reconcile teardown + fresh start, immediately. | Triggered only by user action — never as an automatic recovery. |

## Tunables

Constants ported verbatim from MyOwnLLM's `mesh-client.svelte.ts`.
Names are preserved. The Rust port lives in
`crates/myownmesh-core/src/engine/` and re-exports these as `pub
const`s.

```
HANDSHAKE_TIMEOUT_MS                = 30_000              // tear-down if no auth_response in 30s
HANDSHAKE_HELLO_RETRY_SCHEDULE_MS   = [5_000, 7_000, 10_000]
REHANDSHAKE_JITTER_FRACTION         = 0.2                 // ±20% on every re-handshake delay
REHANDSHAKE_BACKOFF_MS_SCHEDULE     = [2_000, 5_000, 10_000, 20_000, 30_000]
REHANDSHAKE_RESCUE_ATTEMPTS         = 3

HEARTBEAT_INTERVAL_MS               = 30_000              // ping cadence on active connections
HEARTBEAT_TIMEOUT_MS                = 30_000              // peer silent past this triggers Tier 4
WAKE_DETECTION_THRESHOLD_MS         = HEARTBEAT_INTERVAL_MS * 2  // 60s tick gap = "we slept"
WAKE_COALESCE_MS                    = 2_000               // dedupe wake events fired close together
WAKE_PROBE_DELAY_MS                 = 1_500               // tier-2 probe wait

ICE_DISCONNECTED_RESTART_MS         = 1_000               // tier-2.5 watchdog (beats Trystero's 5s)
ICE_RESTART_RECOVERY_MS             = 4_000               // tier-3 grace after restart
ICE_POLL_INTERVAL_MS                = 3_000               // periodic ICE state poll

RECONNECTING_GRACE_MS               = 90_000              // tier-5 max wait before pruning
RECONNECT_PRUNE_INTERVAL_MS         = 10_000              // sweep stale reconnecting entries
OFFLINE_ROSTERED_CHECK_INTERVAL_MS  = 60_000              // re-room-rejoin trigger for offline-too-long rostered peers
REDISCOVERY_BACKOFF_SCHEDULE_MS     = [90_000, 180_000, 300_000, 600_000]
REDISCOVERY_REJOIN_GAP_MS           = 1_500               // gap between leave() and joinRoom() on tier-5

SIGNALING_DIAG_HEARTBEAT_MS         = 5 * 60 * 1000       // periodic "all relays OK" diag emit
SIGNALING_DIAG_INTERVAL_MS          = 10_000              // poll cadence for getRelaySockets()
DEFAULT_SIGNALING_REDUNDANCY        = 5                   // five relays at once

RING_DEFAULT_PREFERRED              = 3                   // 2 neighbors + 1 shortcut
RING_MIN_PREFERRED                  = 2                   // floor; below this we have no shortcut slot

DIAG_MAX                            = 80                  // diag ring buffer cap
```

Scheduler tick names (used by the wake-honest scheduler so tick
gaps can be attributed to a specific timer):
```
SCHED_HEARTBEAT        SCHED_OFFLINE_CHECK
SCHED_RECONNECT_PRUNE  SCHED_CATALOG_REFRESH       (catalog refresh is embedder-defined)
```

## Edge cases handled

These are the bug-discovered behaviors MyOwnLLM ships today. The
Rust port must preserve every one — the comments in the source
files capture the rationale; this section is the index so a
future reader can find them.

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

- **Jittered re-handshake backoff.** ±20 % on every Tier 4 delay
  so simultaneous wake events on multiple peers don't all
  attempt re-handshake at the same instant.

- **Tier 2.5 fires before Trystero's full reconnect.** ICE
  watchdog at 1 s beats Trystero's ~5 s consent-freshness
  reconnect attempt; the engine repairs in place rather than
  destroying the data channel.

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
