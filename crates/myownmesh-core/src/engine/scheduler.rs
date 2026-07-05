//! Engine timing constants. Mirrored from MyOwnLLM's
//! `mesh-client.svelte.ts` — see `CONNECTION-ENGINE.md` for the
//! rationale on each one. Do not relax without understanding the
//! field-discovered behavior the value defends.

/// Time-to-live on the hello → auth_response watchdog. If the
/// peer doesn't reply in this window the connection is torn down
/// and rebuilt from scratch.
pub const HANDSHAKE_TIMEOUT_MS: u64 = 30_000;

/// Delays between hello retries inside a single handshake.
/// Three attempts: first at +5 s, second at +7 s, third at +10 s.
/// Not exponential — the second attempt is fast (before the user
/// gets impatient) and the third backs off so we don't fill the
/// data channel with retries when the other side is genuinely
/// not coming back.
pub const HANDSHAKE_HELLO_RETRY_SCHEDULE_MS: &[u64] = &[5_000, 7_000, 10_000];

/// Heartbeat ping cadence on active connections.
pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;

/// Peer silent past this (no inbound ping or app frame) triggers a
/// drop + rebuild — the link is treated as dead and re-established
/// from scratch rather than restarted in place.
pub const HEARTBEAT_TIMEOUT_MS: u64 = 30_000;

/// Tick gap above this counts as a wake event (~ resume from sleep).
pub const WAKE_DETECTION_THRESHOLD_MS: u64 = HEARTBEAT_INTERVAL_MS * 2;

/// Coalesce wake events fired within this window — multiple
/// sources may detect the same wake.
pub const WAKE_COALESCE_MS: u64 = 2_000;

/// Tier 2 wake-probe wait after pinging every peer.
pub const WAKE_PROBE_DELAY_MS: u64 = 1_500;

/// Minimum gap between announce-driven liveness probes for the same peer.
/// When a peer we hold as Active/Shelved re-announces but its inbound has
/// gone silent past `STALE_INBOUND_MS`, we ping it and rebuild if no traffic
/// confirms within `WAKE_PROBE_DELAY_MS` (see
/// `confirm_active_session_on_announce`). This floor single-flights that
/// probe so a REQ-replay burst of announces can't stack probe tasks on one
/// peer; sized comfortably above the probe's own grace so a new probe never
/// starts while the previous one's confirm window is still open.
pub const LIVENESS_PROBE_MIN_INTERVAL_MS: u64 = 5_000;

/// Tier 2.5 ICE watchdog — beats Trystero's ~5 s consent freshness
/// timeout by firing at 1 s after `ice_disconnected`.
pub const ICE_DISCONNECTED_RESTART_MS: u64 = 1_000;

/// Cadence of the single **state-watch tick** — the one periodic pass that
/// remains after folding the old separate ICE-watchdog and network-watch
/// intervals together. Recovery is event-driven first (ICE-state changes, a
/// data-channel close, a relay reconnect, an inbound announce all act
/// immediately); this tick is the secondary safety net that confirms
/// everything still looks right and enforces the inherently time-based
/// conditions no single event can signal — a data channel that never opens,
/// a restart that never carries traffic, a reconnect intent that needs
/// another nudge, a primary-IP change. Kept inside the WebRTC
/// consent-freshness window so the worst-case "events missed it" latency is
/// still a couple seconds, not the stack's ~30 s internal timer.
pub const STATE_WATCH_INTERVAL_MS: u64 = 2_000;

/// Backoff schedule for the offerer-side reconnect retry. After we drop a
/// peer we were the *offerer* for (a recoverable `IceFailed`), we keep a
/// reconnect *intent* and re-offer on this backoff until the link comes
/// back or [`RECONNECTING_GRACE_MS`] elapses — the offerer-side counterpart
/// to an answerer recovering from the remote's re-offers. Events re-offer
/// immediately (a relay reconnect flushes every intent at once); this backoff
/// only paces the tick's safety-net retries so a peer that genuinely went
/// away doesn't spin the relays. First retry is quick, then it backs off.
pub const RECONNECT_RETRY_BACKOFF_MS: &[u64] = &[2_000, 4_000, 8_000, 15_000];

/// How long to wait for a session's **data channel to open** before
/// declaring the connection attempt failed and rebuilding. This is the
/// single teardown clock for a *connecting* peer, and it keys off the one
/// reliable transport signal — the `DataChannelOpen` event (DTLS + SCTP
/// genuinely established) — not webrtc-rs's ICE connection state, which
/// has been observed reporting `Connected`/`nominated` on links whose data
/// channel never came up and `Failed`/`Disconnected` on links that were
/// fine. ICE-state changes now only ever trigger an in-place restart
/// (recovery); they never tear a peer down. Sized to outlast the worst
/// recoverable case — a relay redial on a fresh interface (seconds) plus a
/// slow signaling round-trip plus ICE gather + DTLS — so a connection
/// that's merely slow to negotiate is never torn down mid-flight, while a
/// genuinely dead one is still reclaimed without waiting out webrtc-rs's
/// ~30 s internal timer. A successful connect opens its channel in 1-2 s
/// regardless, so this only ever bounds a *failure*.
pub const DATA_CHANNEL_OPEN_TIMEOUT_MS: u64 = 30_000;

/// How long a **local offer build** (create_offer + set_local_description —
/// pure local computation, no network round-trip) may take before the engine
/// abandons the attempt. This runs INLINE on the driver task, so an offer
/// build that never returns doesn't just lose one peer — it freezes the
/// entire network's engine: commands, timers, and every other peer queue
/// behind it, which is precisely the wedge observed on the NanoKVM (single
/// slow riscv64 core: driver parked in the offer path forever, control-socket
/// ops timing out, node never claimable). A healthy build takes single-digit
/// milliseconds on x86 and well under a second on the slowest supported
/// device, so ten seconds only ever bounds a failure.
pub const OFFER_BUILD_TIMEOUT_MS: u64 = 10_000;

/// How long a **read-only ICE introspection** call (`selected_candidate_pair`
/// / `ice_check_snapshot` — the diagnostic stats reads the state-watch tick
/// makes to record the chosen path and log connectivity-check progress) may
/// take before the tick abandons it for this pass. Like the offer build these
/// run INLINE on the driver task, but unlike it they were never bounded — the
/// blind spot that still froze a NanoKVM after `OFFER_BUILD_TIMEOUT_MS` landed.
/// The reads contend with the ICE agent's own async lock, so on a single slow
/// core mid-gather (a network change re-gathering on a flapping interface) the
/// snapshot can park the whole driver — commands and signaling included — long
/// enough to trip the bridge's control-socket timeout, exactly the wedge the
/// offer bound fixed for the *offerer* but left open on the *answerer* (which
/// never builds an offer, only introspects). These calls drive no recovery
/// (the connect-timeout keys off `data_channel_open`, not them), so a pass that
/// times out simply skips one diagnostic line / a momentary GUI transport label
/// and self-heals next tick. A healthy read is sub-millisecond, so one second
/// only ever bounds the pathological case — and stays under the tick interval
/// (`STATE_WATCH_INTERVAL_MS`) so the driver always has slack to service
/// commands between passes even when a peer trips both reads in one tick.
pub const ICE_INTROSPECT_TIMEOUT_MS: u64 = 1_000;

/// How long a **control-message send to one peer** (`send_to_peer` →
/// `PeerSession::send` — an engine ping / shelve-unshelve / roster frame over
/// the data channel) may take before the engine abandons it. Like the offer
/// build and the ICE stats reads this runs INLINE on the driver task — reachable
/// on the shared loop via `heartbeat::tick` → `send_ping` and via the
/// state-watch tick's `drop_peer` → `reevaluate_topology` → `send_shelve_unshelve`
/// — so a data-channel send that parks on a slow core mid-gather can wedge the
/// whole driver, the same class of freeze the two constants above bound. This
/// covers ONLY the best-effort control plane: `send_to_peer` is documented
/// best-effort and its callers already handle a send failure, so a timed-out
/// send is just one more dropped ping / shelve that the next tick re-sends. The
/// reliable user-facing channels (site routes, media) go through
/// `send_channel_frame`, NOT this path, and are deliberately left unbounded so
/// their ordered delivery is never truncated. Generous enough to ride transient
/// SCTP buffer pressure on a healthy link, far under the heartbeat / bridge
/// control-socket timeouts a real wedge would trip.
pub const PEER_SEND_TIMEOUT_MS: u64 = 2_000;

/// After an in-place ICE restart reconnects, how long to wait for *inbound
/// traffic* to confirm the path actually carries frames before giving up
/// and rebuilding. ICE reaching `Connected` is **not** proof — webrtc-rs
/// reports it on dead TURN paths that never deliver a byte (seen in the
/// field after a Wi-Fi→hotspot handoff: three peers "Connected" on TURN,
/// zero frames for 90 s). A real path pongs the post-restart confirm-ping
/// within a round-trip, so this only needs to cover that RTT plus jitter.
/// Kept short so a restart that "connected" but is actually dead is rebuilt
/// in seconds, not at the heartbeat timeout a minute later.
pub const RESTART_TRAFFIC_GRACE_MS: u64 = 10_000;

/// Minimum gap between relay redials forced by the "connect timed out with
/// zero remote candidates" rescue (see
/// [`crate::engine::state::NetworkState::request_relay_reconnect_throttled`]).
/// A peer whose candidates never cross the relay re-times-out every
/// `DATA_CHANNEL_OPEN_TIMEOUT_MS`; without this throttle the rescue would
/// bounce the relay sockets on every one of those cycles. One redial per
/// this window is enough to recover a socket that actually went stale
/// after a network blip, while leaving healthy sockets — the ones already
/// delivering candidates for other peers — undisturbed. Matched to the
/// connect-timeout so a single stuck peer maps to at most one redial per
/// timeout cycle.
pub const RELAY_RESCUE_MIN_INTERVAL_MS: u64 = 30_000;

/// After a network change kicks an ICE-restart fan-out, ignore further
/// change-triggered restarts for this long. A Wi-Fi→cellular handoff
/// flips the primary outbound IP several times across a couple seconds
/// (v4 swaps, then v6 appears); without this, each flip fires another
/// `restart_ice()` that collides with the previous one's in-flight
/// gather (`ICE Agent can not be restarted when gathering`) and burns a
/// whole gather cycle. One restart per burst is enough — the
/// checking-timeout watchdog rebuilds anything still stuck afterward.
pub const NETWORK_CHANGE_RESTART_COOLDOWN_MS: u64 = 5_000;

/// Grace window, surfaced in [`crate::events::PeerEvent::Dropped`],
/// during which a fresh reconnect from a just-dropped (previously
/// approved) peer skips the user-approval prompt. Not a timer the engine
/// itself waits on — the embedder/GUI uses it to decide how long a
/// "reconnecting" affordance stays warm before treating the peer as gone.
pub const RECONNECTING_GRACE_MS: u64 = 90_000;

/// Inbound-message staleness threshold for zombie clearing. When a
/// fresh announce/offer arrives from a peer we already hold but
/// haven't received anything from in longer than this, the engine
/// treats the existing session as a zombie and drops it so the
/// inbound signal can drive a clean rebuild — instead of wedging
/// WebRTC by applying a new SDP onto a stale peer connection.
/// Re-exported from the signaling crate so the engine and signaling
/// layer share one value — see `myownmesh-signaling`'s `upstream.rs`
/// item 3.
pub use myownmesh_signaling::upstream::STALE_INBOUND_MS;

/// Periodic diag emit so a long-stable connection still reports
/// status to the UI.
pub const SIGNALING_DIAG_HEARTBEAT_MS: u64 = 5 * 60 * 1000;

/// Diag log ring buffer cap per network.
pub const DIAG_MAX: usize = 80;
