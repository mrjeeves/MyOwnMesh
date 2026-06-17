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

/// Tier 2.5 ICE watchdog — beats Trystero's ~5 s consent freshness
/// timeout by firing at 1 s after `ice_disconnected`.
pub const ICE_DISCONNECTED_RESTART_MS: u64 = 1_000;

/// Periodic ICE state poll cadence. Also the retry cadence for an
/// in-progress ICE renegotiation: while a peer's link stays down the
/// watchdog re-drives the (single-flighted) `renegotiate_ice` here, so a
/// lost restart offer is re-sent within a poll rather than escalating.
pub const ICE_POLL_INTERVAL_MS: u64 = 3_000;

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

/// Network-change watcher poll cadence. Cheap (one UDP bind +
/// connect per network per tick, microseconds of work) so we run
/// it often — 3 s gets us inside the WebRTC consent-freshness
/// window so the user sees recovery in seconds rather than waiting
/// 30 s for ICE to notice the network moved.
pub const NETWORK_WATCH_POLL_MS: u64 = 3_000;

/// Diag log ring buffer cap per network.
pub const DIAG_MAX: usize = 80;
