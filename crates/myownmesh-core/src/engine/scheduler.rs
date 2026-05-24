//! Engine timing constants. Mirrored from MyOwnLLM's
//! `mesh-client.svelte.ts` — see `CONNECTION-ENGINE.md` for the
//! rationale on each one. Do not relax without understanding the
//! field-discovered behavior the value defends.

/// Time-to-live on the hello → auth_response watchdog. If the
/// peer doesn't reply in this window the connection is torn down
/// and re-attempted from Tier 4.
pub const HANDSHAKE_TIMEOUT_MS: u64 = 30_000;

/// Delays between hello retries inside a single handshake.
/// Three attempts: first at +5 s, second at +7 s, third at +10 s.
/// Not exponential — the second attempt is fast (before the user
/// gets impatient) and the third backs off so we don't fill the
/// data channel with retries when the other side is genuinely
/// not coming back.
pub const HANDSHAKE_HELLO_RETRY_SCHEDULE_MS: &[u64] = &[5_000, 7_000, 10_000];

/// ±20 % jitter applied to every re-handshake delay.
pub const REHANDSHAKE_JITTER_FRACTION: f64 = 0.2;

/// Re-handshake backoff inside Tier 4. Five attempts before
/// escalating to Tier 5.
pub const REHANDSHAKE_BACKOFF_MS_SCHEDULE: &[u64] = &[2_000, 5_000, 10_000, 20_000, 30_000];

/// Tier 4 rescue attempts before escalating to Tier 5.
pub const REHANDSHAKE_RESCUE_ATTEMPTS: u32 = 3;

/// Heartbeat ping cadence on active connections.
pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;

/// Peer silent past this triggers Tier 4 re-handshake.
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

/// Tier 3 grace after `pc.restart_ice()` before escalating to
/// Tier 4.
pub const ICE_RESTART_RECOVERY_MS: u64 = 4_000;

/// Periodic ICE state poll cadence.
pub const ICE_POLL_INTERVAL_MS: u64 = 3_000;

/// Tier 5 maximum wait before pruning a reconnecting entry.
pub const RECONNECTING_GRACE_MS: u64 = 90_000;

/// Sweep cadence for stale reconnecting entries.
pub const RECONNECT_PRUNE_INTERVAL_MS: u64 = 10_000;

/// Tier 5 trigger for rostered-but-offline peers.
pub const OFFLINE_ROSTERED_CHECK_INTERVAL_MS: u64 = 60_000;

/// Tier 5 redocking backoff schedule.
pub const REDISCOVERY_BACKOFF_SCHEDULE_MS: &[u64] = &[90_000, 180_000, 300_000, 600_000];

/// Tier 5 — gap between leave() and joinRoom() so the relay sees
/// the leave-presence before the new join.
pub const REDISCOVERY_REJOIN_GAP_MS: u64 = 1_500;

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

/// Named scheduler tick ids — surfaced in diag entries so a gap
/// can be attributed to a specific timer.
pub mod ticks {
    pub const HEARTBEAT: &str = "heartbeat";
    pub const OFFLINE_CHECK: &str = "offline-check";
    pub const RECONNECT_PRUNE: &str = "reconnect-prune";
    pub const ICE_POLL: &str = "ice-poll";
}
