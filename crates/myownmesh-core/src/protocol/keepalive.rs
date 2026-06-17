//! Heartbeat frames: `ping` / `pong`. Sent on every active connection
//! at a configurable interval (default 30s). The recovery ladder uses
//! gaps in inbound traffic (no ping or app message past the heartbeat
//! timeout) as the trigger to drop and rebuild a silent peer.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingMessage {
    /// Sender's monotonic timestamp (milliseconds since some local
    /// reference point — *not* wall-clock, *not* synchronised across
    /// peers). Echoed back in `pong` so the sender can compute
    /// round-trip latency without trusting the peer's clock.
    pub t: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongMessage {
    pub t: i64,
}
