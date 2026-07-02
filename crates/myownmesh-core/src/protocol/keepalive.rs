//! Heartbeat frames: `ping` / `pong`. Sent on every active connection
//! at a configurable interval (default 30s). The recovery ladder uses
//! gaps in inbound traffic (no ping or app message past the heartbeat
//! timeout) as the trigger to drop and rebuild a silent peer.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingMessage {
    /// Sender's **wall clock** at send, as Unix-epoch milliseconds. (Every
    /// shipped build has stamped it this way; this doc used to claim
    /// "monotonic, not wall-clock" — the RTT math never cared, but the
    /// distinction matters now.) Echoed back unchanged in `pong` so the
    /// sender computes round-trip latency purely against its own clock;
    /// the *receiver* additionally reads it as a free, passive clock-skew
    /// sample (`t + rtt/2 − local now`) — the basis of the "your clock is
    /// out of sync with the network" warning, with no extra traffic.
    pub t: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongMessage {
    pub t: i64,
}
