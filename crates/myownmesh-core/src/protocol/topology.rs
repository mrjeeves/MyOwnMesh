//! Topology negotiation frames. Each peer runs the topology selector
//! locally and emits `shelve`/`unshelve` to peers based on the diff
//! between the previous and new preferred sets.
//!
//! Receivers track shelving direction independently:
//!   - `local_shelved`  — we sent `shelve` to them (they're not in our preferred set)
//!   - `remote_shelved` — they sent `shelve` to us (we're not in theirs)
//!
//! A connection is effectively shelved when either flag is true.
//! Either side can `unshelve` later when the selector promotes them.

use serde::{Deserialize, Serialize};

/// "I'm not going to send you application traffic for now — keep the
/// data channel open as a heartbeat so we can flip back to active
/// quickly when the topology rebalances."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShelveMessage {
    /// Why we're shelving — surfaced in the Activity log so the
    /// user can see "shelved bob (out-of-ring)" vs "shelved bob
    /// (over capacity)". Optional.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshelveMessage {}
