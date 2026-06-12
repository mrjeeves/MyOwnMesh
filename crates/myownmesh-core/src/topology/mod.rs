//! Topology selectors make two nested decisions:
//!
//! - **Preferred set** — for the currently-connected authorized
//!   peers, which subset gets sent application traffic. Peers outside
//!   it are shelved — the data channel stays open as a heartbeat, but
//!   no app frames flow.
//! - **Connect set** (optional cap) — for the currently-present
//!   peers, which subset gets a WebRTC transport at all. Peers
//!   outside it are parked — no transport, presence tracked via
//!   signaling only. This is what bounds per-node connection build-up
//!   on large networks; selectors that return `None` keep the
//!   connect-to-everyone behavior.
//!
//! Selectors are pure functions. Every peer runs the same algorithm
//! over the same sorted input and arrives at the same answer — that's
//! what makes shelving *and parking* safe without a coordinator: both
//! ends agree an edge shouldn't exist, so neither dials. The engine
//! diffs the previous and new preferred sets and emits `shelve` /
//! `unshelve` to the affected peers; parking needs no wire frames at
//! all.

use std::collections::HashSet;

pub use crate::config::TopologyMode;

pub mod fullmesh;
pub mod ring;
pub mod star;

/// Strategy for the local "who do I send app traffic to" decision.
///
/// Implementations MUST be pure: given the same `self_id` and
/// `peer_ids` they must return the same `HashSet`. Determinism is
/// what makes shelving symmetric across peers — both sides agree
/// without a round trip.
pub trait Topology: Send + Sync {
    /// Given the local pubkey and all *authorized + currently
    /// connected* peer pubkeys (NOT including self), return the
    /// subset to keep active.
    fn select_preferred(&self, self_id: &str, peer_ids: &[String]) -> HashSet<String>;

    /// Given the local pubkey and all *currently present* peer
    /// pubkeys (connected or parked, NOT including self), return the
    /// subset to keep WebRTC transports to — or `None` for "no cap,
    /// connect to everyone" (the pre-parking behavior, and the
    /// default for selectors that don't override this).
    ///
    /// Implementations MUST be pure and, over the same input, MUST
    /// return a superset of [`select_preferred`](Self::select_preferred)
    /// — a peer can't carry app traffic without a transport. Peers
    /// outside the connect set are *parked*: the engine closes (or
    /// never dials) their transport and tracks them by signaling
    /// presence only.
    fn select_connect(&self, _self_id: &str, _peer_ids: &[String]) -> Option<HashSet<String>> {
        None
    }
}

/// Construct a [`Topology`] trait object from a config-side mode.
pub fn from_mode(mode: &TopologyMode) -> Box<dyn Topology> {
    match mode {
        TopologyMode::Ring { .. } => Box::new(ring::RingSelector {
            n_preferred: mode.effective_n_preferred(),
            n_connect: mode.effective_n_connect(),
        }),
        TopologyMode::Star { hub } => Box::new(star::StarSelector { hub: hub.clone() }),
        TopologyMode::FullMesh => Box::new(fullmesh::FullMeshSelector),
    }
}
