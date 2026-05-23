//! Topology selectors decide, for the set of currently-connected
//! authorized peers, which subset gets sent application traffic.
//! Peers outside the "preferred" set are shelved — the data channel
//! stays open as a heartbeat, but no app frames flow.
//!
//! Selectors are pure functions. Every peer runs the same algorithm
//! over the same sorted input and arrives at the same answer — that's
//! what makes shelving safe without a coordinator. The engine diffs
//! the previous and new preferred sets and emits `shelve` /
//! `unshelve` to the affected peers.

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
}

/// Construct a [`Topology`] trait object from a config-side mode.
pub fn from_mode(mode: &TopologyMode) -> Box<dyn Topology> {
    match mode {
        TopologyMode::Ring { n_preferred } => Box::new(ring::RingSelector {
            n_preferred: n_preferred.unwrap_or(TopologyMode::DEFAULT_RING_N_PREFERRED),
        }),
        TopologyMode::Star { hub } => Box::new(star::StarSelector { hub: hub.clone() }),
        TopologyMode::FullMesh => Box::new(fullmesh::FullMeshSelector),
    }
}
