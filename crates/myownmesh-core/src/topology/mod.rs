//! Topology selectors decide the *shape* of the network: which
//! connections exist at all, which of them carry application traffic,
//! who forwards frames for members that aren't directly connected, and
//! how a frame reaches a member across the shape.
//!
//! Selectors are pure functions. Every peer runs the same algorithm
//! over the same sorted input and arrives at the same answer — that's
//! what makes both shelving *and* connection-shaping safe without a
//! coordinator. Asymmetric transients (two nodes momentarily knowing
//! different member sets) are absorbed by the engine: refusing to
//! *initiate* a dial never refuses to *answer* one, and pruning fires
//! only once both sides have independently shelved the link.
//!
//! Historically selectors only picked the "preferred" (frame-carrying)
//! subset while every connection stayed open as a heartbeat path — so
//! ring and star modes still paid full-mesh connection costs (ICE
//! keepalives, DTLS, engine pings, TURN allocations) and a
//! hub-and-spoke deployment couldn't actually be evaluated.
//! [`Topology::edge`] is the connection-shaping half: modes that
//! return `true` from [`Topology::prunes`] dial only where an edge
//! exists, close both-sides-shelved non-edges, and route the rest
//! through forwarders ([`Topology::forwards`] /
//! [`Topology::next_hops`]) — see `engine::routing`.

use std::collections::HashSet;

pub use crate::config::TopologyMode;

pub mod fullmesh;
pub mod hubs;
pub mod ring;
pub mod star;

/// Strategy for the local shape decisions. Implementations MUST be
/// pure: given the same inputs they must return the same answer on
/// every node — determinism is what replaces coordination.
pub trait Topology: Send + Sync {
    /// Given the local pubkey and all *authorized + currently
    /// connected* peer pubkeys (NOT including self), return the
    /// subset to keep active (receiving application frames).
    fn select_preferred(&self, self_id: &str, peer_ids: &[String]) -> HashSet<String>;

    /// Whether a connection should exist between `a` and `b`, given
    /// every currently-known member (`all` should include both
    /// endpoints when known; implementations tolerate absences).
    /// Symmetric by contract: `edge(a, b, all) == edge(b, a, all)`.
    /// The default — every pair connects — is the pre-shaping
    /// behavior, so a mode shapes connections only by opting in.
    fn edge(&self, _a: &str, _b: &str, _all: &[String]) -> bool {
        true
    }

    /// Whether this mode actively shapes connections: dial only where
    /// [`Topology::edge`] holds, and prune both-sides-shelved
    /// non-edges. `false` preserves the historical keep-every-
    /// connection behavior regardless of what `edge` says.
    fn prunes(&self) -> bool {
        false
    }

    /// Whether `self_id` forwards frames on behalf of members that
    /// aren't directly connected (a hub; any member, on a ring). Only
    /// forwarders re-fan broadcasts and route directed envelopes —
    /// and only forwarders may hand on an envelope whose origin isn't
    /// themselves (see `engine::routing` for the trust note).
    fn forwards(&self, _self_id: &str, _all: &[String]) -> bool {
        false
    }

    /// Where `self_id` should send a frame destined for `dest` when
    /// `dest` isn't directly connected: the next hop(s) to try, best
    /// first, drawn from `connected`. Empty = no route (the caller
    /// surfaces the delivery failure honestly rather than guessing).
    fn next_hops(&self, _self_id: &str, _dest: &str, _connected: &[String]) -> Vec<String> {
        Vec::new()
    }

    /// Hop budget for forwarded frames under this mode. Loop safety
    /// belongs to the per-node dedup ring; the TTL bounds the blast
    /// radius of a routing disagreement during a membership transient.
    fn flood_ttl(&self) -> u8 {
        4
    }
}

/// Construct a [`Topology`] trait object from a config-side mode.
pub fn from_mode(mode: &TopologyMode) -> Box<dyn Topology> {
    match mode {
        TopologyMode::Ring { n_preferred } => Box::new(ring::RingSelector {
            n_preferred: n_preferred.unwrap_or(TopologyMode::DEFAULT_RING_N_PREFERRED),
        }),
        TopologyMode::Star { hub } => Box::new(star::StarSelector { hub: hub.clone() }),
        TopologyMode::Hubs {
            hubs,
            spoke_redundancy,
        } => Box::new(hubs::HubsSelector {
            hubs: hubs.clone(),
            spoke_redundancy: spoke_redundancy
                .unwrap_or(TopologyMode::DEFAULT_SPOKE_REDUNDANCY)
                .max(1),
        }),
        TopologyMode::FullMesh => Box::new(fullmesh::FullMeshSelector),
    }
}
