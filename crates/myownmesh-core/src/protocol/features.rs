//! Capability negotiation between peers. Each peer advertises a set
//! of feature ids in its `HelloMessage::features`. A sender consults
//! the receiver's advertised set before sending optional frame kinds
//! — if the receiver doesn't claim support, the sender skips the
//! frame rather than relying on the receiver's `Unknown` drop path.
//!
//! Stable strings: changing an id breaks rolling upgrades. New
//! features get new ids; the matrix is append-only.

/// Stable feature identifiers. Compared as exact strings.
pub struct Feature;

impl Feature {
    /// Peer participates in ring topology — receives `shelve` /
    /// `unshelve` frames and applies them to its outbound traffic.
    pub const RING_TOPOLOGY: &'static str = "ring_topology";

    /// Peer supports the generic RPC frames (`rpc_request`,
    /// `rpc_response`, `rpc_stream_chunk`, `rpc_stream_end`). All
    /// MyOwnMesh peers advertise this; the flag exists so a future
    /// stripped-down embedder can opt out cheaply.
    pub const GENERIC_RPC: &'static str = "generic_rpc";

    /// Peer supports user-defined typed channels (`Channel` frames).
    pub const TYPED_CHANNELS: &'static str = "typed_channels";

    /// Peer publishes [`CapabilitiesUpdateMessage`] when its local
    /// advertised capabilities change. Receivers that lack this
    /// only see the snapshot included in `hello`.
    pub const CAPABILITIES_UPDATE: &'static str = "capabilities_update";

    /// Peer speaks the closed-network governance wire — emits and
    /// honours `network_state`, `network_state_propose`,
    /// `network_state_ack`, `network_state_split`, and the
    /// `roster_summary` / `roster_request` / `roster_entries`
    /// triad. Senders only emit these frames against peers that
    /// advertise this flag, since older peers would drop them via
    /// the `Unknown` catch-all. See
    /// [`docs/NETWORK-TYPES.md`](../../../../docs/NETWORK-TYPES.md).
    pub const NETWORK_STATE_V1: &'static str = "network_state_v1";
}

/// The set of features this build advertises to peers. Embedders
/// that subset MyOwnMesh's API (e.g. headless-only, no RPC) can
/// override at the [`crate::handle::Mesh::open`] boundary.
pub const ADVERTISED_FEATURES: &[&str] = &[
    Feature::RING_TOPOLOGY,
    Feature::GENERIC_RPC,
    Feature::TYPED_CHANNELS,
    Feature::CAPABILITIES_UPDATE,
    Feature::NETWORK_STATE_V1,
];

/// Test whether a peer's advertised feature list contains `feature`.
/// The advertised list is stringly typed on the wire — peers may
/// advertise features this build doesn't know about (newer release)
/// or omit ones we do (older release).
pub fn peer_supports(peer_features: &[String], feature: &str) -> bool {
    peer_features.iter().any(|f| f == feature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_supports_matches_exactly() {
        let peer = vec!["ring_topology".to_string(), "typed_channels".to_string()];
        assert!(peer_supports(&peer, Feature::RING_TOPOLOGY));
        assert!(peer_supports(&peer, Feature::TYPED_CHANNELS));
        assert!(!peer_supports(&peer, Feature::GENERIC_RPC));
        assert!(!peer_supports(&peer, "Ring_Topology")); // case-sensitive
    }

    #[test]
    fn advertised_features_includes_ring() {
        assert!(ADVERTISED_FEATURES.contains(&Feature::RING_TOPOLOGY));
    }
}
