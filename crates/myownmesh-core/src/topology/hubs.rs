//! Hub-tier topology: a small set of config-named hubs full-meshes
//! among itself; every other member (a spoke) connects to a few of the
//! hubs and reaches the rest of the network through them.
//!
//! Spoke→hub assignment is **rendezvous hashing** over `(spoke, hub)`:
//! every node computes the same ranking with no coordination, and a
//! hub joining or leaving only moves the spokes that ranked it —
//! nobody else re-homes. Redundancy is the top-`spoke_redundancy`
//! hubs of the ranking.
//!
//! Connection counts: a spoke holds `spoke_redundancy` connections; a
//! hub holds (other hubs + the spokes that ranked it). Nothing pays
//! N². Broadcasts flood spoke → its hubs → all hubs → their spokes
//! with per-node dedup; directed frames route the same path (see
//! `engine::routing`).

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::Topology;
use crate::identity::DeviceId;
use crate::signing;

#[derive(Debug, Clone)]
pub struct HubsSelector {
    pub hubs: Vec<DeviceId>,
    /// How many hubs each spoke connects to (≥ 1; clamped to the hub
    /// count at evaluation time).
    pub spoke_redundancy: u32,
}

impl HubsSelector {
    fn is_hub(&self, id: &str) -> bool {
        let id = signing::pubkey_part(id);
        self.hubs.iter().any(|h| signing::pubkey_part(h) == id)
    }

    /// The hubs `spoke` should attach to: the top-`spoke_redundancy`
    /// of the rendezvous ranking. Pure and total — defined even for
    /// ids nobody has seen yet, which is what keeps every node's
    /// answer identical during membership churn.
    fn hubs_for(&self, spoke: &str) -> Vec<String> {
        let spoke = signing::pubkey_part(spoke);
        let mut ranked: Vec<(u64, &str)> = self
            .hubs
            .iter()
            .map(|h| {
                let hub = signing::pubkey_part(h);
                (rendezvous_score(spoke, hub), hub)
            })
            .collect();
        // Highest score first; the hub id breaks exact ties so the
        // order is total.
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
        ranked
            .into_iter()
            .take((self.spoke_redundancy.max(1)) as usize)
            .map(|(_, h)| h.to_string())
            .collect()
    }
}

/// The rendezvous (highest-random-weight) score of a `(spoke, hub)`
/// pair: the first 8 bytes of `SHA-256(spoke ‖ ":" ‖ hub)`.
fn rendezvous_score(spoke: &str, hub: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(spoke.as_bytes());
    hasher.update(b":");
    hasher.update(hub.as_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"))
}

impl Topology for HubsSelector {
    fn select_preferred(&self, self_id: &str, peer_ids: &[String]) -> HashSet<String> {
        // Frames flow exactly where connections exist.
        peer_ids
            .iter()
            .filter(|p| self.edge(self_id, p, peer_ids))
            .cloned()
            .collect()
    }

    fn edge(&self, a: &str, b: &str, _all: &[String]) -> bool {
        match (self.is_hub(a), self.is_hub(b)) {
            // The hub tier is a full mesh among itself.
            (true, true) => true,
            // A spoke connects to exactly the hubs its ranking names.
            (false, true) => self
                .hubs_for(a)
                .iter()
                .any(|h| h == signing::pubkey_part(b)),
            (true, false) => self
                .hubs_for(b)
                .iter()
                .any(|h| h == signing::pubkey_part(a)),
            // Spokes never connect to each other.
            (false, false) => false,
        }
    }

    fn prunes(&self) -> bool {
        true
    }

    fn forwards(&self, self_id: &str, _all: &[String]) -> bool {
        self.is_hub(self_id)
    }

    fn next_hops(&self, self_id: &str, dest: &str, connected: &[String]) -> Vec<String> {
        let dest_key = signing::pubkey_part(dest);
        // Prefer the hubs the destination actually attaches to; fall
        // back to any connected hub (it can take the next step).
        let dest_hubs = if self.is_hub(dest_key) {
            vec![dest_key.to_string()]
        } else {
            self.hubs_for(dest_key)
        };
        let connected_key = |c: &String| signing::pubkey_part(c).to_string();
        let mut hops: Vec<String> = connected
            .iter()
            .filter(|c| dest_hubs.iter().any(|h| h == &connected_key(c)))
            .cloned()
            .collect();
        if hops.is_empty() {
            hops = connected
                .iter()
                .filter(|c| {
                    self.is_hub(c) && signing::pubkey_part(c) != signing::pubkey_part(self_id)
                })
                .cloned()
                .collect();
        }
        hops
    }

    fn flood_ttl(&self) -> u8 {
        // spoke → hub → hub → spoke, plus one spare for a transient.
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel(hubs: &[&str], redundancy: u32) -> HubsSelector {
        HubsSelector {
            hubs: hubs.iter().map(|h| h.to_string()).collect(),
            spoke_redundancy: redundancy,
        }
    }

    #[test]
    fn hubs_full_mesh_and_spokes_attach_to_ranked_hubs() {
        let t = sel(&["hub-a", "hub-b", "hub-c"], 2);
        let all: Vec<String> = ["hub-a", "hub-b", "hub-c", "s1", "s2"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(t.edge("hub-a", "hub-b", &all), "hub tier is a full mesh");
        assert!(!t.edge("s1", "s2", &all), "spokes never interconnect");
        // A spoke has exactly `redundancy` hub edges.
        let hub_edges = ["hub-a", "hub-b", "hub-c"]
            .iter()
            .filter(|h| t.edge("s1", h, &all))
            .count();
        assert_eq!(hub_edges, 2);
    }

    #[test]
    fn edge_is_symmetric_and_deterministic() {
        let t = sel(&["hub-a", "hub-b", "hub-c"], 1);
        let all: Vec<String> = vec![];
        for spoke in ["s1", "s2", "s3", "s4"] {
            for hub in ["hub-a", "hub-b", "hub-c"] {
                assert_eq!(
                    t.edge(spoke, hub, &all),
                    t.edge(hub, spoke, &all),
                    "edge({spoke},{hub}) must be symmetric"
                );
            }
            assert_eq!(t.hubs_for(spoke), t.hubs_for(spoke), "stable ranking");
        }
    }

    #[test]
    fn hub_departure_only_rehomes_its_own_spokes() {
        // Rendezvous property: removing hub-c changes assignments only
        // for spokes whose top pick was hub-c.
        let with_c = sel(&["hub-a", "hub-b", "hub-c"], 1);
        let without_c = sel(&["hub-a", "hub-b"], 1);
        for i in 0..64 {
            let spoke = format!("spoke-{i}");
            let before = with_c.hubs_for(&spoke);
            let after = without_c.hubs_for(&spoke);
            if before[0] != "hub-c" {
                assert_eq!(before, after, "{spoke} must not re-home");
            }
        }
    }

    #[test]
    fn redundancy_clamps_to_hub_count() {
        let t = sel(&["hub-a", "hub-b"], 5);
        assert_eq!(
            t.hubs_for("s1").len(),
            2,
            "can't attach to more hubs than exist"
        );
    }

    #[test]
    fn spoke_routes_via_destinations_hubs_first() {
        let t = sel(&["hub-a", "hub-b", "hub-c"], 1);
        // s2's home hub, per the same ranking every node computes.
        let s2_hub = t.hubs_for("s2")[0].clone();
        // A hub connected to everything routes an s2-bound frame to
        // s2's home hub when it isn't s2's neighbor itself.
        let connected: Vec<String> = ["hub-a", "hub-b", "hub-c"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let hops = t.next_hops("hub-x-not-real", "s2", &connected);
        assert_eq!(hops, vec![s2_hub]);
        // With none of the destination's hubs connected, any hub will do.
        let connected: Vec<String> = vec!["hub-a".into()];
        let t2 = sel(&["hub-a", "hub-b"], 1);
        let hops = t2.next_hops("s1", "s2", &connected);
        assert!(hops == vec!["hub-a".to_string()] || hops.is_empty());
    }

    #[test]
    fn only_hubs_forward() {
        let t = sel(&["hub-a"], 1);
        assert!(t.forwards("hub-a", &[]));
        assert!(!t.forwards("s1", &[]));
    }

    #[test]
    fn preferred_matches_edges() {
        let t = sel(&["hub-a", "hub-b"], 1);
        let peers: Vec<String> = ["hub-a", "hub-b", "s2", "s3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let picks = t.select_preferred("s1", &peers);
        let expected: HashSet<String> = peers
            .iter()
            .filter(|p| t.edge("s1", p, &peers))
            .cloned()
            .collect();
        assert_eq!(picks, expected);
    }
}
