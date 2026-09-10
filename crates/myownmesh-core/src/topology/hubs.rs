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
//! Connection counts are bounded by the configured tier: for `N` total
//! members and `H` unique hubs, spoke-hub edges are at most
//! `(N-H) * spoke_redundancy`, and the explicit hub full mesh contributes
//! `H * (H-1) / 2`. A spoke holds `spoke_redundancy` connections; a
//! hub holds (other hubs + the spokes that ranked it). Broadcasts flood
//! spoke → its hubs → all hubs → their spokes
//! with per-node dedup; directed frames route the same path (see
//! `engine::routing`).

use std::cmp::Ordering;
use std::collections::HashSet;

#[cfg(test)]
use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::Topology;
use crate::identity::DeviceId;
use crate::signing;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
std::thread_local! {
    static RENDEZVOUS_SCORE_WORK: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Clone)]
pub struct HubsSelector {
    pub hubs: Vec<DeviceId>,
    /// How many hubs each spoke connects to (≥ 1; clamped to the hub
    /// count at evaluation time).
    pub spoke_redundancy: u32,
}

impl HubsSelector {
    fn redundancy_limit(&self) -> usize {
        usize::try_from(self.spoke_redundancy).unwrap_or(usize::MAX)
    }

    fn is_hub(&self, id: &str) -> bool {
        let id = signing::pubkey_part(id);
        self.hubs.iter().any(|h| signing::pubkey_part(h) == id)
    }

    fn configured_hub_score(&self, spoke: &str, hub: &str) -> Option<u64> {
        let hub = signing::pubkey_part(hub);
        self.hubs
            .iter()
            .any(|configured| signing::pubkey_part(configured) == hub)
            .then(|| rendezvous_score(spoke, hub))
    }

    /// The hubs `spoke` should attach to: the top-`spoke_redundancy`
    /// of the rendezvous ranking. Pure and total — defined even for
    /// ids nobody has seen yet, which is what keeps every node's
    /// answer identical during membership churn.
    fn retain_ranked_hub<'a>(
        ranked: &mut Vec<RankedHub<'a>>,
        candidate: RankedHub<'a>,
        limit: usize,
    ) {
        if limit == 0
            || (ranked.len() == limit
                && Self::ranked_hub_order(&candidate, ranked.last().expect("full ranking"))
                    != Ordering::Less)
        {
            return;
        }
        let position = ranked
            .binary_search_by(|current| Self::ranked_hub_order(current, &candidate))
            .unwrap_or_else(|position| position);
        if ranked.len() == limit {
            ranked.pop();
        }
        ranked.insert(position, candidate);
    }

    fn ranked_hub_order(left: &RankedHub<'_>, right: &RankedHub<'_>) -> Ordering {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.key.cmp(right.key))
    }

    fn ranked_hubs_prefix<'a>(&'a self, spoke: &str, limit: usize) -> Vec<RankedHub<'a>> {
        let spoke = signing::pubkey_part(spoke);
        let mut ranked: Vec<RankedHub<'a>> = Vec::with_capacity(limit.min(self.hubs.len()));
        for configured in &self.hubs {
            let hub = signing::pubkey_part(configured);
            if ranked.iter().any(|previous| previous.key == hub) {
                continue;
            }
            Self::retain_ranked_hub(
                &mut ranked,
                RankedHub {
                    score: rendezvous_score(spoke, hub),
                    key: hub,
                },
                limit,
            );
        }
        ranked
    }

    fn hubs_for(&self, spoke: &str) -> Vec<String> {
        let limit = self
            .spoke_redundancy
            .max(1)
            .try_into()
            .unwrap_or(usize::MAX);
        self.ranked_hubs_prefix(spoke, limit)
            .into_iter()
            .map(|hub| hub.key.to_string())
            .collect()
    }

    fn spoke_selects_hub(&self, spoke: &str, hub: &str) -> bool {
        let limit = self
            .spoke_redundancy
            .max(1)
            .try_into()
            .unwrap_or(usize::MAX);
        let hub = signing::pubkey_part(hub);
        self.ranked_hubs_prefix(spoke, limit)
            .iter()
            .any(|candidate| candidate.key == hub)
    }

    fn route_candidate_order(left: &RankedCandidate<'_>, right: &RankedCandidate<'_>) -> Ordering {
        right
            .direct
            .cmp(&left.direct)
            .then_with(|| right.score.cmp(&left.score))
            .then_with(|| left.key.cmp(right.key))
    }

    fn next_hops_with_limit(
        &self,
        self_id: &str,
        dest: &str,
        connected: &[String],
        limit: usize,
    ) -> Vec<String> {
        let dest_key = signing::pubkey_part(dest);
        let source_key = signing::pubkey_part(self_id);
        let target = limit.min(self.redundancy_limit());
        if target == 0 {
            return Vec::new();
        }

        // Retain only the best target candidates. A rendezvous rank is
        // monotonic in score, so ranking connected configured hubs directly
        // avoids rescanning the complete configured tier for every peer.
        let destination_is_hub = self.is_hub(dest_key);
        let mut candidates = Vec::<RankedCandidate<'_>>::new();
        for peer in connected {
            let key = signing::pubkey_part(peer);
            if key == source_key {
                continue;
            }
            let Some(score) = self.configured_hub_score(dest_key, key) else {
                continue;
            };
            let candidate = RankedCandidate {
                direct: destination_is_hub && key == dest_key,
                score,
                key,
                peer: peer.as_str(),
            };
            if let Some(existing) = candidates.iter_mut().find(|item| item.key == candidate.key) {
                if candidate.peer < existing.peer {
                    existing.peer = candidate.peer;
                }
                continue;
            }
            if candidates.len() == target
                && Self::route_candidate_order(&candidate, candidates.last().expect("full hops"))
                    != Ordering::Less
            {
                continue;
            }
            let position = candidates
                .binary_search_by(|current| Self::route_candidate_order(current, &candidate))
                .unwrap_or_else(|position| position);
            if candidates.len() == target {
                candidates.pop();
            }
            candidates.insert(position, candidate);
        }
        candidates
            .into_iter()
            .map(|candidate| candidate.peer.to_string())
            .collect()
    }
}

/// The rendezvous (highest-random-weight) score of a `(spoke, hub)`
/// pair: the first 8 bytes of `SHA-256(spoke ‖ ":" ‖ hub)`.
fn rendezvous_score(spoke: &str, hub: &str) -> u64 {
    #[cfg(test)]
    RENDEZVOUS_SCORE_WORK.with(|work| work.set(work.get().saturating_add(1)));
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
        let self_is_hub = self.is_hub(self_id);
        let self_key = signing::pubkey_part(self_id);
        let selected_hubs = (!self_is_hub).then(|| self.hubs_for(self_id));
        peer_ids
            .iter()
            .filter(|peer| {
                if signing::pubkey_part(peer) == self_key {
                    return false;
                }
                match (self_is_hub, self.is_hub(peer)) {
                    (true, true) => true,
                    (false, true) => selected_hubs.as_ref().is_some_and(|hubs| {
                        hubs.iter().any(|hub| hub == signing::pubkey_part(peer))
                    }),
                    (true, false) => self.spoke_selects_hub(peer, self_id),
                    (false, false) => false,
                }
            })
            .cloned()
            .collect()
    }

    fn edge(&self, a: &str, b: &str, _all: &[String]) -> bool {
        if signing::pubkey_part(a) == signing::pubkey_part(b) {
            return false;
        }
        match (self.is_hub(a), self.is_hub(b)) {
            // The hub tier is a full mesh among itself.
            (true, true) => true,
            // A spoke connects to exactly the hubs its ranking names.
            (false, true) => self.spoke_selects_hub(a, b),
            (true, false) => self.spoke_selects_hub(b, a),
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

    fn next_hops(
        &self,
        self_id: &str,
        dest: &str,
        connected: &[String],
        limit: usize,
    ) -> Vec<String> {
        self.next_hops_with_limit(self_id, dest, connected, limit)
    }

    fn flood_ttl(&self) -> u8 {
        // spoke → hub → hub → spoke, plus one spare for a transient.
        4
    }
}

struct RankedCandidate<'a> {
    direct: bool,
    score: u64,
    key: &'a str,
    peer: &'a str,
}

struct RankedHub<'a> {
    score: u64,
    key: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE32_NOPAD;
    use ed25519_dalek::SigningKey;

    fn canonical_key(index: u64) -> String {
        let digest = Sha256::digest(index.to_le_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        let signing_key = SigningKey::from_bytes(&seed);
        BASE32_NOPAD
            .encode(signing_key.verifying_key().as_bytes())
            .to_lowercase()
    }

    fn reset_score_work() {
        RENDEZVOUS_SCORE_WORK.with(|work| work.set(0));
    }

    fn score_work() -> usize {
        RENDEZVOUS_SCORE_WORK.with(|work| work.get())
    }

    fn sel(hubs: &[&str], redundancy: u32) -> HubsSelector {
        HubsSelector {
            hubs: hubs.iter().map(|h| h.to_string()).collect(),
            spoke_redundancy: redundancy,
        }
    }

    fn s(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
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
        let hops = t.next_hops("hub-x-not-real", "s2", &connected, 1);
        assert_eq!(hops, vec![s2_hub]);
        // With none of the destination's hubs connected, any hub will do.
        let connected: Vec<String> = vec!["hub-a".into()];
        let t2 = sel(&["hub-a", "hub-b"], 1);
        let hops = t2.next_hops("s1", "s2", &connected, 1);
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

    #[test]
    fn next_hops_are_bounded_stable_and_self_free_with_duplicate_input() {
        let t = sel(&["hub-a", "hub-b", "hub-c"], 2);
        let first = vec![
            "hub-a".to_string(),
            "hub-a".to_string(),
            "hub-b".to_string(),
            "spoke".to_string(),
        ];
        let mut reordered = first.clone();
        reordered.reverse();
        let a = t.next_hops("spoke", "destination", &first, 2);
        let b = t.next_hops("spoke", "destination", &reordered, 2);
        assert_eq!(a, b, "connected input order must not affect failover");
        assert!(a.len() <= 2);
        assert!(a.iter().all(|hop| signing::pubkey_part(hop) != "spoke"));
        assert_eq!(
            a.iter()
                .map(|hop| signing::pubkey_part(hop))
                .collect::<BTreeSet<_>>()
                .len(),
            a.len()
        );
    }

    #[test]
    fn next_hops_respects_explicit_limit_without_growing_with_connected_input() {
        let t = sel(&["hub-a", "hub-b", "hub-c", "hub-d"], 3);
        let connected = s(&["hub-a", "hub-b", "hub-c", "hub-d", "hub-a-display", "spoke"]);
        let one = t.next_hops_with_limit("spoke", "destination", &connected, 1);
        assert_eq!(one.len(), 1);
        assert!(one.iter().all(|hop| signing::pubkey_part(hop) != "spoke"));
        let zero = t.next_hops_with_limit("spoke", "destination", &connected, 0);
        assert!(zero.is_empty());
        let over = t.next_hops_with_limit("spoke", "destination", &connected, 99);
        assert!(over.len() <= 3);
    }

    #[test]
    fn large_hub_prefix_matches_reference_without_large_retained_ranking() {
        let hubs: Vec<String> = (0..5_000).map(canonical_key).collect();
        let spoke = canonical_key(50_000);
        let t = HubsSelector {
            hubs: hubs.clone(),
            spoke_redundancy: 3,
        };

        reset_score_work();
        let selected = t.hubs_for(&spoke);
        let selected_work = score_work();
        let mut reference_work = 0usize;
        let mut reference: Vec<(u64, String)> = hubs
            .iter()
            .map(|hub| {
                reference_work = reference_work.saturating_add(1);
                (rendezvous_score(&spoke, hub), hub.clone())
            })
            .collect();
        reference.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        let expected: Vec<String> = reference.into_iter().take(3).map(|(_, hub)| hub).collect();
        assert_eq!(selected, expected);
        assert_eq!(selected_work, reference_work);
        assert_eq!(t.ranked_hubs_prefix(&spoke, 3).len(), 3);
    }

    #[test]
    fn large_peer_selection_computes_one_spoke_assignment() {
        let hubs: Vec<String> = (0..5_000).map(canonical_key).collect();
        let spoke = canonical_key(60_000);
        let t = HubsSelector {
            hubs: hubs.clone(),
            spoke_redundancy: 3,
        };
        let expected = t.hubs_for(&spoke);
        let selected = t.select_preferred(&spoke, &hubs);
        assert_eq!(selected.len(), 3);
        assert!(selected.iter().all(|hub| expected.contains(hub)));
    }

    #[test]
    fn canonical_5000_member_plan_is_symmetric_bounded_and_stable() {
        let canonical_hubs: Vec<String> =
            (0..16).map(|index| canonical_key(10_000 + index)).collect();
        let mut configured_hubs = canonical_hubs.clone();
        configured_hubs.insert(1, format!("{}-abc12", canonical_hubs[0]));
        let topology = HubsSelector {
            hubs: configured_hubs.clone(),
            spoke_redundancy: 2,
        };
        let spokes: Vec<String> = (0..4_984).map(canonical_key).collect();
        let mut members = canonical_hubs.clone();
        members.extend(spokes.iter().cloned());

        let mut edge_count = 0usize;
        for spoke in &spokes {
            assert!(!topology.edge(spoke, spoke, &members));
            let selected = topology.hubs_for(spoke);
            assert_eq!(selected.len(), 2);
            for hub in &canonical_hubs {
                assert_eq!(
                    topology.edge(spoke, hub, &members),
                    topology.edge(hub, spoke, &members)
                );
                if topology.edge(spoke, hub, &members) {
                    edge_count = edge_count.saturating_add(1);
                }
            }
        }
        for (index, hub) in canonical_hubs.iter().enumerate() {
            assert!(!topology.edge(hub, hub, &members));
            for other in canonical_hubs.iter().skip(index + 1) {
                assert!(topology.edge(hub, other, &members));
                assert_eq!(
                    topology.edge(hub, other, &members),
                    topology.edge(other, hub, &members)
                );
                edge_count = edge_count.saturating_add(1);
            }
        }
        assert_eq!(edge_count, 4_984 * 2 + (16 * 15 / 2));

        let mut shuffled = configured_hubs;
        shuffled.reverse();
        let shuffled_topology = HubsSelector {
            hubs: shuffled,
            spoke_redundancy: 2,
        };
        for spoke in &spokes {
            assert_eq!(
                topology.hubs_for(spoke),
                shuffled_topology.hubs_for(spoke),
                "hub spelling/order must not affect rendezvous assignment"
            );
        }
    }

    #[test]
    fn preferred_selection_score_work_is_bounded_by_hub_count() {
        let hubs: Vec<String> = (0..16).map(|index| canonical_key(20_000 + index)).collect();
        let topology = HubsSelector {
            hubs: hubs.clone(),
            spoke_redundancy: 2,
        };
        let mut peers = hubs.clone();
        peers.extend((0..4_984).map(canonical_key));
        let self_id = canonical_key(0);
        reset_score_work();
        let selected = topology.select_preferred(&self_id, &peers);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            score_work(),
            16,
            "one spoke assignment should rank each hub once"
        );
    }

    #[test]
    fn aliases_are_deduplicated_and_surviving_hubs_are_ranked_for_failover() {
        let t = sel(&["hub-a", "hub-a-abc12", "hub-b", "hub-c"], 3);
        assert_eq!(t.hubs_for("spoke").len(), 3);

        let homes = t.hubs_for("spoke");
        let connected: Vec<String> = homes.iter().skip(1).cloned().collect();
        let hops = t.next_hops("hub-origin", "spoke", &connected, 3);
        assert_eq!(hops, connected);
        assert!(hops
            .iter()
            .all(|hop| signing::pubkey_part(hop) != "hub-origin"));
    }
}
