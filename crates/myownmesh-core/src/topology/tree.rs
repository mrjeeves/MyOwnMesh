//! A shallow, explicit root -> hub -> leaf topology.
//!
//! This selector only advertises bounded candidate edges. Runtime parent
//! admission, session ownership, relation generations, and child-slot
//! custody belong to the engine; deterministic ranking is not registration.
//! The maximum depth is deliberately two so a leaf-to-leaf route fits the
//! protocol's four-hop routed-envelope ceiling.

use std::cmp::Ordering;
use std::collections::HashSet;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use sha2::{Digest, Sha256};

use super::Topology;
use crate::identity::DeviceId;
use crate::signing;

#[derive(Debug, Clone)]
pub struct HubTreeSelector {
    pub root: DeviceId,
    pub hubs: Vec<DeviceId>,
    /// Number of optional backup hub candidates in addition to the primary.
    pub backup_candidates: u32,
}

impl HubTreeSelector {
    fn is_root(&self, id: &str) -> bool {
        signing::pubkey_part(id) == signing::pubkey_part(&self.root)
    }

    fn is_hub(&self, id: &str) -> bool {
        let key = signing::pubkey_part(id);
        !self.is_root(key) && self.hubs.iter().any(|hub| signing::pubkey_part(hub) == key)
    }

    fn candidate_limit(&self) -> usize {
        usize::try_from(self.backup_candidates)
            .unwrap_or(usize::MAX)
            .saturating_add(1)
            .min(self.hubs.len())
    }

    fn ranked_order(left: &RankedHub<'_>, right: &RankedHub<'_>) -> Ordering {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.key.cmp(right.key))
    }

    fn retain_ranked<'a>(ranked: &mut Vec<RankedHub<'a>>, candidate: RankedHub<'a>, limit: usize) {
        if limit == 0
            || ranked.iter().any(|entry| entry.key == candidate.key)
            || (ranked.len() == limit
                && Self::ranked_order(&candidate, ranked.last().expect("full candidate set"))
                    != Ordering::Less)
        {
            return;
        }
        let position = ranked
            .binary_search_by(|entry| Self::ranked_order(entry, &candidate))
            .unwrap_or_else(|position| position);
        if ranked.len() == limit {
            ranked.pop();
        }
        ranked.insert(position, candidate);
    }

    fn ranked_candidates<'a>(&'a self, leaf: &str, limit: usize) -> Vec<RankedHub<'a>> {
        let leaf = signing::pubkey_part(leaf);
        let mut ranked = Vec::with_capacity(limit);
        for configured in &self.hubs {
            let key = signing::pubkey_part(configured);
            if self.is_root(key) {
                continue;
            }
            Self::retain_ranked(
                &mut ranked,
                RankedHub {
                    score: rendezvous_score(leaf, key),
                    key,
                },
                limit,
            );
        }
        ranked
    }

    fn ranked_connected_candidates<'a>(
        &'a self,
        leaf: &str,
        connected: &[String],
        limit: usize,
    ) -> Vec<RankedHub<'a>> {
        let leaf = signing::pubkey_part(leaf);
        let mut ranked = Vec::with_capacity(limit);
        for configured in &self.hubs {
            let key = signing::pubkey_part(configured);
            if self.is_root(key) || self.connected_spelling(key, connected).is_none() {
                continue;
            }
            Self::retain_ranked(
                &mut ranked,
                RankedHub {
                    score: rendezvous_score(leaf, key),
                    key,
                },
                limit,
            );
        }
        ranked
    }

    fn connected_spelling<'a>(&self, key: &str, connected: &'a [String]) -> Option<&'a str> {
        connected
            .iter()
            .filter(|peer| signing::pubkey_part(peer) == key)
            .map(String::as_str)
            .min()
    }

    fn append_connected(&self, keys: &[String], connected: &[String], limit: usize) -> Vec<String> {
        let mut result = Vec::new();
        for key in keys {
            if result.len() == limit {
                break;
            }
            let key = signing::pubkey_part(key);
            if result
                .iter()
                .any(|peer: &String| signing::pubkey_part(peer) == key)
            {
                continue;
            }
            if let Some(peer) = self.connected_spelling(key, connected) {
                result.push(peer.to_string());
            }
        }
        result
    }

    fn append_ranked_connected(
        &self,
        candidates: &[RankedHub<'_>],
        connected: &[String],
        limit: usize,
    ) -> Vec<String> {
        let mut result = Vec::new();
        for candidate in candidates.iter().take(limit) {
            if let Some(peer) = self.connected_spelling(candidate.key, connected) {
                result.push(peer.to_string());
            }
        }
        result
    }

    fn root_or_connected_hubs(
        &self,
        self_key: &str,
        connected: &[String],
        limit: usize,
    ) -> Vec<String> {
        if let Some(root) = self.connected_spelling(signing::pubkey_part(&self.root), connected) {
            return vec![root.to_string()];
        }
        let candidate_limit = self.candidate_limit().min(limit.saturating_add(1));
        let candidates = self.ranked_connected_candidates(self_key, connected, candidate_limit);
        let mut result = Vec::with_capacity(limit.min(candidates.len()));
        for candidate in candidates {
            if candidate.key == signing::pubkey_part(self_key) {
                continue;
            }
            if let Some(peer) = self.connected_spelling(candidate.key, connected) {
                result.push(peer.to_string());
                if result.len() == limit {
                    break;
                }
            }
        }
        result
    }

    fn candidate_contains(&self, leaf: &str, hub: &str) -> bool {
        let hub = signing::pubkey_part(hub);
        let limit = self.candidate_limit();
        if limit == 0 {
            return false;
        }
        let target_score = rendezvous_score(signing::pubkey_part(leaf), hub);
        let mut rank = 0usize;
        let mut found = false;
        for configured in &self.hubs {
            let candidate = signing::pubkey_part(configured);
            if self.is_root(candidate) {
                continue;
            }
            if candidate == hub {
                found = true;
                continue;
            }
            let score = rendezvous_score(signing::pubkey_part(leaf), candidate);
            if score > target_score || (score == target_score && candidate < hub) {
                rank = rank.saturating_add(1);
                if rank >= limit {
                    return false;
                }
            }
        }
        found
    }
}

fn rendezvous_score(leaf: &str, hub: &str) -> u64 {
    #[cfg(test)]
    RENDEZVOUS_SCORE_CALLS.fetch_add(1, AtomicOrdering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(leaf.as_bytes());
    hasher.update(b":");
    hasher.update(hub.as_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"))
}

/// Return the next configured parent candidate in deterministic rendezvous
/// order. `after` is a cursor key, not an authority claim: the caller still
/// has to verify a current authenticated owner and obtain a ParentingState
/// relation/capacity ticket before sending an attach request. The scan keeps
/// only borrowed state and wraps once when the cursor reaches the end.
pub(crate) fn next_parent_candidate<'a>(
    root: &str,
    hubs: &'a [String],
    leaf: &str,
    after: Option<&str>,
) -> Option<&'a str> {
    let root = signing::pubkey_part(root);
    let leaf = signing::pubkey_part(leaf);
    let cursor_key = after.map(signing::pubkey_part);
    let cursor_score = cursor_key.map(|key| rendezvous_score(leaf, key));

    let mut best: Option<(&'a str, &str, u64)> = None;
    let mut best_after: Option<(&'a str, &str, u64)> = None;
    for configured in hubs {
        let key = signing::pubkey_part(configured);
        if key == root || key == leaf {
            continue;
        }
        let score = rendezvous_score(leaf, key);
        let candidate = (configured.as_str(), key, score);
        if best.is_none_or(|current| {
            rank_tuple_cmp(score, key, current.2, current.1) == Ordering::Less
        }) {
            best = Some(candidate);
        }
        if let (Some(cursor_key), Some(cursor_score)) = (cursor_key, cursor_score) {
            if rank_tuple_cmp(score, key, cursor_score, cursor_key) == Ordering::Greater
                && best_after.is_none_or(|current| {
                    rank_tuple_cmp(score, key, current.2, current.1) == Ordering::Less
                })
            {
                best_after = Some(candidate);
            }
        }
    }
    best_after.or(best).map(|candidate| candidate.0)
}

fn rank_tuple_cmp(left_score: u64, left_key: &str, right_score: u64, right_key: &str) -> Ordering {
    right_score
        .cmp(&left_score)
        .then_with(|| left_key.cmp(right_key))
}

#[cfg(test)]
static RENDEZVOUS_SCORE_CALLS: AtomicUsize = AtomicUsize::new(0);

impl Topology for HubTreeSelector {
    fn select_preferred(&self, self_id: &str, peer_ids: &[String]) -> HashSet<String> {
        let self_key = signing::pubkey_part(self_id);
        if self.is_root(self_key) {
            return peer_ids
                .iter()
                .filter(|peer| signing::pubkey_part(peer) != self_key && self.is_hub(peer))
                .cloned()
                .collect();
        }
        if self.is_hub(self_key) {
            return peer_ids
                .iter()
                .filter(|peer| {
                    let key = signing::pubkey_part(peer);
                    key != self_key
                        && (self.is_root(key)
                            || (!self.is_hub(key) && self.candidate_contains(key, self_key)))
                })
                .cloned()
                .collect();
        }
        let candidates = self.ranked_candidates(self_key, self.candidate_limit());
        peer_ids
            .iter()
            .filter(|peer| {
                let key = signing::pubkey_part(peer);
                key != self_key && candidates.iter().any(|candidate| candidate.key == key)
            })
            .cloned()
            .collect()
    }

    fn edge(&self, a: &str, b: &str, _all: &[String]) -> bool {
        let a_key = signing::pubkey_part(a);
        let b_key = signing::pubkey_part(b);
        if a_key == b_key {
            return false;
        }
        let a_root = self.is_root(a_key);
        let b_root = self.is_root(b_key);
        let a_hub = self.is_hub(a_key);
        let b_hub = self.is_hub(b_key);
        match (a_root, b_root, a_hub, b_hub) {
            (true, false, false, true) | (false, true, true, false) => true,
            (false, false, true, false) => self.candidate_contains(b_key, a_key),
            (false, false, false, true) => self.candidate_contains(a_key, b_key),
            _ => false,
        }
    }

    fn prunes(&self) -> bool {
        true
    }

    fn forwards(&self, self_id: &str, _all: &[String]) -> bool {
        self.is_root(self_id) || self.is_hub(self_id)
    }

    fn next_hops(
        &self,
        self_id: &str,
        dest: &str,
        connected: &[String],
        limit: usize,
    ) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let self_key = signing::pubkey_part(self_id);
        let dest_key = signing::pubkey_part(dest);
        if self_key == dest_key {
            return Vec::new();
        }
        let self_root = self.is_root(self_key);
        let self_hub = self.is_hub(self_key);
        let dest_root = self.is_root(dest_key);
        let dest_hub = self.is_hub(dest_key);

        if self_root {
            if dest_root {
                return Vec::new();
            }
            if dest_hub {
                return self.append_connected(&[dest_key.to_string()], connected, limit);
            }
            let candidates = self.ranked_connected_candidates(
                dest_key,
                connected,
                self.candidate_limit().min(limit),
            );
            return self.append_ranked_connected(&candidates, connected, limit);
        }

        if self_hub {
            if dest_root {
                return self.root_or_connected_hubs(self_key, connected, limit);
            }
            if !dest_hub && self.candidate_contains(dest_key, self_key) {
                if let Some(peer) = self.connected_spelling(dest_key, connected) {
                    return vec![peer.to_string()];
                }
            }
            return self.root_or_connected_hubs(self_key, connected, limit);
        }

        if dest_hub && self.candidate_contains(self_key, dest_key) {
            if let Some(peer) = self.connected_spelling(dest_key, connected) {
                return vec![peer.to_string()];
            }
        }
        let candidates = self.ranked_connected_candidates(
            self_key,
            connected,
            self.candidate_limit().min(limit),
        );
        self.append_ranked_connected(&candidates, connected, limit)
    }

    fn preferred_next_hop(
        &self,
        self_id: &str,
        _dest: &str,
        _connected: &[String],
        preferred_parent: &str,
    ) -> bool {
        let self_key = signing::pubkey_part(self_id);
        let parent_key = signing::pubkey_part(preferred_parent);
        if self_key == parent_key || self.is_root(self_key) {
            return false;
        }
        if self.is_hub(self_key) {
            return self.is_root(parent_key);
        }
        self.is_hub(parent_key)
    }

    fn flood_ttl(&self) -> u8 {
        4
    }
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

    fn key(seed: u64) -> String {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let signing_key = SigningKey::from_bytes(&bytes);
        BASE32_NOPAD
            .encode(signing_key.verifying_key().as_bytes())
            .to_lowercase()
    }

    #[test]
    fn root_hub_leaf_shape_has_no_peer_or_root_leaf_edges() {
        let root = key(1);
        let hubs = vec![key(2), key(3)];
        let selector = HubTreeSelector {
            root: root.clone(),
            hubs: hubs.clone(),
            backup_candidates: 1,
        };
        let leaf = key(4);
        let all = vec![root.clone(), hubs[0].clone(), hubs[1].clone(), leaf.clone()];
        assert!(selector.edge(&root, &hubs[0], &all));
        assert!(!selector.edge(&hubs[0], &hubs[1], &all));
        assert!(!selector.edge(&root, &leaf, &all));
        assert!(!selector.edge(&leaf, &leaf, &all));
        assert_eq!(
            hubs.iter()
                .filter(|hub| selector.edge(&leaf, hub, &all))
                .count(),
            2
        );
        assert_eq!(selector.flood_ttl(), 4);
    }

    #[test]
    fn next_hops_use_destination_candidates_at_root_and_root_at_hub() {
        let root = key(10);
        let hubs = vec![key(11), key(12), key(13)];
        let leaf = key(14);
        let selector = HubTreeSelector {
            root: root.clone(),
            hubs: hubs.clone(),
            backup_candidates: 1,
        };
        let root_hops = selector.next_hops(&root, &leaf, &hubs, 8);
        assert_eq!(root_hops.len(), 2);
        let hub_hops = selector.next_hops(&hubs[0], &key(99), &[root.clone()], 8);
        assert_eq!(hub_hops, vec![root.clone()]);
        let hub_alternatives = selector.next_hops(&hubs[0], &key(99), &hubs[1..], 2);
        assert!(!hub_alternatives.is_empty());
        assert!(hub_alternatives.iter().all(|peer| peer != &hubs[0]));
        assert!(selector.next_hops(&root, &leaf, &hubs, 0).is_empty());
    }

    #[test]
    fn parent_successor_matches_rendezvous_order_and_wraps() {
        let root = key(15);
        let hubs = vec![key(16), key(17), key(18), key(19)];
        let leaf = key(20);
        let first = next_parent_candidate(&root, &hubs, &leaf, None).expect("first parent");
        let second =
            next_parent_candidate(&root, &hubs, &leaf, Some(first)).expect("second parent");
        assert_ne!(first, second);
        assert_ne!(first, signing::pubkey_part(&leaf));
        assert_ne!(second, signing::pubkey_part(&leaf));

        let mut reference = hubs.iter().map(String::as_str).collect::<Vec<_>>();
        reference.sort_by(|left, right| {
            rank_tuple_cmp(
                rendezvous_score(&leaf, left),
                left,
                rendezvous_score(&leaf, right),
                right,
            )
        });
        let mut cursor = None;
        for expected in &reference {
            let next = next_parent_candidate(&root, &hubs, &leaf, cursor)
                .expect("every configured hub is visited");
            assert_eq!(next, *expected);
            cursor = Some(next);
        }
        assert_eq!(
            next_parent_candidate(&root, &hubs, &leaf, cursor),
            Some(first)
        );
    }

    #[test]
    fn single_parent_candidate_remains_retryable_after_wrap() {
        let root = key(21);
        let hubs = vec![key(22)];
        let leaf = key(23);
        let first = next_parent_candidate(&root, &hubs, &leaf, None).expect("single parent exists");
        assert_eq!(
            next_parent_candidate(&root, &hubs, &leaf, Some(first)),
            Some(first)
        );
    }

    #[test]
    fn preferred_parent_is_shape_checked_for_leaf_and_hub() {
        let root = key(31);
        let hubs = vec![key(32), key(33), key(34)];
        let leaf = key(35);
        let selector = HubTreeSelector {
            root: root.clone(),
            hubs: hubs.clone(),
            backup_candidates: 2,
        };
        let parent = next_parent_candidate(&root, &hubs, &leaf, None).expect("leaf parent");
        assert!(selector.preferred_next_hop(&leaf, "destination", &[], parent));
        assert!(!selector.preferred_next_hop(&leaf, "destination", &[], &root));
        assert!(!selector.preferred_next_hop(&leaf, "destination", &[], &leaf));
        assert!(selector.preferred_next_hop(&hubs[0], &leaf, &[], &root));
        assert!(!selector.preferred_next_hop(&root, &leaf, &[], &hubs[0]));
    }

    #[test]
    fn aliases_are_self_free_deduplicated_and_limit_bounded() {
        let root = key(30);
        let hubs = vec![key(31), key(32), key(33)];
        let selector = HubTreeSelector {
            root: root.clone(),
            hubs: hubs.clone(),
            backup_candidates: 2,
        };
        let root_alias = format!("{root}-abc12");
        let connected = vec![
            format!("{}-def34", hubs[0]),
            hubs[0].clone(),
            hubs[1].clone(),
            hubs[2].clone(),
        ];
        let hops = selector.next_hops(&root_alias, &key(34), &connected, 2);
        assert_eq!(hops.len(), 2);
        assert_eq!(
            hops.iter()
                .map(|peer| signing::pubkey_part(peer))
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            hops.len()
        );
        assert!(!selector.edge(&root, &root_alias, &connected));
        assert!(!selector
            .select_preferred(&root_alias, &connected)
            .contains(&root_alias));
    }

    #[test]
    fn five_thousand_member_primary_tree_is_bounded() {
        let root = key(20_000);
        let hubs: Vec<String> = (0..16).map(|index| key(21_000 + index)).collect();
        let leaves: Vec<String> = (0..4_983).map(|index| key(index)).collect();
        let selector = HubTreeSelector {
            root: root.clone(),
            hubs: hubs.clone(),
            backup_candidates: 0,
        };
        let mut members = vec![root.clone()];
        members.extend(hubs.iter().cloned());
        members.extend(leaves.iter().cloned());
        assert_eq!(members.len(), 5_000);
        let root_edges = hubs
            .iter()
            .filter(|hub| selector.edge(&root, hub, &members))
            .count();
        let leaf_edges = leaves
            .iter()
            .map(|leaf| {
                hubs.iter()
                    .filter(|hub| selector.edge(leaf, hub, &members))
                    .count()
            })
            .sum::<usize>();
        assert_eq!(root_edges + leaf_edges, 4_999);
        assert!(members
            .iter()
            .all(|member| !selector.edge(member, member, &members)));
    }

    #[test]
    fn five_thousand_member_planner_bounds_work_and_preserves_roster_order() {
        let root = key(30_000);
        let hubs: Vec<String> = (0..16).map(|index| key(31_000 + index)).collect();
        let leaves: Vec<String> = (0..4_983).map(|index| key(10_000 + index)).collect();
        let selector = HubTreeSelector {
            root: root.clone(),
            hubs: hubs.clone(),
            backup_candidates: 1,
        };
        let mut members = vec![root.clone()];
        members.extend(hubs.iter().cloned());
        members.extend(leaves.iter().cloned());
        let mut reversed = members.clone();
        reversed.reverse();

        RENDEZVOUS_SCORE_CALLS.store(0, AtomicOrdering::Relaxed);
        let preferred = selector.select_preferred(&leaves[0], &members);
        let work = RENDEZVOUS_SCORE_CALLS.load(AtomicOrdering::Relaxed);
        assert_eq!(preferred, selector.select_preferred(&leaves[0], &reversed));
        assert_eq!(preferred.len(), 2);
        assert!(
            work <= hubs.len(),
            "leaf selection scored beyond configured hubs"
        );

        let bounded = selector.ranked_candidates(&leaves[0], 2);
        assert_eq!(bounded.len(), 2);
        assert!(
            bounded.len() <= 2,
            "candidate retention exceeded caller limit"
        );
        let mut reference = hubs
            .iter()
            .map(|hub| RankedHub {
                score: rendezvous_score(&leaves[0], signing::pubkey_part(hub)),
                key: signing::pubkey_part(hub),
            })
            .collect::<Vec<_>>();
        reference.sort_by(HubTreeSelector::ranked_order);
        assert_eq!(
            bounded
                .iter()
                .map(|candidate| candidate.key)
                .collect::<Vec<_>>(),
            reference
                .iter()
                .take(2)
                .map(|candidate| candidate.key)
                .collect::<Vec<_>>()
        );

        RENDEZVOUS_SCORE_CALLS.store(0, AtomicOrdering::Relaxed);
        let hops = selector.next_hops(&root, &leaves[0], &members, 2);
        assert!(hops.len() <= 2);
        assert!(RENDEZVOUS_SCORE_CALLS.load(AtomicOrdering::Relaxed) <= hubs.len());

        let ranked = selector.ranked_candidates(&leaves[0], 2);
        let fallback_connected = ranked
            .get(1)
            .and_then(|candidate| {
                members
                    .iter()
                    .find(|member| signing::pubkey_part(member) == candidate.key)
            })
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(
            selector.next_hops(&root, &leaves[0], &fallback_connected, 2),
            fallback_connected
        );
        let all_ranked = selector.ranked_candidates(&leaves[0], hubs.len());
        let lower_only = all_ranked
            .get(2)
            .and_then(|candidate| {
                members
                    .iter()
                    .find(|member| signing::pubkey_part(member) == candidate.key)
            })
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(
            selector.next_hops(&root, &leaves[0], &lower_only, 2),
            lower_only,
            "a disconnected preferred prefix must not hide a connected lower candidate"
        );

        for member in members.iter().take(32) {
            assert_eq!(
                selector.edge(&root, member, &members),
                selector.edge(member, &root, &members),
                "tree edge selection must be symmetric"
            );
        }
    }
}
