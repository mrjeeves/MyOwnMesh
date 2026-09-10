//! Full-mesh topology selector. Every peer is preferred; nobody gets
//! shelved. Intended for small fixed-size deployments where the N²
//! connection cost is acceptable.

use std::collections::HashSet;

use super::Topology;
use crate::signing;

#[derive(Debug, Clone, Copy, Default)]
pub struct FullMeshSelector;

impl Topology for FullMeshSelector {
    fn select_preferred(&self, _self_id: &str, peer_ids: &[String]) -> HashSet<String> {
        peer_ids.iter().cloned().collect()
    }

    fn next_hops(
        &self,
        self_id: &str,
        dest: &str,
        connected: &[String],
        limit: usize,
    ) -> Vec<String> {
        // Full mesh has no forwarding redundancy: an indirect route would
        // contradict its direct-edge contract. Return the destination only
        // when it is actually connected, preserving the trait's direct-route
        // semantics while refusing guesses and duplicate observations.  The
        // bounded form deliberately scans once and retains only the canonical
        // observation, rather than materializing an unbounded key map.
        if limit == 0 {
            return Vec::new();
        }
        let self_key = signing::pubkey_part(self_id);
        let dest_key = signing::pubkey_part(dest);
        if self_key == dest_key {
            return Vec::new();
        }
        let mut selected = None;
        for peer in connected {
            let key = signing::pubkey_part(peer);
            if key == self_key || key != dest_key {
                continue;
            }
            if selected
                .as_ref()
                .is_none_or(|current: &String| peer.as_str() < current.as_str())
            {
                selected = Some(peer.clone());
            }
        }
        selected.into_iter().take(limit).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_every_peer() {
        let sel = FullMeshSelector;
        let peers: Vec<String> = (0..10).map(|i| format!("peer{i}")).collect();
        let got = sel.select_preferred("self", &peers);
        assert_eq!(got.len(), peers.len());
        for p in &peers {
            assert!(got.contains(p));
        }
    }

    #[test]
    fn empty_peer_list_returns_empty() {
        let sel = FullMeshSelector;
        let got = sel.select_preferred("self", &[]);
        assert!(got.is_empty());
    }

    #[test]
    fn next_hops_only_returns_an_observed_direct_peer() {
        let sel = FullMeshSelector;
        let connected: Vec<String> = ["peer-a", "peer-a", "self"]
            .iter()
            .map(|peer| (*peer).into())
            .collect();
        assert_eq!(
            sel.next_hops("self", "peer-a", &connected, 1),
            vec!["peer-a".to_string()]
        );
        assert!(sel.next_hops("self", "peer-b", &connected, 1).is_empty());
        assert!(sel.next_hops("self", "self", &connected, 1).is_empty());
    }

    #[test]
    fn bounded_next_hops_refuses_zero_and_deduplicates_large_input() {
        let sel = FullMeshSelector;
        let connected: Vec<String> = std::iter::once("peer-a".to_string())
            .chain(std::iter::repeat_n("peer-a".to_string(), 100_000))
            .chain(std::iter::once("self".to_string()))
            .collect();
        assert!(sel.next_hops("self", "peer-a", &connected, 0).is_empty());
        assert_eq!(
            sel.next_hops("self", "peer-a", &connected, usize::MAX),
            vec!["peer-a".to_string()]
        );
    }
}
