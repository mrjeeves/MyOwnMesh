//! Full-mesh topology selector. Every peer is preferred; nobody gets
//! shelved. Intended for small fixed-size deployments where the N²
//! connection cost is acceptable.

use std::collections::HashSet;

use super::Topology;

#[derive(Debug, Clone, Copy, Default)]
pub struct FullMeshSelector;

impl Topology for FullMeshSelector {
    fn select_preferred(&self, _self_id: &str, peer_ids: &[String]) -> HashSet<String> {
        peer_ids.iter().cloned().collect()
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
}
