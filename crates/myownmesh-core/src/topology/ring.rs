//! Ring topology selector. Verbatim port of `selectRingNeighbors`
//! from MyOwnLLM's `src/mesh-protocol.ts` (line 1135).
//!
//! Selection rule: sort peers lexicographically as a ring, take the
//! two immediate ring-neighbors (one in each direction) plus
//! (n_preferred − 2) lexically-closest non-neighbors. Deterministic
//! so both sides agree on who's in vs. out without needing extra
//! coordination.
//!
//! Capacity below `n_preferred` is treated as "give me everyone I
//! can reach" — a 2-peer mesh has both sides keep each other on,
//! shelving is a non-event.

use std::collections::{BTreeSet, HashSet};

use super::Topology;
use crate::signing;

#[derive(Debug, Clone, Copy)]
pub struct RingSelector {
    pub n_preferred: u32,
}

impl Default for RingSelector {
    fn default() -> Self {
        Self { n_preferred: 3 }
    }
}

impl Topology for RingSelector {
    fn select_preferred(&self, self_id: &str, peer_ids: &[String]) -> HashSet<String> {
        select_ring_neighbors(self_id, peer_ids, self.n_preferred)
    }

    fn edge(&self, a: &str, b: &str, all: &[String]) -> bool {
        // An edge exists when either side would prefer the other —
        // the union keeps one-way shortcuts connected (shelving stays
        // per-direction, exactly as before). Each side's preferred set
        // is computed over the full known membership minus itself, so
        // both nodes evaluate the same function on the same inputs.
        let others = |me: &str| -> Vec<String> {
            let mut v: Vec<String> = all.iter().filter(|x| x.as_str() != me).cloned().collect();
            for extra in [a, b] {
                if extra != me && !v.iter().any(|x| x == extra) {
                    v.push(extra.to_string());
                }
            }
            v
        };
        select_ring_neighbors(a, &others(a), self.n_preferred).contains(b)
            || select_ring_neighbors(b, &others(b), self.n_preferred).contains(a)
    }

    fn prunes(&self) -> bool {
        true
    }

    fn forwards(&self, _self_id: &str, _all: &[String]) -> bool {
        // Everyone forwards on a ring — that's what closes it.
        true
    }

    fn next_hops(&self, self_id: &str, dest: &str, connected: &[String]) -> Vec<String> {
        // Greedy ring routing: hand the frame to the connected peer
        // lexicographically closest to the destination (the ring is
        // the sorted id space). The per-node dedup ring and the TTL
        // make transient disagreement safe.
        let mut best: Option<(usize, &String)> = None;
        for c in connected {
            if signing::pubkey_part(c) == signing::pubkey_part(self_id) {
                continue;
            }
            let d = ring_distance(signing::pubkey_part(c), signing::pubkey_part(dest));
            if best.map(|(bd, _)| d < bd).unwrap_or(true) {
                best = Some((d, c));
            }
        }
        best.map(|(_, c)| vec![c.clone()]).unwrap_or_default()
    }

    fn flood_ttl(&self) -> u8 {
        // Half a large ring; dedup terminates the flood well before
        // this on any realistic membership.
        32
    }
}

/// A cheap, total order-distance between two ids in the sorted id
/// space: byte-wise common-prefix inversion. Not a metric — just a
/// deterministic "closer in the ring order" comparator for greedy
/// forwarding.
fn ring_distance(a: &str, b: &str) -> usize {
    let common = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
    let max_len = a.len().max(b.len()).max(1);
    max_len - common.min(max_len)
}

/// The pure algorithm, exposed for direct testing and reuse.
pub fn select_ring_neighbors(
    self_pubkey: &str,
    peer_pubkeys: &[String],
    n_preferred: u32,
) -> HashSet<String> {
    let n = n_preferred as usize;
    if peer_pubkeys.is_empty() {
        return HashSet::new();
    }
    if peer_pubkeys.len() <= n {
        // Below capacity — every peer stays preferred. Saves a sort
        // and avoids the noise of shelving people when there's no
        // reason to.
        return peer_pubkeys.iter().cloned().collect();
    }
    // Insert self into the ring so we can compute "the two on either
    // side of me". Sort lexicographically; pubkeys are deterministic
    // strings so this gives the same order on every node, which is
    // what makes the selection symmetric (both ends pick each other).
    let mut ring_set: BTreeSet<&str> = peer_pubkeys.iter().map(|s| s.as_str()).collect();
    ring_set.insert(self_pubkey);
    let ring: Vec<&str> = ring_set.into_iter().collect();
    let my_idx = ring
        .iter()
        .position(|s| *s == self_pubkey)
        .expect("self in ring after insert");
    let ring_len = ring.len();
    let mut preferred: HashSet<String> = HashSet::new();
    // The two ring-neighbors (clockwise + counterclockwise). Modulo
    // arithmetic so the ends of the ring wrap around to each other —
    // a 5-node ring [a,b,c,d,e] has `a`'s neighbors be `b` and `e`.
    if ring_len > 1 {
        preferred.insert(ring[(my_idx + 1) % ring_len].to_string());
        preferred.insert(ring[(my_idx + ring_len - 1) % ring_len].to_string());
    }
    // Fill up to `n` with the lexically-closest non-neighbor peers.
    // "Closest" is by ring distance to self_pubkey — we walk outward
    // from our position. Could pick by hardware capacity in a
    // follow-up, but the lex-distance heuristic gives stable
    // shortcuts that don't churn as peers ping in/out.
    let mut dist: usize = 2;
    while preferred.len() < n && dist < ring_len {
        let cw = ring[(my_idx + dist) % ring_len];
        if cw != self_pubkey && !preferred.contains(cw) {
            preferred.insert(cw.to_string());
            if preferred.len() >= n {
                break;
            }
        }
        let ccw = ring[(my_idx + ring_len - dist) % ring_len];
        if ccw != self_pubkey && !preferred.contains(ccw) {
            preferred.insert(ccw.to_string());
        }
        dist += 1;
    }
    preferred
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_peer_list_returns_empty() {
        let got = select_ring_neighbors("self", &[], 3);
        assert!(got.is_empty());
    }

    #[test]
    fn below_capacity_returns_everyone() {
        // With 2 peers and n_preferred=3, everyone is preferred.
        let got = select_ring_neighbors("self", &s(&["a", "b"]), 3);
        assert_eq!(got, HashSet::from(["a".into(), "b".into()]));
    }

    #[test]
    fn five_node_ring_picks_neighbors_plus_shortcut() {
        // Ring after sort with self="a": [a, b, c, d, e]
        // a's neighbors are b (cw) and e (ccw); shortcut is c (next
        // closest cw at dist=2).
        let peers = s(&["b", "c", "d", "e"]);
        let got = select_ring_neighbors("a", &peers, 3);
        assert!(got.contains("b"), "got: {got:?}");
        assert!(got.contains("e"), "got: {got:?}");
        // Third slot is filled by the next outward walk. The
        // algorithm tries cw at dist=2 ("c") first; that fills the
        // set and the loop exits.
        assert_eq!(got.len(), 3);
        assert!(got.contains("c") || got.contains("d"), "got: {got:?}");
    }

    #[test]
    fn immediate_ring_neighbors_are_reciprocal() {
        // The two immediate ring neighbors (clockwise + counterclockwise)
        // are always reciprocal — that's what closes the ring. Shortcuts
        // (any pick at dist >= 2) may NOT be reciprocal: each peer walks
        // outward from its own position, so e.g. `alice` may pick `carol`
        // as a shortcut while `carol` reaches capacity on `eve` first
        // and never picks `alice` back. The engine accepts this
        // asymmetry: shelving is per-direction, so a one-way preference
        // simply means traffic flows one way.
        let all = ["alice", "bob", "carol", "dave", "eve"];
        let mut sorted = all.to_vec();
        sorted.sort();

        let preferred: std::collections::HashMap<&str, HashSet<String>> = all
            .iter()
            .map(|&node| {
                let others: Vec<String> = all
                    .iter()
                    .filter(|&&x| x != node)
                    .map(|x| x.to_string())
                    .collect();
                (node, select_ring_neighbors(node, &others, 3))
            })
            .collect();

        for (i, &node) in sorted.iter().enumerate() {
            let cw = sorted[(i + 1) % sorted.len()];
            let ccw = sorted[(i + sorted.len() - 1) % sorted.len()];
            let picks = &preferred[node];
            assert!(
                picks.contains(cw),
                "{node} must pick CW neighbor {cw} (got {picks:?})"
            );
            assert!(
                picks.contains(ccw),
                "{node} must pick CCW neighbor {ccw} (got {picks:?})"
            );
        }
    }

    #[test]
    fn shortcut_asymmetry_is_expected() {
        // Concrete witness that shortcuts may be one-way: in the 5-node
        // sorted ring [alice, bob, carol, dave, eve] with n=3, alice
        // picks carol as her shortcut (dist=2 CW), but carol's own
        // walk fills her shortcut slot with eve (dist=2 CW from
        // carol). The engine handles this — shelving is per-peer
        // per-direction — so the asymmetry is benign.
        let all = ["alice", "bob", "carol", "dave", "eve"];
        let other = |me: &str| -> Vec<String> {
            all.iter()
                .filter(|&&x| x != me)
                .map(|x| x.to_string())
                .collect()
        };
        let alice = select_ring_neighbors("alice", &other("alice"), 3);
        let carol = select_ring_neighbors("carol", &other("carol"), 3);
        assert!(
            alice.contains("carol"),
            "alice should pick carol; got {alice:?}"
        );
        assert!(
            !carol.contains("alice"),
            "carol should NOT pick alice; got {carol:?}"
        );
    }

    #[test]
    fn edge_is_symmetric_and_covers_ring_neighbors() {
        let sel = RingSelector { n_preferred: 3 };
        let all: Vec<String> = ["alice", "bob", "carol", "dave", "eve", "frank"]
            .iter()
            .map(|x| x.to_string())
            .collect();
        for a in &all {
            for b in &all {
                if a == b {
                    continue;
                }
                assert_eq!(
                    sel.edge(a, b, &all),
                    sel.edge(b, a, &all),
                    "edge({a},{b}) must be symmetric"
                );
            }
        }
        // Immediate sorted-ring neighbors always hold an edge.
        let mut sorted = all.clone();
        sorted.sort();
        for i in 0..sorted.len() {
            let next = &sorted[(i + 1) % sorted.len()];
            assert!(
                sel.edge(&sorted[i], next, &all),
                "ring neighbors {} and {next} must share an edge",
                sorted[i]
            );
        }
        assert!(sel.prunes());
        assert!(sel.forwards("alice", &all));
    }

    #[test]
    fn next_hops_picks_the_connected_peer_nearest_the_destination() {
        let sel = RingSelector { n_preferred: 3 };
        let connected: Vec<String> = ["bbbb", "cccc"].iter().map(|x| x.to_string()).collect();
        let hops = sel.next_hops("aaaa", "cccd", &connected);
        assert_eq!(hops, vec!["cccc".to_string()]);
        assert!(sel.next_hops("aaaa", "zzzz", &[]).is_empty());
    }

    #[test]
    fn deterministic_across_runs() {
        let peers = s(&["b", "c", "d", "e", "f", "g", "h"]);
        let r1 = select_ring_neighbors("a", &peers, 3);
        let r2 = select_ring_neighbors("a", &peers, 3);
        assert_eq!(r1, r2);
    }

    #[test]
    fn input_order_does_not_matter() {
        let r1 = select_ring_neighbors("a", &s(&["b", "c", "d", "e", "f"]), 3);
        let r2 = select_ring_neighbors("a", &s(&["f", "e", "d", "c", "b"]), 3);
        assert_eq!(r1, r2);
    }
}
