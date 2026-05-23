//! Star topology selector. Every spoke keeps only the hub active;
//! the hub keeps every peer active.
//!
//! Star runs through the same shelving primitive as Ring/FullMesh.
//! Spokes' selectors return `{hub}` so every non-hub peer gets
//! shelved; the hub's selector returns the full peer set so nobody
//! gets shelved on its end. Determinism is trivial here — the hub
//! is fixed by config, no sort, no walk.
//!
//! Hub election is *not* automatic in v1: the hub Device ID is
//! named explicitly in [`crate::config::TopologyMode::Star`]. An
//! `AutoElect` variant (e.g. lex-greatest pubkey) can be added in
//! a follow-up if a network wants self-healing star.

use std::collections::HashSet;

use super::Topology;
use crate::identity::DeviceId;
use crate::signing;

#[derive(Debug, Clone)]
pub struct StarSelector {
    pub hub: DeviceId,
}

impl Topology for StarSelector {
    fn select_preferred(&self, self_id: &str, peer_ids: &[String]) -> HashSet<String> {
        let hub_pubkey = signing::pubkey_part(&self.hub);
        let self_pubkey = signing::pubkey_part(self_id);
        if self_pubkey == hub_pubkey {
            // We are the hub — everyone is preferred.
            return peer_ids.iter().cloned().collect();
        }
        // We are a spoke. If the hub is among our connected peers,
        // keep it active; if not, return the empty set so we shelve
        // everyone and wait for the hub to reappear. Compare by
        // pubkey-part so a peer presented in display form still
        // matches the config's hub id.
        peer_ids
            .iter()
            .filter(|p| signing::pubkey_part(p) == hub_pubkey)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn hub_keeps_everyone() {
        let sel = StarSelector { hub: "hub".into() };
        let peers = s(&["spoke1", "spoke2", "spoke3"]);
        let got = sel.select_preferred("hub", &peers);
        assert_eq!(got.len(), 3);
        for p in &peers {
            assert!(got.contains(p));
        }
    }

    #[test]
    fn spoke_keeps_only_hub() {
        let sel = StarSelector { hub: "hub".into() };
        let peers = s(&["hub", "spoke1", "spoke2"]);
        let got = sel.select_preferred("spoke3", &peers);
        assert_eq!(got, HashSet::from(["hub".into()]));
    }

    #[test]
    fn spoke_with_no_hub_in_peers_returns_empty() {
        let sel = StarSelector { hub: "hub".into() };
        let peers = s(&["spoke1", "spoke2"]);
        let got = sel.select_preferred("spoke3", &peers);
        assert!(got.is_empty());
    }

    #[test]
    fn hub_id_can_carry_display_suffix() {
        // Config stores the bare pubkey; a peer presented in display
        // form (pubkey-XXXXX) still matches because we strip on both
        // sides via signing::pubkey_part.
        let sel = StarSelector {
            hub: "hubpubkey".into(),
        };
        let peers = s(&["hubpubkey-AB123", "spoke1"]);
        let got = sel.select_preferred("spoke2", &peers);
        assert_eq!(got, HashSet::from(["hubpubkey-AB123".into()]));
    }
}
