//! Tier 6 — user-driven configuration edits. Decides, when the user
//! edits a network's config at runtime, whether the change can be
//! applied in place ([`apply_hot`]) or genuinely needs the transport
//! torn down and rebuilt ([`requires_restart`], orchestrated by the
//! bin's serve loop — the engine task stops cleanly via Shutdown).
//!
//! Why STUN/TURN are *not* a restart
//! ---------------------------------
//! A full restart drops every live peer, including healthy *direct*
//! WebRTC links. That's a sledgehammer for STUN/TURN: those servers
//! only matter while *gathering candidates for a new connection* —
//! an already-connected data channel never touches them again. And
//! [`super::ensure_peer_session`] reads `stun_servers` / `turn_servers`
//! fresh from `state.config` every time it opens a peer, so a hot
//! update reaches every *future* connection (and every reconnect)
//! without disturbing the ones already up. So a STUN/TURN edit —
//! including a venue rotating its time-limited TURN credentials, which
//! otherwise churned the link on every refresh — applies in place.
//!
//! What still needs a restart
//! --------------------------
//! - `network_id`: a different wire-level network entirely (different
//!   room, identity context) — nothing to preserve.
//! - `signaling`: the Nostr driver binds its relay set at start and has
//!   no in-place "switch relays" path (the bridge's outbound receiver is
//!   taken once), so changing relays means recreating the driver. Rare —
//!   venues keep a stable relay set and rotate only credentials.

use std::sync::Arc;

use crate::config::NetworkConfig;
use crate::error::Result;

use super::state::NetworkState;

/// Returns `true` when the new config differs from the current one in a
/// way that can't be applied to a running network — only `network_id`
/// (a different network) or `signaling` (the relay set the Nostr driver
/// is bound to). STUN/TURN, topology, label, roster, and auto-approve
/// are all applied in place by [`apply_hot`] without dropping peers.
pub fn requires_restart(current: &NetworkConfig, next: &NetworkConfig) -> bool {
    current.network_id != next.network_id || current.signaling != next.signaling
}

/// Apply the hot-reloadable subset of config without tearing down
/// sessions: STUN/TURN servers (picked up by the next connection),
/// topology, label, roster path, and auto-approve. Anything left to a
/// restart is gated by [`requires_restart`].
pub fn apply_hot(state: &Arc<NetworkState>, next: NetworkConfig) -> Result<()> {
    {
        let mut cfg = state.config.write();
        cfg.label = next.label;
        cfg.topology = next.topology.clone();
        cfg.auto_approve = next.auto_approve;
        cfg.roster_path = next.roster_path;
        // ICE servers are read fresh per `open_peer`, so updating them
        // here is enough — live peers keep their current connection and
        // the next connect/reconnect uses the new servers.
        cfg.stun_servers = next.stun_servers;
        cfg.turn_servers = next.turn_servers;
    }
    {
        let mut topo = state.topology.write();
        *topo = next.topology.clone();
    }
    {
        let mut sel = state.topology_impl.write();
        *sel = crate::topology::from_mode(&next.topology);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{StunServer, TurnServer};

    fn base_config() -> NetworkConfig {
        NetworkConfig::from_network_id("test-id", "test-net")
    }

    #[test]
    fn stun_turn_changes_do_not_require_restart() {
        let current = base_config();
        let mut next = current.clone();
        next.stun_servers = vec![StunServer {
            urls: vec!["stun:example.com:3478".into()],
        }];
        next.turn_servers = vec![TurnServer {
            urls: vec!["turn:example.com:3478".into()],
            username: Some("user".into()),
            credential: Some("rotated-secret".into()),
        }];
        assert!(
            !requires_restart(&current, &next),
            "STUN/TURN edits (incl. rotated credentials) must apply in place, not restart"
        );
    }

    #[test]
    fn signaling_and_network_id_changes_require_restart() {
        let current = base_config();

        let mut diff_net = current.clone();
        diff_net.network_id = "other-net".into();
        assert!(requires_restart(&current, &diff_net));

        let mut diff_sig = current.clone();
        diff_sig.signaling.servers = vec!["wss://relay.example.com".into()];
        assert!(requires_restart(&current, &diff_sig));
    }

    #[test]
    fn apply_hot_updates_ice_servers_in_place() {
        let state = super::super::build_test_state("reconcile-hot");
        let mut next = state.config.read().clone();
        next.turn_servers = vec![TurnServer {
            urls: vec!["turn:fresh.example.com:3478".into()],
            username: Some("user".into()),
            credential: Some("fresh-secret".into()),
        }];
        next.stun_servers = vec![StunServer {
            urls: vec!["stun:fresh.example.com:3478".into()],
        }];

        apply_hot(&state, next).expect("apply_hot");

        let cfg = state.config.read();
        assert_eq!(cfg.turn_servers.len(), 1);
        assert_eq!(
            cfg.turn_servers[0].credential.as_deref(),
            Some("fresh-secret")
        );
        assert_eq!(cfg.stun_servers[0].urls[0], "stun:fresh.example.com:3478");
    }
}
