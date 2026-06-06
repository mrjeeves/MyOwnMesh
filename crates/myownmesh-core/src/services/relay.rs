//! Roster-gated frame relay. A device running the relay service
//! forwards [`RelayEnvelope`] frames it receives on [`RELAY_CHANNEL`]
//! to other roster members, so peers that can each reach the relay but
//! not each other still exchange messages — the device becomes a
//! router / ingress / egress hub for the network.
//!
//! The forwarder uses nothing beyond the core channel + roster + peer
//! snapshot APIs, so it lives in core and any embedder can host a relay
//! by constructing a [`RelayService`] over a joined network's state.
//! The daemon does exactly that for every joined network when
//! `services.relay.enabled` is set.
//!
//! Trust: forwarding is roster-gated on *both* ends. A frame is only
//! relayed when its sender is an approved peer of this device, and a
//! directed frame only reaches its destination when that destination is
//! also approved. The relay never forwards for or to strangers, and it
//! stamps the authenticated sender id into the forwarded envelope so the
//! recipient can trust the `src` field rather than the wire claim.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::channels::Channel;
use crate::engine::connection::PeerStatus;
use crate::engine::state::NetworkState;

/// Reserved channel name the relay listens on. Versioned so a future
/// envelope-shape change can run a second channel in parallel without a
/// flag day.
pub const RELAY_CHANNEL: &str = "__mesh_relay__/v1";

/// One relayed frame. A member wraps its real payload in this and sends
/// it to the relay on [`RELAY_CHANNEL`]; the relay rewrites `src`,
/// clears `dst`, and forwards to the resolved destination(s).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayEnvelope {
    /// Final recipient device id. Empty = broadcast to every other
    /// roster member the relay currently has reachable.
    #[serde(default)]
    pub dst: String,
    /// Origin device id. Senders may leave this empty; the relay stamps
    /// it from the authenticated channel `from` before forwarding so a
    /// recipient can trust it.
    #[serde(default)]
    pub src: String,
    /// Opaque application payload. The relay never inspects it.
    pub payload: serde_json::Value,
}

/// Decide who a single inbound relay frame should be forwarded to. Pure
/// function so the policy is unit-testable without a live mesh.
///
/// Rules:
///  - `from` must be a roster member (never relay for strangers).
///  - directed (`dst` set): forward iff `dst` is a roster member that
///    is currently reachable, and never reflect back to the sender.
///  - broadcast (`dst` empty): forward to every reachable roster member
///    except the sender, capped at `max_fanout` (0 = unlimited).
pub fn relay_targets(
    from: &str,
    dst: &str,
    rostered: &[String],
    reachable: &[String],
    max_fanout: u32,
) -> Vec<String> {
    let is_rostered = |id: &str| rostered.iter().any(|r| r == id);
    let is_reachable = |id: &str| reachable.iter().any(|a| a == id);

    // Never relay on behalf of a device we haven't approved.
    if !is_rostered(from) {
        return Vec::new();
    }

    if !dst.is_empty() {
        if dst != from && is_rostered(dst) && is_reachable(dst) {
            return vec![dst.to_string()];
        }
        return Vec::new();
    }

    let mut out: Vec<String> = reachable
        .iter()
        .filter(|id| id.as_str() != from && is_rostered(id))
        .cloned()
        .collect();
    if max_fanout > 0 && out.len() > max_fanout as usize {
        out.truncate(max_fanout as usize);
    }
    out
}

/// A peer is "reachable" for relay purposes when its data channel is
/// open — Active or Shelved. Shelved peers are demoted by the topology
/// selector but keep the channel open as a heartbeat path, so a relayed
/// frame still gets through.
fn is_reachable_status(status: PeerStatus) -> bool {
    matches!(status, PeerStatus::Active | PeerStatus::Shelved)
}

/// Running relay forwarder for one network. Holds the spawned task;
/// drop or call [`RelayService::stop`] to tear it down.
pub struct RelayService {
    task: tokio::task::JoinHandle<()>,
}

impl RelayService {
    /// Start forwarding on `state`'s network. `max_fanout` caps
    /// broadcast fan-out (0 = unlimited).
    pub fn start(state: Arc<NetworkState>, max_fanout: u32) -> RelayService {
        let task = tokio::spawn(run(state, max_fanout));
        RelayService { task }
    }

    /// Stop forwarding. The reserved channel subscription is dropped and
    /// the task exits.
    pub fn stop(self) {
        self.task.abort();
    }
}

impl Drop for RelayService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run(state: Arc<NetworkState>, max_fanout: u32) {
    let channel: Channel<RelayEnvelope> = Channel::new(RELAY_CHANNEL.to_string(), state.clone());
    let mut sub = channel.subscribe();
    debug!(network = %state.network_id, "relay service listening on {RELAY_CHANNEL}");
    while let Some(item) = sub.recv().await {
        let msg = match item {
            Ok(m) => m,
            Err(e) => {
                trace!("relay: dropping undecodable frame: {e}");
                continue;
            }
        };
        let from = msg.from;
        let env = msg.body;

        // Snapshot roster + reachable peers fresh per frame so a peer
        // that just left or was removed isn't relayed to.
        let rostered: Vec<String> = state
            .roster
            .read()
            .authorized_devices
            .iter()
            .map(|d| d.device_id.clone())
            .collect();
        let reachable: Vec<String> = state
            .peer_snapshot()
            .into_iter()
            .filter(|p| is_reachable_status(p.status))
            .map(|p| p.device_id)
            .collect();

        let targets = relay_targets(&from, &env.dst, &rostered, &reachable, max_fanout);
        if targets.is_empty() {
            trace!(%from, dst = %env.dst, "relay: no eligible targets");
            continue;
        }

        // Stamp the authenticated origin and clear dst so the recipient
        // sees a flat "from src" frame regardless of how it was
        // addressed.
        let out = RelayEnvelope {
            dst: String::new(),
            src: from.clone(),
            payload: env.payload,
        };
        for target in &targets {
            if let Err(e) = channel.send_to(target, &out).await {
                trace!(%target, "relay: forward failed: {e}");
            }
        }
        debug!(%from, count = targets.len(), "relay: forwarded frame");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn directed_forward_to_active_roster_member() {
        let targets = relay_targets("a", "c", &ids(&["a", "b", "c"]), &ids(&["a", "c"]), 0);
        assert_eq!(targets, ids(&["c"]));
    }

    #[test]
    fn directed_drops_when_dst_not_rostered() {
        let targets = relay_targets("a", "x", &ids(&["a", "c"]), &ids(&["a", "c", "x"]), 0);
        assert!(targets.is_empty());
    }

    #[test]
    fn directed_drops_when_dst_offline() {
        let targets = relay_targets("a", "c", &ids(&["a", "c"]), &ids(&["a"]), 0);
        assert!(targets.is_empty());
    }

    #[test]
    fn never_relays_for_stranger() {
        // Sender not in roster → nothing forwarded, even to valid dst.
        let targets = relay_targets("stranger", "c", &ids(&["a", "c"]), &ids(&["c"]), 0);
        assert!(targets.is_empty());
    }

    #[test]
    fn never_reflects_to_sender() {
        let targets = relay_targets("a", "a", &ids(&["a", "b"]), &ids(&["a", "b"]), 0);
        assert!(targets.is_empty());
    }

    #[test]
    fn broadcast_fans_out_to_other_members_only() {
        let mut targets = relay_targets(
            "a",
            "",
            &ids(&["a", "b", "c", "d"]),
            &ids(&["a", "b", "c"]), // d offline
            0,
        );
        targets.sort();
        assert_eq!(targets, ids(&["b", "c"]));
    }

    #[test]
    fn broadcast_excludes_non_rostered_reachable_peers() {
        // A reachable peer that isn't in the roster is not a broadcast
        // target — relay only serves approved members.
        let targets = relay_targets("a", "", &ids(&["a", "b"]), &ids(&["a", "b", "ghost"]), 0);
        assert_eq!(targets, ids(&["b"]));
    }

    #[test]
    fn broadcast_respects_max_fanout() {
        let targets = relay_targets(
            "a",
            "",
            &ids(&["a", "b", "c", "d", "e"]),
            &ids(&["a", "b", "c", "d", "e"]),
            2,
        );
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn envelope_round_trips_with_defaults() {
        // A sender can omit src and dst (broadcast).
        let raw = r#"{"payload":{"hi":1}}"#;
        let env: RelayEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.dst, "");
        assert_eq!(env.src, "");
        assert_eq!(env.payload, serde_json::json!({"hi": 1}));
    }
}
