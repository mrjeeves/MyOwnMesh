//! Per-peer transport diagnostics. Counts ICE candidate types as
//! they're gathered locally and as they arrive from the peer; the
//! engine surfaces these via [`crate::events::DiagEntry`] so the
//! UI / CLI can show "we found 3 srflx, 0 relay; peer sent 2 host,
//! 1 srflx" — concrete enough to debug "ICE failed, no TURN
//! configured" without dumping raw SDP into the log.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IceCandidateKind {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IceCandidateStats {
    pub host: u32,
    pub server_reflexive: u32,
    pub peer_reflexive: u32,
    pub relay: u32,
    pub unknown: u32,
}

impl IceCandidateStats {
    pub fn record(&mut self, kind: IceCandidateKind) {
        match kind {
            IceCandidateKind::Host => self.host += 1,
            IceCandidateKind::ServerReflexive => self.server_reflexive += 1,
            IceCandidateKind::PeerReflexive => self.peer_reflexive += 1,
            IceCandidateKind::Relay => self.relay += 1,
            IceCandidateKind::Unknown => self.unknown += 1,
        }
    }

    pub fn total(&self) -> u32 {
        self.host + self.server_reflexive + self.peer_reflexive + self.relay + self.unknown
    }
}

/// The ICE candidate pair the agent ultimately picked for sending
/// packets. Authoritative classification of how a peer's data is
/// actually flowing — host↔host is LAN, anything with a relay is
/// TURN, anything else (srflx / prflx involved) is STUN. Populated
/// from `RTCIceTransport::get_selected_candidate_pair` once ICE
/// reaches Connected/Completed; remains `None` until then.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedCandidatePair {
    pub local: IceCandidateKind,
    pub remote: IceCandidateKind,
}

/// One ICE candidate pair's live state, read from the agent's
/// `get_stats()`. This is the ground truth for *why* a connection isn't
/// forming.
///
/// IMPORTANT — only [`state`](Self::state) and [`nominated`](Self::nominated)
/// are real. webrtc-ice 0.13's `get_candidate_pairs_stats` builds every
/// other field (the STUN request/response counters, byte counters) from
/// `..Default::default()` — they are hard-wired to `0` and never updated,
/// no matter how much traffic a pair carries. We deliberately do **not**
/// carry those dead counters here: a snapshot that printed `sent→0 resp←0`
/// on a nominated pair that had been streaming for minutes was actively
/// misleading (it read as "no checks sent" when checks had plainly
/// succeeded). The pair `state` machine and the `nominated` flag are
/// maintained correctly, so the diagnosis below is built only on those.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcePairSnapshot {
    /// Local candidate, pre-rendered as `kind net addr:port`
    /// (e.g. `host udp4 192.168.1.50:54321`).
    pub local: String,
    /// Remote candidate, same `kind net addr:port` shape.
    pub remote: String,
    /// Pair check state: `waiting` / `in-progress` / `failed` /
    /// `succeeded` / `unspecified`. Maintained correctly by webrtc-ice.
    pub state: String,
    /// True once the agent has nominated this pair for traffic.
    /// Maintained correctly by webrtc-ice.
    pub nominated: bool,
}

/// A full, point-in-time snapshot of a peer connection's ICE
/// connectivity checks. Captured from `PeerSession::ice_check_snapshot`
/// at any point in the lifecycle (unlike [`SelectedCandidatePair`],
/// which only resolves once ICE is Connected) so the engine can log
/// *why* a peer is stuck in Checking or just went to Failed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IceCheckSnapshot {
    /// Every local candidate the agent currently holds, `kind net
    /// addr:port` each. Lets the user confirm we actually gathered a
    /// LAN address and see exactly which one.
    pub local_candidates: Vec<String>,
    /// Every remote candidate the peer sent us. If this is empty the
    /// peer's candidates never arrived over signaling — a different
    /// failure (signaling) than checks-not-getting-through (network).
    pub remote_candidates: Vec<String>,
    /// Every candidate pair the agent formed, with check counters.
    pub pairs: Vec<IcePairSnapshot>,
}

impl IceCheckSnapshot {
    /// Nothing to report — no candidates either side, no pairs. The
    /// engine skips logging in this case (the agent hasn't done
    /// anything worth showing yet).
    pub fn is_empty(&self) -> bool {
        self.local_candidates.is_empty()
            && self.remote_candidates.is_empty()
            && self.pairs.is_empty()
    }

    pub fn succeeded_pairs(&self) -> usize {
        self.pairs.iter().filter(|p| p.state == "succeeded").count()
    }

    /// True once any pair is both nominated and succeeded — the path is
    /// up and the agent has picked it.
    pub fn has_nominated_pair(&self) -> bool {
        self.pairs
            .iter()
            .any(|p| p.nominated && p.state == "succeeded")
    }

    /// A plain-language read of the pair states — the one line that turns
    /// raw stats into "here's your problem". Built only on the fields
    /// webrtc-ice actually maintains (`state`, `nominated`); see the note
    /// on [`IcePairSnapshot`] for why the STUN counters are unusable.
    /// Ordered from success down through the failure modes.
    pub fn diagnosis(&self) -> &'static str {
        if self.has_nominated_pair() {
            return "a pair is nominated and succeeded — the path is up";
        }
        if self.succeeded_pairs() > 0 {
            // The decisive case for the flap: connectivity exists (pairs
            // pass their checks) but nothing is nominated yet. On the
            // controlled (answerer) side this means we're waiting on the
            // controlling peer to send USE-CANDIDATE — tearing the agent
            // down now (and rebuilding) just restarts this race.
            return "pairs are succeeding but none is nominated yet — connectivity exists; \
                    waiting on the controlling side to nominate (don't tear down)";
        }
        if self.remote_candidates.is_empty() {
            return "no remote candidates arrived — the peer's ICE candidates never reached us \
                    over signaling (signaling problem, not a network block)";
        }
        if self.pairs.is_empty() {
            return "candidates on both sides but no pairs formed yet — the agent has only just \
                    started, re-check in a few seconds";
        }
        if self.pairs.iter().all(|p| p.state == "failed") {
            return "every candidate pair failed its connectivity check — no usable path between \
                    these address sets (symmetric NAT with no working relay, or UDP blocked)";
        }
        "connectivity checks still in progress — no pair has succeeded yet"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerDiag {
    pub local_candidates: IceCandidateStats,
    pub remote_candidates: IceCandidateStats,
    /// Count of ICE state transitions observed (any direction).
    /// Surfacing this distinguishes a single brief blip ("ICE
    /// disconnected once, recovered") from a flapping connection
    /// ("ICE disconnected 14 times in 90 s").
    pub ice_transitions: u32,
    /// Number of times the engine called `restart_ice()` on this
    /// peer's connection.
    pub ice_restarts: u32,
    /// Number of hello frames sent to this peer (incremented per
    /// send, not per handshake — multiple retries within one
    /// handshake count separately).
    pub hellos_sent: u32,
    /// Total bytes received over the data channel.
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub frames_in: u64,
    pub frames_out: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(state: &str, nominated: bool) -> IcePairSnapshot {
        IcePairSnapshot {
            local: "host udp4 192.168.1.50:54321".into(),
            remote: "host udp4 192.168.1.51:55001".into(),
            state: state.into(),
            nominated,
        }
    }

    #[test]
    fn diagnosis_flags_all_pairs_failed_as_no_usable_path() {
        // Every formed pair failed its connectivity check — no usable
        // path between the two address sets.
        let snap = IceCheckSnapshot {
            local_candidates: vec!["host udp4 192.168.1.50:54321".into()],
            remote_candidates: vec!["host udp4 192.168.1.51:55001".into()],
            pairs: vec![pair("failed", false), pair("failed", false)],
        };
        assert_eq!(snap.succeeded_pairs(), 0);
        assert!(
            snap.diagnosis().contains("no usable path"),
            "got: {}",
            snap.diagnosis()
        );
    }

    #[test]
    fn diagnosis_points_at_signaling_when_no_remote_candidates() {
        let snap = IceCheckSnapshot {
            local_candidates: vec!["host udp4 192.168.1.50:54321".into()],
            remote_candidates: vec![],
            pairs: vec![],
        };
        assert!(
            snap.diagnosis().contains("never reached us"),
            "got: {}",
            snap.diagnosis()
        );
    }

    #[test]
    fn diagnosis_flags_succeeded_but_unnominated_as_awaiting_nomination() {
        // The decisive flap case: a pair passes its check but nothing is
        // nominated yet. Must read as "don't tear down".
        let snap = IceCheckSnapshot {
            local_candidates: vec!["host udp4 192.168.1.50:54321".into()],
            remote_candidates: vec!["host udp4 192.168.1.51:55001".into()],
            pairs: vec![pair("succeeded", false), pair("failed", false)],
        };
        assert_eq!(snap.succeeded_pairs(), 1);
        assert!(!snap.has_nominated_pair());
        assert!(
            snap.diagnosis().contains("waiting on the controlling side"),
            "got: {}",
            snap.diagnosis()
        );
    }

    #[test]
    fn diagnosis_reports_up_when_a_pair_is_nominated_and_succeeded() {
        let snap = IceCheckSnapshot {
            local_candidates: vec!["host udp4 192.168.1.50:54321".into()],
            remote_candidates: vec!["host udp4 192.168.1.51:55001".into()],
            pairs: vec![pair("succeeded", true)],
        };
        assert!(snap.has_nominated_pair());
        assert!(
            snap.diagnosis().contains("the path is up"),
            "got: {}",
            snap.diagnosis()
        );
    }

    #[test]
    fn diagnosis_reports_in_progress_when_checks_still_running() {
        let snap = IceCheckSnapshot {
            local_candidates: vec!["host udp4 192.168.1.50:54321".into()],
            remote_candidates: vec!["host udp4 192.168.1.51:55001".into()],
            pairs: vec![pair("in-progress", false), pair("waiting", false)],
        };
        assert!(
            snap.diagnosis().contains("still in progress"),
            "got: {}",
            snap.diagnosis()
        );
    }

    #[test]
    fn empty_snapshot_is_empty() {
        assert!(IceCheckSnapshot::default().is_empty());
    }

    #[test]
    fn stats_count_each_kind() {
        let mut s = IceCandidateStats::default();
        s.record(IceCandidateKind::Host);
        s.record(IceCandidateKind::Host);
        s.record(IceCandidateKind::ServerReflexive);
        s.record(IceCandidateKind::Relay);
        s.record(IceCandidateKind::Unknown);
        assert_eq!(s.host, 2);
        assert_eq!(s.server_reflexive, 1);
        assert_eq!(s.relay, 1);
        assert_eq!(s.unknown, 1);
        assert_eq!(s.total(), 5);
    }
}
