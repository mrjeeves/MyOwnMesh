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

/// One ICE candidate pair's live connectivity-check counters, read
/// straight from the agent's `get_stats()`. This is the ground truth
/// for *why* a connection isn't forming — far more diagnostic than the
/// gathered-candidate counts in [`IceCandidateStats`], which only say
/// what was *tried*, not what's actually getting through.
///
/// The load-bearing fields are the STUN check counters:
/// - `requests_sent` climbing while `responses_received` stays `0`
///   means our connectivity checks are leaving the box but nothing is
///   coming back — UDP to this peer is being dropped (local firewall,
///   VPN capturing the subnet, or — on macOS — the app not having been
///   granted the Local Network privacy permission).
/// - `requests_received == 0` means the peer's checks aren't reaching
///   us either, so the block is bidirectional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcePairSnapshot {
    /// Local candidate, pre-rendered as `kind net addr:port`
    /// (e.g. `host udp4 192.168.1.50:54321`).
    pub local: String,
    /// Remote candidate, same `kind net addr:port` shape.
    pub remote: String,
    /// Pair check state: `waiting` / `in-progress` / `failed` /
    /// `succeeded` / `unspecified`.
    pub state: String,
    /// True once the agent has nominated this pair for traffic.
    pub nominated: bool,
    /// STUN binding requests we've sent on this pair.
    pub requests_sent: u64,
    /// Success responses we've received back for our requests. The
    /// number that matters: `requests_sent > 0, responses_received
    /// == 0` is the signature of a one-way / fully blocked path.
    pub responses_received: u64,
    /// STUN binding requests the peer has sent us (their checks
    /// reaching us).
    pub requests_received: u64,
    /// Success responses we've sent back to the peer.
    pub responses_sent: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
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

    pub fn total_requests_sent(&self) -> u64 {
        self.pairs.iter().map(|p| p.requests_sent).sum()
    }

    pub fn total_responses_received(&self) -> u64 {
        self.pairs.iter().map(|p| p.responses_received).sum()
    }

    pub fn total_requests_received(&self) -> u64 {
        self.pairs.iter().map(|p| p.requests_received).sum()
    }

    /// A plain-language read of the check counters — the one line that
    /// turns raw stats into "here's your problem". Ordered from
    /// success down through the failure modes the field actually hits.
    pub fn diagnosis(&self) -> &'static str {
        if self.succeeded_pairs() > 0 {
            return "at least one pair succeeded — connectivity exists on this path";
        }
        if self.remote_candidates.is_empty() {
            return "no remote candidates arrived — the peer's ICE candidates never reached us \
                    over signaling (signaling problem, not a network block)";
        }
        if self.pairs.is_empty() {
            return "candidates on both sides but no pairs formed yet — the agent has only just \
                    started, re-check in a few seconds";
        }
        let sent = self.total_requests_sent();
        let resp = self.total_responses_received();
        let inbound = self.total_requests_received();
        if sent == 0 {
            return "no connectivity checks sent yet — agent is still priming the checklist";
        }
        match (resp == 0, inbound == 0) {
            (true, true) => {
                "checks are leaving but NOTHING comes back and the peer's checks \
                             never reach us — UDP to this peer is being dropped in both \
                             directions (local firewall, VPN, or macOS Local Network permission \
                             not granted to this binary)"
            }
            (true, false) => {
                "the peer's checks reach us but ours get no response — one-way \
                              block: our outbound UDP isn't reaching the peer"
            }
            (false, true) => {
                "we get responses to our checks but see none of the peer's inbound \
                              checks — one-way block on the peer's side"
            }
            (false, false) => {
                "checks are flowing both ways but no pair is nominated yet — \
                               keep watching; if it never nominates the path is marginal"
            }
        }
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

    fn pair(state: &str, sent: u64, resp: u64, inbound: u64) -> IcePairSnapshot {
        IcePairSnapshot {
            local: "host udp4 192.168.1.50:54321".into(),
            remote: "host udp4 192.168.1.51:55001".into(),
            state: state.into(),
            nominated: false,
            requests_sent: sent,
            responses_received: resp,
            requests_received: inbound,
            responses_sent: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    #[test]
    fn diagnosis_flags_blocked_udp_when_checks_get_no_replies() {
        // Pairs formed, we're sending checks, but nothing comes back and
        // the peer's checks never reach us — the classic blocked-UDP
        // fingerprint (firewall / VPN / macOS Local Network permission).
        let snap = IceCheckSnapshot {
            local_candidates: vec!["host udp4 192.168.1.50:54321".into()],
            remote_candidates: vec!["host udp4 192.168.1.51:55001".into()],
            pairs: vec![pair("in-progress", 4, 0, 0)],
        };
        assert_eq!(snap.succeeded_pairs(), 0);
        assert_eq!(snap.total_requests_sent(), 4);
        assert!(
            snap.diagnosis().contains("both directions"),
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
    fn diagnosis_reports_success_when_a_pair_succeeds() {
        let snap = IceCheckSnapshot {
            local_candidates: vec!["host udp4 192.168.1.50:54321".into()],
            remote_candidates: vec!["host udp4 192.168.1.51:55001".into()],
            pairs: vec![pair("succeeded", 3, 3, 2)],
        };
        assert_eq!(snap.succeeded_pairs(), 1);
        assert!(
            snap.diagnosis().contains("connectivity exists"),
            "got: {}",
            snap.diagnosis()
        );
    }

    #[test]
    fn diagnosis_flags_one_way_block_when_only_our_checks_land() {
        // We hear the peer's checks but ours get no response: outbound
        // is blocked, inbound isn't.
        let snap = IceCheckSnapshot {
            local_candidates: vec!["host udp4 192.168.1.50:54321".into()],
            remote_candidates: vec!["host udp4 192.168.1.51:55001".into()],
            pairs: vec![pair("in-progress", 5, 0, 3)],
        };
        assert!(
            snap.diagnosis().contains("one-way"),
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
