//! Per-peer transport diagnostics. Counts ICE candidate types as
//! they're gathered locally and as they arrive from the peer; the
//! engine surfaces these via [`crate::events::DiagEntry`] so the
//! UI / CLI can show "we found 3 srflx, 0 relay; peer sent 2 host,
//! 1 srflx" — concrete enough to debug "ICE failed, no TURN
//! configured" without dumping raw SDP into the log.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IceCandidateKind {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
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
