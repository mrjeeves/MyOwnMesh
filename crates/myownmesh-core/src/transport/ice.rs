//! ICE configuration helpers and candidate-type classification.
//!
//! Maps the user's `config.json` STUN / TURN entries into the
//! webrtc-rs `RTCConfiguration` shape, and classifies inbound ICE
//! candidate SDP lines so the diagnostics layer can report "we
//! found N srflx, 0 relay" — a load-bearing hint when a connection
//! is failing because TURN isn't configured.

use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;

use crate::config::{StunServer, TurnServer};

/// The transport-only identity and metadata used when ordering candidate
/// paths.  `id` is an opaque caller-owned path handle; no application data or
/// data-channel capability is carried by this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IceCandidatePath {
    pub id: u64,
    pub local: super::diag::IceCandidateKind,
    pub remote: super::diag::IceCandidateKind,
    pub priority: u32,
}

impl IceCandidatePath {
    pub const fn new(
        id: u64,
        local: super::diag::IceCandidateKind,
        remote: super::diag::IceCandidateKind,
        priority: u32,
    ) -> Self {
        Self {
            id,
            local,
            remote,
            priority,
        }
    }
}

/// A deterministic transport preference for a candidate pair.  Direct paths
/// are preferred, while reflexive and relay paths remain eligible fallbacks.
/// The score is only a tie-breaker after the caller-provided ICE priority.
pub fn candidate_path_preference(
    local: super::diag::IceCandidateKind,
    remote: super::diag::IceCandidateKind,
) -> u8 {
    use super::diag::IceCandidateKind as Kind;

    match (local, remote) {
        (Kind::Host, Kind::Host) => 5,
        (Kind::Host, Kind::ServerReflexive)
        | (Kind::ServerReflexive, Kind::Host)
        | (Kind::ServerReflexive, Kind::ServerReflexive) => 4,
        (Kind::PeerReflexive, Kind::Host)
        | (Kind::Host, Kind::PeerReflexive)
        | (Kind::PeerReflexive, Kind::ServerReflexive)
        | (Kind::ServerReflexive, Kind::PeerReflexive)
        | (Kind::PeerReflexive, Kind::PeerReflexive) => 3,
        (Kind::Relay, _) | (_, Kind::Relay) => 2,
        _ => 1,
    }
}

/// Sort candidate paths by the caller's ICE priority, then by the stable
/// transport preference, then by opaque path ID.  The final key makes equal
/// priority/path-kind inputs deterministic across runs and runtimes.
pub fn rank_candidate_paths(paths: &mut [IceCandidatePath]) {
    paths.sort_unstable_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| {
                candidate_path_preference(right.local, right.remote)
                    .cmp(&candidate_path_preference(left.local, left.remote))
            })
            .then_with(|| left.id.cmp(&right.id))
    });
}

/// Build the webrtc-rs [`RTCConfiguration`] from our user-facing
/// config. ICE candidate pool size is left at the default; the
/// engine's own offer-pool-flush-on-drop policy handles refreshing
/// candidates after a network change.
pub fn build_rtc_configuration(
    stun_servers: &[StunServer],
    turn_servers: &[TurnServer],
) -> RTCConfiguration {
    let mut ice_servers: Vec<RTCIceServer> = Vec::new();

    for s in stun_servers {
        if s.urls.is_empty() {
            continue;
        }
        ice_servers.push(RTCIceServer {
            urls: s.urls.clone(),
            ..Default::default()
        });
    }

    for t in turn_servers {
        if t.urls.is_empty() {
            continue;
        }
        let server = RTCIceServer {
            urls: t.urls.clone(),
            username: t.username.clone().unwrap_or_default(),
            credential: t.credential.clone().unwrap_or_default(),
        };
        ice_servers.push(server);
    }

    RTCConfiguration {
        ice_servers,
        ..Default::default()
    }
}

/// Coarse classification of an ICE candidate from its SDP text.
/// The SDP candidate line is space-separated and the type is
/// always in position 7 after `typ`. We strip-and-tokenize rather
/// than depend on a full SDP parser — the failure mode is
/// returning `Unknown`, which is acceptable for diagnostics.
pub fn classify_candidate_sdp(sdp: &str) -> super::diag::IceCandidateKind {
    use super::diag::IceCandidateKind;
    let mut tokens = sdp.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "typ" {
            return match tokens.next() {
                Some("host") => IceCandidateKind::Host,
                Some("srflx") => IceCandidateKind::ServerReflexive,
                Some("prflx") => IceCandidateKind::PeerReflexive,
                Some("relay") => IceCandidateKind::Relay,
                _ => IceCandidateKind::Unknown,
            };
        }
    }
    IceCandidateKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::diag::IceCandidateKind;

    #[test]
    fn empty_config_produces_no_servers() {
        let cfg = build_rtc_configuration(&[], &[]);
        assert!(cfg.ice_servers.is_empty());
    }

    #[test]
    fn stun_servers_are_added() {
        let stun = vec![StunServer {
            urls: vec!["stun:stun.l.google.com:19302".into()],
        }];
        let cfg = build_rtc_configuration(&stun, &[]);
        assert_eq!(cfg.ice_servers.len(), 1);
        assert_eq!(
            cfg.ice_servers[0].urls,
            vec!["stun:stun.l.google.com:19302".to_string()]
        );
    }

    #[test]
    fn turn_servers_carry_credentials() {
        let turn = vec![TurnServer {
            urls: vec!["turn:turn.example.com:3478".into()],
            username: Some("alice".into()),
            credential: Some("secret".into()),
        }];
        let cfg = build_rtc_configuration(&[], &turn);
        assert_eq!(cfg.ice_servers.len(), 1);
        assert_eq!(cfg.ice_servers[0].username, "alice");
        assert_eq!(cfg.ice_servers[0].credential, "secret");
    }

    #[test]
    fn empty_url_lists_are_skipped() {
        let stun = vec![StunServer { urls: vec![] }];
        let turn = vec![TurnServer {
            urls: vec![],
            username: Some("x".into()),
            credential: None,
        }];
        let cfg = build_rtc_configuration(&stun, &turn);
        assert!(cfg.ice_servers.is_empty());
    }

    #[test]
    fn classify_recognizes_all_candidate_types() {
        assert_eq!(
            classify_candidate_sdp("candidate:1 1 UDP 12345 192.168.1.5 54321 typ host"),
            IceCandidateKind::Host
        );
        assert_eq!(
            classify_candidate_sdp(
                "candidate:2 1 UDP 12345 1.2.3.4 54321 typ srflx raddr 0.0.0.0 rport 0"
            ),
            IceCandidateKind::ServerReflexive
        );
        assert_eq!(
            classify_candidate_sdp(
                "candidate:3 1 UDP 12345 5.6.7.8 54321 typ relay raddr 0.0.0.0 rport 0"
            ),
            IceCandidateKind::Relay
        );
        assert_eq!(
            classify_candidate_sdp("candidate:4 1 UDP 12345 1.1.1.1 54321 typ prflx"),
            IceCandidateKind::PeerReflexive
        );
        assert_eq!(
            classify_candidate_sdp("malformed"),
            IceCandidateKind::Unknown
        );
    }

    #[test]
    fn candidate_paths_rank_deterministically_without_payload_capability() {
        let mut paths = vec![
            IceCandidatePath::new(9, IceCandidateKind::Relay, IceCandidateKind::Relay, 100),
            IceCandidatePath::new(2, IceCandidateKind::Host, IceCandidateKind::Host, 100),
            IceCandidatePath::new(
                1,
                IceCandidateKind::ServerReflexive,
                IceCandidateKind::Host,
                200,
            ),
        ];

        rank_candidate_paths(&mut paths);

        assert_eq!(
            paths.iter().map(|path| path.id).collect::<Vec<_>>(),
            [1, 2, 9]
        );
        assert_eq!(
            candidate_path_preference(paths[1].local, paths[1].remote),
            5
        );
    }

    #[test]
    fn equal_paths_use_opaque_id_as_the_final_tie_breaker() {
        let mut paths = vec![
            IceCandidatePath::new(8, IceCandidateKind::Host, IceCandidateKind::Host, 7),
            IceCandidatePath::new(3, IceCandidateKind::Host, IceCandidateKind::Host, 7),
        ];

        rank_candidate_paths(&mut paths);

        assert_eq!(paths[0].id, 3);
        assert_eq!(paths[1].id, 8);
    }
}
