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
}
