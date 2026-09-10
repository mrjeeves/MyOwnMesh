//! The one closed handshake-profile identifier advertised in
//! `HelloMessage::features`.
//!
//! This protocol does not negotiate optional protocol features or mixed-version
//! fallbacks. Post-authentication traffic belongs to the one current profile.
//! The advertised identifier below is instead a hard precondition for endpoint
//! authentication: a peer either speaks that exact profile or is refused.

/// Stable endpoint-authentication profile identifier, compared as an exact
/// string.
pub struct Feature;

impl Feature {
    /// Peer speaks the Arc 04 endpoint-authentication profile: the
    /// length-prefixed transcript under `ENDPOINT_AUTH_DOMAIN_TAG`, binding
    /// the mesh context, the closed profile identifier, ordered roles, both
    /// per-attempt contributions, and both endpoints' DTLS certificate
    /// fingerprints.
    ///
    /// This is not an optional-frame gate. It is a hard precondition: a peer
    /// that does not advertise it cannot be authenticated at all, and the
    /// handshake fails closed with
    /// `EndpointAuthSetupError::IncompatibleProfile` rather than falling back
    /// to anything. There is deliberately no negotiation and no second
    /// profile to select. Advertising is how a peer states it speaks the one
    /// closed profile, not how it chooses among several.
    ///
    /// A setup refusal, not a terminal one: the gate runs on the inbound Hello
    /// before an endpoint-authentication attempt is reached, so nothing has
    /// been terminalized when it fires. What closes the connection is the
    /// handler's own drop of the exact current peer.
    pub const ENDPOINT_AUTH_V1: &'static str = "endpoint_auth_v1";
}

/// The closed endpoint-authentication profile this build advertises to peers.
pub const ADVERTISED_FEATURES: &[&str] = &[Feature::ENDPOINT_AUTH_V1];

/// Test whether a peer's advertised profile list contains `feature`.
///
/// The list is stringly typed on the wire, so this comparison stays exact and
/// ignores unrelated values rather than guessing compatibility.
pub fn peer_supports(peer_features: &[String], feature: &str) -> bool {
    peer_features.iter().any(|candidate| candidate == feature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_supports_matches_exactly() {
        let peer = vec![
            Feature::ENDPOINT_AUTH_V1.to_string(),
            "unrelated_profile".to_string(),
        ];
        assert!(peer_supports(&peer, Feature::ENDPOINT_AUTH_V1));
        assert!(!peer_supports(&peer, "Endpoint_Auth_V1"));
    }

    #[test]
    fn hello_advertises_only_the_current_endpoint_profile() {
        assert_eq!(ADVERTISED_FEATURES, &[Feature::ENDPOINT_AUTH_V1]);
    }
}
