//! Hostnames excluded from the default relay pool. Each entry has a
//! note explaining the operational reason — keep these comments
//! current so future maintainers don't reverse a deliberate
//! exclusion.

/// Default denylist. The user can override via
/// `NetworkConfig::signaling::denylist`. Hostnames only; match is
/// case-insensitive.
pub const DEFAULT_DENYLIST: &[&str] = &[
    // Rate-limits the OPEN cadence we use under load; new REQs are
    // silently dropped past a threshold that's well below our peer
    // count on busy networks. Symptom: subscription replay logs
    // recurring against this relay only.
    "relay.damus.io",
    // Frequently NAKs incoming EVENTs without forwarding to other
    // subscribers, leaving the sender thinking the publish landed.
    // Symptom: outbound EVENT loops on retry without takers.
    "chorus.pjv.me",
];

/// True if the given URL's hostname matches any denylist entry
/// (case-insensitive). Accepts `wss://host/...` URLs.
pub fn is_denied(url: &str, extra: &[String]) -> bool {
    let Some(host) = extract_host(url) else {
        return false;
    };
    let host_lc = host.to_ascii_lowercase();
    DEFAULT_DENYLIST
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&host_lc))
        || extra.iter().any(|h| h.eq_ignore_ascii_case(&host_lc))
}

fn extract_host(url: &str) -> Option<&str> {
    let after_scheme = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);
    let host = after_scheme.split('/').next()?;
    // Strip any port suffix.
    host.split(':').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_handles_common_forms() {
        assert_eq!(
            extract_host("wss://relay.example.com/x/y"),
            Some("relay.example.com")
        );
        assert_eq!(
            extract_host("wss://relay.example.com"),
            Some("relay.example.com")
        );
        assert_eq!(
            extract_host("ws://relay.example.com:8080/"),
            Some("relay.example.com")
        );
        assert_eq!(extract_host("relay.example.com"), Some("relay.example.com"));
    }

    #[test]
    fn is_denied_matches_default_entries() {
        assert!(is_denied("wss://relay.damus.io", &[]));
        assert!(is_denied("wss://RELAY.DAMUS.IO/foo", &[]));
        assert!(!is_denied("wss://relay.example.com", &[]));
    }

    #[test]
    fn is_denied_honors_user_extra() {
        let extra = vec!["custom.bad.relay".to_string()];
        assert!(is_denied("wss://custom.bad.relay", &extra));
        assert!(!is_denied("wss://other.relay", &extra));
    }
}
