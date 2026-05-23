//! 6-char human-readable verification codes for the handshake's
//! out-of-band confirmation step.
//!
//! Code generation: 6 chars from `[a-z0-9]` — 36^6 ≈ 2.2 billion. Not
//! cryptographically load-bearing (the ed25519 mutual signature is
//! what actually authenticates the peer), but the code is the
//! eyeball-check at first-meeting time: when a user clicks "approve",
//! they read their code over voice/video to the peer and confirm
//! it matches the one their peer is seeing. If two simultaneous
//! attackers were both fishing for an approval from the same user
//! at the same moment, the codes would diverge and the user would
//! catch the mismatch.

use rand_core::{OsRng, RngCore};

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Length of every verification code we emit. Fixed at 6 — readable
/// over voice in under 2 seconds, picks 1-in-2-billion at random per
/// hello so collision at the moment of approval is negligible.
pub const VERIFICATION_CODE_LEN: usize = 6;

/// Generate a fresh code from OS randomness. Caller is responsible
/// for surfacing it to both sides of the handshake before the user
/// approves.
pub fn generate_code() -> String {
    let mut bytes = [0u8; VERIFICATION_CODE_LEN];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|&b| ALPHABET[(b as usize) % ALPHABET.len()] as char)
        .collect()
}

/// Sanity-check a code received from the wire. Cheap defense against
/// a peer sending an empty / oversize / malformed code that would
/// look broken in the UI — we don't reject the handshake on a bad
/// code (the ed25519 sig is what authenticates), but the UI prefers
/// to surface "[malformed]" over a blank space.
pub fn is_well_formed(code: &str) -> bool {
    code.len() == VERIFICATION_CODE_LEN
        && code
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_well_formed_code() {
        for _ in 0..200 {
            let c = generate_code();
            assert!(is_well_formed(&c), "code rejected: {c:?}");
        }
    }

    #[test]
    fn well_formed_rejects_bad_inputs() {
        assert!(!is_well_formed(""));
        assert!(!is_well_formed("abc"));
        assert!(!is_well_formed("abcdefg"));
        assert!(!is_well_formed("ABCDEF")); // uppercase
        assert!(!is_well_formed("abc!23")); // punctuation
        assert!(!is_well_formed("abc 23")); // space
    }

    #[test]
    fn generate_is_random_enough() {
        // 100 codes shouldn't collide. Astronomically unlikely with
        // 36^6 ≈ 2.2B keyspace; if it does we want to know.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let c = generate_code();
            assert!(seen.insert(c.clone()), "duplicate code: {c}");
        }
    }
}
