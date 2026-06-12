//! Minimal Nostr event construction + signing. We implement the
//! NIP-01 event shape directly rather than depend on the
//! full-fat `nostr` crate — we need exactly one event kind, one
//! filter shape, and BIP-340 signing, which is straightforward
//! over `secp256k1`.

use secp256k1::{rand, Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Kind used for MyOwnMesh **presence** — the periodic Announce, and
/// nothing else. Lives in the NIP-01 regular range (1000–9999) so
/// relays store and replay it on a `since`-scoped REQ — that's what
/// lets a late joiner discover every existing peer, not just the one
/// that happens to re-announce inside their window. The earlier
/// ephemeral choice (21000) caused a star-around-first-peer failure
/// mode for *discovery*.
///
/// Presence is the ONLY thing that rides this stored kind. Connection
/// negotiation (offer / answer / candidate) uses
/// [`SIGNALING_EPHEMERAL_KIND`] precisely so it is never stored or
/// replayed — see the rationale there.
pub const SIGNALING_EVENT_KIND: u16 = 1077;

/// Kind used for MyOwnMesh **connection negotiation** — every directed
/// offer / answer / ICE candidate. Lives in the NIP-01 ephemeral range
/// (20000–29999): relays forward these to current subscribers in real
/// time but never persist them, so a `since`-scoped REQ cannot replay
/// them.
///
/// This separation is load-bearing. An offer/answer carries
/// session-specific ICE credentials (ufrag/pwd) bound to exactly one
/// live `RTCPeerConnection`. If a relay replays a *previous* session's
/// offer/answer — which a stored kind does for the whole `since`
/// window — the receiver applies it as its remote description and
/// binds a brand-new PeerConnection to dead credentials: ICE checks
/// never match, the data channel never opens, and the peer sits at
/// `Sighted` until the stale event finally ages out of the window
/// (the "they see each other but never connect" symptom). Routing
/// negotiation through an ephemeral kind makes that class of failure
/// structurally impossible — presence persists, the connection is
/// always live.
///
/// 21077 = 20000 (ephemeral base) + 1077, so the presence and
/// negotiation kinds read as an obvious pair in relay traffic.
pub const SIGNALING_EPHEMERAL_KIND: u16 = 21077;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Debug, Clone)]
pub struct NostrIdentity {
    keypair: Keypair,
    pubkey_hex: String,
}

impl NostrIdentity {
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
        Self::from_secret(sk)
    }

    pub fn from_secret(sk: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey_hex = hex::encode(xonly.serialize());
        Self {
            keypair,
            pubkey_hex,
        }
    }

    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// Sign an event-id digest with BIP-340 Schnorr.
    fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        let secp = Secp256k1::new();
        let sig = secp.sign_schnorr_no_aux_rand(&digest[..], &self.keypair);
        // `Signature::serialize` is deprecated in favor of
        // `to_byte_array` in secp256k1 ≥ 0.30; both return the
        // same 64-byte BIP-340 encoding. Keep an explicit allow
        // so a future rename doesn't silently break the wire
        // shape.
        #[allow(deprecated)]
        sig.serialize()
    }
}

/// Build and sign a fresh event.
pub fn make_event(
    identity: &NostrIdentity,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    created_at: u64,
) -> NostrEvent {
    let pubkey = identity.pubkey_hex().to_string();
    let id_payload = json!([
        0,
        pubkey,
        created_at,
        kind,
        Value::Array(
            tags.iter()
                .map(|t| Value::Array(t.iter().map(|s| Value::String(s.clone())).collect()))
                .collect()
        ),
        content,
    ]);
    let id_bytes = compute_event_id(&id_payload);
    let id_hex = hex::encode(id_bytes);

    let sig_bytes = identity.sign_digest(&id_bytes);
    let sig_hex = hex::encode(sig_bytes);

    NostrEvent {
        id: id_hex,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig: sig_hex,
    }
}

impl NostrEvent {
    /// Verify this event is internally consistent and authentic per NIP-01:
    /// the `id` is the SHA-256 of the canonical
    /// `[0, pubkey, created_at, kind, tags, content]` serialization, and `sig`
    /// is a valid BIP-340 Schnorr signature over that id by `pubkey`. A relay
    /// that forwards/stores only verified events can't be used to inject forged
    /// presence or `leave` traffic. Fails closed on any malformed field.
    pub fn verify(&self) -> bool {
        let id_payload = json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            Value::Array(
                self.tags
                    .iter()
                    .map(|t| Value::Array(t.iter().map(|s| Value::String(s.clone())).collect()))
                    .collect()
            ),
            self.content,
        ]);
        let id_bytes = compute_event_id(&id_payload);
        if hex::encode(id_bytes) != self.id {
            return false;
        }
        let Ok(pk_bytes) = hex::decode(&self.pubkey) else {
            return false;
        };
        let Ok(xonly) = XOnlyPublicKey::from_slice(&pk_bytes) else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(&self.sig) else {
            return false;
        };
        let Ok(sig) = secp256k1::schnorr::Signature::from_slice(&sig_bytes) else {
            return false;
        };
        Secp256k1::verification_only()
            .verify_schnorr(&sig, &id_bytes, &xonly)
            .is_ok()
    }
}

fn compute_event_id(payload: &Value) -> [u8; 32] {
    // NIP-01 specifies a compact JSON serialization with no
    // unnecessary whitespace and no escaping beyond the strictly
    // required minimum. `serde_json::to_string` already emits
    // compact JSON without trailing whitespace, which matches.
    let serialized = serde_json::to_string(payload).expect("serialize ok");
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Current unix-seconds.
pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_deterministic_from_secret() {
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a = NostrIdentity::from_secret(sk);
        let b = NostrIdentity::from_secret(sk);
        assert_eq!(a.pubkey_hex(), b.pubkey_hex());
    }

    #[test]
    fn event_signs_and_pubkey_matches() {
        let id = NostrIdentity::generate();
        let ev = make_event(
            &id,
            SIGNALING_EVENT_KIND,
            vec![vec!["r".into(), "room123".into()]],
            "hello".into(),
            12345,
        );
        assert_eq!(ev.pubkey, id.pubkey_hex());
        assert_eq!(ev.kind, SIGNALING_EVENT_KIND);
        assert_eq!(ev.content, "hello");
        assert_eq!(ev.tags[0][1], "room123");
        // id and sig are non-empty 64-char hex strings
        assert_eq!(ev.id.len(), 64);
        assert_eq!(ev.sig.len(), 128);
        assert!(ev.id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ev.sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_accepts_signed_event_and_rejects_tampering() {
        let id = NostrIdentity::generate();
        let ev = make_event(&id, SIGNALING_EVENT_KIND, vec![], "presence".into(), 999);
        assert!(ev.verify(), "a freshly signed event verifies");

        // Tampered content → recomputed id no longer matches.
        let mut bad = ev.clone();
        bad.content = "spoofed".into();
        assert!(!bad.verify(), "tampered content is rejected");

        // Claiming a different signer → id (which binds the pubkey) won't match.
        let other = NostrIdentity::generate();
        let mut imposter = ev.clone();
        imposter.pubkey = other.pubkey_hex().to_string();
        assert!(!imposter.verify(), "a mismatched pubkey is rejected");
    }

    #[test]
    fn verify_rejects_a_valid_id_with_a_forged_signature() {
        // An attacker who recomputes a correct id for tampered content still
        // can't produce a valid signature without the secret key.
        let id = NostrIdentity::generate();
        let mut ev = make_event(&id, SIGNALING_EVENT_KIND, vec![], "real".into(), 1);
        ev.content = "tampered".into();
        let payload = json!([
            0,
            ev.pubkey,
            ev.created_at,
            ev.kind,
            Value::Array(vec![]),
            ev.content
        ]);
        ev.id = hex::encode(compute_event_id(&payload));
        assert!(
            !ev.verify(),
            "a stale signature over a fresh id is rejected"
        );
    }
}
