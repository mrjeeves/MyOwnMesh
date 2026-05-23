//! Minimal Nostr event construction + signing. We implement the
//! NIP-01 event shape directly rather than depend on the
//! full-fat `nostr` crate — we need exactly one event kind
//! (ephemeral signaling), one filter shape, and BIP-340 signing,
//! which is straightforward over `secp256k1`.

use secp256k1::{rand, Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Kind used for MyOwnMesh signaling. Falls in the ephemeral
/// range (20000–29999) per NIP-01 — relays may forward without
/// storing, which is the semantics we want.
pub const SIGNALING_EVENT_KIND: u16 = 21000;

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
}
