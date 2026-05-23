//! ed25519 signing and verification for the mesh.
//!
//! Used by the auth handshake: when a new peer connects, both ends
//! sign a challenge with their private key, and the receiving side
//! verifies the signature against the claimed Device ID. This proves
//! the peer actually owns the keypair that produces their advertised
//! pubkey, not just that they know it.
//!
//! Signing operations live in Rust so the private key never leaves
//! the anchor file — callers send a message to sign and get back a
//! signature, never the key itself.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

use crate::error::{Error, Result};
use crate::identity;

/// Construct the signed payload for the handshake. The receiving side
/// must produce an identical byte string from its perspective (with
/// `my_device_id` and `their_device_id` swapped) and verify the
/// signature against the sender's pubkey. The `|` separators ensure
/// no `nonce` can be reinterpreted as part of a device id when the
/// concatenation is parsed back — defense in depth on top of the
/// domain tag itself.
pub fn handshake_payload(nonce: &str, my_device_id: &str, their_device_id: &str) -> Vec<u8> {
    format!(
        "{}{nonce}|{my}|{their}",
        crate::SIGN_DOMAIN_TAG,
        nonce = nonce,
        my = my_device_id,
        their = their_device_id,
    )
    .into_bytes()
}

/// Sign an arbitrary message with this device's private key. Returns
/// the 64-byte signature, base32-lowercase encoded. The caller is
/// responsible for whatever protocol-level framing wraps the message
/// — handshakes use [`handshake_payload`], which prefixes the domain
/// tag and binds in both Device IDs.
pub fn sign(message: &[u8]) -> Result<String> {
    let identity = identity::load_or_create()?;
    Ok(sign_with(identity.signing_key(), message))
}

pub(crate) fn sign_with(key: &SigningKey, message: &[u8]) -> String {
    let sig: Signature = key.sign(message);
    BASE32_NOPAD.encode(&sig.to_bytes()).to_lowercase()
}

/// Verify a signature against a claimed Device ID. Accepts the same
/// base32-lowercase encoding the rest of the mesh uses. Returns `true`
/// if and only if the signature is valid for `message` under the
/// pubkey portion of `device_id`. Suffix on the Device ID (the
/// `-XXXXX` display tag) is stripped before parsing — peers exchange
/// raw pubkeys on the wire, but the UI surfaces the display form, so
/// either is accepted here.
pub fn verify(device_id: &str, message: &[u8], signature_b32: &str) -> Result<bool> {
    let pubkey_part_str = pubkey_part(device_id);
    let pubkey_bytes = BASE32_NOPAD
        .decode(pubkey_part_str.to_uppercase().as_bytes())
        .map_err(|e| Error::Signing(format!("device_id is not valid base32: {e}")))?;
    if pubkey_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::Signing(format!(
            "device_id decodes to {} bytes; expected {}",
            pubkey_bytes.len(),
            PUBLIC_KEY_LENGTH
        )));
    }
    let mut pubkey_arr = [0u8; PUBLIC_KEY_LENGTH];
    pubkey_arr.copy_from_slice(&pubkey_bytes);
    let pubkey = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| Error::Signing(format!("device_id is not a valid ed25519 public key: {e}")))?;

    let sig_bytes = BASE32_NOPAD
        .decode(signature_b32.to_uppercase().as_bytes())
        .map_err(|e| Error::Signing(format!("signature is not valid base32: {e}")))?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(Error::Signing(format!(
            "signature decodes to {} bytes; expected {}",
            sig_bytes.len(),
            SIGNATURE_LENGTH
        )));
    }
    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    Ok(pubkey.verify(message, &sig).is_ok())
}

/// Strip the display suffix from a Device ID, returning just the
/// pubkey portion in canonical base32-lowercase form. Used by the
/// roster (which keys on pubkey, not display) and by anywhere that
/// needs to compare two IDs that may differ only by suffix.
///
/// Real pubkeys are pure base32 (no dashes), so we strip a single
/// trailing `-XXXXX` tail where XXXXX is exactly 5 alphanumerics.
/// Inputs that don't match the display-form pattern are returned
/// unchanged.
pub fn pubkey_part(device_id: &str) -> &str {
    if let Some((body, suffix)) = device_id.rsplit_once('-') {
        if suffix.len() == 5 && suffix.chars().all(|c| c.is_ascii_alphanumeric()) {
            return body;
        }
    }
    device_id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_key() -> (SigningKey, String) {
        // Deterministic seed for reproducible test signatures.
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pubkey_b32 = BASE32_NOPAD
            .encode(sk.verifying_key().as_bytes())
            .to_lowercase();
        (sk, pubkey_b32)
    }

    #[test]
    fn sign_verify_round_trip() {
        let (sk, pubkey) = fixture_key();
        let msg = b"hello mesh";
        let sig = sign_with(&sk, msg);
        assert!(verify(&pubkey, msg, &sig).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (sk, pubkey) = fixture_key();
        let sig = sign_with(&sk, b"original");
        assert!(!verify(&pubkey, b"tampered", &sig).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let (sk, _) = fixture_key();
        let other_pubkey = BASE32_NOPAD
            .encode(
                SigningKey::from_bytes(&[8u8; 32])
                    .verifying_key()
                    .as_bytes(),
            )
            .to_lowercase();
        let sig = sign_with(&sk, b"hello");
        assert!(!verify(&other_pubkey, b"hello", &sig).unwrap());
    }

    #[test]
    fn verify_accepts_display_form_device_id() {
        let (sk, pubkey) = fixture_key();
        let msg = b"hello mesh";
        let sig = sign_with(&sk, msg);
        // Display form includes the -XXXXX suffix; verify() strips it.
        let display = format!("{pubkey}-abc12");
        assert!(verify(&display, msg, &sig).unwrap());
    }

    #[test]
    fn pubkey_part_strips_suffix() {
        assert_eq!(pubkey_part("abcdefghij-xyz12"), "abcdefghij");
        assert_eq!(pubkey_part("abcdefghij"), "abcdefghij");
        // Non-5-char tails are not display suffixes — leave alone.
        assert_eq!(pubkey_part("abc-defghij"), "abc-defghij");
        // 5-char tail with non-alphanumerics — leave alone.
        assert_eq!(pubkey_part("abc-xy!12"), "abc-xy!12");
    }

    #[test]
    fn handshake_payload_includes_domain_tag() {
        let payload = handshake_payload("nonce123", "deviceA", "deviceB");
        let s = String::from_utf8(payload).unwrap();
        assert!(s.starts_with(crate::SIGN_DOMAIN_TAG));
        assert!(s.contains("nonce123"));
        assert!(s.contains("deviceA"));
        assert!(s.contains("deviceB"));
    }

    #[test]
    fn handshake_payload_is_order_sensitive() {
        // Swapping my/their device ids produces a different payload, so
        // a peer can't reuse a signature from the opposite direction of
        // the handshake.
        let a = handshake_payload("n", "alice", "bob");
        let b = handshake_payload("n", "bob", "alice");
        assert_ne!(a, b);
    }

    #[test]
    fn round_trip_with_handshake_payload() {
        let (sk, pubkey) = fixture_key();
        let payload = handshake_payload("noncexyz", &pubkey, "peerXyz");
        let sig = sign_with(&sk, &payload);
        assert!(verify(&pubkey, &payload, &sig).unwrap());
        // Tampering with any field invalidates the signature.
        let other = handshake_payload("noncexyy", &pubkey, "peerXyz");
        assert!(!verify(&pubkey, &other, &sig).unwrap());
    }
}
