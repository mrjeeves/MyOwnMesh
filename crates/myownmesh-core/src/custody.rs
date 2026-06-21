//! Per-device custody MFA (TOTP) for closed-network governance.
//!
//! A device may enroll a TOTP authenticator (RFC 6238, HMAC-SHA1, the
//! shape every standard authenticator app speaks) against a specific
//! network. Once enrolled, **this device refuses to *author* — propose or
//! co-sign — a governance transition for that network without a fresh
//! second-factor code**. It is a *local custody lock*: it guards this
//! device's signing authority against misuse (a transferred laptop, a
//! shoulder-surfer, a stray script), and it is deliberately **not** a
//! replacement for the network's cryptographic owner-quorum — that still
//! protects against *remote* forgery. The two compose: quorum says "enough
//! owners agreed", custody says "and this owner really meant it, here and
//! now".
//!
//! Scope is per `(device, network)`: each owner device enrolls its own
//! secret; there is no shared "fleet password" to leak. Enrollment lives in
//! `~/.myownmesh/.secrets/custody.json` (0600), never gossiped.
//!
//! The gate is [`require`]; enrollment management is [`enroll`] /
//! [`is_enrolled`] / [`disable`]. Higher layers decide *which* networks must
//! enroll (e.g. a Fleet mandates it, a Mesh may not) — this module only
//! enforces the lock once it exists.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

/// TOTP digits — 6 is the universal authenticator default.
const DIGITS: u32 = 6;
/// TOTP step in seconds — 30 is the universal default.
const PERIOD: u64 = 30;
/// Accept the code from one step either side of now, to tolerate clock
/// skew and a code typed as the window rolls. (±30s.)
const SKEW_STEPS: i64 = 1;
/// Shared-secret length. RFC 4226 recommends ≥160 bits.
const SECRET_LEN: usize = 20;
/// One-time recovery codes minted at enrollment.
const RECOVERY_CODES: usize = 10;
/// Issuer label shown in the authenticator app.
const ISSUER: &str = "MyOwnMesh";

// ---------------------------------------------------------------------------
// On-disk model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CustodyStore {
    #[serde(default)]
    networks: BTreeMap<String, Enrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Enrollment {
    /// Base32 (RFC 4648, no pad) TOTP shared secret.
    secret_b32: String,
    /// SHA-256 hex of each *unused* one-time recovery code. A code is
    /// removed from this list the moment it is consumed.
    recovery_hashes: Vec<String>,
    created_at: u64,
}

/// What [`enroll`] hands back to show the user exactly once: the secret (as
/// base32 and as an `otpauth://` URI for QR rendering) and the cleartext
/// recovery codes. None of the cleartext is persisted — only the secret and
/// the recovery-code *hashes* live on disk.
#[derive(Debug, Clone, Serialize)]
pub struct Enrolled {
    pub secret_b32: String,
    pub otpauth_uri: String,
    pub recovery_codes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Whether this device holds a custody enrollment for `network_id`.
pub fn is_enrolled(network_id: &str) -> bool {
    store_path()
        .ok()
        .and_then(|p| load_at(&p).ok())
        .map(|s| s.networks.contains_key(network_id))
        .unwrap_or(false)
}

/// Enroll a fresh TOTP authenticator for `network_id` on this device.
/// `account` is the human label shown in the authenticator app (e.g. the
/// device label). Fails if an enrollment already exists — [`disable`] it
/// first (which itself requires a valid code), so the lock can't be
/// silently rotated away.
pub fn enroll(network_id: &str, account: &str) -> Result<Enrolled> {
    enroll_at(&store_path()?, network_id, account)
}

/// The gate. `Ok(())` when the network has no enrollment on this device (the
/// lock is a no-op) **or** when `code` verifies — a TOTP for the current
/// window, or a one-time recovery code, which is then consumed. `Err`
/// otherwise. Custody-affecting governance authoring calls this before it
/// signs.
pub fn require(network_id: &str, code: Option<&str>) -> Result<()> {
    require_at(&store_path()?, network_id, code)
}

/// Remove the custody lock for `network_id` — but only on presentation of a
/// valid code, so the lock can't be undone by someone who doesn't already
/// satisfy it.
pub fn disable(network_id: &str, code: &str) -> Result<()> {
    disable_at(&store_path()?, network_id, code)
}

// ---------------------------------------------------------------------------
// Path-injectable core (so unit tests never touch the real secrets dir)
// ---------------------------------------------------------------------------

fn enroll_at(path: &Path, network_id: &str, account: &str) -> Result<Enrolled> {
    let mut store = load_at(path)?;
    if store.networks.contains_key(network_id) {
        return Err(Error::Custody(format!(
            "network {network_id} already has MFA enrolled on this device; disable it first"
        )));
    }
    let secret = random_bytes(SECRET_LEN);
    let secret_b32 = BASE32_NOPAD.encode(&secret);
    let recovery_codes = gen_recovery_codes();
    let recovery_hashes = recovery_codes.iter().map(|c| hash_code(c)).collect();
    let otpauth_uri = provisioning_uri(&secret_b32, account);
    store.networks.insert(
        network_id.to_string(),
        Enrollment {
            secret_b32: secret_b32.clone(),
            recovery_hashes,
            created_at: now_unix(),
        },
    );
    save_at(path, &store)?;
    Ok(Enrolled {
        secret_b32,
        otpauth_uri,
        recovery_codes,
    })
}

fn require_at(path: &Path, network_id: &str, code: Option<&str>) -> Result<()> {
    let mut store = load_at(path)?;
    let Some(enr) = store.networks.get_mut(network_id) else {
        return Ok(()); // not enrolled on this device → the gate is a no-op
    };
    let Some(code) = code.map(str::trim).filter(|c| !c.is_empty()) else {
        return Err(Error::Custody(
            "this change requires your authenticator code".into(),
        ));
    };
    // TOTP for the current window (±1 step) first.
    let secret = BASE32_NOPAD
        .decode(enr.secret_b32.as_bytes())
        .map_err(|e| Error::Custody(format!("stored secret is not valid base32: {e}")))?;
    if verify_totp_at(&secret, code, now_unix()) {
        return Ok(());
    }
    // Otherwise a one-time recovery code — consumed on match.
    let h = hash_code(code);
    if let Some(pos) = enr
        .recovery_hashes
        .iter()
        .position(|x| constant_eq(x.as_bytes(), h.as_bytes()))
    {
        enr.recovery_hashes.remove(pos);
        save_at(path, &store)?;
        return Ok(());
    }
    Err(Error::Custody("invalid authenticator code".into()))
}

fn disable_at(path: &Path, network_id: &str, code: &str) -> Result<()> {
    require_at(path, network_id, Some(code))?;
    let mut store = load_at(path)?;
    store.networks.remove(network_id);
    save_at(path, &store)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// TOTP / HOTP (RFC 6238 / RFC 4226)
// ---------------------------------------------------------------------------

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    bin % 10u32.pow(DIGITS)
}

// Computing a code *from the secret* is what an authenticator app does, not
// the daemon — the whole point of the second factor is that it comes from a
// separate device. So this lives test-only; production never derives its own
// code (it only ever `verify`s one supplied from outside).
#[cfg(test)]
fn totp_at(secret: &[u8], unix: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, unix / PERIOD),
        width = DIGITS as usize
    )
}

fn verify_totp_at(secret: &[u8], code: &str, unix: u64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let step = (unix / PERIOD) as i64;
    for d in -SKEW_STEPS..=SKEW_STEPS {
        let counter = (step + d).max(0) as u64;
        let candidate = format!("{:0width$}", hotp(secret, counter), width = DIGITS as usize);
        if constant_eq(candidate.as_bytes(), code.as_bytes()) {
            return true;
        }
    }
    false
}

fn provisioning_uri(secret_b32: &str, account: &str) -> String {
    let label = format!("{}:{}", pct(ISSUER), pct(account));
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        pct(ISSUER)
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Percent-encode everything but the RFC 3986 unreserved set.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    if getrandom::getrandom(&mut v).is_err() {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut v);
    }
    v
}

/// `RECOVERY_CODES` formatted as `xxxxx-xxxxx` (base32, lowercase).
fn gen_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let raw = BASE32_NOPAD.encode(&random_bytes(8)).to_lowercase();
            let c: String = raw.chars().take(10).collect();
            format!("{}-{}", &c[..5], &c[5..])
        })
        .collect()
}

/// Normalise (strip separators + case) then SHA-256-hex, so a recovery code
/// matches whether the user types the dashes or not.
fn hash_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();
    let mut h = Sha256::new();
    h.update(normalized.as_bytes());
    hex::encode(h.finalize())
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn store_path() -> Result<PathBuf> {
    Ok(crate::dirs::secrets_dir()?.join("custody.json"))
}

fn load_at(path: &Path) -> Result<CustodyStore> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CustodyStore::default()),
        Err(e) => Err(Error::Custody(format!("read custody store: {e}"))),
    }
}

fn save_at(path: &Path, store: &CustodyStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Custody(format!("create secrets dir: {e}")))?;
        restrict_dir(parent);
    }
    let bytes = serde_json::to_vec_pretty(store)?;
    std::fs::write(path, bytes).map_err(|e| Error::Custody(format!("write custody store: {e}")))?;
    restrict_file(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}
#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}
#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B reference vector (SHA-1 seed, T=59s). The 8-digit
    /// reference is 94287082; truncated to our 6 digits that's 287082.
    #[test]
    fn totp_matches_rfc6238_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_at(secret, 59), "287082");
        assert!(verify_totp_at(secret, "287082", 59));
        // A code from ten steps away is outside the ±1 skew window.
        assert!(!verify_totp_at(secret, "287082", 59 + 10 * PERIOD));
        // Wrong shape is rejected outright.
        assert!(!verify_totp_at(secret, "1234567", 59));
        assert!(!verify_totp_at(secret, "abcdef", 59));
    }

    #[test]
    fn skew_window_accepts_adjacent_steps() {
        let secret = b"12345678901234567890";
        let code = totp_at(secret, 1000);
        assert!(verify_totp_at(secret, &code, 1000));
        assert!(verify_totp_at(secret, &code, 1000 + PERIOD)); // +1 step
        assert!(verify_totp_at(secret, &code, 1000 - PERIOD)); // -1 step
        assert!(!verify_totp_at(secret, &code, 1000 + 2 * PERIOD)); // +2 steps: out
    }

    #[test]
    fn recovery_hash_is_separator_and_case_insensitive() {
        assert_eq!(hash_code("ABCDE-FGHIJ"), hash_code("abcdefghij"));
        assert_eq!(hash_code("ab cd ef"), hash_code("ABCDEF"));
        assert_ne!(hash_code("abcde"), hash_code("abcdf"));
    }

    #[test]
    fn provisioning_uri_is_authenticator_shaped() {
        let uri = provisioning_uri("JBSWY3DPEHPK3PXP", "my laptop");
        assert!(uri.starts_with("otpauth://totp/MyOwnMesh:my%20laptop?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "mom-custody-test-{}-{}.json",
            std::process::id(),
            now_unix_nanos()
        ))
    }
    fn now_unix_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn enroll_then_gate_accepts_totp_and_consumes_recovery() {
        let path = tmp();
        let net = "fleet-xyz";

        // Not enrolled → the gate is a no-op even with no code.
        assert!(require_at(&path, net, None).is_ok());

        let enrolled = enroll_at(&path, net, "laptop").expect("enroll");
        assert_eq!(enrolled.recovery_codes.len(), RECOVERY_CODES);

        // Enrolled → a custody change with no code is refused.
        assert!(require_at(&path, net, None).is_err());
        // Wrong code refused.
        assert!(require_at(&path, net, Some("000000")).is_err());

        // A correct TOTP (computed from the returned secret, as an
        // authenticator app would) is accepted, and is reusable within its
        // window (TOTP is not one-time).
        let secret = BASE32_NOPAD.decode(enrolled.secret_b32.as_bytes()).unwrap();
        let code = totp_at(&secret, now_unix());
        assert!(require_at(&path, net, Some(&code)).is_ok());
        assert!(require_at(&path, net, Some(&code)).is_ok());

        // A recovery code works once, then is burned.
        let rc = &enrolled.recovery_codes[0];
        assert!(require_at(&path, net, Some(rc)).is_ok());
        assert!(
            require_at(&path, net, Some(rc)).is_err(),
            "a recovery code must be single-use"
        );

        // Other networks are unaffected (per-network scope).
        assert!(require_at(&path, "some-mesh", None).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn disable_requires_a_valid_code_then_clears_the_lock() {
        let path = tmp();
        let net = "fleet-abc";
        let enrolled = enroll_at(&path, net, "phone").expect("enroll");
        let secret = BASE32_NOPAD.decode(enrolled.secret_b32.as_bytes()).unwrap();

        // Can't disable without satisfying the lock.
        assert!(disable_at(&path, net, "000000").is_err());
        assert!(is_enrolled_at(&path, net));

        // With a valid code it clears, and the gate is a no-op again.
        let code = totp_at(&secret, now_unix());
        assert!(disable_at(&path, net, &code).is_ok());
        assert!(!is_enrolled_at(&path, net));
        assert!(require_at(&path, net, None).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    // Test-only mirror of `is_enrolled` against an explicit path.
    fn is_enrolled_at(path: &Path, network_id: &str) -> bool {
        load_at(path)
            .map(|s| s.networks.contains_key(network_id))
            .unwrap_or(false)
    }
}
