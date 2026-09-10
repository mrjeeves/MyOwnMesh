//! Long-lived device identity for the mesh.
//!
//! On first use, an ed25519 keypair is generated and persisted to
//! `~/.myownmesh/.secrets/identity.json`. The directory is created with
//! 0700 and the file with 0600 on Unix so the secret key isn't
//! world-readable. Subsequent launches reload the same identity — this
//! pubkey is the device's permanent identifier across mesh joins,
//! restarts, and network ID changes.
//!
//! Encoding: pubkey and Network ID are surfaced as RFC-4648 base32
//! lowercase, no padding. A 32-byte ed25519 pubkey is 52 chars, which
//! is short enough to read aloud and case-insensitive on copy-paste.

use std::path::{Path, PathBuf};

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use parking_lot::RwLock;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};

const ANCHOR_VERSION: u32 = 1;

/// How many characters [`generate_network_id`] produces.
const GENERATED_NETWORK_ID_CHARS: usize = 8;

/// The alphabet a generated Network ID is drawn from. Every character is one
/// ASCII byte, which is what lets a plan state the generated length in bytes
/// without generating anything.
const NETWORK_ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Shortest accepted normalized Network ID, in bytes.
const MIN_NETWORK_ID_BYTES: usize = 3;

/// Longest accepted normalized Network ID, in bytes.
const MAX_NETWORK_ID_BYTES: usize = 64;

/// How many characters [`display_suffix`] produces. One ASCII byte each, so
/// this is a byte count too — which is what lets [`Identity::display_id_len`]
/// answer without hashing, and what fixes the width of the inline array
/// [`display_suffix_bytes`] returns.
pub const DISPLAY_SUFFIX_CHARS: usize = 5;

/// Shorthand for a Device ID — the base32-lowercase representation of
/// a 32-byte ed25519 public key. Kept as a type alias for clarity at
/// the API boundary; the wire form is always a plain `String`.
pub type DeviceId = String;

/// On-disk anchor file format. We keep the secret key inline for v1 —
/// it never leaves the local disk and the file is mode 0600. A future
/// migration can swap to an OS keychain without changing the public
/// API of this module.
#[derive(Debug, Serialize, Deserialize)]
struct Anchor {
    version: u32,
    created_at: String,
    /// 32-byte ed25519 secret seed, base32-lowercase, no padding.
    secret_key: String,
    /// 32-byte ed25519 public key, base32-lowercase, no padding.
    /// Redundant (derivable from `secret_key`) but stored so a
    /// reader can show the Device ID without touching the secret.
    public_key: String,
    /// Optional human-readable label. Free-form; the user can edit
    /// it from the settings UI. Empty by default — the UI falls back
    /// to a truncated Device ID when this is empty.
    label: String,
}

/// In-memory view of the device's identity. Holds the secret key for
/// signing operations and a precomputed encoded public key for cheap
/// display.
///
/// The `label` is interior-mutable so the daemon can update it at
/// runtime (the GUI's Identity tab and `myownmesh identity set-label`
/// both write through to disk via [`set_label`] and into this slot
/// via [`Identity::set_label`]) without rebuilding the shared
/// `Arc<Identity>` held by every joined network.
pub struct Identity {
    signing_key: SigningKey,
    public_id: String,
    label: RwLock<String>,
}

impl Identity {
    /// Build an in-memory identity from an existing signing key
    /// without touching the anchor file. Useful for tests and for
    /// embedders that manage their own key storage.
    pub fn from_signing_key(signing_key: SigningKey, label: impl Into<String>) -> Self {
        let public_id = BASE32_NOPAD
            .encode(signing_key.verifying_key().as_bytes())
            .to_lowercase();
        Self {
            signing_key,
            public_id,
            label: RwLock::new(label.into()),
        }
    }

    /// Generate a brand-new ephemeral identity from OS randomness.
    /// Not persisted; the caller is responsible for storing the
    /// signing key if they need it across runs.
    pub fn ephemeral() -> Self {
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        OsRng.fill_bytes(&mut seed);
        Self::from_signing_key(SigningKey::from_bytes(&seed), String::new())
    }

    /// Base32-lowercase encoding of the public key. This is the
    /// cryptographic identifier used on the wire — peers compare
    /// pubkeys by this value. Stable across launches.
    pub fn public_id(&self) -> &str {
        &self.public_id
    }

    /// Display form of the Device ID surfaced in the UI: the
    /// public-key body, a dash, and a deterministic 5-char
    /// UPPERCASE HEX tag. The tag (sha256 of the base32 pubkey
    /// string, first 5 hex chars) makes instances easier to pick
    /// out at a glance in a peers list — the same device always
    /// shows the same tail. Display-only; the protocol still talks
    /// `public_id()`. Hashing the base32 string (rather than the
    /// raw 32 pubkey bytes) lets clients in other languages derive
    /// the same suffix from the string they already have, without
    /// base32-decoding.
    pub fn display_id(&self) -> String {
        let suffix = display_suffix(self.public_id().as_bytes());
        format!("{}-{}", self.public_id(), suffix)
    }

    /// Exactly how many bytes [`Self::display_id`] will produce, without
    /// producing it.
    ///
    /// Exact, not a bound, and it does not hash: the display form is the
    /// public id, one dash, and a suffix whose length is fixed by
    /// [`display_suffix`]. Every part is either already owned as a `&str` or a
    /// constant, so the answer is arithmetic.
    ///
    /// This exists so a caller sizing a response does not have to restate the
    /// layout. The separator and the suffix width are this module's rules; a
    /// caller writing `public_id().len() + 6` would be copying them out, and
    /// would go quietly wrong the day the suffix changed width.
    pub fn display_id_len(&self) -> usize {
        self.public_id.len() + 1 + DISPLAY_SUFFIX_CHARS
    }

    /// Current human-readable label. Cloned out of the interior
    /// `RwLock` so callers never hold the lock across an await — the
    /// label is short (free-form, typically under 64 chars) so the
    /// clone is cheap.
    pub fn label(&self) -> String {
        self.label.read().clone()
    }

    /// Update the in-memory label. The on-disk anchor is the source
    /// of truth across restarts; persist via [`set_label`] in
    /// addition to this when the change should survive a daemon
    /// reboot.
    pub fn set_label(&self, new_label: &str) {
        *self.label.write() = new_label.to_string();
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// Derive a 5-char UPPERCASE-HEX display tag from a pubkey string.
/// Input is the base32-encoded pubkey (as bytes of that string), not
/// the raw 32-byte pubkey, so external callers can mirror this
/// exactly by hashing the same string they already have — no
/// base32-decoding required.
///
/// 5 hex chars = 20 bits ≈ 1M distinct tags. Plenty for
/// eyeball-disambiguation in a peers list, and the all-caps hex
/// rendering reads unambiguously over voice ("seven C four A one").
pub fn display_suffix(pubkey_string_bytes: &[u8]) -> String {
    let suffix = display_suffix_bytes(pubkey_string_bytes);
    // `str::to_owned` allocates exactly `len` bytes, so the returned `String`
    // has capacity `DISPLAY_SUFFIX_CHARS` and nothing else. That matters to a
    // caller that must charge for this string before building it: the shape
    // this replaced collected the tag through `String: FromIterator<char>`,
    // whose reservation comes from an iterator size hint and lands on
    // whatever capacity the allocator's growth rule picks — a number derived
    // from `std`'s internals rather than from the tag's width.
    std::str::from_utf8(&suffix)
        .expect("uppercase hex digits are ASCII")
        .to_owned()
}

/// The same tag as its exact bytes, built without allocating.
///
/// The measurable form, and the one [`display_suffix`] is defined in terms of
/// so the two cannot render a peer differently. A caller that must publish this
/// tag inside a funded structure stores the array inline: it has one fixed size
/// known at compile time, so it costs no heap term at all, where the `String`
/// form costs a byte term and an allocation per peer.
pub fn display_suffix_bytes(pubkey_string_bytes: &[u8]) -> [u8; DISPLAY_SUFFIX_CHARS] {
    use sha2::{Digest, Sha256};
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut hasher = Sha256::new();
    hasher.update(pubkey_string_bytes);
    let digest = hasher.finalize();
    // 3 bytes → 6 hex chars; take the first 5. Nibble `index` of the digest is
    // the high half of byte `index / 2` when `index` is even and the low half
    // when it is odd, which is the same walk the two-hex-digits-per-byte
    // rendering this replaced performed.
    let mut suffix = [0u8; DISPLAY_SUFFIX_CHARS];
    for (index, slot) in suffix.iter_mut().enumerate() {
        let byte = digest[index / 2];
        let nibble = if index % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0f
        };
        *slot = HEX_DIGITS[usize::from(nibble)];
    }
    suffix
}

/// Normalize a Device ID at an API boundary.
///
/// The wire identity is always the 52-character base32-lowercase encoding of
/// an Ed25519 public key. User-facing surfaces may hand that value back in
/// uppercase, surrounded by whitespace, or with the deterministic `-XXXXX`
/// display suffix. Collapse all accepted forms to the wire identity so peer
/// maps, reconnect intents, signaling recipients, and roster rows cannot key
/// the same public key under different strings.
///
/// A supplied display suffix must be the one derived from the key. Treating an
/// arbitrary five-character tail as cosmetic makes a mistyped UI ID silently
/// target a different identity than the operator intended.
pub fn normalize_device_id(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Identity("device id is empty".into()));
    }

    let (body, supplied_suffix) = match trimmed.rsplit_once('-') {
        Some((body, suffix)) if suffix.len() == 5 => (body, Some(suffix)),
        _ => (trimmed, None),
    };
    let canonical = body.to_ascii_lowercase();
    let decoded = BASE32_NOPAD
        .decode(canonical.to_ascii_uppercase().as_bytes())
        .map_err(|e| Error::Identity(format!("device id is not valid base32: {e}")))?;
    if decoded.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
        return Err(Error::Identity(format!(
            "device id decodes to {} bytes; expected {}",
            decoded.len(),
            ed25519_dalek::PUBLIC_KEY_LENGTH
        )));
    }
    let mut bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
    bytes.copy_from_slice(&decoded);
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| Error::Identity(format!("device id is not an Ed25519 public key: {e}")))?;

    if let Some(supplied) = supplied_suffix {
        let expected = display_suffix(canonical.as_bytes());
        if !supplied.eq_ignore_ascii_case(&expected) {
            return Err(Error::Identity(format!(
                "device id display suffix does not match (expected {expected})"
            )));
        }
    }
    Ok(canonical)
}

/// Path of the anchor file. The directory `~/.myownmesh/.secrets/` is
/// created on demand.
fn anchor_path() -> Result<PathBuf> {
    Ok(crate::dirs::secrets_dir()?.join("identity.json"))
}

/// Load the identity from disk, generating it on first call. Idempotent
/// — repeated calls return the same identity. Errors propagate as-is so
/// callers can surface a clear failure instead of silently regenerating
/// a fresh key (which would orphan any peer relationships the user had
/// already established under the old key).
pub fn load_or_create() -> Result<Identity> {
    let path = anchor_path()?;
    if path.exists() {
        let raw = std::fs::read_to_string(&path).map_err(|e| {
            Error::Identity(format!("read identity anchor at {}: {e}", path.display()))
        })?;
        let anchor: Anchor = serde_json::from_str(&raw).map_err(|e| {
            Error::Identity(format!("parse identity anchor at {}: {e}", path.display()))
        })?;
        return decode_anchor(anchor);
    }
    create_new(&path)
}

fn create_new(path: &Path) -> Result<Identity> {
    // Ensure parent directory exists with restrictive perms.
    let parent = path.parent().ok_or_else(|| {
        Error::Identity(format!(
            "identity anchor path has no parent: {}",
            path.display()
        ))
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        Error::Identity(format!("create .secrets dir at {}: {e}", parent.display()))
    })?;
    restrict_dir_permissions(parent)?;

    // Generate a fresh ed25519 keypair from OS randomness.
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying = signing_key.verifying_key();

    let anchor = Anchor {
        version: ANCHOR_VERSION,
        created_at: chrono_now_iso(),
        secret_key: BASE32_NOPAD.encode(&seed).to_lowercase(),
        public_key: BASE32_NOPAD.encode(verifying.as_bytes()).to_lowercase(),
        label: String::new(),
    };

    let serialized = serde_json::to_string_pretty(&anchor)?;
    // Atomic: a truncated anchor is unrecoverable (the secret key is
    // gone) and load_or_create deliberately refuses to regenerate over
    // a corrupt file — so this write must never be able to produce one.
    crate::persist::write_atomic(path, serialized.as_bytes()).map_err(|e| {
        Error::Identity(format!("write identity anchor to {}: {e}", path.display()))
    })?;
    restrict_file_permissions(path)?;

    Ok(Identity {
        signing_key,
        public_id: anchor.public_key,
        label: RwLock::new(anchor.label),
    })
}

fn decode_anchor(anchor: Anchor) -> Result<Identity> {
    if anchor.version != ANCHOR_VERSION {
        return Err(Error::Identity(format!(
            "identity anchor version {} unsupported (this build expects v{})",
            anchor.version, ANCHOR_VERSION
        )));
    }
    let seed_bytes = BASE32_NOPAD
        .decode(anchor.secret_key.to_uppercase().as_bytes())
        .map_err(|e| {
            Error::Identity(format!(
                "decode identity secret_key (expected base32-lowercase nopad): {e}"
            ))
        })?;
    if seed_bytes.len() != SECRET_KEY_LENGTH {
        return Err(Error::Identity(format!(
            "identity secret_key length is {} bytes, expected {}",
            seed_bytes.len(),
            SECRET_KEY_LENGTH
        )));
    }
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    seed.copy_from_slice(&seed_bytes);
    let signing_key = SigningKey::from_bytes(&seed);
    Ok(Identity {
        signing_key,
        public_id: anchor.public_key,
        label: RwLock::new(anchor.label),
    })
}

/// Generate a fresh memorable Network ID. Eight random chars from
/// `[a-z0-9]` — short enough to read over the phone, long enough
/// (36^8 ≈ 2.8 trillion) that accidental collisions don't happen.
/// The Network ID itself doesn't gate access — the per-peer auth
/// handshake does — so it doesn't need to be cryptographically
/// strong. Signaling-side discovery handles are derived by hashing
/// this value.
///
/// Unfunded, and kept that way for embedders with no resource scope. A caller
/// that must fund the retention before the value exists uses
/// [`prepare_generated_network_id`] instead; both draw from one alphabet.
pub fn generate_network_id() -> String {
    let mut bytes = [0u8; GENERATED_NETWORK_ID_CHARS];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|&b| NETWORK_ID_ALPHABET[(b as usize) % NETWORK_ID_ALPHABET.len()] as char)
        .collect()
}

/// Why a Network ID was refused, as a value rather than a sentence.
///
/// Every variant is `Copy` and carries only integers and one `char`, so a
/// caller can answer a refusal without allocating anything — which is the whole
/// point on a path whose *purpose* is to decide whether an allocation may
/// happen at all. A formatted message would put the allocation before the
/// admission it is supposed to be gating.
///
/// The bounds travel *in* the refusal rather than being named again by the
/// caller. A daemon that wrote its own "must be at least 3 characters" would be
/// restating a rule it does not own, and the two would drift the moment the
/// rule changed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkIdRefusal {
    /// Nothing but whitespace.
    Empty,
    /// Shorter than `min` once trimmed. Named in a code span rather than
    /// linked: a variant's fields are not associated items, so an intra-doc
    /// link to one does not resolve.
    Short { found: usize, min: usize },
    /// Longer than `max` once trimmed.
    Long { found: usize, max: usize },
    /// A character outside `[a-z0-9-_]` survived normalization.
    ///
    /// `at` is a byte offset into the *trimmed* input, so a caller can point at
    /// the character without searching for it again.
    IllegalCharacter { at: usize, found: char },
}

impl NetworkIdRefusal {
    /// The refusal as a `&'static str`, for a caller answering without
    /// allocating.
    ///
    /// Deliberately says nothing the variant's own fields already carry: a
    /// caller that wants the offending character or the exact bound reads them
    /// from the value, *after* it has decided it can afford to build a message.
    pub const fn message(&self) -> &'static str {
        match self {
            Self::Empty => "network id is empty",
            Self::Short { .. } => "network id is shorter than the minimum",
            Self::Long { .. } => "network id is longer than the maximum",
            Self::IllegalCharacter { .. } => {
                "network id may contain only letters, digits, '-', and '_'"
            }
        }
    }
}

impl std::fmt::Display for NetworkIdRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("network id is empty"),
            Self::Short { found, min } => {
                write!(
                    f,
                    "network id must be at least {min} characters, got {found}"
                )
            }
            Self::Long { found, max } => {
                write!(
                    f,
                    "network id must be {max} characters or fewer, got {found}"
                )
            }
            Self::IllegalCharacter { at, found } => write!(
                f,
                "network id contains '{found}' at byte {at}; only letters, digits, '-', and '_' \
                 are allowed"
            ),
        }
    }
}

impl std::error::Error for NetworkIdRefusal {}

impl From<NetworkIdRefusal> for Error {
    fn from(refusal: NetworkIdRefusal) -> Self {
        Error::Identity(refusal.to_string())
    }
}

/// One Network ID, and the funding that keeps it.
///
/// Value before lease, for the reason [`crate::config::FundedMeshConfig`] gives:
/// the string is destroyed first and its funding released after, so the claim
/// never describes memory that has already gone.
///
/// Borrowed access only. There is no method handing the `String` out, because a
/// caller holding one would own bytes whose funding had been released with the
/// owner around it — and the raw `String` is exactly what this seam exists to
/// stop escaping.
pub struct FundedNetworkId {
    value: String,
    _typed: ResourceLease,
}

impl FundedNetworkId {
    pub fn get(&self) -> &str {
        &self.value
    }
}

/// What a Network ID will be, measured before it exists.
///
/// The two rules this file owns — the generated length, and the accepted
/// normalized range — decide the size, and neither escapes: a caller learns
/// what to acquire and nothing about how the number was reached. `generate`
/// draws no randomness and `normalize` allocates no string until
/// [`Self::commit`], so a plan that is refused, dropped, or never funded has
/// produced no value at all.
#[must_use = "a prepared network id measures a value that does not exist until it is committed"]
pub struct PreparedNetworkId<'a> {
    source: PreparedNetworkIdSource<'a>,
    typed_retention_claim: ResourceClaim,
    encoding_ceiling: usize,
}

/// What `commit` will build from, held as the *instruction* rather than the
/// result.
///
/// `Generate` carries no bytes because there are none yet: the draw happens at
/// commit, so an unfunded plan consumes no entropy.
enum PreparedNetworkIdSource<'a> {
    Generate,
    /// The exact validated trimmed span, borrowed from the input that was
    /// checked.
    ///
    /// **The borrow is the binding.** An earlier shape recorded an offset and
    /// a length and let `commit` take an input again — which meant any
    /// same-length string reached the lowercase copy without its characters
    /// ever being validated, and bought a `FundedNetworkId` holding a value
    /// this module had never accepted. Holding the `&str` itself makes that
    /// unrepresentable: there is no second input to supply, and the borrow
    /// checker keeps the validated bytes alive until the plan is consumed.
    Normalize(&'a str),
}

impl PreparedNetworkId<'_> {
    /// What retaining the Network ID will cost, for as long as it is held.
    ///
    /// Memory only: one `String` header plus exactly the bytes it will own.
    /// Nothing here prices the work of producing it — a generated id is eight
    /// random bytes and a normalization is a lowercase copy, both of which are
    /// over before the retention begins.
    pub const fn typed_retention_claim(&self) -> ResourceClaim {
        self.typed_retention_claim
    }

    /// Exactly how many bytes this id occupies as a JSON string, quotes
    /// included.
    ///
    /// Exact rather than conservative, and it can be: every accepted character
    /// is one of `[a-z0-9-_]`, none of which JSON escapes, so the encoding is
    /// two quotes around the bytes themselves. A caller sizing a response line
    /// adds its own wrapper to this and nothing else.
    pub const fn encoding_ceiling(&self) -> usize {
        self.encoding_ceiling
    }

    /// Build the id, now that its retention is funded.
    ///
    /// The lease has to be *this plan's* lease. `ResourceLease::claim` is
    /// public, so without this check the prepare-then-acquire discipline would
    /// be a convention a caller could simply not follow: an unrelated lease, or
    /// a zero one, would buy a `FundedNetworkId` whose funding describes
    /// something else. Checked **before** any string is built and before any
    /// randomness is drawn, so a caller that gets it wrong has caused no work
    /// and consumed no entropy.
    ///
    /// A refused lease is dropped rather than handed back, which returns its
    /// capacity to whatever it was taken from. It is not this plan's to return
    /// as this plan's, and holding it would strand capacity on a refusal.
    /// Takes no input, and that is the safety property rather than an
    /// ergonomic one: the only bytes this can build from are the ones
    /// [`prepare_normalized_network_id`] already validated.
    pub fn commit(self, typed_lease: ResourceLease) -> Result<FundedNetworkId> {
        if typed_lease.claim() != self.typed_retention_claim {
            return Err(Error::Identity(
                "network id lease was not taken for this plan's typed retention claim".to_string(),
            ));
        }
        Ok(FundedNetworkId {
            value: self.build(),
            _typed: typed_lease,
        })
    }

    /// The one builder, shared with the unfunded [`normalize_network_id`].
    ///
    /// Private and used by both paths so the funded and unfunded forms cannot
    /// produce different strings for the same input — the only difference
    /// between them is whether a lease was checked first.
    ///
    /// Infallible: everything that could be refused was refused during
    /// planning, and the value it copies from is the one that survived.
    fn build(&self) -> String {
        match self.source {
            // Reserved at exactly the measured capacity. Collecting into a
            // fresh `String` would grow geometrically toward the same size,
            // asking the allocator for capacity nobody funded.
            PreparedNetworkIdSource::Generate => {
                let mut bytes = [0u8; GENERATED_NETWORK_ID_CHARS];
                OsRng.fill_bytes(&mut bytes);
                let mut value = String::with_capacity(GENERATED_NETWORK_ID_CHARS);
                for byte in bytes {
                    value.push(
                        NETWORK_ID_ALPHABET[(byte as usize) % NETWORK_ID_ALPHABET.len()] as char,
                    );
                }
                value
            }
            // The validated span itself, not a coordinate into something the
            // caller supplies again. ASCII lowercasing is length-preserving and
            // every byte was accepted during planning, so the capacity reserved
            // here is the capacity used.
            PreparedNetworkIdSource::Normalize(trimmed) => {
                let mut value = String::with_capacity(trimmed.len());
                for byte in trimmed.bytes() {
                    value.push(byte.to_ascii_lowercase() as char);
                }
                value
            }
        }
    }
}

/// Plan a fresh Network ID without drawing one.
///
/// The generated length is this module's rule, and this is how a caller funds
/// it without knowing it: eight characters is a fact about
/// [`generate_network_id`], not about the caller.
pub fn prepare_generated_network_id() -> Result<PreparedNetworkId<'static>> {
    Ok(PreparedNetworkId {
        source: PreparedNetworkIdSource::Generate,
        typed_retention_claim: retained_short_string_claim(GENERATED_NETWORK_ID_CHARS)?,
        encoding_ceiling: json_string_len(GENERATED_NETWORK_ID_CHARS)?,
    })
}

/// Validate a user-typed Network ID and measure its normalized form, without
/// building it.
///
/// Every rule [`normalize_network_id`] applies is applied here, on the borrowed
/// input: nothing is lowercased, copied or collected, so a refusal costs one
/// pass over the caller's own bytes and no allocation at all. That ordering is
/// the finding — the old path lowercased into a fresh `String` and only then
/// decided whether the value was acceptable, so the refusal arrived after the
/// allocation it was supposed to prevent.
///
/// Length is measured in bytes and that is exact rather than approximate: an
/// accepted id is ASCII by construction, so bytes and characters coincide, and
/// ASCII lowercasing cannot change the length. A non-ASCII character is refused
/// before it can make the two disagree.
pub fn prepare_normalized_network_id(
    input: &str,
) -> std::result::Result<PreparedNetworkId<'_>, NetworkIdRefusal> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(NetworkIdRefusal::Empty);
    }
    let len = trimmed.len();
    if len < MIN_NETWORK_ID_BYTES {
        return Err(NetworkIdRefusal::Short {
            found: len,
            min: MIN_NETWORK_ID_BYTES,
        });
    }
    if len > MAX_NETWORK_ID_BYTES {
        return Err(NetworkIdRefusal::Long {
            found: len,
            max: MAX_NETWORK_ID_BYTES,
        });
    }
    for (offset, character) in trimmed.char_indices() {
        // The class is asked of the lowercased character, because that is what
        // the value will be. For ASCII the two agree, and a non-ASCII character
        // fails this test whichever case it is in — so the answer is the same
        // one the lowercase-first rule gave, reached without the copy.
        let lowered = character.to_ascii_lowercase();
        if !(lowered.is_ascii_alphanumeric() || lowered == '-' || lowered == '_') {
            return Err(NetworkIdRefusal::IllegalCharacter {
                at: offset,
                found: character,
            });
        }
    }
    let not_representable = || NetworkIdRefusal::Long {
        found: len,
        max: MAX_NETWORK_ID_BYTES,
    };
    Ok(PreparedNetworkId {
        source: PreparedNetworkIdSource::Normalize(trimmed),
        typed_retention_claim: retained_short_string_claim(len).map_err(|_| not_representable())?,
        encoding_ceiling: json_string_len(len).map_err(|_| not_representable())?,
    })
}

/// What one retained short id costs: the `String` header, its bytes, and the
/// single allocation behind it.
///
/// One function so no two plans can price the same shape differently.
fn retained_short_string_claim(len: usize) -> Result<ResourceClaim> {
    let not_representable =
        || Error::Identity("network id retention claim is not representable".to_string());
    let bytes = std::mem::size_of::<String>()
        .checked_add(len)
        .ok_or_else(not_representable)?;
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes).map_err(|_| not_representable())?,
        ),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
    .map_err(|_| not_representable())
}

/// The encoded length of `len` unescaped bytes as a JSON string.
fn json_string_len(len: usize) -> Result<usize> {
    len.checked_add(2).ok_or_else(|| {
        Error::Identity("network id encoding ceiling is not representable".to_string())
    })
}

/// Normalize a user-typed Network ID. Trims whitespace, lowercases,
/// and validates that every character is alphanumeric, `-`, or `_`.
/// Length is enforced to 3–64 chars — long enough to be unambiguous,
/// short enough to share verbally. Returned string is the canonical
/// form we persist and compare against; the signaling discovery
/// handle is derived by hashing this value.
///
/// Unfunded, for embedders with no resource scope, and it is the *same* rule as
/// [`prepare_normalized_network_id`] rather than a second copy of it: this
/// validates through that plan and then runs the plan's own builder. A rule
/// that lived in two places would eventually be two rules, and the funded path
/// would accept ids the unfunded one refused.
///
/// One behavioural difference from the version this replaces, and it is the
/// point of the change: nothing is allocated until the input has been accepted.
/// The old form lowercased into a fresh `String` first and validated afterwards,
/// so every refusal paid for a copy it then threw away.
pub fn normalize_network_id(input: &str) -> Result<String> {
    Ok(prepare_normalized_network_id(input)?.build())
}

/// Update the stored label on the anchor file. Re-reads the anchor to
/// avoid clobbering fields a future migration may have added.
pub fn set_label(label: &str) -> Result<()> {
    let path = anchor_path()?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::Identity(format!("read identity anchor at {}: {e}", path.display())))?;
    let mut anchor: Anchor = serde_json::from_str(&raw)?;
    anchor.label = label.to_string();
    let serialized = serde_json::to_string_pretty(&anchor)?;
    crate::persist::write_atomic(&path, serialized.as_bytes()).map_err(|e| {
        Error::Identity(format!("write identity anchor to {}: {e}", path.display()))
    })?;
    restrict_file_permissions(&path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| Error::io(path.to_path_buf(), e))?
        .permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(path, perms).map_err(|e| Error::io(path.to_path_buf(), e))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| Error::io(path.to_path_buf(), e))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| Error::io(path.to_path_buf(), e))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_path: &Path) -> Result<()> {
    // Windows: rely on the default ACL of the user profile, which
    // restricts access to the user. A future hardening pass can apply
    // a SetSecurityInfo call to remove inherited entries.
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Minimal timestamp formatter so we don't take a `chrono` dependency
/// just for the anchor's `created_at` field. The value is informational
/// only; nothing reads or compares it.
fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("@{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused Network ID allocates nothing, and the refusal says which rule
    /// it broke without formatting a sentence.
    ///
    /// The finding is the ordering: the version this replaces lowercased into a
    /// fresh `String` and validated afterwards, so every refusal paid for a
    /// copy it discarded. A typed refusal is what makes "nothing was built"
    /// checkable at all — an `Error::Identity(String)` would itself be the
    /// allocation the plan is supposed to be deciding about.
    #[test]
    fn v4_r3_core_f7_a_refused_network_id_plan_builds_nothing() {
        // Matched rather than `unwrap_err`ed. The success type is the plan
        // itself, which is deliberately not `Debug` — a resource plan that could
        // be printed is one whose private sizing has a representation — and
        // `Result::unwrap_err` would demand exactly that.
        fn refusal(input: &str) -> NetworkIdRefusal {
            match prepare_normalized_network_id(input) {
                Ok(_plan) => panic!("{input:?} must not plan"),
                Err(refusal) => refusal,
            }
        }

        assert_eq!(refusal("   "), NetworkIdRefusal::Empty);
        assert_eq!(
            refusal("ab"),
            NetworkIdRefusal::Short {
                found: 2,
                min: MIN_NETWORK_ID_BYTES
            },
            "the bound travels in the refusal, so no caller has to restate it"
        );
        let too_long = "a".repeat(MAX_NETWORK_ID_BYTES + 1);
        assert_eq!(
            refusal(&too_long),
            NetworkIdRefusal::Long {
                found: MAX_NETWORK_ID_BYTES + 1,
                max: MAX_NETWORK_ID_BYTES
            }
        );
        assert_eq!(
            refusal("  not space!  "),
            NetworkIdRefusal::IllegalCharacter { at: 3, found: ' ' },
            "the offset is into the trimmed span, so a caller can point at the \
             character without searching for it again"
        );
        // Every refusal answers with a `&'static str` and nothing is formatted
        // to get one.
        assert_eq!(
            NetworkIdRefusal::Empty.message(),
            "network id is empty",
            "non-vacuity: the static message is reachable without Display, so a \
             refusal costs no allocation"
        );
    }

    /// The full funded round trip, against a real provider ledger.
    ///
    /// Everything above observes the *plan*; this observes the **provider**,
    /// which is the only place "nothing was spent" is a fact rather than a
    /// claim about a claim. A finite grant is opened, the ledger is read at
    /// every boundary, and the value is only ever reached through the owner.
    ///
    /// Three things are discriminated: a lease taken for the **wrong** claim
    /// buys nothing and strands nothing; a lease taken for **this plan's** claim
    /// commits exactly once to a value that encodes to exactly the quoted
    /// ceiling; and dropping the owner returns the ledger to its pre-commit
    /// baseline, so the retention was tied to the owner's life rather than
    /// leaked.
    #[test]
    fn v4_r3_core_f7_a_funded_network_id_commit_spends_exactly_its_plan() {
        use crate::resource::provider::{
            FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort,
        };

        let provider = FiniteResourceProvider::new(
            ResourceClaim::try_from_entries([
                (ResourceClass::AccountedMemoryBytes, 4096),
                (ResourceClass::OpaqueDependencyResidual, 64),
            ])
            .expect("the fixture grant is representable"),
        );
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let process_scope = port.process_scope();
        let scope = port
            .create_scope(&process_scope)
            .expect("one fixture scope");
        let baseline = provider.in_use();

        let input = "  Office-Mesh_1  ";
        let plan = prepare_normalized_network_id(input).expect("a legal id plans");
        assert_eq!(
            provider.in_use(),
            baseline,
            "non-vacuity for everything below: planning moved the ledger not at \
             all, so the plan built nothing"
        );
        let ceiling = plan.encoding_ceiling();
        let claim = plan.typed_retention_claim();

        // A lease for a different claim, and deliberately a *larger* one: a
        // build that ignored the check would have had room to succeed.
        let wrong = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                claim
                    .checked_add(ResourceClaim::single(
                        ResourceClass::AccountedMemoryBytes,
                        1,
                    ))
                    .expect("the mismatched claim is representable"),
            )
            .expect("the fixture grant funds the mismatched lease");
        assert!(
            plan.commit(wrong).is_err(),
            "a lease taken for another claim buys no funded id, however roomy"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "and the refused lease was dropped rather than stranded, so its \
             capacity went back"
        );

        // The right lease.
        let plan = prepare_normalized_network_id(input).expect("the same input plans again");
        let typed = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, claim)
            .expect("the fixture grant funds this plan's retention");
        let funded_baseline = provider.in_use();
        assert_ne!(
            funded_baseline, baseline,
            "non-vacuity: the retention this plan priced is really held"
        );
        let owner = plan.commit(typed).expect("the exact lease commits");
        assert_eq!(
            owner.get(),
            "office-mesh_1",
            "one commit, one value, reached only through the owner"
        );
        assert_eq!(
            serde_json::to_string(owner.get())
                .expect("a funded id encodes")
                .len(),
            ceiling,
            "and it encodes to exactly the ceiling quoted before it existed"
        );
        assert_eq!(
            provider.in_use(),
            funded_baseline,
            "committing spent nothing beyond the lease already acquired: the \
             build happens inside the funding, not alongside it"
        );

        drop(owner);
        assert_eq!(
            provider.in_use(),
            baseline,
            "and the retention ends with the owner"
        );
    }

    /// The plan measures exactly what the commit builds — for both sources.
    ///
    /// `encoding_ceiling` is asserted against `serde_json`'s own output rather
    /// than against arithmetic repeated here, because a ceiling that agreed
    /// with a second copy of the same formula would prove only that the formula
    /// was copied correctly.
    #[test]
    fn v4_r3_core_f7_a_network_id_plan_measures_what_it_will_build() {
        let input = "  Office-Mesh_1  ";
        let plan = prepare_normalized_network_id(input).expect("a legal id plans");
        let ceiling = plan.encoding_ceiling();
        let claim = plan.typed_retention_claim();
        let built = normalize_network_id(input).expect("and the same id normalizes");
        assert_eq!(built, "office-mesh_1");
        assert_eq!(
            serde_json::to_string(&built)
                .expect("a network id encodes as a JSON string")
                .len(),
            ceiling,
            "the ceiling is the exact encoded length: every accepted character              is one JSON never escapes"
        );
        assert_eq!(
            claim,
            retained_short_string_claim(built.len()).expect("the built claim is representable"),
            "and the retention priced is the retention taken"
        );

        let generated = prepare_generated_network_id().expect("a generated id plans");
        assert_eq!(
            generated.encoding_ceiling(),
            GENERATED_NETWORK_ID_CHARS + 2,
            "the generated length is this module's rule, answered without              drawing anything"
        );
        let drawn = generate_network_id();
        assert_eq!(
            serde_json::to_string(&drawn)
                .expect("a generated id encodes")
                .len(),
            generated.encoding_ceiling(),
            "non-vacuity: an actually generated id encodes to exactly the size              the plan quoted before generating one"
        );
    }

    /// The funded and unfunded paths cannot disagree about what is legal.
    ///
    /// One rule and one builder: `normalize_network_id` is implemented through
    /// the plan, so an id the plan refuses is an id the unfunded call refuses,
    /// with no second copy of the character class to drift.
    #[test]
    fn v4_r3_core_f7_the_funded_and_unfunded_network_id_rules_are_one_rule() {
        for input in ["", "  ", "ab", "not space!", "hello world", "Ünicode"] {
            assert!(
                prepare_normalized_network_id(input).is_err(),
                "the plan refuses {input:?}"
            );
            assert!(
                normalize_network_id(input).is_err(),
                "and so does the unfunded path, because it is the same rule"
            );
        }
        for input in ["office-mesh", "  Office-Mesh  ", "my_net_1", "ab12"] {
            let planned = prepare_normalized_network_id(input).is_ok();
            assert!(planned, "the plan accepts {input:?}");
            assert_eq!(
                planned,
                normalize_network_id(input).is_ok(),
                "and the two agree on every accepted input too"
            );
        }
    }

    /// The display form's length is answerable without producing it.
    ///
    /// Asserted against the real `display_id`, so a layout change that moved
    /// the separator or the suffix width would fail here rather than silently
    /// under-size a caller's buffer.
    #[test]
    fn v4_r3_core_f7_display_id_length_is_exact_without_building_it() {
        let identity = Identity::ephemeral();
        assert_eq!(
            identity.display_id_len(),
            identity.display_id().len(),
            "the arithmetic answer and the built string agree"
        );
        assert_eq!(
            display_suffix(identity.public_id().as_bytes()).len(),
            DISPLAY_SUFFIX_CHARS,
            "non-vacuity: the constant the length uses is the width the suffix              actually has"
        );
    }

    #[test]
    fn v4_r3_core_f7_the_inline_and_owned_display_suffixes_are_one_suffix() {
        let identity = Identity::ephemeral();
        let pubkey = identity.public_id().as_bytes();
        let owned = display_suffix(pubkey);
        let inline = display_suffix_bytes(pubkey);

        assert_eq!(
            owned.as_bytes(),
            &inline[..],
            "a caller publishing the inline form shows the same tag as one \
             publishing the owned form"
        );
        assert!(
            owned
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()),
            "non-vacuity: both forms are the uppercase-hex rendering, so the \
             agreement above is not two functions agreeing on empty output"
        );
        // Exactness is why the inline form exists. A `String` whose capacity
        // exceeded its length would be a row term nobody could quote before
        // building it.
        assert_eq!(
            owned.capacity(),
            DISPLAY_SUFFIX_CHARS,
            "the owned form allocates its length and no growth-rule slack"
        );
    }

    #[test]
    fn normalize_round_trips_simple_input() {
        let normed = normalize_network_id("office-mesh").unwrap();
        assert_eq!(normed, "office-mesh");
    }

    #[test]
    fn normalize_trims_and_lowercases() {
        assert_eq!(
            normalize_network_id("  Office-Mesh  ").unwrap(),
            "office-mesh"
        );
    }

    #[test]
    fn normalize_accepts_letters_digits_dash_underscore() {
        assert_eq!(normalize_network_id("my_net_1").unwrap(), "my_net_1");
        assert_eq!(normalize_network_id("ab12").unwrap(), "ab12");
    }

    #[test]
    fn normalize_rejects_garbage() {
        assert!(normalize_network_id("").is_err());
        // Too short
        assert!(normalize_network_id("ab").is_err());
        // Too long (65 chars)
        assert!(normalize_network_id(&"a".repeat(65)).is_err());
        // Disallowed character
        assert!(normalize_network_id("not space!").is_err());
        assert!(normalize_network_id("hello world").is_err());
    }

    #[test]
    fn generate_produces_valid_id() {
        for _ in 0..50 {
            let id = generate_network_id();
            assert_eq!(id.len(), 8);
            // Round-trip: anything generate() emits must pass normalize().
            assert_eq!(normalize_network_id(&id).unwrap(), id);
        }
    }

    #[test]
    fn display_suffix_is_5_uppercase_hex() {
        let bytes = b"some-base32-pubkey-string";
        let suffix = display_suffix(bytes);
        assert_eq!(suffix.len(), 5);
        // Uppercase hex only: [0-9A-F]
        assert!(suffix
            .chars()
            .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)));
    }

    #[test]
    fn display_suffix_is_deterministic() {
        let bytes = [7u8; 32];
        assert_eq!(display_suffix(&bytes), display_suffix(&bytes));
    }

    #[test]
    fn display_suffix_differs_across_pubkeys() {
        // Astronomically unlikely to collide on 5 chars of sha256
        // output, but assert so a future refactor that breaks the
        // determinism (or accidentally returns a constant) fails loud.
        let a = display_suffix(&[1u8; 32]);
        let b = display_suffix(&[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn normalize_device_id_collapses_wire_and_display_forms() {
        let identity = Identity::ephemeral();
        let raw = identity.public_id();
        assert_eq!(normalize_device_id(raw).unwrap(), raw);
        assert_eq!(
            normalize_device_id(&format!("  {}  ", raw.to_ascii_uppercase())).unwrap(),
            raw
        );
        assert_eq!(normalize_device_id(&identity.display_id()).unwrap(), raw);
        assert_eq!(
            normalize_device_id(&identity.display_id().to_ascii_lowercase()).unwrap(),
            raw
        );
    }

    #[test]
    fn normalize_device_id_rejects_malformed_or_mistyped_forms() {
        let identity = Identity::ephemeral();
        assert!(normalize_device_id("").is_err());
        assert!(normalize_device_id("peer-a").is_err());
        assert!(normalize_device_id(&format!("{}-00000", identity.public_id())).is_err());
        assert!(normalize_device_id(&"0".repeat(52)).is_err());
    }
}
