//! Canonical, transport-independent V4 semantic content.
//!
//! Authority-bearing values in this module are deliberately typed.  A display
//! label, carrier spelling, or alternate serialization cannot become a second
//! semantic identity or exclusive-cell key.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::VerifyingKey;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use super::FactId;

/// Domain separation for the adopted V4 durable fact union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactDomain {
    Governance,
    EvictionProof,
}

impl FactDomain {
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::EvictionProof => "eviction_proof",
        }
    }
}

/// The only authority-bearing device identity accepted by canonical facts.
///
/// This is the raw Ed25519 public key in its canonical lowercase base32 form.
/// Display suffixes, uppercase encodings, padding, and alternate base32 forms
/// are rejected before a value can enter a fact or cell.
#[derive(Clone)]
pub struct DeviceId(Arc<DeviceIdInner>);

struct DeviceIdInner {
    bytes: [u8; 32],
    canonical: Box<str>,
}

#[derive(Default)]
struct DeviceIdInterner {
    entries: HashMap<[u8; 32], Weak<DeviceIdInner>>,
    insertions_since_cleanup: usize,
}

fn intern_device_id(bytes: [u8; 32], canonical: String) -> DeviceId {
    static INTERNER: OnceLock<Mutex<DeviceIdInterner>> = OnceLock::new();
    const CLEANUP_INTERVAL: usize = 1_024;

    let interner = INTERNER.get_or_init(|| Mutex::new(DeviceIdInterner::default()));
    let mut interner = interner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = interner.entries.get(&bytes).and_then(Weak::upgrade) {
        return DeviceId(existing);
    }
    if interner.insertions_since_cleanup >= CLEANUP_INTERVAL {
        interner
            .entries
            .retain(|_, value| value.strong_count() != 0);
        interner.insertions_since_cleanup = 0;
    }
    let value = Arc::new(DeviceIdInner {
        bytes,
        canonical: canonical.into_boxed_str(),
    });
    interner.entries.insert(bytes, Arc::downgrade(&value));
    interner.insertions_since_cleanup += 1;
    DeviceId(value)
}

impl PartialEq for DeviceId {
    fn eq(&self, other: &Self) -> bool {
        self.0.bytes == other.0.bytes
    }
}

impl Eq for DeviceId {}

impl PartialOrd for DeviceId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DeviceId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Preserve the public canonical-identifier ordering used before the
        // backing allocation was interned. Raw key-byte ordering is not the
        // same ordering as lowercase base32 and can change canonical fact
        // encoding, B-tree iteration, and deterministic rebuild results.
        self.0.canonical.cmp(&other.0.canonical)
    }
}

impl Hash for DeviceId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.bytes.hash(state);
    }
}

/// Signed, typed authority lineage for one authority-bearing subject.  The
/// predecessor list is part of FactContent (and therefore of FactId), so a
/// receiver cannot silently substitute a later or unrelated role head.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityUse {
    pub subject: DeviceId,
    pub predecessors: Vec<FactId>,
}

impl AuthorityUse {
    pub(crate) fn new(subject: DeviceId, mut predecessors: Vec<FactId>) -> Self {
        predecessors.sort();
        predecessors.dedup();
        Self {
            subject,
            predecessors,
        }
    }
}

/// The semantic owner's typed authority relation for one subject.
///
/// `heads` is the complete current AuthorityUse head set, calculated from the
/// causal graph rather than copied from a caller. An ordinary operation is
/// authorizable only when this relation is singular (or empty for the
/// bootstrap root). A typed `AuthorityLineageResolution` may cite the
/// complete conflicting set and select one branch; once admitted, that
/// resolution is itself the sole lineage head for descendants and re-grants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityLineage {
    subject: DeviceId,
    heads: Vec<FactId>,
    selected_branch: Option<FactId>,
}

impl AuthorityLineage {
    pub(crate) fn from_heads(
        subject: DeviceId,
        mut heads: Vec<FactId>,
        selected_branch: Option<FactId>,
    ) -> Self {
        heads.sort();
        heads.dedup();
        Self {
            subject,
            heads,
            selected_branch,
        }
    }

    pub fn subject(&self) -> &DeviceId {
        &self.subject
    }

    pub fn heads(&self) -> &[FactId] {
        &self.heads
    }

    pub fn effective_head(&self) -> Option<FactId> {
        (self.heads.len() == 1).then_some(self.heads[0])
    }

    /// Return the branch selected by the effective typed resolution, when
    /// this lineage descends from one. The selection remains attached to the
    /// subject relation even after a later regrant replaces the raw head.
    pub fn selected_branch(&self) -> Option<FactId> {
        self.selected_branch
    }

    /// Whether this relation has at most one effective head. An empty
    /// relation is the bootstrap state; an ordinary relation must be
    /// singular before it can authorize another ordinary operation.
    pub fn is_singular(&self) -> bool {
        self.heads.len() <= 1
    }

    /// Return the complete conflict set when this relation is forked. A
    /// lineage resolution must cite this exact set.
    pub fn complete_conflict_set(&self) -> Option<&[FactId]> {
        self.is_conflicted().then_some(self.heads.as_slice())
    }

    pub fn is_conflicted(&self) -> bool {
        self.heads.len() > 1
    }
}

impl DeviceId {
    /// Validate a wire identity without allocating or consulting the interner.
    ///
    /// Input length is checked before scanning. Scratch is fixed: two 52-byte
    /// encoding buffers and one 32-byte key, plus Ed25519 validation's bounded
    /// arithmetic. Accepted spellings and key validation match the ordinary
    /// constructor; errors here are static rather than allocated descriptions.
    pub(crate) fn canonical_key_bytes(value: &str) -> Result<[u8; 32], &'static str> {
        if value.len() != 52 {
            return Err("DeviceId must contain exactly 52 canonical base32 bytes");
        }
        let mut upper = [0u8; 52];
        for (encoded, byte) in upper.iter_mut().zip(value.bytes()) {
            if !matches!(byte, b'a'..=b'z' | b'2'..=b'7') {
                return Err("DeviceId must use lowercase unpadded base32");
            }
            *encoded = byte.to_ascii_uppercase();
        }
        let mut key = [0u8; 32];
        let decoded = BASE32_NOPAD
            .decode_mut(&upper, &mut key)
            .map_err(|_| "DeviceId is not canonical base32")?;
        if decoded != key.len() {
            return Err("DeviceId must decode to 32 bytes");
        }
        let mut canonical = [0u8; 52];
        BASE32_NOPAD.encode_mut(&key, &mut canonical);
        canonical.make_ascii_lowercase();
        if canonical.as_slice() != value.as_bytes() {
            return Err("DeviceId is not the canonical base32 spelling");
        }
        VerifyingKey::from_bytes(&key).map_err(|_| "invalid Ed25519 public key")?;
        Ok(key)
    }

    /// Construct frame-owned identity backing, never global interner state.
    ///
    /// Callers admit the backing and surrounding frame work before this call
    /// and retain that funding through every clone of the returned identity.
    /// Malformed input is rejected before either heap allocation is made.
    pub(crate) fn from_canonical_str_uninterned(value: &str) -> Result<Self, &'static str> {
        let bytes = Self::canonical_key_bytes(value)?;
        Ok(Self(Arc::new(DeviceIdInner {
            bytes,
            canonical: Box::<str>::from(value),
        })))
    }

    /// Logical backing bytes for one uninterned identity's two allocations.
    ///
    /// Includes private inner layout, Arc strong/weak counters and the exact
    /// 52-byte string. Excludes the containing DeviceId pointer (already in the
    /// caller's DTO), allocator overhead, provider reservation bookkeeping and
    /// stack scratch. The caller separately prices two allocation residuals.
    /// This is not an RSS measurement or a lease acquisition.
    pub(crate) const fn uninterned_backing_bytes() -> usize {
        std::mem::size_of::<DeviceIdInner>()
            + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
            + 52
    }

    /// Test-only observation; drop the probe to release its weak Arc tail.
    #[cfg(test)]
    pub(crate) fn backing_liveness_for_test(&self) -> impl Fn() -> bool + 'static {
        let weak = Arc::downgrade(&self.0);
        move || weak.strong_count() != 0
    }

    pub fn from_public_key_bytes(bytes: [u8; 32]) -> Result<Self, String> {
        VerifyingKey::from_bytes(&bytes)
            .map_err(|error| format!("invalid Ed25519 public key: {error}"))?;
        let canonical = BASE32_NOPAD.encode(&bytes).to_lowercase();
        Ok(intern_device_id(bytes, canonical))
    }

    pub fn from_canonical_str(value: &str) -> Result<Self, String> {
        if value.is_empty() || value != value.to_lowercase() {
            return Err("DeviceId must use lowercase unpadded base32".into());
        }
        let bytes = BASE32_NOPAD
            .decode(value.to_uppercase().as_bytes())
            .map_err(|error| format!("DeviceId is not canonical base32: {error}"))?;
        if bytes.len() != 32 {
            return Err("DeviceId must decode to 32 bytes".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid Ed25519 public key: {error}"))?;
        let canonical = BASE32_NOPAD.encode(&key).to_lowercase();
        if canonical != value {
            return Err("DeviceId is not the canonical base32 spelling".into());
        }
        Ok(intern_device_id(key, canonical))
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.bytes
    }

    pub fn base32(&self) -> String {
        self.0.canonical.to_string()
    }
}

impl std::ops::Deref for DeviceId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0.canonical
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DeviceId").field(&self.0.canonical).finish()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.canonical)
    }
}

impl Serialize for DeviceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.canonical)
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_canonical_str(&value).map_err(D::Error::custom)
    }
}

/// V4 role tier.  The selected Closed profile determines which tier may
/// author each governance operation; the fact body does not flatten that rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Controller,
    Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationDecision {
    Evict,
    Approve,
    Reject,
}

/// Closed typed union of semantic cells.  The subject type is fixed by the
/// variant, so a free-form `(subject, field)` pair cannot alias authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ExclusiveCell {
    Role { subject: DeviceId },
    Membership { subject: DeviceId },
    Decision { proposal: FactId },
}

impl ExclusiveCell {
    pub fn role(subject: DeviceId) -> Self {
        Self::Role { subject }
    }

    pub fn membership(subject: DeviceId) -> Self {
        Self::Membership { subject }
    }

    pub fn decision(proposal: FactId) -> Self {
        Self::Decision { proposal }
    }

    pub(crate) fn encode(&self, out: &mut Encoder) {
        match self {
            Self::Role { subject } => {
                out.tag("role");
                out.device(subject);
            }
            Self::Membership { subject } => {
                out.tag("membership");
                out.device(subject);
            }
            Self::Decision { proposal } => {
                out.tag("decision");
                out.id(*proposal);
            }
        }
    }
}

impl fmt::Display for ExclusiveCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Role { subject } => write!(f, "role:{subject}"),
            Self::Membership { subject } => write!(f, "membership:{subject}"),
            Self::Decision { proposal } => write!(f, "decision:{proposal}"),
        }
    }
}

/// The adopted V4 durable semantic union.  Context selection, topology, and
/// compaction evidence are outside this ordinary fact graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum FactBody {
    RoleGrant {
        target: DeviceId,
        role: Role,
    },
    RoleRevoke {
        target: DeviceId,
    },
    Evict {
        target: DeviceId,
    },
    /// Controller-authorized Closed membership restoration. Role authority
    /// remains a separate role-cell fact and must be carried causally when
    /// both are needed to restore session admission.
    MembershipAdmit {
        target: DeviceId,
    },
    EvictionProof {
        target: DeviceId,
        evidence: Vec<FactId>,
    },
    SelfStandDown {
        device_id: DeviceId,
        evidence: Vec<FactId>,
    },
    Attestation {
        target: DeviceId,
        proposal: FactId,
        decision: AttestationDecision,
        signer: DeviceId,
        contributions: Vec<FactId>,
    },
    Resolution {
        cell: ExclusiveCell,
        cited_heads: Vec<FactId>,
        selected_head: FactId,
    },
    /// Explicit selector for a subject's AuthorityLineage. Unlike an
    /// ordinary cell resolution, this relation may cite heads from different
    /// exclusive cells, but it must carry the complete current lineage set.
    AuthorityLineageResolution {
        subject: DeviceId,
        cited_heads: Vec<FactId>,
        selected_head: FactId,
    },
}

impl FactBody {
    pub fn normalize(&mut self) {
        match self {
            Self::EvictionProof { evidence, .. }
            | Self::SelfStandDown { evidence, .. }
            | Self::Attestation {
                contributions: evidence,
                ..
            }
            | Self::Resolution {
                cited_heads: evidence,
                ..
            } => {
                evidence.sort();
                evidence.dedup();
            }
            Self::AuthorityLineageResolution {
                cited_heads: evidence,
                ..
            } => {
                evidence.sort();
                evidence.dedup();
            }
            _ => {}
        }
    }

    pub(crate) fn validate_canonical(&self) -> Result<(), super::SemanticError> {
        match self {
            Self::EvictionProof { evidence, .. } | Self::SelfStandDown { evidence, .. } => {
                if evidence.is_empty() {
                    return Err(super::SemanticError::IncompleteEvictionProof);
                }
                require_sorted_unique(evidence, "eviction evidence")
            }
            Self::Attestation { contributions, .. } => {
                require_sorted_unique(contributions, "attestation contributions")
            }
            Self::Resolution { cited_heads, .. }
            | Self::AuthorityLineageResolution { cited_heads, .. } => {
                require_sorted_unique(cited_heads, "resolution cited heads")
            }
            _ => Ok(()),
        }
    }

    pub fn domain(&self) -> FactDomain {
        match self {
            Self::EvictionProof { .. } | Self::SelfStandDown { .. } => FactDomain::EvictionProof,
            _ => FactDomain::Governance,
        }
    }

    pub fn exclusive_cells(&self) -> Vec<ExclusiveCell> {
        match self {
            Self::RoleGrant { target, .. } | Self::RoleRevoke { target } => {
                vec![ExclusiveCell::role(target.clone())]
            }
            Self::Evict { target } => vec![
                ExclusiveCell::role(target.clone()),
                ExclusiveCell::membership(target.clone()),
            ],
            Self::MembershipAdmit { target } => {
                vec![ExclusiveCell::membership(target.clone())]
            }
            Self::EvictionProof { .. } | Self::SelfStandDown { .. } => Vec::new(),
            Self::Attestation { proposal, .. } => vec![ExclusiveCell::decision(*proposal)],
            Self::Resolution { cell, .. } => vec![cell.clone()],
            Self::AuthorityLineageResolution { .. } => Vec::new(),
        }
    }

    pub(crate) fn authority_use_subjects(&self, author: &DeviceId) -> Vec<DeviceId> {
        let mut subjects = match self {
            Self::RoleGrant { target, .. }
            | Self::RoleRevoke { target }
            | Self::Evict { target } => vec![author.clone(), target.clone()],
            Self::MembershipAdmit { target } | Self::EvictionProof { target, .. } => {
                vec![author.clone(), target.clone()]
            }
            Self::SelfStandDown { device_id, .. } => vec![author.clone(), device_id.clone()],
            Self::Attestation { .. } => vec![author.clone()],
            Self::Resolution { cell, .. } => {
                let mut subjects = vec![author.clone()];
                match cell {
                    ExclusiveCell::Role { subject } | ExclusiveCell::Membership { subject } => {
                        subjects.push(subject.clone())
                    }
                    ExclusiveCell::Decision { .. } => {}
                }
                subjects
            }
            Self::AuthorityLineageResolution { subject, .. } => {
                vec![author.clone(), subject.clone()]
            }
        };
        subjects.sort();
        subjects.dedup();
        subjects
    }

    /// Return the non-cell facts that must be in the causal past of this
    /// body.  Exclusive-cell predecessors come from `FactGraph`'s
    /// authoring witness; evidence and cited heads are body-owned support and
    /// must be carried explicitly as parents as well.
    pub fn causal_support(&self) -> Vec<FactId> {
        let mut support = match self {
            Self::EvictionProof { evidence, .. } | Self::SelfStandDown { evidence, .. } => {
                evidence.clone()
            }
            Self::Attestation {
                proposal,
                contributions,
                ..
            } => {
                let mut ids = vec![*proposal];
                ids.extend(contributions.iter().copied());
                ids
            }
            Self::Resolution { cited_heads, .. }
            | Self::AuthorityLineageResolution { cited_heads, .. } => cited_heads.clone(),
            _ => Vec::new(),
        };
        support.sort();
        support.dedup();
        support
    }

    pub(crate) fn encode(&self, out: &mut Encoder) {
        match self {
            Self::RoleGrant { target, role } => {
                out.tag("role_grant");
                out.device(target);
                out.tag(match role {
                    Role::Member => "member",
                    Role::Controller => "controller",
                    Role::Owner => "owner",
                });
            }
            Self::RoleRevoke { target } => {
                out.tag("role_revoke");
                out.device(target);
            }
            Self::Evict { target } => {
                out.tag("evict");
                out.device(target);
            }
            Self::MembershipAdmit { target } => {
                out.tag("membership_admit");
                out.device(target);
            }
            Self::EvictionProof { target, evidence } => {
                out.tag("eviction_proof");
                out.device(target);
                out.list_ids(evidence);
            }
            Self::SelfStandDown {
                device_id,
                evidence,
            } => {
                out.tag("self_stand_down");
                out.device(device_id);
                out.list_ids(evidence);
            }
            Self::Attestation {
                target,
                proposal,
                decision,
                signer,
                contributions,
            } => {
                out.tag("attestation");
                out.device(target);
                out.id(*proposal);
                out.tag(match decision {
                    AttestationDecision::Evict => "evict",
                    AttestationDecision::Approve => "approve",
                    AttestationDecision::Reject => "reject",
                });
                out.device(signer);
                out.list_ids(contributions);
            }
            Self::Resolution {
                cell,
                cited_heads,
                selected_head,
            } => {
                out.tag("resolution");
                cell.encode(out);
                out.list_ids(cited_heads);
                out.id(*selected_head);
            }
            Self::AuthorityLineageResolution {
                subject,
                cited_heads,
                selected_head,
            } => {
                out.tag("authority_lineage_resolution");
                out.device(subject);
                out.list_ids(cited_heads);
                out.id(*selected_head);
            }
        }
    }
}

fn require_sorted_unique<T: Ord>(
    values: &[T],
    field: &'static str,
) -> Result<(), super::SemanticError> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(super::SemanticError::NonCanonicalSet(field))
    }
}

/// Small length-delimited canonical encoder.  Length prefixes prevent field
/// concatenation ambiguity without relying on a serializer's map ordering.
pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn tag(&mut self, value: &str) {
        self.text(value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.bytes
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.bytes
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn id(&mut self, value: FactId) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn device(&mut self, value: &DeviceId) {
        self.bytes.extend_from_slice(&value.as_bytes());
    }

    pub(crate) fn context(&mut self, value: super::MeshContextId) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn list_ids(&mut self, values: &[FactId]) {
        self.bytes
            .extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            self.id(*value);
        }
    }

    pub(crate) fn list_authority_uses(&mut self, values: &[AuthorityUse]) {
        self.bytes
            .extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            self.device(&value.subject);
            self.list_ids(&value.predecessors);
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceId {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap()
    }

    #[test]
    fn device_aliases_are_rejected_before_fact_construction() {
        let canonical = device().base32();
        assert!(DeviceId::from_canonical_str(&canonical).is_ok());
        assert!(DeviceId::from_canonical_str(&canonical.to_uppercase()).is_err());
        assert!(DeviceId::from_canonical_str(&format!("{canonical}-label")).is_err());
        assert!(DeviceId::from_canonical_str(&format!("{canonical}=")).is_err());
    }

    #[test]
    fn bounded_device_validation_matches_ordinary_canonical_acceptance() {
        for seed in [11, 37, 91, 173] {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            let key = signing.verifying_key().to_bytes();
            let canonical = BASE32_NOPAD.encode(&key).to_ascii_lowercase();
            assert_eq!(DeviceId::canonical_key_bytes(&canonical), Ok(key));
            let owned = DeviceId::from_canonical_str_uninterned(&canonical).unwrap();
            assert_eq!(owned, DeviceId::from_canonical_str(&canonical).unwrap());
            let mut bad_tail = canonical.clone();
            bad_tail.replace_range(51..52, "b");
            for invalid in [
                String::new(),
                canonical[..51].to_owned(),
                format!("{canonical}a"),
                canonical.to_ascii_uppercase(),
                format!("{canonical}="),
                format!("{canonical}-label"),
                format!(" {}", &canonical[1..]),
                format!("0{}", &canonical[1..]),
                format!("é{}", &canonical[2..]),
                bad_tail,
                "a".repeat(4_096),
            ] {
                assert!(DeviceId::canonical_key_bytes(&invalid).is_err());
                assert!(DeviceId::from_canonical_str_uninterned(&invalid).is_err());
                assert!(DeviceId::from_canonical_str(&invalid).is_err());
            }
        }
        // Exercise canonical base32 which fails the same Ed25519 validation,
        // without assuming a particular repeated-byte key is invalid.
        let invalid_key = (0u8..=255)
            .map(|byte| [byte; 32])
            .find(|key| VerifyingKey::from_bytes(key).is_err())
            .expect("the finite corpus includes an invalid compressed point");
        let encoded = BASE32_NOPAD.encode(&invalid_key).to_ascii_lowercase();
        assert!(DeviceId::canonical_key_bytes(&encoded).is_err());
        assert!(DeviceId::from_canonical_str_uninterned(&encoded).is_err());
        assert!(DeviceId::from_canonical_str(&encoded).is_err());
    }

    #[test]
    fn uninterned_identity_preserves_order_hash_serde_and_fact_bytes() {
        use std::collections::hash_map::DefaultHasher;
        let mut ordinary = Vec::new();
        let mut uninterned = Vec::new();
        for seed in [19, 41, 83] {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            let key = signing.verifying_key().to_bytes();
            let spelling = BASE32_NOPAD.encode(&key).to_ascii_lowercase();
            let owned = DeviceId::from_canonical_str_uninterned(&spelling).unwrap();
            let interned = DeviceId::from_canonical_str(&spelling).unwrap();
            assert!(!Arc::ptr_eq(&owned.0, &interned.0));
            assert!(Arc::ptr_eq(
                &interned.0,
                &DeviceId::from_public_key_bytes(key).unwrap().0,
            ));
            assert_eq!(owned, interned);
            let mut owned_hash = DefaultHasher::new();
            let mut interned_hash = DefaultHasher::new();
            owned.hash(&mut owned_hash);
            interned.hash(&mut interned_hash);
            assert_eq!(owned_hash.finish(), interned_hash.finish());
            assert_eq!(
                serde_json::to_vec(&owned).unwrap(),
                serde_json::to_vec(&interned).unwrap()
            );
            let decoded: DeviceId =
                serde_json::from_str(&serde_json::to_string(&owned).unwrap()).unwrap();
            assert!(
                Arc::ptr_eq(&decoded.0, &interned.0),
                "ordinary serde still interns"
            );
            ordinary.push(interned);
            uninterned.push(owned);
        }
        ordinary.sort();
        uninterned.sort();
        assert_eq!(ordinary, uninterned);
        let content = |ids: &[DeviceId]| {
            super::super::FactContent::new(
                FactDomain::Governance,
                super::super::MeshContextId::from_bytes([29; 32]),
                FactBody::RoleGrant {
                    target: ids[1].clone(),
                    role: Role::Member,
                },
                ids[0].clone(),
                vec![],
            )
        };
        let ordinary_fact = content(&ordinary);
        let owned_fact = content(&uninterned);
        assert_eq!(
            ordinary_fact.canonical_bytes(),
            owned_fact.canonical_bytes()
        );
        assert_eq!(
            FactId::from_content(&ordinary_fact),
            FactId::from_content(&owned_fact)
        );
        assert_eq!(
            serde_json::to_vec(&ordinary_fact).unwrap(),
            serde_json::to_vec(&owned_fact).unwrap()
        );
    }

    #[test]
    fn fresh_uninterned_identity_drops_without_an_interner_owner() {
        // Build the spelling directly from a signing key: no ordinary DeviceId
        // constructor or deserializer pre-interns this control's target.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[181; 32]);
        let spelling = BASE32_NOPAD
            .encode(&signing.verifying_key().to_bytes())
            .to_ascii_lowercase();
        let owned = DeviceId::from_canonical_str_uninterned(&spelling).unwrap();
        assert_eq!(Arc::strong_count(&owned.0), 1);
        assert_eq!(
            Arc::weak_count(&owned.0),
            0,
            "constructor retained no weak interner entry"
        );
        let probe = owned.backing_liveness_for_test();
        let clone = owned.clone();
        drop(owned);
        assert!(probe());
        drop(clone);
        assert!(!probe());
        drop(probe);
    }

    #[test]
    fn uninterned_backing_is_prefunded_and_releases_at_final_custody_drop() {
        use crate::resource::{
            FiniteResourceProvider, ResourceAuthorityClass, ResourceClaim, ResourceClass,
            ResourceProviderPort,
        };
        let raw = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(DeviceId::uninterned_backing_bytes()).unwrap(),
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .unwrap();
        let grant = FiniteResourceProvider::scope_planning_charge()
            .checked_add(FiniteResourceProvider::reservation_planning_charge(raw).unwrap())
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = port.process_scope();
        let baseline = provider.in_use();
        let lease = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, raw)
            .unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[193; 32]);
        let spelling = BASE32_NOPAD
            .encode(&signing.verifying_key().to_bytes())
            .to_ascii_lowercase();
        let owned = DeviceId::from_canonical_str_uninterned(&spelling).unwrap();
        let probe = owned.backing_liveness_for_test();
        assert_eq!(provider.in_use(), grant);
        assert_eq!(owned.0.canonical.len(), 52);
        assert_eq!(
            DeviceId::uninterned_backing_bytes(),
            std::mem::size_of::<DeviceIdInner>()
                + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
                + 52
        );
        assert!(port
            .acquire(&scope, ResourceAuthorityClass::Admitted, raw)
            .is_err());
        drop(owned);
        assert!(!probe());
        assert_eq!(
            provider.in_use(),
            grant,
            "funding remains through the weak allocation tail"
        );
        drop(probe);
        drop(lease);
        assert_eq!(provider.in_use(), baseline);
    }

    #[test]
    fn authority_use_and_resolution_reject_unknown_nested_wire_fields() {
        let authority = AuthorityUse::new(device(), vec![FactId::from_bytes([1; 32])]);
        let mut authority_wire = serde_json::to_value(&authority).unwrap();
        authority_wire["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AuthorityUse>(authority_wire).is_err());

        let proposal = FactId::from_bytes([2; 32]);
        let mut resolution_wire = serde_json::to_value(FactBody::Resolution {
            cell: ExclusiveCell::decision(proposal),
            cited_heads: vec![proposal],
            selected_head: proposal,
        })
        .unwrap();
        resolution_wire["cell"]["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FactBody>(resolution_wire).is_err());
    }

    #[test]
    fn exclusive_cells_are_a_closed_typed_union() {
        let id = device();
        assert_ne!(
            ExclusiveCell::role(id.clone()),
            ExclusiveCell::membership(id.clone())
        );
        assert_eq!(
            ExclusiveCell::role(id.clone()).to_string(),
            format!("role:{id}")
        );
    }
}
