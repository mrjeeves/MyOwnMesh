//! Canonical Closed/Open bootstrap material for the V4 Semantic owner.
//!
//! A BasisCore commits only to context-free policy material. A MeshContext
//! then commits to that core, and root proofs authenticate the resulting
//! context in a separate transcript. Proof bytes therefore cannot change
//! project identity or policy.

use std::borrow::Borrow;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, SIGNATURE_LENGTH};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::content::DeviceId;

pub const BASIS_VERSION: u16 = 1;
pub const CONTEXT_VERSION: u16 = 1;

const BASIS_DOMAIN: &[u8] = b"myownmesh-semantic-v4-basis-core-v1";
const CONTEXT_DOMAIN: &[u8] = b"myownmesh-semantic-v4-mesh-context-v1";
const ROOT_PROOF_DOMAIN: &[u8] = b"myownmesh-semantic-v4-root-proof-v1";

/// The one Closed governance profile accepted by this V4 cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosedProfileId {
    SingleRootSignedMemberLogV1,
}

impl ClosedProfileId {
    fn tag(self) -> &'static str {
        match self {
            Self::SingleRootSignedMemberLogV1 => "single_root_signed_member_log_v1",
        }
    }
}

/// A content-derived identity for one exact mesh context.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MeshContextId([u8; 32]);

impl MeshContextId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0).to_lowercase()
    }
}

impl std::fmt::Debug for MeshContextId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MeshContextId")
            .field(&self.base32())
            .finish()
    }
}

impl std::fmt::Display for MeshContextId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.base32())
    }
}

impl Serialize for MeshContextId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.base32())
    }
}

impl<'de> Deserialize<'de> for MeshContextId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded != encoded.to_lowercase() {
            return Err(D::Error::custom("MeshContextId must use lowercase base32"));
        }
        let bytes = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(D::Error::custom)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("MeshContextId must decode to 32 bytes"));
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes);
        let id = Self(value);
        if encoded != id.base32() {
            return Err(D::Error::custom("MeshContextId is not canonical base32"));
        }
        Ok(id)
    }
}

/// The exact semantic identity of a mesh, independent of carrier or Device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshContext {
    pub version: u16,
    pub scope: String,
    pub profile: Option<ClosedProfileId>,
    pub basis_core_commitment: Option<[u8; 32]>,
}

impl MeshContext {
    pub fn open(scope: impl Into<String>) -> Result<Self, BootstrapError> {
        let context = Self {
            version: CONTEXT_VERSION,
            scope: scope.into(),
            profile: None,
            basis_core_commitment: None,
        };
        context.validate()?;
        Ok(context)
    }

    fn closed(
        scope: impl Into<String>,
        profile: ClosedProfileId,
        basis_core_commitment: [u8; 32],
    ) -> Result<Self, BootstrapError> {
        let context = Self {
            version: CONTEXT_VERSION,
            scope: scope.into(),
            profile: Some(profile),
            basis_core_commitment: Some(basis_core_commitment),
        };
        context.validate()?;
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), BootstrapError> {
        if self.version != CONTEXT_VERSION {
            return Err(BootstrapError::UnsupportedContextVersion(self.version));
        }
        validate_text(&self.scope, "scope")?;
        match (self.profile, self.basis_core_commitment) {
            (None, None) => Ok(()),
            (Some(_), Some(_)) => Ok(()),
            (None, Some(_)) => Err(BootstrapError::OpenBasisPresent),
            (Some(_), None) => Err(BootstrapError::ClosedBasisMissing),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BootstrapError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(CONTEXT_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        put_text(&mut out, &self.scope);
        match self.profile {
            Some(profile) => {
                out.push(1);
                put_text(&mut out, profile.tag());
            }
            None => out.push(0),
        }
        match self.basis_core_commitment {
            Some(commitment) => {
                out.push(1);
                out.extend_from_slice(&commitment);
            }
            None => out.push(0),
        }
        Ok(out)
    }

    pub fn context_id(&self) -> Result<MeshContextId, BootstrapError> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Ok(MeshContextId(bytes))
    }
}

/// The context-free, unsigned policy material committed by a Closed project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasisCore {
    pub version: u16,
    pub scope: String,
    pub profile: ClosedProfileId,
    pub authority_roots: Vec<DeviceId>,
    pub creation_id: [u8; 32],
}

impl BasisCore {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, BootstrapError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(BASIS_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        put_text(&mut out, &self.scope);
        put_text(&mut out, self.profile.tag());
        put_devices(&mut out, &self.authority_roots);
        out.extend_from_slice(&self.creation_id);
        Ok(out)
    }

    pub fn commitment(&self) -> Result<[u8; 32], BootstrapError> {
        let digest = Sha256::digest(self.unsigned_bytes()?);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), BootstrapError> {
        if self.version != BASIS_VERSION {
            return Err(BootstrapError::UnsupportedBasisVersion(self.version));
        }
        validate_text(&self.scope, "scope")?;
        if self.authority_roots.len() != 1 {
            return Err(BootstrapError::ExactlyOneAuthorityRoot);
        }
        if self
            .authority_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(BootstrapError::AuthorityRootsNotCanonical);
        }
        Ok(())
    }
}

/// A Closed basis plus its root proof envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisBasis {
    pub version: u16,
    pub scope: String,
    pub profile: ClosedProfileId,
    pub authority_roots: Vec<DeviceId>,
    pub creation_id: [u8; 32],
    /// Lowercase base32 Ed25519 proofs over the context/core transcript.
    pub root_signatures: Vec<String>,
}

impl GenesisBasis {
    pub fn core(&self) -> BasisCore {
        BasisCore {
            version: self.version,
            scope: self.scope.clone(),
            profile: self.profile,
            authority_roots: self.authority_roots.clone(),
            creation_id: self.creation_id,
        }
    }

    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, BootstrapError> {
        self.core().unsigned_bytes()
    }

    pub fn commitment(&self) -> Result<[u8; 32], BootstrapError> {
        self.core().commitment()
    }

    pub fn validate(&self) -> Result<(), BootstrapError> {
        let core = self.core();
        core.validate()?;
        if self.root_signatures.len() != 1 {
            return Err(BootstrapError::RootSignatureCount);
        }
        validate_signature(&self.root_signatures[0], &self.authority_roots[0])?;
        Ok(())
    }

    fn validate_proofs(
        &self,
        context_id: &MeshContextId,
        core_commitment: &[u8; 32],
    ) -> Result<(), BootstrapError> {
        self.validate()?;
        let transcript = root_proof_transcript(context_id, core_commitment);
        let root = &self.authority_roots[0];
        let root_text = root.to_string();
        let valid = crate::signing::verify(&root_text, &transcript, &self.root_signatures[0])
            .map_err(|_| BootstrapError::InvalidRootSignature(root_text.clone()))?;
        if !valid {
            return Err(BootstrapError::InvalidRootSignature(root_text));
        }
        Ok(())
    }
}

/// The persisted pair. The optional basis is present exactly for Closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapRecord {
    pub context: MeshContext,
    pub basis: Option<GenesisBasis>,
}

/// A sealed root collection for internal graph construction. Its iterator is
/// crate-private so external callers cannot supply or consume raw roots as a
/// policy input; only a VerifiedBootstrap can mint this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthorityRoots {
    roots: Vec<DeviceId>,
}

impl VerifiedAuthorityRoots {
    pub(crate) fn iter(&self) -> std::slice::Iter<'_, DeviceId> {
        self.roots.iter()
    }
}

/// Sealed proof that a single-root Closed policy was validated.
///
/// Fields are private and there is no public constructor: graph integration
/// must receive this value from VerifiedBootstrap, not caller-selected roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClosedPolicy {
    profile: ClosedProfileId,
    scope: String,
    core_commitment: [u8; 32],
    authority_root: DeviceId,
}

impl VerifiedClosedPolicy {
    pub fn profile(&self) -> ClosedProfileId {
        self.profile
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn core_commitment(&self) -> &[u8; 32] {
        &self.core_commitment
    }

    pub(crate) fn authority_root(&self) -> &DeviceId {
        &self.authority_root
    }
}

/// Sealed project policy returned only by a validated bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedProjectPolicy {
    Open,
    Closed(VerifiedClosedPolicy),
}

/// Authenticated import intent for one exact context.
///
/// No public constructor accepts carrier bytes or an arbitrary context. The
/// wrapper is created from a VerifiedBootstrap and can only be compared to a
/// received context identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedMeshContext {
    context_id: MeshContextId,
}

impl ExpectedMeshContext {
    pub(crate) fn for_local_import(
        _principal: &crate::application_gateway::LocalPrincipalCapability,
        context_id: MeshContextId,
    ) -> Self {
        Self { context_id }
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn matches(&self, context_id: &MeshContextId) -> bool {
        self.context_id == *context_id
    }
}

/// A bootstrap pair that has passed all context, core, and root-proof checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBootstrap {
    record: BootstrapRecord,
    context_id: MeshContextId,
    policy: VerifiedProjectPolicy,
}

impl VerifiedBootstrap {
    pub fn create_closed<I, K>(
        scope: impl Into<String>,
        signing_keys: I,
        creation_id: [u8; 32],
    ) -> Result<Self, BootstrapError>
    where
        I: IntoIterator<Item = K>,
        K: Borrow<SigningKey>,
    {
        let scope = scope.into();
        let mut keys: Vec<SigningKey> = signing_keys
            .into_iter()
            .map(|key| key.borrow().clone())
            .collect();
        if keys.len() != 1 {
            return Err(BootstrapError::ExactlyOneAuthorityRoot);
        }
        let key = keys.pop().expect("one key was checked");
        let root = DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes())
            .map_err(BootstrapError::InvalidAuthorityRoot)?;
        let profile = ClosedProfileId::SingleRootSignedMemberLogV1;
        let core = BasisCore {
            version: BASIS_VERSION,
            scope: scope.clone(),
            profile,
            authority_roots: vec![root.clone()],
            creation_id,
        };
        let core_commitment = core.commitment()?;
        let context = MeshContext::closed(scope.clone(), profile, core_commitment)?;
        let context_id = context.context_id()?;
        let transcript = root_proof_transcript(&context_id, &core_commitment);
        let basis = GenesisBasis {
            version: BASIS_VERSION,
            scope,
            profile,
            authority_roots: vec![root.clone()],
            creation_id,
            root_signatures: vec![crate::signing::sign_with(&key, &transcript)],
        };
        Self::from_record(BootstrapRecord {
            context,
            basis: Some(basis),
        })
    }

    pub fn open(scope: impl Into<String>) -> Result<Self, BootstrapError> {
        let context = MeshContext::open(scope)?;
        Self::from_record(BootstrapRecord {
            context,
            basis: None,
        })
    }

    pub fn from_record(record: BootstrapRecord) -> Result<Self, BootstrapError> {
        record.context.validate()?;
        let (context_id, policy) = match (&record.context.profile, &record.basis) {
            (None, None) => (record.context.context_id()?, VerifiedProjectPolicy::Open),
            (None, Some(_)) => return Err(BootstrapError::OpenBasisPresent),
            (Some(_), None) => return Err(BootstrapError::ClosedBasisMissing),
            (Some(profile), Some(basis)) => {
                if basis.profile != *profile || basis.scope != record.context.scope {
                    return Err(BootstrapError::ProfileOrScopeMismatch);
                }
                let core = basis.core();
                let core_commitment = core.commitment()?;
                if record.context.basis_core_commitment != Some(core_commitment) {
                    return Err(BootstrapError::BasisCommitmentMismatch);
                }
                let expected_context =
                    MeshContext::closed(basis.scope.clone(), basis.profile, core_commitment)?;
                let expected_context_id = expected_context.context_id()?;
                let actual_context_id = record.context.context_id()?;
                if actual_context_id != expected_context_id {
                    return Err(BootstrapError::ContextCommitmentMismatch);
                }
                basis.validate_proofs(&expected_context_id, &core_commitment)?;
                (
                    actual_context_id,
                    VerifiedProjectPolicy::Closed(VerifiedClosedPolicy {
                        profile: basis.profile,
                        scope: basis.scope.clone(),
                        core_commitment,
                        authority_root: basis.authority_roots[0].clone(),
                    }),
                )
            }
        };
        Ok(Self {
            record,
            context_id,
            policy,
        })
    }

    pub fn validate(&self) -> Result<(), BootstrapError> {
        Self::from_record(self.record.clone()).map(|_| ())
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn context(&self) -> &MeshContext {
        &self.record.context
    }

    pub fn record(&self) -> &BootstrapRecord {
        &self.record
    }

    pub fn authority_roots(&self) -> VerifiedAuthorityRoots {
        VerifiedAuthorityRoots {
            roots: self
                .record
                .basis
                .as_ref()
                .map(|basis| basis.authority_roots.clone())
                .unwrap_or_default(),
        }
    }

    pub fn policy(&self) -> &VerifiedProjectPolicy {
        &self.policy
    }

    pub fn profile(&self) -> Option<ClosedProfileId> {
        self.record.context.profile
    }
}

impl TryFrom<BootstrapRecord> for VerifiedBootstrap {
    type Error = BootstrapError;

    fn try_from(record: BootstrapRecord) -> Result<Self, Self::Error> {
        Self::from_record(record)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BootstrapError {
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("{0} is not canonical")]
    NonCanonicalField(&'static str),
    #[error("exactly one authority root is required")]
    ExactlyOneAuthorityRoot,
    #[error("authority roots are not sorted and unique")]
    AuthorityRootsNotCanonical,
    #[error("one root proof is required")]
    RootSignatureCount,
    #[error("authority root is invalid: {0}")]
    InvalidAuthorityRoot(String),
    #[error("authority root proof is invalid: {0}")]
    InvalidRootSignature(String),
    #[error("unsupported basis version: {0}")]
    UnsupportedBasisVersion(u16),
    #[error("unsupported context version: {0}")]
    UnsupportedContextVersion(u16),
    #[error("an Open context cannot carry a Closed basis")]
    OpenBasisPresent,
    #[error("a Closed context requires a GenesisBasis")]
    ClosedBasisMissing,
    #[error("context scope/profile does not match its basis")]
    ProfileOrScopeMismatch,
    #[error("context basis-core commitment does not match the basis core")]
    BasisCommitmentMismatch,
    #[error("context identity does not match the canonical basis core")]
    ContextCommitmentMismatch,
}

fn root_proof_transcript(context_id: &MeshContextId, core_commitment: &[u8; 32]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(ROOT_PROOF_DOMAIN.len() + 64);
    transcript.extend_from_slice(ROOT_PROOF_DOMAIN);
    transcript.extend_from_slice(context_id.as_bytes());
    transcript.extend_from_slice(core_commitment);
    transcript
}

fn validate_text(value: &str, field: &'static str) -> Result<(), BootstrapError> {
    if value.is_empty() {
        return Err(BootstrapError::EmptyField(field));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(BootstrapError::NonCanonicalField(field));
    }
    Ok(())
}

fn validate_signature(signature: &str, root: &DeviceId) -> Result<(), BootstrapError> {
    if signature.is_empty() || signature != signature.to_lowercase() {
        return Err(BootstrapError::InvalidRootSignature(root.to_string()));
    }
    let bytes = BASE32_NOPAD
        .decode(signature.to_uppercase().as_bytes())
        .map_err(|_| BootstrapError::InvalidRootSignature(root.to_string()))?;
    if bytes.len() != SIGNATURE_LENGTH || BASE32_NOPAD.encode(&bytes).to_lowercase() != signature {
        return Err(BootstrapError::InvalidRootSignature(root.to_string()));
    }
    Ok(())
}

fn put_text(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn put_devices(out: &mut Vec<u8>, values: &[DeviceId]) {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        let bytes = value.as_bytes();
        out.extend_from_slice(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn closed_bootstrap_verifies_and_returns_sealed_policy() {
        let verified = VerifiedBootstrap::create_closed("scope-a", vec![key(1)], [7; 32])
            .expect("closed bootstrap");
        assert_eq!(
            verified.profile(),
            Some(ClosedProfileId::SingleRootSignedMemberLogV1)
        );
        assert!(matches!(
            verified.policy(),
            VerifiedProjectPolicy::Closed(policy)
                if policy.profile() == ClosedProfileId::SingleRootSignedMemberLogV1
        ));
        let runtime = crate::runtime::runtime_for_test();
        let principal = crate::application_gateway::LocalPrincipalCapability::for_test(runtime);
        let expected = ExpectedMeshContext::for_local_import(&principal, verified.context_id());
        assert!(expected.matches(&verified.context_id()));
        verified.validate().expect("bootstrap remains valid");
    }

    #[test]
    fn context_and_proof_mutation_are_rejected() {
        let verified = VerifiedBootstrap::create_closed("scope-a", vec![key(2)], [8; 32])
            .expect("closed bootstrap");
        let mut record = verified.record().clone();
        record.context.scope = "other-scope".into();
        assert_eq!(
            VerifiedBootstrap::from_record(record),
            Err(BootstrapError::ProfileOrScopeMismatch)
        );

        let mut record = verified.record().clone();
        record.basis.as_mut().unwrap().root_signatures[0].push('a');
        assert!(matches!(
            VerifiedBootstrap::from_record(record),
            Err(BootstrapError::InvalidRootSignature(_))
        ));
    }

    #[test]
    fn extra_root_is_refused_and_creation_id_is_fixed_width() {
        let extra = VerifiedBootstrap::create_closed("scope-a", vec![key(3), key(4)], [9; 32]);
        assert_eq!(extra, Err(BootstrapError::ExactlyOneAuthorityRoot));

        let basis = GenesisBasis {
            version: BASIS_VERSION,
            scope: "scope-a".into(),
            profile: ClosedProfileId::SingleRootSignedMemberLogV1,
            authority_roots: Vec::new(),
            creation_id: [0; 32],
            root_signatures: Vec::new(),
        };
        assert_eq!(
            basis.commitment(),
            Err(BootstrapError::ExactlyOneAuthorityRoot)
        );
        assert!(DeviceId::from_canonical_str("not-a-root").is_err());
    }

    #[test]
    fn open_has_no_basis_or_closed_policy() {
        let open = VerifiedBootstrap::open("open-scope").expect("open context");
        assert_eq!(open.profile(), None);
        assert!(matches!(open.policy(), VerifiedProjectPolicy::Open));
        assert!(open.record().basis.is_none());
    }

    #[test]
    fn same_scope_and_root_different_creation_changes_context() {
        let first = VerifiedBootstrap::create_closed("scope-a", vec![key(5)], [1; 32])
            .expect("first bootstrap");
        let second = VerifiedBootstrap::create_closed("scope-a", vec![key(5)], [2; 32])
            .expect("second bootstrap");
        assert_ne!(first.context_id(), second.context_id());
    }

    #[test]
    fn proof_envelope_does_not_change_core_or_context_identity() {
        let verified = VerifiedBootstrap::create_closed("scope-a", vec![key(6)], [3; 32])
            .expect("closed bootstrap");
        let context_id = verified.context_id();
        let core_commitment = verified
            .record()
            .basis
            .as_ref()
            .unwrap()
            .commitment()
            .unwrap();
        let mut record = verified.record().clone();
        record.basis.as_mut().unwrap().root_signatures[0] = "invalid".into();
        assert_eq!(record.context.context_id().unwrap(), context_id);
        assert_eq!(
            record.basis.as_ref().unwrap().commitment().unwrap(),
            core_commitment
        );
        assert!(VerifiedBootstrap::from_record(record).is_err());
    }
}
