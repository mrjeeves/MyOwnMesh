//! Validation errors and signature checks for canonical semantic facts.

use thiserror::Error;

use super::{
    AttestationDecision, ExclusiveCell, FactBody, FactId, MeshContextId, Role, SignedFact,
};

/// The bounded semantic resource whose admission would exceed the verified
/// owner policy.  This remains typed so callers cannot mistake a fact-count
/// refusal for an encoded-byte or dependency-graph refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticCapacityDimension {
    FactEncodedBytes,
    DependenciesPerFact,
    AuthorityUsesPerFact,
    AuthorityPredecessorsPerUse,
    AdmittedFacts,
    AdmittedBytes,
    QuarantinedFacts,
    QuarantinedBytes,
    QuarantinedFactsPerAuthor,
    QuarantinedBytesPerAuthor,
    RetainedFactsPerAuthor,
    RetainedBytesPerAuthor,
    DependencyEdges,
    ReadyBatch,
}

/// Errors raised before a fact can enter the canonical causal graph.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SemanticError {
    #[error("unsupported semantic version {0}; only V4 is admitted")]
    UnsupportedVersion(u32),
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("fact domain does not match its body")]
    DomainMismatch,
    #[error("fact parents are not in canonical order")]
    UnsortedParents,
    #[error("fact contains a duplicate parent")]
    DuplicateParent,
    #[error("fact content author does not match the signing key")]
    AuthorMismatch,
    #[error("{0} contains a noncanonical set")]
    NonCanonicalSet(&'static str),
    #[error("eviction proof is incomplete")]
    IncompleteEvictionProof,
    #[error("fact id does not match canonical content")]
    FactIdMismatch,
    #[error("fact signature is invalid")]
    InvalidSignature,
    #[error("fact {0} is missing")]
    MissingParent(FactId),
    #[error("fact cannot cite itself as a parent")]
    SelfParent,
    #[error("fact context {found} does not match graph context {expected}")]
    ContextMismatch {
        expected: MeshContextId,
        found: String,
    },
    #[error("fact graph contains a causal cycle")]
    Cycle,
    #[error("resolution cites an unknown head {0}")]
    UnknownResolutionHead(FactId),
    #[error("resolution must cite every incomparable current head")]
    IncompleteResolution,
    #[error("resolution selected a head it did not cite")]
    ResolutionSelectionNotCited,
    #[error("fact {0} is already present with different content")]
    DuplicateFact(FactId),
    #[error("semantic operation is a no-op: {0}")]
    NoOp(&'static str),
    #[error("fact signer is not currently eligible for quarantine")]
    QuarantineSignerNotEligible,
    #[error("resolution does not apply to its current exclusive cell")]
    ResolutionNotCurrent,
    #[error("eviction proof author is not currently authorized")]
    UnauthorizedEviction,
    #[error("attestation signer is not currently authorized")]
    UnauthorizedAttestation,
    #[error("role grant author is not currently authorized")]
    UnauthorizedRoleGrant,
    #[error("membership admit author is not currently authorized")]
    UnauthorizedMembershipAdmit,
    #[error("eviction evidence is not a valid same-target authorized attestation")]
    InvalidEvictionEvidence,
    #[error("self-stand-down does not cite a valid same-target eviction proof")]
    InvalidStandDownProof,
    #[error("fact carries invalid signed AuthorityUse lineage")]
    InvalidAuthorityUse,
    #[error("semantic capacity {dimension:?} exceeded: {observed} > {limit}")]
    CapacityExceeded {
        dimension: SemanticCapacityDimension,
        limit: u64,
        observed: u64,
    },
    #[error("canonical fact encoding failed")]
    EncodingFailed,
}

/// Verify canonical content, its content-derived identifier, and its signature.
pub fn verify_fact(fact: &SignedFact) -> Result<(), SemanticError> {
    fact.content.validate()?;
    if FactId::from_content(&fact.content) != fact.id {
        return Err(SemanticError::FactIdMismatch);
    }
    let valid = crate::signing::verify(&fact.content.author, fact.id.as_bytes(), &fact.signature)
        .map_err(|_| SemanticError::InvalidSignature)?;
    if !valid {
        return Err(SemanticError::InvalidSignature);
    }
    Ok(())
}

/// Whether a body is a candidate for the exact exclusive cell named by a
/// resolution.  Keeping this check beside the canonical fact verifier avoids
/// letting a caller use a merely related cell (or a stringly-typed alias) as
/// resolution authority.
pub(crate) fn body_advances_cell(body: &FactBody, cell: &ExclusiveCell) -> bool {
    body.exclusive_cells()
        .iter()
        .any(|candidate| candidate == cell)
}

/// Resolve the role value carried by one already-selected role-cell fact.
/// Non-grants are deliberately authority-negative; a revoke, eviction,
/// unresolved head, or unrelated body must never inherit the bootstrap role.
pub(crate) fn projected_role(body: &FactBody, subject: &super::DeviceId) -> Option<Role> {
    match body {
        FactBody::RoleGrant { target, role } if target == subject => Some(*role),
        // A revoke advances the role cell but carries no role value.  In
        // particular, callers must not fall back to the bootstrap Owner after
        // selecting this proposition.
        FactBody::RoleRevoke { target } if target == subject => None,
        _ => None,
    }
}

pub(crate) fn projected_membership(body: &FactBody, subject: &super::DeviceId) -> Option<bool> {
    match body {
        FactBody::Evict { target } if target == subject => Some(false),
        FactBody::MembershipAdmit { target } if target == subject => Some(true),
        _ => None,
    }
}

pub(crate) fn projected_decision(
    body: &FactBody,
    proposal: &FactId,
) -> Option<AttestationDecision> {
    match body {
        FactBody::Attestation {
            proposal: fact_proposal,
            decision,
            ..
        } if fact_proposal == proposal => Some(*decision),
        _ => None,
    }
}
