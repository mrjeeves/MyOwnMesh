//! Transport-independent V4 semantic ownership.
//!
//! The semantic owner is deliberately smaller than the engine: it admits
//! canonical signed facts, maintains causal heads, and computes a projection.
//! Wire envelopes, peer/session routes, courier choice, and compatibility
//! facades remain outside this module.

use serde::{Deserialize, Serialize};

pub mod bootstrap;
pub mod causal;
pub mod content;
pub mod fact;
pub mod projection;
pub mod proof_outbox;
mod storage_codec;
pub(crate) mod store;
pub mod verify;

pub use bootstrap::{
    BasisCore, BootstrapError, BootstrapRecord, ClosedProfileId, ExpectedMeshContext, GenesisBasis,
    MeshContext, MeshContextId, VerifiedBootstrap, VerifiedClosedPolicy, VerifiedProjectPolicy,
    BASIS_VERSION, CONTEXT_VERSION,
};
#[cfg(test)]
pub(crate) use causal::SemanticFactRow;
pub use causal::{Admission, FactGraph, SemanticAdmissionPolicy};
pub(crate) use causal::{SemanticDelta, SemanticFactStatus};
pub use content::{AttestationDecision, DeviceId, ExclusiveCell, FactBody, FactDomain, Role};
pub use fact::{CanonicalFact, FactContent, FactId, SignedFact};
pub use projection::{CellProjection, Projection, StandDown};
pub use proof_outbox::{
    DurableProofOutbox, ProofDeliveryId, ProofOutboxError, ProofRecord, ProofRecordState,
};
pub use verify::{verify_fact, SemanticCapacityDimension, SemanticError};

pub const SEMANTIC_SCHEMA_VERSION: u32 = 4;

/// A bounded request for one deterministic page of canonical signed facts.
/// `cursor` is exclusive: the next page starts strictly after that FactId.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticFactPageRequest {
    pub context_id: MeshContextId,
    pub cursor: Option<FactId>,
    pub max_facts: u32,
    pub max_encoded_bytes: u32,
}

/// Bounds one non-canonical, human-readable view of the facts already kept in
/// the live hot-history cache. The view is for diagnostics only: it is never
/// read by semantic admission and is never persisted as a second ledger.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRecentFactsRequest {
    pub max_facts: u32,
    pub max_encoded_bytes: u32,
}

/// A bounded diagnostic projection of the live hot-history cache.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRecentFacts {
    context_id: MeshContextId,
    total_admitted_fact_count: u64,
    cached_fact_count: u64,
    facts: Vec<SignedFact>,
    #[serde(skip)]
    _funding: Option<crate::resource::ResourceLease>,
}

impl SemanticRecentFacts {
    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn total_admitted_fact_count(&self) -> u64 {
        self.total_admitted_fact_count
    }

    pub fn cached_fact_count(&self) -> u64 {
        self.cached_fact_count
    }

    pub fn facts(&self) -> &[SignedFact] {
        &self.facts
    }

    pub(crate) fn new(
        context_id: MeshContextId,
        total_admitted_fact_count: u64,
        cached_fact_count: u64,
        facts: Vec<SignedFact>,
        funding: crate::resource::ResourceLease,
    ) -> Self {
        Self {
            context_id,
            total_admitted_fact_count,
            cached_fact_count,
            facts,
            _funding: Some(funding),
        }
    }
}

/// One bounded canonical fact page. The private funding lease remains held
/// while a daemon serializes the page, so returned bytes cannot outlive their
/// provider admission.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticFactPage {
    context_id: MeshContextId,
    facts: Vec<SignedFact>,
    next_cursor: Option<FactId>,
    complete: bool,
    #[serde(skip)]
    funding: Option<crate::resource::ResourceLease>,
}

impl SemanticFactPage {
    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn facts(&self) -> &[SignedFact] {
        &self.facts
    }

    pub fn next_cursor(&self) -> Option<FactId> {
        self.next_cursor
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        MeshContextId,
        Vec<SignedFact>,
        Option<FactId>,
        bool,
        Option<crate::resource::ResourceLease>,
    ) {
        (
            self.context_id,
            self.facts,
            self.next_cursor,
            self.complete,
            self.funding,
        )
    }

    pub(crate) fn into_fact_page_message(
        self,
    ) -> Result<
        (
            crate::protocol::FactPageMessage,
            Option<crate::resource::ResourceLease>,
        ),
        String,
    > {
        let (context_id, facts, next_cursor, complete, funding) = self.into_parts();
        let page = crate::protocol::FactPageMessage::new(context_id, facts, next_cursor, complete)?;
        Ok((page, funding))
    }

    pub(crate) fn new(
        context_id: MeshContextId,
        facts: Vec<SignedFact>,
        next_cursor: Option<FactId>,
        complete: bool,
        funding: crate::resource::ResourceLease,
    ) -> Self {
        Self {
            context_id,
            facts,
            next_cursor,
            complete,
            funding: Some(funding),
        }
    }
}

/// A stable observation of one network's semantic state.
///
/// The two commitments distinguish the exact signed-fact set from its
/// projected authority view. Counts are bounded scalar observations; callers
/// use the page API for the individual facts rather than retaining a whole
/// graph in one diagnostic value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticStateIdentity {
    context_id: MeshContextId,
    admitted_fact_count: u64,
    unresolved_fact_count: u64,
    projection_commitment: [u8; 32],
    state_commitment: [u8; 32],
    #[serde(skip)]
    _funding: Option<std::sync::Arc<crate::resource::ResourceLease>>,
}

impl SemanticStateIdentity {
    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn admitted_fact_count(&self) -> u64 {
        self.admitted_fact_count
    }

    pub fn unresolved_fact_count(&self) -> u64 {
        self.unresolved_fact_count
    }

    pub fn projection_commitment(&self) -> [u8; 32] {
        self.projection_commitment
    }

    pub fn state_commitment(&self) -> [u8; 32] {
        self.state_commitment
    }

    pub(crate) fn new(
        context_id: MeshContextId,
        admitted_fact_count: u64,
        unresolved_fact_count: u64,
        projection_commitment: [u8; 32],
        state_commitment: [u8; 32],
        funding: crate::resource::ResourceLease,
    ) -> Self {
        Self {
            context_id,
            admitted_fact_count,
            unresolved_fact_count,
            projection_commitment,
            state_commitment,
            _funding: Some(std::sync::Arc::new(funding)),
        }
    }
}

impl PartialEq for SemanticStateIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.context_id == other.context_id
            && self.admitted_fact_count == other.admitted_fact_count
            && self.unresolved_fact_count == other.unresolved_fact_count
            && self.projection_commitment == other.projection_commitment
            && self.state_commitment == other.state_commitment
    }
}

impl Eq for SemanticStateIdentity {}

/// A durable eviction-proof reference, without choosing a transport or store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionProofReference {
    pub target: DeviceId,
    pub evidence: Vec<FactId>,
}

impl EvictionProofReference {
    pub fn new(target: DeviceId, mut evidence: Vec<FactId>) -> Self {
        evidence.sort();
        evidence.dedup();
        Self { target, evidence }
    }

    pub fn body(&self) -> FactBody {
        FactBody::EvictionProof {
            target: self.target.clone(),
            evidence: self.evidence.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_control_envelopes_reject_unknown_fields() {
        let context_id = MeshContextId::from_bytes([7; 32]);
        let request = serde_json::json!({
            "context_id": context_id,
            "cursor": null,
            "max_facts": 1,
            "max_encoded_bytes": 1,
            "unexpected": true,
        });
        assert!(serde_json::from_value::<SemanticFactPageRequest>(request).is_err());

        let page = serde_json::json!({
            "context_id": context_id,
            "facts": [],
            "next_cursor": null,
            "complete": true,
            "unexpected": true,
        });
        assert!(serde_json::from_value::<SemanticFactPage>(page).is_err());

        let identity = serde_json::json!({
            "context_id": context_id,
            "admitted_fact_count": 0,
            "unresolved_fact_count": 0,
            "projection_commitment": vec![0u8; 32],
            "state_commitment": vec![0u8; 32],
            "unexpected": true,
        });
        assert!(serde_json::from_value::<SemanticStateIdentity>(identity).is_err());
    }
}
