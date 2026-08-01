//! Capability boundary for one bounded connection attempt.
//!
//! This Arc 02 module adds authority types only. It does not redirect the
//! current attempt runtime or change transport behavior.

use super::RuntimeIncarnation;

/// Proof that pre-authentication work was admitted for one attempt.
///
/// The private field prevents public IDs, wire values, and serialized state
/// from being treated as a permit. The permit is intentionally neither
/// `Clone` nor serializable.
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct PreAuthAttemptPermit {
    runtime: RuntimeIncarnation,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl PreAuthAttemptPermit {
    // The attempt owner will call this only after the resource owner admits
    // the work. It stays private until that production port is migrated.
    fn admitted(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }
}

/// Local authority to attempt one connector candidate.
///
/// The capability owns the permit that admitted its speculative work. Moving
/// it into a connector therefore consumes the lower authority structurally.
/// It has no public constructor and is neither `Clone` nor serializable.
///
/// A public peer label cannot create a candidate capability:
///
/// ```compile_fail,E0308
/// use myownmesh_core::runtime::attempt::CandidateCapability;
///
/// let public_peer_id = String::new();
/// let _candidate = CandidateCapability::from(public_peer_id);
/// ```
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct CandidateCapability {
    permit: PreAuthAttemptPermit,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl CandidateCapability {
    // Candidate creation remains owned by the attempt module. Arc 03 will
    // invoke this after the attempt runtime has produced a real candidate.
    fn from_permit(permit: PreAuthAttemptPermit) -> Self {
        Self { permit }
    }

    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.permit.runtime
    }
}

/// Temporary adapter for legacy candidate objects.
///
/// It carries the old object beside, rather than inside, the authority proof.
/// Supplying a legacy value cannot mint a capability. Arc 03 deletes this
/// wrapper after the connector consumes `CandidateCapability` directly.
#[allow(
    dead_code,
    reason = "Arc 03 installs and deletes this migration adapter"
)]
pub(crate) struct LegacyCandidate<T> {
    capability: CandidateCapability,
    legacy: T,
}

#[allow(
    dead_code,
    reason = "Arc 03 installs and deletes this migration adapter"
)]
impl<T> LegacyCandidate<T> {
    pub(crate) fn new(capability: CandidateCapability, legacy: T) -> Self {
        Self { capability, legacy }
    }

    pub(crate) fn capability(&self) -> &CandidateCapability {
        &self.capability
    }

    fn into_parts(self) -> (CandidateCapability, T) {
        (self.capability, self.legacy)
    }
}

#[cfg(test)]
pub(crate) fn candidate_for_test(runtime: RuntimeIncarnation) -> CandidateCapability {
    CandidateCapability::from_permit(PreAuthAttemptPermit::admitted(runtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_candidate_consumes_its_pre_auth_permit() {
        let runtime = crate::runtime::runtime_for_test();
        let permit = PreAuthAttemptPermit::admitted(runtime.clone());
        let candidate = CandidateCapability::from_permit(permit);

        assert!(candidate.runtime().is_same(&runtime));

        fn accepts_candidate(_: CandidateCapability) {}
        accepts_candidate(candidate);
    }

    #[test]
    fn v4_arc02_legacy_adapter_requires_an_existing_capability() {
        let wrapper = LegacyCandidate::new(
            candidate_for_test(crate::runtime::runtime_for_test()),
            "legacy candidate",
        );
        let _ = wrapper.capability();
        let (_capability, legacy) = wrapper.into_parts();

        assert_eq!(legacy, "legacy candidate");
    }
}
