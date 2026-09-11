//! Elastic, provider-backed ownership for one connector's remote candidates.
//!
//! This module owns only local pre-authentication work and queued candidate
//! content. It assigns no ICE, codec, session, or application meaning.

use super::ConnectorWorkResourceScope;
use crate::resource::{
    ResourceAuthorityClass, ResourceClaim, ResourceClass, ResourceLease, ResourceUnavailable,
};
use sha2::{Digest, Sha256};
use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

const REMOTE_CANDIDATE_DIGEST_BYTES: u64 = 32;
const REMOTE_CANDIDATE_DIGEST_DOMAIN: &[u8] = b"myownmesh/remote-candidate/v1";
#[cfg(any(test, feature = "transport-lab"))]
pub(crate) const REMOTE_CANDIDATE_MAX_DIGEST_OVERHEAD_BYTES: u64 =
    REMOTE_CANDIDATE_DIGEST_DOMAIN.len() as u64 + 27;

#[cfg(any(test, feature = "transport-lab"))]
pub(crate) fn remote_candidate_max_digest_work_claim(
    max_content_bytes: u64,
) -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let work = max_content_bytes
        .checked_add(REMOTE_CANDIDATE_MAX_DIGEST_OVERHEAD_BYTES)
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::ParsingOrCpuWork,
        })?;
    Ok(ResourceClaim::single(ResourceClass::ParsingOrCpuWork, work))
}

/// Mechanically derived connector-floor ownership for one candidate-attempt
/// root. The accounted bytes cover the `Arc` allocation that owns the complete
/// inline state plus the separate process-local identity marker allocation.
/// The residual units name those two allocation domains and the ordered map.
pub(crate) fn remote_candidate_attempt_root_claim(
) -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let bytes = std::mem::size_of::<RemoteCandidateAttemptInner>()
        .checked_add(std::mem::size_of::<usize>().checked_mul(4).ok_or(
            crate::resource::ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            },
        )?)
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let bytes = u64::try_from(bytes).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::StorageObject, 1),
        (ResourceClass::OpaqueDependencyResidual, 3),
    ])
}

fn retained_candidate_inline_bytes() -> Result<u64, crate::resource::ResourceClaimArithmeticError> {
    std::mem::size_of::<Mutex<RetainedRemoteCandidateState>>()
        .checked_add(std::mem::size_of::<usize>().checked_mul(2).ok_or(
            crate::resource::ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            },
        )?)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RemoteCandidateIdMarker>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<usize>().checked_mul(2)?))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })
}

pub(crate) fn remote_candidate_digest_retention_aggregate_claim(
    candidate_count: u64,
) -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let digest_bytes = REMOTE_CANDIDATE_DIGEST_BYTES
        .checked_mul(candidate_count)
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::QueuedBytes,
        })?;
    let inline_bytes = retained_candidate_inline_bytes()?
        .checked_mul(candidate_count)
        .and_then(|bytes| bytes.checked_add(digest_bytes))
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let residuals = 3_u64.checked_mul(candidate_count).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::OpaqueDependencyResidual,
        },
    )?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, inline_bytes),
        (ResourceClass::QueuedBytes, digest_bytes),
        (ResourceClass::StorageObject, candidate_count),
        (ResourceClass::CallbackOrScheduledWork, candidate_count),
        (ResourceClass::OpaqueDependencyResidual, residuals),
    ])
}

// Three optional cumulative ceilings used to stand here — submissions, content
// bytes and native applications — together with the wrapper that carried them
// and the counters that fed them. All of it is gone.
//
// They were optional because the provider was always the authority; they were
// *only* ever set from the connector's owner-selected candidate policy, and
// that policy no longer exists. What remains is what did the real refusing all
// along: an exact `ResourceClaim` for the digest work, one for the retention,
// and one for each native application, each acquired against the owner's real
// grant and released when the attempt retires.

/// Borrowed connector-neutral candidate content.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RemoteCandidateInput<'a> {
    pub(crate) candidate: &'a [u8],
    pub(crate) sdp_mid: Option<&'a [u8]>,
    pub(crate) sdp_mline_index: Option<u16>,
    pub(crate) username_fragment: Option<&'a [u8]>,
}

impl<'a> RemoteCandidateInput<'a> {
    #[cfg(test)]
    pub(crate) const fn candidate_only(candidate: &'a [u8]) -> Self {
        Self {
            candidate,
            sdp_mid: None,
            sdp_mline_index: None,
            username_fragment: None,
        }
    }

    fn content_bytes(self) -> Result<u64, RemoteCandidateAdmissionError> {
        let mut bytes = u64::try_from(self.candidate.len())
            .map_err(|_| RemoteCandidateAdmissionError::InputLengthOverflow)?;
        if let Some(sdp_mid) = self.sdp_mid {
            bytes = bytes
                .checked_add(
                    u64::try_from(sdp_mid.len())
                        .map_err(|_| RemoteCandidateAdmissionError::InputLengthOverflow)?,
                )
                .ok_or(RemoteCandidateAdmissionError::InputLengthOverflow)?;
        }
        if self.sdp_mline_index.is_some() {
            bytes = bytes
                .checked_add(2)
                .ok_or(RemoteCandidateAdmissionError::InputLengthOverflow)?;
        }
        if let Some(username_fragment) = self.username_fragment {
            bytes = bytes
                .checked_add(
                    u64::try_from(username_fragment.len())
                        .map_err(|_| RemoteCandidateAdmissionError::InputLengthOverflow)?,
                )
                .ok_or(RemoteCandidateAdmissionError::InputLengthOverflow)?;
        }
        Ok(bytes)
    }

    fn digest_work_bytes(self) -> Result<u64, RemoteCandidateAdmissionError> {
        let domain = u64::try_from(REMOTE_CANDIDATE_DIGEST_DOMAIN.len())
            .map_err(|_| RemoteCandidateAdmissionError::InputLengthOverflow)?;
        let mut bytes = domain
            .checked_add(8)
            .and_then(|value| value.checked_add(self.content_bytes().ok()?))
            .and_then(|value| value.checked_add(3))
            .ok_or(RemoteCandidateAdmissionError::InputLengthOverflow)?;
        if self.sdp_mid.is_some() {
            bytes = bytes
                .checked_add(8)
                .ok_or(RemoteCandidateAdmissionError::InputLengthOverflow)?;
        }
        if self.username_fragment.is_some() {
            bytes = bytes
                .checked_add(8)
                .ok_or(RemoteCandidateAdmissionError::InputLengthOverflow)?;
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct RemoteCandidateView {
    pub(crate) digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteCandidateTerminalReason {
    Provider(ResourceUnavailable),
    AccountingInexact,
    Retired,
}

/// What the owner decides once it has seen the digest.
///
/// A third answer used to stand here — `Refuse` — for an owner that had looked
/// at its own cumulative candidate budget and declined. There is no such budget
/// any more, so nothing can produce that answer: an owner either recognises the
/// digest or does not, and what refuses a candidate it does not recognise is
/// the provider, one line below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteCandidateDigestDecision {
    Retain,
    Duplicate,
}

pub(crate) enum RemoteCandidateAdmission {
    Retained(OwnedRemoteCandidate),
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RemoteCandidateAdmissionError {
    #[error("remote candidate input length overflowed")]
    InputLengthOverflow,
    #[error("the resource provider refused remote candidate work: {0}")]
    Provider(#[from] ResourceUnavailable),
    #[error("the remote candidate attempt is terminal: {0:?}")]
    Terminal(RemoteCandidateTerminalReason),
    #[error("remote candidate validation refused the submission before hashing")]
    ValidationRefused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RemoteCandidateApplyError {
    #[error("the remote candidate belongs to a retired or replaced attempt")]
    StaleAttempt,
    #[error("the retained remote candidate is no longer available")]
    NotRetained,
    #[error("the resource provider refused remote candidate application: {0}")]
    Provider(#[from] ResourceUnavailable),
}

#[derive(Clone)]
pub(crate) struct RemoteCandidateAttemptIdentity {
    marker: Arc<()>,
}

impl RemoteCandidateAttemptIdentity {
    pub(crate) fn same_attempt(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.marker, &other.marker)
    }
}

#[derive(Debug)]
struct OwnedRemoteCandidateContent {
    digest: [u8; 32],
}

impl OwnedRemoteCandidateContent {
    const fn new(digest: [u8; 32]) -> Self {
        Self { digest }
    }

    #[cfg(test)]
    fn view(&self) -> RemoteCandidateView {
        RemoteCandidateView {
            digest: self.digest,
        }
    }
}

struct RetainedRemoteCandidateState {
    content: Option<OwnedRemoteCandidateContent>,
    lease: Option<ResourceLease>,
}

#[derive(Clone)]
struct RemoteCandidateId(Arc<RemoteCandidateIdMarker>);

struct RemoteCandidateIdMarker {
    _owned: u8,
}

impl RemoteCandidateId {
    fn issue() -> Self {
        Self(Arc::new(RemoteCandidateIdMarker { _owned: 0 }))
    }

    fn address(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
}

impl PartialEq for RemoteCandidateId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for RemoteCandidateId {}

impl PartialOrd for RemoteCandidateId {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for RemoteCandidateId {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.address().cmp(&other.address())
    }
}

#[derive(Clone, Copy)]
enum AttemptStatus {
    Active,
    Terminal(RemoteCandidateTerminalReason),
}

struct RemoteCandidateAttemptState {
    status: AttemptStatus,
    retained: BTreeMap<RemoteCandidateId, Arc<Mutex<RetainedRemoteCandidateState>>>,
}

struct RemoteCandidateAttemptInner {
    identity: RemoteCandidateAttemptIdentity,
    resources: ConnectorWorkResourceScope,
    state: Mutex<RemoteCandidateAttemptState>,
}

/// Owner for one exact process-local remote-candidate attempt.
///
/// Restart replaces the identity and drains every retained candidate. No
/// elapsed time, rate, serialized generation, or durable route identity is
/// involved.
pub(crate) struct RemoteCandidateAttempt {
    inner: Arc<RemoteCandidateAttemptInner>,
}

impl RemoteCandidateAttempt {
    pub(crate) fn new(resources: ConnectorWorkResourceScope) -> Self {
        Self {
            inner: Arc::new(RemoteCandidateAttemptInner {
                identity: RemoteCandidateAttemptIdentity {
                    marker: Arc::new(()),
                },
                resources,
                state: Mutex::new(RemoteCandidateAttemptState {
                    status: AttemptStatus::Active,
                    retained: BTreeMap::new(),
                }),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn identity(&self) -> RemoteCandidateAttemptIdentity {
        self.inner.identity.clone()
    }

    #[cfg(test)]
    pub(crate) fn restart(&mut self) {
        let resources = self.inner.resources.clone();
        self.retire();
        *self = Self::new(resources);
    }

    pub(crate) fn retire(&self) {
        let mut state = self.lock_state();
        Self::terminalize(&mut state, RemoteCandidateTerminalReason::Retired);
    }

    pub(crate) fn admit(
        &self,
        input: RemoteCandidateInput<'_>,
    ) -> Result<OwnedRemoteCandidate, RemoteCandidateAdmissionError> {
        self.admit_with_before_digest(input, || true)
    }

    pub(crate) fn admit_with_before_digest(
        &self,
        input: RemoteCandidateInput<'_>,
        before_digest: impl FnOnce() -> bool,
    ) -> Result<OwnedRemoteCandidate, RemoteCandidateAdmissionError> {
        match self.admit_with_digest_decision(input, before_digest, |_| {
            RemoteCandidateDigestDecision::Retain
        })? {
            RemoteCandidateAdmission::Retained(candidate) => Ok(candidate),
            RemoteCandidateAdmission::Duplicate => {
                unreachable!("the default admission path always retains a unique candidate")
            }
        }
    }

    pub(crate) fn admit_with_digest_decision(
        &self,
        input: RemoteCandidateInput<'_>,
        before_digest: impl FnOnce() -> bool,
        after_digest: impl FnOnce([u8; 32]) -> RemoteCandidateDigestDecision,
    ) -> Result<RemoteCandidateAdmission, RemoteCandidateAdmissionError> {
        let digest_work_bytes = input.digest_work_bytes()?;
        let mut state = self.lock_state();
        if let AttemptStatus::Terminal(reason) = state.status {
            return Err(RemoteCandidateAdmissionError::Terminal(reason));
        }

        let work_claim = ResourceClaim::single(ResourceClass::ParsingOrCpuWork, digest_work_bytes);
        let work_lease = match self
            .inner
            .resources
            .acquire(ResourceAuthorityClass::Speculative, work_claim)
        {
            Ok(lease) => lease,
            Err(error) => {
                Self::terminalize(&mut state, RemoteCandidateTerminalReason::Provider(error));
                return Err(RemoteCandidateAdmissionError::Provider(error));
            }
        };
        if !before_digest() {
            drop(work_lease);
            Self::terminalize(&mut state, RemoteCandidateTerminalReason::Retired);
            return Err(RemoteCandidateAdmissionError::ValidationRefused);
        }
        let digest = digest_remote_candidate(input);

        match after_digest(digest) {
            RemoteCandidateDigestDecision::Duplicate => {
                drop(work_lease);
                return Ok(RemoteCandidateAdmission::Duplicate);
            }
            RemoteCandidateDigestDecision::Retain => {}
        }
        let retained_claim = remote_candidate_digest_retention_aggregate_claim(1)
            .map_err(|_| RemoteCandidateAdmissionError::InputLengthOverflow)?;
        let retained_lease = match self
            .inner
            .resources
            .acquire(ResourceAuthorityClass::Speculative, retained_claim)
        {
            Ok(lease) => lease,
            Err(error) => {
                Self::terminalize(&mut state, RemoteCandidateTerminalReason::Provider(error));
                return Err(RemoteCandidateAdmissionError::Provider(error));
            }
        };

        // Issue process-local identity only after the provider accepted both
        // work and retention. Refused submissions consume no lifetime-wide
        // numeric namespace.
        let candidate_id = RemoteCandidateId::issue();
        let retained = Arc::new(Mutex::new(RetainedRemoteCandidateState {
            content: Some(OwnedRemoteCandidateContent::new(digest)),
            lease: Some(retained_lease),
        }));
        state.retained.insert(candidate_id.clone(), retained);
        drop(work_lease);

        Ok(RemoteCandidateAdmission::Retained(OwnedRemoteCandidate {
            attempt: Arc::downgrade(&self.inner),
            identity: self.inner.identity.clone(),
            candidate_id,
            armed: true,
        }))
    }

    fn terminalize(state: &mut RemoteCandidateAttemptState, reason: RemoteCandidateTerminalReason) {
        state.status = AttemptStatus::Terminal(reason);
        state.retained.clear();
    }

    fn lock_state(&self) -> MutexGuard<'_, RemoteCandidateAttemptState> {
        self.inner.state.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            Self::terminalize(&mut state, RemoteCandidateTerminalReason::AccountingInexact);
            state
        })
    }
}

impl Drop for RemoteCandidateAttempt {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Move-only ownership of one queued candidate and its exact provider lease.
pub(crate) struct OwnedRemoteCandidate {
    attempt: Weak<RemoteCandidateAttemptInner>,
    identity: RemoteCandidateAttemptIdentity,
    candidate_id: RemoteCandidateId,
    armed: bool,
}

impl std::fmt::Debug for OwnedRemoteCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedRemoteCandidate")
            .field("candidate_id", &self.candidate_id.address())
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

impl OwnedRemoteCandidate {
    pub(crate) fn digest(&self) -> Option<[u8; 32]> {
        let attempt = self.attempt.upgrade()?;
        let state = attempt
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retained.get(&self.candidate_id).and_then(|retained| {
            retained
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .content
                .as_ref()
                .map(|content| content.digest)
        })
    }

    #[cfg(test)]
    pub(crate) fn identity(&self) -> RemoteCandidateAttemptIdentity {
        self.identity.clone()
    }

    #[cfg(test)]
    pub(crate) fn belongs_to(&self, attempt: &RemoteCandidateAttempt) -> bool {
        self.identity.same_attempt(&attempt.inner.identity)
    }

    #[cfg(test)]
    pub(crate) fn apply<T>(
        self,
        apply: impl FnOnce(RemoteCandidateView) -> T,
    ) -> Result<T, RemoteCandidateApplyError> {
        let applying = self.begin_apply()?;
        Ok(apply(applying.view()))
    }

    /// Enter native application while retaining the exact admitted claim.
    /// The returned owner must stay alive across any asynchronous native call.
    pub(crate) fn begin_apply(
        mut self,
    ) -> Result<ApplyingRemoteCandidate, RemoteCandidateApplyError> {
        let Some(attempt) = self.attempt.upgrade() else {
            return Err(RemoteCandidateApplyError::StaleAttempt);
        };
        if !self.identity.same_attempt(&attempt.identity) {
            return Err(RemoteCandidateApplyError::StaleAttempt);
        }
        let mut attempt_state = attempt
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(attempt_state.status, AttemptStatus::Active) {
            return Err(RemoteCandidateApplyError::StaleAttempt);
        }
        let Some(retained) = attempt_state.retained.get(&self.candidate_id).cloned() else {
            return Err(RemoteCandidateApplyError::NotRetained);
        };
        let mut retained_state = retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let lease = retained_state
            .lease
            .as_mut()
            .ok_or(RemoteCandidateApplyError::NotRetained)?;
        let claim = lease.claim();
        if let Err(error) = lease.transition_to(ResourceAuthorityClass::Admitted, claim) {
            RemoteCandidateAttempt::terminalize(
                &mut attempt_state,
                RemoteCandidateTerminalReason::Provider(error),
            );
            return Err(RemoteCandidateApplyError::Provider(error));
        }
        let content = retained_state
            .content
            .take()
            .ok_or(RemoteCandidateApplyError::NotRetained)?;
        let lease = retained_state
            .lease
            .take()
            .ok_or(RemoteCandidateApplyError::NotRetained)?;
        attempt_state.retained.remove(&self.candidate_id);
        self.armed = false;
        drop(retained_state);
        drop(attempt_state);

        Ok(ApplyingRemoteCandidate {
            _content: content,
            _lease: lease,
        })
    }
}

/// Exact admitted candidate work retained through a native application.
#[derive(Debug)]
pub(crate) struct ApplyingRemoteCandidate {
    _content: OwnedRemoteCandidateContent,
    _lease: ResourceLease,
}

impl ApplyingRemoteCandidate {
    /// Replace queue/application ownership with the exact retained identity
    /// claim after native application succeeds. A refusal leaves the original
    /// conservative claim intact so the caller can still retain or retire it
    /// without creating capacity.
    pub(crate) fn transition_after_application(
        &mut self,
        retained_identity: ResourceClaim,
    ) -> Result<(), ResourceUnavailable> {
        self._lease
            .transition_to(ResourceAuthorityClass::Admitted, retained_identity)
    }

    #[cfg(test)]
    pub(crate) fn view(&self) -> RemoteCandidateView {
        self._content.view()
    }
}

impl Drop for OwnedRemoteCandidate {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(attempt) = self.attempt.upgrade() {
            attempt
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retained
                .remove(&self.candidate_id);
        }
    }
}

fn digest_remote_candidate(input: RemoteCandidateInput<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REMOTE_CANDIDATE_DIGEST_DOMAIN);
    digest_field(&mut digest, input.candidate);
    digest_optional_field(&mut digest, input.sdp_mid);
    match input.sdp_mline_index {
        Some(index) => {
            digest.update([1]);
            digest.update(index.to_be_bytes());
        }
        None => digest.update([0]),
    }
    digest_optional_field(&mut digest, input.username_fragment);
    digest.finalize().into()
}

fn digest_field(digest: &mut Sha256, field: &[u8]) {
    digest.update(
        u64::try_from(field.len())
            .expect("validated candidate length")
            .to_be_bytes(),
    );
    digest.update(field);
}

fn digest_optional_field(digest: &mut Sha256, field: Option<&[u8]>) {
    match field {
        Some(field) => {
            digest.update([1]);
            digest_field(digest, field);
        }
        None => digest.update([0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{FiniteResourceProvider, ResourceProviderPort};
    use crate::runtime::attempt::{
        explicit_test_grant, AttemptLifetime, ConnectorCandidateCapability,
        ConnectorCandidateResourceClaim, ConnectorResourceOwnerPort, PreAuthAttemptPermit,
    };

    fn test_grant(
        retained_candidates: u64,
        parsing_bytes: u64,
        queued_bytes: u64,
    ) -> ResourceClaim {
        let expected_digest_bytes = REMOTE_CANDIDATE_DIGEST_BYTES
            .checked_mul(retained_candidates)
            .expect("fixture digest bytes are representable");
        assert_eq!(
            queued_bytes, expected_digest_bytes,
            "the connector-neutral owner retains only its digest bytes"
        );
        let candidate_work = remote_candidate_digest_retention_aggregate_claim(retained_candidates)
            .and_then(|claim| {
                claim.checked_add(ResourceClaim::try_from_entries([
                    (ResourceClass::ParsingOrCpuWork, parsing_bytes),
                    (
                        ResourceClass::OpaqueDependencyResidual,
                        retained_candidates
                            .checked_add(1)
                            .expect("fixture reservation records are representable"),
                    ),
                ])?)
            })
            .expect("the explicit candidate-work grant is representable");
        explicit_test_grant(1, 1)
            .checked_add(candidate_work)
            .expect("the explicit test grant is representable")
    }

    fn fixture(
        grant: ResourceClaim,
    ) -> (
        FiniteResourceProvider,
        ConnectorResourceOwnerPort,
        ConnectorCandidateCapability,
        AttemptLifetime,
        RemoteCandidateAttempt,
    ) {
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the explicit grant accounts for the process scope");
        let owner = ConnectorResourceOwnerPort::new(port);
        let mesh_scope = owner
            .issue_mesh_scope()
            .expect("the explicit grant accounts for the Mesh scope");
        let (permit, lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), mesh_scope);
        let connector = permit
            .reserve_connector_candidate(ConnectorCandidateResourceClaim::exact_connector_floor())
            .expect("the explicit grant admits the connector candidate");
        let attempt = RemoteCandidateAttempt::new(connector.work_resource_scope());
        (provider, owner, connector, lifetime, attempt)
    }

    fn candidate_input() -> RemoteCandidateInput<'static> {
        RemoteCandidateInput {
            candidate: b"candidate:1 1 UDP 1 192.0.2.1 10000 typ host",
            sdp_mid: Some(b"data"),
            sdp_mline_index: Some(0),
            username_fragment: Some(b"ufrag"),
        }
    }

    #[test]
    fn arc03_remote_candidate_acquires_work_before_digest() {
        let input = candidate_input();
        let work = input
            .digest_work_bytes()
            .expect("fixture work is measurable");
        let queued = REMOTE_CANDIDATE_DIGEST_BYTES;
        let grant = test_grant(1, work, queued);
        let (provider, _owner, _connector, _lifetime, attempt) = fixture(grant);
        let saw_work = std::cell::Cell::new(false);

        let candidate = attempt
            .admit_with_before_digest(input, || {
                saw_work.set(provider.in_use().amount(ResourceClass::ParsingOrCpuWork) == work);
                true
            })
            .expect("the explicit provider grant admits the candidate");
        assert!(saw_work.get());
        assert_eq!(provider.in_use().amount(ResourceClass::ParsingOrCpuWork), 0);
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), queued);
        drop(candidate);
    }

    #[test]
    fn arc03_remote_candidate_parsing_pressure_is_terminal_and_typed() {
        let input = candidate_input();
        let queued = REMOTE_CANDIDATE_DIGEST_BYTES;
        let grant = test_grant(1, 0, queued);
        let (provider, _owner, _connector, _lifetime, attempt) = fixture(grant);
        let digest_called = std::cell::Cell::new(false);

        let first = attempt.admit_with_before_digest(input, || {
            digest_called.set(true);
            true
        });
        let error = match first {
            Err(error) => error,
            Ok(_) => panic!("the provider supplied no parsing work"),
        };
        assert!(matches!(
            error,
            RemoteCandidateAdmissionError::Provider(ResourceUnavailable::Pressure(pressure))
                if pressure.dimension == ResourceClass::ParsingOrCpuWork
        ));
        assert!(!digest_called.get());
        assert!(matches!(
            attempt.admit(input),
            Err(RemoteCandidateAdmissionError::Terminal(
                RemoteCandidateTerminalReason::Provider(ResourceUnavailable::Pressure(pressure))
            )) if pressure.dimension == ResourceClass::ParsingOrCpuWork
        ));
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 0);
    }

    #[test]
    fn arc03_remote_candidate_retention_pressure_releases_work_and_is_terminal() {
        let input = candidate_input();
        let work = input
            .digest_work_bytes()
            .expect("fixture work is measurable");
        let queued = REMOTE_CANDIDATE_DIGEST_BYTES;
        let grant = test_grant(1, work, queued)
            .checked_sub(ResourceClaim::single(ResourceClass::QueuedBytes, queued))
            .expect("the refusal fixture removes only queued-byte capacity");
        let (provider, _owner, _connector, _lifetime, attempt) = fixture(grant);
        let baseline_storage = provider.in_use().amount(ResourceClass::StorageObject);

        let error = match attempt.admit(input) {
            Err(error) => error,
            Ok(_) => panic!("the provider supplied no queued bytes"),
        };
        assert!(matches!(
            error,
            RemoteCandidateAdmissionError::Provider(ResourceUnavailable::Pressure(pressure))
                if pressure.dimension == ResourceClass::QueuedBytes
        ));
        assert_eq!(provider.in_use().amount(ResourceClass::ParsingOrCpuWork), 0);
        assert_eq!(
            provider.in_use().amount(ResourceClass::StorageObject),
            baseline_storage
        );
    }

    #[test]
    fn arc03_remote_candidate_apply_releases_exact_retention() {
        let input = candidate_input();
        let work = input
            .digest_work_bytes()
            .expect("fixture work is measurable");
        let queued = REMOTE_CANDIDATE_DIGEST_BYTES;
        let grant = test_grant(1, work, queued);
        let (provider, _owner, _connector, _lifetime, attempt) = fixture(grant);
        let baseline_storage = provider.in_use().amount(ResourceClass::StorageObject);
        let candidate = attempt
            .admit(input)
            .expect("the explicit provider grant admits the candidate");
        assert!(candidate.belongs_to(&attempt));
        let identity = candidate.identity();

        let digest = candidate
            .apply(|candidate| candidate.digest)
            .expect("the retained candidate applies once");
        assert!(identity.same_attempt(&attempt.identity()));
        assert_eq!(digest, digest_remote_candidate(input));
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 0);
        assert_eq!(
            provider.in_use().amount(ResourceClass::StorageObject),
            baseline_storage
        );
    }

    #[test]
    fn arc03_remote_candidate_drop_releases_exact_retention() {
        let input = candidate_input();
        let work = input
            .digest_work_bytes()
            .expect("fixture work is measurable");
        let queued = REMOTE_CANDIDATE_DIGEST_BYTES;
        let grant = test_grant(1, work, queued);
        let (provider, _owner, _connector, _lifetime, attempt) = fixture(grant);
        let candidate = attempt
            .admit(input)
            .expect("the explicit provider grant admits the candidate");
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), queued);
        drop(candidate);
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 0);
    }

    #[test]
    fn arc03_remote_candidate_restart_drains_old_attempt_and_replaces_identity() {
        let input = candidate_input();
        let work = input
            .digest_work_bytes()
            .expect("fixture work is measurable");
        let queued = REMOTE_CANDIDATE_DIGEST_BYTES;
        let grant = test_grant(1, work, queued);
        let (provider, _owner, _connector, _lifetime, mut attempt) = fixture(grant);
        let candidate = attempt
            .admit(input)
            .expect("the explicit provider grant admits the candidate");
        let old_identity = attempt.identity();

        attempt.restart();
        assert!(!old_identity.same_attempt(&attempt.identity()));
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 0);
        assert!(matches!(
            candidate.apply(|_| ()),
            Err(RemoteCandidateApplyError::StaleAttempt)
        ));
    }

    /// The grant is the ceiling, and it is attempt-scoped.
    ///
    /// This used to state an explicit one-submission local ceiling and check
    /// that the second submission was refused against it. There is no local
    /// ceiling to state now, so the same property is proven the only way it can
    /// still be reached: a provider funded for exactly one retained candidate
    /// admits one and refuses the next, and the refusal leaves the accounting
    /// exactly where the first submission left it rather than charging for work
    /// it did not keep.
    #[test]
    fn arc03_remote_candidate_retention_is_bounded_by_the_grant_and_attempt_scoped() {
        let input = RemoteCandidateInput::candidate_only(b"candidate");
        let work = input
            .digest_work_bytes()
            .expect("fixture work is measurable");
        let queued = REMOTE_CANDIDATE_DIGEST_BYTES;
        let grant = test_grant(1, work, queued);
        let (provider, _owner, _connector, _lifetime, attempt) = fixture(grant);
        let first = attempt
            .admit(input)
            .expect("the explicit first submission is admitted");
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), queued);

        assert!(matches!(
            attempt.admit(input).err(),
            Some(RemoteCandidateAdmissionError::Provider(_))
        ));
        // The refusal is terminal for this attempt, so what it had retained is
        // released rather than half-kept behind a grant that cannot cover the
        // next submission.
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 0);
        drop(first);
    }

    #[test]
    fn arc03_remote_candidate_owner_decides_duplicate_before_retention() {
        let input = candidate_input();
        let work = input
            .digest_work_bytes()
            .expect("fixture work is measurable");
        let queued = REMOTE_CANDIDATE_DIGEST_BYTES;
        let grant = test_grant(1, work, queued);
        let (provider, _owner, connector, lifetime, attempt) = fixture(grant);
        let first = attempt
            .admit_with_digest_decision(input, || true, |_| RemoteCandidateDigestDecision::Retain)
            .expect("the exact retention grant admits one unique candidate");
        let RemoteCandidateAdmission::Retained(first) = first else {
            panic!("the first candidate is retained");
        };
        let retained_use = provider.in_use();

        assert!(matches!(
            attempt.admit_with_digest_decision(
                input,
                || true,
                |_| RemoteCandidateDigestDecision::Duplicate,
            ),
            Ok(RemoteCandidateAdmission::Duplicate)
        ));
        assert_eq!(
            provider.in_use(),
            retained_use,
            "duplicate hashing does not require a second retained-candidate claim"
        );

        drop(first);
        drop(attempt);
        drop(connector);
        drop(lifetime);
    }

    #[test]
    fn arc03_remote_candidate_digest_distinguishes_absent_and_present_fields() {
        let absent = RemoteCandidateInput::candidate_only(b"candidate");
        let present = RemoteCandidateInput {
            candidate: b"candidate",
            sdp_mid: Some(b""),
            sdp_mline_index: None,
            username_fragment: None,
        };
        assert_ne!(
            digest_remote_candidate(absent),
            digest_remote_candidate(present)
        );
    }
}
