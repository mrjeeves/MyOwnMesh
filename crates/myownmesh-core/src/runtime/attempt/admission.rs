//! Reserve-before-allocation connector-candidate admission and promotion.

use super::*;

pub(super) struct ConnectorCandidateReservation {
    pub(super) owner: Arc<ConnectorResourceOwnerInner>,
    pub(super) mesh_scope: Arc<MeshConnectorResourceScopeToken>,
    pub(super) claim: PreAuthResourceClaim,
    pub(super) release_on_drop: bool,
}

impl ConnectorCandidateReservation {
    fn transition(&mut self, next: PreAuthResourceClaim) -> bool {
        if !self.owner.transition(self.mesh_scope.id, self.claim, next) {
            return false;
        }
        self.claim = next;
        true
    }

    /// Convert this exact live claim into a process-owned failed-cleanup slot.
    /// The aggregate already includes the claim, so this records the terminal
    /// disposition and prevents `Drop` from making the slot reusable.
    fn retain_after_cleanup_failure(&mut self) {
        if !self.release_on_drop {
            return;
        }
        self.owner.retain_after_cleanup_failure(self.mesh_scope.id);
        self.release_on_drop = false;
    }
}

impl Drop for ConnectorCandidateReservation {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        self.owner.release(self.mesh_scope.id, self.claim);
    }
}

/// Proof that pre-authentication work was admitted for one attempt.
///
/// The private field prevents public IDs, wire values, and serialized state
/// from being treated as a permit. The permit is intentionally neither
/// `Clone` nor serializable.
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct PreAuthAttemptPermit {
    pub(super) attempt: Arc<AttemptOwnership>,
    pub(super) resource_scope: MeshConnectorResourceScope,
    #[cfg(test)]
    pub(super) aggregate: Arc<ConnectorResourceOwnerInner>,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl PreAuthAttemptPermit {
    // The attempt owner will call this only after the resource owner admits
    // the work. It stays private until that production port is migrated.
    pub(super) fn admitted(
        runtime: RuntimeIncarnation,
        resource_scope: impl Into<MeshConnectorResourceScope>,
    ) -> (Self, AttemptLifetime) {
        let resource_scope = resource_scope.into();
        #[cfg(test)]
        let aggregate = Arc::clone(&resource_scope.token.owner);
        let (retired, _retirement_receiver) = watch::channel(false);
        let attempt = Arc::new(AttemptOwnership {
            runtime,
            active: AtomicBool::new(true),
            transition: Mutex::new(()),
            retired,
        });
        let lifetime = AttemptLifetime {
            attempt: Arc::clone(&attempt),
        };
        (
            Self {
                attempt,
                #[cfg(test)]
                aggregate,
                resource_scope,
            },
            lifetime,
        )
    }

    /// Reserve one child and only then run the candidate allocation.
    ///
    /// The attempt permit remains alive and may issue more child reservations
    /// from the same aggregate. The closure is never called when admission
    /// fails.
    pub(super) fn allocate_connector_candidate<T>(
        &self,
        claim: ConnectorCandidateResourceClaim,
        allocate: impl FnOnce() -> T,
    ) -> Option<(ConnectorCandidateCapability, T)> {
        let capability = self.reserve_connector_candidate(claim)?;
        let candidate = allocate();
        Some((capability, candidate))
    }

    /// Reserve the opening claim before asynchronous connector construction.
    /// The attempt permit remains available for other racing candidates.
    pub(crate) fn reserve_connector_candidate(
        &self,
        claim: ConnectorCandidateResourceClaim,
    ) -> Option<ConnectorCandidateCapability> {
        let _transition = self.attempt.transition.lock().ok()?;
        if !self.attempt.active.load(Ordering::Acquire) {
            return None;
        }
        let reservation = self.resource_scope.reserve(claim.opening)?;
        Some(ConnectorCandidateCapability {
            attempt: Arc::clone(&self.attempt),
            reservation,
            connected_claim: claim.connected,
        })
    }
}

/// Admit one single-candidate attempt at the exact Arc 03 connector floor.
/// This attempt-local capacity is not a process or ingress limit.
pub(crate) fn admit_single_connector_candidate(
    runtime: RuntimeIncarnation,
    resource_scope: MeshConnectorResourceScope,
) -> (
    PreAuthAttemptPermit,
    AttemptLifetime,
    ConnectorCandidateResourceClaim,
) {
    let claim = ConnectorCandidateResourceClaim::exact_connector_floor();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, resource_scope);
    (permit, lifetime, claim)
}

/// Local authority to attempt one connector candidate.
///
/// The capability owns one child resource reservation and an exact, local
/// witness for the attempt that issued it. It does not consume the attempt
/// permit. One admitted attempt can therefore own multiple candidates under
/// one aggregate reservation. The capability has no public constructor and is
/// neither `Clone` nor serializable.
///
/// A public peer label cannot create a candidate capability:
///
/// ```compile_fail,E0308
/// use myownmesh_core::runtime::attempt::ConnectorCandidateCapability;
///
/// let public_peer_id = String::new();
/// let _candidate = ConnectorCandidateCapability::from(public_peer_id);
/// ```
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct ConnectorCandidateCapability {
    attempt: Arc<AttemptOwnership>,
    reservation: ConnectorCandidateReservation,
    connected_claim: PreAuthResourceClaim,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl ConnectorCandidateCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.attempt.runtime
    }

    pub(crate) fn liveness(&self) -> AttemptLiveness {
        AttemptLiveness {
            attempt: Arc::clone(&self.attempt),
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        let Ok(_transition) = self.attempt.transition.lock() else {
            return false;
        };
        self.attempt.active.load(Ordering::Acquire)
    }

    pub(crate) fn retain_after_cleanup_failure(&mut self) {
        self.reservation.retain_after_cleanup_failure();
    }

    pub(crate) fn promote_if_live<T>(self, promote: impl FnOnce(Self) -> T) -> Option<T> {
        self.try_promote_if_live(promote).ok()
    }

    /// Promote without losing cleanup ownership when retirement or a
    /// fail-closed aggregate refuses the transition.
    #[allow(
        clippy::result_large_err,
        reason = "boxing the move-only cleanup claim would add an unaccounted allocation"
    )]
    pub(crate) fn try_promote_if_live<T>(
        mut self,
        promote: impl FnOnce(Self) -> T,
    ) -> std::result::Result<T, Self> {
        let attempt = Arc::clone(&self.attempt);
        let _transition = match attempt.transition.lock() {
            Ok(transition) => transition,
            Err(_) => return Err(self),
        };
        if !attempt.active.load(Ordering::Acquire) {
            return Err(self);
        }
        if !self.reservation.transition(self.connected_claim) {
            return Err(self);
        }
        Ok(promote(self))
    }

    #[cfg(test)]
    pub(crate) fn reservation_is_active_for_test(&self) -> bool {
        self.reservation.owner.active() != PreAuthResourceClaim::ZERO
    }

    #[cfg(test)]
    pub(super) fn belongs_to(&self, permit: &PreAuthAttemptPermit) -> bool {
        Arc::ptr_eq(&self.attempt, &permit.attempt)
            && Arc::ptr_eq(&self.reservation.mesh_scope, &permit.resource_scope.token)
    }
}
