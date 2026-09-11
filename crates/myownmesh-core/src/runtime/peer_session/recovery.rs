//! Provider-owned recovery demand for one logical peer session.
//!
//! A demand is separate from any announce attempt. An attempt can be refused
//! or rate-limited before the terminal boundary without consuming the demand;
//! only an accepted settlement after that boundary does so.

use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::resource::{
    ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceUnavailable,
};

use super::LogicalSessionValidityWitness;

/// Why a provider-owned recovery demand could not be armed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RecoveryDemandError {
    #[error("the logical session is already terminal")]
    Terminal,
    #[error("recovery demand resources were unavailable: {0}")]
    ResourceUnavailable(#[source] ResourceUnavailable),
    #[error("recovery demand claim arithmetic failed: {0}")]
    Arithmetic(#[source] ResourceClaimArithmeticError),
}

/// Whether arming created the one owned demand or coalesced with it.
#[derive(Clone, Debug)]
pub(crate) enum RecoveryDemandAdmission {
    Created(RecoveryDemandHandle),
    Coalesced(RecoveryDemandHandle),
}

impl RecoveryDemandAdmission {
    pub(crate) fn into_handle(self) -> RecoveryDemandHandle {
        match self {
            Self::Created(handle) | Self::Coalesced(handle) => handle,
        }
    }
}

/// Provider outcome presented to the post-terminal settlement seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryAttempt {
    Accepted,
    Refused,
}

/// Result of attempting to settle a recovery demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryDemandSettlement {
    /// The call happened before the exact terminal boundary.
    PreTerminal,
    /// The terminal attempt was refused; demand remains.
    Unsatisfied,
    /// An accepted post-terminal attempt consumed the demand.
    Satisfied,
    /// There was no demand to settle.
    NoDemand,
}

const ARMED: u8 = 0;
const TERMINAL: u8 = 1;
const SATISFIED: u8 = 2;
const CANCELLED: u8 = 3;

struct RecoveryDemandInner {
    status: AtomicU8,
    /// Exact provider custody retained until settlement or cancellation. It
    /// lives behind the shared inner so a handle held by engine cleanup keeps
    /// custody after the logical session record is dropped.
    lease: Mutex<Option<ResourceLease>>,
}

/// Cloneable custody for one provider-owned recovery demand.
///
/// Clones share one lease and one terminal/settlement state. This is the
/// engine's post-retirement witness: the logical record may disappear while a
/// close supervisor retains this handle.
#[derive(Clone)]
pub(crate) struct RecoveryDemandHandle(Arc<RecoveryDemandInner>);

impl fmt::Debug for RecoveryDemandHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryDemandHandle")
            .field("status", &self.0.status.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl RecoveryDemandHandle {
    fn new(lease: ResourceLease) -> Self {
        Self(Arc::new(RecoveryDemandInner {
            status: AtomicU8::new(ARMED),
            lease: Mutex::new(Some(lease)),
        }))
    }

    fn release_lease(&self) {
        drop(self.0.lease.lock().take());
    }

    /// Mark the exact terminal boundary. Idempotent for repeated terminal
    /// notifications and harmless after cancellation/settlement.
    pub(crate) fn mark_terminal(&self) {
        let _ =
            self.0
                .status
                .compare_exchange(ARMED, TERMINAL, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Settle the one accepted post-terminal attempt, or retain custody for a
    /// refusal/rate limit. The lease is released exactly once.
    pub(crate) fn settle_post_terminal(
        &self,
        attempt: RecoveryAttempt,
    ) -> RecoveryDemandSettlement {
        loop {
            match self.0.status.load(Ordering::Acquire) {
                ARMED => return RecoveryDemandSettlement::PreTerminal,
                TERMINAL if attempt != RecoveryAttempt::Accepted => {
                    return RecoveryDemandSettlement::Unsatisfied;
                }
                TERMINAL => {
                    if self
                        .0
                        .status
                        .compare_exchange(TERMINAL, SATISFIED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        self.release_lease();
                        return RecoveryDemandSettlement::Satisfied;
                    }
                }
                SATISFIED | CANCELLED => return RecoveryDemandSettlement::NoDemand,
                _ => return RecoveryDemandSettlement::NoDemand,
            }
        }
    }

    /// Cancel custody for shutdown or a usable successor.
    pub(crate) fn cancel(&self) -> bool {
        loop {
            let status = self.0.status.load(Ordering::Acquire);
            if !matches!(status, ARMED | TERMINAL) {
                return false;
            }
            if self
                .0
                .status
                .compare_exchange(status, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.release_lease();
                return true;
            }
        }
    }
}

/// One coalesced, provider-funded recovery demand.
pub(crate) struct RecoveryDemandState {
    demand: Option<RecoveryDemandHandle>,
    terminal: bool,
}

impl RecoveryDemandState {
    pub(crate) fn new() -> Self {
        Self {
            demand: None,
            terminal: false,
        }
    }

    fn claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let bytes = u64::try_from(std::mem::size_of::<RecoveryDemandInner>()).map_err(|_| {
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            }
        })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Arm the one demand, retaining it against the exact session provider.
    /// Repeated calls coalesce and return a clone of the same handle.
    pub(crate) fn arm(
        &mut self,
        validity: &LogicalSessionValidityWitness,
    ) -> Result<RecoveryDemandAdmission, RecoveryDemandError> {
        if self.terminal {
            return Err(RecoveryDemandError::Terminal);
        }
        if let Some(demand) = self.demand.as_ref() {
            return Ok(RecoveryDemandAdmission::Coalesced(demand.clone()));
        }
        let lease = validity
            .reserve_retained(Self::claim().map_err(RecoveryDemandError::Arithmetic)?)
            .map_err(RecoveryDemandError::ResourceUnavailable)?;
        let handle = RecoveryDemandHandle::new(lease);
        self.demand = Some(handle.clone());
        Ok(RecoveryDemandAdmission::Created(handle))
    }

    /// Mark the exact logical terminal boundary.
    pub(crate) fn mark_terminal(&mut self) {
        self.terminal = true;
        if let Some(demand) = self.demand.as_ref() {
            demand.mark_terminal();
        }
    }

    /// Cancel demand because shutdown owns the lifecycle boundary.
    pub(crate) fn cancel_for_shutdown(&mut self) -> bool {
        self.demand.take().is_some_and(|demand| demand.cancel())
    }

    /// Cancel demand because a usable successor now owns recovery.
    pub(crate) fn cancel_for_usable_successor(&mut self) -> bool {
        self.demand.take().is_some_and(|demand| demand.cancel())
    }
}

#[cfg(test)]
fn unmetered_control_handle() -> RecoveryDemandHandle {
    RecoveryDemandHandle(Arc::new(RecoveryDemandInner {
        status: AtomicU8::new(ARMED),
        lease: Mutex::new(None),
    }))
}

#[cfg(test)]
mod tests {
    use super::{unmetered_control_handle, RecoveryAttempt, RecoveryDemandSettlement};

    #[test]
    fn recovery_demand_preserves_custody_until_post_terminal_acceptance() {
        let demand = unmetered_control_handle();
        assert_eq!(
            demand.settle_post_terminal(RecoveryAttempt::Accepted),
            RecoveryDemandSettlement::PreTerminal
        );
        demand.mark_terminal();
        assert_eq!(
            demand.settle_post_terminal(RecoveryAttempt::Refused),
            RecoveryDemandSettlement::Unsatisfied
        );
        assert_eq!(
            demand.settle_post_terminal(RecoveryAttempt::Refused),
            RecoveryDemandSettlement::Unsatisfied
        );
        assert_eq!(
            demand.settle_post_terminal(RecoveryAttempt::Accepted),
            RecoveryDemandSettlement::Satisfied
        );
        assert_eq!(
            demand.settle_post_terminal(RecoveryAttempt::Accepted),
            RecoveryDemandSettlement::NoDemand
        );
    }

    #[test]
    fn recovery_demand_cancellation_is_terminal_for_successor_and_shutdown() {
        let successor = unmetered_control_handle();
        assert!(successor.cancel());
        assert!(!successor.cancel());
        assert_eq!(
            successor.settle_post_terminal(RecoveryAttempt::Accepted),
            RecoveryDemandSettlement::NoDemand
        );

        let shutdown = unmetered_control_handle();
        shutdown.mark_terminal();
        assert!(shutdown.cancel());
        assert_eq!(
            shutdown.settle_post_terminal(RecoveryAttempt::Accepted),
            RecoveryDemandSettlement::NoDemand
        );
    }
}
