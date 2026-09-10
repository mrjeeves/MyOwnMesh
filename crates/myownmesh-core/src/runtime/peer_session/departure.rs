//! Lifecycle-owned graceful departure state for one promoted logical session.
//!
//! The state is deliberately below the engine.  A pending local observation
//! is funded by the logical validity lineage that admitted it, while a remote
//! departure is a one-way terminal transition on that same lineage.  Neither
//! path names a device, channel generation, route, timer, or retry policy.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

use crate::protocol::DepartureCorrelation;
use crate::resource::{
    ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceUnavailable,
};

use super::LogicalSessionValidityWitness;

const PENDING: u8 = 0;
const OBSERVED: u8 = 1;
const CANCELLED: u8 = 2;

/// Opaque process-local identity of the connector that carried the local
/// Depart. It is never serialized or used as routing/session identity.
#[derive(Clone)]
pub(crate) struct DepartureCarrier(Arc<crate::connector::ConnectorIncarnation>);

impl DepartureCarrier {
    pub(crate) fn new(value: Arc<crate::connector::ConnectorIncarnation>) -> Self {
        Self(value)
    }

    fn same(&self, other: &Self) -> bool {
        self.0.is_same(&other.0)
    }
}

struct PendingObservation {
    outcome: AtomicU8,
    wake: Notify,
}

impl PendingObservation {
    fn new() -> Self {
        Self {
            outcome: AtomicU8::new(PENDING),
            wake: Notify::new(),
        }
    }

    fn observed(&self) -> bool {
        self.outcome
            .compare_exchange(PENDING, OBSERVED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn cancel(&self) -> bool {
        self.outcome
            .compare_exchange(PENDING, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

struct PendingDeparture {
    correlation: DepartureCorrelation,
    carrier: DepartureCarrier,
    observation: Arc<PendingObservation>,
    /// This lease is the one pending observation owner. It remains held in
    /// the logical state until the matching receipt, exact carrier failure,
    /// or until the session is invalidated and the record is dropped.
    _lease: ResourceLease,
}

/// Why a local departure could not become the one pending observation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DepartureAdmissionError {
    #[error("a local departure observation is already pending")]
    AlreadyPending,
    #[error("the logical session is already terminal")]
    Terminal,
    #[error("departure observation resources were unavailable: {0}")]
    ResourceUnavailable(#[source] ResourceUnavailable),
    #[error("departure observation claim arithmetic failed: {0}")]
    Arithmetic(#[source] ResourceClaimArithmeticError),
}

/// The result of waiting for the exact receipt or for the existing lifecycle
/// validity to cancel the wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DepartureWaitOutcome {
    Observed,
    Cancelled,
}

/// Move-only caller-side handle for one pending local observation.
///
/// The handle contains no routing or session identity.  Its correlation is
/// only the opaque value that must match the remote receipt; the logical
/// witness supplied to [`Self::wait`] remains the authority and cancellation
/// boundary.
pub(crate) struct DepartureWaiter {
    observation: Arc<PendingObservation>,
}

impl DepartureWaiter {
    pub(crate) async fn wait(
        &self,
        validity: &LogicalSessionValidityWitness,
    ) -> DepartureWaitOutcome {
        loop {
            match self.observation.outcome.load(Ordering::Acquire) {
                OBSERVED => return DepartureWaitOutcome::Observed,
                CANCELLED => return DepartureWaitOutcome::Cancelled,
                _ => {}
            }
            if !validity.is_live() {
                return DepartureWaitOutcome::Cancelled;
            }
            let notified = self.observation.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.observation.outcome.load(Ordering::Acquire) {
                OBSERVED => return DepartureWaitOutcome::Observed,
                CANCELLED => return DepartureWaitOutcome::Cancelled,
                _ => {}
            }
            if !validity.is_live() {
                return DepartureWaitOutcome::Cancelled;
            }
            tokio::select! {
                _ = notified => {}
                _ = validity.revoked() => return DepartureWaitOutcome::Cancelled,
            }
        }
    }
}

/// State owned by exactly one [`LogicalSessionRecord`].
pub(crate) struct DepartureState {
    pending: Option<PendingDeparture>,
    remote_terminal: bool,
    recovery: super::recovery::RecoveryDemandState,
}

impl DepartureState {
    pub(crate) fn new() -> Self {
        Self {
            pending: None,
            remote_terminal: false,
            recovery: super::recovery::RecoveryDemandState::new(),
        }
    }

    fn claim(
        correlation: &DepartureCorrelation,
    ) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let bytes = u64::try_from(correlation.as_str().len())
            .ok()
            .and_then(|length| {
                u64::try_from(std::mem::size_of::<PendingDeparture>())
                    .ok()?
                    .checked_add(length)
            })
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    pub(crate) fn begin_local(
        &mut self,
        correlation: DepartureCorrelation,
        carrier: DepartureCarrier,
        validity: &LogicalSessionValidityWitness,
    ) -> Result<DepartureWaiter, DepartureAdmissionError> {
        if self.remote_terminal {
            return Err(DepartureAdmissionError::Terminal);
        }
        if self.pending.is_some() {
            return Err(DepartureAdmissionError::AlreadyPending);
        }
        let lease = validity
            .reserve_retained(
                Self::claim(&correlation).map_err(DepartureAdmissionError::Arithmetic)?,
            )
            .map_err(DepartureAdmissionError::ResourceUnavailable)?;
        let observation = Arc::new(PendingObservation::new());
        let waiter = DepartureWaiter {
            observation: Arc::clone(&observation),
        };
        self.pending = Some(PendingDeparture {
            correlation,
            carrier,
            observation,
            _lease: lease,
        });
        Ok(waiter)
    }

    /// Mark the one matching local receipt observed.  The lease is dropped
    /// only after the exact correlation has won the state transition.
    pub(crate) fn observe_local(&mut self, correlation: &DepartureCorrelation) -> bool {
        let Some(pending) = self.pending.take() else {
            return false;
        };
        if pending.correlation != *correlation {
            self.pending = Some(pending);
            return false;
        }
        if !pending.observation.observed() {
            self.pending = Some(pending);
            return false;
        }
        pending.observation.wake.notify_waiters();
        true
    }

    /// Accept a remote departure exactly once. A simultaneous local pending
    /// observation remains independently owned and is cancelled only by its
    /// own receipt, exact carrier failure, or logical validity revocation;
    /// the remote frame is never reinterpreted as that local receipt.
    pub(crate) fn accept_remote(&mut self, _correlation: &DepartureCorrelation) -> bool {
        if self.remote_terminal {
            return false;
        }
        self.remote_terminal = true;
        self.recovery.mark_terminal();
        true
    }

    pub(crate) fn arm_recovery(
        &mut self,
        validity: &LogicalSessionValidityWitness,
    ) -> Result<super::recovery::RecoveryDemandAdmission, super::recovery::RecoveryDemandError>
    {
        self.recovery.arm(validity)
    }

    pub(crate) fn cancel_recovery_for_shutdown(&mut self) -> bool {
        self.recovery.cancel_for_shutdown()
    }

    pub(crate) fn cancel_recovery_for_usable_successor(&mut self) -> bool {
        self.recovery.cancel_for_usable_successor()
    }

    /// Cancel only the local observation carried by this exact connector.
    pub(crate) fn cancel_for_carrier(&mut self, carrier: DepartureCarrier) -> bool {
        let Some(pending) = self.pending.take() else {
            return false;
        };
        if !pending.carrier.same(&carrier) {
            self.pending = Some(pending);
            return false;
        }
        if !pending.observation.cancel() {
            self.pending = Some(pending);
            return false;
        }
        pending.observation.wake.notify_waiters();
        true
    }

    /// Cancel the one pending observation because shutdown has become the
    /// winning lifecycle owner. This is a direct cancellation edge, not a
    /// timer or retry policy; the exact logical record and its lease remain
    /// the only state being touched.
    pub(crate) fn cancel_for_shutdown(&mut self) -> bool {
        let Some(pending) = self.pending.take() else {
            return false;
        };
        if !pending.observation.cancel() {
            self.pending = Some(pending);
            return false;
        }
        pending.observation.wake.notify_waiters();
        true
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}
