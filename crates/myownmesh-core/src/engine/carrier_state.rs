//! Provider-owned carrier emission and recovery custody.

use std::sync::Arc;

use super::peer_registry::PeerOwnerToken;
use super::state::{NetworkState, RecoveryCarrierInstance, RecoveryPublishId, SignalingEmissionId};
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease, ResourceUnavailable};

pub(super) struct CarrierState {
    pub(super) attempts: parking_lot::Mutex<CarrierAttemptList>,
}

impl Default for CarrierState {
    fn default() -> Self {
        Self {
            attempts: parking_lot::Mutex::new(CarrierAttemptList::default()),
        }
    }
}

pub(super) struct RecoveryCohort {
    pub(super) pending: RecoveryCohortCauseList,
    pub(super) in_flight: Option<RecoveryCohortGeneration>,
    pub(super) next_generation: u64,
    pub(super) queued_publication: Option<RecoveryPublishId>,
    pub(super) publication: Option<RecoveryPublication>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CarrierEmissionRecord {
    Stale,
    Pending,
    Accepted,
    FinalRefusal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CarrierEmissionAdmission {
    Admitted,
    Existing,
    Stale,
    Refused,
}

impl CarrierEmissionAdmission {
    pub(crate) fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted | Self::Existing)
    }
}

pub(crate) struct CarrierEmissionSettlement {
    pub(crate) record: CarrierEmissionRecord,
    pub(crate) owner: Option<PeerOwnerToken>,
}

pub(super) struct RecoveryPublication {
    pub(super) id: RecoveryPublishId,
    pub(super) remaining: CarrierInstanceList,
}

/// Outcome of admitting one queued recovery generation to a finite carrier
/// cohort.  `Refused` is terminal for this carrier admission only: the exact
/// generation is rolled back to pending so a later explicit attach can retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryPublicationStart {
    Started(RecoveryPublishId),
    Stale,
    Refused(ResourceUnavailable),
}

impl RecoveryPublicationStart {
    pub(super) fn into_started(self) -> Option<RecoveryPublishId> {
        match self {
            Self::Started(id) => Some(id),
            Self::Stale | Self::Refused(_) => None,
        }
    }
}

#[derive(Default)]
pub(super) struct CarrierInstanceList {
    pub(super) head: Option<Box<CarrierInstanceNode>>,
}

pub(super) struct CarrierInstanceNode {
    pub(super) instance: RecoveryCarrierInstance,
    pub(super) _lease: ResourceLease,
    pub(super) next: Option<Box<CarrierInstanceNode>>,
}

impl CarrierInstanceList {
    pub(super) fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    pub(super) fn contains(&self, instance: RecoveryCarrierInstance) -> bool {
        let mut cursor = self.head.as_deref();
        while let Some(node) = cursor {
            if node.instance == instance {
                return true;
            }
            cursor = node.next.as_deref();
        }
        false
    }

    pub(super) fn push_front(&mut self, mut node: Box<CarrierInstanceNode>) {
        node.next = self.head.take();
        self.head = Some(node);
    }

    pub(super) fn pop_front(&mut self) -> Option<Box<CarrierInstanceNode>> {
        let mut node = self.head.take()?;
        self.head = node.next.take();
        Some(node)
    }

    pub(super) fn remove(
        &mut self,
        instance: RecoveryCarrierInstance,
    ) -> Option<Box<CarrierInstanceNode>> {
        let mut link = &mut self.head;
        loop {
            match link {
                Some(node) if node.instance == instance => {
                    let mut removed = link.take().expect("matched carrier instance");
                    *link = removed.next.take();
                    return Some(removed);
                }
                Some(node) => link = &mut node.next,
                None => return None,
            }
        }
    }
}

impl Drop for CarrierInstanceList {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

pub(super) struct CarrierAttemptNode {
    pub(super) emission: SignalingEmissionId,
    pub(super) attempt: String,
    pub(super) owner: Option<PeerOwnerToken>,
    pub(super) _entry_lease: Option<ResourceLease>,
    pub(super) carriers: Option<Box<CarrierAttemptCarrier>>,
    pub(super) expected: usize,
    pub(super) resolved: usize,
    pub(super) accepted: bool,
    pub(super) claimed: bool,
    pub(super) fenced: bool,
    pub(super) terminal: Option<CarrierEmissionRecord>,
    pub(super) next: Option<Box<CarrierAttemptNode>>,
}

pub(super) struct CarrierAttemptCarrier {
    pub(super) instance: RecoveryCarrierInstance,
    pub(super) resolved: bool,
    pub(super) accepted: bool,
    pub(super) next: Option<Box<CarrierAttemptCarrier>>,
}

impl CarrierAttemptNode {
    pub(super) fn carrier_mut(
        &mut self,
        instance: RecoveryCarrierInstance,
    ) -> Option<&mut CarrierAttemptCarrier> {
        let mut cursor = self.carriers.as_deref_mut();
        while let Some(carrier) = cursor {
            if carrier.instance == instance {
                return Some(carrier);
            }
            cursor = carrier.next.as_deref_mut();
        }
        None
    }

    pub(super) fn remove_carrier(&mut self, instance: RecoveryCarrierInstance) -> bool {
        let mut link = &mut self.carriers;
        loop {
            if link
                .as_ref()
                .is_some_and(|carrier| carrier.instance == instance)
            {
                let mut removed = link.take().expect("matched carrier copy");
                *link = removed.next.take();
                return true;
            }
            match link.as_mut() {
                Some(carrier) => link = &mut carrier.next,
                None => return false,
            }
        }
    }

    pub(super) fn remaining_carriers(&self) -> usize {
        let mut count = 0usize;
        let mut cursor = self.carriers.as_deref();
        while let Some(carrier) = cursor {
            count = count.saturating_add(1);
            cursor = carrier.next.as_deref();
        }
        count
    }

    pub(super) fn resize_tombstone_lease(&mut self) {
        let remaining = self.remaining_carriers();
        let Some(bytes) = std::mem::size_of::<CarrierAttemptNode>()
            .checked_add(self.attempt.len())
            .and_then(|bytes| {
                bytes.checked_add(
                    remaining.checked_mul(std::mem::size_of::<CarrierAttemptCarrier>())?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
        else {
            return;
        };
        let Some(residuals) = remaining.checked_add(1).and_then(|n| u64::try_from(n).ok()) else {
            return;
        };
        let Ok(claim) = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, residuals),
        ]) else {
            return;
        };
        let Some(lease) = self._entry_lease.as_mut() else {
            return;
        };
        // A reduction can only fail if the provider itself is inconsistent;
        // retaining the larger already-funded lease is safe in that case.
        let _ = lease.transition(claim);
    }
}

impl Drop for CarrierAttemptNode {
    fn drop(&mut self) {
        let mut cursor = self.carriers.take();
        while let Some(mut carrier) = cursor {
            cursor = carrier.next.take();
        }
    }
}

#[derive(Default)]
pub(super) struct CarrierAttemptList {
    pub(super) head: Option<Box<CarrierAttemptNode>>,
}

impl CarrierAttemptList {
    pub(super) fn emissions_for_owner(
        &self,
        owner: &PeerOwnerToken,
    ) -> Vec<(SignalingEmissionId, String)> {
        let mut emissions = Vec::new();
        let mut cursor = self.head.as_deref();
        while let Some(node) = cursor {
            if node.owner.as_ref().is_some_and(|candidate| {
                Arc::ptr_eq(candidate.connection(), owner.connection())
                    && candidate.binding_coordinate() == owner.binding_coordinate()
            }) {
                emissions.push((node.emission, node.attempt.clone()));
            }
            cursor = node.next.as_deref();
        }
        emissions
    }

    pub(super) fn settle_emission(&mut self, emission: SignalingEmissionId, attempt: &str) -> bool {
        self.remove_emission(emission, attempt).is_some()
    }

    pub(super) fn find_emission_mut(
        &mut self,
        emission: SignalingEmissionId,
        attempt: &str,
    ) -> Option<&mut CarrierAttemptNode> {
        let mut cursor = self.head.as_deref_mut();
        while let Some(node) = cursor {
            if node.emission == emission && node.attempt == attempt {
                return Some(node);
            }
            cursor = node.next.as_deref_mut();
        }
        None
    }

    pub(super) fn push_front(&mut self, mut node: Box<CarrierAttemptNode>) {
        node.next = self.head.take();
        self.head = Some(node);
    }

    pub(super) fn remove_emission(
        &mut self,
        emission: SignalingEmissionId,
        attempt: &str,
    ) -> Option<Box<CarrierAttemptNode>> {
        let mut link = &mut self.head;
        loop {
            if link
                .as_ref()
                .is_some_and(|node| node.emission == emission && node.attempt == attempt)
            {
                let mut removed = link.take().expect("matched emission node");
                *link = removed.next.take();
                return Some(removed);
            }
            match link.as_mut() {
                Some(node) => link = &mut node.next,
                None => return None,
            }
        }
    }

    pub(super) fn fence_attempt(&mut self, attempt: &str) {
        let mut cursor = self.head.as_deref_mut();
        while let Some(node) = cursor {
            if node.attempt == attempt {
                node.fenced = true;
                node.terminal = Some(CarrierEmissionRecord::Stale);
                // Retain only the bounded stale witness. The lease is reduced
                // to the exact remaining physical carrier copies below; it is
                // never dropped while one delayed copy can still acknowledge.
                node.owner = None;
                node.resize_tombstone_lease();
            }
            cursor = node.next.as_deref_mut();
        }
        self.remove_empty_fenced();
    }

    pub(super) fn acknowledge_terminal(
        &mut self,
        emission: SignalingEmissionId,
        attempt: &str,
        instance: RecoveryCarrierInstance,
    ) -> bool {
        let mut link = &mut self.head;
        loop {
            let matches = link.as_ref().is_some_and(|node| {
                node.emission == emission && node.attempt == attempt && node.terminal.is_some()
            });
            if matches {
                let remove = {
                    let node = link.as_mut().expect("matched terminal emission");
                    if !node.remove_carrier(instance) {
                        return false;
                    }
                    if node.carriers.is_none() && node.fenced {
                        true
                    } else {
                        node.resize_tombstone_lease();
                        false
                    }
                };
                if remove {
                    let mut removed = link.take().expect("matched fenced emission");
                    *link = removed.next.take();
                    return true;
                }
                return false;
            }
            match link.as_mut() {
                Some(node) => link = &mut node.next,
                None => return false,
            }
        }
    }

    pub(super) fn remove_empty_fenced(&mut self) {
        let mut link = &mut self.head;
        loop {
            let remove = link
                .as_ref()
                .is_some_and(|node| node.fenced && node.carriers.is_none());
            if remove {
                let mut removed = link.take().expect("matched empty fenced emission");
                *link = removed.next.take();
                continue;
            }
            match link.as_mut() {
                Some(node) => link = &mut node.next,
                None => return,
            }
        }
    }

    pub(super) fn remove_unfenced(&mut self, attempt: &str) {
        let mut link = &mut self.head;
        loop {
            let remove = link
                .as_ref()
                .is_some_and(|node| node.attempt == attempt && !node.fenced);
            if remove {
                let mut removed = link.take().expect("matched unfenced attempt node");
                *link = removed.next.take();
                continue;
            }
            match link.as_mut() {
                Some(node) => link = &mut node.next,
                None => return,
            }
        }
    }
}

impl Drop for CarrierAttemptList {
    fn drop(&mut self) {
        while let Some(mut node) = self.head.take() {
            self.head = node.next.take();
        }
    }
}

pub(super) struct RecoveryCohortGeneration {
    pub(super) id: RecoveryPublishId,
    pub(super) causes: RecoveryCohortCauseList,
}

pub(super) struct RecoveryCohortCause {
    pub(super) owner: PeerOwnerToken,
    pub(super) demand: crate::runtime::peer_session::RecoveryDemandHandle,
    pub(super) collection_lease: ResourceLease,
    pub(super) next: Option<Box<RecoveryCohortCause>>,
}

impl RecoveryCohortCause {
    pub(super) fn release(self) {
        let Self {
            owner,
            demand,
            collection_lease,
            next,
        } = self;
        drop(next);
        drop(collection_lease);
        drop(demand);
        drop(owner);
    }

    pub(super) fn cancel(self) {
        let Self {
            owner,
            demand,
            collection_lease,
            next,
        } = self;
        demand.cancel();
        drop(next);
        drop(collection_lease);
        drop(demand);
        drop(owner);
    }
}

#[derive(Default)]
pub(super) struct RecoveryCohortCauseList {
    pub(super) head: Option<Box<RecoveryCohortCause>>,
}

impl RecoveryCohortCauseList {
    pub(super) fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    pub(super) fn push_front(&mut self, mut cause: Box<RecoveryCohortCause>) {
        cause.next = self.head.take();
        self.head = Some(cause);
    }

    pub(super) fn pop_front(&mut self) -> Option<Box<RecoveryCohortCause>> {
        let mut cause = self.head.take()?;
        self.head = cause.next.take();
        Some(cause)
    }

    pub(super) fn append(&mut self, other: &mut Self) {
        while let Some(cause) = other.pop_front() {
            self.push_front(cause);
        }
    }

    pub(super) fn contains_owner(&self, owner: &PeerOwnerToken) -> bool {
        let mut cursor = self.head.as_deref();
        while let Some(cause) = cursor {
            if NetworkState::same_recovery_owner(&cause.owner, owner) {
                return true;
            }
            cursor = cause.next.as_deref();
        }
        false
    }
}

impl Drop for RecoveryCohortCauseList {
    fn drop(&mut self) {
        let mut cursor = self.head.take();
        while let Some(mut cause) = cursor {
            cursor = cause.next.take();
        }
    }
}

impl RecoveryCohort {
    pub(super) fn new() -> Self {
        Self {
            pending: RecoveryCohortCauseList::default(),
            in_flight: None,
            next_generation: 0,
            queued_publication: None,
            publication: None,
        }
    }
}
