//! The compact accepted-entry representation every gateway queue is built on.

use crate::resource::{
    LeasedQueue, ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease,
};

/// The exact successful Application Gateway acceptance point. Construction is
/// possible only after a live receiver and both value/node leases exist.
pub(crate) struct GatewayAccepted;

struct GatewayEntry<T> {
    value: T,
    _retention: ResourceLease,
}

/// One accepted delivery after its mailbox node has been released. The value's
/// off-node retention remains funded until this wrapper is consumed or dropped.
///
/// The gateway sibling of [`crate::resource::ResourceMailboxDelivery`], and it
/// keeps the same rule for the same reason: the value is declared before the
/// lease, fields are destroyed in declaration order, so the funding is released
/// after the bytes it pays for are gone. Handing the two out as a tuple made
/// that order the caller's to get right, and a caller that bound the lease to a
/// throwaway name could release it while the value was still being deserialized
/// into a longer-lived owner.
///
/// The lease carries an underscore because it is never *read* in a production
/// build — it is held, and its `Drop` at the end of this struct's is the entire
/// job. Reading it would mean handing it somewhere, which is the split this
/// type exists to prevent. Same spelling and same reason as
/// `GatewayEntry::_retention` above; the name is what keeps `dead_code` honest
/// rather than silenced by an allow.
pub(crate) struct GatewayDelivery<T> {
    value: T,
    _retention: ResourceLease,
}

impl<T> GatewayDelivery<T> {
    /// The delivered value, borrowed. The funding outlives the borrow.
    ///
    /// The whole read surface. An owner that needs the value to keep living —
    /// an `RpcStreamChunk` — stores this delivery itself and reads through
    /// here, rather than taking the value out and the funding beside it.
    pub(crate) fn value(&self) -> &T {
        &self.value
    }

    /// Split the delivery into its two halves. **Controls only** — a control
    /// that asserts on the funding has to hold both at once to see it.
    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (T, ResourceLease) {
        (self.value, self._retention)
    }
}

/// Compact one-allocation-per-entry mailbox representation. The queue lease
/// funds only its node; the entry keeps off-node retention funded after pop.
pub(crate) struct GatewayMailbox<T> {
    queue: LeasedQueue<GatewayEntry<T>>,
}

impl<T> GatewayMailbox<T> {
    pub(crate) const fn new() -> Self {
        Self {
            queue: LeasedQueue::new(),
        }
    }

    pub(crate) fn node_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        LeasedQueue::<GatewayEntry<T>>::entry_claim()
    }

    /// Claim the producer-measured off-node representation retained by one
    /// value. Allocation count is explicit because a serialized byte block and
    /// a decoded tree are different representations and must not share a guess.
    /// What one queued item retains, in the three figures that are genuinely
    /// three different things.
    ///
    /// `retained_bytes` and `queued_bytes` used to be one argument used twice,
    /// which is right only when the queued form and the retained form are the
    /// same size. For a flat name or a byte string they are. For a
    /// `serde_json::Value` they are not, and the ratio between them is chosen by
    /// whoever sent it: `[[[[]]]]` is a handful of queued bytes and a chain of
    /// separately allocated nodes in memory. A caller that has both figures
    /// passes both; one whose item is flat passes the same number twice, which
    /// is the old behaviour stated rather than assumed.
    pub(crate) fn retention_claim(
        retained_bytes: usize,
        queued_bytes: usize,
        allocations: usize,
    ) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let retained_bytes =
            u64::try_from(retained_bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        let queued_bytes =
            u64::try_from(queued_bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::QueuedBytes,
            })?;
        let allocations =
            u64::try_from(allocations).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::OpaqueDependencyResidual,
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, retained_bytes),
            (ResourceClass::QueuedBytes, queued_bytes),
            (ResourceClass::OpaqueDependencyResidual, allocations),
        ])
    }

    pub(crate) fn accept(
        &mut self,
        value: T,
        retention: ResourceLease,
        node: ResourceLease,
    ) -> GatewayAccepted {
        self.queue.push(
            GatewayEntry {
                value,
                _retention: retention,
            },
            node,
        );
        GatewayAccepted
    }

    pub(crate) fn pop(&mut self) -> Option<GatewayDelivery<T>> {
        self.queue.pop_front().map(|entry| GatewayDelivery {
            value: entry.value,
            _retention: entry._retention,
        })
    }

    #[cfg(test)]
    pub(crate) const fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    use crate::resource::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort, ResourceScope,
    };

    fn mailbox_provider(
        node: ResourceClaim,
        retention: ResourceClaim,
    ) -> (FiniteResourceProvider, ResourceProviderPort, ResourceScope) {
        let scope_record = FiniteResourceProvider::scope_record_charge_for_test();
        let grant = scope_record
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(node)
                    .expect("the node reservation is representable"),
            )
            .and_then(|grant| {
                grant.checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(retention)
                        .expect("the retention reservation is representable"),
                )
            })
            .expect("one mailbox entry and its provider records compose");
        let provider = FiniteResourceProvider::new(grant);
        let port =
            ResourceProviderPort::new(provider.clone()).expect("the grant funds the process scope");
        let scope = port.process_scope();
        (provider, port, scope)
    }

    #[test]
    fn gateway_pop_releases_node_but_delivery_keeps_retention_funded() {
        let node = GatewayMailbox::<Bytes>::node_claim().expect("node claim is representable");
        let retention = GatewayMailbox::<Bytes>::retention_claim(4, 4, 1)
            .expect("retention claim is representable");
        let (provider, port, scope) = mailbox_provider(node, retention);
        let baseline = provider.in_use();
        let retention_lease = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, retention)
            .expect("the exact retention claim is available");
        let node_lease = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, node)
            .expect("the exact node claim is available");
        let mut mailbox = GatewayMailbox::new();
        let _accepted = mailbox.accept(Bytes::from_static(b"test"), retention_lease, node_lease);
        assert!(!mailbox.is_empty(), "acceptance installed one real entry");

        let delivery = mailbox.pop().expect("the accepted entry is delivered");
        let (value, retention_lease) = delivery.into_parts();
        assert_eq!(value, Bytes::from_static(b"test"));
        assert!(mailbox.is_empty(), "pop released the mailbox node");
        assert_eq!(
            provider.in_use(),
            baseline
                .checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(retention)
                        .expect("the retention reservation is representable"),
                )
                .expect("baseline and retention compose"),
            "the returned delivery still owns its exact off-node retention",
        );
        drop((value, retention_lease));
        let after_removed_value_drop = provider.in_use();
        assert_eq!(after_removed_value_drop, baseline);
    }
}
