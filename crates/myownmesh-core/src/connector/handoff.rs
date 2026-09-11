//! Connector-owned handoff of a working channel to its next owner.
//!
//! This is the generic form of what the WebRTC adapter previously owned
//! directly. It carries three things and nothing else: the move-only connected
//! capability, the opaque connector incarnation that produced it, and the
//! connector-owned retention that must re-take the claim if the handoff is
//! dropped.

use super::incarnation::ConnectorIncarnation;
use super::ConnectedChannelCapability;
use std::sync::Arc;

/// The connector-owned obligation to re-retain a connected claim.
///
/// One method, one purpose. This exists because [`ConnectedChannelHandoff`] is
/// generic over connectors while the retention it must run on drop is
/// transport-specific: the WebRTC close owner knows how to hold the claim
/// through native close, and no generic type can. It is deliberately not a
/// behaviour grab bag — nothing else may be added to it, and it exposes no
/// downcast, so a downstream owner cannot recover the transport from it.
pub(crate) trait ConnectedChannelRetention: Send + Sync {
    /// Take the claim back into connector-owned retention.
    fn retain_connected_claim(self: Arc<Self>, capability: ConnectedChannelCapability);
}

/// One move-only handoff from an exact connector incarnation to its next
/// owner.
///
/// Promotion moves the **whole** handoff, because this type is what carries the
/// connector incarnation and the retention owner, and its `Drop` is what
/// re-retains the connected claim until native close succeeds. There is
/// deliberately no `take`/`restore` of the bare capability: extracting it alone
/// would strip that retention, so an authenticated capability dropped on
/// retirement or on a refused install would release the claim early.
pub(crate) struct ConnectedChannelHandoff {
    capability: Option<ConnectedChannelCapability>,
    incarnation: Arc<ConnectorIncarnation>,
    retention: Arc<dyn ConnectedChannelRetention>,
}

impl ConnectedChannelHandoff {
    /// Construct the handoff.
    ///
    /// Crate-private, and in practice called only by a connector that already
    /// holds both the capability and its own retention owner. No application,
    /// wire, or endpoint-authentication caller can assemble one.
    pub(crate) fn new(
        capability: ConnectedChannelCapability,
        incarnation: Arc<ConnectorIncarnation>,
        retention: Arc<dyn ConnectedChannelRetention>,
    ) -> Self {
        Self {
            capability: Some(capability),
            incarnation,
            retention,
        }
    }

    /// Whether this channel belongs to that exact incarnation.
    pub(crate) fn belongs_to(&self, incarnation: &Arc<ConnectorIncarnation>) -> bool {
        self.incarnation.is_same(incarnation)
    }

    /// The exact connector incarnation this channel belongs to.
    pub(crate) fn incarnation(&self) -> &Arc<ConnectorIncarnation> {
        &self.incarnation
    }

    /// Borrow the connected capability without consuming the handoff.
    ///
    /// Endpoint authentication validates against this borrow before it takes
    /// anything, so a refused attempt leaves the handoff intact and `Drop`
    /// still re-retains the claim.
    pub(crate) fn capability(&self) -> Option<&ConnectedChannelCapability> {
        self.capability.as_ref()
    }
}

impl Drop for ConnectedChannelHandoff {
    fn drop(&mut self) {
        if let Some(capability) = self.capability.take() {
            Arc::clone(&self.retention).retain_connected_claim(capability);
        }
    }
}

/// Retention that simply drops the claim, for fixtures with no close owner.
#[cfg(test)]
struct DiscardingRetention;

#[cfg(test)]
impl ConnectedChannelRetention for DiscardingRetention {
    fn retain_connected_claim(self: Arc<Self>, capability: ConnectedChannelCapability) {
        drop(capability);
    }
}

/// One handoff over a fixture channel, with a fresh incarnation.
///
/// Test-only, and deliberately not a production constructor: it has no close
/// owner to retain through, so it must never stand in for a real connector
/// handoff on a production path.
#[cfg(test)]
pub(crate) fn handoff_for_test(
    runtime: crate::runtime::RuntimeIncarnation,
) -> ConnectedChannelHandoff {
    ConnectedChannelHandoff::new(
        super::connected_for_test(runtime),
        ConnectorIncarnation::new(),
        Arc::new(DiscardingRetention),
    )
}

/// Retention that counts how many times a claim came back to it.
///
/// For controls where "the claim is returned" is not enough and the property is
/// that it is returned **exactly once** — a second return would mean a lifecycle
/// path released the same claim twice.
#[cfg(test)]
pub(crate) struct CountedRetention {
    retained: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl CountedRetention {
    pub(crate) fn count(&self) -> usize {
        self.retained.load(std::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(test)]
impl ConnectedChannelRetention for CountedRetention {
    fn retain_connected_claim(self: Arc<Self>, capability: ConnectedChannelCapability) {
        self.retained
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        drop(capability);
    }
}

/// A fixture handoff plus the retention owner that observes its claim.
#[cfg(test)]
pub(crate) fn counted_handoff_for_test(
    runtime: crate::runtime::RuntimeIncarnation,
) -> (ConnectedChannelHandoff, Arc<CountedRetention>) {
    let retention = Arc::new(CountedRetention {
        retained: std::sync::atomic::AtomicUsize::new(0),
    });
    let handoff = ConnectedChannelHandoff::new(
        super::connected_for_test(runtime),
        ConnectorIncarnation::new(),
        Arc::clone(&retention) as Arc<dyn ConnectedChannelRetention>,
    );
    (handoff, retention)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingRetention {
        retained: AtomicUsize,
    }

    impl ConnectedChannelRetention for CountingRetention {
        fn retain_connected_claim(self: Arc<Self>, capability: ConnectedChannelCapability) {
            self.retained.fetch_add(1, Ordering::Release);
            drop(capability);
        }
    }

    #[test]
    fn v4_arc04b_dropped_handoff_returns_the_claim_to_connector_retention() {
        let runtime = crate::runtime::runtime_for_test();
        let retention = Arc::new(CountingRetention {
            retained: AtomicUsize::new(0),
        });
        let incarnation = ConnectorIncarnation::new();
        let handoff = ConnectedChannelHandoff::new(
            super::super::connected_for_test(runtime),
            Arc::clone(&incarnation),
            Arc::clone(&retention) as Arc<dyn ConnectedChannelRetention>,
        );

        assert!(handoff.belongs_to(&incarnation));
        assert!(handoff.capability().is_some());
        assert_eq!(retention.retained.load(Ordering::Acquire), 0);

        drop(handoff);

        assert_eq!(retention.retained.load(Ordering::Acquire), 1);
    }
}
