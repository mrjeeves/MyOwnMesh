//! Opaque process-local identity for one connector incarnation.
//!
//! Endpoint authentication must be able to name *which* connector produced a
//! channel without importing that connector's transport types. This module
//! owns that identity, and nothing else: it carries no transport state, no
//! capability, no liveness, and no authority.
//!
//! Generality here comes from the connector minting the token, not from
//! erasing a transport behind a trait object. A transport keeps its own
//! incarnation type and owns one of these; downstream owners compare this one.

use std::sync::Arc;

/// Exact process-local identity for one connector incarnation.
///
/// Identity only. Holding one proves that a connector incarnation existed and
/// lets an owner ask whether another handle names that same incarnation —
/// nothing more.
///
/// Liveness is deliberately absent. The transport's own incarnation is the
/// single authoritative source for whether a connector is still live, and a
/// second flag here would be a duplicate that could disagree with it. Nothing
/// downstream asks this type "are you still live"; the questions it exists to
/// answer are "which connector produced this channel" and "is that the same one
/// I hold", both of which stay truthful after retirement.
///
/// It is crate-private, has no public constructor, is not `Clone` by value, and
/// is not serializable: no public or wire caller can name, mint, or rebind one.
/// Runtime owners share the exact instance through `Arc`, and identity *is* that
/// `Arc`'s allocation — the same construction the engine's peer-installation
/// token uses.
pub(crate) struct ConnectorIncarnation {}

impl ConnectorIncarnation {
    /// Mint one identity.
    ///
    /// Crate-private on purpose: only connector-owned construction may create
    /// an incarnation, so an application or wire value can never produce one.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {})
    }

    /// Exact identity comparison.
    ///
    /// Pointer equality, so a different incarnation is a different incarnation
    /// regardless of anything else. A caller that also needs "and still live"
    /// asks the transport, which owns that fact.
    pub(crate) fn is_same(self: &Arc<Self>, other: &Arc<Self>) -> bool {
        Arc::ptr_eq(self, other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc04b_connector_incarnation_is_exact_identity_only() {
        let first = ConnectorIncarnation::new();
        let second = ConnectorIncarnation::new();

        assert!(first.is_same(&Arc::clone(&first)));
        assert!(!first.is_same(&second));
        // Two separately minted identities are distinct even though the type
        // carries no state to tell them apart: the identity is the allocation,
        // so this is what would break if the token ever became something
        // shareable or reconstructible rather than minted once per connector.
        assert!(!Arc::ptr_eq(&first, &second));
    }
}
