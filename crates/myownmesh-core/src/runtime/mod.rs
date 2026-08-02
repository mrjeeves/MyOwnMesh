//! Target-owned runtime nodes introduced by the V4 transition.

use std::sync::Arc;

pub mod attempt;
pub mod relay;
pub mod session_broker;

/// Memory-only witness for one process runtime.
///
/// Capabilities retain this witness so a value from one runtime cannot be
/// combined with a principal or permit from another runtime. The marker has no
/// serialized representation and cannot be created through the public API.
/// Possession does not detect a same-process runtime replacement by itself.
/// Every future authority consumer must compare this witness with the Runtime
/// Supervisor's current witness before use.
#[derive(Clone)]
#[allow(
    dead_code,
    reason = "Arc 02 links this witness before production capability migration"
)]
pub(crate) struct RuntimeIncarnation {
    marker: Arc<RuntimeMarker>,
}

struct RuntimeMarker;

#[allow(
    dead_code,
    reason = "Arc 02 links this witness before production capability migration"
)]
impl RuntimeIncarnation {
    pub(crate) fn new() -> Self {
        Self {
            marker: Arc::new(RuntimeMarker),
        }
    }

    pub(crate) fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.marker, &other.marker)
    }
}

#[cfg(test)]
pub(crate) fn runtime_for_test() -> RuntimeIncarnation {
    RuntimeIncarnation::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_fresh_runtime_witnesses_are_distinct() {
        let first = runtime_for_test();
        let second = runtime_for_test();

        assert!(first.is_same(&first));
        assert!(!first.is_same(&second));
    }
}
