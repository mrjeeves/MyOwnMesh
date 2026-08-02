//! Exact relay-allocation permit boundary for V4.
//!
//! Arc 02 defines the permit type only. It does not retain ordinary member
//! forwarding or create a relay allocation.

use crate::runtime::RuntimeIncarnation;

/// Proof that one exact relay allocation was admitted for one runtime.
///
/// This type does not imply endpoint authentication, session promotion,
/// arbitrary destination selection, fanout, or application parsing. Arc 12
/// supplies the exact endpoint and resource-bound production issuer.
#[allow(dead_code, reason = "Arc 12 moves the production relay caller")]
pub struct RelayAllocationPermit {
    runtime: RuntimeIncarnation,
}

impl RelayAllocationPermit {
    #[cfg(test)]
    fn for_test(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }

    #[cfg(test)]
    fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_relay_permit_is_bound_to_one_runtime() {
        let runtime = crate::runtime::runtime_for_test();
        let permit = RelayAllocationPermit::for_test(runtime.clone());

        assert!(permit.runtime().is_same(&runtime));
    }
}
