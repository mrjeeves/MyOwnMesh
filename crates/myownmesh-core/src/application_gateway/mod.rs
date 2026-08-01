//! Local-principal and application-queue capability boundary for V4.
//!
//! Arc 02 installs memory-only authority types. It does not choose the
//! operating-system principal binding or redirect an application operation.

use crate::runtime::RuntimeIncarnation;

/// Local proof that an operating-system principal was authenticated and is
/// eligible for a later Session Broker policy check.
///
/// A public user, client, request, or peer label cannot construct this type:
///
/// ```compile_fail,E0308
/// use myownmesh_core::application_gateway::LocalPrincipalCapability;
///
/// let public_client_label = String::new();
/// let _principal = LocalPrincipalCapability::from(public_client_label);
/// ```
#[allow(dead_code, reason = "Arc 06 moves the production gateway caller")]
pub struct LocalPrincipalCapability {
    runtime: RuntimeIncarnation,
}

#[allow(dead_code, reason = "Arc 06 moves the production gateway caller")]
impl LocalPrincipalCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }

    #[cfg(test)]
    pub(crate) fn for_test(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }
}

/// Proof that post-authentication application-queue capacity was admitted.
///
/// Arc 02 creates no production issuer and supplies no conversion from any
/// pre-authentication permit.
#[allow(dead_code, reason = "Arc 06 moves the production gateway caller")]
pub struct ApplicationQueuePermit {
    runtime: RuntimeIncarnation,
}

impl ApplicationQueuePermit {
    #[cfg(test)]
    pub(crate) fn for_test(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }

    #[cfg(test)]
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }
}

/// Arc 06 compatibility container for an already-authenticated local
/// principal.
#[allow(
    dead_code,
    reason = "Arc 06 installs and deletes this migration adapter"
)]
pub(crate) struct LegacyPrincipal<T> {
    capability: LocalPrincipalCapability,
    legacy: T,
}

#[allow(
    dead_code,
    reason = "Arc 06 installs and deletes this migration adapter"
)]
impl<T> LegacyPrincipal<T> {
    pub(crate) fn new(capability: LocalPrincipalCapability, legacy: T) -> Self {
        Self { capability, legacy }
    }

    pub(crate) fn capability(&self) -> &LocalPrincipalCapability {
        &self.capability
    }

    fn into_parts(self) -> (LocalPrincipalCapability, T) {
        (self.capability, self.legacy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_principal_and_queue_permit_are_runtime_bound() {
        let runtime = crate::runtime::runtime_for_test();
        let principal = LocalPrincipalCapability::for_test(runtime.clone());
        let queue = ApplicationQueuePermit::for_test(runtime.clone());

        assert!(principal.runtime().is_same(&runtime));
        assert!(queue.runtime().is_same(&runtime));
    }

    #[test]
    fn v4_arc02_legacy_principal_requires_existing_authority() {
        let principal = LocalPrincipalCapability::for_test(crate::runtime::runtime_for_test());
        let wrapper = LegacyPrincipal::new(principal, "legacy principal");
        let _ = wrapper.capability();
        let (_capability, legacy) = wrapper.into_parts();

        assert_eq!(legacy, "legacy principal");
    }
}
