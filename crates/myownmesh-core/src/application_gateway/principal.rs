//! The local-process principal binding this owner authenticates against.

use crate::runtime::RuntimeIncarnation;

/// Local proof that an operating-system principal was authenticated and is
/// eligible for a Session Broker policy check.
///
/// One per process, minted by [`Self::for_local_process`] and shared through an
/// `Arc` by every session that speaks for it. A second value would be a second
/// principal, which is why there is no other constructor.
///
/// A public user, client, request, or peer label cannot construct this type:
///
/// ```compile_fail,E0308
/// use myownmesh_core::application_gateway::LocalPrincipalCapability;
///
/// let public_client_label = String::new();
/// let _principal = LocalPrincipalCapability::from(public_client_label);
/// ```
pub struct LocalPrincipalCapability {
    runtime: RuntimeIncarnation,
}

impl LocalPrincipalCapability {
    /// Bind the principal for this process's runtime.
    ///
    /// Crate-private and called once, by the Session Broker. The authority is
    /// the running process's own: no evidence is parsed, because none is
    /// transmitted — an in-process embedder cannot present a principal other
    /// than the one it is.
    ///
    /// The daemon's control clients are deliberately **not** separate
    /// principals. A Device value arriving over control IPC is a selector, and
    /// which local process may call the daemon at all is the operating system's
    /// socket boundary to decide. Each supervising application gets this
    /// principal through its own daemon process, so per-client identities would
    /// add a second identity system without adding a second trust boundary.
    pub(crate) fn for_local_process(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }

    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }

    #[cfg(test)]
    pub(crate) fn for_test(runtime: RuntimeIncarnation) -> Self {
        Self::for_local_process(runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_local_principal_is_runtime_bound() {
        let runtime = crate::runtime::runtime_for_test();
        let principal = LocalPrincipalCapability::for_test(runtime.clone());

        assert!(principal.runtime().is_same(&runtime));
    }
}
