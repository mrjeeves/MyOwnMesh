//! Session Broker capability boundary for V4.
//!
//! Arc 02 defines the output and post-authentication permit types. It does not
//! implement or expose session promotion. Arc 05 adds the owner-private atomic
//! transition only after every `MayPromote` input is represented and checked.

use crate::application_gateway::LocalPrincipalCapability;
use crate::endpoint_auth::AuthenticatedChannelCapability;
use crate::runtime::RuntimeIncarnation;

/// Proof that post-authentication session capacity was admitted.
///
/// There is no conversion from `PreAuthAttemptPermit` or
/// `EndpointAuthPermit` into this type.
#[allow(
    dead_code,
    reason = "Arc 05 moves the production Session Broker caller"
)]
pub struct SessionPermit {
    runtime: RuntimeIncarnation,
}

impl SessionPermit {
    #[cfg(test)]
    fn for_test(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }
}

/// Memory-only authority for application use of one promoted peer session.
///
/// It has no public or crate-visible constructor. Arc 02 intentionally has no
/// production mint path because the full promotion predicate is not yet
/// implemented.
///
/// The public type path resolves and can be used to type a boundary:
///
/// ```
/// use myownmesh_core::runtime::session_broker::SessionCapability;
///
/// fn requires_promoted_session(_: &SessionCapability) {}
/// # let _ = requires_promoted_session;
/// ```
///
/// A public label cannot invoke a constructor:
///
/// ```compile_fail,E0599
/// use myownmesh_core::runtime::session_broker::SessionCapability;
///
/// let _session = SessionCapability::new("public-session-label");
/// ```
///
/// The capability is not serializable:
///
/// ```compile_fail,E0277
/// use myownmesh_core::runtime::session_broker::SessionCapability;
///
/// fn session() -> SessionCapability { unimplemented!() }
/// let _ = serde_json::to_string(&session());
/// ```
///
/// The capability is not clonable:
///
/// ```compile_fail,E0277
/// use myownmesh_core::runtime::session_broker::SessionCapability;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<SessionCapability>();
/// ```
///
/// A pre-authentication permit cannot satisfy post-authentication session
/// admission:
///
/// ```compile_fail,E0308
/// use myownmesh_core::runtime::attempt::PreAuthAttemptPermit;
/// use myownmesh_core::runtime::session_broker::SessionPermit;
///
/// fn pre_authentication_permit() -> PreAuthAttemptPermit { unimplemented!() }
/// fn requires_session_permit(_: SessionPermit) {}
///
/// requires_session_permit(pre_authentication_permit());
/// ```
#[allow(
    dead_code,
    reason = "Arc 05 moves the production Session Broker caller"
)]
pub struct SessionCapability {
    authenticated_channel: AuthenticatedChannelCapability,
    local_principal: LocalPrincipalCapability,
    permit: SessionPermit,
}

#[allow(
    dead_code,
    reason = "Arc 05 moves the production Session Broker caller"
)]
impl SessionCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        self.authenticated_channel.runtime()
    }
}

/// Arc 05 compatibility container for an already-promoted session.
///
/// It cannot mint a session from its legacy value. The raw value is private to
/// this owner and Arc 06 deletes the adapter with the legacy application path.
#[allow(
    dead_code,
    reason = "Arc 06 installs and deletes this migration adapter"
)]
pub(crate) struct LegacySession<T> {
    capability: SessionCapability,
    legacy: T,
}

#[allow(
    dead_code,
    reason = "Arc 06 installs and deletes this migration adapter"
)]
impl<T> LegacySession<T> {
    pub(crate) fn new(capability: SessionCapability, legacy: T) -> Self {
        Self { capability, legacy }
    }

    pub(crate) fn capability(&self) -> &SessionCapability {
        &self.capability
    }

    fn into_parts(self) -> (SessionCapability, T) {
        (self.capability, self.legacy)
    }
}

#[cfg(test)]
fn session_for_test(runtime: RuntimeIncarnation) -> SessionCapability {
    let authenticated_channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
    let local_principal =
        crate::application_gateway::LocalPrincipalCapability::for_test(runtime.clone());
    let permit = SessionPermit::for_test(runtime);

    assert!(authenticated_channel
        .runtime()
        .is_same(local_principal.runtime()));
    assert!(authenticated_channel.runtime().is_same(&permit.runtime));

    SessionCapability {
        authenticated_channel,
        local_principal,
        permit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_test_scaffold_preserves_all_runtime_bindings() {
        let runtime = crate::runtime::runtime_for_test();
        let session = session_for_test(runtime.clone());

        assert!(session.runtime().is_same(&runtime));
        assert!(session
            .authenticated_channel
            .runtime()
            .is_same(session.local_principal.runtime()));
        assert!(session
            .authenticated_channel
            .runtime()
            .is_same(&session.permit.runtime));
    }

    #[test]
    fn v4_arc02_legacy_adapter_requires_an_existing_session() {
        let session = session_for_test(crate::runtime::runtime_for_test());
        let wrapper = LegacySession::new(session, "legacy session");
        let _ = wrapper.capability();
        let (_capability, legacy) = wrapper.into_parts();

        assert_eq!(legacy, "legacy session");
    }
}
