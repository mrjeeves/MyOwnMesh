//! Endpoint-authentication capability boundary for V4.
//!
//! Arc 02 installs the types only. Arc 04 supplies the real transcript and
//! channel-binding verifier before this owner can issue an authenticated
//! channel capability in production.

use crate::connector::ConnectedChannelCapability;
use crate::runtime::RuntimeIncarnation;
use crate::transport::{EndpointAuthHandoff, WebRtcConnectorIncarnation};
use std::sync::Arc;

/// The one runtime owner that receives a newly working channel before any
/// authentication frame may be emitted or consumed. Arc 04 replaces the
/// legacy handshake body, but Arc 03 makes this ownership handoff mandatory.
pub(crate) struct EndpointAuthTask {
    connected: EndpointAuthHandoff,
}

impl EndpointAuthTask {
    pub(crate) fn begin(connected: EndpointAuthHandoff) -> Self {
        Self { connected }
    }

    pub(crate) fn belongs_to(&self, incarnation: &Arc<WebRtcConnectorIncarnation>) -> bool {
        self.connected.belongs_to(incarnation)
    }
}

/// Proof that bounded endpoint-authentication work was admitted.
///
/// The type has no public constructor, serialization, or cloning path.
#[allow(dead_code, reason = "Arc 04 moves the production endpoint-auth caller")]
pub struct EndpointAuthPermit {
    runtime: RuntimeIncarnation,
}

impl EndpointAuthPermit {
    #[cfg(test)]
    fn admitted_for_test(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }
}

/// Local proof that both Device identities were freshly authenticated on one
/// exact connected channel.
///
/// Arc 04 will add the owner-private production transition after it verifies
/// the complete channel-bound transcript. Until then, only test scaffolding
/// can create this type.
///
/// A connected channel has no implicit conversion into authentication:
///
/// ```compile_fail,E0308
/// use myownmesh_core::connector::ConnectedChannelCapability;
/// use myownmesh_core::endpoint_auth::AuthenticatedChannelCapability;
///
/// fn connected() -> ConnectedChannelCapability { unimplemented!() }
/// fn requires_authentication(_: AuthenticatedChannelCapability) {}
///
/// requires_authentication(connected());
/// ```
#[allow(dead_code, reason = "Arc 04 moves the production endpoint-auth caller")]
pub struct AuthenticatedChannelCapability {
    connected: ConnectedChannelCapability,
    permit: EndpointAuthPermit,
}

#[allow(dead_code, reason = "Arc 04 moves the production endpoint-auth caller")]
impl AuthenticatedChannelCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        self.connected.runtime()
    }
}

/// Arc 04 compatibility container.
///
/// The adapter accepts an already-issued capability. It cannot authenticate a
/// legacy value, and the raw value remains private to this owner module.
#[allow(
    dead_code,
    reason = "Arc 05 installs and deletes this migration adapter"
)]
pub(crate) struct LegacyAuthenticatedChannel<T> {
    capability: AuthenticatedChannelCapability,
    legacy: T,
}

#[allow(
    dead_code,
    reason = "Arc 05 installs and deletes this migration adapter"
)]
impl<T> LegacyAuthenticatedChannel<T> {
    pub(crate) fn new(capability: AuthenticatedChannelCapability, legacy: T) -> Self {
        Self { capability, legacy }
    }

    pub(crate) fn capability(&self) -> &AuthenticatedChannelCapability {
        &self.capability
    }

    fn into_parts(self) -> (AuthenticatedChannelCapability, T) {
        (self.capability, self.legacy)
    }
}

#[cfg(test)]
pub(crate) fn authenticated_for_test(
    runtime: RuntimeIncarnation,
) -> AuthenticatedChannelCapability {
    let connected = crate::connector::connected_for_test(runtime.clone());
    let permit = EndpointAuthPermit::admitted_for_test(runtime);
    assert!(connected.runtime().is_same(&permit.runtime));
    AuthenticatedChannelCapability { connected, permit }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_authenticated_channel_preserves_runtime_binding() {
        let runtime = crate::runtime::runtime_for_test();
        let authenticated = authenticated_for_test(runtime.clone());

        assert!(authenticated.runtime().is_same(&runtime));
        assert!(authenticated
            .connected
            .runtime()
            .is_same(&authenticated.permit.runtime));
    }

    #[test]
    fn v4_arc02_legacy_adapter_cannot_manufacture_authentication() {
        let authenticated = authenticated_for_test(crate::runtime::runtime_for_test());
        let wrapper = LegacyAuthenticatedChannel::new(authenticated, "legacy auth channel");
        let _ = wrapper.capability();
        let (_capability, legacy) = wrapper.into_parts();

        assert_eq!(legacy, "legacy auth channel");
    }
}
