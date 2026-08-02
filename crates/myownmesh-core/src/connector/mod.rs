//! Capability boundary for connector-owned channel establishment.
//!
//! This Arc 02 module adds the ownership transition only. Existing WebRTC,
//! Arc 03 wraps the existing ICE, TURN, and connection behavior in this owner.

use crate::runtime::attempt::ConnectorCandidateCapability;
use crate::runtime::RuntimeIncarnation;
use crate::transport::WebRtcConnectorIncarnation;
use std::sync::Arc;

/// Local proof that a connector candidate produced a working channel.
///
/// The capability owns the candidate authority it consumed. It has no public
/// constructor and is neither `Clone` nor serializable. A working channel is
/// still not endpoint authentication or application-session authority.
///
/// A connected channel cannot satisfy an application operation that requires
/// a session capability:
///
/// ```compile_fail,E0308
/// use myownmesh_core::connector::ConnectedChannelCapability;
/// use myownmesh_core::runtime::session_broker::SessionCapability;
///
/// fn connected_channel() -> ConnectedChannelCapability {
///     unimplemented!()
/// }
///
/// fn application_operation(_session: &SessionCapability) {}
///
/// application_operation(&connected_channel());
/// ```
#[allow(dead_code, reason = "Arc 03 moves the production connector caller")]
pub struct ConnectedChannelCapability {
    candidate: ConnectorCandidateCapability,
}

/// Consume one candidate after the connector has established a working
/// channel.
///
/// This stays private so only the connector owner can perform the transition.
/// Arc 03 moves the call behind the connector worker's successful channel
/// event.
#[allow(dead_code, reason = "Arc 03 moves the production connector caller")]
pub(crate) fn mark_connected(
    candidate: ConnectorCandidateCapability,
) -> Option<ConnectedChannelCapability> {
    try_mark_connected(candidate).ok()
}

/// Attempt the exact candidate-to-connected resource transition while
/// returning the still-owned candidate when retirement or admission wins the
/// race. Cleanup can then retain that child claim through native close.
#[allow(
    clippy::result_large_err,
    reason = "boxing the move-only cleanup claim would add an unaccounted allocation"
)]
pub(crate) fn try_mark_connected(
    candidate: ConnectorCandidateCapability,
) -> std::result::Result<ConnectedChannelCapability, ConnectorCandidateCapability> {
    candidate.try_promote_if_live(|candidate| ConnectedChannelCapability { candidate })
}

#[allow(dead_code, reason = "Arc 03 moves the production connector caller")]
impl ConnectedChannelCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        self.candidate.runtime()
    }

    pub(crate) fn into_candidate(self) -> ConnectorCandidateCapability {
        self.candidate
    }

    pub(crate) fn poison_cleanup(&mut self) {
        self.candidate.poison_cleanup();
    }
}

/// Exact, process-local authority for one connector-native real-time flow.
///
/// This type deliberately says nothing about codecs, media kinds, lanes, or
/// application semantics. It only proves that the legacy admission path
/// authorized real-time work on one exact live connector incarnation. Arc 04
/// will replace that compatibility issuance point with authenticated-session
/// ownership.
///
/// It has no public constructor and is neither cloneable by value nor
/// serializable. Runtime owners may share the exact instance through `Arc`.
pub(crate) struct ConnectorRealtimeFlowCapability {
    incarnation: Arc<WebRtcConnectorIncarnation>,
}

impl ConnectorRealtimeFlowCapability {
    pub(super) fn new(incarnation: Arc<WebRtcConnectorIncarnation>) -> Self {
        Self { incarnation }
    }

    pub(crate) fn belongs_to(&self, incarnation: &Arc<WebRtcConnectorIncarnation>) -> bool {
        Arc::ptr_eq(&self.incarnation, incarnation) && incarnation.is_active()
    }
}

/// Temporary adapter for the existing live channel object.
///
/// The adapter requires a capability that the connector already produced. A
/// legacy object cannot mint the capability. Arc 04 deletes this wrapper when
/// endpoint authentication consumes `ConnectedChannelCapability` directly.
#[allow(
    dead_code,
    reason = "Arc 04 installs and deletes this migration adapter"
)]
pub(crate) struct LegacyConnectedChannel<T> {
    capability: ConnectedChannelCapability,
    legacy: T,
}

#[allow(
    dead_code,
    reason = "Arc 04 installs and deletes this migration adapter"
)]
impl<T> LegacyConnectedChannel<T> {
    pub(crate) fn new(capability: ConnectedChannelCapability, legacy: T) -> Self {
        Self { capability, legacy }
    }

    pub(crate) fn capability(&self) -> &ConnectedChannelCapability {
        &self.capability
    }

    fn into_parts(self) -> (ConnectedChannelCapability, T) {
        (self.capability, self.legacy)
    }
}

#[cfg(test)]
pub(crate) fn connected_for_test(runtime: RuntimeIncarnation) -> ConnectedChannelCapability {
    let (candidate, _lifetime) = crate::runtime::attempt::connector_candidate_for_test(runtime);
    mark_connected(candidate).expect("fixture candidate belongs to its live attempt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::attempt::connector_candidate_for_test;

    #[test]
    fn v4_arc02_connected_channel_consumes_candidate_authority() {
        let runtime = crate::runtime::runtime_for_test();
        let (candidate, _lifetime) = connector_candidate_for_test(runtime.clone());
        let connected = mark_connected(candidate).expect("live exact attempt");

        assert!(connected.runtime().is_same(&runtime));

        fn accepts_connected(_: ConnectedChannelCapability) {}
        accepts_connected(connected);
    }

    #[test]
    fn v4_arc03_connected_channel_rejects_retired_attempt() {
        let (retired_candidate, retired_lifetime) =
            connector_candidate_for_test(crate::runtime::runtime_for_test());
        retired_lifetime.retire();
        assert!(mark_connected(retired_candidate).is_none());
    }

    #[test]
    fn v4_arc02_legacy_adapter_requires_an_existing_capability() {
        let connected = connected_for_test(crate::runtime::runtime_for_test());
        let wrapper = LegacyConnectedChannel::new(connected, "legacy channel");
        let _ = wrapper.capability();
        let (_capability, legacy) = wrapper.into_parts();

        assert_eq!(legacy, "legacy channel");
    }
}
