//! Capability boundary for connector-owned channel establishment.
//!
//! This Arc 02 module adds the ownership transition only. Existing WebRTC,
//! Arc 03 wraps the existing ICE, TURN, and connection behavior in this owner.
//!
//! Arc 04B-1 adds the transport-independent boundary that endpoint
//! authentication consumes, split by owner rather than by size:
//!
//! - [`incarnation`] owns the opaque process-local connector identity;
//! - [`handoff`] owns the move-only channel handoff and its retention contract;
//! - [`binding`] owns the closed connector-supplied channel binding.
//!
//! A transport keeps its own incarnation type and owns a generic one. Endpoint
//! authentication names only the generic types, so it imports no transport.

mod binding;
mod handoff;
mod incarnation;

pub(crate) use binding::EndpointAuthBinding;
#[cfg(test)]
pub(crate) use handoff::{counted_handoff_for_test, handoff_for_test};
pub(crate) use handoff::{ConnectedChannelHandoff, ConnectedChannelRetention};
pub(crate) use incarnation::ConnectorIncarnation;

use crate::runtime::attempt::ConnectorCandidateCapability;
use crate::runtime::RuntimeIncarnation;

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
pub struct ConnectedChannelCapability {
    candidate: ConnectorCandidateCapability,
}

/// Consume one candidate after the connector has established a working
/// channel.
///
/// This stays private so only the connector owner can perform the transition.
/// Arc 03 moves the call behind the connector worker's successful channel
/// event.
#[cfg(test)]
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

impl ConnectedChannelCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        self.candidate.runtime()
    }

    pub(crate) fn into_candidate(self) -> ConnectorCandidateCapability {
        self.candidate
    }

    pub(crate) fn retain_after_cleanup_failure(&mut self) {
        self.candidate.retain_after_cleanup_failure();
    }

    pub(crate) fn release_after_cleanup_success(&mut self) {
        self.candidate.release_after_cleanup_success();
    }
}

// The connector issues no real-time authority.
//
// Real-time work is authorized by the promoted `SessionCapability` and the flow
// set that session owns. That set is the only thing that mints a label, and an
// inbound track may attach only to a binding the set established, so a
// connector holding no promoted session has nothing a track can attach to.
//
// There is exactly one admission decision, and it is promotion — which proves
// the exact current connector, current policy, the authenticated local
// principal, and a held post-authentication reservation atomically under the
// engine's registry fence. No second connector-side capability or delivery
// boolean exists to be kept in step with it.

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
}
