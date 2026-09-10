//! The bounded command port consumed by the network driver.

use tokio::sync::oneshot;

use crate::config::TopologyMode;
use crate::error::Result;
use crate::events::DropReason;
use crate::protocol::{rpc::RpcRequestMessage, CapabilityAdvert};
use crate::resource::{
    checked_measure_add, mailbox_measure_serialized, strings_measure, MailboxMeasurement,
    ResourceClaimArithmeticError, ResourceClass, ResourceMailboxItem, ResourceMailboxItemError,
};

use super::peer_registry::PeerOwnerToken;

/// Opaque custody transfer of an already-admitted introduction signal. Only
/// the engine can construct this value; it is not a public signaling ingress.
#[doc(hidden)]
pub struct IntroducedSignaling(pub(super) super::signaling_ingress::EphemeralIngress);

/// Reuses the caller's already-funded registration identity. No new reply,
/// waiter list, notification allocation, or copied device string is created.
#[doc(hidden)]
pub struct IntroductionWaitTransfer {
    pub(super) shared: crate::resource::FundedArc<super::state::ConnectWaitShared>,
}

/// The existing connection-work actor owns this negotiation after enqueue.
/// Its token is never retained by the caller across wire publication.
#[doc(hidden)]
pub struct OpaqueChangeTransfer {
    pub(super) dispatch: super::peer_registry::AdmittedInboundDispatch,
    pub(super) worker: std::sync::Arc<crate::transport::WebRtcConnectorWorker>,
    pub(super) name: crate::transport::webrtc::RealtimeFlowName,
    pub(super) change: crate::transport::webrtc::OpaqueFlowChange,
    pub(super) wire: crate::application_gateway::FundedOpaqueControl,
    pub(super) completion: crate::resource::FundedArc<OpaqueControlCompletion>,
    pub(super) deadline: std::time::Instant,
    pub(super) reply: oneshot::Sender<std::result::Result<(), crate::realtime::RealtimeRefusal>>,
    pub(super) _name_work: crate::resource::ResourceLease,
    pub(super) _demand_use: Option<super::state::OwnedDemandLinkUse>,
}

/// Single funded completion shared by the queued writer and its optional
/// caller. It is not a flow registry or peer acknowledgement.
pub(super) struct OpaqueControlCompletion {
    result: parking_lot::Mutex<Option<std::result::Result<(), crate::realtime::RealtimeRefusal>>>,
    ready: tokio::sync::Notify,
}

impl OpaqueControlCompletion {
    pub(super) fn new(
        resources: &crate::resource::LocalApplicationResourceScope,
    ) -> std::result::Result<crate::resource::FundedArc<Self>, crate::realtime::RealtimeRefusal>
    {
        use crate::resource::{FundedArc, ResourceClaim, ResourceClass, ResourceLease};
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<ResourceLease>())
            .and_then(|n| n.checked_add(4 * std::mem::size_of::<usize>()))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(crate::realtime::RealtimeRefusal::FlowRefused)?;
        let claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| crate::realtime::RealtimeRefusal::FlowRefused)?;
        let lease = resources
            .acquire(claim)
            .map_err(|_| crate::realtime::RealtimeRefusal::FlowRefused)?;
        FundedArc::new(
            Self {
                result: parking_lot::Mutex::new(None),
                ready: tokio::sync::Notify::new(),
            },
            lease,
        )
        .map_err(|_| crate::realtime::RealtimeRefusal::FlowRefused)
    }

    pub(super) fn finish(&self, result: std::result::Result<(), crate::realtime::RealtimeRefusal>) {
        let mut current = self.result.lock();
        if current.is_none() {
            *current = Some(result);
        }
        drop(current);
        self.ready.notify_waiters();
    }

    pub(super) async fn wait(&self) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(result) = *self.result.lock() {
                return result;
            }
            notified.await;
        }
    }
}

/// Only the engine constructs these commands. All controls share the ordinary
/// serialized command writer; the captured dispatch cannot select a successor.
#[doc(hidden)]
pub struct OpaqueControlTransfer {
    pub(super) dispatch: super::peer_registry::AdmittedInboundDispatch,
    pub(super) worker: std::sync::Arc<crate::transport::WebRtcConnectorWorker>,
    pub(super) wire: crate::application_gateway::FundedOpaqueControl,
    pub(super) completion: crate::resource::FundedArc<OpaqueControlCompletion>,
    // Inline command backing is already priced by the existing mailbox.
    // This guard outlives the last native/control write, including cancellation.
    pub(super) _demand_use: Option<super::state::OwnedDemandLinkUse>,
}

impl Drop for OpaqueControlTransfer {
    fn drop(&mut self) {
        // Dropping the receiver's accepted command during shutdown must also
        // settle an outstanding caller. Shutdown owns session retirement.
        self.completion
            .finish(Err(crate::realtime::RealtimeRefusal::SessionNotCurrent));
    }
}

/// General engine command queue entry. Application requests and network
/// reconfiguration use this serialized path. Connector events remain on their
/// bounded per-worker runtime path and do not enter this enum.
// Opaque transfers intentionally remain inline: their worker, funded wire,
// completion, and demand leases are already priced by their ownership paths;
// boxing would change that inline layout and its existing mailbox accounting.
#[allow(clippy::large_enum_variant)]
pub enum NetworkCmd {
    ReplayCapabilities {
        owner: PeerOwnerToken,
    },
    SetTopology(TopologyMode),
    DropPeer {
        device_id: String,
        reason: DropReason,
    },
    DropPeerIfCurrent {
        owner: PeerOwnerToken,
        attempt: String,
        reason: DropReason,
    },
    AttemptRefused {
        owner: PeerOwnerToken,
        refusal: myownmesh_signaling::AttemptRefusal,
    },
    AttemptOutcome {
        owner: PeerOwnerToken,
        outcome: myownmesh_signaling::AttemptOutcome,
    },
    Reconnect {
        peer: Option<String>,
    },
    ConnectPeer {
        device_id: String,
        sticky: bool,
        reply: Option<super::state::ConnectWaiterRegistration>,
    },
    BeginIntroducedPeer {
        device_id: String,
        ticket: super::hub_introduction::IntroductionTicket,
    },
    SettleIntroduction {
        key: [u8; 32],
        ticket: super::hub_introduction::IntroductionTicket,
        generation: u64,
    },
    SettleIntroductionWait(IntroductionWaitTransfer),
    IntroducedSignaling(IntroducedSignaling),
    OpaqueControl(OpaqueControlTransfer),
    OpaqueChange(OpaqueChangeTransfer),
    SendChannelReliable {
        peer: String,
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    },
    SendChannelFrame {
        peer: String,
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    },
    BroadcastChannelFrame {
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<usize>,
    },
    SendRpcRequest {
        peer: String,
        request: RpcRequestMessage,
        reply: oneshot::Sender<Result<()>>,
    },
    FanoutCapabilities {
        caps: CapabilityAdvert,
    },
    ProposeRoleGrant {
        target: String,
        role: crate::semantic::Role,
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<crate::semantic::FactId>>,
    },
    ProposeRoleRevoke {
        target: String,
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<crate::semantic::FactId>>,
    },
    ProposeEvict {
        target: String,
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<crate::semantic::FactId>>,
    },
}

unsafe impl ResourceMailboxItem for NetworkCmd {
    fn measured_claim(
        &self,
    ) -> std::result::Result<MailboxMeasurement<Self>, ResourceMailboxItemError> {
        let measure = match self {
            Self::ReplayCapabilities { .. } => (0, 0, 0),
            Self::SetTopology(mode) => mailbox_measure_serialized(mode)?,
            Self::ConnectPeer { device_id, .. } => strings_measure([device_id.as_str()])?,
            Self::BeginIntroducedPeer { device_id, .. } => strings_measure([device_id.as_str()])?,
            Self::SettleIntroduction { .. } => (0, 0, 0),
            Self::SettleIntroductionWait(_) => (0, 0, 0),
            Self::IntroducedSignaling(signal) => signal.0.inbound().string_measure()?,
            // Wire and completion pointees own distinct admitted leases.
            Self::OpaqueControl(_) => (0, 0, 0),
            Self::OpaqueChange(_) => (0, 0, 0),
            Self::DropPeer { device_id, reason } => {
                let reason = match reason {
                    DropReason::TransportError { message } => Some(message.as_str()),
                    DropReason::Denied
                    | DropReason::IceFailed
                    | DropReason::AuthFailed
                    | DropReason::UserLeft
                    | DropReason::TopologyPruned
                    | DropReason::HeartbeatTimeout => None,
                };
                strings_measure([Some(device_id.as_str()), reason].into_iter().flatten())?
            }
            Self::DropPeerIfCurrent {
                attempt, reason, ..
            } => {
                let reason = match reason {
                    DropReason::TransportError { message } => Some(message.as_str()),
                    DropReason::Denied
                    | DropReason::IceFailed
                    | DropReason::AuthFailed
                    | DropReason::UserLeft
                    | DropReason::TopologyPruned
                    | DropReason::HeartbeatTimeout => None,
                };
                strings_measure([Some(attempt.as_str()), reason].into_iter().flatten())?
            }
            Self::AttemptRefused { refusal, .. } => {
                let reason = match &refusal.refusal {
                    myownmesh_signaling::NegotiationRefusal::DuplicateLiveEvent => None,
                    myownmesh_signaling::NegotiationRefusal::Provider(reason) => {
                        Some(reason.as_str())
                    }
                };
                strings_measure(
                    [
                        Some(refusal.attempt.as_str()),
                        Some(refusal.event_id.as_str()),
                        reason,
                    ]
                    .into_iter()
                    .flatten(),
                )?
            }
            Self::AttemptOutcome { outcome, .. } => {
                let reason = match &outcome.kind {
                    myownmesh_signaling::AttemptOutcomeKind::TypedRefused(reason) => {
                        Some(reason.as_str())
                    }
                    _ => None,
                };
                strings_measure(
                    [
                        Some(outcome.attempt.as_str()),
                        Some(outcome.event_id.as_str()),
                        reason,
                    ]
                    .into_iter()
                    .flatten(),
                )?
            }
            Self::Reconnect { peer } => strings_measure(peer.iter().map(String::as_str))?,
            Self::SendChannelReliable {
                peer,
                channel,
                payload,
                ..
            }
            | Self::SendChannelFrame {
                peer,
                channel,
                payload,
                ..
            } => checked_measure_add(
                strings_measure([peer.as_str(), channel.as_str()])?,
                mailbox_measure_serialized(payload)?,
            )?,
            Self::BroadcastChannelFrame {
                channel, payload, ..
            } => checked_measure_add(
                strings_measure([channel.as_str()])?,
                mailbox_measure_serialized(payload)?,
            )?,
            Self::SendRpcRequest { peer, request, .. } => checked_measure_add(
                strings_measure([peer.as_str()])?,
                mailbox_measure_serialized(request)?,
            )?,
            Self::FanoutCapabilities { caps } => mailbox_measure_serialized(caps)?,
            Self::ProposeRoleGrant {
                target, mfa_code, ..
            }
            | Self::ProposeRoleRevoke {
                target, mfa_code, ..
            }
            | Self::ProposeEvict {
                target, mfa_code, ..
            } => strings_measure(
                [Some(target.as_str()), mfa_code.as_deref()]
                    .into_iter()
                    .flatten(),
            )?,
        };
        let effect_allocations = match self {
            Self::ReplayCapabilities { .. } | Self::FanoutCapabilities { .. } => 0,
            Self::SetTopology(_)
            | Self::DropPeer { .. }
            | Self::DropPeerIfCurrent { .. }
            | Self::Reconnect { .. } => 0,
            Self::AttemptRefused { .. } | Self::AttemptOutcome { .. } => 1,
            // The waiter reply and its cancellation/shared state are already
            // funded by ConnectWaitShared. The mailbox owns only this command
            // value and its embedded handle, so it must not charge the
            // intrinsically-funded pointee a second time.
            Self::ConnectPeer { .. } => 0,
            Self::BeginIntroducedPeer { .. } => 0,
            Self::SettleIntroduction { .. } => 0,
            Self::SettleIntroductionWait(_) => 0,
            Self::IntroducedSignaling(_) => 0,
            Self::OpaqueControl(_) => 0,
            Self::OpaqueChange(_) => 1,
            Self::SendChannelReliable { .. }
            | Self::SendChannelFrame { .. }
            | Self::BroadcastChannelFrame { .. }
            | Self::SendRpcRequest { .. }
            | Self::ProposeRoleGrant { .. }
            | Self::ProposeRoleRevoke { .. }
            | Self::ProposeEvict { .. } => 1,
        };
        let allocations = measure.2.checked_add(effect_allocations).ok_or(
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::OpaqueDependencyResidual,
            },
        )?;
        MailboxMeasurement::from_parts(measure.0, measure.1, allocations)
    }
}

#[cfg(test)]
mod opaque_completion_tests {
    use super::*;

    #[tokio::test]
    async fn opaque_completion_registers_before_check_and_keeps_first_terminal() {
        use std::future::Future;
        let completion = OpaqueControlCompletion {
            result: parking_lot::Mutex::new(None),
            ready: tokio::sync::Notify::new(),
        };
        let wait = completion.wait();
        tokio::pin!(wait);
        std::future::poll_fn(|cx| {
            assert!(wait.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        completion.finish(Ok(()));
        completion.finish(Err(crate::realtime::RealtimeRefusal::SessionNotCurrent));
        assert_eq!(wait.await, Ok(()));
        assert_eq!(
            completion.wait().await,
            Ok(()),
            "terminal-before-first-poll is not lost"
        );
    }
}
