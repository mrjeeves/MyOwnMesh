//! Local-principal and application-queue capability boundary for V4.
//!
//! The principal binding selected here is the **local process itself**: the
//! application operations this crate serves run in-process with the embedder, so
//! the operating-system principal that authenticated is the one already running
//! this code. That is a real binding, not a placeholder, and it is deliberately
//! the narrowest one that is true — there is no per-request principal inference,
//! no client label, and no identity or attestation framework.
//!
//! The owner itself is one type, `ApplicationGateway`, and its state is
//! declared here so that each submodule can reach exactly the fields its own
//! operations need. The submodules hold the operations, not a second owner:
//! `capabilities` the retained local advertisement, `channels` the named
//! subscriber queues, `frame` the encoded-frame admission and decode split,
//! `mailbox` the accepted-entry representation those queues are built on,
//! `principal` the local-process principal, and `rpc` the RPC seam.

mod capabilities;
mod channels;
mod flows;
mod frame;
mod mailbox;
mod principal;
mod rpc;

pub use capabilities::capability_advert_planning_claim;
pub use frame::json_input_work_claim;
pub use principal::LocalPrincipalCapability;

pub(crate) use capabilities::{CapabilityReplaceRefusal, LocalCapabilityState};
pub(crate) use channels::{ChannelSubscriber, GatewayChannelFrame};
pub(crate) use flows::{validate_native_application_lane, FundedOpaqueControl, OpaqueControlView};
pub(crate) use frame::{
    structural_json_claim, AdmittedApplicationFrame, DecodedApplicationFrame,
    DecodedApplicationMessage,
};
pub(crate) use mailbox::{GatewayAccepted, GatewayDelivery, GatewayMailbox};

use crate::resource::{LeasedMap, LocalApplicationResourceScope, ResourceUnavailable};

use channels::GatewayChannel;

/// The one local application owner for a joined network.
pub(crate) struct ApplicationGateway {
    channels: parking_lot::Mutex<LeasedMap<String, GatewayChannel>>,
    capabilities: LocalCapabilityState,
    rpc: parking_lot::RwLock<Option<crate::resource::FundedArc<crate::rpc::RpcInner>>>,
    closed: std::sync::atomic::AtomicBool,
    resources: LocalApplicationResourceScope,
}

impl ApplicationGateway {
    pub(crate) fn new(resources: LocalApplicationResourceScope) -> Self {
        Self {
            channels: parking_lot::Mutex::new(LeasedMap::new()),
            capabilities: LocalCapabilityState::new(),
            rpc: parking_lot::RwLock::new(None),
            closed: std::sync::atomic::AtomicBool::new(false),
            resources,
        }
    }

    pub(crate) fn capability_state(&self) -> &LocalCapabilityState {
        &self.capabilities
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        let subscribers = std::mem::take(&mut *self.channels.lock());
        drop(subscribers);
        self.capabilities.clear();
        if let Some(rpc) = self.rpc.write().take() {
            drop(std::mem::take(&mut *rpc.handlers.lock()));
        }
    }
}

/// Why the Application Gateway refused an encoded application frame or queued
/// delivery. No receiver and provider pressure are different facts and remain
/// distinguishable to reliable delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GatewayRefusal {
    #[error("no local receiver is installed")]
    NoReceiver,
    #[error("the application gateway is closed")]
    Revoked,
    #[error("the local receiver lagged by {0} entries")]
    Lag(u64),
    #[error("the resource provider refused application work: {0:?}")]
    Pressure(ResourceUnavailable),
    #[error("application work is not representable as a resource claim")]
    Malformed,
}
