//! Owner-selected connector policy values.

use crate::transport::webrtc::WebRtcConnectorProfile;

// The owner-selected callback mailbox capacities and scheduler service weights
// used to live here: per-class slot counts, per-class payload ceilings for an
// owner minting its own provider, and a consecutive-service quantum per class.
// All of it is gone, and nothing replaces it.
//
// Every one of those numbers was a local ceiling in front of an admission that
// already had to happen: a callback is admitted against the process provider at
// the payload's actual size, so a slot count could only refuse work the owner's
// real grant would have funded. The scheduler keeps the property the weights
// were there to state — structurally fair, work-conserving service across the
// closed class set, with empty classes skipped — as behaviour rather than as
// configuration, so there is no number for a deployment to get wrong and none
// for this file and the scheduler to disagree about.

/// Owner-selected callback behavior for one connector.
///
/// No class here carries a byte limit that gates the native callback, and there
/// is no frame-limit check standing behind one anywhere. Endpoint data is
/// admitted against the provider at the payload's actual size, and what bounds
/// the application parsing that follows is the provider structural claim taken
/// once the callback has been classified — capacity an owner granted, refused
/// when it is not there. Naming a frame limit here would promise a check that no
/// longer runs.
///
/// An encoded access unit is not an endpoint message frame, and neither one is
/// bounded here: both are admitted against the provider at the size actually in
/// front of the connector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackPolicy {
    realtime: RealtimeConnectorPolicy,
}

/// Owner-selected real-time behavior for one connector.
///
/// Two states and no payload. `Disabled` is a complete data-only policy that
/// carries no placeholder media limits; `Enabled` admits generic real-time work
/// against the provider.
///
/// The variant used to carry an optional local ceiling — a unit-byte maximum,
/// active-flow counts, a per-flow queue capacity, fragment and in-progress
/// limits, inbound and outbound byte partitions, and a one-variant overflow
/// rule. Every one of those is gone. The registry that enforced them enforces
/// the provider's real leases instead, which is what it already did whenever an
/// owner declined to state a ceiling, so the elastic path is not a fallback
/// here: it is the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtimeConnectorPolicy {
    Disabled,
    Enabled,
}

impl ConnectorCallbackPolicy {
    /// Resource-backed data-only callbacks.
    pub const fn elastic_data_only() -> Self {
        Self {
            realtime: RealtimeConnectorPolicy::Disabled,
        }
    }

    /// Resource-backed generic real-time callbacks with structurally fair,
    /// work-conserving service and no codec or flow meaning.
    pub const fn elastic_realtime() -> Self {
        Self {
            realtime: RealtimeConnectorPolicy::Enabled,
        }
    }

    pub const fn realtime(self) -> RealtimeConnectorPolicy {
        self.realtime
    }
}

impl RealtimeConnectorPolicy {
    pub const fn enabled() -> Self {
        Self::Enabled
    }
}

/// Point-in-time report from the connector resource owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorResourceOwnerReport {
    pub active_candidates: usize,
    /// Exact candidate claims retained after a native cleanup failure. These
    /// slots remain consumed until process exit and cannot be reused.
    pub failed_cleanup_candidates: usize,
    /// Aggregate accounting is no longer exact, so all later admissions are
    /// refused. A known per-candidate cleanup failure does not set this flag.
    pub accounting_poisoned: bool,
    pub cleanup: ConnectorCleanupHealth,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectorCleanupHealth {
    pub queued_jobs: usize,
    pub active_jobs: usize,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub executor_failed: bool,
}

/// Complete connector admission policy for one connector-capable [`crate::Mesh`].
///
/// The resource port refers to one owner-selected, process-local provider.
/// Cloning this policy does not create capacity. Every Mesh and connector
/// scope created through a clone still draws from the same provider grant.
#[derive(Clone, Debug)]
pub struct WebRtcConnectorCapablePolicy {
    resources: crate::resource::ResourceProviderPort,
    webrtc: WebRtcConnectorProfile,
}

impl WebRtcConnectorCapablePolicy {
    pub fn new(
        resources: crate::resource::ResourceProviderPort,
        webrtc: WebRtcConnectorProfile,
    ) -> Self {
        Self { resources, webrtc }
    }

    pub fn resources(&self) -> crate::resource::ResourceProviderPort {
        self.resources.clone()
    }

    /// Borrowed since the profile stopped being `Copy`: it now carries the
    /// application's real-time codec registrations, which are owned data.
    pub const fn webrtc(&self) -> &WebRtcConnectorProfile {
        &self.webrtc
    }
}
