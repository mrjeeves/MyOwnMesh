//! Owner-selected connector policy values.

use super::*;

/// Owner-selected bounds for the connector's closed callback-class set.
///
/// Codec and media names belong to the WebRTC compatibility adapter. The
/// connector resource owner accounts only for control, endpoint data, and
/// codec-neutral real-time flow callbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackMailboxCapacities {
    control: NonZeroUsize,
    endpoint_data: NonZeroUsize,
}

impl ConnectorCallbackMailboxCapacities {
    pub const fn new(control: NonZeroUsize, endpoint_data: NonZeroUsize) -> Self {
        Self {
            control,
            endpoint_data,
        }
    }

    pub const fn control(self) -> NonZeroUsize {
        self.control
    }

    pub const fn endpoint_data(self) -> NonZeroUsize {
        self.endpoint_data
    }
}

/// Owner-selected scheduler weights for the closed callback-class set.
///
/// No default exists. A weight is a maximum consecutive service quantum when
/// the selected class remains ready. Empty classes are skipped, so a stalled
/// class cannot block the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackServiceWeights {
    control: NonZeroUsize,
    endpoint_data: NonZeroUsize,
    realtime: Option<NonZeroUsize>,
}

impl ConnectorCallbackServiceWeights {
    pub const fn new(
        control: NonZeroUsize,
        endpoint_data: NonZeroUsize,
        realtime: NonZeroUsize,
    ) -> Self {
        Self {
            control,
            endpoint_data,
            realtime: Some(realtime),
        }
    }

    pub const fn data_only(control: NonZeroUsize, endpoint_data: NonZeroUsize) -> Self {
        Self {
            control,
            endpoint_data,
            realtime: None,
        }
    }

    pub const fn control(self) -> NonZeroUsize {
        self.control
    }

    pub const fn endpoint_data(self) -> NonZeroUsize {
        self.endpoint_data
    }

    pub const fn realtime(self) -> Option<NonZeroUsize> {
        self.realtime
    }
}

/// Owner-selected callback behavior for one connector.
///
/// Endpoint frames retain the protocol's independent frame limit. The
/// real-time unit and structural queue limits are separate operational inputs
/// because an encoded access unit is not an endpoint message frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackPolicy {
    mailboxes: ConnectorCallbackMailboxCapacities,
    service_weights: ConnectorCallbackServiceWeights,
    realtime: RealtimeConnectorPolicy,
}

/// Owner-selected real-time behavior for one connector.
///
/// `Disabled` is a complete data-only policy. It carries no placeholder
/// media limits. `Enabled` contains every value needed by the generic
/// real-time owner and has no production default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtimeConnectorPolicy {
    Disabled,
    Enabled(EnabledRealtimeConnectorPolicy),
}

/// Validated resource and queue policy for enabled real-time work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnabledRealtimeConnectorPolicy {
    max_unit_bytes: NonZeroUsize,
    flows: ConnectorRealtimeFlowPolicy,
}

/// Deterministic compatibility behavior when one bounded real-time flow
/// queue is full. This is connector-local backpressure, not application flow
/// policy. Arc 03 supports only dropping the newly offered complete unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealtimeQueueOverflowRule {
    DropNewest,
}

/// Owner-selected concurrency and queue bounds for real-time flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeFlowCapacities {
    max_inbound_active_flows: NonZeroUsize,
    max_outbound_active_flows: NonZeroUsize,
    queue_capacity_per_flow: NonZeroUsize,
}

impl ConnectorRealtimeFlowCapacities {
    pub const fn new(
        max_inbound_active_flows: NonZeroUsize,
        max_outbound_active_flows: NonZeroUsize,
        queue_capacity_per_flow: NonZeroUsize,
    ) -> Self {
        Self {
            max_inbound_active_flows,
            max_outbound_active_flows,
            queue_capacity_per_flow,
        }
    }
}

/// Owner-selected structural bounds for one inbound real-time flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeInboundLimits {
    max_fragment_bytes: NonZeroUsize,
    max_fragments_per_unit: NonZeroUsize,
    max_in_progress_units: NonZeroUsize,
}

impl ConnectorRealtimeInboundLimits {
    pub const fn new(
        max_fragment_bytes: NonZeroUsize,
        max_fragments_per_unit: NonZeroUsize,
        max_in_progress_units: NonZeroUsize,
    ) -> Self {
        Self {
            max_fragment_bytes,
            max_fragments_per_unit,
            max_in_progress_units,
        }
    }
}

/// Owner-selected resource envelope for connector-local real-time flows.
///
/// The envelope is codec-neutral. It bounds independent flow queues and the
/// bytes retained by all real-time work on one connector. No production
/// default exists. Omitting this policy leaves real-time flow admission
/// disabled while control and endpoint-data connector work remains usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeFlowPolicy {
    max_inbound_active_flows: NonZeroUsize,
    max_outbound_active_flows: NonZeroUsize,
    queue_capacity_per_flow: NonZeroUsize,
    max_inbound_fragment_bytes: NonZeroUsize,
    max_inbound_fragments_per_unit: NonZeroUsize,
    max_in_progress_units_per_flow: NonZeroUsize,
    byte_budgets: ConnectorRealtimeByteBudgets,
    overflow_rule: RealtimeQueueOverflowRule,
}

/// Owner-selected byte partitions for one connector's real-time work.
///
/// The inbound and outbound ceilings are independent reservations beneath the
/// total connector ceiling. Their sum must fit inside the total, so speculative
/// inbound quarantine cannot consume capacity reserved for locally authorized
/// outbound work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeByteBudgets {
    max_inbound_bytes: NonZeroUsize,
    max_outbound_bytes: NonZeroUsize,
    max_total_bytes: NonZeroUsize,
}

impl ConnectorRealtimeByteBudgets {
    pub const fn new(
        max_inbound_bytes: NonZeroUsize,
        max_outbound_bytes: NonZeroUsize,
        max_total_bytes: NonZeroUsize,
    ) -> Self {
        Self {
            max_inbound_bytes,
            max_outbound_bytes,
            max_total_bytes,
        }
    }

    pub const fn max_inbound_bytes(self) -> NonZeroUsize {
        self.max_inbound_bytes
    }

    pub const fn max_outbound_bytes(self) -> NonZeroUsize {
        self.max_outbound_bytes
    }

    pub const fn max_total_bytes(self) -> NonZeroUsize {
        self.max_total_bytes
    }
}

impl ConnectorRealtimeFlowPolicy {
    pub const fn new(
        capacities: ConnectorRealtimeFlowCapacities,
        inbound: ConnectorRealtimeInboundLimits,
        byte_budgets: ConnectorRealtimeByteBudgets,
        overflow_rule: RealtimeQueueOverflowRule,
    ) -> Self {
        Self {
            max_inbound_active_flows: capacities.max_inbound_active_flows,
            max_outbound_active_flows: capacities.max_outbound_active_flows,
            queue_capacity_per_flow: capacities.queue_capacity_per_flow,
            max_inbound_fragment_bytes: inbound.max_fragment_bytes,
            max_inbound_fragments_per_unit: inbound.max_fragments_per_unit,
            max_in_progress_units_per_flow: inbound.max_in_progress_units,
            byte_budgets,
            overflow_rule,
        }
    }

    pub const fn max_inbound_active_flows(self) -> NonZeroUsize {
        self.max_inbound_active_flows
    }

    pub const fn max_outbound_active_flows(self) -> NonZeroUsize {
        self.max_outbound_active_flows
    }

    pub const fn queue_capacity_per_flow(self) -> NonZeroUsize {
        self.queue_capacity_per_flow
    }

    pub const fn max_inbound_fragment_bytes(self) -> NonZeroUsize {
        self.max_inbound_fragment_bytes
    }

    pub const fn max_inbound_fragments_per_unit(self) -> NonZeroUsize {
        self.max_inbound_fragments_per_unit
    }

    pub const fn max_in_progress_units_per_flow(self) -> NonZeroUsize {
        self.max_in_progress_units_per_flow
    }

    /// Bytes whose ownership is visible to this connector's real-time
    /// reservations. Allocator slack and memory retained internally by native
    /// WebRTC dependencies are intentionally outside this exact quantity.
    pub const fn byte_budgets(self) -> ConnectorRealtimeByteBudgets {
        self.byte_budgets
    }

    pub const fn overflow_rule(self) -> RealtimeQueueOverflowRule {
        self.overflow_rule
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorCallbackPolicyError {
    #[error("real-time inbound fragment limit {fragment_bytes} exceeds unit limit {unit_bytes}")]
    InboundFragmentExceedsUnit {
        fragment_bytes: usize,
        unit_bytes: usize,
    },
    #[error("real-time unit limit is too large to derive the guarded assembly bound")]
    AssemblyBoundOverflow,
    #[error(
        "accounted real-time byte limit {available_bytes} cannot hold one guarded assembly requiring {required_bytes} bytes"
    )]
    AccountedBytesCannotHoldOneAssembly {
        required_bytes: usize,
        available_bytes: usize,
    },
    #[error(
        "outbound real-time byte limit {available_bytes} cannot hold one complete unit requiring {required_bytes} bytes"
    )]
    OutboundBytesCannotHoldOneUnit {
        required_bytes: usize,
        available_bytes: usize,
    },
    #[error(
        "real-time domain byte ceilings require {required_bytes} aggregate bytes but the connector ceiling is {available_bytes}"
    )]
    RealtimeDomainBudgetsExceedAggregate {
        required_bytes: usize,
        available_bytes: usize,
    },
    #[error("legacy WebRTC media compatibility requires enabled generic real-time ownership")]
    LegacyMediaRequiresRealtime,
    #[error(
        "legacy WebRTC media pre-provisions {required_flows} outbound flows but the owner ceiling is {available_flows}"
    )]
    LegacyMediaExceedsOutboundFlowCeiling {
        required_flows: usize,
        available_flows: usize,
    },
    #[error("data-only callback policy must not carry a real-time service weight")]
    DisabledRealtimeHasServiceWeight,
    #[error("enabled real-time callback policy requires an explicit real-time service weight")]
    EnabledRealtimeMissingServiceWeight,
    #[error(
        "{class} callback mailbox capacity {requested} exceeds Tokio's supported maximum {maximum}"
    )]
    MailboxCapacityExceedsRuntimeLimit {
        class: &'static str,
        requested: usize,
        maximum: usize,
    },
}

impl ConnectorCallbackPolicy {
    pub fn new(
        mailboxes: ConnectorCallbackMailboxCapacities,
        service_weights: ConnectorCallbackServiceWeights,
        realtime: RealtimeConnectorPolicy,
    ) -> std::result::Result<Self, ConnectorCallbackPolicyError> {
        match (realtime, service_weights.realtime()) {
            (RealtimeConnectorPolicy::Disabled, Some(_)) => {
                return Err(ConnectorCallbackPolicyError::DisabledRealtimeHasServiceWeight)
            }
            (RealtimeConnectorPolicy::Enabled(_), None) => {
                return Err(ConnectorCallbackPolicyError::EnabledRealtimeMissingServiceWeight)
            }
            _ => {}
        }
        for (class, requested) in [
            ("control", mailboxes.control().get()),
            ("endpoint-data", mailboxes.endpoint_data().get()),
        ] {
            if requested > tokio::sync::Semaphore::MAX_PERMITS {
                return Err(
                    ConnectorCallbackPolicyError::MailboxCapacityExceedsRuntimeLimit {
                        class,
                        requested,
                        maximum: tokio::sync::Semaphore::MAX_PERMITS,
                    },
                );
            }
        }
        Ok(Self {
            mailboxes,
            service_weights,
            realtime,
        })
    }

    pub const fn mailboxes(self) -> ConnectorCallbackMailboxCapacities {
        self.mailboxes
    }

    pub const fn service_weights(self) -> ConnectorCallbackServiceWeights {
        self.service_weights
    }

    pub const fn realtime(self) -> RealtimeConnectorPolicy {
        self.realtime
    }

    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn unrestricted_lab(mailbox_capacity: NonZeroUsize) -> Self {
        Self {
            mailboxes: ConnectorCallbackMailboxCapacities::new(mailbox_capacity, mailbox_capacity),
            service_weights: ConnectorCallbackServiceWeights::new(
                mailbox_capacity,
                mailbox_capacity,
                mailbox_capacity,
            ),
            realtime: RealtimeConnectorPolicy::Enabled(EnabledRealtimeConnectorPolicy {
                // Leave arithmetic headroom for simultaneous guarded input
                // and output observations in the raw compatibility lab.
                max_unit_bytes: NonZeroUsize::new(usize::MAX / 4)
                    .expect("quarter of usize::MAX is nonzero"),
                flows: ConnectorRealtimeFlowPolicy::new(
                    ConnectorRealtimeFlowCapacities::new(
                        NonZeroUsize::new(usize::MAX / 4)
                            .expect("quarter of usize::MAX is nonzero"),
                        NonZeroUsize::new(usize::MAX / 4)
                            .expect("quarter of usize::MAX is nonzero"),
                        mailbox_capacity,
                    ),
                    ConnectorRealtimeInboundLimits::new(
                        NonZeroUsize::new(usize::MAX / 4)
                            .expect("quarter of usize::MAX is nonzero"),
                        NonZeroUsize::new(usize::MAX / 4)
                            .expect("quarter of usize::MAX is nonzero"),
                        NonZeroUsize::new(usize::MAX / 4)
                            .expect("quarter of usize::MAX is nonzero"),
                    ),
                    ConnectorRealtimeByteBudgets::new(
                        NonZeroUsize::new(usize::MAX / 2).expect("half of usize::MAX is nonzero"),
                        NonZeroUsize::new(usize::MAX / 2).expect("half of usize::MAX is nonzero"),
                        NonZeroUsize::new(usize::MAX - 1).expect("usize::MAX minus one is nonzero"),
                    ),
                    RealtimeQueueOverflowRule::DropNewest,
                ),
            }),
        }
    }
}

impl RealtimeConnectorPolicy {
    pub fn enabled(
        max_unit_bytes: NonZeroUsize,
        flows: ConnectorRealtimeFlowPolicy,
    ) -> std::result::Result<Self, ConnectorCallbackPolicyError> {
        if flows.max_inbound_fragment_bytes().get() > max_unit_bytes.get() {
            return Err(ConnectorCallbackPolicyError::InboundFragmentExceedsUnit {
                fragment_bytes: flows.max_inbound_fragment_bytes().get(),
                unit_bytes: max_unit_bytes.get(),
            });
        }
        let required_bytes = max_unit_bytes
            .get()
            .checked_mul(2)
            .ok_or(ConnectorCallbackPolicyError::AssemblyBoundOverflow)?;
        let byte_budgets = flows.byte_budgets();
        if byte_budgets.max_inbound_bytes().get() < required_bytes {
            return Err(
                ConnectorCallbackPolicyError::AccountedBytesCannotHoldOneAssembly {
                    required_bytes,
                    available_bytes: byte_budgets.max_inbound_bytes().get(),
                },
            );
        }
        if byte_budgets.max_outbound_bytes().get() < max_unit_bytes.get() {
            return Err(
                ConnectorCallbackPolicyError::OutboundBytesCannotHoldOneUnit {
                    required_bytes: max_unit_bytes.get(),
                    available_bytes: byte_budgets.max_outbound_bytes().get(),
                },
            );
        }
        let required_total = byte_budgets
            .max_inbound_bytes()
            .get()
            .checked_add(byte_budgets.max_outbound_bytes().get())
            .ok_or(ConnectorCallbackPolicyError::AssemblyBoundOverflow)?;
        if byte_budgets.max_total_bytes().get() < required_total {
            return Err(
                ConnectorCallbackPolicyError::RealtimeDomainBudgetsExceedAggregate {
                    required_bytes: required_total,
                    available_bytes: byte_budgets.max_total_bytes().get(),
                },
            );
        }
        Ok(Self::Enabled(EnabledRealtimeConnectorPolicy {
            max_unit_bytes,
            flows,
        }))
    }
}

impl EnabledRealtimeConnectorPolicy {
    pub const fn max_unit_bytes(self) -> NonZeroUsize {
        self.max_unit_bytes
    }

    pub const fn flows(self) -> ConnectorRealtimeFlowPolicy {
        self.flows
    }
}

/// Owner-selected bound for the connector's pre-SDP remote-candidate queue.
///
/// The byte ceiling covers exact candidate payload bytes retained by the
/// connector. The item ceiling independently bounds queue metadata. There is no
/// default because both values depend on the deployment's ICE environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRemoteCandidatePolicy {
    max_items: NonZeroUsize,
    max_payload_bytes: NonZeroUsize,
}

impl PendingRemoteCandidatePolicy {
    pub const fn new(max_items: NonZeroUsize, max_payload_bytes: NonZeroUsize) -> Self {
        Self {
            max_items,
            max_payload_bytes,
        }
    }

    pub const fn max_items(self) -> NonZeroUsize {
        self.max_items
    }

    pub const fn max_payload_bytes(self) -> NonZeroUsize {
        self.max_payload_bytes
    }
}

/// Temporary provider-specific H.264 and Opus media compatibility profile.
///
/// Generic real-time ownership never creates media tracks. This explicit
/// profile is the only construction input that can request the legacy WebRTC
/// adapter. Its lane grace remains compatibility behavior and is not part of
/// the generic real-time flow contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyWebRtcMediaProfile {
    max_lanes_per_kind: NonZeroUsize,
    preprovisioned_video_lanes: usize,
    preprovisioned_audio_lanes: usize,
    lane_drain_grace: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LegacyWebRtcMediaProfileError {
    #[error("legacy WebRTC media lane ceiling {requested} exceeds the u8 lane identity space")]
    LaneIdentitySpaceExceeded { requested: usize },
    #[error(
        "legacy WebRTC media pre-provisions {preprovisioned} {kind} lanes but its per-kind ceiling is {maximum}"
    )]
    PreprovisionedLanesExceedCeiling {
        kind: &'static str,
        preprovisioned: usize,
        maximum: usize,
    },
}

impl LegacyWebRtcMediaProfile {
    pub fn h264_opus(
        max_lanes_per_kind: NonZeroUsize,
        preprovisioned_video_lanes: usize,
        preprovisioned_audio_lanes: usize,
        lane_drain_grace: Duration,
    ) -> std::result::Result<Self, LegacyWebRtcMediaProfileError> {
        let maximum = max_lanes_per_kind.get();
        let lane_identity_space = usize::from(u8::MAX) + 1;
        if maximum > lane_identity_space {
            return Err(LegacyWebRtcMediaProfileError::LaneIdentitySpaceExceeded {
                requested: maximum,
            });
        }
        for (kind, preprovisioned) in [
            ("video", preprovisioned_video_lanes),
            ("audio", preprovisioned_audio_lanes),
        ] {
            if preprovisioned > maximum {
                return Err(
                    LegacyWebRtcMediaProfileError::PreprovisionedLanesExceedCeiling {
                        kind,
                        preprovisioned,
                        maximum,
                    },
                );
            }
        }
        Ok(Self {
            max_lanes_per_kind,
            preprovisioned_video_lanes,
            preprovisioned_audio_lanes,
            lane_drain_grace,
        })
    }

    pub const fn max_lanes_per_kind(self) -> NonZeroUsize {
        self.max_lanes_per_kind
    }

    pub const fn preprovisioned_video_lanes(self) -> usize {
        self.preprovisioned_video_lanes
    }

    pub const fn preprovisioned_audio_lanes(self) -> usize {
        self.preprovisioned_audio_lanes
    }

    pub const fn lane_drain_grace(self) -> Duration {
        self.lane_drain_grace
    }

    pub const fn preprovisioned_outbound_flows(self) -> Option<usize> {
        self.preprovisioned_video_lanes
            .checked_add(self.preprovisioned_audio_lanes)
    }
}

/// Explicit policy supplied by the process resource owner.
///
/// Arc 03 deliberately provides no `Default`: the maximum number of admitted
/// candidates, callback capacities, and the pre-SDP queue bounds are operational
/// values that require owner review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorResourcePolicy {
    max_active_candidates: NonZeroUsize,
    callbacks: ConnectorCallbackPolicy,
    pending_remote_candidates: PendingRemoteCandidatePolicy,
    legacy_media: Option<LegacyWebRtcMediaProfile>,
}

impl ConnectorResourcePolicy {
    pub const fn new(
        max_active_candidates: NonZeroUsize,
        callbacks: ConnectorCallbackPolicy,
        pending_remote_candidates: PendingRemoteCandidatePolicy,
    ) -> Self {
        Self {
            max_active_candidates,
            callbacks,
            pending_remote_candidates,
            legacy_media: None,
        }
    }

    pub const fn max_active_candidates(self) -> NonZeroUsize {
        self.max_active_candidates
    }

    pub const fn callbacks(self) -> ConnectorCallbackPolicy {
        self.callbacks
    }

    pub const fn pending_remote_candidates(self) -> PendingRemoteCandidatePolicy {
        self.pending_remote_candidates
    }

    pub const fn legacy_media(self) -> Option<LegacyWebRtcMediaProfile> {
        self.legacy_media
    }

    pub fn with_legacy_webrtc_media(
        mut self,
        profile: LegacyWebRtcMediaProfile,
    ) -> std::result::Result<Self, ConnectorCallbackPolicyError> {
        let enabled = match self.callbacks.realtime() {
            RealtimeConnectorPolicy::Disabled => {
                return Err(ConnectorCallbackPolicyError::LegacyMediaRequiresRealtime)
            }
            RealtimeConnectorPolicy::Enabled(enabled) => enabled,
        };
        let required_flows = profile
            .preprovisioned_outbound_flows()
            .ok_or(ConnectorCallbackPolicyError::AssemblyBoundOverflow)?;
        let available_flows = enabled.flows().max_outbound_active_flows().get();
        if required_flows > available_flows {
            return Err(
                ConnectorCallbackPolicyError::LegacyMediaExceedsOutboundFlowCeiling {
                    required_flows,
                    available_flows,
                },
            );
        }
        self.legacy_media = Some(profile);
        Ok(self)
    }
}

/// A process resource root already owns a different connector policy.
///
/// Reusing the installed policy is safe. Replacing it while live claims may
/// exist would split the process limit, so the root refuses the change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the process connector resource policy is already installed with different values")]
pub struct ConnectorResourcePolicyConflict {
    pub installed: ConnectorResourcePolicy,
    pub requested: ConnectorResourcePolicy,
}

/// Point-in-time report from the connector resource owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorResourceOwnerReport {
    pub max_active_candidates: NonZeroUsize,
    pub active_candidates: usize,
    /// Exact candidate claims retained after a native cleanup failure. These
    /// slots remain consumed until process exit and cannot be reused.
    pub failed_cleanup_candidates: usize,
    /// Aggregate accounting is no longer exact, so all later admissions are
    /// refused. A known per-candidate cleanup failure does not set this flag.
    pub accounting_poisoned: bool,
    pub callbacks: ConnectorCallbackPolicy,
    pub pending_remote_candidates: PendingRemoteCandidatePolicy,
    pub legacy_media: Option<LegacyWebRtcMediaProfile>,
}

/// Explicit owner-selected connector ceiling for one live [`crate::Mesh`]
/// runtime.
///
/// This value has no `Default` and is not derived from the process ceiling or
/// the number of Mesh runtimes. Arc 03E implements a hard child ceiling only.
/// It does not reserve capacity for a child and does not borrow capacity from
/// another child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshConnectorResourcePolicy {
    max_active_candidates: NonZeroUsize,
}

/// Complete connector admission policy for one connector-capable [`crate::Mesh`].
///
/// The process component is installed once and shared across Mesh runtimes.
/// The Mesh component is an independent hard ceiling for this exact runtime.
/// Both values are owner-selected. Neither is inferred from the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCapableResourcePolicy {
    process: ConnectorResourcePolicy,
    mesh: MeshConnectorResourcePolicy,
}

impl ConnectorCapableResourcePolicy {
    pub const fn new(process: ConnectorResourcePolicy, mesh: MeshConnectorResourcePolicy) -> Self {
        Self { process, mesh }
    }

    pub const fn process(self) -> ConnectorResourcePolicy {
        self.process
    }

    pub const fn mesh(self) -> MeshConnectorResourcePolicy {
        self.mesh
    }
}

impl MeshConnectorResourcePolicy {
    pub const fn new(max_active_candidates: NonZeroUsize) -> Self {
        Self {
            max_active_candidates,
        }
    }

    pub const fn max_active_candidates(self) -> NonZeroUsize {
        self.max_active_candidates
    }
}
