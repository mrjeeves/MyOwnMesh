//! Callback classification, lifecycle fencing, and bounded scheduling.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConnectorCallbackClass {
    Control,
    EndpointData,
    Realtime,
}

impl ConnectorCallbackClass {
    pub(super) fn for_event(event: &TransportEvent) -> Self {
        match event {
            TransportEvent::Message(_) => Self::EndpointData,
            // `Realtime` has no callback mailbox, so classing a unit this way
            // makes the general callback route fail *closed* — `emit_inner`
            // answers `WrongOwnerPath` rather than dropping it on the control
            // lane uncapped, where a media flood would displace ICE and
            // peer-state events. Real-time units take `emit_realtime`, which
            // is charged, observed and gated; this is the backstop for a route
            // that should never be taken.
            TransportEvent::RealtimeUnit(_) => Self::Realtime,
            _ => Self::Control,
        }
    }

    pub(super) const fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::EndpointData => 1,
            Self::Realtime => 2,
        }
    }

    pub(super) const fn from_index(index: usize) -> Self {
        match index % 3 {
            0 => Self::Control,
            1 => Self::EndpointData,
            _ => Self::Realtime,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CallbackPhaseClaims {
    queued: crate::resource::ResourceClaim,
    executing: crate::resource::ResourceClaim,
}

impl CallbackPhaseClaims {
    pub(super) const fn new(
        queued: crate::resource::ResourceClaim,
        executing: crate::resource::ResourceClaim,
    ) -> Self {
        Self { queued, executing }
    }
}

/// Owner-selected callback claims. These values supplement the mechanically
/// accounted callback object and payload bytes. They contain no defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CallbackProducerClaims {
    control: CallbackPhaseClaims,
    endpoint_data: CallbackPhaseClaims,
    realtime: CallbackPhaseClaims,
}

impl CallbackProducerClaims {
    pub(super) const fn new(
        control: CallbackPhaseClaims,
        endpoint_data: CallbackPhaseClaims,
        realtime: CallbackPhaseClaims,
    ) -> Self {
        Self {
            control,
            endpoint_data,
            realtime,
        }
    }

    /// Use only the mechanically accounted callback item and payload bytes.
    /// The process provider still selects the finite aggregate grant.
    pub(super) const fn structural_only() -> Self {
        let phases = CallbackPhaseClaims::new(
            crate::resource::ResourceClaim::ZERO,
            crate::resource::ResourceClaim::ZERO,
        );
        Self::new(phases, phases, phases)
    }

    const fn for_class(self, class: ConnectorCallbackClass) -> CallbackPhaseClaims {
        match class {
            ConnectorCallbackClass::Control => self.control,
            ConnectorCallbackClass::EndpointData => self.endpoint_data,
            ConnectorCallbackClass::Realtime => self.realtime,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CallbackProducerOverload {
    // The two "the policy states no ceiling" refusals are gone with the policy
    // surface that could omit one. A lab fixture now hands its four numbers in
    // by value, so there is no absent-ceiling state left to report.
    PayloadSizeUnrepresentable {
        class: ConnectorCallbackClass,
    },
    PhaseMismatch {
        class: ConnectorCallbackClass,
    },
    ClaimArithmetic {
        class: ConnectorCallbackClass,
        error: crate::resource::ResourceClaimArithmeticError,
    },
    ResourceUnavailable {
        class: ConnectorCallbackClass,
        unavailable: crate::resource::ResourceUnavailable,
    },
}

#[cfg(test)]
trait CallbackResourceScope: Send + Sync {
    fn acquire(
        &self,
        authority: crate::resource::ResourceAuthorityClass,
        claim: crate::resource::ResourceClaim,
    ) -> std::result::Result<crate::resource::ResourceLease, crate::resource::ResourceUnavailable>;
}

#[derive(Clone)]
enum CallbackResourceScopeOwner {
    Production(crate::runtime::attempt::ConnectorWorkResourceScope),
    #[cfg(test)]
    Test(Arc<dyn CallbackResourceScope>),
    #[cfg(any(test, feature = "transport-lab"))]
    Lab {
        port: crate::resource::ResourceProviderPort,
        scope: crate::resource::ResourceScope,
    },
}

impl CallbackResourceScopeOwner {
    fn acquire(
        &self,
        authority: crate::resource::ResourceAuthorityClass,
        claim: crate::resource::ResourceClaim,
    ) -> std::result::Result<crate::resource::ResourceLease, crate::resource::ResourceUnavailable>
    {
        match self {
            Self::Production(scope) => scope.acquire(authority, claim),
            #[cfg(test)]
            Self::Test(scope) => scope.acquire(authority, claim),
            #[cfg(any(test, feature = "transport-lab"))]
            Self::Lab { port, scope } => port.acquire(scope, authority, claim),
        }
    }
}

/// Nonblocking producer admission for one exact connector resource scope.
///
/// The synchronous admission call runs before a producer can queue or await
/// hidden work. The returned lease must move with the callback value and stay
/// alive through delivery or execution.
#[derive(Clone)]
pub(super) struct CallbackProducerOwner {
    scope: CallbackResourceScopeOwner,
    authority: crate::resource::ResourceAuthorityClass,
    claims: CallbackProducerClaims,
}

impl CallbackProducerOwner {
    pub(super) fn new(
        scope: crate::runtime::attempt::ConnectorWorkResourceScope,
        authority: crate::resource::ResourceAuthorityClass,
        claims: CallbackProducerClaims,
    ) -> Self {
        Self {
            scope: CallbackResourceScopeOwner::Production(scope),
            authority,
            claims,
        }
    }

    pub(super) fn try_admit(
        &self,
        class: ConnectorCallbackClass,
        payload_bytes: usize,
    ) -> std::result::Result<CallbackWorkLease, CallbackProducerOverload> {
        self.try_admit_with_accounted_slack(class, payload_bytes, 0)
    }

    pub(super) fn try_admit_with_accounted_slack(
        &self,
        class: ConnectorCallbackClass,
        payload_bytes: usize,
        retained_slack: usize,
    ) -> std::result::Result<CallbackWorkLease, CallbackProducerOverload> {
        let payload_bytes = u64::try_from(payload_bytes)
            .map_err(|_| CallbackProducerOverload::PayloadSizeUnrepresentable { class })?;
        let retained_slack = u64::try_from(retained_slack)
            .map_err(|_| CallbackProducerOverload::PayloadSizeUnrepresentable { class })?;
        let phase = self.claims.for_class(class);
        let retention = crate::resource::ResourceClaim::single(
            crate::resource::ResourceClass::AccountedMemoryBytes,
            retained_slack,
        );
        let queued = phase
            .queued
            .checked_add(retention)
            .and_then(|supplemental| callback_phase_claim(supplemental, payload_bytes, true))
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let executing = phase
            .executing
            .checked_add(retention)
            .and_then(|supplemental| callback_phase_claim(supplemental, payload_bytes, false))
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let lease = self
            .scope
            .acquire(self.authority, queued)
            .map_err(
                |unavailable| CallbackProducerOverload::ResourceUnavailable { class, unavailable },
            )?;
        Ok(CallbackWorkLease {
            lease,
            class,
            executing,
            phase: CallbackWorkPhase::Queued,
        })
    }

    /// Replace a structural executing callback claim with the measured
    /// payload and retained allocation slack after native conversion reveals
    /// their exact sizes. The original claim remains owned if the transition
    /// is refused.
    pub(super) fn account_executing_payload(
        &self,
        work: &mut CallbackWorkLease,
        payload_bytes: usize,
        retained_slack: usize,
    ) -> std::result::Result<(), CallbackProducerOverload> {
        let class = work.class;
        if work.phase != CallbackWorkPhase::Executing {
            return Err(CallbackProducerOverload::PhaseMismatch { class });
        }
        let payload_bytes = u64::try_from(payload_bytes)
            .map_err(|_| CallbackProducerOverload::PayloadSizeUnrepresentable { class })?;
        let retained_slack = u64::try_from(retained_slack)
            .map_err(|_| CallbackProducerOverload::PayloadSizeUnrepresentable { class })?;
        let retention = crate::resource::ResourceClaim::single(
            crate::resource::ResourceClass::AccountedMemoryBytes,
            retained_slack,
        );
        let executing = self
            .claims
            .for_class(class)
            .executing
            .checked_add(retention)
            .and_then(|supplemental| callback_phase_claim(supplemental, payload_bytes, false))
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        work.lease.transition(executing).map_err(|unavailable| {
            CallbackProducerOverload::ResourceUnavailable { class, unavailable }
        })?;
        work.executing = executing;
        Ok(())
    }

    /// Reserve one lifecycle delivery as the component-wise maximum of its
    /// queued and executing phases. The later phase transition can therefore
    /// only release capacity and cannot lose open or close under pressure.
    pub(super) fn reserve_lifecycle_delivery(
        &self,
    ) -> std::result::Result<CallbackWorkLease, CallbackProducerOverload> {
        let class = ConnectorCallbackClass::Control;
        let phase = self.claims.for_class(class);
        let queued = callback_phase_claim(phase.queued, 0, true)
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let executing = callback_phase_claim(phase.executing, 0, false)
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let reserved = componentwise_max_claim(queued, executing)
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let lease = self
            .scope
            .acquire(self.authority, reserved)
            .map_err(
                |unavailable| CallbackProducerOverload::ResourceUnavailable { class, unavailable },
            )?;
        Ok(CallbackWorkLease {
            lease,
            class,
            executing,
            phase: CallbackWorkPhase::Queued,
        })
    }

    /// Build a finite provider for the raw transport-lab compatibility API.
    ///
    /// This path exists only outside the engine-owned connector, and its four
    /// numbers come from the **fixture that calls it**, not from a policy type.
    /// They used to arrive as owner-selected local ceilings on
    /// `ConnectorCallbackPolicy`, which made a lab-only need look like a
    /// production configuration surface and put four numbers in every
    /// deployment's vocabulary to serve one test path. The numbers themselves
    /// are unchanged and so is the arithmetic below; only who states them moved.
    /// It does not select a production policy or create a basal product-object
    /// limit.
    ///
    /// **Each class is funded from its own stated ceiling, at both phases.**
    /// Control and endpoint data both carry payload bytes into
    /// [`callback_phase_claim`], which charges `QueuedBytes` on the queued
    /// phase, so a grant that funds only one class funds neither reliably — the
    /// provider is a single pool and whichever class draws first decides whether
    /// the other is refused. That is not a hypothetical: this path previously
    /// derived its whole byte grant from an endpoint frame maximum and control
    /// ICE candidates were admitted out of it, so removing that maximum left the
    /// grant with zero `QueuedBytes` and every gathered candidate was refused.
    ///
    /// One ceiling shared by both classes would be the same defect in a softer
    /// form — the grant would carry `max(control, endpoint)` for each and the
    /// generously-sized class would pay for the other — so the two are stated
    /// and applied separately. The reserved lifecycle deliveries are funded at
    /// their real payload of zero rather than at either ceiling, because payload
    /// surplus reserved for callbacks that carry no payload is exactly the
    /// undeclared pool this whole repair exists to remove.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(super) fn for_local_lab_grant(
        grant: TransportLabCallbackGrant,
    ) -> std::result::Result<Self, CallbackProducerOverload> {
        let class = ConnectorCallbackClass::Control;
        let control_slots = u64::try_from(grant.control_slots.get())
            .map_err(|_| CallbackProducerOverload::PayloadSizeUnrepresentable { class })?;
        let endpoint_slots = u64::try_from(grant.endpoint_slots.get())
            .map_err(|_| CallbackProducerOverload::PayloadSizeUnrepresentable { class })?;

        // The two numbers this path cannot infer, one per class. A fixture that
        // mints its own provider states the largest payload it will fund for
        // each; core picks neither, and neither class's limit is borrowed to
        // stand in for the other's.
        let control_payload = u64::try_from(grant.control_payload_bytes.get())
            .map_err(|_| CallbackProducerOverload::PayloadSizeUnrepresentable { class })?;
        let endpoint_payload = u64::try_from(grant.endpoint_payload_bytes.get()).map_err(|_| {
            CallbackProducerOverload::PayloadSizeUnrepresentable {
                class: ConnectorCallbackClass::EndpointData,
            }
        })?;

        let structural = CallbackProducerClaims::structural_only();
        let control = structural.for_class(ConnectorCallbackClass::Control);
        let endpoint = structural.for_class(ConnectorCallbackClass::EndpointData);
        // Queued *and* executing, summed rather than maxed, because the native
        // pump reaches both at once: a callback that has converted its payload
        // holds the executing lease while the handoff behind it takes a queued
        // one. Control carries payload bytes like any other queued class — a
        // local ICE candidate is converted to JSON and queued, and those bytes
        // are charged against `QueuedBytes` on the queued phase.
        let control_slot = callback_phase_claim(control.queued, control_payload, true)
            .and_then(|queued| {
                callback_phase_claim(control.executing, control_payload, false)
                    .and_then(|executing| queued.checked_add(executing))
            })
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let endpoint_slot = callback_phase_claim(endpoint.queued, endpoint_payload, true)
            .and_then(|queued| {
                callback_phase_claim(endpoint.executing, endpoint_payload, false)
                    .and_then(|executing| queued.checked_add(executing))
            })
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic {
                class: ConnectorCallbackClass::EndpointData,
                error,
            })?;
        // The reserved lifecycle deliveries are funded at the payload they
        // actually carry, which is none, and componentwise-maxed exactly as
        // `reserve_lifecycle_delivery` reserves them. Handing them the control
        // ceiling instead would be payload surplus for callbacks that never
        // carry a payload — a pool five candidates deep that nothing declared,
        // sitting where a real control admission could quietly draw on it.
        let lifecycle_slot = callback_phase_claim(control.queued, 0, true)
            .and_then(|queued| {
                callback_phase_claim(control.executing, 0, false)
                    .and_then(|executing| componentwise_max_claim(queued, executing))
            })
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let containers = scale_claim(
            callback_mailbox_container_claim()
                .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?,
            2,
        )
        .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;

        let lifecycle_slots = u64::try_from(grant.observation_slots.get())
            .map_err(|_| CallbackProducerOverload::PayloadSizeUnrepresentable { class })?;
        let callback_claims = scale_claim(control_slot, control_slots)
            .and_then(|claim| {
                scale_claim(lifecycle_slot, lifecycle_slots)
                    .and_then(|lifecycle| claim.checked_add(lifecycle))
            })
            .and_then(|claim| {
                scale_claim(endpoint_slot, endpoint_slots)
                    .and_then(|endpoint| claim.checked_add(endpoint))
            })
            .and_then(|claim| claim.checked_add(containers))
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;

        // The finite provider accounts one residual record per scope and per
        // live reservation. Include both scopes, both mailbox reservations,
        // every local queue/lifecycle reservation, and one executing callback.
        let reservation_records = 2_u64
            .checked_add(lifecycle_slots)
            .and_then(|value| value.checked_add(control_slots))
            .and_then(|value| value.checked_add(endpoint_slots))
            .and_then(|value| value.checked_add(1))
            .ok_or(CallbackProducerOverload::ClaimArithmetic {
                class,
                error: crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                },
            })?;
        let provider_records = reservation_records.checked_add(2).ok_or(
            CallbackProducerOverload::ClaimArithmetic {
                class,
                error: crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                },
            },
        )?;
        let grant = callback_claims
            .checked_add(crate::resource::ResourceClaim::single(
                crate::resource::ResourceClass::OpaqueDependencyResidual,
                provider_records,
            ))
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let port = crate::resource::ResourceProviderPort::new(
            crate::resource::FiniteResourceProvider::new(grant),
        )
        .map_err(
            |unavailable| CallbackProducerOverload::ResourceUnavailable { class, unavailable },
        )?;
        let scope = port
            .create_scope(&port.process_scope())
            .map_err(
                |unavailable| CallbackProducerOverload::ResourceUnavailable { class, unavailable },
            )?;
        Ok(Self {
            scope: CallbackResourceScopeOwner::Lab { port, scope },
            authority: crate::resource::ResourceAuthorityClass::Speculative,
            claims: structural,
        })
    }

    #[cfg(test)]
    fn from_test_scope(
        scope: impl CallbackResourceScope + 'static,
        authority: crate::resource::ResourceAuthorityClass,
        claims: CallbackProducerClaims,
    ) -> Self {
        Self {
            scope: CallbackResourceScopeOwner::Test(Arc::new(scope)),
            authority,
            claims,
        }
    }
}

/// What one raw transport-lab fixture funds, stated by that fixture.
///
/// Four numbers and no policy: slot counts per class and the largest single
/// payload the fixture will fund per class. Both payload figures are required
/// together because a grant that funds one class out of the other's budget is
/// the cross-funding defect this whole path was repaired for — an endpoint
/// frame maximum standing in for an ICE candidate's bytes left `QueuedBytes`
/// empty and refused every gathered candidate.
#[cfg(any(test, feature = "transport-lab"))]
#[derive(Clone, Copy, Debug)]
pub struct TransportLabCallbackGrant {
    pub control_slots: NonZeroUsize,
    pub endpoint_slots: NonZeroUsize,
    pub control_payload_bytes: NonZeroUsize,
    pub endpoint_payload_bytes: NonZeroUsize,
    /// Lifecycle deliveries this fixture funds: the reserved open and close,
    /// plus however many of the three independently pending observations —
    /// renegotiation, ICE state, peer-connection state — it will actually
    /// produce.
    ///
    /// Stated rather than fixed at five, because a lifecycle delivery is funded
    /// at a payload of zero and is therefore pure count capacity. A fixture that
    /// reserves two and is granted five is holding three unattributed callback
    /// slots in the same pool a control-class or endpoint insert draws from —
    /// which is exactly how a control asserting "the next insert is refused"
    /// gets it admitted instead, out of capacity nothing declared and nothing
    /// consumes.
    pub observation_slots: NonZeroUsize,
}

#[cfg(any(test, feature = "transport-lab"))]
fn scale_claim(
    claim: crate::resource::ResourceClaim,
    factor: u64,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    crate::resource::ResourceClaim::try_from_entries(
        crate::resource::ResourceClass::ALL
            .into_iter()
            .map(|dimension| {
                claim
                    .amount(dimension)
                    .checked_mul(factor)
                    .map(|amount| (dimension, amount))
                    .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow { dimension })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
    )
}

fn componentwise_max_claim(
    left: crate::resource::ResourceClaim,
    right: crate::resource::ResourceClaim,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    crate::resource::ResourceClaim::try_from_entries(
        crate::resource::ResourceClass::ALL
            .into_iter()
            .map(|dimension| {
                (
                    dimension,
                    left.amount(dimension).max(right.amount(dimension)),
                )
            }),
    )
}

fn callback_phase_claim(
    supplemental: crate::resource::ResourceClaim,
    payload_bytes: u64,
    queued: bool,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let record_bytes = if queued {
        callback_queue_record_bytes()?
    } else {
        u64::try_from(std::mem::size_of::<WebRtcConnectorEvent>()).map_err(|_| {
            crate::resource::ResourceClaimArithmeticError::Overflow {
                dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
            }
        })?
    };
    let accounted_bytes = payload_bytes.checked_add(record_bytes).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let mut structural = crate::resource::ResourceClaim::try_from_entries([
        (crate::resource::ResourceClass::CallbackOrScheduledWork, 1),
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted_bytes,
        ),
        // One queue-node or executing dependency-work domain whose allocation
        // shape is not represented by the Rust value's inline size. For local
        // ICE conversion this residual is live before `to_json` starts.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
    ])?;
    if queued {
        structural = structural.checked_add(crate::resource::ResourceClaim::single(
            crate::resource::ResourceClass::QueuedBytes,
            payload_bytes,
        ))?;
    }
    structural.checked_add(supplemental)
}

fn callback_queue_record_bytes(
) -> std::result::Result<u64, crate::resource::ResourceClaimArithmeticError> {
    let links = std::mem::size_of::<usize>().checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let bytes = std::mem::size_of::<QueuedTransportEvent>()
        .checked_add(links)
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    u64::try_from(bytes).map_err(
        |_| crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )
}

fn callback_mailbox_container_claim() -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let arc_header_bytes = std::mem::size_of::<usize>().checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let bytes = std::mem::size_of::<ResourceBackedCallbackMailbox>()
        .checked_add(arc_header_bytes)
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let bytes = u64::try_from(bytes).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    crate::resource::ResourceClaim::try_from_entries([
        (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
        // The mailbox and Arc counters occupy one allocation shared by its
        // producers and consumer. Allocator overhead is an explicit residual.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

#[cfg(any(test, feature = "transport-lab"))]
pub(super) fn connector_construction_claims() -> std::result::Result<
    [crate::resource::ResourceClaim; 7],
    crate::resource::ResourceClaimArithmeticError,
> {
    let phases =
        CallbackProducerClaims::structural_only().for_class(ConnectorCallbackClass::Control);
    let queued = callback_phase_claim(phases.queued, 0, true)?;
    let executing = callback_phase_claim(phases.executing, 0, false)?;
    let lifecycle = componentwise_max_claim(queued, executing)?;
    let container = callback_mailbox_container_claim()?;
    // Two lossless mailbox containers plus open, close, renegotiation, ICE
    // state, and peer-connection state. Each lifecycle owner can retain one
    // exact item independently of ordinary mailbox pressure.
    Ok([
        container, container, lifecycle, lifecycle, lifecycle, lifecycle, lifecycle,
    ])
}

/// Derive the callback leases admitted by one explicit test profile.
///
/// This is test-fixture accounting, not a product default. The fixture funds
/// each local mailbox slot in both its queued and executing forms, plus one
/// executing native-track callback for every track surface declared by the
/// temporary compatibility profile. Production grants remain owner supplied.
///
/// The two payload ceilings arrive as arguments rather than being read off the
/// policy here, and that is deliberate. This function has no way to refuse: its
/// error type is claim arithmetic, so a missing ceiling could only become a
/// silent zero — which is precisely the underfunding being repaired. The caller
/// resolves them from the profile and refuses by name when one is absent, so
/// there is no path on which a declared mailbox is funded for no payload.
#[cfg(any(test, feature = "transport-lab"))]
pub(super) fn connector_fixture_operation_claims(
    slots: Option<(NonZeroUsize, NonZeroUsize)>,
    native_realtime_surfaces: usize,
    control_payload: u64,
    endpoint_payload: u64,
) -> std::result::Result<
    Vec<crate::resource::ResourceClaim>,
    crate::resource::ResourceClaimArithmeticError,
> {
    let Some((control_slots, endpoint_slots)) = slots else {
        return Ok(Vec::new());
    };
    let structural = CallbackProducerClaims::structural_only();
    let mut claims = Vec::new();

    let control = structural.for_class(ConnectorCallbackClass::Control);
    for _ in 0..control_slots.get() {
        claims.push(callback_phase_claim(control.queued, control_payload, true)?);
        claims.push(callback_phase_claim(
            control.executing,
            control_payload,
            false,
        )?);
    }

    let endpoint = structural.for_class(ConnectorCallbackClass::EndpointData);
    for _ in 0..endpoint_slots.get() {
        claims.push(callback_phase_claim(
            endpoint.queued,
            endpoint_payload,
            true,
        )?);
        claims.push(callback_phase_claim(
            endpoint.executing,
            endpoint_payload,
            false,
        )?);
    }

    let realtime = structural.for_class(ConnectorCallbackClass::Realtime);
    for _ in 0..native_realtime_surfaces {
        claims.push(callback_phase_claim(realtime.executing, 0, false)?);
    }
    Ok(claims)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CallbackWorkPhase {
    Queued,
    Executing,
}

/// Exact provider lease owned by one queued or executing callback.
#[derive(Debug)]
pub(super) struct CallbackWorkLease {
    lease: crate::resource::ResourceLease,
    class: ConnectorCallbackClass,
    executing: crate::resource::ResourceClaim,
    phase: CallbackWorkPhase,
}

impl CallbackWorkLease {
    #[cfg(test)]
    pub(super) fn phase(&self) -> CallbackWorkPhase {
        self.phase
    }

    #[cfg(test)]
    pub(super) fn claim(&self) -> crate::resource::ResourceClaim {
        self.lease.claim()
    }

    pub(super) fn begin_execution(&mut self) -> std::result::Result<(), CallbackProducerOverload> {
        if self.phase == CallbackWorkPhase::Executing {
            return Ok(());
        }
        self.lease
            .transition(self.executing)
            .map_err(
                |unavailable| CallbackProducerOverload::ResourceUnavailable {
                    class: self.class,
                    unavailable,
                },
            )?;
        self.phase = CallbackWorkPhase::Executing;
        Ok(())
    }

    fn class(&self) -> ConnectorCallbackClass {
        self.class
    }
}

/// Why a callback value was not inserted into its resource-backed mailbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CallbackMailboxInsertErrorKind {
    Closed,
    MissingLease,
    WrongClass,
    WrongPhase,
}

/// Typed refusal that returns the exact value and its lease to the producer.
///
/// Dropping this error releases every lease owned by the refused value. There
/// is no producer-side waiter or secondary queue.
pub(super) struct CallbackMailboxInsertError {
    kind: CallbackMailboxInsertErrorKind,
    _event: QueuedTransportEvent,
}

impl CallbackMailboxInsertError {
    pub(super) const fn kind(&self) -> CallbackMailboxInsertErrorKind {
        self.kind
    }

    #[cfg(test)]
    pub(super) fn into_event(self) -> QueuedTransportEvent {
        self._event
    }
}

/// One resource-backed callback mailbox with no item ceiling at all.
///
/// Every queued value must arrive with a live queued-phase callback lease.
/// The queue uses a linked representation so it does not retain unaccounted
/// spare capacity. Each event record, its two queue links, and one allocator
/// residual are part of that value's queued claim, so provider pressure is not
/// merely authoritative — it is the whole of the bound. The optional per-class
/// slot count an owner could once state is gone: it could only refuse a
/// callback the owner's real grant had already funded.
pub(super) struct ResourceBackedCallbackMailbox {
    class: ConnectorCallbackClass,
    queue: SyncMutex<std::collections::LinkedList<QueuedTransportEvent>>,
    ready: Arc<tokio::sync::Notify>,
    closed: AtomicBool,
    _container_lease: crate::resource::ResourceLease,
}

impl CallbackProducerOwner {
    /// Reserve the mailbox container before allocating it.
    ///
    /// The returned mailbox has no item ceiling unless an explicit local
    /// wrapper is supplied. Every later insertion is synchronous and fallible.
    pub(super) fn create_mailbox(
        &self,
        class: ConnectorCallbackClass,
        ready: Arc<tokio::sync::Notify>,
    ) -> std::result::Result<Arc<ResourceBackedCallbackMailbox>, CallbackProducerOverload> {
        let claim = callback_mailbox_container_claim()
            .map_err(|error| CallbackProducerOverload::ClaimArithmetic { class, error })?;
        let lease = self
            .scope
            .acquire(self.authority, claim)
            .map_err(
                |unavailable| CallbackProducerOverload::ResourceUnavailable { class, unavailable },
            )?;
        Ok(Arc::new(ResourceBackedCallbackMailbox {
            class,
            queue: SyncMutex::new(std::collections::LinkedList::new()),
            ready,
            closed: AtomicBool::new(false),
            _container_lease: lease,
        }))
    }
}

impl ResourceBackedCallbackMailbox {
    /// Insert one already-admitted callback without awaiting or creating a
    /// producer waiter. A refusal returns the exact value to its producer.
    #[allow(
        clippy::result_large_err,
        reason = "the refusal deliberately returns the move-only event and its exact resource lease without another allocation"
    )]
    pub(super) fn try_insert(
        &self,
        event: QueuedTransportEvent,
    ) -> std::result::Result<(), CallbackMailboxInsertError> {
        let refusal = |kind, event| CallbackMailboxInsertError {
            kind,
            _event: event,
        };
        let Some(work) = event.callback_work.as_ref() else {
            return Err(refusal(CallbackMailboxInsertErrorKind::MissingLease, event));
        };
        if work.class() != self.class {
            return Err(refusal(CallbackMailboxInsertErrorKind::WrongClass, event));
        }
        if work.phase != CallbackWorkPhase::Queued {
            return Err(refusal(CallbackMailboxInsertErrorKind::WrongPhase, event));
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(refusal(CallbackMailboxInsertErrorKind::Closed, event));
        }
        let mut queue = self.queue.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(refusal(CallbackMailboxInsertErrorKind::Closed, event));
        }
        queue.push_back(event);
        drop(queue);
        self.ready.notify_one();
        Ok(())
    }

    pub(super) fn try_take(&self) -> Option<QueuedTransportEvent> {
        self.queue.lock().pop_front()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Stop insertion and release every queued callback outside the queue lock.
    pub(super) fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let queued = {
            let mut queue = self.queue.lock();
            std::mem::take(&mut *queue)
        };
        drop(queued);
        self.ready.notify_waiters();
    }
}

struct ConnectorOperationFenceState {
    closing: bool,
    active_operations: usize,
    accounting_poisoned: bool,
}

/// One total ordering boundary for application-affecting connector work.
///
/// Inbound callbacks, endpoint sends, real-time writes, lane operations, track
/// attachment, and close all enter through this owner. Work admitted before
/// close may finish or be discarded by the receiver, but work presented after
/// close cannot enter. Native close waits for all earlier operations to drop
/// their permits.
pub(super) struct ConnectorOperationFence {
    state: SyncMutex<ConnectorOperationFenceState>,
    closed_signal: watch::Sender<bool>,
    active_signal: watch::Sender<usize>,
}

impl Default for ConnectorOperationFence {
    fn default() -> Self {
        let (closed_signal, _receiver) = watch::channel(false);
        let (active_signal, _receiver) = watch::channel(0);
        Self {
            state: SyncMutex::new(ConnectorOperationFenceState {
                closing: false,
                active_operations: 0,
                accounting_poisoned: false,
            }),
            closed_signal,
            active_signal,
        }
    }
}

impl ConnectorOperationFence {
    pub(super) fn try_enter(self: &Arc<Self>) -> Option<ConnectorOperationPermit> {
        let mut state = self.state.lock();
        if state.closing || state.accounting_poisoned {
            return None;
        }
        let Some(active_operations) = state.active_operations.checked_add(1) else {
            state.accounting_poisoned = true;
            state.closing = true;
            self.closed_signal.send_replace(true);
            return None;
        };
        state.active_operations = active_operations;
        self.active_signal.send_replace(active_operations);
        Some(ConnectorOperationPermit {
            fence: Arc::clone(self),
            active: true,
        })
    }

    pub(super) fn begin_close(&self) -> bool {
        let mut state = self.state.lock();
        if state.closing {
            return false;
        }
        state.closing = true;
        self.closed_signal.send_replace(true);
        true
    }

    pub(super) fn is_closed(&self) -> bool {
        self.state.lock().closing
    }

    pub(super) async fn wait_for_operations(&self) {
        let mut active = self.active_signal.subscribe();
        loop {
            if *active.borrow() == 0 {
                return;
            }
            if active.changed().await.is_err() {
                return;
            }
        }
    }

    #[cfg(test)]
    pub(super) fn active_operations_for_test(&self) -> usize {
        self.state.lock().active_operations
    }
}

pub(super) struct ConnectorOperationPermit {
    fence: Arc<ConnectorOperationFence>,
    active: bool,
}

impl Drop for ConnectorOperationPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.fence.state.lock();
        let Some(active_operations) = state.active_operations.checked_sub(1) else {
            state.accounting_poisoned = true;
            state.closing = true;
            self.fence.closed_signal.send_replace(true);
            return;
        };
        state.active_operations = active_operations;
        self.fence.active_signal.send_replace(active_operations);
        self.active = false;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConnectorLifecyclePhase {
    AwaitingOpen,
    OpenPending,
    OpenCommitted,
    ClosedPending,
    ClosedDelivered,
}

struct ConnectorLifecycleState {
    phase: ConnectorLifecyclePhase,
    open_exposed: bool,
    reserved_open_work: Option<CallbackWorkLease>,
    reserved_close_work: Option<CallbackWorkLease>,
    open_work: Option<CallbackWorkLease>,
    close_work: Option<CallbackWorkLease>,
    close_survives_retirement: bool,
    renegotiation_work: Option<CallbackWorkLease>,
    ice_connection_state: Option<(RTCIceConnectionState, CallbackWorkLease)>,
    peer_connection_state: Option<(RTCPeerConnectionState, CallbackWorkLease)>,
}

/// Fixed, lossless owner for connector lifecycle and coalesced observations.
///
/// Open, close, and renegotiation never compete for ordinary callback mailbox
/// capacity. ICE and peer-connection state are latest-value observations.
pub(super) struct ConnectorLifecycleOwner {
    state: SyncMutex<ConnectorLifecycleState>,
    ready: tokio::sync::Notify,
}

impl Default for ConnectorLifecycleOwner {
    fn default() -> Self {
        Self {
            state: SyncMutex::new(ConnectorLifecycleState {
                phase: ConnectorLifecyclePhase::AwaitingOpen,
                open_exposed: false,
                reserved_open_work: None,
                reserved_close_work: None,
                open_work: None,
                close_work: None,
                close_survives_retirement: false,
                renegotiation_work: None,
                ice_connection_state: None,
                peer_connection_state: None,
            }),
            ready: tokio::sync::Notify::new(),
        }
    }
}

impl ConnectorLifecycleOwner {
    fn owns_queued_control_work(work: &CallbackWorkLease) -> bool {
        work.class == ConnectorCallbackClass::Control && work.phase == CallbackWorkPhase::Queued
    }

    /// Build the lifecycle owner with open- and close-delivery claims reserved
    /// before native callbacks can start. Neither transition can be lost merely
    /// because speculative callbacks consumed the remaining process grant.
    pub(super) fn with_reserved_lifecycle_work(
        open_work: CallbackWorkLease,
        close_work: CallbackWorkLease,
    ) -> Self {
        Self {
            state: SyncMutex::new(ConnectorLifecycleState {
                phase: ConnectorLifecyclePhase::AwaitingOpen,
                open_exposed: false,
                reserved_open_work: Some(open_work),
                reserved_close_work: Some(close_work),
                open_work: None,
                close_work: None,
                close_survives_retirement: false,
                renegotiation_work: None,
                ice_connection_state: None,
                peer_connection_state: None,
            }),
            ready: tokio::sync::Notify::new(),
        }
    }

    pub(super) fn record_open(&self) -> ConnectorCallbackInsertResult {
        let mut state = self.state.lock();
        let result = match state.phase {
            ConnectorLifecyclePhase::AwaitingOpen => {
                let Some(work) = state.reserved_open_work.take() else {
                    return ConnectorCallbackInsertResult::PolicyRefused;
                };
                state.phase = ConnectorLifecyclePhase::OpenPending;
                state.open_exposed = false;
                state.open_work = Some(work);
                ConnectorCallbackInsertResult::Queued
            }
            ConnectorLifecyclePhase::OpenPending | ConnectorLifecyclePhase::OpenCommitted => {
                ConnectorCallbackInsertResult::PolicyRefused
            }
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered => {
                ConnectorCallbackInsertResult::DiscardedAfterClose
            }
        };
        drop(state);
        if result == ConnectorCallbackInsertResult::Queued {
            self.ready.notify_one();
        }
        result
    }

    pub(super) fn record_close(&self, survives_retirement: bool) -> ConnectorCallbackInsertResult {
        let mut state = self.state.lock();
        let result = match state.phase {
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered => {
                ConnectorCallbackInsertResult::DiscardedAfterClose
            }
            ConnectorLifecyclePhase::AwaitingOpen
            | ConnectorLifecyclePhase::OpenPending
            | ConnectorLifecyclePhase::OpenCommitted => {
                let Some(work) = state.reserved_close_work.take() else {
                    return ConnectorCallbackInsertResult::PolicyRefused;
                };
                state.phase = ConnectorLifecyclePhase::ClosedPending;
                state.close_survives_retirement = survives_retirement;
                state.reserved_open_work = None;
                state.open_work = None;
                state.close_work = Some(work);
                state.renegotiation_work = None;
                state.ice_connection_state = None;
                state.peer_connection_state = None;
                ConnectorCallbackInsertResult::Queued
            }
        };
        drop(state);
        if result == ConnectorCallbackInsertResult::Queued {
            self.ready.notify_one();
        }
        result
    }

    pub(super) fn commit_open(&self) -> bool {
        let mut state = self.state.lock();
        if state.phase != ConnectorLifecyclePhase::OpenPending || !state.open_exposed {
            return false;
        }
        state.phase = ConnectorLifecyclePhase::OpenCommitted;
        true
    }

    pub(super) fn record_renegotiation(
        &self,
        work: CallbackWorkLease,
    ) -> ConnectorCallbackInsertResult {
        if !Self::owns_queued_control_work(&work) {
            return ConnectorCallbackInsertResult::PolicyRefused;
        }
        let mut state = self.state.lock();
        if matches!(
            state.phase,
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered
        ) {
            return ConnectorCallbackInsertResult::DiscardedAfterClose;
        }
        if state.renegotiation_work.is_none() {
            state.renegotiation_work = Some(work);
        }
        drop(state);
        self.ready.notify_one();
        ConnectorCallbackInsertResult::Queued
    }

    pub(super) fn record_ice_state(
        &self,
        value: RTCIceConnectionState,
        work: CallbackWorkLease,
    ) -> ConnectorCallbackInsertResult {
        if !Self::owns_queued_control_work(&work) {
            return ConnectorCallbackInsertResult::PolicyRefused;
        }
        let mut state = self.state.lock();
        if matches!(
            state.phase,
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered
        ) {
            return ConnectorCallbackInsertResult::DiscardedAfterClose;
        }
        state.ice_connection_state = Some((value, work));
        drop(state);
        self.ready.notify_one();
        ConnectorCallbackInsertResult::Queued
    }

    pub(super) fn record_peer_state(
        &self,
        value: RTCPeerConnectionState,
        work: CallbackWorkLease,
    ) -> ConnectorCallbackInsertResult {
        if !Self::owns_queued_control_work(&work) {
            return ConnectorCallbackInsertResult::PolicyRefused;
        }
        let mut state = self.state.lock();
        if matches!(
            state.phase,
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered
        ) {
            return ConnectorCallbackInsertResult::DiscardedAfterClose;
        }
        state.peer_connection_state = Some((value, work));
        drop(state);
        self.ready.notify_one();
        ConnectorCallbackInsertResult::Queued
    }

    pub(super) fn try_take_close_event(&self) -> Option<QueuedTransportEvent> {
        let mut state = self.state.lock();
        if state.phase != ConnectorLifecyclePhase::ClosedPending {
            return None;
        }
        let work = state.close_work.take()?;
        state.phase = ConnectorLifecyclePhase::ClosedDelivered;
        Some(QueuedTransportEvent {
            event: TransportEvent::DataChannelClosed,
            observation: None,
            callback_work: Some(work),
            #[cfg(feature = "route-flow-diagnostics")]
            route_flow_receipt: None,
        })
    }

    pub(super) fn try_take_event(&self) -> Option<QueuedTransportEvent> {
        if let Some(close) = self.try_take_close_event() {
            return Some(close);
        }
        let mut state = self.state.lock();
        let (event, callback_work) = match state.phase {
            ConnectorLifecyclePhase::OpenPending if !state.open_exposed => {
                let work = state.open_work.take()?;
                state.open_exposed = true;
                Some((TransportEvent::DataChannelOpen, work))
            }
            _ if state.renegotiation_work.is_some() => Some((
                TransportEvent::RenegotiationNeeded,
                state.renegotiation_work.take()?,
            )),
            _ => state
                .ice_connection_state
                .take()
                .map(|(value, work)| (TransportEvent::IceConnectionStateChanged(value), work))
                .or_else(|| {
                    state.peer_connection_state.take().map(|(value, work)| {
                        (TransportEvent::PeerConnectionStateChanged(value), work)
                    })
                }),
        }?;
        Some(QueuedTransportEvent {
            event,
            observation: None,
            callback_work: Some(callback_work),
            #[cfg(feature = "route-flow-diagnostics")]
            route_flow_receipt: None,
        })
    }

    pub(super) fn has_pending(&self) -> bool {
        let state = self.state.lock();
        state.phase == ConnectorLifecyclePhase::ClosedPending
            || (state.phase == ConnectorLifecyclePhase::OpenPending && !state.open_exposed)
            || state.renegotiation_work.is_some()
            || state.ice_connection_state.is_some()
            || state.peer_connection_state.is_some()
    }

    pub(super) fn close_survives_retirement(&self) -> bool {
        self.state.lock().close_survives_retirement
    }

    #[cfg(test)]
    pub(super) fn phase(&self) -> ConnectorLifecyclePhase {
        self.state.lock().phase
    }

    pub(super) async fn notified(&self) {
        self.ready.notified().await;
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ConnectorControlSourceCursor {
    mailbox_next: bool,
}

impl ConnectorControlSourceCursor {
    /// Take from lifecycle and ordinary control in strict alternating order
    /// while skipping an empty source. A continuously refreshed lifecycle
    /// observation therefore cannot starve an admitted control callback.
    pub(super) fn try_take(
        &mut self,
        lifecycle: &ConnectorLifecycleOwner,
        control: &ResourceBackedCallbackMailbox,
    ) -> Option<QueuedTransportEvent> {
        // Close is the one terminal lifecycle transition. Once committed it
        // supersedes ordinary control observations already waiting in the
        // mailbox so none can be dispatched after the close fence.
        if let Some(close) = lifecycle.try_take_close_event() {
            return Some(close);
        }
        for _ in 0..2 {
            let mailbox = self.mailbox_next;
            self.mailbox_next = !self.mailbox_next;
            let event = if mailbox {
                control.try_take()
            } else {
                lifecycle.try_take_event()
            };
            if event.is_some() {
                return event;
            }
        }
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConnectorCallbackScheduler {
    pub(super) weights: [usize; 3],
    pub(super) cursor: usize,
    pub(super) remaining: usize,
}

impl ConnectorCallbackScheduler {
    /// One quantum per ready class, and real-time only when the policy admits
    /// real-time work at all.
    ///
    /// The owner-selected weights this used to read are gone. What they were
    /// configuring — which class runs next and for how long — is a property of
    /// the rotation rather than of a deployment: every ready class gets one
    /// turn, an empty class is skipped rather than waited on, and the cursor
    /// advances, so service stays fair and work-conserving without a number for
    /// an owner to state or for this file and the rotation to disagree about. A
    /// disabled real-time policy scores zero, which is how a class that cannot
    /// exist is skipped rather than given a turn that finds nothing.
    pub(super) fn new(policy: ConnectorCallbackPolicy) -> Self {
        let weights = [
            1,
            1,
            usize::from(matches!(
                policy.realtime(),
                RealtimeConnectorPolicy::Enabled
            )),
        ];
        Self {
            weights,
            cursor: 0,
            remaining: weights[0],
        }
    }

    pub(super) fn current(&self) -> ConnectorCallbackClass {
        ConnectorCallbackClass::from_index(self.cursor)
    }

    pub(super) fn skip_current(&mut self) {
        loop {
            self.cursor = (self.cursor + 1) % self.weights.len();
            self.remaining = self.weights[self.cursor];
            if self.remaining != 0 {
                break;
            }
        }
    }

    pub(super) fn delivered(&mut self, class: ConnectorCallbackClass) {
        let index = class.index();
        if index != self.cursor {
            self.cursor = index;
            self.remaining = self.weights[index];
        }
        self.remaining = self.remaining.saturating_sub(1);
        if self.remaining == 0 {
            self.skip_current();
        }
    }
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use crate::resource::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceClaim, ResourceClass,
        ResourceProviderPort, ResourceScope, ResourceUnavailable,
    };

    #[derive(Clone)]
    struct TestScope {
        provider: ResourceProviderPort,
        scope: ResourceScope,
    }

    impl CallbackResourceScope for TestScope {
        fn acquire(
            &self,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> std::result::Result<crate::resource::ResourceLease, ResourceUnavailable> {
            self.provider.acquire(&self.scope, authority, claim)
        }
    }

    fn claim(entries: &[(ResourceClass, u64)]) -> ResourceClaim {
        ResourceClaim::try_from_entries(entries.iter().copied()).expect("finite test claim")
    }

    fn owner_with_grant(
        grant: ResourceClaim,
        claims: CallbackProducerClaims,
    ) -> (CallbackProducerOwner, FiniteResourceProvider) {
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let scope = port
            .create_scope(&port.process_scope())
            .expect("connector bookkeeping");
        (
            CallbackProducerOwner::from_test_scope(
                TestScope {
                    provider: port,
                    scope,
                },
                ResourceAuthorityClass::Speculative,
                claims,
            ),
            provider,
        )
    }

    fn structural_mailbox_grant(item_count: usize) -> ResourceClaim {
        // One process scope and one connector scope exist before mailbox work.
        let mut grant = ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 2);
        grant = grant
            .checked_add(callback_mailbox_container_claim().expect("mailbox claim is finite"))
            .expect("mailbox grant is finite");
        // The provider retains one reservation record for the container lease.
        grant = grant
            .checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                1,
            ))
            .expect("mailbox bookkeeping is finite");
        for _ in 0..item_count {
            grant = grant
                .checked_add(
                    callback_phase_claim(ResourceClaim::ZERO, 0, true)
                        .expect("callback claim is finite"),
                )
                .expect("callback grant is finite");
            // Each live callback lease has one provider reservation record.
            grant = grant
                .checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    1,
                ))
                .expect("callback bookkeeping is finite");
        }
        grant
    }

    #[test]
    fn producer_admission_precedes_queueing_and_owns_exact_phase_claims() {
        let queued_record_bytes = callback_queue_record_bytes().expect("record size fits");
        let executing_record_bytes =
            u64::try_from(std::mem::size_of::<WebRtcConnectorEvent>()).expect("record size fits");
        let maximum_phase_bytes = queued_record_bytes.max(executing_record_bytes);
        let phases = CallbackPhaseClaims::new(
            ResourceClaim::single(ResourceClass::StorageBytes, 3),
            ResourceClaim::single(ResourceClass::ParsingOrCpuWork, 2),
        );
        let claims = CallbackProducerClaims::new(phases, phases, phases);
        let grant = claim(&[
            (ResourceClass::AccountedMemoryBytes, 7 + maximum_phase_bytes),
            (ResourceClass::QueuedBytes, 7),
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::StorageBytes, 3),
            (ResourceClass::ParsingOrCpuWork, 2),
            (ResourceClass::OpaqueDependencyResidual, 4),
        ]);
        let (owner, provider) = owner_with_grant(grant, claims);

        let mut work = owner
            .try_admit(ConnectorCallbackClass::EndpointData, 7)
            .expect("synchronous producer admission");
        assert_eq!(work.phase(), CallbackWorkPhase::Queued);
        assert_eq!(work.claim().amount(ResourceClass::QueuedBytes), 7);
        assert_eq!(
            work.claim().amount(ResourceClass::AccountedMemoryBytes),
            7 + queued_record_bytes
        );
        assert_eq!(work.claim().amount(ResourceClass::StorageBytes), 3);

        work.begin_execution().expect("atomic dequeue transition");
        assert_eq!(work.phase(), CallbackWorkPhase::Executing);
        assert_eq!(work.claim().amount(ResourceClass::QueuedBytes), 0);
        assert_eq!(
            work.claim().amount(ResourceClass::AccountedMemoryBytes),
            7 + executing_record_bytes
        );
        assert_eq!(work.claim().amount(ResourceClass::ParsingOrCpuWork), 2);
        drop(work);
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 2)
        );
    }

    #[test]
    fn lifecycle_delivery_reserves_both_phases_and_cannot_be_lost_on_transition() {
        let phases = CallbackPhaseClaims::new(
            ResourceClaim::single(ResourceClass::StorageBytes, 3),
            ResourceClaim::single(ResourceClass::ParsingOrCpuWork, 5),
        );
        let claims = CallbackProducerClaims::new(phases, phases, phases);
        let queued =
            callback_phase_claim(phases.queued, 0, true).expect("queued lifecycle claim is finite");
        let executing = callback_phase_claim(phases.executing, 0, false)
            .expect("executing lifecycle claim is finite");
        let reserved =
            componentwise_max_claim(queued, executing).expect("lifecycle phase maximum is finite");
        let grant = reserved
            .checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                3,
            ))
            .expect("process, connector, and reservation bookkeeping are finite");
        let (owner, _provider) = owner_with_grant(grant, claims);

        let mut work = owner
            .reserve_lifecycle_delivery()
            .expect("the exact phase maximum admits lifecycle delivery");
        work.begin_execution()
            .expect("execution only releases the pre-reserved phase maximum");
        assert_eq!(work.phase(), CallbackWorkPhase::Executing);
        assert_eq!(work.claim(), executing);
    }

    #[test]
    fn producer_claim_includes_visible_payload_and_retained_string_slack() {
        let phases = CallbackPhaseClaims::new(ResourceClaim::ZERO, ResourceClaim::ZERO);
        let claims = CallbackProducerClaims::new(phases, phases, phases);
        let payload_bytes = 7_usize;
        let retained_slack = 11_usize;
        let queued = callback_phase_claim(
            ResourceClaim::single(
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(retained_slack).expect("fixture slack fits u64"),
            ),
            u64::try_from(payload_bytes).expect("fixture payload fits u64"),
            true,
        )
        .expect("queued payload claim is finite");
        let grant = queued
            .checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                3,
            ))
            .expect("scope and reservation bookkeeping are finite");
        let (owner, _provider) = owner_with_grant(grant, claims);

        let work = owner
            .try_admit_with_accounted_slack(
                ConnectorCallbackClass::Control,
                payload_bytes,
                retained_slack,
            )
            .expect("the exact producer payload claim is admitted before retention");
        assert_eq!(work.claim(), queued);
        assert_eq!(
            work.claim().amount(ResourceClass::QueuedBytes),
            u64::try_from(payload_bytes).expect("fixture payload fits u64")
        );
    }

    #[test]
    fn executing_callback_accounts_converted_payload_before_async_retention() {
        let phases = CallbackPhaseClaims::new(ResourceClaim::ZERO, ResourceClaim::ZERO);
        let claims = CallbackProducerClaims::new(phases, phases, phases);
        let payload_bytes = 7_usize;
        let retained_slack = 11_usize;
        let expected = callback_phase_claim(
            ResourceClaim::single(
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(retained_slack).expect("fixture slack fits u64"),
            ),
            u64::try_from(payload_bytes).expect("fixture payload fits u64"),
            false,
        )
        .expect("executing payload claim is finite");
        let grant = expected
            .checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                3,
            ))
            .expect("scope and reservation bookkeeping are finite");
        let (owner, _provider) = owner_with_grant(grant, claims);

        let mut work = owner
            .try_admit(ConnectorCallbackClass::Control, 0)
            .expect("structural callback work is admitted before conversion");
        work.begin_execution()
            .expect("native callback starts its executing phase");
        owner
            .account_executing_payload(&mut work, payload_bytes, retained_slack)
            .expect("measured payload replaces the structural executing claim");
        assert_eq!(work.claim(), expected);
    }

    #[test]
    fn producer_overload_is_typed_and_creates_no_hidden_work() {
        let phases = CallbackPhaseClaims::new(ResourceClaim::ZERO, ResourceClaim::ZERO);
        let claims = CallbackProducerClaims::new(phases, phases, phases);
        let grant = claim(&[
            (
                ResourceClass::AccountedMemoryBytes,
                callback_queue_record_bytes().expect("record size fits"),
            ),
            (ResourceClass::OpaqueDependencyResidual, 4),
        ]);
        let (owner, provider) = owner_with_grant(grant, claims);

        let unavailable = owner
            .try_admit(ConnectorCallbackClass::Control, 0)
            .expect_err("callback work was not provisioned");
        assert!(matches!(
            unavailable,
            CallbackProducerOverload::ResourceUnavailable {
                class: ConnectorCallbackClass::Control,
                unavailable: ResourceUnavailable::Pressure(crate::resource::ResourcePressure {
                    dimension: ResourceClass::CallbackOrScheduledWork,
                    ..
                }),
            }
        ));
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 2)
        );
    }

    /// A refusal hands the exact value and its lease back to the producer.
    ///
    /// The refusal this used to exercise was an owner-selected item ceiling,
    /// which no longer exists — there is no count in front of a mailbox any
    /// more, only the provider claim each queued callback already carries. The
    /// property the control was really about outlives it: whatever a mailbox
    /// refuses, it refuses by returning, so no producer is left waiting and no
    /// lease is stranded inside a queue that did not take the value.
    #[test]
    fn resource_backed_mailbox_refuses_without_hiding_a_producer() {
        let claims = CallbackProducerClaims::structural_only();
        let (owner, _provider) = owner_with_grant(structural_mailbox_grant(2), claims);
        let mailbox = owner
            .create_mailbox(
                ConnectorCallbackClass::Control,
                Arc::new(tokio::sync::Notify::new()),
            )
            .expect("container is admitted before allocation");

        let first_work = owner
            .try_admit(ConnectorCallbackClass::Control, 0)
            .expect("first callback is admitted");
        mailbox
            .try_insert(QueuedTransportEvent {
                event: TransportEvent::LocalIceCandidate(None),
                observation: None,
                callback_work: Some(first_work),
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            })
            .unwrap_or_else(|_| panic!("first callback enters the mailbox"));
        assert!(matches!(
            mailbox.try_take().map(|queued| queued.event),
            Some(TransportEvent::LocalIceCandidate(None))
        ));

        mailbox.close();
        let second_work = owner
            .try_admit(ConnectorCallbackClass::Control, 0)
            .expect("second callback is admitted before insertion");
        let refused = mailbox
            .try_insert(QueuedTransportEvent {
                event: TransportEvent::RenegotiationNeeded,
                observation: None,
                callback_work: Some(second_work),
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            })
            .expect_err("a closed mailbox refuses the exact value");
        assert_eq!(refused.kind(), CallbackMailboxInsertErrorKind::Closed);
        assert!(refused.into_event().callback_work.is_some());

        assert!(mailbox.is_closed());
        assert!(mailbox.is_empty());
    }

    #[test]
    fn control_source_cursor_alternates_lifecycle_and_mailbox_work() {
        let claims = CallbackProducerClaims::structural_only();
        let (owner, _provider) = owner_with_grant(structural_mailbox_grant(2), claims);
        let mailbox = owner
            .create_mailbox(
                ConnectorCallbackClass::Control,
                Arc::new(tokio::sync::Notify::new()),
            )
            .expect("mailbox is admitted");
        let lifecycle = ConnectorLifecycleOwner::default();

        let lifecycle_work = owner
            .try_admit(ConnectorCallbackClass::Control, 0)
            .expect("lifecycle callback is admitted");
        assert_eq!(
            lifecycle.record_renegotiation(lifecycle_work),
            ConnectorCallbackInsertResult::Queued
        );
        let mailbox_work = owner
            .try_admit(ConnectorCallbackClass::Control, 0)
            .expect("mailbox callback is admitted");
        mailbox
            .try_insert(QueuedTransportEvent {
                event: TransportEvent::LocalIceCandidate(None),
                observation: None,
                callback_work: Some(mailbox_work),
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            })
            .unwrap_or_else(|_| panic!("mailbox callback is queued"));

        let mut cursor = ConnectorControlSourceCursor::default();
        assert!(matches!(
            cursor
                .try_take(&lifecycle, &mailbox)
                .map(|queued| queued.event),
            Some(TransportEvent::RenegotiationNeeded)
        ));
        assert!(matches!(
            cursor
                .try_take(&lifecycle, &mailbox)
                .map(|queued| queued.event),
            Some(TransportEvent::LocalIceCandidate(None))
        ));
    }

    /// Every admitted class gets its turn, and a class the policy admits no
    /// work for gets none.
    ///
    /// The owner-selected weights this used to drive are gone, so what is under
    /// test is the rotation itself: one quantum each, in order, round-robin. The
    /// data-only leg is the discriminating half — a scheduler that gave the
    /// real-time class a turn on a connector that will never produce a real-time
    /// callback would spend a third of its rotation finding nothing, which is
    /// exactly what the zero weight prevents.
    #[test]
    fn the_scheduler_serves_every_admitted_class_and_skips_the_one_that_is_disabled() {
        let mut scheduler =
            ConnectorCallbackScheduler::new(ConnectorCallbackPolicy::elastic_realtime());
        let mut delivered = [0; 3];
        for _ in 0..6 {
            let class = scheduler.current();
            delivered[class.index()] += 1;
            scheduler.delivered(class);
        }
        assert_eq!(
            delivered,
            [2, 2, 2],
            "an enabled real-time policy rotates through all three classes evenly"
        );

        let mut data_only =
            ConnectorCallbackScheduler::new(ConnectorCallbackPolicy::elastic_data_only());
        let mut delivered = [0; 3];
        for _ in 0..6 {
            let class = data_only.current();
            delivered[class.index()] += 1;
            data_only.delivered(class);
        }
        assert_eq!(
            delivered,
            [3, 3, 0],
            "and a data-only policy never offers a turn to the class it admits \
             no work for"
        );

        scheduler.cursor = ConnectorCallbackClass::Control.index();
        scheduler.remaining = scheduler.weights[scheduler.cursor];
        scheduler.skip_current();
        assert_eq!(scheduler.current(), ConnectorCallbackClass::EndpointData);
    }
}
