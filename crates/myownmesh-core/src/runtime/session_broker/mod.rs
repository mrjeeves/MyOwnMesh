//! Session Broker: the one atomic promotion into `SessionCapability`.
//!
//! Arc 02 defined the output types and left the transition unimplemented. This
//! module implements it. Promotion consumes, in one call and with no partial
//! commit:
//!
//! - one `AuthenticatedChannelCapability` for the exact current connector;
//! - the canonical typed current-policy answer in [`policy`], derived from the
//!   engine's existing admission state;
//! - one explicit local process principal;
//! - exact post-authentication reservations for the promoted record and the
//!   refcounted validity block its delayed witnesses share.
//!
//! Two invalidations are structural rather than checked by a timer or a
//! generation counter. Connector replacement invalidates because the capability
//! privately retains the exact `ConnectorIncarnation` it was promoted from, and
//! every use compares that `Arc` by pointer identity against the installed one.
//! Process restart invalidates because nothing here is serializable, durable, or
//! reconstructible from a label — the whole chain is memory-only.
//!
//! There is deliberately no identity, attestation, or migration framework here,
//! no timer, generation, or route authority, and no compatibility mode. A
//! session is promoted or it is not.

pub(crate) mod policy;

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use crate::application_gateway::LocalPrincipalCapability;
use crate::connector::ConnectorIncarnation;
use crate::endpoint_auth::AuthenticatedChannelCapability;
use crate::resource::{ResourceClaim, ResourceLease, ResourceUnavailable};
use crate::runtime::attempt::MeshConnectorResourceScope;
use crate::runtime::RuntimeIncarnation;

pub(crate) use policy::CurrentPolicyAdmission;

/// Proof that one post-authentication channel's capacity was reserved.
///
/// There is no conversion from `PreAuthAttemptPermit` into this type, and none
/// from `AuthenticatedChannelCapability` either: an authenticated channel is not
/// an authorized session. It privately owns the provider lease, so dropping the
/// permit releases exactly the reservation it took and nothing else.
pub(crate) struct SessionPermit {
    runtime: RuntimeIncarnation,
    /// The Mesh grant this reservation came out of, retained so the shared
    /// validity lineage can pay for what it goes on to retain.
    ///
    /// A promoted session holds application state whose size it does not know at
    /// promotion time — one retained frame per un-acknowledged reliable send.
    /// Pre-paying a ceiling for that at promotion is the fixed cap the
    /// transition removes; charging each retention against this scope as it
    /// happens is what makes the provider, rather than a constant, the bound.
    /// The scope grants nothing by itself: every acquisition through it is the
    /// provider's own decision.
    scope: MeshConnectorResourceScope,
    /// Held for its `Drop`. The reservation exists for as long as the permit
    /// does, which is for as long as this channel remains promoted.
    _lease: ResourceLease,
}

impl SessionPermit {
    fn reserve(
        scope: &MeshConnectorResourceScope,
        runtime: RuntimeIncarnation,
    ) -> Result<Self, ResourceUnavailable> {
        let lease = scope.reserve_session(
            // The slot owns the exact `LeasedMap` entry. The broker permit
            // therefore funds only the channel-local realtime-flow root it
            // retains; charging the map entry here would double-charge the
            // first install and every additional channel.
            crate::transport::webrtc::SessionRealtimeFlows::promotion_root_claim().expect(
                "the realtime-flow promotion root claim is `size_of` arithmetic over fixed types and cannot overflow",
            ),
        )?;
        Ok(Self {
            runtime,
            scope: scope.clone(),
            _lease: lease,
        })
    }
}

/// Memory-only authority for application use of one promoted peer session.
///
/// The only way to obtain one is [`SessionBroker::promote`], from a verified
/// authenticated channel. Not `Clone`, not serializable, no id field, no
/// constructor taking a label — so a peer string, socket, or stored client
/// record cannot produce one, and possession cannot be transferred or replayed.
pub(crate) struct SessionCapability {
    /// The channel this session was promoted from. Held by value: the session
    /// *is* the authenticated channel's application-facing continuation, and
    /// dropping the session returns the connected claim to the connector.
    ///
    /// The option is only so a slot-install refusal can move this exact
    /// capability back to the connection's authenticated-channel slot before
    /// the session's ordinary `Drop` releases its permit and validity owner.
    authenticated_channel: Option<AuthenticatedChannelCapability>,
    /// The one local process principal, shared rather than re-minted.
    ///
    /// `Arc` because there is exactly one authenticated local principal per
    /// process and every session speaks for that same one. Sharing it is not
    /// cloning authority — a second `LocalPrincipalCapability` value would be a
    /// second principal, which is precisely the generic identity framework the
    /// directive excludes.
    local_principal: Arc<LocalPrincipalCapability>,
    _permit: SessionPermit,
    /// The exact connector this session was promoted from, retained privately
    /// so currentness is decided by pointer identity rather than by a device id
    /// a replacement may since have taken over.
    connector: Arc<ConnectorIncarnation>,
    validity: Arc<SessionValidity>,
}

/// The purpose-owned allocation shared by one session and its delayed
/// witnesses. Its lease lives in this allocation, last, so it remains funded
/// until the final witness drops rather than merely until the session does.
struct SessionValidity {
    live: AtomicBool,
    channel_owners: AtomicUsize,
    wake: tokio::sync::Notify,
    /// The exact provider scope that funded this logical validity lineage.
    /// Retained reservations must come from this scope even when the channel
    /// that first minted the lineage is no longer the caller.
    scope: MeshConnectorResourceScope,
    /// The runtime that funded the lineage, retained alongside its provider
    /// scope so the record remains self-describing across shared channels.
    runtime: RuntimeIncarnation,
    _lease: ResourceLease,
}

impl SessionValidity {
    fn claim() -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
        // Charge the visible funded record. The residual below covers
        // dependency-private shared-allocation metadata; exact Arc
        // control-block layout is not part of the session contract.
        let record = std::mem::size_of::<Self>();
        ResourceClaim::try_from_entries([
            (
                crate::resource::ResourceClass::AccountedMemoryBytes,
                u64::try_from(record).map_err(|_| {
                    crate::resource::ResourceClaimArithmeticError::Overflow {
                        dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
                    }
                })?,
            ),
            (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    fn mint(permit: &SessionPermit) -> Result<Arc<Self>, ResourceUnavailable> {
        let scope = permit.scope.clone();
        let runtime = permit.runtime.clone();
        let lease = permit.scope.reserve_session(Self::claim().expect(
            "the validity record claim is size_of arithmetic over fixed types and cannot overflow",
        ))?;
        Ok(Arc::new(Self {
            live: AtomicBool::new(true),
            channel_owners: AtomicUsize::new(1),
            wake: tokio::sync::Notify::new(),
            scope,
            runtime,
            _lease: lease,
        }))
    }

    /// Reserve capacity retained by this logical validity lineage, independent
    /// of whichever channel currently presents its witness.
    fn reserve_retained(&self, claim: ResourceClaim) -> Result<ResourceLease, ResourceUnavailable> {
        self.scope.reserve_session(claim)
    }

    fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }

    fn invalidate(&self) {
        self.live.store(false, Ordering::Release);
        self.wake.notify_waiters();
    }

    /// Try to attach another promoted channel without minting a second
    /// validity allocation.  The owner is acquired only after the lineage is
    /// observed live and is rechecked after the atomic increment so a
    /// concurrent revocation cannot resurrect a dead session.
    fn try_add_channel_owner(&self) -> bool {
        loop {
            if !self.live.load(Ordering::Acquire) {
                return false;
            }
            let owners = self.channel_owners.load(Ordering::Acquire);
            let Some(next) = owners.checked_add(1) else {
                return false;
            };
            if self
                .channel_owners
                .compare_exchange(owners, next, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            if self.live.load(Ordering::Acquire) {
                return true;
            }
            self.release_channel_owner();
            return false;
        }
    }

    fn release_channel_owner(&self) {
        if self.channel_owners.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.invalidate();
        }
    }
}

/// A cloneable, read-only proof that an owned operation still belongs to the
/// promoted session that minted it.
#[derive(Clone)]
pub(crate) struct SessionValidityWitness {
    validity: Arc<SessionValidity>,
}

impl SessionValidityWitness {
    pub(crate) fn is_live(&self) -> bool {
        self.validity.live.load(Ordering::Acquire)
    }

    /// Revoke this exact logical lineage while its owning session remains
    /// retained for terminal transport cleanup.
    pub(crate) fn invalidate(&self) {
        self.validity.invalidate();
    }

    /// Whether this witness was minted by `session` — the very same promoted
    /// session, not merely one that is also live.
    ///
    /// Identity, by pointer, because the question is identity. [`Self::is_live`]
    /// answers a weaker one that is nearly always sufficient: replacement drops
    /// the predecessor, and `Drop for SessionCapability` invalidates, so a
    /// witness for a replaced session reads dead and stays dead. This exists for
    /// the one caller that should not have to rely on that chain — work funded
    /// under one session and committed under a later acquisition of the same
    /// peer, where "the peer has *a* live session" and "the peer still has *the*
    /// session that paid for this" are different facts and only the second one
    /// authorizes the commit.
    pub(crate) fn witnesses(&self, session: &SessionCapability) -> bool {
        Arc::ptr_eq(&self.validity, &session.validity)
    }

    /// Whether these two witnesses retain the exact same validity allocation.
    ///
    /// This is identity, not merely shared liveness: two live lineages are not
    /// interchangeable authorities.
    pub(crate) fn same_validity(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.validity, &other.validity)
    }

    /// Reserve capacity against the exact provider scope retained by this
    /// witness's logical validity lineage.
    pub(crate) fn reserve_retained(
        &self,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.validity.reserve_retained(claim)
    }

    pub(crate) async fn revoked(&self) {
        loop {
            if !self.is_live() {
                return;
            }
            let notified = self.validity.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.is_live() {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for SessionCapability {
    fn drop(&mut self) {
        self.validity.release_channel_owner();
    }
}

impl SessionCapability {
    /// Return the exact authenticated channel for rollback, consuming this
    /// session capability. The capability's normal drop then releases its
    /// validity owner and retained permit; no authority is cloned or recreated.
    pub(crate) fn demote(mut self) -> Option<AuthenticatedChannelCapability> {
        self.authenticated_channel.take()
    }

    pub(crate) fn validity_witness(&self) -> SessionValidityWitness {
        SessionValidityWitness {
            validity: Arc::clone(&self.validity),
        }
    }
    fn runtime(&self) -> &RuntimeIncarnation {
        self.validity.runtime()
    }

    /// Whether this session was promoted from that exact connector incarnation.
    ///
    /// This is the replacement-invalidation predicate, and it is **identity
    /// only**. A session promoted from a superseded connector answers `false`
    /// against the replacement's incarnation, with no timer, generation counter,
    /// or revocation list.
    ///
    /// Liveness is deliberately not answered here, for the same reason
    /// [`ConnectorIncarnation`] does not answer it: the transport's own
    /// incarnation is the single authoritative source for whether a connector is
    /// still live, and a second flag on this side could disagree with it. A
    /// consumer that needs "the same connector **and** still live" — every
    /// send-time gate does — pairs this with the transport's own liveness:
    ///
    /// ```text
    /// session.belongs_to(incarnation.generic()) && incarnation.is_active()
    /// ```
    ///
    /// A session is never re-bound to a replacement connector. Replacement
    /// invalidates it and the application promotes a new one; an authority that
    /// followed its peer across channels would be the cross-channel relay the
    /// non-session-unique binding cannot rule out on its own.
    pub(crate) fn belongs_to(&self, incarnation: &Arc<ConnectorIncarnation>) -> bool {
        Arc::ptr_eq(&self.connector, incarnation)
    }

    /// Whether this session authenticates that exact mesh and remote Device.
    ///
    /// Read from the channel's own private record, never from a caller-supplied
    /// label, so a session for one context cannot be presented for another.
    /// The §7.3 recheck every application operation owes, in one call.
    ///
    /// Promotion proved these once. This proves them *again at use*, which is
    /// the point: a cached session outlives the instant it was minted, and the
    /// facts it rests on can move underneath it. Each conjunct is read from the
    /// session's own private record or from an identity comparison, never from a
    /// caller-supplied label.
    ///
    /// - the exact connector, so replacement invalidates;
    /// - the exact mesh context and remote Device, so a session cannot be
    ///   presented for a peer or a network it was not authenticated for;
    /// - the local principal and the reservation, still bound to the runtime the
    ///   broker is currently promoting under.
    #[cfg(test)]
    pub(crate) fn authenticated_for(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        self.authenticated_channel
            .as_ref()
            .expect("a live session retains its authenticated channel until demotion")
            .authenticated_for(mesh_context, remote_device_id)
    }

    /// The exact remote Device this session was authenticated against.
    ///
    /// For attribution only. It is derived from the authenticated record, so it
    /// cannot be used to *reach* a peer — reaching one requires presenting this
    /// capability to the registry fence, which revalidates it.
    #[cfg(test)]
    pub(crate) fn remote_device_id(&self) -> &str {
        self.authenticated_channel
            .as_ref()
            .expect("a live session retains its authenticated channel until demotion")
            .record()
            .remote_device_id()
    }

    pub(crate) fn local_principal(&self) -> &LocalPrincipalCapability {
        &self.local_principal
    }

    /// Reserve capacity this session will hold for as long as it holds the
    /// thing it pays for.
    ///
    /// Reachable only through a live session, which is the point: capacity taken
    /// out of a Mesh's grant on a peer's behalf should be traceable to the
    /// session that authorized it, and released by that session ending. There is
    /// no way to acquire this without holding the capability, and no way to hold
    /// the capability past replacement.
    ///
    /// The claim is the caller's to derive from what it actually retains. This
    /// deliberately does not know what is being paid for — a size decided here
    /// would be a second, weaker account of a representation this module cannot
    /// see.
    pub(crate) fn reserve_retained(
        &self,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.validity.reserve_retained(claim)
    }
}

/// Why one promotion did not happen.
///
/// Every variant is a statement about *this* promotion attempt. None of them
/// retires the channel or the connector: refusing to promote leaves the caller's
/// own fail-closed handling to decide what happens to the connection, exactly as
/// the endpoint-authentication setup vocabulary does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionPromotionError {
    /// The channel's connector is no longer the installed one, so there is no
    /// live channel left to promote.
    ChannelNotCurrent,
    /// Current policy does not admit this peer.
    PolicyRefused,
    /// The local principal belongs to a different runtime than the channel.
    ///
    /// Not an authorization decision: it means two values that must describe one
    /// process do not, which makes the promotion meaningless rather than merely
    /// refused.
    RuntimeMismatch,
    /// Post-authentication session capacity was not available.
    ResourcesUnavailable,
}

/// The one owner of the promotion transition.
///
/// Holds the process-wide inputs a promotion needs beside the per-channel ones:
/// the explicit local principal for this process, and the resource scope its
/// post-authentication reservations draw from.
pub(crate) struct SessionBroker {
    runtime: RuntimeIncarnation,
    principal: Arc<LocalPrincipalCapability>,
    resources: MeshConnectorResourceScope,
}

impl SessionBroker {
    pub(crate) fn reserve_local_application(
        &self,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.resources.reserve_application(claim)
    }
    /// Install the broker for one live Mesh runtime.
    ///
    /// The principal is minted once, here, from the explicit local process
    /// binding — not inferred per request from a client label, and not
    /// negotiated with a peer.
    pub(crate) fn new(runtime: RuntimeIncarnation, resources: MeshConnectorResourceScope) -> Self {
        let principal = Arc::new(LocalPrincipalCapability::for_local_process(runtime.clone()));
        Self {
            runtime,
            principal,
            resources,
        }
    }

    /// Promote the authenticated channel held in `slot` into a live session, or
    /// refuse without disturbing it.
    ///
    /// The channel is **borrowed** for every fallible step and moved out of the
    /// slot only once the post-authentication reservation has been taken. That
    /// ordering is the contract, not an implementation detail: a
    /// [`ResourcesUnavailable`](SessionPromotionError::ResourcesUnavailable)
    /// refusal leaves the exact authenticated channel installed, so the next
    /// attempt retries the same proven channel rather than having to
    /// re-authenticate one that a transient capacity shortfall destroyed — a
    /// shortfall the peer had no part in and cannot be asked to prove its way
    /// out of again.
    ///
    /// The three *terminal* refusals still consume it, deliberately and
    /// visibly: a channel whose connector is superseded, whose peer policy
    /// refuses, or whose runtime disagrees is not one this entry may keep, and
    /// retrying it could only ever produce the same answer.
    ///
    /// Lending the slot rather than the value is what makes both halves
    /// structural. A caller cannot commit a channel other than the one that was
    /// validated, because it never holds one: the move happens in here, after
    /// the last fallible step, and nothing between the two can substitute a
    /// different value.
    pub(crate) fn promote(
        &self,
        slot: &mut Option<AuthenticatedChannelCapability>,
        connector: &Arc<ConnectorIncarnation>,
        policy: CurrentPolicyAdmission,
    ) -> Result<SessionCapability, SessionPromotionError> {
        self.promote_with_logical(slot, connector, policy, None)
    }

    /// Promote an additional authenticated channel into an existing logical
    /// session.  The new channel receives its own channel reservation, but
    /// shares the established session validity owner directly.  In particular,
    /// this path does not mint a second `SessionValidity` and then join it
    /// after the fact, which would transiently charge and later release a
    /// duplicate logical reservation.
    pub(crate) fn promote_additional(
        &self,
        slot: &mut Option<AuthenticatedChannelCapability>,
        connector: &Arc<ConnectorIncarnation>,
        policy: CurrentPolicyAdmission,
        established: &SessionCapability,
    ) -> Result<SessionCapability, SessionPromotionError> {
        self.promote_with_logical(slot, connector, policy, Some(established))
    }

    fn promote_with_logical(
        &self,
        slot: &mut Option<AuthenticatedChannelCapability>,
        connector: &Arc<ConnectorIncarnation>,
        policy: CurrentPolicyAdmission,
        established: Option<&SessionCapability>,
    ) -> Result<SessionCapability, SessionPromotionError> {
        // Every free conjunct, decided against a borrow so that nothing is
        // consumed while an answer is still in doubt. The borrow ends with this
        // block — the value it yields carries no reference — which is what lets
        // the terminal arm below take the slot at all.
        let terminal = match slot.as_ref() {
            // No channel to promote. Spelled as `ChannelNotCurrent` because that
            // is what an absent channel means here: the entry holds no live
            // authenticated channel for this connector.
            None => Some(SessionPromotionError::ChannelNotCurrent),
            Some(authenticated_channel) => {
                if !authenticated_channel.belongs_to(connector) {
                    // The channel must have been promoted from the exact
                    // connector the caller is promoting for. Trusting the
                    // caller's connector alone would accept a capability from a
                    // superseded channel whenever the current one was supplied
                    // alongside it.
                    Some(SessionPromotionError::ChannelNotCurrent)
                } else if !policy.admits(authenticated_channel) {
                    // Policy is read from the canonical proof value rather than
                    // re-derived here, so the broker cannot disagree with the
                    // fence that produced it.
                    Some(SessionPromotionError::PolicyRefused)
                } else if !authenticated_channel.runtime().is_same(&self.runtime)
                    || !self.principal.runtime().is_same(&self.runtime)
                {
                    // One process, one runtime. A principal from a replaced
                    // runtime object cannot be combined with a channel from this
                    // one.
                    Some(SessionPromotionError::RuntimeMismatch)
                } else {
                    None
                }
            }
        };
        if let Some(error) = terminal {
            drop(slot.take());
            return Err(error);
        }

        if let Some(established) = established {
            if !established.runtime().is_same(&self.runtime)
                || !established
                    .local_principal()
                    .runtime()
                    .is_same(&self.runtime)
                || !established.validity_witness().is_live()
            {
                return Err(SessionPromotionError::ResourcesUnavailable);
            }
        }

        // The one fallible step that can refuse a channel which is in every
        // other respect promotable. Until it succeeds the slot still holds its
        // channel, so `?` here retries cleanly.
        let permit = SessionPermit::reserve(&self.resources, self.runtime.clone())
            .map_err(|_| SessionPromotionError::ResourcesUnavailable)?;
        let validity = match established {
            Some(established) => {
                if !established.validity.try_add_channel_owner() {
                    return Err(SessionPromotionError::ResourcesUnavailable);
                }
                Arc::clone(&established.validity)
            }
            None => SessionValidity::mint(&permit)
                .map_err(|_| SessionPromotionError::ResourcesUnavailable)?,
        };

        // Infallible from here: the move out of the slot *is* the commit.
        let authenticated_channel = slot
            .take()
            .expect("the slot held a channel through every check above and nothing released it");

        Ok(SessionCapability {
            authenticated_channel: Some(authenticated_channel),
            local_principal: Arc::clone(&self.principal),
            _permit: permit,
            connector: Arc::clone(connector),
            validity,
        })
    }
}

#[cfg(test)]
pub(crate) fn session_for_test(runtime: RuntimeIncarnation) -> SessionCapability {
    session_in_scope_for_test(runtime, test_resource_scope())
}

/// One session whose scope funds the baseline **plus** `extra`.
///
/// [`session_for_test`] is this with nothing extra, and is what nearly every
/// control wants. This exists for the controls that must fund something the
/// baseline deliberately does not — a control that retains an admitted JSON
/// frame needs `ParsingOrCpuWork`, which no session record and no mailbox item
/// charges, so the baseline grants none of it.
///
/// Naming the extra term is the alternative to widening the baseline. Widening
/// it would hand every other control in the tree capacity it was written
/// without, and a pressure control that passes because of unrelated headroom is
/// the failure mode this whole fixture family is arranged to avoid. `extra` is a
/// bare claim: the reservation record the provider keeps for it is added here,
/// so a caller states what it retains and not what the accounting costs.
#[cfg(test)]
pub(crate) fn session_funding_for_test(
    runtime: RuntimeIncarnation,
    extra: ResourceClaim,
) -> SessionCapability {
    let extra = crate::resource::FiniteResourceProvider::reservation_charge_for_test(extra)
        .expect("the extra retention plus its provider record is representable");
    let grant = fixture_grant(1)
        .checked_add(fixture_stream_retention_claim())
        .and_then(|grant| grant.checked_add(extra))
        .expect("the baseline grant and one control's extra retention compose");
    session_in_scope_for_test(runtime, scope_for_grant(grant))
}

/// [`session_funding_for_test`], plus a handle on the provider behind it.
///
/// For the controls whose subject *is* the ledger — where the question is not
/// "did this succeed" but "was the claim still out at this exact moment". Every
/// other fixture deliberately hides the provider, because a control that can
/// read the ledger can also assert on a number that happens to be right for the
/// wrong reason. This one exists for the cases where the timing of a release is
/// the property under test and nothing else can see it.
#[cfg(test)]
pub(crate) fn session_and_provider_for_test(
    runtime: RuntimeIncarnation,
    extra: ResourceClaim,
) -> (SessionCapability, crate::resource::FiniteResourceProvider) {
    use crate::resource::{FiniteResourceProvider, ProcessResourceRoot, ResourceProviderPort};

    let extra = FiniteResourceProvider::reservation_charge_for_test(extra)
        .expect("the extra retention plus its provider record is representable");
    let grant = fixture_grant(1)
        .checked_add(fixture_stream_retention_claim())
        .and_then(|grant| grant.checked_add(extra))
        .expect("the baseline grant and one control's extra retention compose");
    let provider = FiniteResourceProvider::new(grant);
    let observed = provider.clone();
    let port = ResourceProviderPort::new(provider)
        .expect("fixture provider accounts for its own process scope");
    let scope = ProcessResourceRoot::isolated()
        .install_resource_provider(port)
        .expect("fresh isolated root has no installed provider")
        .issue_mesh_scope()
        .expect("installed provider issues one mesh scope");
    (session_in_scope_for_test(runtime, scope), observed)
}

#[cfg(test)]
fn session_in_scope_for_test(
    runtime: RuntimeIncarnation,
    scope: MeshConnectorResourceScope,
) -> SessionCapability {
    let authenticated_channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
    let connector = Arc::clone(authenticated_channel.record().connector());
    let local_principal = Arc::new(LocalPrincipalCapability::for_test(runtime.clone()));
    let permit = SessionPermit::reserve(&scope, runtime)
        .expect("fixture provider admits one session reservation");
    let validity = SessionValidity::mint(&permit)
        .expect("fixture provider admits one session validity allocation");

    SessionCapability {
        authenticated_channel: Some(authenticated_channel),
        local_principal,
        _permit: permit,
        connector,
        validity,
    }
}

/// What the finite provider records for one scope, over and above whatever the
/// scope is granted.
///
/// Taken from the provider rather than restated, so a fixture cannot come to
/// disagree with the accounting it is paying for. Kept as a named local because
/// this is the scope half of the provider's bookkeeping; the reservation half
/// is [`session_reservation_charge_for_test`], and a grant that is short should
/// read as a missing term rather than as an unexplained number.
#[cfg(test)]
fn provider_bookkeeping_unit() -> ResourceClaim {
    crate::resource::FiniteResourceProvider::scope_record_charge_for_test()
}

/// The exact provider reservation for the owned correlation String of one
/// promoted channel, including that lease's bookkeeping record.
fn session_correlation_reservation_charge(correlation: &str) -> ResourceClaim {
    let correlation = correlation.to_owned();
    crate::resource::FiniteResourceProvider::reservation_planning_charge(
        crate::runtime::peer_session::PromotedSession::channel_correlation_claim(&correlation)
            .expect("channel correlation claim is representable"),
    )
    .expect("channel correlation planning charge is representable")
}

#[cfg(test)]
pub(crate) fn session_correlation_reservation_charge_for_test(correlation: &str) -> ResourceClaim {
    session_correlation_reservation_charge(correlation)
}

/// The individual provider reservations for one promoted channel and its
/// retained signaling custody. The returned entries deliberately remain
/// separate: every correlation or dedup map-node lease carries its own
/// provider bookkeeping record, and summing bare claims before applying that
/// charge would underfund the fixture.
#[cfg(test)]
pub(crate) fn session_channel_retained_reservation_charges_for_test(
    correlation: &str,
    dedup_tokens: usize,
) -> Vec<ResourceClaim> {
    let mut charges = Vec::with_capacity(
        dedup_tokens
            .checked_add(3)
            .expect("test planning charge count fits usize"),
    );
    let planning = |claim| {
        crate::resource::FiniteResourceProvider::reservation_planning_charge(claim)
            .expect("retained channel planning charge is representable")
    };
    charges.push(planning(
        crate::runtime::peer_session::PromotedSession::channel_claim()
            .expect("channel flow-root claim is representable"),
    ));
    charges.push(planning(
        crate::runtime::peer_session::PromotedSession::channel_map_entry_claim()
            .expect("channel map-entry claim is representable"),
    ));
    charges.push(session_correlation_reservation_charge_for_test(correlation));
    let dedup_claim = crate::runtime::peer_session::PromotedDedupSet::entry_claim()
        .expect("dedup map-entry claim is representable");
    for _ in 0..dedup_tokens {
        charges.push(planning(dedup_claim));
    }
    charges
}

/// What a first promoted session costs the provider: five separate reservations
/// for its flow root, logical record, leased-map entry, validity lineage, and
/// owned channel correlation.
///
/// Each call to `reservation_planning_charge` includes the provider bookkeeping
/// record for that one lease; combining the bare claims first would undercount.
fn session_reservation_charge_for_correlation(correlation: &str) -> ResourceClaim {
    let flow_root = crate::resource::FiniteResourceProvider::reservation_planning_charge(
        crate::runtime::peer_session::PromotedSession::channel_claim()
            .expect("the channel flow-root claim is `size_of` arithmetic and cannot overflow"),
    )
    .expect("the flow-root claim plus its provider record is representable");
    let logical = crate::resource::FiniteResourceProvider::reservation_planning_charge(
        crate::runtime::peer_session::PromotedSession::logical_claim()
            .expect("the logical session claim is `size_of` arithmetic and cannot overflow"),
    )
    .expect("the logical claim plus its provider record is representable");
    let map_entry = crate::resource::FiniteResourceProvider::reservation_planning_charge(
        crate::runtime::peer_session::PromotedSession::channel_map_entry_claim()
            .expect("the channel map-entry claim is `size_of` arithmetic and cannot overflow"),
    )
    .expect("the map-entry claim plus its provider record is representable");
    let validity = session_validity_reservation_charge_for_test();
    let correlation = session_correlation_reservation_charge(correlation);
    flow_root
        .checked_add(logical)
        .and_then(|claim| claim.checked_add(map_entry))
        .and_then(|claim| claim.checked_add(validity))
        .and_then(|claim| claim.checked_add(correlation))
        .expect("the five first-session reservations compose")
}

#[cfg(test)]
pub(crate) fn session_reservation_charge_for_test() -> ResourceClaim {
    session_reservation_charge_for_correlation("aaaaaaaaaaaaa")
}

fn session_validity_reservation_charge_for_test() -> ResourceClaim {
    crate::resource::FiniteResourceProvider::reservation_planning_charge(
        SessionValidity::claim().expect("the validity record claim is fixed-size arithmetic"),
    )
    .expect("one validity claim plus the provider's reservation record is representable")
}

/// The exact reservation one promoted session takes for a supplied channel
/// correlation. Production minting uses an eight-byte random value encoded as
/// 13 base32 characters; accepting the actual string lets an external fixture
/// derive the same owned allocation instead of guessing its capacity.
///
/// This is the one public planning entry point. The reservation charge, rather
/// than the bare claim, includes the provider record held for that lease, so a
/// fixture cannot silently substitute a synthetic workload or underfund the
/// promotion by omitting that record.
pub fn session_reservation_planning_claim_for_correlation(correlation: &str) -> ResourceClaim {
    session_reservation_charge_for_correlation(correlation)
}

/// What the fixture's own scaffolding costs, before a single session.
///
/// Two things are charged that are not session capacity: the two provider
/// scopes — the process scope `ResourceProviderPort::new` creates and the Mesh
/// scope `issue_mesh_scope` creates — and the reservation the connector cleanup
/// executor holds for as long as it lives, which carries the provider's record
/// on top of the infrastructure claim itself.
///
/// A grant that names only the session claim's own dimension is refused at
/// provider construction, in the `OpaqueDependencyResidual` dimension, before
/// any control can express what it meant to test — which is why every control
/// here adds this scaffolding rather than granting session capacity alone.
///
/// Every term is derived rather than written out. The executor's claim is the
/// connector's to choose and the records are the provider's; restating either
/// would mean a change on that side turned into a fixture that quietly stopped
/// admitting the thing under test rather than one that fails loudly.
#[cfg(test)]
fn fixture_scaffolding_claim() -> ResourceClaim {
    let scopes = provider_bookkeeping_unit()
        .checked_scale(2)
        .expect("two scope records are representable");
    crate::resource::FiniteResourceProvider::reservation_charge_for_test(
        crate::runtime::attempt::cleanup_executor_infrastructure_claim()
            .expect("the cleanup executor infrastructure claim is representable"),
    )
    .expect("the cleanup executor reservation charge is representable")
    .checked_add(scopes)
    .expect("the fixture scaffolding claim is representable")
}

/// The scaffolding above plus room for exactly `sessions` first promotions.
#[cfg(test)]
fn fixture_grant(sessions: u64) -> ResourceClaim {
    let sessions = session_reservation_charge_for_test()
        .checked_scale(sessions)
        .expect("the fixture session capacity is representable");
    fixture_scaffolding_claim()
        .checked_add(sessions)
        .expect("the fixture grant is representable")
}

/// The largest single stream payload this module's baseline scope funds
/// retained, and how many of them it funds at once.
///
/// Owner-stated numbers, not a figure borrowed from a wire limit. They size a
/// grant: nothing here is checked against a payload on its way in, so a fixture
/// that funds too little sees a refusal, never a truncation.
///
/// Two items, and both have a named holder: one payload queued in a mailbox,
/// and one further payload's claim taken while the first is still queued. That
/// is exactly the shape
/// `rpc::session_ownership_tests::stream_pressure_refuses_without_queueing`
/// exercises, and the count is what makes it discriminating — funding one would
/// refuse its oversized push for want of a slot rather than for its size, which
/// is the same vacuity as funding none. More would be capacity nothing here
/// holds. The payload figure is deliberately far below the oversized push that
/// control makes, for the same reason.
#[cfg(test)]
const FIXTURE_STREAM_PAYLOAD_BYTES: usize = 8 * 1024;
#[cfg(test)]
const FIXTURE_STREAM_ITEMS: u64 = 2;

/// Room for what a promoted session later retains, over and above its record.
///
/// A session record and the work that session goes on to retain are different
/// quantities, and this is the second one.
/// [`PromotedSession::promotion_claim`](crate::runtime::peer_session::PromotedSession::promotion_claim)
/// funds neither queue content nor queue nodes on purpose: at promotion the
/// session's queue is empty and holds no node, and everything it later retains
/// is funded at the moment it is retained, through
/// [`SessionCapability::reserve_retained`]. Pre-paying retention into the record
/// would restore the fixed ceiling that design exists to remove, so the fixture
/// leaves room for retention that no record was ever charged for instead.
///
/// The claim is taken from the gateway in the same two calls
/// `RpcStreamInbox::push` makes — one payload's retention plus one mailbox node
/// — rather than restated here. A fixture that writes out its own formula is
/// exactly how a grant denominated in records came to meet a claim denominated
/// in bytes, and be short in a dimension no term in it ever named.
///
/// Each of the two is charged as its **own** reservation, and their sum is not
/// charged once. `push` takes two independent
/// [`SessionCapability::reserve_retained`] calls and therefore holds two leases,
/// for which the provider keeps two records. Charging the combined claim would
/// budget one record per item and leave the second paid for out of whatever
/// slack some unrelated term happened to leave — which is the same silent
/// underfunding this whole term exists to close.
#[cfg(test)]
fn fixture_stream_retention_claim() -> ResourceClaim {
    use crate::application_gateway::GatewayMailbox;
    use crate::resource::FiniteResourceProvider;

    let payload = FiniteResourceProvider::reservation_charge_for_test(
        GatewayMailbox::<serde_json::Value>::retention_claim(
            FIXTURE_STREAM_PAYLOAD_BYTES,
            FIXTURE_STREAM_PAYLOAD_BYTES,
            1,
        )
        .expect("one retained stream payload claim is representable"),
    )
    .expect("the retained payload claim plus its provider record is representable");
    let node = FiniteResourceProvider::reservation_charge_for_test(
        GatewayMailbox::<serde_json::Value>::node_claim()
            .expect("the mailbox node claim is `size_of` arithmetic and cannot overflow"),
    )
    .expect("the mailbox node claim plus its provider record is representable");

    payload
        .checked_add(node)
        .expect("one retained item is its payload's reservation plus its node's")
        .checked_scale(FIXTURE_STREAM_ITEMS)
        .expect("the fixture retention capacity is representable")
}

/// The baseline scope every control in this module — and `rpc`'s session
/// controls — draws on.
///
/// Two named terms rather than one, because they fund different things: room to
/// promote sessions, and room for what a promoted session retains afterwards.
///
/// The retention term is added here rather than inside [`fixture_grant`] on
/// purpose. Retention is not a property of a session record, so scaling it by
/// the session count would be the pre-payment
/// [`fixture_stream_retention_claim`] exists to avoid; and the exactness
/// controls below grant `fixture_grant(1)` and depend on it admitting exactly
/// one session, which slack in the dimensions retention shares with a record
/// would quietly undo.
#[cfg(test)]
fn test_resource_scope() -> MeshConnectorResourceScope {
    scope_for_grant(
        fixture_grant(64)
            .checked_add(fixture_stream_retention_claim())
            .expect("the fixture session and retention grants compose"),
    )
}

/// Stand one isolated provider up over `grant` and issue its Mesh scope.
///
/// The whole chain, so a control that wants a different capacity says so with a
/// grant and nothing else moves between it and the baseline.
#[cfg(test)]
fn scope_for_grant(grant: ResourceClaim) -> MeshConnectorResourceScope {
    use crate::resource::{FiniteResourceProvider, ProcessResourceRoot, ResourceProviderPort};

    let provider = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("fixture provider accounts for its own process scope");
    ProcessResourceRoot::isolated()
        .install_resource_provider(provider)
        .expect("fresh isolated root has no installed provider")
        .issue_mesh_scope()
        .expect("installed provider issues one mesh scope")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker_for_test(runtime: RuntimeIncarnation) -> SessionBroker {
        SessionBroker::new(runtime, test_resource_scope())
    }

    #[test]
    fn v4_arc05_promotion_binds_channel_principal_permit_and_connector() {
        // Positive control: a promotion that satisfies every conjunct produces a
        // capability bound to the exact channel, connector, and runtime it was
        // promoted from.
        let runtime = crate::runtime::runtime_for_test();
        let broker = broker_for_test(runtime.clone());
        let channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let connector = Arc::clone(channel.record().connector());

        let mut slot = Some(channel);
        let session = broker
            .promote(
                &mut slot,
                &connector,
                CurrentPolicyAdmission::admitted_for_test(),
            )
            .expect("every promotion conjunct holds");

        assert!(
            slot.is_none(),
            "a committed promotion moves the channel out of the slot"
        );
        assert!(session.belongs_to(&connector));
        assert!(session.runtime().is_same(&runtime));
        assert!(session.local_principal().runtime().is_same(&runtime));
        assert!(session.authenticated_for("fixture-mesh", "fixture-device-remote"));
    }

    #[test]
    fn v4_arc05_validity_allocation_stays_funded_until_the_last_witness_drops() {
        use crate::resource::{FiniteResourceProvider, ProcessResourceRoot, ResourceProviderPort};

        let grant = fixture_grant(1);
        let provider = FiniteResourceProvider::new(grant);
        let port =
            ResourceProviderPort::new(provider.clone()).expect("the grant funds the process scope");
        let scope = ProcessResourceRoot::isolated()
            .install_resource_provider(port)
            .expect("the isolated root accepts one provider")
            .issue_mesh_scope()
            .expect("the provider funds the mesh scope");
        let runtime = crate::runtime::runtime_for_test();
        let broker = SessionBroker::new(runtime.clone(), scope);
        let channel = crate::endpoint_auth::authenticated_for_test(runtime);
        let connector = Arc::clone(channel.record().connector());
        let baseline = provider.in_use();
        let mut slot = Some(channel);
        let session = broker
            .promote(
                &mut slot,
                &connector,
                CurrentPolicyAdmission::admitted_for_test(),
            )
            .expect("the exact session and validity reservations are available");
        let witness = session.validity_witness();

        drop(session);
        assert!(
            !witness.is_live(),
            "session drop synchronously invalidates witnesses"
        );
        assert_eq!(
            provider.in_use(),
            baseline
                .checked_add(session_validity_reservation_charge_for_test())
                .expect("the baseline and validity reservation compose"),
            "the session reservation returns but the refcounted validity block remains funded",
        );
        drop(witness);
        assert_eq!(
            provider.in_use(),
            baseline,
            "the final witness drop releases the validity block and its provider record",
        );
    }

    #[test]
    fn v4_arc05_additional_promotion_shares_the_established_validity_owner() {
        let runtime = crate::runtime::runtime_for_test();
        let broker = broker_for_test(runtime.clone());

        let first = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let first_connector = Arc::clone(first.record().connector());
        let mut first_slot = Some(first);
        let established = broker
            .promote(
                &mut first_slot,
                &first_connector,
                CurrentPolicyAdmission::admitted_for_test(),
            )
            .expect("the first channel promotes");
        let established_witness = established.validity_witness();

        let additional = crate::endpoint_auth::authenticated_for_test(runtime);
        let additional_connector = Arc::clone(additional.record().connector());
        let mut additional_slot = Some(additional);
        let joined = broker
            .promote_additional(
                &mut additional_slot,
                &additional_connector,
                CurrentPolicyAdmission::admitted_for_test(),
                &established,
            )
            .expect("the additional channel reserves only channel capacity");

        assert!(
            established_witness.same_validity(&joined.validity_witness()),
            "additional promotion must share the established validity allocation"
        );
        drop(established);
        assert!(
            joined.validity_witness().is_live(),
            "dropping the first channel must not revoke the additional channel"
        );
    }

    #[test]
    fn v4_arc05_additional_promotion_rejects_stale_successor_without_mutation() {
        let runtime = crate::runtime::runtime_for_test();
        let broker = broker_for_test(runtime.clone());

        let established_channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let established_connector = Arc::clone(established_channel.record().connector());
        let established = broker
            .promote(
                &mut Some(established_channel),
                &established_connector,
                CurrentPolicyAdmission::admitted_for_test(),
            )
            .expect("the established session promotes");
        let stale_witness = established.validity_witness();
        established.validity.invalidate();
        assert!(
            !stale_witness.is_live(),
            "the predecessor lineage is revoked"
        );

        let successor = crate::endpoint_auth::authenticated_for_test(runtime);
        let successor_connector = Arc::clone(successor.record().connector());
        let mut slot = Some(successor);
        assert_eq!(
            broker
                .promote_additional(
                    &mut slot,
                    &successor_connector,
                    CurrentPolicyAdmission::admitted_for_test(),
                    &established,
                )
                .err(),
            Some(SessionPromotionError::ResourcesUnavailable)
        );
        assert!(
            slot.is_some(),
            "a stale established lineage cannot consume the successor channel"
        );
    }

    #[test]
    fn v4_arc05_promotion_refuses_a_channel_from_another_connector() {
        // Negative control for the replacement conjunct: the capability and the
        // connector are each individually genuine, and the promotion still
        // refuses, because they are not the same channel.
        let runtime = crate::runtime::runtime_for_test();
        let broker = broker_for_test(runtime.clone());
        let channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let replacement = crate::endpoint_auth::authenticated_for_test(runtime);
        let other_connector = Arc::clone(replacement.record().connector());

        let mut slot = Some(channel);
        assert_eq!(
            broker
                .promote(
                    &mut slot,
                    &other_connector,
                    CurrentPolicyAdmission::admitted_for_test()
                )
                .err(),
            Some(SessionPromotionError::ChannelNotCurrent)
        );
        assert!(
            slot.is_none(),
            "a terminal refusal consumes the channel: it can never promote here"
        );
    }

    #[test]
    fn v4_arc05_promotion_refuses_when_current_policy_does_not_admit() {
        // Negative control for the policy conjunct, with every other conjunct
        // held true — so the refusal is attributable to policy alone.
        let runtime = crate::runtime::runtime_for_test();
        let broker = broker_for_test(runtime.clone());
        let channel = crate::endpoint_auth::authenticated_for_test(runtime);
        let connector = Arc::clone(channel.record().connector());

        let mut slot = Some(channel);
        assert_eq!(
            broker
                .promote(
                    &mut slot,
                    &connector,
                    CurrentPolicyAdmission::refused_for_test()
                )
                .err(),
            Some(SessionPromotionError::PolicyRefused)
        );
        assert!(
            slot.is_none(),
            "a policy refusal is terminal, so the channel does not survive it"
        );
    }

    #[test]
    fn v4_arc05_promotion_refuses_a_channel_from_another_runtime() {
        // Negative control for the runtime conjunct: a channel authenticated
        // under a replaced runtime object cannot be promoted by this broker.
        let broker = broker_for_test(crate::runtime::runtime_for_test());
        let foreign = crate::runtime::runtime_for_test();
        let channel = crate::endpoint_auth::authenticated_for_test(foreign);
        let connector = Arc::clone(channel.record().connector());

        let mut slot = Some(channel);
        assert_eq!(
            broker
                .promote(
                    &mut slot,
                    &connector,
                    CurrentPolicyAdmission::admitted_for_test()
                )
                .err(),
            Some(SessionPromotionError::RuntimeMismatch)
        );
        assert!(
            slot.is_none(),
            "a runtime disagreement is terminal, so the channel does not survive it"
        );
    }

    /// Positive install premise for every control in this module.
    ///
    /// The fixture grant covers its own scaffolding — both provider scopes and
    /// the connector cleanup executor — so a provider stands up, issues a Mesh
    /// scope, and admits a promotion. Without this the whole module fails at
    /// `ResourceProviderPort::new` in the `OpaqueDependencyResidual` dimension,
    /// and every control reads as a broken conjunct rather than as a grant that
    /// never described the fixture it was paying for.
    ///
    /// The second half is what keeps that scaffolding honest. Every dimension
    /// the scaffolding names is already spoken for — the executor's own
    /// reservation covers its infrastructure claim, including the accounted
    /// memory a session claim is denominated in, and the bookkeeping is spent on
    /// the two scopes and that reservation. If a session could still be promoted
    /// out of the scaffolding alone, then `fixture_grant(1)` would really admit
    /// two, and the exhaustion control below would be measuring slack rather
    /// than its own stated capacity.
    #[test]
    fn v4_arc05_the_fixture_grant_pays_for_its_own_scaffolding_and_no_session() {
        let runtime = crate::runtime::runtime_for_test();

        let broker = SessionBroker::new(runtime.clone(), scope_for_grant(fixture_grant(1)));
        let channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let connector = Arc::clone(channel.record().connector());
        assert!(
            broker
                .promote(
                    &mut Some(channel),
                    &connector,
                    CurrentPolicyAdmission::admitted_for_test()
                )
                .is_ok(),
            "the scaffolding plus one session admits exactly that one session"
        );

        let bare = SessionBroker::new(
            runtime.clone(),
            scope_for_grant(fixture_scaffolding_claim()),
        );
        let channel = crate::endpoint_auth::authenticated_for_test(runtime);
        let connector = Arc::clone(channel.record().connector());
        let mut slot = Some(channel);
        assert_eq!(
            bare.promote(
                &mut slot,
                &connector,
                CurrentPolicyAdmission::admitted_for_test()
            )
            .err(),
            Some(SessionPromotionError::ResourcesUnavailable),
            "and the scaffolding on its own admits no session, so the capacity \
             in a fixture grant is the only thing that ever admits one"
        );
        assert!(
            slot.is_some(),
            "a capacity refusal is not terminal: the exact channel stays installed"
        );
    }

    #[test]
    fn v4_arc05_promotion_refuses_when_session_capacity_is_exhausted() {
        // Negative control for the resource conjunct. The grant is the fixture
        // scaffolding plus exactly one session, so the second promotion refuses
        // on capacity with every other conjunct still true — and the refusal is
        // a typed cause, not a silent unpromoted channel.
        //
        // The scaffolding is added rather than the session claim being used as
        // the whole grant: a grant naming only the session's own dimension
        // cannot construct a provider at all, so this control would have
        // panicked before reaching its own subject. The one session remains the
        // only session capacity, which is what keeps it discriminating.
        //
        // The grant is exact in every dimension a promotion touches, so the
        // second one exceeds it in both the session dimension and the
        // bookkeeping its reservation is charged. That is the fixture paying
        // for exactly one session rather than a dimension left slack, and both
        // are released together by the drop below.
        let runtime = crate::runtime::runtime_for_test();
        let broker = SessionBroker::new(runtime.clone(), scope_for_grant(fixture_grant(1)));

        let first = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let first_connector = Arc::clone(first.record().connector());
        let held = broker
            .promote(
                &mut Some(first),
                &first_connector,
                CurrentPolicyAdmission::admitted_for_test(),
            )
            .expect("the first session fits the whole grant");

        let second = crate::endpoint_auth::authenticated_for_test(runtime);
        let second_connector = Arc::clone(second.record().connector());
        let mut retryable = Some(second);
        assert_eq!(
            broker
                .promote(
                    &mut retryable,
                    &second_connector,
                    CurrentPolicyAdmission::admitted_for_test()
                )
                .err(),
            Some(SessionPromotionError::ResourcesUnavailable)
        );
        assert!(
            retryable.is_some(),
            "capacity is the one refusal that leaves the channel installed — the \
             peer proved this channel and a shortfall it had no part in must not \
             cost it that proof"
        );

        // Non-vacuity, and the retry contract in one step: the capacity is
        // genuinely released with the session, and what promotes afterwards is
        // the *exact* channel the shortfall refused — not a freshly minted one.
        // A broker that destroyed the channel on `ResourcesUnavailable` could
        // not reach this line at all, and one that never admits twice would fail
        // it.
        drop(held);
        assert!(broker
            .promote(
                &mut retryable,
                &second_connector,
                CurrentPolicyAdmission::admitted_for_test()
            )
            .is_ok());
        assert!(
            retryable.is_none(),
            "and the successful retry is the commit that finally moves it"
        );
    }

    #[test]
    fn v4_arc05_a_promoted_session_names_one_exact_remote_device() {
        let runtime = crate::runtime::runtime_for_test();
        let session = session_for_test(runtime);

        assert_eq!(session.remote_device_id(), "fixture-device-remote");
        assert!(!session.authenticated_for("fixture-mesh", "other-device"));
    }
}
