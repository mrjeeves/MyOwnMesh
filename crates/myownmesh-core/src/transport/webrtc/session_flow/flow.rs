//! One open flow: what it binds, what may still reach it, and what its close
//! leaves behind.
//!
//! The gate is the reason this is a module rather than a struct with public
//! fields. A flow outlives its session's currentness — the holder may not have
//! dropped it yet — so possession is not permission, and every route to the
//! port runs through a check against the connector incarnation the flow was
//! actually opened on. The weak handle beside it exists so a pump can reach
//! that accounting without extending the lifetime the close is supposed to end.

use super::*;

/// The native half a closed flow leaves behind, and how it gets finished.
///
/// Handed back by [`SessionRealtimeFlows::close`] rather than retired there:
/// close runs under the fence, which is a sync mutex and cannot await, and both
/// forms of retirement are async. The caller finishes outside it.
///
/// The two directions differ because their ownership does, not because of a
/// convention. An outbound flow's track was moved into its pump at attach, so
/// nothing here can hand it back — only a receipt for the retirement the pump
/// performs on its own. An inbound flow's transceiver is owned by the
/// connector's track table, so what comes back is the token that names it.
///
/// `None` is ordinary, not an error: a flow closed before negotiation reached
/// the native layer has nothing outstanding.
// Each variant is an owned terminal handoff with its own funded custody. A
// Box here would change the close/drop ownership boundary rather than merely
// improve layout.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RealtimeFlowRemains {
    /// The retirement owner for a transceiver still to be stopped.
    ///
    /// It is an owner rather than a bare token because the two ways a flow ends
    /// are not the same. An explicit close takes the submission out and awaits
    /// the receipt through the connector worker, which is what lets a daemon
    /// acknowledge truthfully. An implicit end — revocation, replacement,
    /// shutdown, the session simply going — never calls anything, so the
    /// submission has to be the drop itself. A token whose retirement someone
    /// else already claimed is a no-op wherever it arrives, which is what makes
    /// the two safe to race.
    Inbound(RealtimeInboundRetirement),
    /// A receipt for the outbound pump's own retirement.
    ///
    /// The close that produced it dropped the flow's queue, which is what wakes
    /// the pump; the pump then removes its track and completes this. Awaiting it
    /// only makes the caller's acknowledgement truthful — the retirement happens
    /// whether anyone waits or not, and that is why an implicit session drop
    /// needs no hook.
    Outbound(RealtimeNativeRetired),
    None,
}

impl Default for RealtimeFlowRemains {
    fn default() -> Self {
        Self::None
    }
}

/// One flow's end-of-life wake.
///
/// Held by the flow and watched by its inbound pump. `Drop` is the whole signal,
/// so an explicit close and an implicit session drop fire it identically — the
/// pump cannot tell those apart and must not have to.
///
/// It exists because a failed port upgrade is not enough on its own. The pump
/// spends its life parked in `read_rtp`, and a peer that has stopped sending
/// never returns from it; without this the flow would be closed and its reader
/// still parked, holding a native read lease, until the connection died.
///
/// `notify_one`, not `notify_waiters`. The wake almost always arrives while the
/// pump is inside `read_rtp` rather than at its watch point, and
/// `notify_waiters` drops a signal with no one currently waiting. `notify_one`
/// stores a permit, so the wake is still there when the pump looks. This is the
/// same reason [`SessionStreamReader`] hands its reconnect permit the same way.
///
/// The wake it holds is a [`LeasedWake`], so the block survives this flow
/// **funded**. A watcher outliving the close is the design rather than an edge
/// case, and a lease kept out here would have been released at the close while
/// that watcher still held the allocation.
pub(super) struct RealtimeFlowEnd(Arc<LeasedWake>);

impl RealtimeFlowEnd {
    /// Fund the wake, then allocate it. Refusal is ordinary and fails the open
    /// closed.
    fn mint(registry: &RealtimeFlowRegistry) -> FlowResult<Self> {
        LeasedWake::mint(registry).map(Self)
    }

    /// The watcher's half. Strong, because the watcher must still be able to
    /// observe the wake after the flow that sent it is gone — and it carries
    /// that block's own funding with it, so what the watcher holds stays paid
    /// for until the watcher itself lets go.
    pub(super) fn watch(&self) -> Arc<LeasedWake> {
        Arc::clone(&self.0)
    }

    pub(super) fn notify(&self) -> Arc<LeasedWake> {
        Arc::clone(&self.0)
    }
}

impl Drop for RealtimeFlowEnd {
    fn drop(&mut self) {
        self.0.notify().notify_one();
    }
}

/// A non-owning claim on one already-open flow's port.
///
/// The inbound pump's only route to the flow it feeds, and deliberately not a
/// [`RealtimeFlowPort`]: that is `Clone` and owns an `Arc<RealtimeFlowLifetime>`,
/// so a pump holding one would keep the registry's active-flow lease alive for
/// as long as the pump ran — which is past the close that was supposed to
/// release it.
///
/// It is equally deliberately not a second `open_inbound_flow_checked`. The flow
/// this feeds is already open and already holds exactly one active-flow lease;
/// taking a second for the same application flow halves the configured capacity
/// and lets the second acquisition refuse media on a flow whose open had already
/// succeeded. One application flow, one lease.
///
/// Upgrade per unit and hold across nothing. A failed upgrade *is* the close and
/// needs no other signal; the reservations taken from the upgraded port hold it
/// strongly for the in-progress unit only, which is the one window where a flow
/// must not vanish under work already accounted for.
#[derive(Clone)]
pub(in crate::transport::webrtc) struct RealtimeFlowPortHandle {
    lifetime: std::sync::Weak<RealtimeFlowLifetime>,
}

impl RealtimeFlowPortHandle {
    /// A weak claim on an open flow, from a strong one.
    ///
    /// For a caller that legitimately owns the port already and needs to lend
    /// the assembler a claim without lending it the lease.
    pub(in crate::transport::webrtc) fn of(port: &RealtimeFlowPort) -> Self {
        Self {
            lifetime: Arc::downgrade(&port.lifetime),
        }
    }

    /// The port, while its flow is still open.
    pub(in crate::transport::webrtc) fn port(&self) -> Option<RealtimeFlowPort> {
        Some(RealtimeFlowPort {
            lifetime: self.lifetime.upgrade()?,
        })
    }

    /// A handle onto no flow at all.
    ///
    /// Exactly what a pump is left holding once its flow has closed, so a
    /// control that uses one is exercising the closed case rather than a weaker
    /// fixture. It is built here because the weak reference inside stays
    /// private: a constructor taking an arbitrary `Weak` would let a caller aim
    /// a pump at a flow it never opened.
    #[cfg(test)]
    pub(super) fn detached() -> Self {
        Self {
            lifetime: std::sync::Weak::new(),
        }
    }
}

/// Everything one admitted inbound track needs to feed its flow.
///
/// Separate from [`RealtimeInboundBinding`], which stays a declarative record of
/// what was negotiated — comparable, printable, and free of runtime handles.
/// This is the live half, produced only by [`RealtimeInboundBindings::admit`].
pub(in crate::transport::webrtc) struct RealtimeInboundAttachment {
    pub(in crate::transport::webrtc) label: RealtimeFlowLabel,
    pub(in crate::transport::webrtc) policy: RealtimeUnitPolicy,
    pub(in crate::transport::webrtc) port: RealtimeFlowPortHandle,
    pub(in crate::transport::webrtc) end: Arc<LeasedWake>,
}

/// One real-time flow, bound to the session that opened it.
///
/// Holds the connector-local port (which owns admission, queueing and every
/// resource claim), the session-scoped label, and the exact connector
/// incarnation the session was promoted from. Dropping it returns the label
/// and releases the port, which removes the flow from the registry.
///
/// **Byte movement is not here.** Outbound units go to the connector's track
/// and inbound units arrive on the session's inbound queue, both through the
/// pump that already owns them; this type owns the *binding* — who may use the
/// flow, under which name, for how long. Putting the pump behind it would move
/// codec-shaped work back into the layer this cutover is taking it out of.
///
/// Four fields are reachable from the flow set that holds these and no further.
/// The set is what negotiates on a flow's behalf, records what its close will
/// leave, and drains its queue, so it reads them directly rather than through
/// accessors that would exist only to be called from one place. The other four
/// are the binding itself and stay private, because `is_current_for` and
/// [`Self::port_if_current`] are the only truthful ways to ask about them.
pub(crate) struct RealtimeFlow {
    pub(super) port: RealtimeFlowPort,
    label: RealtimeFlowLabel,
    pub(super) kind: RealtimeFlowKind,
    direction: RealtimeDirection,
    pub(super) queue: FlowQueue,
    pub(super) opaque_pending: Option<OpaqueFlowPending>,
    /// A Change which has been prepared but not yet committed by the
    /// authenticated control transaction.  It lives on the flow record rather
    /// than in a session-side map, so close/replacement cannot accidentally
    /// commit a successor with the same label.
    pub(super) opaque_pending_change: Option<OpaqueFlowPendingChange>,
    /// One owner-funded local application claim on an opaque record. Remote
    /// Open creates the record without this lease; a local application must
    /// claim that exact record before its handle can be minted.
    pub(super) opaque_application_claim: Option<crate::resource::ResourceLease>,
    /// Dropped with this flow, waking whatever was reading for it.
    pub(super) end: RealtimeFlowEnd,
    /// What this flow's close will leave for its caller to finish.
    ///
    /// Recorded as negotiation reaches the native layer — a retirement owner at
    /// `bind_inbound`, a completion lease at `attach_outbound` — and taken out
    /// by close. A flow that never got that far leaves `None`.
    ///
    /// A close is not the only thing that ends it. Both arms retire whatever
    /// they hold when this flow is simply dropped: the inbound retirement
    /// submits, and dropping the outbound receipt only stops anyone waiting for
    /// a retirement the pump performs regardless. A close therefore makes the
    /// end *awaitable*, not merely certain.
    pub(super) native: RealtimeFlowRemains,
    /// The incarnation the opening session was promoted from. Retained by
    /// value so the gate below compares against the connector this flow was
    /// actually opened on, never against whatever is current now — a
    /// replacement must fail the check, not silently satisfy it.
    incarnation: Arc<crate::connector::ConnectorIncarnation>,
}

/// Readiness state for one logical opaque Open/Accept transaction. The record
/// owns this state; the wake is borrowed from the flow's already-funded end
/// signal, so pending negotiation adds no allocation or parallel registry.
pub(crate) struct OpaqueFlowPending {
    pub(crate) coordinate: crate::protocol::ApplicationFlowCoordinate,
    pub(crate) mode: crate::realtime::OpaqueFlowMode,
    pub(crate) max_unit_bytes: usize,
    pub(crate) ready: bool,
}

/// The staged scalar state for one exact flow-record Change.  It contains no
/// label copy; its shared marker carries the operation's funding and is also
/// held by the caller token, so either owner may outlive the other safely.
pub(super) struct OpaqueFlowPendingChange {
    pub(super) previous: crate::protocol::ApplicationFlowCoordinate,
    pub(super) coordinate: crate::protocol::ApplicationFlowCoordinate,
    pub(super) opener_direction: crate::realtime::RealtimeFlowDirection,
    pub(super) mode: crate::realtime::OpaqueFlowMode,
    pub(super) max_unit_bytes: usize,
    pub(super) active: Arc<OpaqueChangeMarker>,
    pub(super) confirmed: bool,
}

/// A move-only citation of one prepared Change.  The weak record identity is
/// checked again at commit/rollback, preventing a label ABA from applying a
/// delayed control to a successor flow.
pub(crate) struct OpaqueFlowChange {
    pub(super) identity: RealtimeFlowIdentity,
    pub(super) previous: crate::protocol::ApplicationFlowCoordinate,
    pub(super) coordinate: crate::protocol::ApplicationFlowCoordinate,
    pub(super) opener_direction: crate::realtime::RealtimeFlowDirection,
    pub(super) mode: crate::realtime::OpaqueFlowMode,
    pub(super) max_unit_bytes: usize,
    pub(super) active: Arc<OpaqueChangeMarker>,
    pub(super) finished: bool,
}

impl Drop for OpaqueFlowChange {
    fn drop(&mut self) {
        if !self.finished {
            self.active.cancel();
        }
    }
}

impl RealtimeFlow {
    pub(crate) fn label(&self) -> &RealtimeFlowLabel {
        &self.label
    }

    pub(crate) fn encoding(&self) -> Option<&RealtimeEncoding> {
        match &self.kind {
            RealtimeFlowKind::Rtp(encoding) => Some(encoding),
            RealtimeFlowKind::Opaque { .. } => None,
        }
    }

    pub(crate) fn opaque_mode(&self) -> Option<crate::realtime::OpaqueFlowMode> {
        match &self.kind {
            RealtimeFlowKind::Rtp(_) => None,
            RealtimeFlowKind::Opaque { mode, .. } => Some(*mode),
        }
    }

    pub(crate) fn opaque_max_unit_bytes(&self) -> Option<usize> {
        match &self.kind {
            RealtimeFlowKind::Rtp(_) => None,
            RealtimeFlowKind::Opaque { max_unit_bytes, .. } => Some(*max_unit_bytes),
        }
    }

    pub(crate) fn opaque_coordinate(&self) -> Option<crate::protocol::ApplicationFlowCoordinate> {
        match &self.kind {
            RealtimeFlowKind::Rtp(_) => None,
            RealtimeFlowKind::Opaque { coordinate, .. } => Some(*coordinate),
        }
    }

    pub(crate) fn opaque_opener_direction(&self) -> Option<crate::realtime::RealtimeFlowDirection> {
        match &self.kind {
            RealtimeFlowKind::Rtp(_) => None,
            RealtimeFlowKind::Opaque {
                opener_direction, ..
            } => Some(*opener_direction),
        }
    }

    pub(crate) fn opaque_is_ready(&self) -> Option<bool> {
        self.opaque_mode()
            .map(|_| match self.opaque_pending.as_ref() {
                Some(pending) => pending.ready,
                None => true,
            })
    }

    pub(crate) fn direction(&self) -> RealtimeDirection {
        self.direction
    }

    /// The connector-local port, for the pump that moves this flow's bytes.
    ///
    /// Reached only through [`Self::port_if_current`], never directly, so the
    /// gate cannot be skipped by a caller that happens to hold the flow.
    fn port(&self) -> &RealtimeFlowPort {
        &self.port
    }

    /// A weak claim on this flow's port, for the pump that feeds it.
    ///
    /// The gate is not skipped by handing this out. What the holder gets is the
    /// ability to reach *this* flow's accounting for as long as this flow is
    /// open, and nothing at all afterwards — which is exactly the authority an
    /// inbound pump needs and no more. Currentness is still proved before the
    /// binding that yields one is ever recorded.
    pub(super) fn port_handle(&self) -> RealtimeFlowPortHandle {
        RealtimeFlowPortHandle::of(&self.port)
    }

    /// Whether `session` may still use this flow, given the connector's own
    /// currently-live incarnation.
    ///
    /// Three facts, and all three are needed. `live` proves the connector has
    /// not retired — it is `None` from the worker once it has. `Arc::ptr_eq`
    /// against the retained incarnation proves the live connector is the one
    /// this flow was opened on, not a replacement that took its place. And the
    /// session answers that it was promoted from that same incarnation.
    ///
    /// **Liveness cannot come from `session.is_current_on` and must not be
    /// asked of it.** That predicate is identity-only: `ConnectorIncarnation`
    /// deliberately carries no liveness, because the transport is the single
    /// authoritative source and a second flag could disagree with it. Asked
    /// against this flow's *retained* `Arc` it would answer true forever,
    /// including against a dead connector — so the retained value can only
    /// ever be one half of an identity comparison, never the source of the
    /// currentness answer.
    ///
    /// A replaced or retired connector fails here and is never re-bound: the
    /// application promotes a new session and opens new flows.
    pub(crate) fn is_current_for(
        &self,
        session: &impl RealtimeSessionBinding,
        live: &Arc<crate::connector::ConnectorIncarnation>,
    ) -> bool {
        Arc::ptr_eq(live, &self.incarnation) && session.is_current_on(&self.incarnation)
    }

    /// The port, but only while the session that opened this flow is still
    /// current on the connector it was opened on.
    ///
    /// This is the send- and receive-time gate. It is deliberately the *only*
    /// way to reach the port: a flow outlives its session's currentness — the
    /// holder may not have dropped it yet — so possession of a `RealtimeFlow`
    /// cannot be allowed to mean permission to use one.
    /// Visible to the flow set that owns these and no wider, because it hands
    /// back a connector-local port. The binding checks above are `pub(crate)`;
    /// the port itself never leaves this layer.
    ///
    /// `live` is taken as the `Option` the worker actually returns, not as an
    /// unwrapped reference, so a caller cannot reach this gate holding a value
    /// it obtained some other way. A retired connector yields `None` and is
    /// refused here; that is the whole reason the argument is threaded in
    /// rather than read off `self`.
    ///
    /// **A borrow, and never a generic lend.** A `with_current_port(|port| …)`
    /// shape would let the closure return the port itself — a port is `Clone` —
    /// and walk a live one out past the very fence this imposes, authorizing
    /// everything after that point by a check that had already stopped being
    /// true. Every route to the port has a return type that says exactly what
    /// may escape.
    pub(super) fn port_if_current(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
    ) -> FlowResult<&RealtimeFlowPort> {
        let Some(live) = live else {
            return Err(RealtimeFlowError::SessionNotCurrent);
        };
        if !self.is_current_for(session, live) {
            return Err(RealtimeFlowError::SessionNotCurrent);
        }
        Ok(self.port())
    }
}

/// Open one flow for `session` on `incarnation`.
///
/// The caller resolves a Device selector to a session through the registry
/// fence and lends the borrow in; nothing here retains it, which is what keeps
/// the session non-`Clone` promise intact — the flow holds a binding it
/// re-checks, never a capability it could re-present.
///
/// Refuses before claiming anything if the session is not current on this
/// incarnation, so a replaced session cannot consume a label or a flow slot on
/// its way to being refused.
///
/// **The name was checked free by the caller, against the flow map, under the
/// same borrow that will insert into it.** There is no second table of held
/// names here and no `release` on the refusal paths below: the label is a leased
/// record, so a refused open drops the only copy that ever existed and the bytes
/// go back with it. A name is in use exactly when a flow of this session is
/// keyed by it, which is one fact in one place rather than two that agree until
/// they do not.
fn open_flow(
    session: &impl RealtimeSessionBinding,
    live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
    registry: &Arc<RealtimeFlowRegistry>,
    direction: RealtimeDirection,
    name: RealtimeFlowName,
    kind: RealtimeFlowKind,
    opaque_application_claim: Option<crate::resource::ResourceLease>,
) -> FlowResult<(RealtimeFlow, crate::resource::ResourceLease)> {
    // Same acquisition rule as the send-time gate: `live` is the worker's own
    // `Option`, which is `None` once the connector has retired. A flow can
    // therefore only ever be opened on a connector that is alive at the moment
    // of opening, and the value retained below is that exact incarnation — so
    // the later gate has something true to compare against.
    let Some(incarnation) = live else {
        return Err(RealtimeFlowError::SessionNotCurrent);
    };
    if !session.is_current_on(incarnation) {
        return Err(RealtimeFlowError::SessionNotCurrent);
    }
    // One allocator, and it is not this one. The application names the label;
    // this side mints exactly that value or refuses. There is no lowest-free
    // path in production: a second allocator over one space would collide on a
    // live flow rather than fail at open.
    //
    // A label is a leased name, not a permission. Holding one proves only that
    // this session paid for these bytes; every use of the flow behind it is
    // re-gated by `port_if_current`, so nothing downstream may treat possession
    // of a label as authority to move anything.
    let label = RealtimeFlowLabel::mint(name, registry)?;
    // The checked forms deliberately, not the `Option` twins: those are
    // `#[cfg(test)]` or discard the reason, and a refused open is worth
    // knowing the cause of even where this layer answers one variant for all
    // of them.
    let port = match direction {
        RealtimeDirection::Outbound => registry.open_outbound_flow_checked(),
        RealtimeDirection::Inbound => registry.open_inbound_flow_checked(),
    };
    // The connector refused: its own ceiling, or resources. Returning here
    // drops `label`, which is the whole of handing the name back — there is no
    // table to remove it from, so a refused open cannot burn a name. The reason
    // stays inside the connector, which already recorded it through its own drop
    // accounting; surfacing it here would put a connector-local vocabulary in
    // this layer's public error.
    let port = port.map_err(realtime_drop_refusal)?;
    // The node in the session's flow map that this record is about to occupy.
    // Last of the three claims an open takes, and released the same way as the
    // other two if it is refused: the label goes back here, and the port goes
    // back by being dropped.
    //
    // Handed out beside the flow rather than stored inside it, because the map
    // is what will hold the node and the map is what must be given the lease
    // that funded it. A copy kept here as well would be a second charge for one
    // allocation.
    let map_entry = registry
        .acquire_map_entry::<RealtimeFlowLabel, RealtimeFlow>()
        .map_err(realtime_drop_refusal)?;
    // The blocks this flow's own constructors are about to allocate: one wake
    // in either direction, and outbound additionally a queue and the wake that
    // drives its pump. Each is funded before it exists and each carries its own
    // lease, because the three do not share a lifetime — see
    // [`RealtimeFlowRegistry::flow_root_claim`].
    //
    // A refusal here unwinds by returning, exactly as the two acquisitions above
    // do. Nothing needs undoing by hand: the label, the port and any block
    // minted before the refusal are all dropped with this frame, and each of
    // those drops is what releases its own funding.
    let end = RealtimeFlowEnd::mint(registry)?;
    let queue = match &kind {
        RealtimeFlowKind::Opaque { .. } if direction == RealtimeDirection::Outbound => {
            FlowQueue::OpaqueOutbound(RealtimeFlowQueue::mint(registry)?)
        }
        RealtimeFlowKind::Opaque { .. } => FlowQueue::Inbound,
        RealtimeFlowKind::Rtp(_) if direction == RealtimeDirection::Outbound => {
            FlowQueue::Outbound(RealtimeFlowQueue::mint(registry)?)
        }
        RealtimeFlowKind::Rtp(_) => FlowQueue::Inbound,
    };
    let opaque_pending = match &kind {
        RealtimeFlowKind::Opaque {
            coordinate,
            mode,
            max_unit_bytes,
            opener_direction: _,
            ..
        } => Some(OpaqueFlowPending {
            coordinate: *coordinate,
            mode: *mode,
            max_unit_bytes: *max_unit_bytes,
            ready: false,
        }),
        RealtimeFlowKind::Rtp(_) => None,
    };
    Ok((
        RealtimeFlow {
            port,
            label,
            kind,
            direction,
            queue,
            opaque_pending,
            opaque_pending_change: None,
            opaque_application_claim,
            end,
            native: RealtimeFlowRemains::None,
            incarnation: Arc::clone(incarnation),
        },
        map_entry,
    ))
}

pub(super) fn open_session_flow(
    session: &impl RealtimeSessionBinding,
    live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
    registry: &Arc<RealtimeFlowRegistry>,
    spec: RealtimeFlowSpec,
) -> FlowResult<(RealtimeFlow, crate::resource::ResourceLease)> {
    open_flow(
        session,
        live,
        registry,
        spec.direction,
        spec.name,
        RealtimeFlowKind::Rtp(spec.encoding),
        None,
    )
}

pub(super) fn open_opaque_flow(
    session: &impl RealtimeSessionBinding,
    live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
    registry: &Arc<RealtimeFlowRegistry>,
    spec: OpaqueFlowSpec,
    coordinate: crate::protocol::ApplicationFlowCoordinate,
    application_claim: Option<crate::resource::ResourceLease>,
) -> FlowResult<(RealtimeFlow, crate::resource::ResourceLease)> {
    open_flow(
        session,
        live,
        registry,
        spec.direction,
        spec.name,
        RealtimeFlowKind::Opaque {
            mode: spec.mode,
            max_unit_bytes: spec.max_unit_bytes,
            coordinate,
            opener_direction: spec.opener_direction,
        },
        application_claim,
    )
}

/// The provider-specific kind of a logical flow.  Keeping this beside the
/// existing flow record means opaque and RTP flows share identity, labels,
/// leases, and close semantics without teaching the generic registry about
/// codecs or introducing a second map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RealtimeFlowKind {
    Rtp(RealtimeEncoding),
    Opaque {
        mode: crate::realtime::OpaqueFlowMode,
        max_unit_bytes: usize,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        opener_direction: crate::realtime::RealtimeFlowDirection,
    },
}

/// What an application asks for when opening a flow.
#[derive(Clone, Debug)]
pub(crate) struct RealtimeFlowSpec {
    pub(crate) direction: RealtimeDirection,
    pub(crate) encoding: RealtimeEncoding,
    /// The name the application chose. Required: this side never allocates one.
    ///
    /// Raw and unleased, because at this point nothing has agreed to keep it.
    /// The leased label is minted from it only once the session has accepted
    /// the name.
    pub(crate) name: RealtimeFlowName,
}

/// Provider-local view of the generic opaque-flow request. The name and
/// direction use the existing leased flow machinery; only the wire mode and
/// negotiated body ceiling differ. Provider-neutral callers use
/// [`crate::realtime::OpaqueFlowOpen`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpaqueFlowSpec {
    pub(crate) direction: RealtimeDirection,
    /// Direction in the opener's coordinate system. For a remote Open this
    /// differs from the local flow direction.
    pub(crate) opener_direction: crate::realtime::RealtimeFlowDirection,
    pub(crate) mode: crate::realtime::OpaqueFlowMode,
    pub(crate) max_unit_bytes: usize,
    pub(crate) name: RealtimeFlowName,
}
