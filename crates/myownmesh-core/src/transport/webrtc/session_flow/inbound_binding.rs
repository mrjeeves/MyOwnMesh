//! Which negotiated track may attach to which already-open inbound flow.
//!
//! The authority argument for the whole inbound path lives here. An entry
//! exists only because the local application opened a flow and this side then
//! minted a token and negotiated a transceiver against it, so the most a peer
//! can do is present a token this side created — and it can create none.
//!
//! Three types, in the order the negotiation reaches them: the declarative
//! record of what was agreed, the minted identity it was agreed against, and
//! the table that turns an arriving track into a destination.

use super::*;

/// What a negotiated inbound track has to be in order to attach to a flow.
///
/// Recorded by the connector when it negotiates a receive transceiver for a
/// flow the local application has *already* opened, and consulted when the
/// track actually arrives. Never built from anything the peer said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealtimeInboundBinding {
    label: RealtimeFlowLabel,
    encoding: RealtimeEncoding,
    framing: RealtimeFraming,
}

impl RealtimeInboundBinding {
    pub(crate) fn new(
        label: RealtimeFlowLabel,
        encoding: RealtimeEncoding,
        framing: RealtimeFraming,
    ) -> Self {
        Self {
            label,
            encoding,
            framing,
        }
    }

    /// The unit policy the application's profile chose for this family.
    ///
    /// There is deliberately no `label` accessor beside it. The destination is
    /// reached only through [`RealtimeInboundBindings::admit`], which hands back
    /// a [`RealtimeInboundAttachment`] carrying the label together with the
    /// handles on the flow that label names — so there is no way to learn where
    /// a track may go without having passed the admission that decided it may
    /// go anywhere.
    fn unit_policy(&self) -> RealtimeUnitPolicy {
        self.framing.unit_policy()
    }
}

/// Exact process-local identity for one negotiated inbound track.
///
/// **Minted by this side, before the transceiver that will carry the track
/// exists.** That ordering is the whole point: a binding is recorded against
/// the token first, and only then is a transceiver created against it, so any
/// track that can ever arrive under this token already had a binding when the
/// thing that would carry it was built. There is no window in which a track
/// arrives before its binding, and so no start-of-flow media to lose.
///
/// It is deliberately not the obvious key, the transceiver's MID.
/// A MID is *a string that appears in SDP* — keying the demux table on one
/// makes the key a value that also crosses the wire, so the peer would have a
/// hand in naming its own destination. A minted token cannot appear in an
/// answer at all, and the peer has no way to name one.
///
/// Identity is the allocation, the same construction
/// [`crate::connector::ConnectorIncarnation`] uses. It carries no state, is not
/// `Clone` by value, is not serializable, and has no public constructor, so it
/// grants nothing on its own — it only answers "is this the track we built for
/// that flow".
pub(crate) struct RealtimeTrackIdentity {
    /// The charge for this identity's own allocation, held **inside** it.
    ///
    /// The allocation is the identity, so it is named by everyone who can reach
    /// the track: the flow's binding, the retirement, a claim carried out of the
    /// table, the engine's phase-2 and phase-3 locals. Those outlive the table's
    /// record — a claim taken during a sweep is exactly a holder that survives
    /// `forget` — so the lease cannot live on the record. Put here, it releases
    /// when the last of them drops, which is the only moment the allocation is
    /// actually gone.
    _lease: crate::resource::ResourceLease,
}

impl RealtimeTrackIdentity {
    /// Mint one identity around the lease that funds it.
    ///
    /// The lease arrives already acquired, so the decision was made before the
    /// allocation existed. There is no path that mints one and then finds out it
    /// could not be paid for.
    pub(crate) fn mint(lease: crate::resource::ResourceLease) -> Arc<Self> {
        Arc::new(Self { _lease: lease })
    }

    /// One identity funded from a control's own provider fixture.
    ///
    /// Controls only, and it still acquires: a fixture that skipped the lease
    /// would be exercising a different constructor from the one production uses,
    /// and the retention this record exists to prove would be untested.
    #[cfg(test)]
    pub(crate) fn mint_for_test(
        scope: &crate::runtime::attempt::ConnectorWorkResourceScope,
    ) -> Arc<Self> {
        let lease = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                Self::mint_claim().expect("the identity claim is representable"),
            )
            .expect("the fixture grant funds this identity");
        Self::mint(lease)
    }

    /// Exactly what minting one costs.
    ///
    /// Derived here because `size_of::<Self>()` is this module's fact, the same
    /// reason [`RealtimeFlowLabel::mint_claim`] lives beside its record. Content
    /// bytes plus the `Arc` counter pair, and one residual for the block itself.
    pub(crate) fn mint_claim() -> std::result::Result<
        crate::resource::ResourceClaim,
        crate::resource::ResourceClaimArithmeticError,
    > {
        let counters = std::mem::size_of::<usize>().checked_mul(2).ok_or(
            crate::resource::ResourceClaimArithmeticError::Overflow {
                dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
            },
        )?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(counters)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
                dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
            })?;
        crate::resource::ResourceClaim::try_from_entries([
            (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
            (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }
}

/// Connector-owned demux from negotiated track identity to the flow it may
/// attach to.
///
/// **The label is not on this table because a peer sent it.** An entry exists
/// only because the local application opened an inbound flow and this side
/// then minted a token and negotiated a transceiver against it, so a track
/// resolving to no token on this table has nothing to attach to and is
/// dropped. That is the whole authority argument: a peer can influence *which*
/// of our flows a track lands on only to the extent of presenting a token we
/// already created, and it can create none.
pub(crate) struct RealtimeInboundBindings {
    /// A list rather than a map, deliberately. The obvious map key for an
    /// `Arc` identity is its address, and an address is exactly the thing that
    /// can be recycled once the allocation behind it is freed; holding the
    /// `Arc` strongly in the entry would prevent that, but then the key and
    /// the thing keeping it valid are two facts that have to stay in step.
    /// A linear scan compared by `Arc::ptr_eq` has no second fact at all.
    ///
    /// The scan is not a cost worth avoiding: it runs once per arriving track,
    /// never per packet, and the list is bounded by the session's label space.
    ///
    /// A [`crate::resource::LeasedQueue`] rather than a `Vec` because this
    /// table grows with what the session negotiates: a `Vec` would double its
    /// buffer on a push no single entry asked for, keep the spare after
    /// entries were released, and give no entry an allocation of its own to pay
    /// for. Here one binding is one funded node, and forgetting a binding
    /// releases exactly that.
    bound: SyncMutex<crate::resource::LeasedQueue<RealtimeInboundEntry>>,
}

/// One negotiated token and everything admitting its track needs.
pub(super) struct RealtimeInboundEntry {
    identity: Arc<RealtimeTrackIdentity>,
    binding: RealtimeInboundBinding,
    /// The already-open flow this token's track feeds, weakly.
    port: RealtimeFlowPortHandle,
    /// The wake that ends its pump when that flow goes, funded by the block it
    /// lives in rather than by this entry.
    end: Arc<LeasedWake>,
}

impl Default for RealtimeInboundBindings {
    fn default() -> Self {
        Self {
            bound: SyncMutex::new(crate::resource::LeasedQueue::new()),
        }
    }
}

impl RealtimeInboundBindings {
    /// Record what the connector will negotiate for one already-open inbound
    /// flow.
    ///
    /// Answers `false` if that token is already bound, rather than replacing:
    /// a second binding on one token would make attachment ambiguous, and
    /// silently taking the newer one would move a live flow's media onto a
    /// different flow.
    ///
    /// Refuses an outbound direction outright. Nothing outbound is ever
    /// attachable, so an outbound entry could only ever be a mistake that this
    /// table would then make look deliberate.
    ///
    /// `record` funds the node this entry will live in. It is acquired by the
    /// caller, which is the side holding the flow whose owner should pay, and
    /// it is released when the entry is forgotten or the table is dropped.
    pub(crate) fn bind(
        &self,
        identity: Arc<RealtimeTrackIdentity>,
        direction: RealtimeDirection,
        binding: RealtimeInboundBinding,
        port: RealtimeFlowPortHandle,
        end: Arc<LeasedWake>,
        record: crate::resource::ResourceLease,
    ) -> bool {
        if direction != RealtimeDirection::Inbound {
            return false;
        }
        let mut bound = self.bound.lock();
        if bound
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.identity, &identity))
        {
            // Refused, so nothing is retained: `record` is dropped here and its
            // funding goes straight back.
            return false;
        }
        bound.push(
            RealtimeInboundEntry {
                identity,
                binding,
                port,
                end,
            },
            record,
        );
        true
    }

    /// Forget every binding for one label, when its flow closes.
    ///
    /// Each forgotten entry is dropped where it is removed, so its node's
    /// funding is released at the moment the binding stops existing.
    pub(crate) fn release(&self, label: &RealtimeFlowLabel) {
        self.bound
            .lock()
            .retain(|entry| &entry.binding.label != label);
    }

    /// The single admission decision for a negotiated inbound track.
    ///
    /// Fail-closed in both halves. A token with no binding answers `None`,
    /// because this side never offered it. A token whose negotiated shape is
    /// not the shape we bound also answers `None` — a peer that answered with
    /// a different codec than the flow was opened for is not delivering that
    /// flow's media, and attaching it would feed a decoder configured for
    /// something else.
    ///
    /// MIME comparison is case-insensitive because SDP is; everything else is
    /// exact.
    ///
    /// What comes back is the live half — the destination label, the framing
    /// policy, and the two handles on the already-open flow. It notably does not
    /// include an active-flow lease, because the flow being attached to already
    /// holds the only one it is entitled to.
    pub(in crate::transport::webrtc) fn admit(
        &self,
        identity: &Arc<RealtimeTrackIdentity>,
        kind: WebRtcRtpKind,
        mime: &str,
        clock_rate: u32,
        channels: u16,
    ) -> Option<RealtimeInboundAttachment> {
        let mut bound = self.bound.lock();
        let entry = bound
            .iter()
            .find(|entry| Arc::ptr_eq(&entry.identity, identity))?;
        let expected = &entry.binding.encoding;
        (expected.kind() == kind
            && expected.clock_rate() == clock_rate
            && expected.channels() == channels
            && expected.mime().eq_ignore_ascii_case(mime))
        .then(|| RealtimeInboundAttachment {
            label: entry.binding.label.clone(),
            policy: entry.binding.unit_policy(),
            port: entry.port.clone(),
            end: Arc::clone(&entry.end),
        })
    }
}
