//! The peer's advertisement, as heard over one promoted session.
//!
//! Owned here so it cannot outlive the session that heard it. A replacement
//! answers `None` until its own peer advertises, which is the truthful answer:
//! nothing has been advertised over *this* session yet.

use crate::error::{Error, Result};
use crate::protocol::CapabilityAdvert;
use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};
use crate::runtime::session_broker::SessionCapability;

/// The one allocation a retained advertisement owns.
///
/// The boxed encoded buffer, whose length is its capacity. Nothing else: the
/// handle to it is inline in the session record and was paid for at promotion.
const RETAINED_ADVERT_ALLOCATIONS: u64 = 1;

/// The peer's advertisement, retained as canonical encoded bytes under a lease.
///
/// Retained **encoded** rather than as a decoded `CapabilityAdvert` for one
/// reason: a decoded advert is a tree of application-controlled `Vec`s and
/// `String`s whose heap this module cannot measure without walking a foreign
/// representation and guessing at its internals. Canonical bytes have exactly
/// one size, and it is the number this lease was taken for.
///
/// The peer controls the size, which is precisely why it must be funded. A
/// refused reservation retains nothing.
struct LeasedCapabilityAdvert {
    encoded: Box<[u8]>,
    /// Held for its `Drop`. The reservation lasts exactly as long as the bytes,
    /// and both end when the session does or when a replacement advertisement
    /// takes their place.
    _lease: ResourceLease,
}

/// The advert slot one promoted session owns.
///
/// Empty at promotion and empty again for every replacement session, which is
/// what makes "what has this peer told *this* session" answerable without a key.
#[derive(Default)]
pub(crate) struct RetainedAdvert {
    held: Option<LeasedCapabilityAdvert>,
}

impl RetainedAdvert {
    /// The peer's advertisement as heard over this session.
    ///
    /// Decoded on demand, into a value the caller owns and this record does not.
    /// The retained form is bytes; a decoded copy kept beside them would be a
    /// second representation of one fact, and an unfunded one. Callers wanting
    /// to publish an advert take it from here and it lives as long as they hold
    /// it, not as long as the session.
    ///
    /// A decode failure answers `None`. These bytes were produced by
    /// [`Self::replace`] from a value of this very type, so a failure would mean
    /// the encoding is not round-tripping — a defect to fix in the type, not a
    /// condition for a snapshot path to panic on.
    pub(crate) fn decoded(&self) -> Option<CapabilityAdvert> {
        let retained = self.held.as_ref()?;
        serde_json::from_slice(&retained.encoded).ok()
    }

    /// Record what the peer advertised over this session, replacing any earlier
    /// advertisement it made over the same one.
    ///
    /// Fallible, and the failure is a refusal rather than a degraded write. The
    /// advertisement is peer-controlled data of peer-chosen size, so retaining
    /// it is a resource acquisition like any other: the encoded form is measured
    /// exactly, funded through the session that will own it, and only then
    /// built and installed.
    ///
    /// **On refusal nothing changes, and nothing was built.** The previous
    /// advertisement — including none — stays exactly as it was, no buffer was
    /// ever allocated for the rejected one, and the caller must not announce a
    /// change, because none happened. The ordering is what guarantees it: the
    /// size is counted without encoding, the encode happens only once the claim
    /// is funded, and the replacement is the last step with nothing after it
    /// that can fail.
    ///
    /// `session` is the funding authority and the proof that a current session
    /// authorized this. Taking it makes both unforgeable rather than
    /// conventional.
    pub(crate) fn replace(
        &mut self,
        session: &SessionCapability,
        advert: &CapabilityAdvert,
    ) -> Result<()> {
        // Counted, not built. The peer chooses this size, so the refusal paths
        // below are the ones that matter most: a session with no capacity for
        // the advertisement must not pay for encoding it first.
        let encoded_len = advert.encoded_len().ok_or_else(|| {
            Error::Transport(
                "capability advertisement does not encode to a measurable size".to_string(),
            )
        })?;
        let claim = retained_advert_claim(encoded_len).map_err(|e| {
            Error::Transport(format!(
                "capability advertisement is not representable as a resource claim: {e:?}"
            ))
        })?;
        let lease = session.reserve_retained(claim).map_err(|e| {
            Error::Transport(format!(
                "capability advertisement refused: no capacity to retain it for this session: {e:?}"
            ))
        })?;
        // The old advertisement stays installed while the new one is measured,
        // funded and encoded — that overlap is what lets a refusal above leave
        // the previous value untouched. The encode is last because it is the
        // allocation the lease was taken for: nothing before this point has
        // built a buffer, so every refusal above is free.
        let encoded = advert.encode_exact(encoded_len).ok_or_else(|| {
            Error::Transport(
                "capability advertisement did not encode to its counted size".to_string(),
            )
        })?;
        // This assignment is the only state change, and it releases the old
        // bytes and the old lease together.
        self.held = Some(LeasedCapabilityAdvert {
            encoded,
            _lease: lease,
        });
        Ok(())
    }
}

/// Whether this session still owes its peer the local advertisement.
///
/// A field of the session and nowhere else, which is what makes the two rules
/// the outbound replay needs fall out of the lifetime rather than out of
/// bookkeeping:
///
/// * a **replacement** session is a fresh record, so it owes the current advert
///   again and there is no path by which it could inherit a cleared flag;
/// * a **refused** promotion mints no record at all, so nothing is consumed and
///   the first later successful promotion still owes it.
///
/// An engine-side map keyed by device would need its own invalidation on
/// replacement — a second copy of the session's lifetime, free to drift from it.
/// A replay that leaves the fence and returns needs no session identity to
/// settle against, because one peer entry promotes at most one session:
/// `install_endpoint_auth` refuses a second task, `install_authenticated_channel`
/// refuses a second capability, and a successful promotion consumes the one
/// there is. A genuine connector replacement installs a *new* entry with a new
/// owner token, and the fence already refuses a stale one — so "still the same
/// session" and "still the same owner" are the same statement here, and the
/// exact-owner requirement already carries it.
pub(crate) struct LocalAdvertDebt {
    owed: bool,
}

impl LocalAdvertDebt {
    /// Owed from the moment the session exists.
    ///
    /// There is no `Default`, deliberately, even though `bool`'s would be wrong
    /// in the safe direction: a session that started out believing it had
    /// already sent an advertisement it never sent would make every control
    /// asserting the replay pass vacuously. Requiring the constructor makes the
    /// starting value a decision rather than an inheritance.
    pub(crate) fn new() -> Self {
        Self { owed: true }
    }

    pub(crate) fn owed(&self) -> bool {
        self.owed
    }

    /// Record that the peer has been told, after a send that actually
    /// succeeded.
    ///
    /// Cleared separately from being read, rather than consumed up front:
    /// taking the debt before the send would lose the advertisement outright
    /// when the send fails. The worst case in this direction is two identical
    /// advertisements, which the receiver replaces wholesale.
    pub(crate) fn clear(&mut self) {
        self.owed = false;
    }
}

/// What one retained advertisement costs, derived from the retained
/// representation.
///
/// One byte term — the boxed buffer, whose length is its capacity — and one
/// residual for that allocation. The `Option` holding it is inline in the
/// session record and was already charged by
/// [`PromotedSession::promotion_claim`](super::PromotedSession::promotion_claim);
/// charging it again here would bill the same bytes twice.
fn retained_advert_claim(
    encoded: usize,
) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(encoded).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?,
        ),
        (
            ResourceClass::OpaqueDependencyResidual,
            RETAINED_ADVERT_ALLOCATIONS,
        ),
    ])
}

/// The full provider charge for retaining one advertisement, for fixtures that
/// must fund a known number of them.
///
/// The update path's own arithmetic composed with the provider's, for the same
/// reason as the reliable frame charge: a fixture that restates either half
/// funds a different number from the one the provider is asked for, and a
/// pressure control built on the difference proves nothing.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn retained_advert_reservation_charge_for_test(encoded: usize) -> ResourceClaim {
    let claim = retained_advert_claim(encoded)
        .expect("the retained advert claim is arithmetic over a bounded length");
    crate::resource::FiniteResourceProvider::reservation_charge_for_test(claim)
        .expect("one retained advert claim plus the provider's reservation record is representable")
}

/// The encoded size the advert path will charge for `advert`, so a fixture can
/// fund exactly one of *this* advertisement rather than a guess at its size.
///
/// Counted by the same call the update path uses, so the number is the one that
/// will actually be asked for and not an estimate of it. It counts rather than
/// encodes for the same reason the update path does — and because a fixture that
/// encoded here would be measuring a different call from the one under test.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn encoded_advert_len_for_test(advert: &CapabilityAdvert) -> usize {
    advert
        .encoded_len()
        .expect("a control advertisement serializes")
}
