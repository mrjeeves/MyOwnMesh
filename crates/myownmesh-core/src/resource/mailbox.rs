use parking_lot::Mutex;
use std::marker::PhantomData;

use super::{
    FundedArc, LeasedQueue, LocalApplicationResourceScope, ResourceClaim,
    ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceUnavailable,
};

struct MailboxEntry<T> {
    value: T,
    retention: ResourceLease,
}

/// The shared mailbox state, as it sits inside the funded allocation.
///
/// The root lease is deliberately **not** a field here. `root_claim()` prices
/// the shared allocation itself, so its owner is [`FundedArc`]: one shared
/// lease held beside the pointee rather than inside it, released on the final
/// strong drop, and observed weakly through a weak funding pointer — which is
/// what makes `upgrade` all-or-nothing and what keeps a weak-only handle from
/// retaining any part of this claim. Nothing reachable from inside the pointee
/// can clone that owner or extend what it funds.
struct MailboxInner<T> {
    queue: Mutex<LeasedQueue<MailboxEntry<T>>>,
    ready: tokio::sync::Notify,
    closed_ready: tokio::sync::Notify,
    closed: std::sync::atomic::AtomicBool,
    senders: std::sync::atomic::AtomicUsize,
    owner: LocalApplicationResourceScope,
}

/// Measured off-node retention owned by one mailbox value.
///
/// Implementations count the value itself and every allocation or handle it
/// retains. The mailbox adds one scheduled-work obligation and owns the queue
/// node separately, so all three parts of an accepted entry leave together.
#[must_use = "a mailbox measurement must be consumed by admission or planning"]
pub struct MailboxMeasurement<T> {
    claim: ResourceClaim,
    _item: PhantomData<fn() -> T>,
}

impl<T> MailboxMeasurement<T> {
    pub(crate) fn from_parts(
        retained_bytes: usize,
        queued_bytes: usize,
        allocations: usize,
    ) -> Result<Self, ResourceMailboxItemError> {
        Ok(Self {
            claim: mailbox_retained_claim::<T>(retained_bytes, queued_bytes, allocations)?,
            _item: PhantomData,
        })
    }

    pub(crate) fn into_claim(self) -> ResourceClaim {
        self.claim
    }
}

/// Measurements are opaque and are produced by the central mailbox
/// arithmetic, so a safe caller cannot forge a claim.
///
/// # Safety
///
/// An implementation must return a token that funds the exact value and all
/// off-node state retained by it, including allocations, handles, and effects.
pub unsafe trait ResourceMailboxItem: Sized {
    fn measured_claim(&self) -> Result<MailboxMeasurement<Self>, ResourceMailboxItemError>;
}

/// A mailbox value described before it is constructed.
///
/// Some values are assembled from buffers an admitted caller already owns. In
/// that case requiring a finished [`ResourceMailboxItem`] before admission
/// makes the construction itself unaccounted: pressure can refuse the value,
/// but only after the allocation or copy already happened. A builder measures
/// the borrowed inputs, then consumes them only after the mailbox has acquired
/// both the value-retention and queue-node leases.
///
/// The claim has the same contract as [`ResourceMailboxItem::measured_claim`]:
/// it names the finished value's off-node retention only, and must equal the
/// claim `build()`'s result would answer. Controls for a borrowed mirror should
/// compare the two directly; the mailbox cannot do so without constructing the
/// value before admission and defeating this interface. The mailbox adds its
/// scheduled-work obligation and owns the queue node separately.
///
/// # Safety
///
/// The measurement must fund the exact value returned by `build`, and `build`
/// must not be invoked before the mailbox has acquired its leases.
pub unsafe trait ResourceMailboxItemBuilder<T: ResourceMailboxItem> {
    fn measured_claim(&self) -> Result<MailboxMeasurement<T>, ResourceMailboxItemError>;
    fn build(self) -> T;
}

/// Conservatively measure a serializable, JSON-shaped mailbox value and return
/// an opaque token for the off-node claim that must remain leased while the
/// typed value is queued.
///
/// The encoded length bounds both the decoded tree's owned fragments and its
/// allocation count. The value's inline representation is added separately;
/// queued bytes name exactly what a later writer will serialize, and the same
/// measured length prices the serialization pass as parsing/CPU work. This is
/// the shared measurement for pure-data mailbox items; values carrying opaque
/// handles or effects must add those dependencies in their own implementation.
pub fn measure_serialized_mailbox_item<T>(
    value: &impl serde::Serialize,
) -> Result<MailboxMeasurement<T>, ResourceMailboxItemError> {
    let (retained, queued, allocations) = mailbox_measure_serialized(value)?;
    MailboxMeasurement::from_parts(retained, queued, allocations)
}

/// Measure one mailbox value and remove the bare retention already funded by
/// an upstream owner of part of that value.
///
/// The subtraction is performed on the central opaque claim, dimension by
/// dimension. An underflow therefore rejects a mismatched or incomplete
/// funded claim before any builder can construct its owned value. This is the
/// only supported composition seam; callers cannot forge a measurement from a
/// claim or bypass the serialized measurement.
pub fn measure_serialized_mailbox_item_after_funded<T>(
    value: &impl serde::Serialize,
    funded: ResourceClaim,
) -> Result<MailboxMeasurement<T>, ResourceMailboxItemError> {
    let measured = measure_serialized_mailbox_item::<T>(value)?.into_claim();
    Ok(MailboxMeasurement {
        claim: measured.checked_sub(funded)?,
        _item: PhantomData,
    })
}

/// Measure a serializable borrowed view as the mailbox value it will build.
///
/// The view must encode byte-for-byte like `T`. Its serialization supplies the
/// decoded-tree, queued-byte and allocation measurements, while `T` supplies
/// the inline size of the value the mailbox will actually retain. Measuring
/// the view as its own type would instead charge
/// for its references and could underfund the owned value constructed after
/// admission.
/// Measure a borrowed value as three totals: retained bytes, queued bytes, and
/// allocations.
///
/// The measurement kit an owner needs when the thing to be funded is *not* one
/// serializable value but several borrowed pieces that will be assembled after
/// admission. [`measure_serialized_mailbox_item`] is this composed with the
/// central retained-claim arithmetic for the single-value case; an owner measuring a
/// borrowed source field by field composes the parts with
/// [`checked_measure_add`] instead and only then acquires.
///
/// **Measures, never acquires, and borrows throughout.** Nothing here reserves
/// capacity, and nothing here clones the caller's source — which is the whole
/// point at a call site that must decide whether it may build an owned snapshot
/// before it builds one.
pub fn mailbox_measure_serialized(
    value: &impl serde::Serialize,
) -> Result<(usize, usize, usize), ResourceMailboxItemError> {
    struct CountBytes(Option<usize>);

    impl std::io::Write for CountBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.and_then(|count| count.checked_add(bytes.len()));
            self.0
                .ok_or_else(|| std::io::Error::other("serialized length overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut encoded = CountBytes(Some(0));
    serde_json::to_writer(&mut encoded, value)
        .map_err(|_| ResourceMailboxItemError::Measurement("JSON serialization failed"))?;
    let encoded = encoded.0.ok_or(ResourceMailboxItemError::Measurement(
        "JSON serialization length overflowed",
    ))?;
    let allocations = encoded;
    let bytes_per_fragment = std::mem::size_of::<serde_json::Value>()
        .checked_add(1)
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let retained =
        encoded
            .checked_mul(bytes_per_fragment)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
    Ok((retained, encoded, allocations))
}

/// Turn a completed measurement into the exact claim for retaining one `T`.
///
/// `T` supplies the inline size of the value that will actually be held; the
/// three measured totals supply everything it reaches. The residual is the
/// measured allocation count plus one for the value's own.
///
/// The final step of the borrowed-measurement path: measure with
/// [`mailbox_measure_serialized`], combine with [`checked_measure_add`], claim
/// here, acquire, and only then build the owned value.
pub(crate) fn mailbox_retained_claim<T>(
    retained_bytes: usize,
    queued_bytes: usize,
    allocations: usize,
) -> Result<ResourceClaim, ResourceMailboxItemError> {
    let fixed = std::mem::size_of::<T>().checked_add(retained_bytes).ok_or(
        ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let fixed = u64::try_from(fixed).map_err(|_| ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    })?;
    let queued =
        u64::try_from(queued_bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::QueuedBytes,
        })?;
    let allocations = u64::try_from(allocations)
        .map_err(|_| ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::OpaqueDependencyResidual,
        })?
        .checked_add(1)
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::OpaqueDependencyResidual,
        })?;
    Ok(ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, fixed),
        (ResourceClass::QueuedBytes, queued),
        (ResourceClass::ParsingOrCpuWork, queued),
        (ResourceClass::OpaqueDependencyResidual, allocations),
    ])?)
}

/// Add two measurements, refusing rather than wrapping on any of the three.
///
/// How an owner measuring a composite borrowed source accumulates its parts
/// before a single acquisition. Each total is checked in its own dimension, so
/// an overflow names the class it happened in rather than being absorbed into a
/// figure that would then underfund the value.
pub fn checked_measure_add(
    left: (usize, usize, usize),
    right: (usize, usize, usize),
) -> Result<(usize, usize, usize), ResourceMailboxItemError> {
    Ok((
        left.0
            .checked_add(right.0)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?,
        left.1
            .checked_add(right.1)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::QueuedBytes,
            })?,
        left.2
            .checked_add(right.2)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::OpaqueDependencyResidual,
            })?,
    ))
}

pub(crate) fn strings_measure<'a>(
    strings: impl IntoIterator<Item = &'a str>,
) -> Result<(usize, usize, usize), ResourceMailboxItemError> {
    strings
        .into_iter()
        .try_fold((0usize, 0usize, 0usize), |measure, value| {
            let bytes = measure.0.checked_add(value.len()).ok_or(
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                },
            )?;
            let queued = measure.1.checked_add(value.len()).ok_or(
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::QueuedBytes,
                },
            )?;
            let allocations = measure
                .2
                .checked_add(usize::from(!value.is_empty()))
                .ok_or(ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
            Ok((bytes, queued, allocations))
        })
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceMailboxItemError {
    #[error("mailbox item claim is not representable: {0}")]
    Claim(#[from] ResourceClaimArithmeticError),
    #[error("mailbox item could not be measured: {0}")]
    Measurement(&'static str),
}

/// Why the exact provider charge for a future accepted item could not be
/// planned. Planning acquires nothing; it only applies the same item, node and
/// provider-record arithmetic that [`ResourceMailboxSender::send`] will use.
#[derive(Debug, thiserror::Error)]
pub enum ResourceMailboxPlanningError {
    #[error("mailbox item charge could not be represented: {0}")]
    Item(#[from] ResourceMailboxItemError),
    #[error("mailbox provider-record charge could not be represented: {0:?}")]
    Provider(ResourceUnavailable),
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceMailboxCreateError {
    #[error("mailbox root claim is not representable: {0}")]
    Claim(#[from] ResourceClaimArithmeticError),
    #[error("mailbox root was refused by the resource provider: {0:?}")]
    Pressure(ResourceUnavailable),
}

#[derive(Debug)]
pub enum ResourceMailboxSendError<T> {
    Claim {
        value: T,
        error: ResourceMailboxItemError,
    },
    Pressure {
        value: T,
        error: ResourceUnavailable,
    },
    Closed(T),
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceMailboxAdmissionError {
    #[error("mailbox item was not representable: {0}")]
    Claim(#[from] ResourceMailboxItemError),
    #[error("mailbox item was refused by the resource provider: {0:?}")]
    Pressure(ResourceUnavailable),
    #[error("mailbox admission is closed")]
    Closed,
}

impl<T> ResourceMailboxSendError<T> {
    pub fn into_value(self) -> T {
        match self {
            Self::Claim { value, .. } | Self::Pressure { value, .. } | Self::Closed(value) => value,
        }
    }

    pub fn pressure(&self) -> Option<ResourceUnavailable> {
        match self {
            Self::Pressure { error, .. } => Some(*error),
            Self::Claim { .. } | Self::Closed(_) => None,
        }
    }

    pub fn into_admission_error(self) -> ResourceMailboxAdmissionError {
        match self {
            Self::Claim { error, .. } => ResourceMailboxAdmissionError::Claim(error),
            Self::Pressure { error, .. } => ResourceMailboxAdmissionError::Pressure(error),
            Self::Closed(_) => ResourceMailboxAdmissionError::Closed,
        }
    }
}

/// Producer for one resource-backed, count-unbounded mailbox.
///
/// Cloning a producer allocates nothing. Every accepted value arrives with one
/// lease for its off-node retention and one lease for the queue node. The
/// mailbox never guesses an item count or acquires authority on the caller's
/// behalf.
pub struct ResourceMailboxSender<T> {
    inner: FundedArc<MailboxInner<T>>,
}

impl<T> Clone for ResourceMailboxSender<T> {
    fn clone(&self) -> Self {
        self.inner
            .senders
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |senders| senders.checked_add(1),
            )
            .expect("a live handle bounds the number of mailbox senders");
        // Cloning the funded handle adds a holder to the one reservation that
        // already funds this allocation; it does not take out a second one.
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Single consumer for a resource-backed mailbox.
pub struct ResourceMailboxReceiver<T> {
    inner: FundedArc<MailboxInner<T>>,
}

/// A mailbox whose shared allocation is funded but not constructed.
///
/// Owners that must re-check identity or lifecycle immediately before
/// publishing an effect can acquire the root first, perform that final check,
/// and then call [`Self::commit`] without another fallible operation. Dropping
/// a preparation releases the unused root lease and constructs nothing.
#[must_use = "a prepared mailbox owns a root lease until it is committed or dropped"]
pub struct PreparedResourceMailbox<T> {
    owner: LocalApplicationResourceScope,
    root: ResourceLease,
    item: std::marker::PhantomData<fn() -> T>,
}

impl<T> PreparedResourceMailbox<T> {
    /// Construct both mailbox halves from the already-acquired root.
    ///
    /// Infallible: every provider operation happened in
    /// [`prepare_resource_mailbox`], so this is suitable for an identity-exact
    /// commit section after its last refusal.
    pub fn commit(self) -> (ResourceMailboxSender<T>, ResourceMailboxReceiver<T>) {
        let Self { owner, root, .. } = self;
        let inner = FundedArc::new(
            MailboxInner {
                queue: Mutex::new(LeasedQueue::new()),
                ready: tokio::sync::Notify::new(),
                closed_ready: tokio::sync::Notify::new(),
                closed: std::sync::atomic::AtomicBool::new(false),
                senders: std::sync::atomic::AtomicUsize::new(1),
                owner,
            },
            root,
        )
        // Unreachable rather than merely unlikely: `FundedArc::new` refuses one
        // thing, a speculative lease, and the only way to reach this line is
        // through `prepare_resource_mailbox`, whose acquisition goes through
        // `LocalApplicationResourceScope::acquire` — which names
        // `ResourceAuthorityClass::Admitted` itself and takes no authority from
        // the caller. There is no spelling of a prepared mailbox holding a
        // speculative root, so this preserves the documented infallibility of
        // the commit rather than quietly adding a refusal to it.
        .expect("a prepared mailbox root is admitted, never speculative");
        (
            ResourceMailboxSender {
                inner: inner.clone(),
            },
            ResourceMailboxReceiver { inner },
        )
    }
}

/// One delivered value and the funding for its off-node retention, as a single
/// move-only owner. The queue-node lease is released by the pop; this is what
/// remains.
///
/// **The two halves are one value on purpose.** `value` is declared before
/// `retention`, and struct fields are destroyed in declaration order, so the
/// value dies first and its funding is released second. The ordering is a
/// property of this layout rather than of what each call site remembers to do.
///
/// Handing the pair out as a tuple put that order back in the caller's hands,
/// and the shape it invited — `let (frame, _retention) = ...;` — is precisely
/// the failure: two locals whose relative drop order is whatever the rest of
/// the function body happens to imply, with the funding free to go first while
/// the frame is still being serialized and written. Worse, the value could be
/// moved onward into another queue while the retention stayed behind and was
/// released at the end of the block, so the provider was told those bytes were
/// free while they were still very much alive somewhere else.
///
/// **The public surface is therefore an immutable borrow and nothing else.**
/// [`Self::value`] is the whole of it: a serializer reads through it, a writer
/// awaits with it, and the delivery is dropped afterwards, so the funding
/// outlives the write by construction rather than by convention. Anything that
/// needs the value to keep living moves the delivery itself.
///
/// Three shapes that look reasonable are deliberately absent, each because it
/// would hand the separation back under a friendlier name:
///
/// - a `&mut` accessor — `mem::replace` and `mem::take` move the value straight
///   out through one, so it is not the weaker capability it appears to be;
/// - a general `map(FnOnce(T) -> U)` carrying this claim onto the output —
///   nothing in that signature stops a small funded `T` becoming a large `U`,
///   so it could *underfund* its result while the ledger read unchanged;
/// - a `consume(FnOnce(T) -> R) -> R` that drops the funding after the closure
///   returns — `R` can be `T`, or an error containing `T`, so the value walks
///   out having outlived its claim by exactly the margin the type promised it
///   could not.
///
/// There is no in-crate exception either — no seam handing the two halves to a
/// closure, and no wrapper around the lease for a destination to hold. Both
/// were tried, and both are the same split with better manners: a closure
/// receiving `(T, ResourceLease)` can return the bare value, return the pair,
/// or build something larger than the claim, and a wrapper is still a second
/// value that can be dropped before the first. An owner that needs this value
/// to keep living stores *this type*, whole.
pub struct ResourceMailboxDelivery<T> {
    value: T,
    retention: ResourceLease,
}

impl<T> ResourceMailboxDelivery<T> {
    /// The delivered value, borrowed. The funding outlives the borrow.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Run one terminal effect over the delivered value, releasing the funding
    /// only once that effect has finished.
    ///
    /// **The single consuming seam in the crate, and it exists for one shape of
    /// caller: a public message enum whose payload is consumed by value
    /// downstream.** A command handler is not a reader — `NetworkCmd` carries
    /// `oneshot::Sender`s in fifteen of its variants, and `Sender::send`
    /// consumes, so the command genuinely cannot be handled from a borrow.
    /// The signaling `EphemeralIngress` is the same shape for a different reason:
    /// the classified input it carries lands in `apply_remote_sdp`, which takes
    /// an owned `String`, and
    /// `add_remote_candidate_observed`, which takes an owned
    /// `LocalIceCandidate`. In both cases the alternatives are worse — rebuild
    /// the public enum around interior mutability across every variant and
    /// construction site, or clone multi-kilobyte SDP bodies outside the claim
    /// that funded them. This is the narrower answer.
    ///
    /// **`Output = ()` closes the return path, and only that.** A consuming
    /// form of `FnOnce(T) -> R`, where `R` could be `T` or an error containing
    /// `T`, would let the value walk out through the signature itself. Nothing
    /// returns here, and `retention` is dropped after the future has
    /// *completed* rather than after it has been built.
    ///
    /// That is not a structural impossibility and must not be read as one: an
    /// effect is free to `spawn` the value onto another task, push it into a
    /// queue, or park it in a global and still return `()`. Any of those would
    /// outlive this claim exactly as the returned value would have.
    ///
    /// So the load-bearing rule is the census, not the type. The seam is
    /// crate-private and has six counted implementation callers: the
    /// supervisor's dedicated ConnectPeer actor, its ordered NetworkCmd,
    /// speculative-promotion, and EphemeralIngress arms, plus the two matching
    /// test-driver helpers. Each hands
    /// the message to a terminal handler that consumes it locally — the command
    /// handlers move only a `oneshot::Sender` out in order to answer, and the
    /// signaling handler hands its payload to a transport call that finishes
    /// within the awaited future. A handler may retain an intrinsically
    /// independently funded `ConnectWaitShared` handle and a separately
    /// leased registry entry; that retention is outside this delivery claim
    /// and remains funded until both the registration and caller terminal
    /// handles drop. **Any other caller that stored the message onward, or
    /// spawned it, would break this and the signature would not stop it** —
    /// which is why the caller list is part of the contract and any addition to
    /// it needs the same scrutiny the seam itself got.
    ///
    /// **Not for serialization, writes, or fan-out.** Those keep the delivery
    /// whole and read through [`Self::value`]; a writer has somewhere for the
    /// bytes to go and so does not need this. The callers are the driver loop's
    /// `NetworkCmd`, `SpeculativePromotionCmd`, and `EphemeralIngress` arms,
    /// plus the test command driver's `NetworkCmd` and
    /// `SpeculativePromotionCmd` arms. That census is the point of the seam
    /// being `pub(crate)` and named for what it is.
    /// `the_terminal_effect_seam_has_exactly_its_documented_callers` fails if
    /// the counted implementation set moves.
    pub(crate) async fn run_terminal_effect<F>(self, effect: impl FnOnce(T) -> F)
    where
        F: std::future::Future<Output = ()>,
    {
        let Self { value, retention } = self;
        effect(value).await;
        drop(retention);
    }

    /// Split the delivery into its two halves. **This module's controls only.**
    ///
    /// Private, and `#[cfg(test)]` rather than feature-gated. A feature is a
    /// buildable production surface — any consumer that turned it on would get
    /// a real, callable tuple API, and the invariant that a delivery cannot
    /// separate its value from its retention would simply be false for them.
    /// The audience is the handful of controls in this file that assert on the
    /// funding itself: that a live retention is still charged while the value
    /// exists, that dropping the value releases exactly it. Those have to hold
    /// both halves at once to observe it at all, and they are the one caller
    /// for which caller-controlled drop order is the subject rather than the
    /// hazard. Every other test, in this crate and outside it, reads through
    /// [`Self::value`] or moves the delivery whole.
    #[cfg(test)]
    fn into_parts(self) -> (T, ResourceLease) {
        (self.value, self.retention)
    }
}

/// Construct one mailbox from its exact local-application owner.
pub fn resource_mailbox<T>(
    owner: LocalApplicationResourceScope,
) -> Result<(ResourceMailboxSender<T>, ResourceMailboxReceiver<T>), ResourceMailboxCreateError> {
    Ok(prepare_resource_mailbox(owner)?.commit())
}

/// Acquire one mailbox root without constructing its shared allocation.
pub fn prepare_resource_mailbox<T>(
    owner: LocalApplicationResourceScope,
) -> Result<PreparedResourceMailbox<T>, ResourceMailboxCreateError> {
    let root = owner
        .acquire(ResourceMailboxSender::<T>::root_claim()?)
        .map_err(ResourceMailboxCreateError::Pressure)?;
    Ok(PreparedResourceMailbox {
        owner,
        root,
        item: std::marker::PhantomData,
    })
}

impl<T> ResourceMailboxSender<T> {
    /// Claim for the shared mailbox record.
    ///
    /// The visible record bytes are charged directly. One broad residual covers
    /// dependency-private allocation metadata; Arc control-block layout is not
    /// a resource-protocol invariant.
    pub fn root_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let bytes = u64::try_from(std::mem::size_of::<MailboxInner<T>>()).map_err(|_| {
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            }
        })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Exact claim for one queue node. Off-node value retention is separate.
    pub fn node_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        LeasedQueue::<MailboxEntry<T>>::entry_claim()
    }

    fn scheduled_work_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        ResourceClaim::try_from_entries([(ResourceClass::CallbackOrScheduledWork, 1)])
    }

    /// Commit an already-funded value. On closure, both leases and the value
    /// are returned together so the caller observes one lossless refusal.
    ///
    /// The refusal is deliberately stored inline: boxing it would add a fresh
    /// allocation to the mailbox's closed path, where no new resource should
    /// be required merely to hand ownership back to the caller.
    #[expect(
        clippy::result_large_err,
        reason = "the closed path must hand `T` and both leases back by value — \
                  that is what makes the refusal lossless, and it is the whole \
                  reason this signature exists. Boxing the `Err` would demand a \
                  fresh allocation at the one moment the mailbox has just been \
                  found closed, purely to return ownership the caller already \
                  had. The success arm carries nothing, so the wide `Result` \
                  costs the accepting path only its size"
    )]
    pub(crate) fn accept(
        &self,
        value: T,
        retention: ResourceLease,
        node: ResourceLease,
    ) -> Result<(), (T, ResourceLease, ResourceLease)> {
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err((value, retention, node));
        }
        let mut queue = self.inner.queue.lock();
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err((value, retention, node));
        }
        queue.push(MailboxEntry { value, retention }, node);
        drop(queue);
        self.inner.ready.notify_one();
        Ok(())
    }

    /// Close admission and wake the consumer. Already accepted entries remain
    /// available to drain.
    pub fn close(&self) {
        let queue = self.inner.queue.lock();
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        drop(queue);
        self.inner.ready.notify_waiters();
        self.inner.closed_ready.notify_waiters();
    }

    /// Wait until admission closes, including closure caused by the receiver
    /// being dropped. Register before re-checking the flag so closure cannot be
    /// lost between observation and suspension. Closure notifications are
    /// deliberately separate from value-arrival notifications, so a close
    /// witness can never consume the receiver's wake.
    pub async fn closed(&self) {
        loop {
            if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            let notified = self.inner.closed_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    /// Measure and admit a value before constructing it.
    ///
    /// `builder.build()` is not called when the mailbox is already closed, the
    /// claim is not representable, or either provider acquisition refuses.
    /// Once both leases exist the construction is infallible and the ordinary
    /// lossless commit installs the value. A close racing that final commit may
    /// still receive and immediately drop the constructed value; no admission
    /// API can revoke construction synchronously after it has begun.
    pub fn send_building<B>(&self, builder: B) -> Result<(), ResourceMailboxAdmissionError>
    where
        T: ResourceMailboxItem,
        B: ResourceMailboxItemBuilder<T>,
    {
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ResourceMailboxAdmissionError::Closed);
        }
        let retention_claim = builder
            .measured_claim()?
            .into_claim()
            .checked_add(Self::scheduled_work_claim().map_err(ResourceMailboxItemError::from)?)
            .map_err(ResourceMailboxItemError::from)?;
        let retention = self
            .inner
            .owner
            .acquire(retention_claim)
            .map_err(ResourceMailboxAdmissionError::Pressure)?;
        let node = self
            .inner
            .owner
            .acquire(Self::node_claim().map_err(ResourceMailboxItemError::from)?)
            .map_err(ResourceMailboxAdmissionError::Pressure)?;
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ResourceMailboxAdmissionError::Closed);
        }
        self.accept(builder.build(), retention, node)
            .map_err(|(_value, _retention, _node)| ResourceMailboxAdmissionError::Closed)
    }
}

impl<T: ResourceMailboxItem> ResourceMailboxSender<T> {
    fn item_planning_charge(
        item: ResourceClaim,
    ) -> Result<ResourceClaim, ResourceMailboxPlanningError> {
        let scheduled = Self::scheduled_work_claim().map_err(ResourceMailboxItemError::from)?;
        let retention = item
            .checked_add(scheduled)
            .map_err(ResourceMailboxItemError::from)?;
        let retention = super::FiniteResourceProvider::reservation_planning_charge(retention)
            .map_err(ResourceMailboxPlanningError::Provider)?;
        let node = Self::node_claim().map_err(ResourceMailboxItemError::from)?;
        let node = super::FiniteResourceProvider::reservation_planning_charge(node)
            .map_err(ResourceMailboxPlanningError::Provider)?;
        retention
            .checked_add(node)
            .map_err(ResourceMailboxItemError::from)
            .map_err(ResourceMailboxPlanningError::from)
    }

    /// Exact provider capacity consumed by accepting this concrete value.
    ///
    /// The mailbox makes two reservations per item: one for the value plus its
    /// scheduled-work obligation, and one for the queue node. This planning
    /// result includes the provider's bookkeeping record for each reservation.
    /// It creates no scope, lease or admission and is intended for owners that
    /// must size a finite grant from the production admission shape.
    pub fn accepted_item_planning_charge(
        value: &T,
    ) -> Result<ResourceClaim, ResourceMailboxPlanningError> {
        Self::item_planning_charge(value.measured_claim()?.into_claim())
    }

    /// Exact provider capacity consumed by accepting what this builder will
    /// construct. Computes capacity only; it invokes neither `build` nor any
    /// provider operation.
    pub fn building_item_planning_charge<B>(
        builder: &B,
    ) -> Result<ResourceClaim, ResourceMailboxPlanningError>
    where
        B: ResourceMailboxItemBuilder<T>,
    {
        Self::item_planning_charge(builder.measured_claim()?.into_claim())
    }

    /// Exact provider charge for accepting one concrete item in a fixture.
    ///
    /// Production admission deliberately acquires the retained value and the
    /// queue node as two reservations. Tests that size a finite provider must
    /// price those same reservations from this implementation rather than
    /// restating their claims and silently borrowing capacity from another
    /// subsystem.
    #[cfg(test)]
    pub(crate) fn accepted_item_charge_for_test(value: &T) -> ResourceClaim {
        Self::accepted_item_planning_charge(value)
            .expect("fixture mailbox accepted-item charge is representable")
    }

    /// Reserve from the exact owner this sender uses, for pressure controls.
    #[cfg(test)]
    pub(crate) fn reserve_for_test(
        &self,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.inner.owner.acquire(claim)
    }

    /// Measure and admit one value. Refusal returns the exact value and never
    /// leaves a node, retained allocation, or scheduled-work charge behind.
    pub fn send(&self, value: T) -> Result<(), ResourceMailboxSendError<T>> {
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ResourceMailboxSendError::Closed(value));
        }
        let retention_claim = match value.measured_claim().and_then(|measurement| {
            measurement
                .into_claim()
                .checked_add(Self::scheduled_work_claim()?)
                .map_err(Into::into)
        }) {
            Ok(claim) => claim,
            Err(error) => return Err(ResourceMailboxSendError::Claim { value, error }),
        };
        let retention = match self.inner.owner.acquire(retention_claim) {
            Ok(lease) => lease,
            Err(error) => return Err(ResourceMailboxSendError::Pressure { value, error }),
        };
        let node_claim = match Self::node_claim() {
            Ok(claim) => claim,
            Err(error) => {
                return Err(ResourceMailboxSendError::Claim {
                    value,
                    error: error.into(),
                })
            }
        };
        let node = match self.inner.owner.acquire(node_claim) {
            Ok(lease) => lease,
            Err(error) => return Err(ResourceMailboxSendError::Pressure { value, error }),
        };
        self.accept(value, retention, node)
            .map_err(|(value, _retention, _node)| ResourceMailboxSendError::Closed(value))
    }
}

impl<T> Drop for ResourceMailboxSender<T> {
    fn drop(&mut self) {
        let previous = self
            .inner
            .senders
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        assert!(previous > 0, "mailbox sender count cannot underflow");
        if previous == 1 {
            self.close();
        }
    }
}

impl<T> ResourceMailboxReceiver<T> {
    pub fn try_recv(&mut self) -> Option<ResourceMailboxDelivery<T>> {
        self.inner
            .queue
            .lock()
            .pop_front()
            .map(|entry| ResourceMailboxDelivery {
                value: entry.value,
                retention: entry.retention,
            })
    }

    pub async fn recv(&mut self) -> Option<ResourceMailboxDelivery<T>> {
        loop {
            let inner = self.inner.clone();
            let notified = inner.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(delivery) = self.try_recv() {
                return Some(delivery);
            }
            if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
                return None;
            }
            notified.await;
        }
    }
}

impl<T> Drop for ResourceMailboxReceiver<T> {
    fn drop(&mut self) {
        let mut queue = self.inner.queue.lock();
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        while queue.pop_front().is_some() {}
        drop(queue);
        self.inner.ready.notify_waiters();
        self.inner.closed_ready.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
    struct TestItem(Vec<u8>);

    unsafe impl ResourceMailboxItem for TestItem {
        fn measured_claim(&self) -> Result<MailboxMeasurement<Self>, ResourceMailboxItemError> {
            measure_serialized_mailbox_item::<Self>(self)
        }
    }

    struct CountingBuilder {
        item: TestItem,
        builds: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    unsafe impl ResourceMailboxItemBuilder<TestItem> for CountingBuilder {
        fn measured_claim(&self) -> Result<MailboxMeasurement<TestItem>, ResourceMailboxItemError> {
            measure_serialized_mailbox_item::<TestItem>(&self.item)
        }

        fn build(self) -> TestItem {
            self.builds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.item
        }
    }

    struct FundedCountingBuilder {
        item: TestItem,
        funded: ResourceClaim,
        builds: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    unsafe impl ResourceMailboxItemBuilder<TestItem> for FundedCountingBuilder {
        fn measured_claim(&self) -> Result<MailboxMeasurement<TestItem>, ResourceMailboxItemError> {
            measure_serialized_mailbox_item_after_funded::<TestItem>(&self.item, self.funded)
        }

        fn build(self) -> TestItem {
            self.builds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.item
        }
    }

    fn fixture(
        item: Option<&TestItem>,
    ) -> (
        ResourceMailboxSender<TestItem>,
        ResourceMailboxReceiver<TestItem>,
        super::super::FiniteResourceProvider,
    ) {
        fixture_for(item)
    }

    fn fixture_for<T: ResourceMailboxItem>(
        item: Option<&T>,
    ) -> (
        ResourceMailboxSender<T>,
        ResourceMailboxReceiver<T>,
        super::super::FiniteResourceProvider,
    ) {
        let scopes = super::super::FiniteResourceProvider::scope_record_charge_for_test()
            .checked_scale(2)
            .expect("process and local-application scope records fit");
        let root = super::super::FiniteResourceProvider::reservation_charge_for_test(
            ResourceMailboxSender::<T>::root_claim().expect("mailbox root claim fits"),
        )
        .expect("mailbox root reservation fits");
        let mut grant = scopes.checked_add(root).expect("fixture root grant fits");
        if let Some(item) = item {
            grant = grant
                .checked_add(ResourceMailboxSender::<T>::accepted_item_charge_for_test(
                    item,
                ))
                .expect("fixture item grant fits");
        }
        let provider = super::super::FiniteResourceProvider::new(grant);
        let observed = provider.clone();
        let port = super::super::ResourceProviderPort::new(provider)
            .expect("fixture provider admits its process scope");
        let process = super::super::ProcessResourceRoot::isolated();
        process
            .install_local_application_provider(port)
            .expect("fixture installs its local provider");
        let scope = process
            .issue_local_application_scope()
            .expect("fixture issues its local scope");
        let (tx, rx) = resource_mailbox(scope).expect("fixture mailbox is funded");
        (tx, rx, observed)
    }

    fn funded_fixture(
        item: &TestItem,
        one_unit_short: bool,
    ) -> (
        ResourceMailboxSender<TestItem>,
        ResourceMailboxReceiver<TestItem>,
        super::super::FiniteResourceProvider,
        ResourceLease,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        ResourceClaim,
    ) {
        let (retained, queued, allocations) =
            mailbox_measure_serialized(item).expect("the funded payload is measurable");
        let funded =
            crate::application_gateway::GatewayMailbox::<serde_json::Value>::retention_claim(
                retained,
                queued,
                allocations,
            )
            .expect("the funded payload claim is representable");
        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let builder = FundedCountingBuilder {
            item: item.clone(),
            funded,
            builds: std::sync::Arc::clone(&builds),
        };
        let mailbox_charge =
            ResourceMailboxSender::<TestItem>::building_item_planning_charge(&builder)
                .expect("the remaining mailbox charge is representable");
        let scopes = super::super::FiniteResourceProvider::scope_record_charge_for_test()
            .checked_scale(2)
            .expect("process and local-application scope records fit");
        let root = super::super::FiniteResourceProvider::reservation_charge_for_test(
            ResourceMailboxSender::<TestItem>::root_claim().expect("mailbox root claim fits"),
        )
        .expect("mailbox root reservation fits");
        let payload = super::super::FiniteResourceProvider::reservation_charge_for_test(funded)
            .expect("the upstream payload reservation fits");
        let grant = scopes
            .checked_add(root)
            .and_then(|claim| claim.checked_add(payload))
            .and_then(|claim| claim.checked_add(mailbox_charge))
            .expect("the exact funded fixture grant fits");
        let grant = if one_unit_short {
            grant
                .checked_sub(ResourceClaim::single(ResourceClass::ParsingOrCpuWork, 1))
                .expect("one unit can be removed from the outer claim")
        } else {
            grant
        };
        let provider = super::super::FiniteResourceProvider::new(grant);
        let observed = provider.clone();
        let port = super::super::ResourceProviderPort::new(provider)
            .expect("fixture provider admits its process scope");
        let process = super::super::ProcessResourceRoot::isolated();
        process
            .install_local_application_provider(port)
            .expect("fixture installs its local provider");
        let scope = process
            .issue_local_application_scope()
            .expect("fixture issues its local scope");
        let payload_lease = scope
            .acquire(funded)
            .expect("the exact grant funds the upstream payload");
        let (tx, rx) = resource_mailbox(scope).expect("fixture mailbox is funded");
        (tx, rx, observed, payload_lease, builds, funded)
    }

    #[test]
    fn pressure_returns_the_exact_value_and_retains_no_entry() {
        let item = TestItem(vec![7; 32]);
        let (tx, mut rx, provider) = fixture(None);
        let before = provider.in_use();
        let refused = tx.send(item).expect_err("the fixture funds no item");
        assert!(matches!(
            &refused,
            ResourceMailboxSendError::Pressure { .. }
        ));
        assert_eq!(refused.into_value(), TestItem(vec![7; 32]));
        assert!(rx.try_recv().is_none());
        assert_eq!(provider.in_use(), before);
    }

    /// A builder is not allowed to construct an owned value before the exact
    /// retained-value and queue-node leases are admitted. Pressure therefore
    /// refuses without invoking `build`, and the successful path invokes it
    /// only after both reservations exist.
    #[test]
    fn building_mailbox_item_is_gated_by_exact_admission() {
        let item = TestItem(vec![4; 32]);
        let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (tx, mut rx, provider) = fixture(None);
        let before = provider.in_use();
        assert!(matches!(
            tx.send_building(CountingBuilder {
                item: item.clone(),
                builds: std::sync::Arc::clone(&builds),
            }),
            Err(ResourceMailboxAdmissionError::Pressure(_))
        ));
        assert_eq!(
            builds.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "pressure is observed before the owned value is constructed"
        );
        assert!(rx.try_recv().is_none());
        assert_eq!(provider.in_use(), before);

        let (tx, mut rx, provider) = fixture(Some(&item));
        let baseline = provider.in_use();
        tx.send_building(CountingBuilder {
            item: item.clone(),
            builds: std::sync::Arc::clone(&builds),
        })
        .expect("the exact fixture grant admits one built item");
        assert_eq!(
            builds.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the builder runs exactly once after admission"
        );
        assert_eq!(
            rx.try_recv()
                .expect("the built item is queued")
                .into_parts()
                .0,
            item
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "popping releases item custody while the mailbox handles retain the root"
        );
        drop(tx);
        drop(rx);
        assert_eq!(
            provider.in_use(),
            ResourceClaim::ZERO,
            "dropping the final mailbox handles releases root and scope custody"
        );
    }

    #[test]
    fn serialized_view_measurement_is_branded_for_the_built_type() {
        let item = TestItem(vec![9; 17]);
        let (retained, queued, allocations) =
            mailbox_measure_serialized(&item).expect("the borrowed production view is measurable");
        let measured = measure_serialized_mailbox_item::<TestItem>(&item)
            .expect("the target type receives the central measurement");
        let expected = MailboxMeasurement::<TestItem>::from_parts(retained, queued, allocations)
            .expect("the measured view claim is representable");
        assert_eq!(measured.claim, expected.claim);
        assert_eq!(
            ResourceMailboxSender::<TestItem>::building_item_planning_charge(&CountingBuilder {
                item: item.clone(),
                builds: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            })
            .expect("builder planning charge is representable"),
            ResourceMailboxSender::<TestItem>::accepted_item_planning_charge(&item)
                .expect("concrete planning charge is representable")
        );
    }

    #[test]
    fn funded_measurement_subtracts_exact_payload_and_rejects_mismatch() {
        let item = TestItem(vec![3; 24]);
        let (retained, queued, allocations) =
            mailbox_measure_serialized(&item).expect("the outer value is measurable");
        let funded =
            crate::application_gateway::GatewayMailbox::<serde_json::Value>::retention_claim(
                retained,
                queued,
                allocations,
            )
            .expect("the bare payload claim is representable");
        let full = measure_serialized_mailbox_item::<TestItem>(&item)
            .expect("the full outer claim is representable")
            .into_claim();
        let remaining = measure_serialized_mailbox_item_after_funded::<TestItem>(&item, funded)
            .expect("the exact bare payload can be netted")
            .into_claim();
        assert_eq!(
            remaining,
            full.checked_sub(funded).expect("the subtraction is exact")
        );
        assert!(matches!(
            measure_serialized_mailbox_item_after_funded::<TestItem>(
                &item,
                ResourceClaim::single(ResourceClass::SocketOrHandle, 1),
            ),
            Err(ResourceMailboxItemError::Claim(
                ResourceClaimArithmeticError::Underflow {
                    dimension: ResourceClass::SocketOrHandle,
                }
            ))
        ));
    }

    #[test]
    fn funded_builder_accepts_exact_remaining_grant_and_holds_payload_after_pop() {
        let item = TestItem(vec![4; 24]);
        let (tx, mut rx, provider, payload_lease, builds, funded) = funded_fixture(&item, false);
        let before_send = provider.in_use();
        tx.send_building(FundedCountingBuilder {
            item: item.clone(),
            funded,
            builds: std::sync::Arc::clone(&builds),
        })
        .expect("the exact remaining grant admits the outer value");
        let delivery = rx.try_recv().expect("the admitted value is queued");
        assert_eq!(
            builds.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "construction occurs only after exact subtraction and admission"
        );
        drop(delivery);
        assert_eq!(
            provider.in_use(),
            before_send,
            "popping releases only the outer mailbox charge; the upstream payload remains funded"
        );
        drop(tx);
        drop(rx);
        let with_payload = provider.in_use();
        drop(payload_lease);
        assert_ne!(
            provider.in_use(),
            with_payload,
            "the independently funded payload reservation outlives mailbox delivery"
        );
    }

    #[test]
    fn funded_builder_one_unit_short_refuses_without_building() {
        let item = TestItem(vec![5; 24]);
        let (tx, mut rx, provider, payload_lease, builds, funded) = funded_fixture(&item, true);
        assert!(matches!(
            tx.send_building(FundedCountingBuilder {
                item,
                funded,
                builds: std::sync::Arc::clone(&builds),
            }),
            Err(ResourceMailboxAdmissionError::Pressure(_))
        ));
        assert_eq!(
            builds.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "an admission refusal never constructs the outer value"
        );
        assert!(rx.try_recv().is_none());
        drop(tx);
        drop(rx);
        drop(payload_lease);
        let _ = provider;
    }

    #[tokio::test]
    async fn dropping_the_last_sender_wakes_the_receiver_closed() {
        let (tx, mut rx, _provider) = fixture(None);
        let last = tx.clone();
        drop(tx);
        drop(last);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .expect("last-sender close wakes the receiver")
                .is_none()
        );
    }

    #[tokio::test]
    async fn dropping_the_receiver_wakes_a_sender_waiting_for_close() {
        let (tx, rx, _provider) = fixture(None);
        let waiter = tokio::spawn(async move { tx.closed().await });
        tokio::task::yield_now().await;
        drop(rx);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("receiver drop wakes the sender-side close witness")
            .expect("the close witness task completes");
    }

    #[test]
    fn a_value_arrival_never_wakes_the_close_witness() {
        use std::future::Future as _;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll};

        struct WakeCounter(AtomicUsize);
        impl futures::task::ArcWake for WakeCounter {
            fn wake_by_ref(counter: &std::sync::Arc<Self>) {
                counter.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let item = TestItem(vec![6; 32]);
        let (tx, mut rx, _provider) = fixture(Some(&item));
        let close_probe = tx.clone();
        let close_wakes = std::sync::Arc::new(WakeCounter(AtomicUsize::new(0)));
        let close_waker = futures::task::waker(std::sync::Arc::clone(&close_wakes));
        let mut close_context = Context::from_waker(&close_waker);
        let mut close_waiter = Box::pin(close_probe.closed());
        assert!(matches!(
            close_waiter.as_mut().poll(&mut close_context),
            Poll::Pending
        ));

        tx.send(item.clone()).expect("fixture funds one item");
        assert_eq!(
            close_wakes.0.load(Ordering::SeqCst),
            0,
            "a value notification belongs only to the receiver"
        );

        let receiver_waker = futures::task::noop_waker();
        let mut receiver_context = Context::from_waker(&receiver_waker);
        let mut receive = Box::pin(rx.recv());
        let Poll::Ready(Some(delivery)) = receive.as_mut().poll(&mut receiver_context) else {
            panic!("the accepted value is immediately available to its receiver");
        };
        assert_eq!(delivery.into_parts().0, item);
        drop(receive);
        drop(rx);
        assert_eq!(
            close_wakes.0.load(Ordering::SeqCst),
            1,
            "receiver drop wakes the separate close witness exactly once"
        );
        assert!(matches!(
            close_waiter.as_mut().poll(&mut close_context),
            Poll::Ready(())
        ));
    }

    #[tokio::test]
    async fn close_preserves_an_accepted_entry_until_it_is_drained() {
        let item = TestItem(vec![8; 32]);
        let (tx, mut rx, _provider) = fixture(Some(&item));
        tx.send(item).expect("fixture funds one accepted item");
        tx.close();

        let delivered = rx
            .recv()
            .await
            .expect("close does not discard an already accepted item");
        assert_eq!(delivered.into_parts().0, TestItem(vec![8; 32]));
        assert!(
            rx.recv().await.is_none(),
            "the receiver observes closure only after the accepted prefix drains"
        );
    }

    #[test]
    fn dropping_the_receiver_releases_every_queued_entry() {
        let item = TestItem(vec![9; 32]);
        let (tx, rx, provider) = fixture(Some(&item));
        let before = provider.in_use();
        tx.send(item).expect("fixture funds one item");
        assert_ne!(provider.in_use(), before);
        drop(rx);
        assert_eq!(provider.in_use(), before);
        assert!(matches!(
            tx.send(TestItem(vec![1])),
            Err(ResourceMailboxSendError::Closed(_))
        ));
    }

    /// A delivered value that reports what the provider still showed at the
    /// moment it was destroyed.
    ///
    /// The retention is the thing under test, so it must not be observable by
    /// asking the delivery — a control that read the lease would prove only
    /// that the field existed. This reads the *provider*, from inside the
    /// value's own `Drop`, which is the one instant that distinguishes a
    /// retention released before the value from one released after it.
    struct FundingWitness {
        bytes: Vec<u8>,
        provider: super::super::FiniteResourceProvider,
        at_drop: std::sync::Arc<parking_lot::Mutex<Option<ResourceClaim>>>,
    }

    unsafe impl ResourceMailboxItem for FundingWitness {
        fn measured_claim(&self) -> Result<MailboxMeasurement<Self>, ResourceMailboxItemError> {
            MailboxMeasurement::from_parts(0, self.bytes.len(), 0)
        }
    }

    impl Drop for FundingWitness {
        fn drop(&mut self) {
            *self.at_drop.lock() = Some(self.provider.in_use());
        }
    }

    /// **Review control 1 of 4.** The value is destroyed while its retention is
    /// still live, not after.
    ///
    /// This is the whole delivery invariant stated as an observation: a
    /// `ResourceMailboxDelivery` declares `value` before `retention`, so the
    /// value goes first and the funding is returned only once it is gone.
    /// Swapping those two fields — which is the entire defect, and which no
    /// type checks — leaves the provider showing the item's charge already
    /// returned by the time the bytes are being freed.
    #[test]
    fn v4_r3_core_f1_a_delivered_value_is_still_funded_while_it_is_destroyed() {
        let at_drop = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let (tx, mut rx, provider) = {
            // Sized against a throwaway that reports into its own slot: this one
            // is destroyed as the block ends, and writing that into `at_drop`
            // would answer the question before the control has asked it.
            let probe = FundingWitness {
                bytes: vec![3; 48],
                provider: super::super::FiniteResourceProvider::new(ResourceClaim::ZERO),
                at_drop: std::sync::Arc::new(parking_lot::Mutex::new(None)),
            };
            fixture_for(Some(&probe))
        };
        let baseline = provider.in_use();
        // Matched rather than unwrapped. A refusal hands the witness back
        // inside the error, so `expect` would need `ResourceMailboxSendError<
        // FundingWitness>: Debug` and therefore `FundingWitness: Debug` — a
        // derive this fixture must not have, because the witness holds the very
        // provider it reads in its `Drop` and printing one would print the
        // other. The arm below still fails the control on a refused send, so
        // nothing is weakened to get there.
        match tx.send(FundingWitness {
            bytes: vec![3; 48],
            provider: provider.clone(),
            at_drop: std::sync::Arc::clone(&at_drop),
        }) {
            Ok(()) => {}
            Err(_) => panic!("the fixture funds exactly one witness"),
        }
        let admitted = provider.in_use();
        assert_ne!(
            admitted, baseline,
            "the send must actually have charged something, or this control \
             observes nothing"
        );

        let delivery = rx
            .try_recv()
            .expect("the accepted witness is delivered whole");
        assert!(
            at_drop.lock().is_none(),
            "the witness is still alive — nothing has been destroyed yet"
        );

        // What the delivery actually holds, which is not what the send charged.
        // `admitted` includes the queue node, and `try_recv` gave that node back
        // as it removed the entry — so the reading to compare the value's own
        // destruction against is this one, taken while the delivery is alive and
        // holding exactly its off-node retention. Comparing against `admitted`
        // would be asserting that a delivery still owns a node the mailbox no
        // longer has, which is a different and false claim.
        let delivered_live = provider.in_use();
        assert_ne!(
            delivered_live, baseline,
            "non-vacuity: the delivery still holds its retention, so there is \
             something for the observation below to be about"
        );
        assert_ne!(
            delivered_live, admitted,
            "non-vacuity: and the pop really did return the queue node, so this \
             reading is the retention alone rather than the send's total"
        );
        drop(delivery);

        let observed = at_drop
            .lock()
            .expect("the delivered value was destroyed exactly once");
        assert_eq!(
            observed, delivered_live,
            "the retention was already released while the value it funds was \
             still being destroyed"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "and once both are gone the charge is returned in full"
        );
    }

    /// The terminal-effect seam has exactly the callers its contract names.
    ///
    /// `run_terminal_effect` is safe because of *who calls it*, not because of
    /// its signature: an effect can spawn the value onto another task and still
    /// return `()`, which would outlive the claim just as a returned value
    /// would. The doc therefore names its callers, and a claim about a caller
    /// list is worth exactly as much as something that checks it.
    ///
    /// **Counted over the implementation sources.** The engine's own test
    /// module reaches the seam as well, and legitimately: handing
    /// `handle_command` an owned command is what the seam is for, and no other
    /// route out of a delivery is public. But a caller under `mod tests` must
    /// not be able to raise the number this census exists to hold down, so the
    /// file is cut at its test module; the two matching engine helpers are
    /// counted alongside the four supervisor consumers.
    /// Promotion handling consumes each owned delivery inside the same
    /// terminal effect, so these are intentional consumers rather than leaks.
    /// Test coverage of the seam is then asserted separately, as coverage
    /// rather than as census.
    ///
    /// A real check with two stated limits. It cannot see a call added in some
    /// *other* module, so it catches drift in the checked implementation set.
    /// The cut is at the test module, not at every `#[cfg(test)]` item, so a helper gated
    /// outside that module still counts: that is why the checked count is six.
    #[test]
    fn the_terminal_effect_seam_has_exactly_its_documented_callers() {
        const ENGINE: &str = include_str!("../engine/mod.rs");
        const SUPERVISOR: &str = include_str!("../engine/supervisor.rs");
        const SEAM: &str = ".run_terminal_effect(";

        // Fail closed. A census taken over the wrong slice reads exactly like a
        // passing one while measuring nothing, so an absent or repeated
        // boundary is the failure itself rather than a reason to fall back to
        // the whole file. Matched line by line so a checkout with CRLF endings
        // cuts in the same place as one without.
        let lines: Vec<&str> = ENGINE.lines().collect();
        let boundaries: Vec<usize> = lines
            .windows(2)
            .enumerate()
            .filter(|(_, pair)| pair[0].trim() == "#[cfg(test)]" && pair[1].trim() == "mod tests {")
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            boundaries.len(),
            1,
            "the census cuts engine/mod.rs at its `#[cfg(test)] mod tests` \
             boundary and found {} of them. None means the marker moved and \
             this control is counting an unknown slice; more than one means the \
             cut is ambiguous. Either way the counts below would mean nothing, \
             so it fails here instead of reporting a number it cannot justify",
            boundaries.len()
        );
        let boundary = boundaries[0];

        let production: usize = lines[..boundary]
            .iter()
            .map(|line| line.matches(SEAM).count())
            .sum();
        let supervisor_calls: usize = SUPERVISOR
            .lines()
            .map(|line| line.matches(SEAM).count())
            .sum();
        assert_eq!(
            production + supervisor_calls,
            6,
            "the seam's contract names six checked implementation call sites; \
             test module: the driver loop's `NetworkCmd`, \
             `SpeculativePromotionCmd`, and `EphemeralIngress` arms, plus the \
             matching `NetworkCmd` and `SpeculativePromotionCmd` arms in the \
             test command driver. Each consumes its owned delivery inside the \
             terminal effect; an additional route still needs the same review \
             before this number moves"
        );

        let under_test: usize = lines[boundary..]
            .iter()
            .map(|line| line.matches(SEAM).count())
            .sum();
        assert!(
            under_test >= 1,
            "the engine's test module reaches the seam too, and that is the \
             point: a control that replays a command has to consume a delivery \
             the way production does. If this reaches zero, either the control \
             is gone or it found a way to take a delivery apart without the \
             seam — and the second would be the defect the seam exists to \
             prevent, arriving through the door marked `test`"
        );
    }
}
