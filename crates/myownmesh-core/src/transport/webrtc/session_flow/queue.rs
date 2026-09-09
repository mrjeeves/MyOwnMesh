//! Where an outbound flow's units wait, and what wakes the pump that drains
//! them.
//!
//! One direction only. An outbound flow is the sole destination for what an
//! application sends on it, so its units wait where they were sent; inbound
//! units have exactly one consumer for the whole session and wait on that
//! consumer's queue instead. The asymmetry is stated in [`FlowQueue`] and is the
//! correction that removed the second retained copy of every arrival.
//!
//! Closure here is mechanical rather than announced: dropping the queue is the
//! wake, and the pump learns its flow is gone by failing to upgrade a `Weak`.
//! Nothing sets a flag and nothing emits a retirement event, so there is no
//! second fact that could disagree with the drop.

use super::*;

/// One unit waiting in a flow's queue, holding the bytes it is accounted for.
///
/// The lease travels with the unit and is released when the unit is taken or
/// when the queue is dropped. That is what makes teardown release memory
/// without a separate sweep: dropping the flow drops the queue drops the
/// leases.
pub(super) struct QueuedUnit<T> {
    pub(super) unit: T,
    _payload: RealtimePayloadLease,
}

/// The in-flight count has its own allocation because a detached native unit
/// may outlive the queue/flow that issued it.  The lease travels inside this
/// shared counter, so the count and its funding remain live through the final
/// unit drop rather than being backed by the queue's inline root alone.
pub(super) struct InFlightCounter {
    value: std::sync::atomic::AtomicUsize,
    _root: crate::resource::ResourceLease,
}

impl InFlightCounter {
    pub(super) fn load(&self) -> usize {
        self.value.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(super) fn finish(&self) {
        let previous = self.value.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        debug_assert!(previous > 0, "opaque in-flight count underflow");
    }
}

/// A flow's own queue, in its own direction.
///
/// Deliberately not the inbound `QueuedTransportEvent` path. That queue
/// carries `TransportEvent` into the engine callback pump and only knows the
/// codec-specific sample variants; putting outbound units on it would send
/// them the wrong way through a type that cannot describe them.
///
/// Bounded by resource accounting rather than by a count. Every unit holds a
/// payload lease taken before it is queued and sits in a node funded by its own
/// record lease, so the ceiling is the owner's existing budget and there is no
/// new queue-depth constant to choose.
///
/// A [`crate::resource::LeasedQueue`] rather than a `VecDeque` for the same
/// reason: a ring's spare capacity belongs to no entry, so no entry's departure
/// could release it. Here one queued unit is one funded allocation, and taking
/// it releases exactly that.
///
/// **Two blocks, two leases, because they have two lifetimes.** This record is
/// reached only through the flow's own strong pointer — a pump holds a `Weak` —
/// so its lease is stored here and released exactly at the close. The `ready`
/// wake is handed to that pump strongly, because it has to survive this record
/// in order to deliver the wake announcing this record is gone, so its lease
/// lives inside *it* and is released by whichever of the two lets go last.
pub(super) struct RealtimeFlowQueue<T> {
    units: SyncMutex<crate::resource::LeasedQueue<QueuedUnit<T>>>,
    ready: Arc<LeasedWake>,
    /// Units detached for a native handoff remain counted until their owned
    /// entry is dropped after the write reaches a terminal result.
    in_flight: Arc<InFlightCounter>,
    /// Whether a pump has already been issued for this queue.
    ///
    /// One permit from `Drop` wakes one waiter, so "at most one pump" is not a
    /// convention here — it is the precondition that makes closure reliable,
    /// and it is enforced rather than assumed.
    pump_issued: std::sync::atomic::AtomicBool,
    /// Sticky native failure. Once a real write fails, later accepted queue
    /// entries would otherwise accumulate behind a pump that has terminated.
    pump_failed: std::sync::atomic::AtomicBool,
    /// Never read; it owns the block these fields live in. Last, so everything
    /// it accounts for is destroyed before the funding goes back.
    _root: crate::resource::ResourceLease,
}

/// Dropping the queue wakes its pump — durably.
///
/// This is what makes closure mechanical rather than announced. There is no
/// retirement event and no `closed` flag to set: dropping the promoted session
/// drops the flow set, the flows, and their queues, and this is the wake. A
/// flag would be a second fact that could disagree with the drop; the wake
/// cannot, because it *is* the drop.
///
/// **`notify_one`, deliberately, not `notify_waiters`.** `notify_waiters`
/// wakes only tasks already registered and stores nothing, which loses the
/// wake in exactly the gap a pump spends most of its life in: it observes an
/// empty queue, and the drop lands before it registers. It would then park on
/// a queue that no longer exists, forever. `notify_one` stores a permit when
/// nobody is waiting, so the pump's next `notified()` returns immediately and
/// it sees the failed upgrade. One permit is enough because a queue issues at
/// most one pump — see [`RealtimeFlowQueue::claim_pump`].
impl<T> Drop for RealtimeFlowQueue<T> {
    fn drop(&mut self) {
        self.ready.notify().notify_one();
    }
}

impl<T> RealtimeFlowQueue<T> {
    /// Fund both of this queue's blocks, then allocate them.
    ///
    /// The wake first, because the queue holds it: if this record's own claim is
    /// refused, the wake minted above is dropped here and its funding goes
    /// straight back, so a refused open retains neither block.
    ///
    /// Both claims are taken **before** either allocation exists, which is what
    /// makes the refusal honest — a provider under pressure declines and the
    /// open fails closed, rather than the constructor having already boxed
    /// something nothing accounted for.
    pub(super) fn mint(registry: &RealtimeFlowRegistry) -> FlowResult<Arc<Self>> {
        let ready = LeasedWake::mint(registry)?;
        let root = registry
            .acquire_flow_root(std::mem::size_of::<Self>())
            .map_err(realtime_drop_refusal)?;
        let in_flight_root = registry
            .acquire_flow_root(std::mem::size_of::<InFlightCounter>())
            .map_err(realtime_drop_refusal)?;
        Ok(Arc::new(Self {
            units: SyncMutex::new(crate::resource::LeasedQueue::new()),
            ready,
            in_flight: Arc::new(InFlightCounter {
                value: std::sync::atomic::AtomicUsize::new(0),
                _root: in_flight_root,
            }),
            pump_issued: std::sync::atomic::AtomicBool::new(false),
            pump_failed: std::sync::atomic::AtomicBool::new(false),
            _root: root,
        }))
    }

    /// Claim the right to be this queue's pump. Answers `false` if one was
    /// already issued.
    ///
    /// The single permit stored by `Drop` wakes one waiter. A second pump on
    /// the same queue would be the waiter that never wakes, so the invariant
    /// is enforced here rather than left to callers.
    pub(super) fn claim_pump(&self) -> bool {
        if self.pump_failed.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        !self
            .pump_issued
            .swap(true, std::sync::atomic::Ordering::AcqRel)
    }

    pub(super) fn is_failed(&self) -> bool {
        self.pump_failed.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(super) fn mark_failed(&self) {
        self.pump_failed
            .store(true, std::sync::atomic::Ordering::Release);
        self.ready.notify().notify_waiters();
    }

    /// Append one unit. Synchronous and lock-scoped: the guard is dropped
    /// before the wake, so a waiting drainer never contends with the push that
    /// woke it.
    ///
    /// Two leases, because there are two allocations: `payload` owns the bytes
    /// and `record` owns the node holding them. Both were acquired before this
    /// was called, which is why appending cannot fail — the refusal already
    /// happened, at the point where it could still be reported.
    pub(super) fn push(
        &self,
        unit: T,
        payload: RealtimePayloadLease,
        record: crate::resource::ResourceLease,
    ) {
        {
            let mut units = self.units.lock();
            units.push(
                QueuedUnit {
                    unit,
                    _payload: payload,
                },
                record,
            );
        }
        self.ready.notify().notify_one();
    }

    /// Take the oldest unit, if any. Never blocks and never awaits — the
    /// caller may be holding the registry mutation lock.
    ///
    /// Both of that entry's leases are released here: the record when the node
    /// leaves the queue, the payload when the wrapper is unpacked.
    pub(super) fn pop(&self) -> Option<T> {
        self.units.lock().pop_front().map(|queued| queued.unit)
    }

    /// Detach the full funded queue entry for a native handoff. The payload
    /// lease and queue-node lease remain coupled inside the entry's value and
    /// guard until the pump's native write completes.
    pub(super) fn pop_owned(
        &self,
    ) -> Option<crate::resource::queue::LeasedQueueEntry<QueuedUnit<T>>> {
        let mut units = self.units.lock();
        let entry = units.pop_front_owned()?;
        self.in_flight
            .value
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Some(entry)
    }

    pub(super) fn in_flight(&self) -> usize {
        self.in_flight.load()
    }

    pub(super) fn in_flight_token(&self) -> Arc<InFlightCounter> {
        Arc::clone(&self.in_flight)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.units.lock().is_empty()
    }

    /// A handle a pump can await on without holding any lock of this flow.
    ///
    /// The clone carries the wake's own funding with it, so a pump that outlives
    /// this queue is holding a block that is still paid for rather than one the
    /// close released out from under it.
    pub(super) fn ready(&self) -> Arc<LeasedWake> {
        Arc::clone(&self.ready)
    }
}

/// What a flow owns in its own direction — which, one way, is a queue and the
/// other way is nothing.
///
/// **Only outbound has a queue, and the asymmetry is the point.** An outbound
/// flow is the sole destination for what an application sends on it, so its
/// units wait where they were sent. Inbound units have exactly one consumer for
/// the whole session, so they wait in that consumer's one queue rather than in
/// per-flow stores a session-wide reader would then have to be told about
/// separately. Giving inbound a queue here as well is what produced two
/// retained copies of one arrival — the unit in the flow's store and a notice
/// of it in the session's — where a consumer could take the notice and find the
/// unit gone.
///
/// The outbound queue is held behind `Arc` so a pump can observe its death
/// through a `Weak` rather than be told about it.
pub(super) enum FlowQueue {
    Outbound(Arc<RealtimeFlowQueue<RealtimeSendUnit>>),
    /// An outbound opaque flow uses the same provider-funded queue shape as
    /// RTP, but its units carry no pacing or codec metadata.  The persistent
    /// native opaque lane is drained by the worker; opening another logical
    /// flow never allocates another native channel.
    OpaqueOutbound(Arc<RealtimeFlowQueue<OpaqueSendUnit>>),
    /// Nothing to hold: units for this flow are funded and retained on the
    /// session's one inbound queue, which is where its only consumer reads.
    Inbound,
}

/// Everything the outbound pump needs, and deliberately nothing more.
///
/// The queue is `Weak`: the pump never keeps a flow alive. When the session
/// retires, the flow set drops, the queue drops, `ready` fires from the
/// queue's `Drop`, the pump wakes, `upgrade` answers `None`, and the pump
/// ends. No retirement event, no flag, no ordering to get right.
///
/// The pump holds `ready` as a strong `Arc` on purpose — it has to survive the
/// queue in order to deliver the very wake that announces the queue is gone.
pub(crate) struct RealtimeOutboundPump {
    pub(super) queue: std::sync::Weak<RealtimeFlowQueue<RealtimeSendUnit>>,
    pub(super) ready: Arc<LeasedWake>,
    /// The provider-owned tail witness stays with the actual pump task until
    /// native retirement is terminal.  Controls construct a pump without a
    /// native task, hence the option on this provider-internal test shape.
    pub(super) _tail: Option<super::RealtimeNativeTail>,
}

impl RealtimeOutboundPump {
    /// Take the next unit to write, or answer why there is none.
    ///
    /// `Closed` is terminal: the flow is gone and the pump must stop rather
    /// than wait again. `Empty` means park on [`Self::ready`] and retry.
    pub(in crate::transport::webrtc) fn next(&self) -> RealtimePumpStep {
        let Some(queue) = self.queue.upgrade() else {
            return RealtimePumpStep::Closed;
        };
        match queue.pop() {
            Some(unit) => RealtimePumpStep::Unit(unit),
            None => RealtimePumpStep::Empty,
        }
    }

    /// Await the next wake — a push, or the queue's own drop.
    pub(in crate::transport::webrtc) async fn ready(&self) {
        self.ready.notify().notified().await;
    }
}

/// The single flow-owned drainer for an opaque logical flow. The queue stores
/// each unit's exact coordinate/mode snapshot, so this pump does not carry a
/// second mutable flow record or let a Change rewrite an already-admitted
/// unit's wire identity.
pub(crate) struct OpaqueOutboundPump {
    pub(super) queue: std::sync::Weak<RealtimeFlowQueue<OpaqueSendUnit>>,
    pub(super) ready: Arc<LeasedWake>,
    pub(super) _tail: super::RealtimeNativeTail,
}

impl OpaqueOutboundPump {
    pub(crate) fn next(&self) -> OpaquePumpStep {
        let Some(queue) = self.queue.upgrade() else {
            return OpaquePumpStep::Closed;
        };
        match queue.pop_owned() {
            Some(entry) => {
                let unit = &entry.value().unit;
                OpaquePumpStep::Unit(OpaqueOutboundUnit {
                    data: unit.data.clone(),
                    mode: unit.mode,
                    direction: unit.direction,
                    coordinate: unit.coordinate,
                    max_unit_bytes: unit.max_unit_bytes,
                    in_flight: queue.in_flight_token(),
                    _entry: entry,
                })
            }
            None => OpaquePumpStep::Empty,
        }
    }

    pub(crate) async fn ready(&self) {
        self.ready.notify().notified().await;
    }

    pub(crate) fn mark_failed(&self) {
        if let Some(queue) = self.queue.upgrade() {
            queue.mark_failed();
        }
    }

    /// Complete the common native-write terminal boundary.  Production uses
    /// this immediately after the real data-channel future resolves; the
    /// boolean keeps the provider's native error type out of the flow queue.
    /// A failed write permanently closes admission for this logical queue.
    pub(crate) fn native_write_finished(&self, success: bool) -> bool {
        if !success {
            self.mark_failed();
        }
        success
    }
}

// This enum intentionally carries the funded detached unit inline. Boxing it
// would add an allocation and move custody outside the existing pump claim.
#[allow(clippy::large_enum_variant)]
pub(crate) enum OpaquePumpStep {
    Unit(OpaqueOutboundUnit),
    Empty,
    Closed,
}

/// What one turn of the outbound pump found.
pub(in crate::transport::webrtc) enum RealtimePumpStep {
    Unit(RealtimeSendUnit),
    Empty,
    /// The flow is gone. Terminal.
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real flow queue's sticky terminal bit is the refusal boundary after
    /// a native pump write fails.  Once set, a replacement pump cannot claim a
    /// queue that may still contain accepted work from the dead pump.
    #[test]
    fn v4_opaque_pump_failure_latch_refuses_reclaim() {
        let (registry, _resources) =
            RealtimeFlowRegistry::elastic_for_control(super::super::super::elastic_control_grant());
        let queue = RealtimeFlowQueue::<OpaqueSendUnit>::mint(&registry)
            .expect("the finite control provider funds one opaque queue");
        assert!(queue.claim_pump(), "the first native pump owns the queue");
        queue.mark_failed();
        assert!(queue.is_failed());
        assert!(
            !queue.claim_pump(),
            "a failed native pump cannot be replaced behind accepted queue work"
        );
    }
}
