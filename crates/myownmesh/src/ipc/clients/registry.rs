//! Every operation the registry performs on its tables.
//!
//! A descendant of the module that declares the state, which is what lets this
//! file hold the whole of `impl ClientRegistry` without a single field being
//! widened: a child sees its parent's private items, while a sibling or an
//! outside caller still sees only what the parent chose to publish. The tables,
//! the handle's own maps and the pending records stay exactly as private as they
//! were.
//!
//! The declarations stayed behind deliberately. What a `RegistryTables` *is* —
//! five leased maps under one lock — is a fact a reader needs before any of
//! this makes sense, and it belongs beside the claims that fund them. What the
//! registry *does* with them is this file, and it was two thirds of a file
//! nobody could hold in their head.
//!
//! Three helpers open the file rather than sitting in the parent, because all
//! three take `&mut RegistryTables` and have no meaning without it: they are
//! parts of these operations that happen to be shared between them.

use super::*;

/// Drop one client out of one channel's subscriber set, and drop the set itself
/// once it empties. Answers whether the channel now has no subscribers.
///
/// Removing the empty set is not tidiness: the previous shape left one behind
/// for every channel any client had ever subscribed to, so the table only ever
/// grew, and it grew on names local clients chose.
fn remove_channel_member(
    tables: &mut RegistryTables,
    key: &ClaimKey,
    membership: ChannelMembershipId,
) -> Option<RetiredRoute> {
    let empty = match tables.channel_subs.get_mut(key) {
        Some(route) => {
            route.members.remove(&membership);
            !route.members.any_value(|_| true)
        }
        None => return None,
    };
    if !empty {
        return None;
    }
    // The route goes with its last member, and its pump comes back to the
    // caller rather than being dropped here. Dropping a `JoinHandle` detaches
    // the task instead of stopping it, so a route torn down without the caller
    // cancelling and joining would leave a pump running against a channel
    // nobody is subscribed to.
    // Retired rather than dropped, and returned rather than finished here: both
    // stages owe somebody something — a pump owes a join, an unfinished install
    // owes its followers an answer — and paying either means awaiting or
    // notifying, which this module does not do under the tables lock.
    Some(RetiredRoute::from_state(
        tables.channel_subs.remove(key)?.state,
    ))
}

/// Detach every match under an acquisition the caller already holds.
///
/// For the one sweep that cannot alternate lock-and-settle: displacing a method
/// claim has to remove the previous owner's in-flight calls under the *same*
/// acquisition that moved the claim, or a call could be admitted against an
/// ownership state that is half-updated. So this returns the records and the
/// caller settles them after releasing — settling here would deadlock for the
/// reason [`settle_pending_where`] gives.
///
/// No key clones: `pop_first_where` detaches matches in place. What is left is
/// one node per record, and each record carries the lease that funds its own
/// node — acquired when the call was filed, moved into the node here, released
/// after that node is freed. A `Vec` cannot carry this: its buffer is sized by
/// capacity rather than by length, and its `Drop` destroys the records before it
/// frees the buffer they sat in.
fn take_pending_under(
    tables: &mut RegistryTables,
    mut names: impl FnMut(&PendingKey, &PendingRecord) -> bool,
) -> crate::ipc::LeasedList<PendingRecord> {
    let mut taken = crate::ipc::LeasedList::new();
    while let Some((_key, mut pending)) = tables.exact_pending_inbound.pop_first_where(&mut names) {
        pending.cancelled.cancel();
        let node = pending
            .cleanup
            .take()
            .expect("a filed pending record holds the funding for its own sweep node");
        taken.push(pending, node);
    }
    taken
}

/// Settle every pending operation the predicate names, one at a time.
///
/// The lock is taken per record and released before each settlement, and that
/// alternation is the point rather than an inefficiency. Settling wakes the task
/// waiting on the operation, and waking it under this lock invites it straight
/// back into a method that takes the same lock — which this mutex, being unfair
/// to no one and reentrant for no one, would answer with a deadlock.
///
/// `pop_first_where` detaches only the first match and leaves every rejected
/// node in the allocation it already had, so this needs no key clone, no
/// snapshot vector, and no reinsertion. A pending call is therefore charged for
/// exactly the two copies of its coordinates that exist: the map's and the
/// ticket's.
///
/// Nothing here can be refused, because nothing here allocates. A disconnect
/// path that cannot allocate cannot be told no.
fn settle_pending_where(
    tables: &parking_lot::Mutex<RegistryTables>,
    mut names: impl FnMut(&PendingKey, &PendingRecord) -> bool,
    reason: &str,
) {
    loop {
        let taken = {
            let mut guard = tables.lock();
            guard.exact_pending_inbound.pop_first_where(&mut names)
        };
        let Some((_key, pending)) = taken else {
            return;
        };
        pending.cancelled.cancel();
        settle_one(pending, reason);
    }
}

/// Settle one taken operation truthfully, after the tables have been released.
///
/// A single-shot awaiter is told why in words that reach the calling peer. A
/// stream sender is dropped without a terminal item, which core reports to the
/// peer as a failed stream — correct, because it is one: the client that was
/// producing the stream is no longer entitled to finish it.
fn settle_one(pending: PendingRecord, reason: &str) {
    match pending.effect {
        PendingInbound::Single(tx) => {
            let _ = tx.send(Err(reason.to_string()));
        }
        PendingInbound::Stream(tx) => drop(tx),
    }
}

/// Refuse anything new once the runtime has left `Running`.
///
/// Taken against tables the caller already holds, never by locking again. The
/// whole reason the lifecycle lives under this mutex is that the check and the
/// write it guards must be one critical section; a helper that re-locked would
/// reintroduce exactly the window the placement was chosen to remove.
fn admitting(tables: &RegistryTables) -> Result<(), IpcAdmissionError> {
    match tables.lifecycle {
        Lifecycle::Running => Ok(()),
        Lifecycle::Closing | Lifecycle::Closed => Err(IpcAdmissionError::Closing),
    }
}

impl ClientRegistry {
    /// One registry over one acquisition port.
    ///
    /// No queue sizing to select: the inbound RPC stream queue is a resource
    /// mailbox, so its capacity is the grant rather than an item count.
    pub fn new(resources: LocalApplicationResourceScope) -> Result<Self, IpcAdmissionError> {
        Self::try_over(RegistryResources::Application(resources))
    }

    /// A registry funded by a provider this control owns outright.
    ///
    /// `grant` is the whole budget, so sizing it just above or just below the
    /// claim under test is what makes a refusal attributable to that claim
    /// rather than to slack the fixture happened to have. Nothing here is
    /// installed process-wide: this registry races no other control and no other
    /// control can exhaust it.
    #[cfg(test)]
    pub fn over_grant(grant: ResourceClaim) -> Self {
        let custody = myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
            final_watchdog_claim().expect("the final watchdog claim is representable"),
        )
        .expect("the final watchdog charge is representable");
        let grant = grant
            .checked_add(custody)
            .expect("the test grant includes final watchdog custody");
        let provider = myownmesh_core::FiniteResourceProvider::new(grant);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the control grant funds its own process scope");
        let scope = port.process_scope();
        Self::over(RegistryResources::Isolated {
            _provider: provider,
            port,
            scope,
        })
    }

    #[cfg(test)]
    fn over(resources: RegistryResources) -> Self {
        Self::try_over(resources).expect("the test registry's final watchdog custody starts")
    }

    fn try_over(resources: RegistryResources) -> Result<Self, IpcAdmissionError> {
        let final_watchdog_custody = Some(FinalWatchdogCustody::reserve(&resources)?);
        Ok(Self {
            inner: Arc::new(RegistryInner {
                resources,
                next_id: AtomicU64::new(0),
                next_call_stream_id: AtomicU64::new(0),
                next_operation_id: AtomicU64::new(0),
                next_membership_id: AtomicU64::new(0),
                next_handler_generation: AtomicU64::new(0),
                idle: tokio::sync::Notify::new(),
                closing: tokio::sync::Notify::new(),
                #[cfg(test)]
                fanout_barrier: Mutex::new(None),
                #[cfg(test)]
                channel_frames_built: AtomicUsize::new(0),
                tables: Mutex::new(RegistryTables {
                    lifecycle: Lifecycle::Running,
                    live_tasks: 0,
                    watchdogs: crate::ipc::LeasedList::new(),
                    final_watchdog_custody,
                    clients: LeasedMap::new(),
                    handler_claims: LeasedMap::new(),
                    channel_subs: LeasedMap::new(),
                    exact_pending_inbound: LeasedMap::new(),
                    installed_handlers: LeasedMap::new(),
                }),
            }),
        })
    }

    /// Park the next channel pump at the line after it has selected a
    /// subscriber and before it builds that subscriber's frame.
    ///
    /// See [`FanoutBarrier`]. Installed rather than passed as an argument
    /// because the pump is spawned by production code from a real subscription,
    /// and a control that had to construct the pump itself would not be driving
    /// the production fan-out at all.
    #[cfg(test)]
    pub fn park_fanout_after_selection(&self, barrier: Arc<FanoutBarrier>) {
        *self.inner.fanout_barrier.lock() = Some(barrier);
    }

    /// Pass the installed fan-out barrier, if a control installed one.
    ///
    /// The `Arc` is cloned out and the lock released before anything is
    /// awaited, so a parked pump holds no registry lock of any kind -- which is
    /// exactly the property the control that installs one is asserting.
    #[cfg(test)]
    pub(crate) async fn pass_fanout_barrier(&self) {
        let barrier = self.inner.fanout_barrier.lock().clone();
        if let Some(barrier) = barrier {
            barrier.pass().await;
        }
    }

    /// The counter one channel pump's frame builder increments, borrowed.
    ///
    /// Handed to the builder rather than reached for by it: the builder is a row
    /// of borrows with no way back to a registry, and giving it one would be a
    /// coupling that exists only for the test.
    #[cfg(test)]
    pub(crate) fn channel_frame_build_counter(&self) -> &AtomicUsize {
        &self.inner.channel_frames_built
    }

    /// How many `ChannelInbound` frames this registry's pumps have built.
    ///
    /// A total rather than a flag, and read before and after by whoever asks:
    /// "zero more were built" and "exactly one more was built" are the two
    /// statements a pressure control needs, and neither is expressible by a
    /// boolean.
    #[cfg(test)]
    pub(crate) fn channel_frames_built(&self) -> usize {
        self.inner
            .channel_frames_built
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Issue one acquisition subtree under this registry's own port.
    ///
    /// For things with a lifetime of their own — an inbound stream's queue is
    /// the one caller today — so that everything the thing holds is released as
    /// a unit when it ends, rather than lingering in the registry's scope until
    /// the daemon stops.
    /// Acquire one already-derived claim against this registry's own port.
    ///
    /// For funding whose shape is decided by the type being funded rather than
    /// by this registry — a [`LeasedList`] node is the live case, and its size
    /// is the list's to state, not this module's. Narrower than
    /// [`Self::child_resources`], which hands out a whole scope: this admits one
    /// claim and answers with one lease.
    ///
    /// Not gated on the lifecycle. The callers are the control runtime's own
    /// bookkeeping, and a registry that refused to fund the storage its drain
    /// hands back would be refusing to be shut down.
    ///
    /// [`LeasedList`]: crate::ipc::LeasedList
    pub(crate) fn acquire_claim(
        &self,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, IpcAdmissionError> {
        self.inner
            .resources
            .acquire(claim)
            .map_err(IpcAdmissionError::Resources)
    }

    pub fn child_resources(&self) -> Result<LocalApplicationResourceScope, IpcAdmissionError> {
        self.inner
            .resources
            .child()
            .map_err(IpcAdmissionError::Resources)
    }

    /// Fund one task this registry keeps alive, before it is spawned.
    ///
    /// The lease must be **moved into the task's own future**, so that it is
    /// released exactly when the task stops running — including when the task
    /// is dropped mid-await rather than returning. A lease held anywhere else
    /// would report the task as funded for a lifetime that is not the task's.
    ///
    /// Acquired before `tokio::spawn` rather than inside the future, because a
    /// task that started and then discovered it was unfunded would already be
    /// consuming a runtime worker — the refusal has to happen while there is
    /// still nothing to clean up.
    ///
    /// One owner for all four IPC task kinds — the accepted connection, the
    /// channel pump, the inbound stream watchdog, and the outbound
    /// stream-forwarding task — so the process owner sees one number for daemon
    /// IPC concurrency instead of four that have to be added up.
    /// Where this runtime is in its life, as of this instant.
    ///
    /// A snapshot, and only useful as one: by the time a caller acts on
    /// `Running` the answer may be `Closing`. Every decision that must not race
    /// the transition is taken under the tables lock instead, which is why the
    /// admitting paths below check `lifecycle` themselves rather than calling
    /// this first.
    pub fn lifecycle(&self) -> Lifecycle {
        self.inner.tables.lock().lifecycle
    }

    /// Enter `Closing`, once.
    ///
    /// Answers `true` to exactly one caller. That is the whole point: the drain
    /// that follows unregisters every client, releases every synthetic handler
    /// and closes every realtime flow, and running it twice would try to close
    /// flows that are already closed and forget handlers already forgotten. A
    /// second shutdown signal, a second `serve` on the same registry, or a
    /// racing supervisor gets `false` and does nothing.
    ///
    /// The wake happens after the lock is released. Waking under it would put
    /// every woken task straight into a method that takes the same lock.
    pub fn begin_closing(&self) -> bool {
        {
            let mut tables = self.inner.tables.lock();
            if tables.lifecycle != Lifecycle::Running {
                return false;
            }
            tables.lifecycle = Lifecycle::Closing;
        }
        self.inner.closing.notify_waiters();
        true
    }

    /// What this registry is still holding, for controls that assert it holds
    /// nothing.
    ///
    /// One acquisition over every table plus the task count, so the answer is a
    /// single consistent instant rather than five reads that could disagree.
    /// Counts rather than contents: a control asserting "nothing remains" needs
    /// to be told about a leftover it did not anticipate, and a shape that
    /// returned only the kinds the control asked about would hide exactly that.
    #[cfg(test)]
    pub(crate) fn residue(&self) -> RegistryResidue {
        let tables = self.inner.tables.lock();
        let mut residue = RegistryResidue {
            lifecycle: tables.lifecycle,
            live_tasks: tables.live_tasks,
            watchdogs: tables.watchdogs.len() as u64,
            clients: 0,
            realtime_flows: 0,
            handler_claims: 0,
            installed_handlers: 0,
            channel_subs: 0,
            channel_routes: 0,
            installing_routes: 0,
            pending_inbound: 0,
        };
        tables.clients.for_each(|_, client| {
            residue.clients += 1;
            client.realtime_flows.lock().for_each(|_, _| {
                residue.realtime_flows += 1;
            });
        });
        tables
            .handler_claims
            .for_each(|_, _| residue.handler_claims += 1);
        tables
            .installed_handlers
            .for_each(|_, _| residue.installed_handlers += 1);
        tables.channel_subs.for_each(|_, route| {
            residue.channel_routes += 1;
            if route.is_installing() {
                residue.installing_routes += 1;
            }
            route.members.for_each(|_, _| residue.channel_subs += 1);
        });
        tables
            .exact_pending_inbound
            .for_each(|_, _| residue.pending_inbound += 1);
        residue
    }

    /// What this registry's own provider is holding, for controls that assert an
    /// exact release rather than inferring one from a later admission.
    ///
    /// `None` unless the registry was built by [`Self::over_grant`]. See
    /// [`RegistryResources::in_use`] for why the production arm cannot answer.
    #[cfg(test)]
    pub(crate) fn in_use(&self) -> Option<ResourceClaim> {
        self.inner.resources.in_use()
    }

    /// Enter `Closed` if that is actually true, and answer the state either way.
    ///
    /// Separate from `begin_closing` because the two mean different things to a
    /// reader: `Closing` is "refusing new work", `Closed` is "there is no work
    /// left". Collapsing them would make the state say the second while the
    /// first was still true.
    ///
    /// Conditional rather than an unconditional write, and that is the point:
    /// `Closed` is the strongest claim this type makes, so it is published only
    /// from `Closing` and only with the task count at zero, under the one lock
    /// that owns both. A caller that has not drained, or has not waited, gets
    /// back the state as it really is and can say so. Writing `Closed`
    /// regardless would turn this from a fact into an announcement.
    pub fn finish_closed(&self) -> Lifecycle {
        let mut tables = self.inner.tables.lock();
        if tables.lifecycle == Lifecycle::Closing && tables.live_tasks == 0 {
            tables.lifecycle = Lifecycle::Closed;
        }
        tables.lifecycle
    }

    /// Resolve once no accepted task is still live.
    ///
    /// The loop re-reads the count after every wake rather than trusting the
    /// notification. A `Notify` permit can be consumed by another waiter and a
    /// wake can arrive spuriously, and both of those turn a bare await into a
    /// hang or an early return; re-reading makes the count the authority and the
    /// wake merely the prompt.
    ///
    /// The subscription is taken *before* the count is read. Registering first
    /// is what closes the window where the last task drops between the read and
    /// the await and its wake lands with nobody listening.
    pub async fn wait_for_tasks(&self) {
        loop {
            let idle = self.inner.idle.notified();
            tokio::pin!(idle);
            // `notified()` does not subscribe until it is first polled, so a
            // constructed-but-unpolled future is not listening yet and a
            // `notify_waiters` landing before that first poll is lost forever.
            // `enable` performs the subscription now, which is what makes the
            // check below safe to fail: any wake after this point is held for
            // this future rather than missed.
            idle.as_mut().enable();
            if self.inner.tables.lock().live_tasks == 0 {
                return;
            }
            idle.await;
        }
    }

    /// Retain an inbound-stream watchdog under the same lifecycle fence as
    /// every other registry admission. The handle is returned on refusal so
    /// its owner can abort and observe it exactly once rather than detaching
    /// it on an error path.
    #[cfg(test)]
    pub(crate) fn retain_watchdog(
        &self,
        handle: tokio::task::JoinHandle<()>,
    ) -> Result<(), (tokio::task::JoinHandle<()>, IpcAdmissionError)> {
        let claim = match crate::ipc::LeasedList::<tokio::task::JoinHandle<()>>::node_claim() {
            Ok(claim) => claim,
            Err(reason) => return Err((handle, IpcAdmissionError::Claim(reason))),
        };
        let mut tables = self.inner.tables.lock();
        if let Err(reason) = admitting(&tables) {
            return Err((handle, reason));
        }
        let node = match self.inner.resources.acquire(claim) {
            Ok(node) => node,
            Err(reason) => return Err((handle, IpcAdmissionError::Resources(reason))),
        };
        if tables.final_watchdog_custody.is_none() {
            let custody = match FinalWatchdogCustody::reserve(&self.inner.resources) {
                Ok(custody) => custody,
                Err(reason) => return Err((handle, reason)),
            };
            tables.final_watchdog_custody = Some(custody);
        }
        tables.watchdogs.push(handle, node);
        Ok(())
    }

    /// Remove and await every retained watchdog, observing each terminal
    /// result exactly once. The table lock is released before awaiting, and
    /// the node lease is released when the entry is popped.
    pub(crate) async fn drain_watchdogs(&self) -> usize {
        let mut abnormal = 0;
        while let Some(handle) = {
            let mut tables = self.inner.tables.lock();
            tables.watchdogs.pop()
        } {
            let custody = {
                let tables = self.inner.tables.lock();
                tables
                    .final_watchdog_custody
                    .clone()
                    .expect("every registry has a watchdog terminal owner")
            };
            let mut guard = WatchdogJoinGuard {
                handle: Some(handle),
                custody,
            };
            #[cfg(test)]
            {
                WATCHDOG_GUARD_CREATED.fetch_add(1, Ordering::AcqRel);
                watchdog_guard_notify().notify_waiters();
            }
            if guard
                .handle
                .as_mut()
                .expect("the watchdog guard owns the popped handle")
                .await
                .is_err()
            {
                abnormal += 1;
            }
            guard.handle.take();
        }
        abnormal
    }

    /// Resolve when the runtime enters `Closing`, or immediately if it already
    /// has.
    ///
    /// For tasks parked on something that will not finish by itself — a socket
    /// read, a pump receive — to select against. The already-closing check is
    /// after the subscription for the same reason as above, and it is the half
    /// that matters here: a connection accepted microseconds before the drain
    /// would otherwise wait for a second signal that is never sent.
    pub async fn closing(&self) {
        let closing = self.inner.closing.notified();
        tokio::pin!(closing);
        // Subscribed before the state is read, for the reason spelled out in
        // [`Self::wait_for_tasks`]. Here the loss would be permanent rather than
        // merely delayed: `begin_closing` notifies exactly once, so a wake that
        // arrives between an unsubscribed check and the first poll is never
        // resent and the connection task waits for a signal already sent.
        closing.as_mut().enable();
        if self.lifecycle() != Lifecycle::Running {
            return;
        }
        closing.await;
    }

    /// Admit one accepted task: its funding, and its place in the join count.
    ///
    /// Refused while closing, so a connection accepted in the same breath as the
    /// shutdown signal is turned away rather than spawned into a runtime that is
    /// already draining — which would be a task `serve` then has to wait for,
    /// doing work the drain has just undone.
    ///
    /// The count is incremented here and not in the spawned task. Incrementing
    /// inside would leave a window between the spawn and the task's first poll
    /// in which the task exists and the count says it does not, and `serve` is
    /// entitled to return in that window.
    pub fn lease_task(&self) -> Result<TaskAdmission, IpcAdmissionError> {
        self.admit_task(task_claim().map_err(IpcAdmissionError::Claim)?)
    }

    /// Admit one task together with `retained` bytes its captures hold.
    ///
    /// For the spawn sites that clone owned state into the future rather than
    /// only moving handles. One lease, taken before the clone, released when the
    /// task ends -- so the captured bytes are funded for exactly as long as the
    /// task that holds them, with no second lease that could be refused after
    /// the task was already running.
    pub fn lease_task_retaining(
        &self,
        retained: usize,
    ) -> Result<TaskAdmission, IpcAdmissionError> {
        self.admit_task(task_claim_retaining(retained).map_err(IpcAdmissionError::Claim)?)
    }

    /// The lifecycle check, the acquisition and the increment, in that order.
    ///
    /// The order is the contract. Checking the lifecycle last would admit a task
    /// into a closing runtime; incrementing before the acquisition would leave
    /// the count raised for a task that was refused and never spawned, and
    /// `serve` would wait for it forever.
    fn admit_task(&self, claim: ResourceClaim) -> Result<TaskAdmission, IpcAdmissionError> {
        // All three steps under one acquisition, which is the entire point of
        // this function existing. Releasing the lock between the check and the
        // increment would leave a window in which `begin_closing` publishes
        // `Closing`, sees a count of zero and lets `serve` finish waiting, while
        // an admission that had already passed the check goes on to spawn a task
        // into a runtime that believes it has none. The acquisition is
        // synchronous, so holding a parking_lot mutex across it blocks nothing
        // that could re-enter this registry.
        let mut tables = self.inner.tables.lock();
        admitting(&tables)?;
        let lease = self
            .inner
            .resources
            .acquire(claim)
            .map_err(IpcAdmissionError::Resources)?;
        tables.live_tasks += 1;
        drop(tables);
        Ok(TaskAdmission::new(lease, &self.inner))
    }

    /// Allocate a fresh `ClientId` and register the client's outbound writer.
    /// Returns the handle the read loop should keep alongside its socket.
    ///
    /// Registration is an admission and can be refused. Both of the things this
    /// installs — the handle's own record and the registry's index node for it —
    /// are funded before the id is consumed, so a refusal leaves no gap in the
    /// id space and nothing partially installed: the caller sees the provider's
    /// own reason and the registry is exactly as it was.
    ///
    /// Two claims rather than one because they are released at two different
    /// moments. The record's lease lives in the handle and goes when the last
    /// reference to it does; the index node's lease lives in the table and goes
    /// when the client is unregistered, which can be earlier.
    ///
    /// The refusal reaches an IPC client as a failed `EventsSubscribe`, which
    /// is the truthful answer — the daemon cannot carry this connection's
    /// outbound stream, and a client told it had subscribed would wait forever
    /// for frames nothing was funded to send it.
    pub fn register(
        &self,
        writer_tx: ResourceMailboxSender<ServerOut>,
    ) -> Result<FundedArc<ClientHandle>, IpcAdmissionError> {
        // Checked twice, and the second one is the load-bearing one.
        //
        // This first check is only an early exit: it saves minting a capability
        // and funding two claims for a client that is about to be refused
        // anyway. It cannot be the guard, because the lock is released across
        // the funding below and the drain can begin in that gap.
        admitting(&self.inner.tables.lock())?;
        let record = self
            .inner
            .resources
            .acquire(client_record_claim().map_err(IpcAdmissionError::Claim)?)
            .map_err(IpcAdmissionError::Resources)?;
        let entry = self
            .inner
            .lease_entry::<ClientId, FundedArc<ClientHandle>>()?;
        let id = ClientId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let handle = FundedArc::new(
            ClientHandle {
                id,
                capability: ClientCapability::mint(),
                connected: AtomicBool::new(true),
                disconnected: tokio::sync::Notify::new(),
                writer_tx,
                method_claims: HeldNames::default(),
                channel_subs: HeldNames::default(),
                realtime_flows: Mutex::new(LeasedMap::new()),
            },
            record,
        )
        .unwrap_or_else(|_| unreachable!("an admitted client-record lease may be shared"));
        // The real guard: rechecked in the same acquisition as the insert, so a
        // drain that started while this client was being built refuses it here
        // rather than leaving it installed in tables already walked. Refusing
        // drops `handle` and `entry`, which releases both claims and the minted
        // capability with them — nothing was written, so there is nothing to
        // unwind.
        {
            let mut tables = self.inner.tables.lock();
            admitting(&tables)?;
            tables
                .clients
                .insert(id, handle.clone(), entry)
                // The counter above is monotonic and never reset, so the id in
                // hand has never been issued before and cannot already be in
                // the table.
                .expect("client ids are issued once and never reused");
        }
        Ok(handle)
    }

    pub fn capability<'a>(&self, client: &'a ClientHandle) -> &'a str {
        client.capability.expose()
    }

    pub fn authenticate(&self, id: ClientId, presented: &str) -> Option<FundedArc<ClientHandle>> {
        let client = self.client(id)?;
        client.capability.matches(presented).then_some(client)
    }

    /// Install a completed realtime open only while its event-stream owner is
    /// still registered. This shares the registry table seam with
    /// [`Self::unregister`]: install-first means the disconnect drain observes
    /// and closes the flow; disconnect-first returns the move-only handle to
    /// the caller, which must close it directly.
    ///
    /// The flow's table entry is funded before the flow is filed, and the
    /// refusal hands the handle back exactly as the disconnect race does. Both
    /// mean the same thing to the caller — this flow was never installed, and
    /// closing it is yours — which is why one `Err` shape carries both.
    pub fn install_realtime_flow(
        &self,
        owner: &FundedArc<ClientHandle>,
        network: String,
        flow: myownmesh_core::realtime::RealtimeFlowHandle,
    ) -> Result<RealtimeFlowCapability, Box<RealtimeFlowRejected>> {
        // The capability is a fixed-width mint, so its length is known before
        // it exists; the network name is the client-influenced half and is the
        // reason this is computed per call rather than being a constant.
        let retained = realtime_flow_retained(REALTIME_CAPABILITY_BYTES, &network);
        // The node this flow will occupy in the disconnect drain's list, as its
        // own lease. Acquired before the install rather than folded into
        // `retained`, because the two are released in different places: the
        // retention with the flow's own strings, the node lease after the drain
        // node it funds has been freed. If the install refuses, this drops with
        // the closure that never ran.
        let cleanup = match crate::ipc::LeasedList::<OwnedRealtimeFlow>::node_claim()
            .map_err(IpcAdmissionError::Claim)
            .and_then(|claim| {
                self.inner
                    .resources
                    .acquire(claim)
                    .map_err(IpcAdmissionError::Resources)
            }) {
            Ok(cleanup) => cleanup,
            Err(reason) => {
                return Err(Box::new(RealtimeFlowRejected {
                    flow,
                    reason: RegistrationError::Admission(reason),
                }));
            }
        };
        self.install_if_live(
            owner,
            LeasedMap::<String, OwnedRealtimeFlow>::entry_claim(),
            retained,
            funded_record_retained::<RealtimeFlowSlot>(),
            flow,
            |flow, entry, retained, slot| {
                owner.register_realtime_flow(network, flow, entry, retained, slot, cleanup)
            },
        )
        .map_err(|(flow, reason)| Box::new(RealtimeFlowRejected { flow, reason }))
    }

    /// Run `install` only while `owner` is still a registered, connected client
    /// of this registry — under one acquisition of the tables, so a disconnect
    /// cannot land between the check and the install.
    ///
    /// `install` receives the funding for the table entry it files, the
    /// capability/network retention stored with that value, and the separate
    /// funded flow slot that can outlive the row during an in-flight Change.
    /// All three leases are acquired inside the seam rather than before it, so
    /// a value that is never installed is never funded either.
    ///
    /// Both failures hand `value` straight back, because the caller's obligation
    /// is the same in both: nothing was installed, and whatever `value` holds is
    /// now the caller's alone to release. They differ only in what there is to
    /// say about it.
    ///
    /// Generic over the value rather than written out for the one production
    /// caller, because a real `RealtimeFlowHandle` is `pub(crate)` to core and
    /// cannot be minted from this crate. The ordering that matters lives here,
    /// so the controls drive it with a stand-in value.
    ///
    /// `pub(super)` for exactly that reason and no other: the controls are a
    /// sibling module, and a sibling sees only what this one publishes. It
    /// reaches no further than the module tree that owns the registry, so
    /// nothing outside can install past the disconnect seam.
    pub(super) fn install_if_live<T, R>(
        &self,
        owner: &FundedArc<ClientHandle>,
        entry_claim: Result<ResourceClaim, ResourceClaimArithmeticError>,
        retained_claim: Result<ResourceClaim, ResourceClaimArithmeticError>,
        slot_claim: Result<ResourceClaim, ResourceClaimArithmeticError>,
        value: T,
        install: impl FnOnce(T, ResourceLease, ResourceLease, ResourceLease) -> R,
    ) -> Result<R, (T, RegistrationError)> {
        let tables = self.inner.tables.lock();
        // Same acquisition as the liveness check below, so "the runtime is still
        // admitting" and "this client is still registered" are one answer. A
        // realtime flow installed during the drain would be one the shutdown
        // sweep has already passed, and its native half would outlive the
        // daemon that opened it.
        if let Err(refusal) = admitting(&tables) {
            return Err((value, refusal.into()));
        }
        let live = match tables.client(owner.id) {
            Some(current) => {
                std::ptr::eq(&*current, &**owner) && owner.connected.load(Ordering::Acquire)
            }
            None => false,
        };
        if !live {
            return Err((value, RegistrationError::ClientGone));
        }
        let acquire = |claim: Result<ResourceClaim, ResourceClaimArithmeticError>| {
            claim.map_err(IpcAdmissionError::Claim).and_then(|claim| {
                self.inner
                    .resources
                    .acquire(claim)
                    .map_err(IpcAdmissionError::Resources)
            })
        };
        let entry = match acquire(entry_claim) {
            Ok(entry) => entry,
            Err(refusal) => return Err((value, refusal.into())),
        };
        // Three leases because they are stored in three places: the node lease
        // goes to the map and dies with the node, the retained lease goes
        // inside the value so it survives `pop_first_entry` and travels with
        // the owned key, and the slot lease backs the FundedArc that may be
        // held by an in-flight Change after the row is removed. All are
        // acquired before either is stored, so a refusal of any one installs
        // nothing.
        let retained = match acquire(retained_claim) {
            Ok(retained) => retained,
            Err(refusal) => return Err((value, refusal.into())),
        };
        let slot = match acquire(slot_claim) {
            Ok(slot) => slot,
            Err(refusal) => return Err((value, refusal.into())),
        };
        // Still holding the tables, which is the whole point of taking them.
        Ok(install(value, entry, retained, slot))
    }

    /// Remove one exact connection owner, all its claims and subscriptions,
    /// and every pending operation it owns. A stream sender disappearing
    /// without an explicit terminal item is a peer-visible failure in core.
    ///
    /// Answers which methods it was the last claimant of, so the caller can
    /// uninstall their synthetic handlers. Leaving them installed against a
    /// future re-claim would be unbounded: a client can claim a thousand
    /// methods, disconnect, and leave a thousand handlers installed for methods
    /// nobody serves — each holding its own retention in the network's gateway
    /// scope, which is not this registry's to spend.
    pub fn unregister(&self, id: ClientId) -> Option<UnregisteredClient> {
        let mut tables = self.inner.tables.lock();
        let handle = tables.clients.remove(&id)?;
        handle.connected.store(false, Ordering::Release);
        handle.disconnected.notify_waiters();
        // Method claims this client owned, dropped only where it still owns
        // them: a displacing client may already have taken one over, and that
        // claimant's handler is not ours to forget.
        // Drained rather than snapshotted: each name comes out owned and still
        // funded, so the vector below holds names that are accounted for the
        // whole time it holds them. The previous shape cloned every key into an
        // unfunded vector and released the original's funding immediately, so
        // the copies this path actually used were charged to nobody.
        let mut forget = crate::ipc::LeasedList::new();
        while let Some((key, held)) = handle.method_claims.pop_first() {
            let HeldName {
                retained, cleanup, ..
            } = held;
            if tables.handler_claims.get(&key).map(|claim| claim.value) != Some(id) {
                continue;
            }
            tables.handler_claims.remove(&key);
            if let Some(installed) = tables.installed_handlers.remove(&key) {
                // The name moves into the caller's list together with the lease
                // that pays for its buffers and the registration that removes
                // its handler, and it lands in a node whose own funding was
                // acquired when the claim was taken. Nothing is released under
                // this lock.
                forget.push(
                    ForgottenMethod::new(key, Some(installed), retained),
                    cleanup,
                );
            }
            // A name whose claim a successor took over, or whose handler was
            // already gone, drops both leases here: no node was built for it.
        }
        // Channel subscriptions. An emptied set is removed with its last
        // member, and the fan-out task running for this (network, channel) is
        // stopped *exactly*: the route comes back as a `RetiredRoute` and the
        // caller awaits `retire`, which cancels the pump and joins it. It does
        // not notice anything -- the shape that left it to spot an empty
        // subscriber set on its next frame never ended on a channel nobody was
        // publishing to.
        // Routes this client was the last subscriber of. Collected rather than
        // retired: retiring one means awaiting a task or waking waiters, and
        // this method is synchronous and holding the tables.
        //
        // One name at a time, and one output vector. Draining every name into a
        // vector first and then building a second one beside it would keep two
        // allocations alive together, and only one slot per name is funded.
        let mut routes = crate::ipc::LeasedList::new();
        while let Some((key, held)) = handle.channel_subs.pop_first() {
            let HeldName {
                retained,
                cleanup,
                membership,
            } = held;
            if let Some(route) = membership
                .and_then(|membership| remove_channel_member(&mut tables, &key, membership))
            {
                // Into a node the subscription that took this name pre-paid for,
                // on the same pattern as `forget`.
                routes.push(route, cleanup);
            }
            // Nothing further owns this name, so its funding goes with the last
            // copy of it rather than at the moment it left the table. A
            // subscription whose route was already gone drops its unused node
            // lease here too.
            drop((key, retained));
        }
        // Released before the pending sweep, which takes and releases it once per
        // record so that no settlement happens under it.
        drop(tables);
        settle_pending_where(
            &self.inner.tables,
            |_, pending| pending.owner == id,
            "local IPC handler disconnected",
        );
        Some(UnregisteredClient {
            handle,
            forget,
            routes,
        })
    }

    pub fn client(&self, id: ClientId) -> Option<FundedArc<ClientHandle>> {
        self.inner.tables.lock().client(id)
    }

    /// The next client the shutdown drain has to release, or `None` when the
    /// table is empty.
    ///
    /// **No snapshot, and therefore nothing to fund.** This answered a
    /// `Vec<ClientId>` sized by how many clients had connected, with each slot
    /// pre-paid by its client's record claim. Pre-payment was the right instinct
    /// and the wrong shape: the vector's allocation is sized by capacity rather
    /// than by length, and the per-client funding was released as the loop
    /// unregistered each one while the shared buffer stayed alive to the end.
    /// An allocation that never happens needs no funding and cannot be refused,
    /// which is the stronger answer wherever it is available.
    ///
    /// The caller takes one id, passes it through [`Self::unregister`], releases
    /// that client's realtime flows and synthetic handlers, and asks again.
    /// Progress is guaranteed because `unregister` removes the entry this
    /// answered: an id that comes back has not been released, and one that was
    /// removed by another path is simply not answered again.
    ///
    /// The first key rather than a cursor, because ids are only ever removed
    /// during the drain — nothing is inserted, `begin_closing` having already
    /// refused every admitting path — so "the first one still here" walks the
    /// whole table exactly once.
    #[must_use = "the answered client still has to be unregistered and its registrations released"]
    pub fn shutdown_next(&self) -> Option<ClientId> {
        let tables = self.inner.tables.lock();
        let mut first = None;
        tables.clients.for_each(|id, _| {
            if first.is_none() {
                first = Some(*id);
            }
        });
        first
    }

    /// The one sweep that follows a full shutdown walk.
    ///
    /// Defensive: handler futures can race shutdown after the id snapshot.
    /// Dropping a stream entry without End is explicitly failed by core;
    /// dropping a single sender wakes its waiter with cancellation.
    pub fn shutdown_settle_pending(&self) {
        settle_pending_where(
            &self.inner.tables,
            |_, _| true,
            "the control runtime shut down",
        );
    }

    /// A reference to this registry that does not keep it alive.
    ///
    /// The only shape a handler closure may hold: see [`WeakClientRegistry`]
    /// for whose lifetime a strong one would attach the daemon's tables to.
    pub fn downgrade(&self) -> WeakClientRegistry {
        WeakClientRegistry {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Mint the generation for one installation of one method name.
    ///
    /// Called *before* the handler closure is built, because the closure has to
    /// capture it. Minting is not claiming: a generation that never reaches a
    /// commit is simply never seen again, and the counter is monotonic so it
    /// cannot be confused with a later one.
    pub fn next_handler_generation(&self) -> HandlerGeneration {
        HandlerGeneration(
            self.inner
                .next_handler_generation
                .fetch_add(1, Ordering::Relaxed),
        )
    }

    /// Who owns this method *for the caller's own installation of it*.
    ///
    /// Every synthetic handler closure asks this and passes the generation and
    /// class it was installed with. Anything else answers a different question:
    /// a closure cloned from an earlier installation is still in flight while a
    /// successor holds the name, and `handler_owner` by name alone would hand
    /// that stale closure the newcomer's owner — dispatching a call under one
    /// client's class to another client that never agreed to serve it.
    ///
    /// A record that is still `Installing` answers normally. Routing is decided
    /// by identity, not by whether the registration has arrived: before core
    /// publishes there is no closure carrying this generation, and after it
    /// publishes — which cannot fail — the closure carrying it is the right one.
    pub fn handler_owner_for(
        &self,
        key: &ClaimKey,
        generation: HandlerGeneration,
        mode: HandlerMode,
    ) -> Option<ClientId> {
        let tables = self.inner.tables.lock();
        let installed = tables.installed_handlers.get(key)?;
        if installed.generation != generation || installed.mode != mode {
            return None;
        }
        tables.handler_claims.get(key).map(|claim| claim.value)
    }

    /// Publish one method claim *and* one core registration, all-or-nothing.
    ///
    /// The daemon's half runs inside core's `commit_with`, under core's handlers
    /// lock, which is what makes the two atomic. Neither ordering of two
    /// separate steps can be: installing the handler first leaves an orphan
    /// serving a claim that was then refused, and claiming first leaves a client
    /// told it serves a method no handler can reach.
    ///
    /// Lock order is core-handlers → daemon-tables and never the reverse. This
    /// method therefore holds no daemon lock when it calls `commit_with`, and
    /// every registration it displaces or fails to file is dropped out here,
    /// after core's lock is released — dropping one takes that lock.
    pub fn claim_method_committing_with_key(
        &self,
        key: ClaimKey,
        new_owner: ClientId,
        mode: HandlerMode,
        generation: HandlerGeneration,
        prepared: myownmesh_core::rpc::PreparedRegistration,
    ) -> Result<Option<(ClientId, ClaimKey)>, RegistrationError> {
        let committed = prepared
            .commit_with(|| self.claim_under_lock(&key, new_owner, mode, generation))
            .into_result();
        let (token, committed) = match committed {
            Ok(published) => published,
            Err(refused) => {
                return Err(match refused.into_parts().1 {
                    myownmesh_core::rpc::CommitRefusal::Caller(error) => error,
                    // The gateway closed between prepare and commit. The daemon
                    // half was never called, so there is nothing to undo -- and
                    // it is the network that went, not the client, which is a
                    // different thing to be told and a terminal one.
                    myownmesh_core::rpc::CommitRefusal::Revoked => {
                        RegistrationError::GatewayRevoked
                    }
                });
            }
        };
        // Infallible and generation-exact. A stale answer means this claim was
        // already displaced or released while core was publishing, and the
        // registration comes back to be dropped here — removing its own
        // generation from core and nothing else.
        let stale = self.finalize_handler(&key, generation, token);
        let ClaimCommitted {
            displaced,
            retired,
            mut settled,
        } = committed;
        while let Some(pending) = settled.pop() {
            settle_one(pending, "local IPC handler displaced");
        }
        // Both outside every daemon lock, which is the point of carrying them
        // this far.
        drop(stale);
        drop(retired);
        Ok(displaced.map(|owner| (owner, key)))
    }

    #[cfg(test)]
    pub fn claim_method_committing(
        &self,
        key: ClaimKey,
        new_owner: ClientId,
        mode: HandlerMode,
        generation: HandlerGeneration,
        prepared: myownmesh_core::rpc::PreparedRegistration,
    ) -> Result<Option<ClientId>, RegistrationError> {
        self.claim_method_committing_with_key(key, new_owner, mode, generation, prepared)
            .map(|displaced| displaced.map(|(owner, _)| owner))
    }

    /// Claim a method with no core registration behind it.
    ///
    /// Controls only. Drives exactly the same transaction body as
    /// [`Self::claim_method_committing`] and finalizes with a stand-in, so the
    /// ordering and generation rules under test are the production ones.
    #[cfg(test)]
    pub fn claim_method(
        &self,
        key: ClaimKey,
        new_owner: ClientId,
        mode: HandlerMode,
    ) -> Result<Option<ClientId>, RegistrationError> {
        self.claim_method_generation(key, new_owner, mode)
            .map(|(_, displaced)| displaced)
    }

    /// [`Self::claim_method`], answering the generation it installed as well.
    ///
    /// Separate because most controls do not care which installation they got,
    /// and the ones that do are asking the question this whole design exists to
    /// answer: whether a closure from an earlier installation can still route.
    #[cfg(test)]
    pub fn claim_method_generation(
        &self,
        key: ClaimKey,
        new_owner: ClientId,
        mode: HandlerMode,
    ) -> Result<(HandlerGeneration, Option<ClientId>), RegistrationError> {
        let generation = self.next_handler_generation();
        let committed = self.claim_under_lock(&key, new_owner, mode, generation)?;
        {
            let mut tables = self.inner.tables.lock();
            if let Some(installed) = tables.installed_handlers.get_mut(&key) {
                if installed.generation == generation {
                    installed.token = HandlerToken::LiveWithoutCore;
                }
            }
        }
        let mut settled = committed.settled;
        while let Some(pending) = settled.pop() {
            settle_one(pending, "local IPC handler displaced");
        }
        drop(committed.retired);
        Ok((generation, committed.displaced))
    }

    /// Store the registration core just published, if this is still its
    /// generation.
    ///
    /// Cannot fail and cannot be refused: everything it writes is a field of a
    /// record that already exists. A generation that no longer matches hands the
    /// registration straight back rather than dropping it here, because dropping
    /// it takes core's handlers lock and this one is holding the tables.
    fn finalize_handler(
        &self,
        key: &ClaimKey,
        generation: HandlerGeneration,
        token: myownmesh_core::rpc::OwnedMethodRegistration,
    ) -> Option<myownmesh_core::rpc::OwnedMethodRegistration> {
        let mut tables = self.inner.tables.lock();
        let Some(installed) = tables.installed_handlers.get_mut(key) else {
            return Some(token);
        };
        // Both halves. The generation says this is the record this registration
        // was published for; `Installing` says nothing has been filed into it
        // yet, so the assignment below cannot drop a live registration while
        // this lock is held.
        if installed.generation != generation
            || !matches!(installed.token, HandlerToken::Installing)
        {
            return Some(token);
        }
        installed.token = HandlerToken::Live {
            _registration: token,
        };
        None
    }

    /// The daemon's half of one claim transaction, as core's `commit_with`
    /// calls it: under core's handlers lock, synchronous, no await and no
    /// re-entry into core.
    ///
    /// Three tables are written and each one's entry is funded first, before any
    /// of them is touched. A refusal therefore leaves the registry exactly as it
    /// was rather than half-claimed — a method routed to a client its own
    /// disconnect path would never clean up — and core, seeing the refusal,
    /// publishes nothing either.
    ///
    /// Funding is skipped where the entry already exists, because a re-claim
    /// writes over a value and writing over a value allocates no node. That
    /// check and the write that follows it happen under one acquisition of the
    /// tables, so nothing can slip in between and make the skip wrong.
    ///
    /// What it displaces comes back rather than being dropped: a replaced
    /// record holds a core registration, and releasing one takes the very lock
    /// this is running under.
    fn claim_under_lock(
        &self,
        key: &ClaimKey,
        new_owner: ClientId,
        mode: HandlerMode,
        generation: HandlerGeneration,
    ) -> Result<ClaimCommitted, RegistrationError> {
        let mut tables = self.inner.tables.lock();
        admitting(&tables)?;
        let Some(client) = tables.client(new_owner) else {
            return Err(RegistrationError::ClientGone);
        };
        // Three tables each keep their own clone of this key, so the client's
        // chosen name is retained three times over and each copy is funded
        // where it is made.
        let retained = claim_key_retained(key).map_err(IpcAdmissionError::Claim)?;
        let claim_entry = match tables.handler_claims.contains_key(key) {
            true => None,
            false => Some(
                self.inner
                    .lease_entry_pair::<ClaimKey, Funded<ClientId>>(retained)?,
            ),
        };
        let installed_entry = match tables.installed_handlers.contains_key(key) {
            true => None,
            false => Some(
                self.inner
                    .lease_entry_pair::<ClaimKey, InstalledHandler>(retained)?,
            ),
        };
        // The per-client copy is the one that has to survive the disconnect
        // sweep, so it carries a *second* lease beside its retention: the node
        // it will occupy in `unregister`'s forget list. Separate and not summed,
        // because the two are released in different places at different moments
        // -- the retention with the last copy of the name, the node lease after
        // the node it funds has been freed. Acquired now rather than on the
        // disconnect path, which cannot decline to clean up and so has no honest
        // answer to a refusal.
        let held_entry = match client.method_claims.holds(key) {
            true => None,
            false => {
                let (node, retained) = self
                    .inner
                    .lease_entry_pair::<ClaimKey, HeldName>(retained)?;
                let cleanup = self.inner.resources.acquire(
                    crate::ipc::LeasedList::<ForgottenMethod>::node_claim()
                        .map_err(IpcAdmissionError::Claim)?,
                );
                let cleanup = cleanup.map_err(IpcAdmissionError::Resources)?;
                Some((
                    node,
                    HeldName {
                        retained,
                        cleanup,
                        membership: None,
                    },
                ))
            }
        };
        // Nothing below can fail, so from here the claim is installed whole.
        // The per-client cache goes first so on-disconnect cleanup sees the new
        // claim even if it runs the instant this lock is released.
        if let Some((node, held)) = held_entry {
            client.method_claims.hold(key.clone(), node, held);
        }
        let prev = match claim_entry {
            Some((node, retained)) => {
                tables
                    .handler_claims
                    .insert(
                        key.clone(),
                        Funded {
                            value: new_owner,
                            _retained: retained,
                        },
                        node,
                    )
                    .expect("absence was established while these tables were held");
                None
            }
            None => tables
                .handler_claims
                .get_mut(key)
                .map(|claim| std::mem::replace(&mut claim.value, new_owner)),
        };
        // The record this installation replaces comes back rather than being
        // dropped here: it holds a core registration, and releasing one takes
        // the handlers lock this is already running under.
        let retired = match installed_entry {
            Some((node, retained)) => {
                tables
                    .installed_handlers
                    .insert(
                        key.clone(),
                        InstalledHandler {
                            generation,
                            mode,
                            token: HandlerToken::Installing,
                            _retained: retained,
                        },
                        node,
                    )
                    .expect("absence was established while these tables were held");
                None
            }
            None => tables.installed_handlers.get_mut(key).map(|installed| {
                // Generation, class and registration replaced together, because
                // they are one installation. Leaving the old generation in place
                // would let a closure from it keep routing; leaving the old class
                // would dispatch this client's calls in a shape it never asked
                // for.
                //
                // Written field by field rather than replacing the whole record,
                // so the lease that funds this node's key stays with the node
                // instead of leaving in the value being carried out.
                installed.generation = generation;
                installed.mode = mode;
                std::mem::replace(&mut installed.token, HandlerToken::Installing)
            }),
        };
        let Some(prev_owner) = prev.filter(|prev| *prev != new_owner) else {
            return Ok(ClaimCommitted {
                displaced: None,
                retired,
                settled: crate::ipc::LeasedList::new(),
            });
        };
        if let Some(prev_client) = tables.client(prev_owner) {
            prev_client.method_claims.release(key);
        }
        let settled = take_pending_under(&mut tables, |pending_key, pending| {
            pending.owner == prev_owner
                && pending_key.network == key.0
                && pending_key.method == key.1
        });
        Ok(ClaimCommitted {
            displaced: Some(prev_owner),
            retired,
            settled,
        })
    }

    /// Release a method claim, and say whether the engine's synthetic handler
    /// for it is now owned by nobody.
    pub fn release_method(&self, key: &ClaimKey, owner: ClientId) -> MethodRelease {
        let mut tables = self.inner.tables.lock();
        if let Some(client) = tables.client(owner) {
            client.method_claims.release(key);
        }
        if tables.handler_claims.get(key).map(|claim| claim.value) != Some(owner) {
            return MethodRelease {
                released: false,
                _retired: None,
            };
        }
        tables.handler_claims.remove(key);
        // This was the claim, and a claim is the only thing an installed
        // handler serves, so removing the record and removing the handler are
        // the same event. The record travels out with the caller: dropping it
        // releases the core registration, which takes core's handlers lock, and
        // this one is holding the tables.
        MethodRelease {
            released: true,
            _retired: tables.installed_handlers.remove(key),
        }
    }

    pub fn handler_owner(&self, key: &ClaimKey) -> Option<ClientId> {
        self.inner
            .tables
            .lock()
            .handler_claims
            .get(key)
            .map(|claim| claim.value)
    }

    #[allow(dead_code)]
    pub fn handler_mode(&self, key: &ClaimKey) -> Option<HandlerMode> {
        self.inner
            .tables
            .lock()
            .installed_handlers
            .get(key)
            .map(|installed| installed.mode)
    }

    /// Record one subscriber and say what it must do before reporting success.
    ///
    /// Up to three entries, funded before any is installed, for the same reason
    /// [`Self::claim_method`] funds first: a half-installed subscription is a
    /// client that receives channel traffic its disconnect will not stop.
    ///
    /// The three arms of [`ChannelJoin`] are the three real cases, and two of
    /// them mean *do not answer the client yet*. A follower arriving while a
    /// route is still being installed is one of those two: telling it that it
    /// had subscribed would leave it subscribed to a route with no pump if the
    /// install then failed.
    pub(crate) fn subscribe_channel_borrowed(
        &self,
        key: &ClaimKey,
        client: ClientId,
    ) -> Result<ChannelJoin, RegistrationError> {
        let mut tables = self.inner.tables.lock();
        admitting(&tables)?;
        let Some(c) = tables.client(client) else {
            return Err(RegistrationError::ClientGone);
        };
        let already_member = c.channel_subs.holds(key);
        // The retained heap of this key, once per copy that is kept: the
        // client's own held-name table and the registry's subscriber table each
        // keep one. The client's copy also acquires the node it will occupy in
        // the disconnect drain's route list, as its own lease, for the reason
        // the method claim gives.
        let retained = claim_key_retained(key).map_err(IpcAdmissionError::Claim)?;
        let held_entry = match c.channel_subs.holds(key) {
            true => None,
            false => {
                let (node, retained) = self
                    .inner
                    .lease_entry_pair::<ClaimKey, HeldName>(retained)?;
                let cleanup = self
                    .inner
                    .resources
                    .acquire(
                        crate::ipc::LeasedList::<RetiredRoute>::node_claim()
                            .map_err(IpcAdmissionError::Claim)?,
                    )
                    .map_err(IpcAdmissionError::Resources)?;
                Some((
                    node,
                    HeldName {
                        retained,
                        cleanup,
                        membership: None,
                    },
                ))
            }
        };
        let set_entry = match tables.channel_subs.contains_key(key) {
            true => None,
            false => {
                // The route's node and key bytes, and the readiness `Arc` it
                // is about to allocate, all before any of them exists. A
                // subscribe that cannot afford to tell its followers what
                // happened refuses here rather than after the route is visible.
                // The pump's cancellation is acquired separately, by
                // `route_cancellation`, because its last owner is the pump and
                // not this route.
                let signals = self
                    .inner
                    .resources
                    .acquire(route_ready_retained().map_err(IpcAdmissionError::Claim)?)
                    .map_err(IpcAdmissionError::Resources)?;
                let (node, retained) = self
                    .inner
                    .lease_entry_pair::<ClaimKey, ChannelRoute>(retained)?;
                Some((node, retained, signals))
            }
        };
        let member_entry = match already_member {
            true => None,
            false => Some(self.inner.lease_entry::<ChannelMembershipId, ClientId>()?),
        };
        let membership = match already_member {
            true => None,
            false => Some(ChannelMembershipId(
                self.inner
                    .next_membership_id
                    .fetch_add(1, Ordering::Relaxed),
            )),
        };
        // Nothing below can fail.
        if let Some((node, mut retained)) = held_entry {
            retained.membership = membership;
            c.channel_subs.hold(key.clone(), node, retained);
        }
        let installing = match set_entry {
            Some((node, retained, signals)) => {
                let ready = FundedArc::new(RouteReady::new(), signals)
                    .unwrap_or_else(|_| unreachable!("an admitted readiness lease may be shared"));
                tables
                    .channel_subs
                    .insert(
                        key.clone(),
                        ChannelRoute {
                            state: RouteState::Installing(ready.clone()),
                            members: LeasedMap::new(),
                            _retained: retained,
                        },
                        node,
                    )
                    .expect("absence was established while these tables were held");
                Some(ready)
            }
            None => None,
        };
        let route = tables
            .channel_subs
            .get_mut(key)
            .expect("the route exists or was just inserted");
        if let (Some(entry), Some(membership)) = (member_entry, membership) {
            route
                .members
                .insert(membership, client, entry)
                .expect("absence was established while these tables were held");
        }
        // Membership is recorded either way, and only then is the role decided.
        // A follower is a member of a route that is not yet live, which is
        // exactly why it must not report success: it is subscribed, and nothing
        // can deliver to it yet.
        Ok(match (installing, &route.state) {
            (Some(ready), _) => ChannelJoin::Install(ready),
            (None, RouteState::Installing(ready)) => ChannelJoin::Pending(ready.clone()),
            (None, RouteState::Live(_)) => ChannelJoin::Live,
        })
    }

    /// Owned convenience for controls that are about registry semantics rather
    /// than the pre-build boundary. Production uses the borrowed form above so
    /// decoded coordinates are not cloned before admission.
    #[cfg(test)]
    pub(crate) fn subscribe_channel(
        &self,
        key: ClaimKey,
        client: ClientId,
    ) -> Result<ChannelJoin, RegistrationError> {
        self.subscribe_channel_borrowed(&key, client)
    }

    /// A funded stop-signal for one pump.
    ///
    /// Acquired here rather than folded into the route, because the pump keeps a
    /// clone and is still reading it while it unwinds — after the route that
    /// asked for it has been removed. A refusal reaches the installer before
    /// its pump is spawned, and unwinds the whole route through
    /// [`Self::finish_channel_install`], so subscribe stays all-or-nothing.
    pub(crate) fn route_cancellation(
        &self,
    ) -> Result<FundedArc<RouteCancellation>, IpcAdmissionError> {
        let retained = self
            .inner
            .resources
            .acquire(route_cancellation_retained().map_err(IpcAdmissionError::Claim)?)
            .map_err(IpcAdmissionError::Resources)?;
        let port = process_route_join_port(&self.inner.resources)?;
        self.route_cancellation_reserved(
            retained,
            port,
            #[cfg(test)]
            None,
        )
    }

    fn route_cancellation_reserved(
        &self,
        retained: ResourceLease,
        port: RouteJoinPort,
        #[cfg(test)] fail_at: Option<usize>,
    ) -> Result<FundedArc<RouteCancellation>, IpcAdmissionError> {
        let retirement = RouteRetirementCustodian::reserve(&self.inner.resources, port)?;
        let cancel = FundedArc::new(RouteCancellation::new(retirement.clone()), retained)
            .unwrap_or_else(|_| unreachable!("an admitted cancellation lease may be shared"));
        retirement.start(
            #[cfg(test)]
            fail_at,
        )?;
        Ok(cancel)
    }

    #[cfg(test)]
    pub(super) fn route_cancellation_with_port(
        &self,
        port: RouteJoinPort,
        fail_at: Option<usize>,
    ) -> Result<FundedArc<RouteCancellation>, IpcAdmissionError> {
        let retained = self
            .inner
            .resources
            .acquire(route_cancellation_retained().map_err(IpcAdmissionError::Claim)?)
            .map_err(IpcAdmissionError::Resources)?;
        self.route_cancellation_reserved(retained, port, fail_at)
    }

    /// Publish the outcome of an install, and wake everyone waiting on it.
    ///
    /// Success moves the route to `Live` and hands it the pump's cancellation
    /// and join handle — the two things that will one day stop it, taken now
    /// rather than reconstructed later.
    ///
    /// Failure removes the route *and every member it had accumulated*, not just
    /// the installer's own. That is the whole point of the state: followers
    /// joined a route that never became deliverable, and leaving them recorded
    /// would leave them subscribed to nothing with no pump to notice.
    ///
    /// Waking happens after the lock is released, on this module's usual rule.
    #[must_use = "a pump published into no route must still be cancelled and joined"]
    pub(crate) fn finish_channel_install(
        &self,
        key: &ClaimKey,
        ready: &FundedArc<RouteReady>,
        pump: Option<(FundedArc<RouteCancellation>, tokio::task::JoinHandle<()>)>,
    ) -> Option<RetiredRoute> {
        enum Outcome {
            Live,
            Failed,
        }

        let outcome = {
            let mut tables = self.inner.tables.lock();
            // Same key, but is it the same route? A route can be removed by its
            // last unsubscribe and recreated by a new subscriber while a slow
            // install is still running, and the key alone cannot tell those
            // apart. `FundedArc::ptr_eq` against the readiness this installer was
            // handed can: identity, not coordinates.
            //
            // Without it a late finish publishes its pump into the successor's
            // route — which then has two pumps and joins one — or a late failure
            // deletes a route that was perfectly healthy.
            let ours = matches!(
                tables.channel_subs.get(key).map(|route| &route.state),
                Some(RouteState::Installing(current)) if FundedArc::ptr_eq(current, ready)
            );
            match (ours, pump) {
                (false, pump) => {
                    // Nothing here is ours to change. Anything built is handed
                    // back for retirement rather than dropped, because dropping
                    // a `JoinHandle` detaches a live task.
                    let orphan =
                        pump.map(|(cancel, join)| RetiredRoute::orphaned_pump(cancel, join));
                    drop(tables);
                    // Only this generation is settled — the successor's waiters
                    // are not this installer's to answer, and `settle` is
                    // first-wins besides.
                    ready.settle_failed();
                    return orphan;
                }
                (true, Some((cancel, join))) => {
                    let route = tables
                        .channel_subs
                        .get_mut(key)
                        .expect("presence was established under this same acquisition");
                    let retirement = cancel.retirement();
                    route.state = RouteState::Live(PumpOwner {
                        cancel,
                        join: Some(join),
                        retirement,
                    });
                    Outcome::Live
                }
                (true, None) => {
                    let mut route = tables
                        .channel_subs
                        .remove(key)
                        .expect("presence was established under this same acquisition");
                    // Every member's own copy of this key goes too, one at a
                    // time out of the route's own member table. The route and
                    // its members are central; each client *also* holds the name
                    // in its `HeldNames` with the lease that funds it, and
                    // leaving those installed is stale ownership a later retry
                    // would then skip funding, because the client "already
                    // holds" the name.
                    //
                    // Popped rather than snapshotted: a vector of member ids
                    // built here would be sized by how many clients subscribed
                    // and funded by none of them, on a path that has no honest
                    // way to decline an allocation.
                    while let Some((_membership, member)) = route.members.pop_first_entry() {
                        if let Some(handle) = tables.client(member) {
                            handle.channel_subs.release(key);
                        }
                    }
                    Outcome::Failed
                }
            }
        };

        // Settled after the tables are released, on this module's usual rule:
        // waking a follower under the lock it is about to want is how this
        // module would deadlock.
        match outcome {
            Outcome::Live => ready.settle(RouteReady::LIVE),
            Outcome::Failed => ready.settle_failed(),
        }
        None
    }

    /// Drop one subscriber, and hand back the route if that was the last of
    /// them.
    ///
    /// Returned rather than finished here because finishing it means awaiting a
    /// task or waking waiters, and this is a synchronous method holding a lock.
    /// The caller retires it outside both.
    #[must_use = "a removed route must be retired, or its pump outlives it"]
    pub(crate) fn unsubscribe_channel(
        &self,
        key: &ClaimKey,
        client: ClientId,
    ) -> Option<RetiredRoute> {
        let mut tables = self.inner.tables.lock();
        let membership = tables
            .client(client)
            .and_then(|c| c.channel_subs.release(key))
            .and_then(|held| held.membership);
        membership.and_then(|membership| remove_channel_member(&mut tables, key, membership))
    }

    /// One step of a channel fan-out: the next subscriber after `after`.
    ///
    /// **The lock is released between subscribers, and that is the whole point
    /// of this shape.** Per subscriber the caller deep-clones a peer-controlled
    /// JSON payload, measures its serialized size, acquires against the
    /// provider, inserts into a mailbox and logs refusals. Each step is
    /// synchronous, but the *duration* of the whole is the remote payload's
    /// shape multiplied by the local subscriber count — and one lock protects
    /// clients, method claims, channel routes, pending calls, installed
    /// handlers, lifecycle state and live-task accounting. Holding it across
    /// that work would queue a client disconnect, a control shutdown, a method
    /// displacement, a pending RPC settlement and a route retirement behind a
    /// remote peer's choice of payload. Visiting in place is not enough when
    /// what is visited is attacker-sized; the lock has to be released before
    /// that work happens, and a cursor is how a caller resumes without it.
    ///
    /// **Exact by three identities, and none of them is a position.** The
    /// subscriber cursor is a [`ChannelMembershipId`], which is monotonic and
    /// never reused even when the same client unsubscribes and subscribes again,
    /// so a membership removed between two steps is skipped rather than
    /// re-resolved into its successor. The route is matched by the
    /// exact [`RouteOwner`] the pump holds, so a route removed and reinstalled
    /// under the same key answers `Gone` rather than handing the predecessor's
    /// pump the successor's subscribers. And the frame is bounded by a
    /// high-water member id fixed at its first step, so a stream of new
    /// subscriptions — whose new memberships necessarily carry larger ids —
    /// cannot extend one frame's fan-out indefinitely and starve the next frame.
    ///
    /// None of the three is a new piece of state. The membership id, the route's own
    /// cancellation [`FundedArc`] and the membership map all already exist;
    /// this reads them, and it is why there is no vector to return — a
    /// resource-backed snapshot would be a per-frame allocation to fund, and an
    /// allocation that does not happen cannot be refused. `FundedArc::ptr_eq`
    /// binds route identity to that exact funded allocation without exposing a
    /// raw pointer or relying on its pointee layout.
    ///
    /// An unpublished route answers `End` rather than `Gone`. A pump can pull a
    /// frame between its own spawn and its own `finish_channel_install`, and it
    /// cannot tell its own pending install from a successor's — but neither may
    /// deliver, so both get the same answer: nothing this frame, and the route
    /// is still here. Exiting instead would end a pump whose route was about to
    /// publish it.
    ///
    /// A member with no live client record is passed over inside the same walk.
    /// It is a subscription whose client has been removed and whose membership
    /// has not been swept yet, and there is nobody to deliver to.
    ///
    /// The cost is one lock acquisition and one `O(log n)` successor descent
    /// per subscriber, plus one last-key descent when the frame fixes its
    /// ceiling. Every comparison is between fixed-size membership identities,
    /// so the work is chosen by how many clients subscribed and never by what a
    /// peer sent. The work that *is* peer-sized happens with no lock held.
    pub(crate) fn subscriber_after(
        &self,
        key: &ClaimKey,
        owner: RouteOwner<'_>,
        position: &mut ChannelFanout,
    ) -> ChannelFanoutStep {
        let tables = self.inner.tables.lock();
        let Some(route) = tables.channel_subs.get(key) else {
            return ChannelFanoutStep::Gone;
        };
        let live = match &route.state {
            RouteState::Live(owner) => Some(&owner.cancel),
            RouteState::Installing(_) => None,
        };
        match owner {
            RouteOwner::Pump(pump) => match live {
                None => return ChannelFanoutStep::End,
                Some(live) if !FundedArc::ptr_eq(live, pump) => return ChannelFanoutStep::Gone,
                Some(_) => {}
            },
            #[cfg(test)]
            RouteOwner::Any => {}
        }
        // Fix the frame boundary to the newest subscription present now. A
        // later re-subscription has a fresh identity and cannot inherit it.
        if position.ceiling.is_none() {
            let Some((highest, _)) = route.members.last_key_value() else {
                return ChannelFanoutStep::End;
            };
            position.ceiling = Some(*highest);
        }
        let ceiling = match position.ceiling {
            Some(ceiling) => ceiling,
            // Unreachable: the branch above either set it or returned.
            None => return ChannelFanoutStep::End,
        };
        loop {
            let Some((membership, client_id)) =
                route.members.successor_after(position.after.as_ref())
            else {
                return ChannelFanoutStep::End;
            };
            if *membership > ceiling {
                return ChannelFanoutStep::End;
            }
            position.after = Some(*membership);
            if let Some(client) = tables.clients.get(client_id) {
                return ChannelFanoutStep::Next {
                    client: client.clone(),
                };
            }
        }
    }

    /// Every current subscriber of one channel, in id order.
    ///
    /// Controls only, and a thin loop over [`Self::subscriber_after`] rather
    /// than a second implementation: a control that wants the whole set is not
    /// on the fan-out path and has no lock-duration problem to solve, while
    /// production must release the lock between subscribers. Written in terms of
    /// the cursor so the two cannot disagree about who a subscriber is.
    ///
    /// Answers `false` only when the route itself is gone, which is the
    /// distinction every caller of it actually makes: a route with no members is
    /// removed with its last one, so "no route" and "no members" arrive
    /// together.
    #[cfg(test)]
    pub fn for_each_subscriber(
        &self,
        key: &ClaimKey,
        mut visit: impl FnMut(&FundedArc<ClientHandle>),
    ) -> bool {
        let mut position = ChannelFanout::frame();
        loop {
            match self.subscriber_after(key, RouteOwner::Any, &mut position) {
                ChannelFanoutStep::Gone => return false,
                ChannelFanoutStep::End => return true,
                ChannelFanoutStep::Next { client, .. } => visit(&client),
            }
        }
    }

    /// Monotonic counter used to tag outbound stream calls.
    /// The lib's `Rpc::call_stream` allocates its own request
    /// id internally but doesn't expose it; the IPC layer
    /// generates its own correlation id so clients can match
    /// chunks back to their originating call.
    pub fn next_call_stream_id(&self) -> u64 {
        self.inner
            .next_call_stream_id
            .fetch_add(1, Ordering::Relaxed)
    }

    /// Fund one inbound call before any of it is built.
    ///
    /// **Borrowed coordinates in, funding out, and nothing constructed.** Every
    /// term of the claim is a length, and a length is readable from the inbound
    /// call's own fields — so this can be refused while the peer's coordinates
    /// still exist only as borrows of the call core already funded. Copying the
    /// coordinates into a `PendingKey` and building the answering channel
    /// before asking for funding would not be an admission at all: the memory
    /// the refusal is about would already have been taken, at whatever rate the
    /// peer chose to call.
    ///
    /// The liveness checks are here too, and deliberately not only here: a
    /// closing runtime or a departed owner refuses before anything is acquired,
    /// and [`Self::commit_exact_pending`] re-checks under the lock that finally
    /// writes. Neither check alone is enough — this one cannot hold the lock
    /// across the caller's construction, and that one would be refusing after
    /// the construction it exists to prevent.
    ///
    /// The duplicate check is *not* here, because it cannot be: the key it would
    /// ask about is the thing this exists to avoid building. It is the commit's,
    /// where the key exists and the lock is held.
    pub fn prepare_exact_pending(
        &self,
        key: &ClaimKey,
        remote_peer: &str,
        remote_request_id: &str,
        class: HandlerMode,
        owner: ClientId,
    ) -> Result<PreparedPending, PendingRefusal> {
        {
            let tables = self.inner.tables.lock();
            admitting(&tables)?;
            if tables.client(owner).is_none() {
                return Err(PendingRefusal::OwnerGone);
            }
        }
        let retained = pending_retained_for(&key.0, &key.1, remote_peer, remote_request_id)
            .map_err(IpcAdmissionError::Claim)?;
        let (entry, retained) = self
            .inner
            .lease_entry_pair::<PendingKey, PendingRecord>(retained)?;
        let cancellation = self
            .inner
            .resources
            .acquire(pending_cancellation_claim().map_err(IpcAdmissionError::Claim)?)
            .map_err(IpcAdmissionError::Resources)?;
        let cleanup = self
            .inner
            .resources
            .acquire(
                crate::ipc::LeasedList::<PendingRecord>::node_claim()
                    .map_err(IpcAdmissionError::Claim)?,
            )
            .map_err(IpcAdmissionError::Resources)?;
        Ok(PreparedPending {
            key: key.clone(),
            class,
            owner,
            entry,
            retained,
            cancellation,
            cleanup,
        })
    }

    /// File a prepared call against the effect that answers it.
    ///
    /// The coordinates are copied here, into funding acquired before this was
    /// called.
    ///
    /// **`build` runs past every refusal, never before one.** It is infallible
    /// and it is called under the same lock the insertion is made under, after
    /// lifecycle, owner and duplicate have all been re-checked — so a refusal
    /// constructs no effect and there is none to hand back. The shape this
    /// replaces took a built `PendingInbound` and returned it inside the
    /// refusal, where it outlived the prepared leases that were covering it:
    /// the leases were dropped at the return and the caller was left holding an
    /// unfunded channel, on exactly the commit-race path that is hardest to
    /// reach and therefore least likely to be noticed.
    ///
    /// `build` also answers the caller's half of whatever it made — the
    /// response receiver, the close probe — because that half is created in the
    /// same breath as the effect and nothing outside can name it.
    ///
    /// Infallible is a real constraint, and it is what shapes the streaming
    /// path. Funding a stream's queue can be *refused*, and a refusal here has
    /// nowhere to go: this section runs past the last point at which anything
    /// could be handed back, so an acquisition inside it would either have to
    /// panic or leave a half-filed record. That is the constraint — not a
    /// blanket rule about the provider and the tables, which other paths on this
    /// type legitimately break by acquiring under the lock where the acquisition
    /// is allowed to fail. So the streaming caller acquires the queue's root
    /// *before* preparing and carries the result in — a
    /// `PreparedResourceMailbox`, which
    /// is funding and nothing else. No `Arc`, no queue, no sender and no
    /// receiver exist until `build` runs here; a refusal above returns the
    /// prepared root, which releases what it holds and leaves nothing behind
    /// that anyone could have been handed. The single-shot `oneshot` is built
    /// here for a different reason: nothing but the pending lease covers its
    /// allocation, so it must not exist on a path where that lease is going
    /// away.
    ///
    /// **Not a production entry point.** Pairing a prepared call's class with
    /// the effect that answers it is the invariant this seam exists to keep, and
    /// a caller free to choose both would be free to file a stream's sender
    /// under a single-shot's funding. The two narrowed forms below each pass a
    /// constant; this one checks anyway, and a control drives it directly to
    /// prove the check discriminates.
    pub(crate) fn commit_exact_pending_as<E>(
        &self,
        prepared: PreparedPending,
        remote_peer: &str,
        remote_request_id: &str,
        expected: HandlerMode,
        build: impl FnOnce() -> (PendingInbound, E),
    ) -> Result<(PendingTicket, E), PendingRefusal> {
        let PreparedPending {
            key: claim_key,
            class,
            owner,
            entry,
            retained,
            cancellation,
            cleanup,
        } = prepared;
        if class != expected {
            return Err(PendingRefusal::ClassMismatch);
        }
        let key = PendingKey {
            network: claim_key.0,
            method: claim_key.1,
            remote_peer: remote_peer.to_string(),
            remote_request_id: remote_request_id.to_string(),
            class,
        };
        let mut tables = self.inner.tables.lock();
        // Re-checked under the lock that writes. The preparation's checks
        // refused early and cheaply; these are the ones the insertion is atomic
        // with. Every one of them returns before `build` is called, and the
        // prepared leases are released by that return with nothing outstanding
        // for them to have been covering.
        if let Err(reason) = admitting(&tables) {
            return Err(reason.into());
        }
        if tables.client(owner).is_none() {
            return Err(PendingRefusal::OwnerGone);
        }
        if tables.exact_pending_inbound.contains_key(&key) {
            return Err(PendingRefusal::Duplicate);
        }
        // Minted past every refusal, so no builder ever runs against an
        // identity that was taken and then abandoned. Once minted it is never
        // returned to the counter, even if a later invariant bug were to make
        // the infallible tail stop short of publication.
        let operation_id = self.inner.next_operation_id.fetch_add(1, Ordering::Relaxed);
        // Past every refusal, and still holding the lock the insertion is made
        // under: what this builds cannot be refused and cannot be left behind.
        let (effect, caller) = build();
        // One charge, two owners. It is released when the later of the record
        // and the ticket goes, which is the only moment at which no copy of
        // these buffers is still live.
        let funding = FundedArc::new(PendingFunding, retained)
            .unwrap_or_else(|_| unreachable!("admitted pending funding may be shared"));
        let ticket_key = key.clone();
        let cancelled = FundedArc::new(
            PendingCancellation {
                cancelled: AtomicBool::new(false),
                notify: tokio::sync::Notify::new(),
            },
            cancellation,
        )
        .unwrap_or_else(|_| unreachable!("an admitted cancellation lease may be shared"));
        tables
            .exact_pending_inbound
            .insert(
                key,
                PendingRecord {
                    owner,
                    operation_id,
                    effect,
                    cancelled: cancelled.clone(),
                    cleanup: Some(cleanup),
                    _funding: funding.clone(),
                },
                entry,
            )
            .expect("absence was established while these tables were held");
        Ok((
            PendingTicket {
                registry: Arc::downgrade(&self.inner),
                key: ticket_key,
                operation_id,
                cancelled,
                _funding: funding,
            },
            caller,
        ))
    }

    /// File a prepared single-shot call, and answer the receiver its response
    /// will arrive on.
    ///
    /// The class is this method's, not its caller's: a single-shot preparation
    /// is the only thing it accepts and a `oneshot` is the only thing it builds,
    /// so the two cannot disagree.
    pub fn commit_exact_single_pending(
        &self,
        prepared: PreparedPending,
        remote_peer: &str,
        remote_request_id: &str,
    ) -> Result<
        (
            PendingTicket,
            tokio::sync::oneshot::Receiver<Result<serde_json::Value, String>>,
        ),
        PendingRefusal,
    > {
        self.commit_exact_pending_as(
            prepared,
            remote_peer,
            remote_request_id,
            HandlerMode::Single,
            || {
                let (tx, rx) = tokio::sync::oneshot::channel();
                (PendingInbound::Single(tx), rx)
            },
        )
    }

    /// File a prepared streaming call against an already-funded queue root, and
    /// answer the receiver its chunks travel on together with a sender clone the
    /// caller's watchdog watches for closure.
    ///
    /// Same pairing guarantee as the single-shot form, and the same reason for
    /// taking the queue as *preparation* rather than as halves: the two halves
    /// are built past the last refusal, inside the fence that installs them.
    pub fn commit_exact_stream_pending(
        &self,
        prepared: PreparedPending,
        remote_peer: &str,
        remote_request_id: &str,
        queue: myownmesh_core::PreparedResourceMailbox<myownmesh_core::rpc::RpcStreamItem>,
    ) -> Result<
        (
            PendingTicket,
            myownmesh_core::ResourceMailboxReceiver<myownmesh_core::rpc::RpcStreamItem>,
            myownmesh_core::ResourceMailboxSender<myownmesh_core::rpc::RpcStreamItem>,
        ),
        PendingRefusal,
    > {
        self.commit_exact_pending_as(
            prepared,
            remote_peer,
            remote_request_id,
            HandlerMode::Stream,
            move || {
                let (tx, rx) = queue.commit();
                let probe = tx.clone();
                (PendingInbound::Stream(tx), (rx, probe))
            },
        )
        .map(|(ticket, (rx, probe))| (ticket, rx, probe))
    }

    /// Track one inbound call so a later `RpcRespond` or stream frame can settle
    /// it, and answer the ticket that owns its removal.
    ///
    /// The refusal says which of the three things went wrong and hands the
    /// engine-side awaiter back. That distinction reaches the calling peer: a
    /// duplicate is the peer's own coordinates colliding, an absent owner is a
    /// local client that left, and a refusal is the daemon out of the capacity
    /// this call would need. Reporting all three as a duplicate — which is what
    /// a bare `Err(effect)` left the caller to do — told the peer to fix
    /// something that was not wrong.
    /// Controls only. Production files through
    /// [`Self::prepare_exact_pending`] and [`Self::commit_exact_pending`],
    /// because a caller that already holds a built `PendingKey` has already
    /// taken the allocation the split exists to make refusable. This form is
    /// kept for the controls that drive the table directly and have no inbound
    /// call to borrow coordinates from.
    #[cfg(test)]
    pub fn insert_exact_pending(
        &self,
        key: PendingKey,
        owner: ClientId,
        effect: PendingInbound,
    ) -> Result<PendingTicket, PendingRejected> {
        let mut tables = self.inner.tables.lock();
        if let Err(reason) = admitting(&tables) {
            return Err(PendingRejected {
                effect,
                reason: reason.into(),
            });
        }
        if tables.client(owner).is_none() {
            return Err(PendingRejected {
                effect,
                reason: PendingRefusal::OwnerGone,
            });
        }
        if tables.exact_pending_inbound.contains_key(&key) {
            return Err(PendingRejected {
                effect,
                reason: PendingRefusal::Duplicate,
            });
        }
        // The node, and separately everything the call retains off it: both
        // copies of the coordinates, the shared cancellation, the effect, and
        // the sweep slot. Acquired before anything is written, so a refusal of
        // either leaves the table exactly as it was and hands the effect back
        // for the caller to drop deliberately.
        let retained = match pending_retained(&key) {
            Ok(retained) => retained,
            Err(error) => {
                return Err(PendingRejected {
                    effect,
                    reason: IpcAdmissionError::Claim(error).into(),
                })
            }
        };
        let (entry, retained) = match self
            .inner
            .lease_entry_pair::<PendingKey, PendingRecord>(retained)
        {
            Ok(leases) => leases,
            Err(refusal) => {
                return Err(PendingRejected {
                    effect,
                    reason: refusal.into(),
                })
            }
        };
        let cancellation = match pending_cancellation_claim()
            .map_err(IpcAdmissionError::Claim)
            .and_then(|claim| {
                self.inner
                    .resources
                    .acquire(claim)
                    .map_err(IpcAdmissionError::Resources)
            }) {
            Ok(cancellation) => cancellation,
            Err(reason) => {
                return Err(PendingRejected {
                    effect,
                    reason: reason.into(),
                })
            }
        };
        // The node this record will occupy if a claim displacement has to detach
        // it, as its own lease. Acquired here, moved into that node when the
        // sweep builds it, released after the node is freed. Refused, nothing
        // has been written and the effect goes back to the caller.
        let cleanup = match crate::ipc::LeasedList::<PendingRecord>::node_claim()
            .map_err(IpcAdmissionError::Claim)
            .and_then(|claim| {
                self.inner
                    .resources
                    .acquire(claim)
                    .map_err(IpcAdmissionError::Resources)
            }) {
            Ok(cleanup) => cleanup,
            Err(reason) => {
                return Err(PendingRejected {
                    effect,
                    reason: reason.into(),
                })
            }
        };
        let operation_id = self.inner.next_operation_id.fetch_add(1, Ordering::Relaxed);
        // One charge, two owners. It is released when the later of the record
        // and the ticket goes, which is the only moment at which no copy of
        // these buffers is still live.
        let funding = FundedArc::new(PendingFunding, retained)
            .unwrap_or_else(|_| unreachable!("admitted pending funding may be shared"));
        let ticket_key = key.clone();
        let cancelled = FundedArc::new(
            PendingCancellation {
                cancelled: AtomicBool::new(false),
                notify: tokio::sync::Notify::new(),
            },
            cancellation,
        )
        .unwrap_or_else(|_| unreachable!("an admitted cancellation lease may be shared"));
        tables
            .exact_pending_inbound
            .insert(
                key,
                PendingRecord {
                    owner,
                    operation_id,
                    effect,
                    cancelled: cancelled.clone(),
                    cleanup: Some(cleanup),
                    _funding: funding.clone(),
                },
                entry,
            )
            .expect("absence was established while these tables were held");
        Ok(PendingTicket {
            registry: Arc::downgrade(&self.inner),
            key: ticket_key,
            operation_id,
            cancelled,
            _funding: funding,
        })
    }

    /// Settle one single-shot operation, with success or with the client's
    /// error. `true` only if that exact operation was pending and this caller
    /// owned it: the key, the owner and the private operation id must all
    /// match, and the record must be of the single-shot class.
    ///
    /// The class check is what stops a `RpcRespond` from terminating a stream
    /// that happens to share every public coordinate with it.
    pub fn resolve_exact_single(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        result: Result<serde_json::Value, String>,
    ) -> bool {
        let mut tables = self.inner.tables.lock();
        let ours = match tables.exact_pending_inbound.get(key) {
            Some(pending) => {
                pending.owner == owner
                    && pending.operation_id == operation_id
                    && matches!(&pending.effect, PendingInbound::Single(_))
            }
            None => false,
        };
        if !ours {
            return false;
        }
        let pending = tables
            .exact_pending_inbound
            .remove(key)
            .expect("the record was present while these tables were held");
        // Cancelled under the tables, like every other terminal path, so a
        // concurrent chunk that already holds a cloned sender sees a settled
        // operation. Released before the waiter is woken: resolving the oneshot
        // resumes a task that goes straight back into this registry, and this
        // lock is not reentrant.
        pending.cancelled.cancel();
        drop(tables);
        let PendingInbound::Single(tx) = pending.effect else {
            unreachable!("the response class was checked before removal")
        };
        let _ = tx.send(result);
        true
    }

    /// Push one chunk into an in-flight stream. `true` if it was accepted.
    ///
    /// Synchronous, and that is the whole shape of it. The queue is
    /// resource-bounded rather than count-bounded, so admission is decided
    /// immediately: nothing awaits a full queue, and so there is no interval —
    /// after the sender is cloned out and the map guard released — in which a
    /// settlement could land unseen.
    ///
    /// Cancellation is still checked, because it is still a real answer: every
    /// terminal path — [`Self::close_exact_stream`], [`Self::unregister`],
    /// displacement, and dropping the [`PendingTicket`] — cancels while holding
    /// the registry's tables, before its own terminal item goes out. Reading it
    /// here means a settled stream refuses a late chunk rather than writing one
    /// after the `End` its peer has already been told is final.
    ///
    /// A refusal from the mailbox itself — the provider would not fund this
    /// chunk's retention — answers `false` too, so the client learns its chunk
    /// was not accepted rather than waiting on capacity that is not coming.
    pub fn push_exact_stream(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        payload: serde_json::Value,
    ) -> bool {
        let (tx, cancelled) = {
            let tables = self.inner.tables.lock();
            match tables.exact_pending_inbound.get(key) {
                Some(pending) if pending.owner == owner && pending.operation_id == operation_id => {
                    match &pending.effect {
                        PendingInbound::Stream(tx) => (tx.clone(), pending.cancelled.clone()),
                        _ => return false,
                    }
                }
                _ => return false,
            }
        };
        if cancelled.is_cancelled() {
            return false;
        }
        tx.send(myownmesh_core::rpc::RpcStreamItem::Chunk(payload))
            .is_ok()
    }

    /// Terminate one in-flight stream, cleanly or with the client's error.
    ///
    /// The record is removed and its cancellation fired inside one write
    /// acquisition, before the terminal item is sent, so no chunk still parked
    /// on a full queue can overtake it.
    ///
    /// [`RpcStreamItem::End`] is sent rather than the sender merely dropped:
    /// the error the client supplied is the point, and a drop would report
    /// every ending as the same failure.
    ///
    /// [`RpcStreamItem::End`]: myownmesh_core::rpc::RpcStreamItem::End
    pub fn close_exact_stream(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        error: Option<String>,
    ) -> bool {
        let mut tables = self.inner.tables.lock();
        let ours = match tables.exact_pending_inbound.get(key) {
            Some(pending) => {
                pending.owner == owner
                    && pending.operation_id == operation_id
                    && matches!(&pending.effect, PendingInbound::Stream(_))
            }
            None => false,
        };
        if !ours {
            return false;
        }
        let pending = tables
            .exact_pending_inbound
            .remove(key)
            .expect("the record was present while these tables were held");
        pending.cancelled.cancel();
        drop(tables);
        let PendingInbound::Stream(tx) = pending.effect else {
            unreachable!("the response class was checked before removal")
        };
        tx.send(myownmesh_core::rpc::RpcStreamItem::End(
            error.map_or(Ok(()), Err),
        ))
        .is_ok()
    }
}

/// One registry over the daemon's test grant, for controls.
///
/// The fixture entry point, and the only one: production calls
/// [`ClientRegistry::new`] with the scope its owner issued it, and a `Default`
/// that reached for a scope of its own would be a registry admitting clients
/// nobody granted capacity for. This is not compiled into the daemon.
#[cfg(test)]
impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new(crate::test_application_scope())
            .expect("the daemon test grant starts the IPC final watchdog custodian")
    }
}
