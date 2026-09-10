//! Named application channels: the subscriber queues and the gateway
//! operations that install, retire, and deliver into them.

#[cfg(test)]
use crate::resource::measure_serialized_mailbox_item;
use crate::resource::{
    FundedArc, FundedWeak, LeasedMap, LeasedQueue, ResourceClaim, ResourceClass, ResourceLease,
};
use crate::runtime::peer_session::LogicalSessionValidityWitness;

use super::{ApplicationGateway, GatewayAccepted, GatewayDelivery, GatewayMailbox, GatewayRefusal};

pub(crate) struct GatewayChannelFrame {
    pub(crate) from: String,
    pub(crate) payload: serde_json::Value,
}

/// One subscriber's queue, owned by its subscription and observed weakly by the
/// channel registry that routes to it.
///
/// The funding rides in the strong [`FundedArc`] handles. A [`FundedWeak`]
/// registry entry retains no claim and can upgrade only while a funded strong
/// owner still exists. A delivered message owns its own delivery, not this
/// mailbox, so dropping the subscription releases all queued deliveries.
pub(crate) struct ChannelSubscriber {
    mailbox: parking_lot::Mutex<GatewayMailbox<GatewayChannelFrame>>,
    ready: tokio::sync::Notify,
    closed: std::sync::atomic::AtomicBool,
    pressure: std::sync::atomic::AtomicU64,
}

impl ChannelSubscriber {
    fn new() -> Self {
        Self {
            mailbox: parking_lot::Mutex::new(GatewayMailbox::new()),
            ready: tokio::sync::Notify::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
            pressure: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn accept(&self, frame: GatewayChannelFrame, retention: ResourceLease, node: ResourceLease) {
        self.mailbox.lock().accept(frame, retention, node);
        self.ready.notify_one();
    }

    fn note_pressure(&self) {
        self.pressure
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.ready.notify_one();
    }

    pub(crate) async fn recv(
        &self,
    ) -> Result<GatewayDelivery<GatewayChannelFrame>, GatewayRefusal> {
        self.recv_with_before_wait(|| {}).await
    }

    async fn recv_with_before_wait(
        &self,
        mut before_wait: impl FnMut(),
    ) -> Result<GatewayDelivery<GatewayChannelFrame>, GatewayRefusal> {
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let skipped = self.pressure.swap(0, std::sync::atomic::Ordering::AcqRel);
            if skipped != 0 {
                return Err(GatewayRefusal::Lag(skipped));
            }
            if let Some(delivery) = self.mailbox.lock().pop() {
                return Ok(delivery);
            }
            if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Err(GatewayRefusal::Revoked);
            }
            before_wait();
            notified.await;
        }
    }

    fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.ready.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&self) -> Option<GatewayDelivery<GatewayChannelFrame>> {
        self.mailbox.lock().pop()
    }
}

pub(super) struct GatewayChannel {
    subscribers: LeasedQueue<FundedWeak<ChannelSubscriber>>,
    _name: ResourceLease,
}

impl Drop for GatewayChannel {
    fn drop(&mut self) {
        while let Some(subscriber) = self.subscribers.pop_front() {
            if let Some(subscriber) = subscriber.upgrade() {
                subscriber.close();
            }
        }
    }
}

/// Retire weak subscription nodes whose funded strong owner has already gone
/// away, then return the exact number of candidates that can receive.  The
/// count feeds the scratch reservation below, so stale nodes must not make a
/// live route fail for capacity it cannot use.
fn retain_live_subscriber_count(channel: &mut GatewayChannel) -> usize {
    channel
        .subscribers
        .retain(|subscriber| subscriber.strong_count() != 0);
    channel.subscribers.iter().count()
}

impl ApplicationGateway {
    /// Submit one locally-originated channel frame through the engine's
    /// owner-bound transport command port.
    ///
    /// The gateway owns the application operation; the engine still owns the
    /// signaling/transport implementation. Keeping that distinction explicit
    /// prevents a public channel handle from manufacturing a worker, peer
    /// session, or signaling authority of its own.
    pub(crate) async fn send_channel_frame(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> crate::error::Result<()> {
        state.send_channel_frame(peer, channel, payload).await
    }

    /// Submit one locally-originated reliable channel frame through the same
    /// typed gateway boundary. Retention and acknowledgement remain owned by
    /// the exact live session selected by the engine.
    pub(crate) async fn send_channel_reliable(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> crate::error::Result<()> {
        state.send_channel_reliable(peer, channel, payload).await
    }

    /// Submit a best-effort fan-out through the engine's per-owner transport
    /// selection. The returned count is a send-success count, not a delivery
    /// guarantee.
    pub(crate) async fn broadcast_channel_frame(
        &self,
        state: &crate::engine::state::NetworkState,
        channel: &str,
        payload: serde_json::Value,
    ) -> crate::error::Result<usize> {
        state.broadcast_channel_frame(channel, payload).await
    }

    pub(crate) fn subscribe_channel(
        &self,
        name: &str,
    ) -> Result<FundedArc<ChannelSubscriber>, GatewayRefusal> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        let subscriber_bytes = u64::try_from(std::mem::size_of::<ChannelSubscriber>())
            .map_err(|_| GatewayRefusal::Malformed)?;
        // This residual covers the subscriber allocation and the dependency's
        // internal shared-owner representation without mirroring allocator
        // control-block arithmetic.
        // A decoded result is not a property of the subscription: applications
        // may retain any number of distinct messages. Each accepted delivery
        // therefore acquires its own decoded-result residual below.
        let subscriber_claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, subscriber_bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .map_err(|_| GatewayRefusal::Malformed)?;
        let subscriber_allocation = self
            .resources
            .acquire(subscriber_claim)
            .map_err(GatewayRefusal::Pressure)?;
        let subscriber = FundedArc::new(ChannelSubscriber::new(), subscriber_allocation)
            .expect("a gateway subscriber allocation is admitted, never speculative");
        let mut channels = self.channels.lock();
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        // Everything this subscription needs is acquired before any of it is
        // written, and the writes below cannot fail.
        //
        // The previous order inserted the channel entry first and only then
        // acquired the subscriber's queue node. A refusal at that second
        // acquisition left the channel installed with an empty subscriber
        // queue — a route the caller was told it did not get, holding a name
        // lease and a map node, removed by nothing, because the only thing that
        // removes an empty channel is the last subscriber leaving and there had
        // never been a first one.
        let subscriber_node = self
            .resources
            .acquire(
                LeasedQueue::<FundedWeak<ChannelSubscriber>>::entry_claim()
                    .map_err(|_| GatewayRefusal::Malformed)?,
            )
            .map_err(GatewayRefusal::Pressure)?;
        let fresh_channel = match channels.get(name) {
            Some(_) => None,
            None => {
                let name_claim = GatewayMailbox::<()>::retention_claim(name.len(), name.len(), 1)
                    .map_err(|_| GatewayRefusal::Malformed)?;
                let name_lease = self
                    .resources
                    .acquire(name_claim)
                    .map_err(GatewayRefusal::Pressure)?;
                let node = self
                    .resources
                    .acquire(
                        LeasedMap::<String, GatewayChannel>::entry_claim()
                            .map_err(|_| GatewayRefusal::Malformed)?,
                    )
                    .map_err(GatewayRefusal::Pressure)?;
                Some((name_lease, node))
            }
        };
        // Past every refusal. A return between here and the end of the function
        // would be the defect this ordering removes.
        if let Some((name_lease, node)) = fresh_channel {
            channels
                .insert(
                    name.to_string(),
                    GatewayChannel {
                        subscribers: LeasedQueue::new(),
                        _name: name_lease,
                    },
                    node,
                )
                .expect("absence was established under this same acquisition");
        }
        channels
            .get_mut(name)
            .expect("the channel entry was installed under this lock")
            .subscribers
            .push(subscriber.downgrade(), subscriber_node);
        Ok(subscriber)
    }

    pub(crate) fn unsubscribe_channel(
        &self,
        name: &str,
        subscriber: &FundedArc<ChannelSubscriber>,
    ) {
        let mut registry = self.channels.lock();
        if let Some(channel) = registry.get_mut(name) {
            channel.subscribers.retain(|candidate| {
                candidate
                    .upgrade()
                    .is_some_and(|candidate| !FundedArc::ptr_eq(&candidate, subscriber))
            });
            if channel.subscribers.is_empty() {
                registry.remove_entry(name);
            }
        }
        subscriber.close();
    }

    pub(crate) fn accept_channel(
        &self,
        validity: &LogicalSessionValidityWitness,
        claim: ResourceClaim,
        parse_retention: ResourceLease,
        name: &str,
        from: &str,
        payload: serde_json::Value,
    ) -> Result<GatewayAccepted, GatewayRefusal> {
        let mut registry = self.channels.lock();
        let candidate_count = registry
            .get_mut(name)
            .map_or(0, retain_live_subscriber_count);
        if candidate_count == 0 {
            return Err(GatewayRefusal::NoReceiver);
        }
        // The temporary live-subscriber snapshot and the all-or-nothing
        // prepared-delivery set each own one exact backing allocation. Fund
        // both before either Vec exists; the lease remains live until both
        // buffers have been consumed below.
        let scratch_count =
            u64::try_from(candidate_count).map_err(|_| GatewayRefusal::Malformed)?;
        let live_bytes = u64::try_from(std::mem::size_of::<FundedArc<ChannelSubscriber>>())
            .map_err(|_| GatewayRefusal::Malformed)?
            .checked_mul(scratch_count)
            .ok_or(GatewayRefusal::Malformed)?;
        let prepared_bytes = u64::try_from(std::mem::size_of::<(
            FundedArc<ChannelSubscriber>,
            ResourceLease,
            ResourceLease,
            serde_json::Value,
        )>())
        .map_err(|_| GatewayRefusal::Malformed)?
        .checked_mul(scratch_count)
        .ok_or(GatewayRefusal::Malformed)?;
        let scratch_claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                live_bytes
                    .checked_add(prepared_bytes)
                    .ok_or(GatewayRefusal::Malformed)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| GatewayRefusal::Malformed)?;
        let _scratch = validity
            .reserve_retained(scratch_claim)
            .map_err(GatewayRefusal::Pressure)?;
        let subscribers = {
            let Some(channel) = registry.get_mut(name) else {
                return Err(GatewayRefusal::NoReceiver);
            };
            let mut live = Vec::with_capacity(candidate_count);
            live.extend(channel.subscribers.iter().filter_map(FundedWeak::upgrade));
            channel
                .subscribers
                .retain(|subscriber| subscriber.strong_count() != 0);
            live
        };
        if subscribers.is_empty() {
            return Err(GatewayRefusal::NoReceiver);
        }
        let node_claim = GatewayMailbox::<GatewayChannelFrame>::node_claim()
            .map_err(|_| GatewayRefusal::Malformed)?;
        let entry_claim = channel_delivery_claim(claim, from)?;
        let mut original_payload = Some(payload);
        let mut prepared = Vec::with_capacity(candidate_count);
        for (index, subscriber) in subscribers.iter().enumerate() {
            let retention = validity.reserve_retained(entry_claim).map_err(|error| {
                for subscriber in &subscribers {
                    subscriber.note_pressure();
                }
                GatewayRefusal::Pressure(error)
            })?;
            let node = validity.reserve_retained(node_claim).map_err(|error| {
                for subscriber in &subscribers {
                    subscriber.note_pressure();
                }
                GatewayRefusal::Pressure(error)
            })?;
            let payload = if index + 1 == subscribers.len() {
                original_payload
                    .take()
                    .expect("last subscriber owns payload")
            } else {
                original_payload.as_ref().expect("payload remains").clone()
            };
            prepared.push((FundedArc::clone(subscriber), retention, node, payload));
        }
        for (subscriber, retention, node, payload) in prepared {
            subscriber.accept(
                GatewayChannelFrame {
                    from: from.to_string(),
                    payload,
                },
                retention,
                node,
            );
        }
        drop(registry);
        drop(parse_retention);
        Ok(GatewayAccepted)
    }

    /// How many channel records exist.
    ///
    /// Controls only, and distinct from the subscriber count on purpose: an
    /// empty channel record and an absent one are the same to
    /// [`Self::channel_subscriber_count_for_test`], and the difference between
    /// them is exactly the residue an all-or-nothing subscribe must not leave.
    #[cfg(test)]
    pub(crate) fn channel_count_for_test(&self) -> usize {
        self.channels.lock().len()
    }

    #[cfg(test)]
    pub(crate) fn channel_subscriber_count_for_test(&self, name: &str) -> usize {
        self.channels
            .lock()
            .get_mut(name)
            .map_or(0, |channel| channel.subscribers.iter().count())
    }
}

/// Everything retained by one accepted channel delivery, including one
/// opaque owner for the application-selected decoded result derived from it.
/// The residual is deliberately per delivery rather than part of the shared
/// subscriber claim: retaining N decoded results retains N reservations.
fn channel_delivery_claim(
    payload_claim: ResourceClaim,
    from: &str,
) -> Result<ResourceClaim, GatewayRefusal> {
    let from_claim = GatewayMailbox::<GatewayChannelFrame>::retention_claim(
        from.len(),
        from.len(),
        usize::from(!from.is_empty()),
    )
    .map_err(|_| GatewayRefusal::Malformed)?;
    let queued_payload = ResourceClaim::single(
        ResourceClass::QueuedBytes,
        payload_claim.amount(ResourceClass::AccountedMemoryBytes),
    );
    payload_claim
        .checked_add(from_claim)
        .and_then(|claim| claim.checked_add(queued_payload))
        .and_then(|claim| {
            claim.checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                1,
            ))
        })
        .map_err(|_| GatewayRefusal::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    use crate::resource::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort, ResourceScope,
    };

    /// A gateway over a provider the control keeps, so it can read the ledger
    /// this crate charges against rather than inferring pressure from behaviour.
    fn gateway_fixture() -> (crate::resource::FiniteResourceProvider, ApplicationGateway) {
        let grant = ResourceClaim::try_from_entries(
            ResourceClass::ALL
                .into_iter()
                .map(|resource| (resource, 1 << 20)),
        )
        .expect("the broad control grant is representable");
        let provider = crate::resource::FiniteResourceProvider::new(grant);
        let port = crate::resource::ResourceProviderPort::new(provider.clone())
            .expect("the control grant funds its process scope");
        let process = crate::resource::ProcessResourceRoot::isolated();
        process
            .install_local_application_provider(port)
            .expect("the control installs its local provider");
        let resources = process
            .issue_local_application_scope()
            .expect("the control issues a local-application scope");
        (provider, ApplicationGateway::new(resources))
    }

    fn subscriber_fixture() -> (ApplicationGateway, FundedArc<ChannelSubscriber>) {
        let (_provider, gateway) = gateway_fixture();
        let subscriber = gateway
            .subscribe_channel("wake-control")
            .expect("the control funds one subscriber");
        (gateway, subscriber)
    }

    fn one_delivery_subscriber(
        node: ResourceClaim,
        retention: ResourceClaim,
    ) -> (
        FiniteResourceProvider,
        ResourceProviderPort,
        ResourceScope,
        ChannelSubscriber,
    ) {
        let grant = FiniteResourceProvider::scope_record_charge_for_test()
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(node)
                    .expect("the node reservation is representable"),
            )
            .and_then(|grant| {
                grant.checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(retention)
                        .expect("the delivery reservation is representable"),
                )
            })
            .expect("one delivery and its provider records compose");
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the exact grant funds its process scope");
        let scope = port.process_scope();
        (provider, port, scope, ChannelSubscriber::new())
    }

    fn admit_test_delivery(
        port: &ResourceProviderPort,
        scope: &ResourceScope,
        subscriber: &ChannelSubscriber,
        retention: ResourceClaim,
        node: ResourceClaim,
        payload: serde_json::Value,
    ) -> bool {
        let Ok(retention) = port.acquire(scope, ResourceAuthorityClass::Admitted, retention) else {
            return false;
        };
        let Ok(node) = port.acquire(scope, ResourceAuthorityClass::Admitted, node) else {
            return false;
        };
        subscriber.accept(
            GatewayChannelFrame {
                from: String::new(),
                payload,
            },
            retention,
            node,
        );
        true
    }

    struct DecodedResult {
        body: String,
        _delivery: GatewayDelivery<GatewayChannelFrame>,
    }

    fn decode_one(
        subscriber: &ChannelSubscriber,
        decodes: &std::sync::atomic::AtomicUsize,
    ) -> DecodedResult {
        let delivery = subscriber
            .try_recv()
            .expect("one admitted delivery is queued");
        decodes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let body = String::deserialize(&delivery.value().payload)
            .expect("the admitted test payload decodes as a string");
        DecodedResult {
            body,
            _delivery: delivery,
        }
    }

    /// One subscription is not permission to retain an unbounded number of
    /// application-selected decoded graphs. The exact provider admits one
    /// delivery (node plus off-node owner); once its node is popped, retaining
    /// the decoded result still prevents the next delivery from completing.
    /// Dropping that result returns the same capacity for a later delivery.
    #[test]
    fn v4_r5_core_f1_one_subscriber_cannot_retain_two_decoded_graphs_under_one_residual() {
        let payload = serde_json::Value::String("decoded-result".to_owned());
        let payload_claim = measure_serialized_mailbox_item::<serde_json::Value>(&payload)
            .expect("the payload claim is measurable")
            .into_claim();
        let retention = channel_delivery_claim(payload_claim, "")
            .expect("the per-delivery claim is representable");
        assert_eq!(
            retention.amount(ResourceClass::OpaqueDependencyResidual),
            payload_claim.amount(ResourceClass::OpaqueDependencyResidual) + 1,
            "each delivery adds exactly one decoded-result residual"
        );
        let node = GatewayMailbox::<GatewayChannelFrame>::node_claim()
            .expect("the mailbox node claim is representable");
        let (provider, port, scope, subscriber) = one_delivery_subscriber(node, retention);
        let baseline = provider.in_use();
        let decodes = std::sync::atomic::AtomicUsize::new(0);

        assert!(admit_test_delivery(
            &port,
            &scope,
            &subscriber,
            retention,
            node,
            payload.clone(),
        ));
        let first = decode_one(&subscriber, &decodes);
        assert_eq!(first.body, "decoded-result");
        assert_eq!(decodes.load(std::sync::atomic::Ordering::Relaxed), 1);

        assert!(
            !admit_test_delivery(&port, &scope, &subscriber, retention, node, payload.clone(),),
            "the first retained result consumes the only decoded-result capacity"
        );
        assert!(
            subscriber.try_recv().is_none(),
            "the refused delivery was not queued"
        );
        assert_eq!(
            decodes.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a delivery refused by capacity is never decoded"
        );

        drop(first);
        assert_eq!(provider.in_use(), baseline);
        assert!(admit_test_delivery(
            &port,
            &scope,
            &subscriber,
            retention,
            node,
            payload,
        ));
        let later = decode_one(&subscriber, &decodes);
        assert_eq!(later.body, "decoded-result");
        assert_eq!(decodes.load(std::sync::atomic::Ordering::Relaxed), 2);
        drop(later);
        assert_eq!(provider.in_use(), baseline);
    }

    /// A delivered value owns only its delivery, never the subscriber mailbox.
    /// Keeping A while the subscription owner goes away must release queued B
    /// and C immediately; otherwise an application can make abandoned mailbox
    /// contents hostage merely by retaining one value it already received.
    #[test]
    fn a_delivered_channel_message_does_not_pin_the_abandoned_subscriber_mailbox() {
        let grant = ResourceClaim::try_from_entries(
            ResourceClass::ALL
                .into_iter()
                .map(|resource| (resource, 1 << 20)),
        )
        .expect("the broad control grant is representable");
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the control grant funds its process scope");
        let scope = port.process_scope();
        let baseline = provider.in_use();

        let subscriber_claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(std::mem::size_of::<ChannelSubscriber>())
                    .expect("the subscriber layout fits the ledger"),
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .expect("the subscriber claim is representable");
        let subscriber = FundedArc::new(
            ChannelSubscriber::new(),
            port.acquire(&scope, ResourceAuthorityClass::Admitted, subscriber_claim)
                .expect("the subscriber allocation is admitted"),
        )
        .expect("an admitted subscriber allocation may be shared");

        let payload = serde_json::Value::String("held-a".to_owned());
        let payload_claim = measure_serialized_mailbox_item::<serde_json::Value>(&payload)
            .expect("the payload claim is measurable")
            .into_claim();
        let retention = channel_delivery_claim(payload_claim, "peer")
            .expect("the delivery claim is representable");
        let node = GatewayMailbox::<GatewayChannelFrame>::node_claim()
            .expect("the mailbox node claim is representable");

        for _ in 0..3 {
            subscriber.accept(
                GatewayChannelFrame {
                    from: "peer".to_owned(),
                    payload: payload.clone(),
                },
                port.acquire(&scope, ResourceAuthorityClass::Admitted, retention)
                    .expect("the delivery retention is admitted"),
                port.acquire(&scope, ResourceAuthorityClass::Admitted, node)
                    .expect("the delivery node is admitted"),
            );
        }

        let delivery = subscriber.try_recv().expect("A is delivered");
        let body =
            String::deserialize(&delivery.value().payload).expect("the admitted payload decodes");
        let held = crate::channels::ChannelMessage::from_delivery(body, delivery);

        drop(subscriber);
        let held_only = baseline
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(retention)
                    .expect("the retained delivery charge is representable"),
            )
            .expect("baseline and one retained delivery compose");
        assert_eq!(
            provider.in_use(),
            held_only,
            "queued B and C plus the subscriber allocation release while A is held"
        );

        drop(held);
        assert_eq!(provider.in_use(), baseline);
    }

    /// What a subscription is supposed to leave behind when it succeeds.
    ///
    /// The companion to the refusal control below, and not a formality: an
    /// assertion that a refusal leaves nothing proves nothing on its own if a
    /// success also leaves nothing, because then the control would pass against
    /// a `subscribe_channel` that had stopped working entirely.
    #[test]
    fn v4_f2_core_a_subscribe_installs_exactly_one_channel_and_one_subscriber() {
        let (provider, gateway) = gateway_fixture();
        let baseline = provider.in_use();

        let first = gateway
            .subscribe_channel("alpha")
            .expect("the control grant funds one subscription");

        assert_eq!(gateway.channel_count_for_test(), 1);
        assert_eq!(gateway.channel_subscriber_count_for_test("alpha"), 1);
        assert_ne!(
            provider.in_use(),
            baseline,
            "a live subscription is charged for"
        );

        // A second subscriber joins the channel that already exists, so exactly
        // one more subscriber and no second channel record.
        let second = gateway
            .subscribe_channel("alpha")
            .expect("the control grant funds a second subscription");
        assert_eq!(gateway.channel_count_for_test(), 1);
        assert_eq!(gateway.channel_subscriber_count_for_test("alpha"), 2);

        gateway.unsubscribe_channel("alpha", &first);
        gateway.unsubscribe_channel("alpha", &second);
        drop((first, second));
        assert_eq!(
            provider.in_use(),
            baseline,
            "and everything it was charged for comes back when it leaves"
        );
    }

    /// A dropped subscription can leave a weak node until the route is next
    /// inspected.  That node has no receiver and must not consume scratch
    /// reservation or make a live route report pressure for an unreachable
    /// candidate.
    #[test]
    fn stale_subscription_nodes_are_pruned_before_candidate_counting() {
        let (_provider, gateway) = gateway_fixture();
        let subscriber = gateway
            .subscribe_channel("stale")
            .expect("the control grant funds one subscription");
        drop(subscriber);

        assert_eq!(
            gateway.channel_subscriber_count_for_test("stale"),
            1,
            "the deliberately stale weak node is present before route inspection"
        );
        let candidates = {
            let mut registry = gateway.channels.lock();
            retain_live_subscriber_count(
                registry
                    .get_mut("stale")
                    .expect("the channel remains while its stale node is queued"),
            )
        };
        assert_eq!(candidates, 0);
        assert_eq!(
            gateway.channel_subscriber_count_for_test("stale"),
            0,
            "pruning removes the unreachable node before any scratch claim"
        );
    }

    /// A subscription refused part-way through leaves the gateway exactly as it
    /// found it.
    ///
    /// The defect this control exists for was an ordering, not a leak: the
    /// channel record was inserted first and the subscriber's queue node was
    /// acquired second. A refusal at that second acquisition left a channel
    /// installed with an empty subscriber queue — holding a name lease and a map
    /// node, reported to the caller as a failure, and removed by nothing,
    /// because the only thing that retires an empty channel is its last
    /// subscriber leaving and there had never been a first one.
    ///
    /// The refusal is forced at the *name lease*, which is the third of the four
    /// acquisitions and the only one that touches `QueuedBytes`. That choice is
    /// what makes this control discriminating rather than merely negative: the
    /// subscriber allocation and the subscriber's queue node have both already
    /// been acquired when it fires, so a path that installed anything before its
    /// last acquisition — or that failed to release the two it already held —
    /// shows up as a ledger that does not return to the baseline.
    #[test]
    fn v4_f2_core_a_refused_subscribe_leaves_no_channel_no_subscriber_and_no_lease() {
        let (provider, gateway) = gateway_fixture();
        let held = gateway
            .subscribe_channel("alpha")
            .expect("the control grant funds one subscription");
        // The baseline is taken with a live subscription in place, so the
        // assertion below is "nothing changed", not "nothing exists" — a
        // gateway that tore down the wrong channel fails it too.
        let baseline = provider.in_use();

        provider.script_pressure(ResourceClass::QueuedBytes);
        let refusal = gateway.subscribe_channel("beta");
        assert!(
            matches!(refusal, Err(GatewayRefusal::Pressure(_))),
            "the scripted shortage is reported as pressure, not swallowed"
        );

        assert_eq!(
            gateway.channel_count_for_test(),
            1,
            "no channel record survives a refused subscription"
        );
        assert_eq!(
            gateway.channel_subscriber_count_for_test("beta"),
            0,
            "and no subscriber is queued against the name that was refused"
        );
        assert_eq!(
            gateway.channel_subscriber_count_for_test("alpha"),
            1,
            "the subscription that already existed is untouched"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "and the two acquisitions the refusal ran past are released exactly"
        );

        // The scripted shortage was consumed by that one refusal, so the same
        // subscription now succeeds. Nothing the failed attempt left behind is
        // in the way of it — which is the other half of all-or-nothing, and the
        // half a control that only asserts emptiness would miss.
        let beta = gateway
            .subscribe_channel("beta")
            .expect("the retry is admitted once the shortage passes");
        assert_eq!(gateway.channel_count_for_test(), 2);
        assert_eq!(gateway.channel_subscriber_count_for_test("beta"), 1);
        gateway.unsubscribe_channel("beta", &beta);
        drop((beta, held));
    }

    #[tokio::test]
    async fn close_in_the_check_to_wait_window_cannot_be_lost() {
        let (_gateway, subscriber) = subscriber_fixture();
        let closer = FundedArc::clone(&subscriber);
        let refusal = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            subscriber.recv_with_before_wait(move || closer.close()),
        )
        .await
        .expect("the registered waiter observes close in the critical window");
        assert!(matches!(refusal, Err(GatewayRefusal::Revoked)));
    }
}
