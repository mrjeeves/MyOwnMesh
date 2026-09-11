//! Controls for the IPC client registry.
//!
//! One module rather than one per operation, because almost every control here
//! spans more than one of them: a disconnect is asserted against claims,
//! subscriptions and pending calls at once, and splitting them by subject would
//! have put the fixtures in one file and the assertions in another.

use super::*;

fn fresh_client(
    registry: &ClientRegistry,
) -> (
    FundedArc<ClientHandle>,
    myownmesh_core::ResourceMailboxReceiver<ServerOut>,
) {
    let (tx, rx) = myownmesh_core::resource_mailbox(crate::test_application_scope())
        .expect("the daemon test grant funds one client writer mailbox");
    let handle = registry
        .register(tx)
        .expect("the daemon test grant funds one client record");
    (handle, rx)
}

#[cfg(feature = "transport-lab")]
fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.into())
}

#[cfg(feature = "transport-lab")]
fn require_active_resource_baseline(
    actual: &myownmesh_core::resource::ResourceReport,
    baseline: &myownmesh_core::resource::ResourceReport,
    operation: &'static str,
) -> Result<(), String> {
    for (actual, baseline) in actual
        .pre_authentication
        .iter()
        .zip(&baseline.pre_authentication)
    {
        require(
            actual.family == baseline.family
                && actual.active == baseline.active
                && actual.active_lease_count == baseline.active_lease_count,
            format!(
                "{operation}: pre-auth {:?} active resources changed: actual={:?}/{}, baseline={:?}/{}",
                actual.family,
                actual.active,
                actual.active_lease_count,
                baseline.active,
                baseline.active_lease_count,
            ),
        )?;
    }
    for (actual, baseline) in actual
        .post_authentication
        .iter()
        .zip(&baseline.post_authentication)
    {
        require(
            actual.family == baseline.family
                && actual.active == baseline.active
                && actual.active_lease_count == baseline.active_lease_count,
            format!(
                "{operation}: post-auth {:?} active resources changed: actual={:?}/{}, baseline={:?}/{}",
                actual.family,
                actual.active,
                actual.active_lease_count,
                baseline.active,
                baseline.active_lease_count,
            ),
        )?;
    }
    Ok(())
}

#[cfg(feature = "transport-lab")]
fn live_slot_connector_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
    myownmesh_core::WebRtcConnectorCapablePolicy::new(
        crate::test_resource_provider(),
        myownmesh_core::WebRtcConnectorProfile::new(
            myownmesh_core::ConnectorCallbackPolicy::elastic_realtime(),
        ),
    )
}

#[cfg(feature = "transport-lab")]
fn live_slot_network(id: &str) -> myownmesh_core::config::NetworkConfig {
    let mut config =
        myownmesh_core::config::NetworkConfig::from_network_id(id, "daemon-slot-control");
    config.label = id.to_owned();
    config.signaling = myownmesh_core::config::SignalingConfig {
        strategy: "none".to_owned(),
        mdns: false,
        public_fallback: false,
        ..myownmesh_core::config::SignalingConfig::default()
    };
    config.auto_approve = true;
    config.introduction = None;
    config.validate().expect("live slot network validates");
    config
}

#[cfg(feature = "transport-lab")]
async fn live_slot_within<T>(
    operation: &'static str,
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, String> {
    let value = tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| format!("{operation}: exceeded its absolute deadline"))?;
    if tokio::time::Instant::now() > deadline {
        return Err(format!(
            "{operation}: completed after its absolute deadline"
        ));
    }
    Ok(value)
}

#[cfg(feature = "transport-lab")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn installed_realtime_slot_custody_is_linear_and_funded() {
    let home = tempfile::tempdir().expect("isolated live slot fixture home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
    let alice_identity = std::sync::Arc::new(myownmesh_core::Identity::ephemeral());
    let bob_identity = std::sync::Arc::new(myownmesh_core::Identity::ephemeral());
    let alice_id = alice_identity.public_id().to_owned();
    let bob_id = bob_identity.public_id().to_owned();
    let policy = live_slot_connector_policy();
    let registry_grant =
        registry_fixture_claim(2, 2, 16).expect("slot registry grant is representable");
    let oversized_slot_demand = registry_grant
        .amount(ResourceClass::AccountedMemoryBytes)
        .checked_add(1)
        .expect("the finite registry grant leaves room for one representable pressure unit");
    let registry = ClientRegistry::over_grant(registry_grant);
    let mut alice_mesh = None;
    let mut bob_mesh = None;
    let mut alice_baseline = None;
    let mut bob_baseline = None;
    let mut alice = None;
    let mut bob = None;
    let mut link = None;
    let mut bob_inbound = None;
    let mut uninstalled_flow = None;
    let mut owner = None;
    let mut installed_capability = None;
    let mut removed_flow = None;
    let mut captured_slot = None;
    let result: Result<(), String> = async {
        let opened_alice = live_slot_within(
            "slot-alice-open",
            deadline,
            myownmesh_core::Mesh::open_connector_capable_with_identity(
                myownmesh_core::MeshConfig::default(),
                alice_identity,
                policy.clone(),
            ),
        )
        .await?
        .map_err(|error| format!("Alice mesh refused: {error}"))?;
        alice_baseline = Some(opened_alice.resource_report());
        alice_mesh = Some(opened_alice);
        let opened_bob = live_slot_within(
            "slot-bob-open",
            deadline,
            myownmesh_core::Mesh::open_connector_capable_with_identity(
                myownmesh_core::MeshConfig::default(),
                bob_identity,
                policy,
            ),
        )
        .await?
        .map_err(|error| format!("Bob mesh refused: {error}"))?;
        bob_baseline = Some(opened_bob.resource_report());
        bob_mesh = Some(opened_bob);
        let joined_alice = live_slot_within(
            "slot-alice-join",
            deadline,
            alice_mesh
                .as_ref()
                .ok_or_else(|| "Alice mesh disappeared before join".to_owned())?
                .join(live_slot_network("alice")),
        )
        .await?
        .map_err(|error| format!("Alice join refused: {error}"))?;
        alice = Some(joined_alice);
        let joined_bob = live_slot_within(
            "slot-bob-join",
            deadline,
            bob_mesh
                .as_ref()
                .ok_or_else(|| "Bob mesh disappeared before join".to_owned())?
                .join(live_slot_network("bob")),
        )
        .await?
        .map_err(|error| format!("Bob join refused: {error}"))?;
        bob = Some(joined_bob);
        let alice_ref = alice
            .as_ref()
            .ok_or_else(|| "Alice network disappeared before link setup".to_owned())?;
        let bob_ref = bob
            .as_ref()
            .ok_or_else(|| "Bob network disappeared before link setup".to_owned())?;
        link = Some(
            live_slot_within(
                "slot-real-link",
                deadline,
                alice_ref.install_retirable_session_over_real_link(bob_ref),
            )
            .await?,
        );
        bob_inbound = Some(
            bob_ref
                .realtime_inbound(&alice_id)
                .ok_or_else(|| "Bob could not claim the one exact inbound stream".to_owned())?,
        );
        let open = myownmesh_core::realtime::OpaqueFlowOpen::new(
            vec![0, 0xff, b's', b'l', b'o', b't'],
            myownmesh_core::realtime::RealtimeFlowDirection::Outbound,
            myownmesh_core::realtime::OpaqueFlowMode::ReliableOrdered,
            1024,
        )
        .ok_or_else(|| "slot flow request is not well formed".to_owned())?;
        let flow = live_slot_within(
            "slot-flow-open",
            deadline,
            alice_ref.open_opaque_flow(&bob_id, &open),
        )
        .await?
        .map_err(|error| format!("real opaque flow refused: {error}"))?;
        uninstalled_flow = Some(flow);
        let (owner_tx, _owner_rx) =
            myownmesh_core::resource_mailbox(crate::test_application_scope())
                .map_err(|error| format!("slot owner mailbox refused: {error}"))?;
        let owner_handle = registry
            .register(owner_tx)
            .map_err(|error| format!("slot owner registration refused: {error}"))?;
        owner = Some(owner_handle);
        let owner_ref = owner
            .as_ref()
            .ok_or_else(|| "slot owner disappeared after registration".to_owned())?;
        let registry_baseline = registry.in_use().ok_or_else(|| {
            "isolated registry exposes no usage after owner registration".to_owned()
        })?;
        let callback_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_probe = callback_called.clone();
        let flow = match registry.install_if_live(
            owner_ref,
            LeasedMap::<String, OwnedRealtimeFlow>::entry_claim(),
            realtime_flow_retained(REALTIME_CAPABILITY_BYTES, "alice"),
            Ok(ResourceClaim::single(
                ResourceClass::AccountedMemoryBytes,
                oversized_slot_demand,
            )),
            uninstalled_flow.take().ok_or_else(|| {
                "the uninstalled flow was lost before the refusal probe".to_owned()
            })?,
            move |flow, _entry, _retained, _slot| {
                callback_probe.store(true, Ordering::Release);
                flow
            },
        ) {
            Err((flow, reason)) => {
                require(
                    matches!(
                        &reason,
                        RegistrationError::Admission(IpcAdmissionError::Resources(
                            myownmesh_core::ResourceUnavailable::Pressure(pressure),
                        )) if pressure.dimension == ResourceClass::AccountedMemoryBytes
                    ),
                    format!("slot reservation refused at the wrong stage: {reason}"),
                )?;
                flow
            }
            Ok(_) => return Err("the deliberately oversized slot reservation admitted".to_owned()),
        };
        require(
            !callback_called.load(Ordering::Acquire),
            "refused install ran its callback",
        )?;
        uninstalled_flow = Some(flow);
        require(
            registry.in_use() == Some(registry_baseline),
            "entry and retained leases survived the refused slot reservation",
        )?;
        let flow = uninstalled_flow
            .take()
            .ok_or_else(|| "the refused real handle was not returned".to_owned())?;
        require(
            alice_ref.realtime_is_current(&flow),
            "the refused handle was not still current",
        )?;
        let capability = registry
            .install_realtime_flow(owner_ref, "alice".to_owned(), flow)
            .map_err(|_| "the exact funded slot refused the real flow".to_owned())?;
        installed_capability = Some(capability.clone());
        let slot = owner_ref
            .realtime_flow_slot(capability.expose(), "alice")
            .ok_or_else(|| "installed flow exposes no exact funded slot".to_owned())?;
        captured_slot = Some(slot.clone());
        let busy_guard = slot.handle.try_lock().map_err(|_| {
            "the control could not borrow the slot before the busy probe".to_owned()
        })?;
        let changed = myownmesh_core::realtime::OpaqueFlowOpen::new(
            vec![0, 0xff, b's', b'l', b'o', b't'],
            myownmesh_core::realtime::RealtimeFlowDirection::Outbound,
            myownmesh_core::realtime::OpaqueFlowMode::ReliableOrdered,
            512,
        )
        .ok_or_else(|| "busy Change request is not well formed".to_owned())?;
        let busy_result = live_slot_within(
            "slot-busy-change",
            deadline,
            slot.change_opaque(alice_ref, &changed),
        )
        .await?;
        require(
            busy_result == Err(myownmesh_core::realtime::RealtimeRefusal::FlowRefused),
            format!("busy Change returned {busy_result:?}"),
        )?;
        drop(busy_guard);

        let owned = owner_ref
            .take_realtime_flow(capability.expose())
            .ok_or_else(|| "row removal returned no installed flow".to_owned())?;
        removed_flow = Some(owned);
        require(
            owner_ref
                .realtime_flow_slot(capability.expose(), "alice")
                .is_none(),
            "removed row still resolves the old capability",
        )?;
        let owned = removed_flow
            .take()
            .ok_or_else(|| "removed flow was lost before close".to_owned())?;
        let close_guard = slot
            .handle
            .try_lock()
            .map_err(|_| "close probe could not borrow the exact slot".to_owned())?;
        let mut close = Box::pin(owned.close_through(alice_ref));
        let completed_while_held = tokio::select! {
            biased;
            _ = &mut close => true,
            _ = tokio::task::yield_now() => false,
        };
        if completed_while_held {
            drop(close_guard);
            return Err("close completed while the exact slot was borrowed".to_owned());
        }
        drop(close_guard);
        live_slot_within("slot-close", deadline, &mut close)
            .await?
            .map_err(|error| format!("exact flow close failed after slot release: {error}"))?;

        let slot_charge = myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
            funded_record_retained::<RealtimeFlowSlot>()
                .map_err(|error| format!("slot claim is not representable: {error:?}"))?,
        )
        .map_err(|error| format!("slot reservation charge is not representable: {error:?}"))?;
        let after_row = registry
            .in_use()
            .ok_or_else(|| "isolated registry did not expose usage after close".to_owned())?;
        require(
            after_row.checked_sub(registry_baseline) == Ok(slot_charge),
            "captured slot did not remain exactly funded after row removal",
        )?;
        drop(slot);
        captured_slot = None;
        require(
            registry.in_use() == Some(registry_baseline),
            "final slot capture did not release its exact reservation",
        )?;

        let unregistered = registry
            .unregister(owner_ref.id)
            .ok_or_else(|| "owner unregister found no live client".to_owned())?;
        drop(unregistered.handle);
        let (successor_tx, _successor_rx) =
            myownmesh_core::resource_mailbox(crate::test_application_scope())
                .map_err(|error| format!("successor mailbox refused: {error}"))?;
        let successor = registry
            .register(successor_tx)
            .map_err(|error| format!("successor registration refused: {error}"))?;
        require(
            successor.id != owner_ref.id,
            "successor reused the disconnected client id",
        )?;
        require(
            successor
                .realtime_flow_slot(capability.expose(), "alice")
                .is_none(),
            "a disconnected successor reused the old flow capability",
        )?;
        installed_capability = None;
        Ok(())
    }
    .await;

    drop(bob_inbound.take());
    let cleanup_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut cleanup_failures = Vec::new();
    if let Some(owned) = removed_flow.take() {
        if let Some(network) = alice.as_ref() {
            match live_slot_within(
                "cleanup-flow-close",
                cleanup_deadline,
                owned.close_through(network),
            )
            .await
            {
                Ok(Ok(()))
                | Ok(Err(myownmesh_core::realtime::RealtimeRefusal::SessionNotCurrent)) => {}
                Ok(Err(error)) => cleanup_failures.push(format!("flow close: {error}")),
                Err(error) => cleanup_failures.push(error),
            }
        } else {
            cleanup_failures.push("flow close had no Alice network owner".to_owned());
        }
    }
    if let Some(capability) = installed_capability.take() {
        if let Some(owner) = owner.as_ref() {
            if let Some(owned) = owner.take_realtime_flow(capability.expose()) {
                if let Some(network) = alice.as_ref() {
                    match live_slot_within(
                        "cleanup-installed-flow-close",
                        cleanup_deadline,
                        owned.close_through(network),
                    )
                    .await
                    {
                        Ok(Ok(()))
                        | Ok(Err(myownmesh_core::realtime::RealtimeRefusal::SessionNotCurrent)) => {
                        }
                        Ok(Err(error)) => {
                            cleanup_failures.push(format!("installed flow close: {error}"))
                        }
                        Err(error) => cleanup_failures.push(error),
                    }
                } else {
                    cleanup_failures
                        .push("installed flow close had no Alice network owner".to_owned());
                }
            }
        } else {
            cleanup_failures.push("installed flow close had no client owner".to_owned());
        }
    }
    if let Some(flow) = uninstalled_flow.take() {
        if let Some(network) = alice.as_ref() {
            match live_slot_within(
                "cleanup-uninstalled-flow-close",
                cleanup_deadline,
                network.close_realtime(flow),
            )
            .await
            {
                Ok(Ok(()))
                | Ok(Err(myownmesh_core::realtime::RealtimeRefusal::SessionNotCurrent)) => {}
                Ok(Err(error)) => cleanup_failures.push(format!("uninstalled flow close: {error}")),
                Err(error) => cleanup_failures.push(error),
            }
        } else {
            cleanup_failures.push("uninstalled flow close had no Alice network owner".to_owned());
        }
    }
    drop(captured_slot.take());
    if let Some(link) = link.take() {
        match live_slot_within(
            "cleanup-real-link-retire",
            cleanup_deadline,
            link.retire_sessions(),
        )
        .await
        {
            Ok(results) => cleanup_failures.extend(
                results
                    .into_iter()
                    .filter_map(Result::err)
                    .map(|error| error.to_string()),
            ),
            Err(error) => cleanup_failures.push(error),
        }
    }
    for (name, network) in [("alice", alice.as_ref()), ("bob", bob.as_ref())] {
        if let Some(network) = network {
            match live_slot_within(
                "cleanup-network-shutdown",
                cleanup_deadline,
                network.shutdown(),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => cleanup_failures.push(format!("{name} shutdown: {error}")),
                Err(error) => cleanup_failures.push(format!("{name} shutdown: {error}")),
            }
        }
    }
    drop((alice.take(), bob.take(), owner.take()));
    let resource_result = match (
        alice_mesh.as_ref(),
        alice_baseline.as_ref(),
        bob_mesh.as_ref(),
        bob_baseline.as_ref(),
    ) {
        (Some(alice_mesh), Some(alice_baseline), Some(bob_mesh), Some(bob_baseline)) => {
            let alice_report = alice_mesh.resource_report();
            let bob_report = bob_mesh.resource_report();
            require_active_resource_baseline(&alice_report, alice_baseline, "Alice slot cleanup")
                .and_then(|_| {
                    require_active_resource_baseline(&bob_report, bob_baseline, "Bob slot cleanup")
                })
        }
        _ => Ok(()),
    };
    let cleanup_result = if cleanup_failures.is_empty() {
        Ok(())
    } else {
        Err(format!("slot fixture cleanup failed: {cleanup_failures:?}"))
    };
    assert!(resource_result.is_ok(), "{}", resource_result.unwrap_err());
    assert!(cleanup_result.is_ok(), "{}", cleanup_result.unwrap_err());
    assert!(result.is_ok(), "slot custody control failed: {result:?}");
}

#[test]
fn client_id_roundtrips_through_string() {
    let id = ClientId(42);
    assert_eq!(id.to_string(), "c42");
    let parsed: ClientId = "c42".parse().expect("parse");
    assert_eq!(parsed, id);
    assert!("not-an-id".parse::<ClientId>().is_err());
    assert!("c-99".parse::<ClientId>().is_err());
    assert!("c042".parse::<ClientId>().is_err());
}

#[test]
fn ids_are_monotonic_and_unique() {
    let reg = ClientRegistry::default();
    let (a, _ra) = fresh_client(&reg);
    let (b, _rb) = fresh_client(&reg);
    let (c, _rc) = fresh_client(&reg);
    assert_eq!(a.id, ClientId(0));
    assert_eq!(b.id, ClientId(1));
    assert_eq!(c.id, ClientId(2));
    assert!(reg.client(a.id).is_some());
    assert!(reg.client(ClientId(99)).is_none());
    assert!(reg.authenticate(a.id, reg.capability(&a)).is_some());
    assert!(reg.authenticate(b.id, reg.capability(&a)).is_none());
}

#[test]
fn disconnect_winner_returns_completed_install_to_its_sole_cleanup_owner() {
    #[derive(Debug)]
    struct Completed(Arc<AtomicU64>);
    impl Drop for Completed {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    let reg = ClientRegistry::default();
    let (owner, _) = fresh_client(&reg);
    reg.unregister(owner.id).expect("registered owner");
    let drops = Arc::new(AtomicU64::new(0));
    let installed = Arc::new(AtomicBool::new(false));
    let installed_probe = installed.clone();
    let returned = reg
        .install_if_live(
            &owner,
            LeasedMap::<ClaimKey, ()>::entry_claim(),
            Ok(ResourceClaim::ZERO),
            Ok(ResourceClaim::ZERO),
            Completed(drops.clone()),
            move |completed, _entry, _retained, _slot| {
                installed_probe.store(true, Ordering::Release);
                completed
            },
        )
        .expect_err("disconnect won the shared table seam");
    assert!(!installed.load(Ordering::Acquire));
    assert_eq!(drops.load(Ordering::Acquire), 0);
    drop(returned);
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

/// The other side of the seam from
/// `disconnect_winner_returns_completed_install_to_its_sole_cleanup_owner`:
/// an install that lands while its owner is still registered stays landed,
/// and the disconnect path hands back the very handle it landed in — which
/// is what lets the caller's drain find it and close it.
///
/// Bounded deliberately, and the bound is worth stating. A real
/// `RealtimeFlowHandle` is `pub(crate)` to core and cannot be minted from
/// this crate, so this drives `install_if_live` generically rather than
/// `install_realtime_flow`. The ordering under test lives entirely in that
/// seam — the flow table is only what the closure happens to write to — but
/// the consequence is that the end-to-end install → disconnect → drain →
/// close path is still uncovered here.
#[test]
fn an_install_that_wins_the_seam_survives_the_disconnect_that_must_clean_it_up() {
    let reg = ClientRegistry::default();
    let (owner, _) = fresh_client(&reg);
    let table: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

    let landed = table.clone();
    reg.install_if_live(
        &owner,
        LeasedMap::<ClaimKey, ()>::entry_claim(),
        Ok(ResourceClaim::ZERO),
        Ok(ResourceClaim::ZERO),
        7_u32,
        move |value, _entry, _retained, _slot| landed.lock().push(value),
    )
    .expect("a registered, connected owner admits the install");
    assert_eq!(&*table.lock(), &[7], "the install ran");

    let returned = reg.unregister(owner.id).expect("registered owner");
    assert!(
        std::ptr::eq(&*returned.handle, &*owner),
        "disconnect answers with the same handle the install landed in"
    );
    assert_eq!(
        &*table.lock(),
        &[7],
        "unregister does not undo a completed install — the drain that runs \
         after it is what releases one, and it can only release what is \
         still there"
    );

    let refused = table.clone();
    assert!(
        reg.install_if_live(
            &owner,
            LeasedMap::<ClaimKey, ()>::entry_claim(),
            Ok(ResourceClaim::ZERO),
            Ok(ResourceClaim::ZERO),
            9_u32,
            move |value, _entry, _retained, _slot| refused.lock().push(value)
        )
        .is_err(),
        "the same owner admits nothing once it has disconnected"
    );
    assert_eq!(
        &*table.lock(),
        &[7],
        "and the refused value never reached the table"
    );
}

#[test]
fn claim_method_takes_ownership_and_displaces_prior() {
    let reg = ClientRegistry::default();
    let (a, _ra) = fresh_client(&reg);
    let (b, _rb) = fresh_client(&reg);
    let key = ("net".to_string(), "infer".to_string());

    let prev = reg
        .claim_method(key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    assert!(prev.is_none());
    assert_eq!(reg.handler_owner(&key), Some(a.id));
    assert!(a.method_claims.holds(&key));

    let prev = reg
        .claim_method(key.clone(), a.id, HandlerMode::Single)
        .expect("re-claiming a method this client already holds funds nothing new");
    assert!(prev.is_none());

    let prev = reg
        .claim_method(key.clone(), b.id, HandlerMode::Stream)
        .expect("the daemon test grant funds the displacing claim");
    assert_eq!(prev, Some(a.id));
    assert_eq!(reg.handler_owner(&key), Some(b.id));
    assert_eq!(reg.handler_mode(&key), Some(HandlerMode::Stream));
    assert!(b.method_claims.holds(&key));
    assert!(!a.method_claims.holds(&key));
}

#[test]
fn release_method_only_succeeds_for_current_owner() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "infer".to_string());

    reg.claim_method(key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");

    let foreign = reg.release_method(&key, b.id);
    assert!(!foreign.released);
    assert!(
        !foreign.retired(),
        "a release that changed nothing cannot orphan the handler it left alone"
    );
    assert_eq!(reg.handler_owner(&key), Some(a.id));
    assert_eq!(reg.handler_mode(&key), Some(HandlerMode::Single));

    let owned = reg.release_method(&key, a.id);
    assert!(owned.released);
    assert!(
        owned.retired(),
        "the last claim on a method leaves its synthetic handler serving nobody"
    );
    assert!(reg.handler_owner(&key).is_none());
    assert!(
        reg.handler_mode(&key).is_none(),
        "and the record of it is released with the claim rather than kept forever"
    );
    assert!(!a.method_claims.holds(&key));

    let again = reg.release_method(&key, a.id);
    assert!(!again.released);
    assert!(
        !again.retired(),
        "forgetting is answered once; a second release has no handler to orphan"
    );
}

#[test]
fn unregister_drops_claims_and_subscriptions() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let method_key = ("net".to_string(), "infer".to_string());
    let channel_key = ("net".to_string(), "catalog".to_string());

    reg.claim_method(method_key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    reg.subscribe_channel(channel_key.clone(), a.id)
        .expect("the daemon test grant funds one channel subscription");

    assert_eq!(reg.handler_owner(&method_key), Some(a.id));
    let mut members = Vec::new();
    assert!(reg.for_each_subscriber(&channel_key, |client| members.push(client.id)));
    assert_eq!(members, vec![a.id]);

    let removed = reg.unregister(a.id).expect("registered client");

    assert!(reg.handler_owner(&method_key).is_none());
    assert!(!reg.for_each_subscriber(&channel_key, |_| {}));
    assert!(reg.client(a.id).is_none());
    // Popped rather than iterated: the cleanup collections are funded lists now,
    // one allocation per entry, and taking an entry out is what releases that
    // entry's node. The assertion is the same one and is made stronger by it --
    // the list is exhausted afterwards, so this names every method the
    // disconnect forgot rather than the first of them.
    let mut forget = removed.forget;
    let forgotten = forget.pop().expect("the disconnect forgot one method");
    assert_eq!(
        forgotten.key, method_key,
        "a disconnect is the last unclaim too, and it carries out the registration that \
         removes the handler"
    );
    drop(forgotten);
    assert!(
        forget.is_empty(),
        "and exactly one: nothing else was claimed"
    );
}

#[test]
fn unregister_doesnt_collateral_drop_a_displacing_claim() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "infer".to_string());

    reg.claim_method(key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    reg.claim_method(key.clone(), b.id, HandlerMode::Single)
        .expect("the daemon test grant funds the displacing claim");
    assert_eq!(reg.handler_owner(&key), Some(b.id));

    let removed = reg.unregister(a.id).expect("registered client");
    assert_eq!(reg.handler_owner(&key), Some(b.id));
    assert!(
        removed.forget.is_empty(),
        "the displaced client is not the last claimant, so the handler b now \
         owns is not its to have forgotten"
    );
}

/// The first subscriber installs; everyone after it waits or is already live.
///
/// The distinction is between owning the install and waiting on one already
/// under way: a follower that joins a route still being installed must not be
/// told it is subscribed before anything exists to deliver to it.
#[test]
fn v4_f2_daemon_only_the_first_subscriber_owns_the_install() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "catalog".to_string());

    let a_join = reg
        .subscribe_channel(key.clone(), a.id)
        .expect("the daemon test grant funds one channel subscription");
    assert!(
        matches!(a_join, ChannelJoin::Install(_)),
        "the first subscriber owns the install"
    );
    assert!(
        matches!(
            reg.subscribe_channel(key.clone(), b.id)
                .expect("the daemon test grant funds a second member"),
            ChannelJoin::Pending(_)
        ),
        "a follower arriving mid-install must wait, not be told it succeeded"
    );
    assert!(
        matches!(
            reg.subscribe_channel(key.clone(), b.id)
                .expect("re-subscribing funds no second member"),
            ChannelJoin::Pending(_)
        ),
        "and a repeat subscription is still not an install"
    );

    // Both are members already, which is what makes the wait correct rather
    // than merely cautious: they are subscribed, and the route is what is not
    // yet deliverable.
    let mut seen = Vec::new();
    assert!(reg.for_each_subscriber(&key, |client| seen.push(client.id)));
    assert_eq!(seen, vec![a.id, b.id]);
}

/// A failed install refuses every member, not just the installer.
///
/// Unwinding only the caller that discovered the failure would leave a
/// follower that had joined in the meantime holding its membership, with its
/// client already told it was subscribed and no pump to ever notice.
#[tokio::test]
async fn v4_f2_daemon_a_failed_install_unwinds_every_member() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "catalog".to_string());

    let ChannelJoin::Install(installing) = reg
        .subscribe_channel(key.clone(), a.id)
        .expect("the daemon test grant funds one channel subscription")
    else {
        panic!("the first subscriber owns the install")
    };
    let ChannelJoin::Pending(waiting) = reg
        .subscribe_channel(key.clone(), b.id)
        .expect("the daemon test grant funds a second member")
    else {
        panic!("the second subscriber is a follower")
    };

    // The install fails. No pump was built.
    assert!(
        reg.finish_channel_install(&key, &installing, None)
            .is_none(),
        "a failure that built no pump has nothing to hand back"
    );

    assert!(
        !waiting.wait().await,
        "the follower is told the install failed rather than that it succeeded"
    );
    assert!(
        !reg.for_each_subscriber(&key, |_| {}),
        "and the route is gone, with both members, not just the installer"
    );
    assert_eq!(
        reg.residue().channel_routes,
        0,
        "no route survives a failed install"
    );
    // The central tables are only half of it. Each client keeps its own copy of
    // the name, with the lease that funds it, and an unwind that left those
    // installed would be stale ownership: a later retry would skip funding the
    // name because the client "already holds" it, and a disconnect would release
    // a subscription that no longer exists.
    assert!(
        !a.channel_subs.holds(&key),
        "the installer's own held name is released"
    );
    assert!(
        !b.channel_subs.holds(&key),
        "and so is the follower's, which the old unwind never knew about"
    );
    assert_eq!(
        reg.residue().channel_subs,
        0,
        "no client is left holding a name for a route that does not exist"
    );
}

/// A finish that lands on a route it did not install changes nothing.
///
/// The window is real: a route can be emptied by its last unsubscribe and
/// recreated by a new subscriber while the first installer's gateway
/// subscription is still being built. Both routes answer to the same
/// `(network, channel)` key, so a finish that matched on the key alone would
/// publish the first installer's pump into the second installer's route — which
/// then owns two pumps and joins one — or, on failure, delete a route that was
/// perfectly healthy and strand its followers.
#[tokio::test]
async fn v4_f2_daemon_a_stale_installer_cannot_touch_the_route_that_replaced_it() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "catalog".to_string());

    let ChannelJoin::Install(first) = reg
        .subscribe_channel(key.clone(), a.id)
        .expect("the daemon test grant funds one channel subscription")
    else {
        panic!("the first subscriber owns the install")
    };
    // A leaves before its install finishes, so the route is removed and its
    // followers -- none, here -- are owed an answer.
    reg.unsubscribe_channel(&key, a.id)
        .expect("the last member takes the route with it")
        .retire()
        .await;
    // B arrives and creates a second route under the same name.
    let ChannelJoin::Install(second) = reg
        .subscribe_channel(key.clone(), b.id)
        .expect("the daemon test grant funds a second subscription")
    else {
        panic!("the route was removed, so B installs a new one")
    };
    assert!(
        !std::ptr::eq(&*first, &*second),
        "the fixture is only meaningful if these are different generations"
    );

    // Now A's install finishes, late, with a pump.
    let orphan = reg
        .finish_channel_install(&key, &first, Some(fixture_pump(&reg)))
        .expect("a pump published into no route comes back rather than being dropped");
    orphan.retire().await;

    assert_eq!(
        reg.residue().installing_routes,
        1,
        "B's route is untouched -- still installing, not live and not deleted"
    );
    assert!(
        !first.wait().await,
        "A's own generation is told it failed, because for A it did"
    );

    // And B can still finish its own install, which is the proof that nothing
    // was consumed on its behalf.
    assert!(
        reg.finish_channel_install(&key, &second, Some(fixture_pump(&reg)))
            .is_none(),
        "the current installer publishes into its own route"
    );
    assert!(second.wait().await, "and its followers are told it worked");
    assert_eq!(reg.residue().installing_routes, 0);
    assert_eq!(reg.residue().channel_routes, 1);
    reg.unsubscribe_channel(&key, b.id)
        .expect("the last member retires the route")
        .retire()
        .await;
}

/// The last unsubscribe retires the route and hands back its pump.
///
/// Leaving the task to notice on its next frame would make the pump immortal
/// on a channel nobody publishes to, which is exactly where it is useless. The
/// handle comes back so the caller can cancel and join it — and it is
/// `#[must_use]`,
/// because dropping a `JoinHandle` detaches a task rather than stopping it.
#[test]
fn v4_f2_daemon_the_last_unsubscribe_retires_the_route() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "catalog".to_string());

    let ChannelJoin::Install(installing) = reg
        .subscribe_channel(key.clone(), a.id)
        .expect("the daemon test grant funds one channel subscription")
    else {
        panic!("the first subscriber owns the install")
    };
    reg.subscribe_channel(key.clone(), b.id)
        .expect("the daemon test grant funds a second member");
    // A pump the control owns, so retirement has something real to hand back.
    //
    // The runtime is built but deliberately never driven until the retirement
    // below, which is what makes this control discriminating rather than
    // merely descriptive: the spawned task has provably not reached its first
    // poll, so the cancellation arrives strictly *before* anything is listening
    // for it. A bare `Notify` would deliver that wake to nobody -- it reaches
    // whoever is subscribed at that instant and this signal is sent exactly
    // once -- and the task would then park forever on a notification that has
    // already been spent. The flag is what a late waiter reads instead.
    let cancel = reg
        .route_cancellation()
        .expect("the daemon test grant funds one pump cancellation");
    let waiting = cancel.clone();
    let pump = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the fixture pump");
    let join = pump.spawn(async move { waiting.cancelled().await });
    assert!(
        reg.finish_channel_install(&key, &installing, Some((cancel, join)))
            .is_none(),
        "the current installer publishes into its own route"
    );

    assert!(
        reg.unsubscribe_channel(&key, b.id).is_none(),
        "a route with members left is not retired"
    );
    assert_eq!(reg.residue().channel_routes, 1);
    let retired = reg
        .unsubscribe_channel(&key, a.id)
        .expect("the last member retires the route and yields its pump");
    assert_eq!(
        reg.residue().channel_routes,
        0,
        "the route goes with its last member"
    );
    assert!(
        reg.unsubscribe_channel(&key, a.id).is_none(),
        "and an unknown channel retires nothing"
    );
    // The join is the assertion. The timeout is a failure detector and not the
    // authority for success: a pump that lost its only wake never returns from
    // this, and without a bound that regression would hang the control rather
    // than fail it.
    pump.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(10), retired.retire())
            .await
            .expect("the pump observes a cancellation that arrived before it was listening");
    });
}

/// A pump the controls own, spawned on a runtime they drive.
///
/// The cancellation comes from the registry rather than being constructed here,
/// so these fixtures exercise the same funded allocation production does.
fn fixture_pump(
    registry: &ClientRegistry,
) -> (
    FundedArc<crate::ipc::RouteCancellation>,
    tokio::task::JoinHandle<()>,
) {
    let cancel = registry
        .route_cancellation()
        .expect("the daemon test grant funds one pump cancellation");
    let waiting = cancel.clone();
    let join = tokio::spawn(async move { waiting.cancelled().await });
    (cancel, join)
}

/// A closure from an earlier installation cannot route to the client that
/// displaced it.
///
/// The window is real and unavoidable: a synthetic handler's closure is cloned
/// per call and may still be awaiting a response when another client claims the
/// same method. Asking "who owns this name?" would hand that in-flight clone
/// the *newcomer* -- dispatching a call that arrived under one client's class to
/// another client that never agreed to serve it, and filing a pending entry
/// under a coordinate the new owner will never answer.
///
/// So the question is not "who owns this name" but "am I still the installation
/// that was published?", and both halves have to match: the generation, because
/// a name outlives its installations, and the class, because a client that
/// re-claims its own method as a stream is a different installation from the
/// single-shot one it replaced.
#[test]
fn v4_f3_daemon_a_stale_closure_cannot_route_to_the_client_that_displaced_it() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "infer".to_string());

    let (first, displaced) = reg
        .claim_method_generation(key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    assert!(displaced.is_none(), "there was no incumbent to displace");
    assert_eq!(
        reg.handler_owner_for(&key, first, HandlerMode::Single),
        Some(a.id),
        "the installation that was published routes to the client that made it"
    );
    assert_eq!(
        reg.handler_owner_for(&key, first, HandlerMode::Stream),
        None,
        "and only in the shape it was installed as"
    );

    let (second, displaced) = reg
        .claim_method_generation(key.clone(), b.id, HandlerMode::Stream)
        .expect("the daemon test grant funds the displacing claim");
    assert_eq!(displaced, Some(a.id));
    assert_ne!(
        first, second,
        "the fixture is only meaningful if these are different installations"
    );

    assert_eq!(
        reg.handler_owner_for(&key, first, HandlerMode::Single),
        None,
        "A's closure is told nobody holds the method, which for A's own installation is true"
    );
    assert_eq!(
        reg.handler_owner_for(&key, first, HandlerMode::Stream),
        None,
        "and it cannot reach B by guessing the new class either"
    );
    assert_eq!(
        reg.handler_owner_for(&key, second, HandlerMode::Stream),
        Some(b.id),
        "while the installation that is actually published routes normally"
    );
    assert_eq!(
        reg.handler_owner(&key),
        Some(b.id),
        "the claim itself moved: it is the routing question that is exact, not the ownership record"
    );
}

/// A claim the daemon refuses leaves the incumbent installation untouched.
///
/// Refusal is the ordinary case, not the exceptional one: a client that
/// disconnects between funding a registration and committing it, a runtime
/// entering shutdown, a grant with nothing left. Under an install-then-claim
/// order the incumbent's handler would already be overwritten by the time any
/// of those was discovered, so a refused claim would take the method away from
/// a client that was serving it.
///
/// Every field of the incumbent is checked, because "unchanged" has three parts
/// here and only one of them is the owner: a refusal that left the generation
/// or the class moved would silently stop the incumbent's own closure routing
/// while telling it nothing.
#[test]
fn v4_f3_daemon_a_refused_claim_leaves_the_incumbent_generation_and_class_exact() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "infer".to_string());

    let (incumbent, _) = reg
        .claim_method_generation(key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");

    // B goes away between funding its registration and committing it. Core
    // would have published nothing, because the daemon's half refuses first.
    let gone = b.id;
    drop(reg.unregister(gone).expect("registered client"));
    let refusal = reg.claim_method_generation(key.clone(), gone, HandlerMode::Stream);
    assert!(
        matches!(refusal, Err(RegistrationError::ClientGone)),
        "the refusal names the real cause"
    );

    assert_eq!(
        reg.handler_owner(&key),
        Some(a.id),
        "the incumbent still owns the method it was serving"
    );
    assert_eq!(
        reg.handler_mode(&key),
        Some(HandlerMode::Single),
        "in the shape it claimed it, not the one that was refused"
    );
    assert_eq!(
        reg.handler_owner_for(&key, incumbent, HandlerMode::Single),
        Some(a.id),
        "and its own closure still routes -- the generation did not move under it"
    );
    assert!(
        a.method_claims.holds(&key),
        "and the incumbent's own record of the claim is intact"
    );
}

/// The fan-out cursor skips a member that left, excludes one that arrived, and
/// never names the same subscriber twice.
///
/// The lock-scope claim is not this control's: that belongs to
/// `v4_r2_daemon_a_large_channel_frame_does_not_hold_the_registry_while_it_fans_out`
/// in `bridge`, which parks the production pump. What is here is the cursor's
/// own contract, and each clause of it is a way a positional walk goes wrong:
///
/// 1. **A member that left is skipped.** The cursor resumes by client identity,
///    so a subscriber removed mid-frame is passed over rather than re-resolved
///    into whoever came after it — which is what a positional resume does, and
///    it delivers one client's frame to another.
/// 2. **A member that arrived is excluded.** The ceiling is fixed at the first
///    step, so subscriptions taken during a frame belong to the next one.
///    Without it, a client subscribing faster than the fan-out advances extends
///    one frame indefinitely, and the pump never returns to its receiver.
/// 3. **Nobody is named twice.** The two rules above are both about *which*
///    subscribers a frame reaches; a cursor that went backwards would satisfy
///    neither and could still pass a membership check.
#[tokio::test]
async fn v4_r2_daemon_a_fanout_cursor_skips_removed_members_and_never_repeats_one() {
    let reg = ClientRegistry::default();
    let (a, _ra) = fresh_client(&reg);
    let (b, _rb) = fresh_client(&reg);
    let (c, _rc) = fresh_client(&reg);
    let key = ("net".to_string(), "catalog".to_string());

    let ChannelJoin::Install(installing) = reg
        .subscribe_channel(key.clone(), a.id)
        .expect("the daemon test grant funds one channel subscription")
    else {
        panic!("the first subscriber owns the install")
    };
    for member in [b.id, c.id] {
        reg.subscribe_channel(key.clone(), member)
            .expect("the daemon test grant funds a further subscription");
    }
    assert!(
        reg.finish_channel_install(&key, &installing, Some(fixture_pump(&reg)))
            .is_none(),
        "the installer publishes into its own route"
    );
    assert!(
        installing.wait().await,
        "and its followers are told it worked"
    );

    let mut position = crate::ipc::ChannelFanout::frame();
    let mut delivered = Vec::new();
    let crate::ipc::ChannelFanoutStep::Next { client, .. } =
        reg.subscriber_after(&key, crate::ipc::RouteOwner::Any, &mut position)
    else {
        panic!("non-vacuity: a route with three members answers a first step")
    };
    delivered.push(client.id);

    // Mid-frame: one member leaves and one arrives. The arrival is given a
    // larger id than anything the ceiling saw, which is the case the ceiling
    // exists for.
    reg.unregister(b.id)
        .expect("a disconnect is recorded mid-frame");
    let (late, _rlate) = fresh_client(&reg);
    assert!(
        late.id > c.id,
        "non-vacuity: the late subscriber sorts after every member this frame \
         started with, so excluding it is the ceiling's doing and not the walk \
         simply having passed it"
    );
    reg.subscribe_channel(key.clone(), late.id)
        .expect("the daemon test grant funds a late subscription");

    while let crate::ipc::ChannelFanoutStep::Next { client, .. } =
        reg.subscriber_after(&key, crate::ipc::RouteOwner::Any, &mut position)
    {
        delivered.push(client.id);
    }

    assert!(
        !delivered.contains(&b.id),
        "the member that left mid-frame was skipped, not resolved into its \
         successor: {delivered:?}"
    );
    assert!(
        !delivered.contains(&late.id),
        "the member that arrived mid-frame belongs to the next frame: \
         {delivered:?}"
    );
    let mut unique = delivered.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        delivered.len(),
        "and no subscriber was named twice: {delivered:?}"
    );
    assert_eq!(
        unique,
        vec![a.id, c.id],
        "which leaves exactly the members that were subscribed for the whole \
         frame: {delivered:?}"
    );
}

#[tokio::test]
async fn a_resubscription_cannot_inherit_an_in_flight_frame() {
    let reg = ClientRegistry::default();
    let (a, _ra) = fresh_client(&reg);
    let (b, _rb) = fresh_client(&reg);
    let key = ("net".to_string(), "membership".to_string());

    let ChannelJoin::Install(installing) = reg
        .subscribe_channel(key.clone(), a.id)
        .expect("the first exact membership is admitted")
    else {
        panic!("the first subscriber owns installation")
    };
    reg.subscribe_channel(key.clone(), b.id)
        .expect("the second exact membership is admitted");
    assert!(reg
        .finish_channel_install(&key, &installing, Some(fixture_pump(&reg)))
        .is_none());

    let mut old_frame = crate::ipc::ChannelFanout::frame();
    let crate::ipc::ChannelFanoutStep::Next { client } =
        reg.subscriber_after(&key, crate::ipc::RouteOwner::Any, &mut old_frame)
    else {
        panic!("non-vacuity: the old frame selects its first member")
    };
    assert_eq!(client.id, a.id);

    assert!(reg.unsubscribe_channel(&key, b.id).is_none());
    reg.subscribe_channel(key.clone(), b.id)
        .expect("the same client receives a fresh membership");
    assert!(matches!(
        reg.subscriber_after(&key, crate::ipc::RouteOwner::Any, &mut old_frame),
        crate::ipc::ChannelFanoutStep::End
    ));

    let mut next_frame = crate::ipc::ChannelFanout::frame();
    let mut delivered = Vec::new();
    while let crate::ipc::ChannelFanoutStep::Next { client } =
        reg.subscriber_after(&key, crate::ipc::RouteOwner::Any, &mut next_frame)
    {
        delivered.push(client.id);
    }
    assert_eq!(delivered, vec![a.id, b.id]);
    eprintln!("route-resubscription: membership assertions complete; before scope teardown");
}

/// Unlike the retirement controls that keep an external custodian alive, only
/// weak observations escape this runtime. The child really owns and uses the
/// funded cancellation, so its destruction can release the last custodian.
/// The manager's external process envelope bounds a hang; a timeout is never
/// success, and this control does not replace teardown with explicit retirement.
#[test]
fn route_last_owner_runtime_drop_releases_captured_cancellation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the last-owner fixture runtime builds");
    let (cancel_observer, retirement_observer, registry_observer, installed) =
        runtime.block_on(async {
            let reg = ClientRegistry::default();
            let (client, _receiver) = fresh_client(&reg);
            let key = ("net".to_string(), "last-owner".to_string());
            let ChannelJoin::Install(installing) = reg
                .subscribe_channel(key.clone(), client.id)
                .expect("the original exact membership is admitted")
            else {
                panic!("the first subscriber owns installation")
            };
            let cancel = reg
                .route_cancellation()
                .expect("the existing daemon grant funds the exact pump cancellation");
            let cancel_observer = cancel.downgrade();
            let retirement_observer = cancel.retirement.downgrade();
            let registry_observer = Arc::downgrade(&reg.inner);
            let waiting = cancel.clone();
            let join = tokio::spawn(async move { waiting.cancelled().await });
            let orphan = reg.finish_channel_install(&key, &installing, Some((cancel, join)));
            let installed = orphan.is_none();
            // Preserve the existing abort/handoff Drop path even on an
            // unexpected install refusal; no orphaned join is detached here.
            drop(orphan);
            (
                cancel_observer,
                retirement_observer,
                registry_observer,
                installed,
            )
        });

    eprintln!("route-last-owner: before runtime destruction");
    drop(runtime);
    eprintln!("route-last-owner: after runtime destruction");

    assert!(installed, "the exact original pump was installed");
    assert_eq!(cancel_observer.strong_count(), 0);
    assert!(
        cancel_observer.upgrade().is_none(),
        "no funded cancellation owner survives runtime destruction"
    );
    assert!(
        retirement_observer.upgrade().is_none(),
        "the exact retirement custodian has been destroyed"
    );
    assert!(
        registry_observer.upgrade().is_none(),
        "the original registry has no surviving owner"
    );
    // Weak expiry and runtime destruction are the available terminal evidence.
    // The shared fixture provider is not an isolated zero-census oracle, and
    // the custodian's shared terminal bit is not proof both threads joined.
}

// An explicitly owned root: its finite provider is never installed in OnceLock.
// The registry remains alive across the before/after comparison, so its process
// scope and independently owned final-watchdog custody have identical lifetimes.
fn isolated_route_join_fixture() -> (
    ClientRegistry,
    myownmesh_core::FiniteResourceProvider,
    RouteJoinOwner,
    ResourceClaim,
) {
    let grant = registry_fixture_claim(1, 1, 10)
        .map_err(IpcAdmissionError::Claim)
        .and_then(|claim| {
            claim
                .checked_add(route_join_root_planning_charge()?)
                .map_err(IpcAdmissionError::Claim)
        })
        .and_then(|claim| {
            claim
                .checked_add(
                    route_custody_planning_charge()?
                        .checked_scale(2)
                        .map_err(IpcAdmissionError::Claim)?,
                )
                .map_err(IpcAdmissionError::Claim)
        })
        .expect("two exact route custodians and one isolated join root are representable");
    let registry = ClientRegistry::over_grant(grant);
    let RegistryResources::Isolated {
        _provider: provider,
        ..
    } = &registry.inner.resources
    else {
        unreachable!("over_grant owns an isolated provider")
    };
    let provider = provider.clone();
    let baseline = provider.in_use();
    let owner = RouteJoinOwner::reserve(&registry.inner.resources)
        .expect("the exact root planning claim admits its owner");
    (registry, provider, owner, baseline)
}

#[test]
fn route_join_isolated_last_owner_runtime_drop_joins_and_releases_every_owner() {
    let (registry, provider, owner, _registry_baseline) = isolated_route_join_fixture();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the isolated last-owner runtime starts");
    let port = owner.port.clone();
    let (cancel_weak, retirement_weak, registry_weak, terminal, watchdogs, installed) = runtime
        .block_on(async move {
            let (client, _receiver) = fresh_client(&registry);
            let key = ("net".to_string(), "last-owner".to_string());
            let ChannelJoin::Install(installing) = registry
                .subscribe_channel(key.clone(), client.id)
                .expect("the exact isolated membership is admitted")
            else {
                panic!("the first member owns installation")
            };
            let cancel = registry
                .route_cancellation_with_port(port, None)
                .expect("the isolated owner admits the actual funded cancellation");
            let terminal = cancel.retirement.terminal.clone();
            let cancel_weak = cancel.downgrade();
            let retirement_weak = cancel.retirement.downgrade();
            let registry_weak = Arc::downgrade(&registry.inner);
            let waiting = cancel.clone();
            let pump_registry = registry.clone();
            let child = tokio::spawn(async move {
                let _registry = pump_registry;
                waiting.cancelled().await;
            });
            let orphan = registry.finish_channel_install(&key, &installing, Some((cancel, child)));
            let installed = orphan.is_none();
            drop(orphan);
            // The unrelated registry watchdog owner also owns native threads.
            // Take their actual handles while its senders are still open so
            // this isolated control can join ALL fixture owners after teardown.
            // No watchdog/registry/cancellation owner Arc escapes this block.
            let watchdogs = {
                let tables = registry.inner.tables.lock();
                let custody = tables
                    .final_watchdog_custody
                    .as_ref()
                    .expect("the registry has its original watchdog custody");
                let primary = route_join_lock(&custody.custodian.worker).take();
                let fallback = route_join_lock(&custody.custodian.fallback_worker).take();
                [primary, fallback]
            };
            (
                cancel_weak,
                retirement_weak,
                registry_weak,
                terminal,
                watchdogs,
                installed,
            )
        });
    eprintln!("route-isolated-last-owner: before runtime destruction");
    drop(runtime);
    eprintln!("route-isolated-last-owner: after runtime destruction");
    // Only the independent Owner can join the root. The funded terminal
    // witness retains neither cancellation nor custodian nor registry.
    drop(owner);
    let watchdogs_joined = watchdogs.map(|handle| match handle {
        Some(handle) => handle.join().is_ok(),
        None => false,
    });
    let joined = terminal.observed.load(Ordering::Acquire);
    let errors = terminal.join_errors.load(Ordering::Acquire);
    let expired = cancel_weak.strong_count() == 0
        && cancel_weak.upgrade().is_none()
        && retirement_weak.upgrade().is_none()
        && registry_weak.upgrade().is_none();
    drop((terminal, cancel_weak, retirement_weak, registry_weak));
    let final_claim = provider.in_use();
    let final_reservations = provider.active_reservations();
    let final_scopes = provider.active_scopes();
    assert!(
        installed && expired && joined,
        "installed={installed}, exact owners expired={expired}, both observers joined={joined}"
    );
    assert_eq!(errors, 0);
    assert!(watchdogs_joined.into_iter().all(|joined| joined));
    assert_eq!(final_claim, ResourceClaim::ZERO);
    assert_eq!(final_reservations, 0);
    assert_eq!(final_scopes, 0);
}

#[test]
fn route_join_close_waits_for_registered_unqueued_custody() {
    let (registry, provider, owner, baseline) = isolated_route_join_fixture();
    let cancel = registry
        .route_cancellation_with_port(owner.port.clone(), None)
        .expect("the route registers before its observers start");
    let terminal = cancel.retirement.terminal.clone();
    let port = owner.port.clone();
    owner.close();
    let registered_unqueued = {
        let mut state = route_join_lock(&port.0.state);
        while !state.waiting_after_close {
            state = port
                .0
                .changed
                .wait(state)
                .expect("the test custody fence is not poisoned");
        }
        !state.accepting && state.outstanding == 1 && state.head.is_none()
    };
    let root_still_waiting = !owner
        .worker
        .as_ref()
        .expect("the owner retains its join")
        .is_finished();
    let refused = matches!(
        registry.route_cancellation_with_port(port.clone(), None),
        Err(IpcAdmissionError::Closing)
    );
    // The already registered node must still be accepted AFTER close.
    drop(cancel);
    drop(owner);
    let joined = terminal.observed.load(Ordering::Acquire);
    let join_errors = terminal.join_errors.load(Ordering::Acquire);
    let outstanding = route_join_lock(&port.0.state).outstanding;
    drop((terminal, port));
    let restored = provider.in_use() == baseline;
    drop(registry);
    assert!(registered_unqueued && root_still_waiting && refused);
    assert!(joined);
    assert_eq!(join_errors, 0);
    assert_eq!(outstanding, 0);
    assert!(
        restored,
        "the isolated root itself and every route lease returned"
    );
}

#[test]
fn route_join_constructor_refusals_leave_no_registered_node() {
    let (registry, provider, owner, baseline) = isolated_route_join_fixture();
    let root_baseline = provider.in_use();
    let mut refused = [false; 2];
    let mut restored = [false; 2];
    for index in 0..2 {
        refused[index] = matches!(
            registry.route_cancellation_with_port(owner.port.clone(), Some(index)),
            Err(IpcAdmissionError::CustodyUnavailable)
        );
        restored[index] = provider.in_use() == root_baseline
            && route_join_lock(&owner.port.0.state).outstanding == 0;
    }
    // Scope plus registry watchdog custody only: no cancellation-record lease
    // can be acquired, and no observer or registered node may be produced.
    let starved = ClientRegistry::over_grant(
        registry_fixture_claim(0, 0, 0).expect("the scope claim is representable"),
    );
    let before = starved.in_use();
    let record_refused = matches!(
        starved.route_cancellation_with_port(owner.port.clone(), None),
        Err(IpcAdmissionError::Resources(_))
    );
    let refusal_clean =
        starved.in_use() == before && route_join_lock(&owner.port.0.state).outstanding == 0;
    drop(starved);
    drop(owner);
    let root_restored = provider.in_use() == baseline;
    drop(registry);
    assert!(refused.into_iter().all(|value| value));
    assert!(restored.into_iter().all(|value| value));
    assert!(record_refused && refusal_clean && root_restored);
}

#[test]
fn route_join_two_queued_pairs_retain_funding_through_fallback_join() {
    let (registry, provider, owner, baseline) = isolated_route_join_fixture();
    let root_baseline = provider.in_use();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the pair-gate runtime starts");
    let mut primary_gates = Vec::new();
    let mut fallback_gates = Vec::new();
    let mut primary_done = Vec::new();
    let mut fallback_done = Vec::new();
    let mut witnesses = Vec::new();
    for _ in 0..2 {
        let cancel = registry
            .route_cancellation_with_port(owner.port.clone(), None)
            .expect("both exact paired-observer reservations are admitted");
        witnesses.push(cancel.retirement.terminal.clone());
        for (index, destination) in [
            &cancel.retirement.sender,
            &cancel.retirement.fallback_sender,
        ]
        .into_iter()
        .enumerate()
        {
            let (release, wait) = tokio::sync::oneshot::channel::<()>();
            let (finished, done) = tokio::sync::oneshot::channel::<()>();
            let task = runtime.spawn(async move {
                let _ = wait.await;
                let _ = finished.send(());
            });
            // Exercise both actual observer receivers, not a synthetic funding
            // flag. Each receives its one exact task while that task is gated.
            let sender = route_join_lock(destination);
            if let Err(refused) = sender
                .as_ref()
                .expect("the observer sender is live")
                .try_send(task)
            {
                let _retained_handle = refused;
                std::process::abort();
            }
            if index == 0 {
                primary_gates.push(release);
                primary_done.push(done);
            } else {
                fallback_gates.push(release);
                fallback_done.push(done);
            }
        }
        drop(cancel);
    }
    owner.close();
    let pair_workers = route_retirement_claim()
        .expect("the pair claim is valid")
        .amount(ResourceClass::WorkerOrTask)
        .checked_mul(2)
        .expect("two pairs fit");
    let expected_workers = root_baseline
        .amount(ResourceClass::WorkerOrTask)
        .checked_add(pair_workers)
        .expect("root and two pairs fit");
    let both_pairs_held = provider.in_use().amount(ResourceClass::WorkerOrTask) == expected_workers;
    for gate in primary_gates {
        let _ = gate.send(());
    }
    runtime.block_on(async {
        for done in primary_done {
            let _ = done.await;
        }
    });
    // Observe each real primary's terminal body, not just its child's signal.
    // The fallback tasks remain gated throughout this observation.
    for terminal in &witnesses {
        let mut exited = route_join_lock(&terminal.exited);
        while *exited & 1 == 0 {
            exited = terminal
                .exited_changed
                .wait(exited)
                .expect("the observer-exit fence is not poisoned");
        }
    }
    let fallback_still_holds_pairs = provider.in_use().amount(ResourceClass::WorkerOrTask)
        == expected_workers
        && witnesses
            .iter()
            .all(|terminal| !terminal.observed.load(Ordering::Acquire));
    for gate in fallback_gates {
        let _ = gate.send(());
    }
    runtime.block_on(async {
        for done in fallback_done {
            let _ = done.await;
        }
    });
    drop(runtime);
    drop(owner);
    let joined = witnesses.iter().all(|terminal| {
        terminal.observed.load(Ordering::Acquire)
            && terminal.join_errors.load(Ordering::Acquire) == 0
    });
    drop(witnesses);
    let restored = provider.in_use() == baseline;
    drop(registry);
    assert!(both_pairs_held && fallback_still_holds_pairs);
    assert!(joined && restored);
}

#[test]
fn route_join_isolated_normal_and_cancelled_retirement_restore_baseline() {
    for cancelled in [false, true] {
        let (registry, provider, owner, baseline) = isolated_route_join_fixture();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the retirement runtime starts");
        let terminal = runtime.block_on(async {
            let cancel = registry
                .route_cancellation_with_port(owner.port.clone(), None)
                .expect("the actual cancellation record and observers are funded");
            let retirement = cancel.retirement();
            let terminal = retirement.terminal.clone();
            let waiting = cancel.clone();
            let child = tokio::spawn(async move { waiting.cancelled().await });
            let retired = RetiredRoute::orphaned_pump(cancel, child);
            if cancelled {
                // Poll the actual retire future to its child-join boundary,
                // then drop that future while the child is still unpolled.
                let mut retiring = std::pin::pin!(retired.retire());
                let pending = std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(
                        std::future::Future::poll(retiring.as_mut(), cx).is_pending(),
                    )
                })
                .await;
                // No assertion before cleanup; record unexpected readiness as
                // a scalar alongside the independently funded terminal witness.
                // Leaving this branch drops pin!'s underlying retire future,
                // before the runtime and isolated join owner are destroyed.
                (terminal, pending)
            } else {
                retired.retire().await;
                (terminal, true)
            }
        });
        drop(runtime);
        drop(owner);
        let joined = terminal.0.observed.load(Ordering::Acquire);
        let errors = terminal.0.join_errors.load(Ordering::Acquire);
        let pending = terminal.1;
        drop(terminal);
        let restored = provider.in_use() == baseline;
        drop(registry);
        assert!(joined && pending && restored);
        assert_eq!(errors, 0);
    }
}

/// A route that was replaced answers `Gone` to its predecessor's pump, and the
/// predecessor cannot reach the successor's members.
///
/// The window is real: a pump is cancelled and joined by the route that owns it,
/// but a frame already in flight inside that pump can ask for its next
/// subscriber after the route it belonged to has been removed and a new one
/// installed under the same name. Answering by *name* would hand the old pump
/// the successor's subscriber set — one channel's fan-out delivering into
/// another's, under a key that looks identical.
///
/// The identity is the route's own cancellation `Arc`, not a generation counter
/// or a ledger: it is the thing the pump was handed and the thing the route
/// holds, so "is this my route" is a pointer comparison that cannot go stale.
///
/// Non-vacuity is the second half: the *current* pump's own identity is answered
/// `Next` against the same key and the same members, so `Gone` above is about
/// identity and not about the route being empty or unusable.
#[tokio::test]
async fn v4_r2_daemon_a_replaced_route_answers_gone_to_its_predecessors_pump() {
    let reg = ClientRegistry::default();
    let (a, _ra) = fresh_client(&reg);
    let (b, _rb) = fresh_client(&reg);
    let key = ("net".to_string(), "catalog".to_string());

    // Generation one, live, with a pump of its own.
    let ChannelJoin::Install(first) = reg
        .subscribe_channel(key.clone(), a.id)
        .expect("the daemon test grant funds one channel subscription")
    else {
        panic!("the first subscriber owns the install")
    };
    let (first_cancel, first_join) = fixture_pump(&reg);
    let predecessor = first_cancel.clone();
    assert!(reg
        .finish_channel_install(&key, &first, Some((first_cancel, first_join)))
        .is_none());
    assert!(first.wait().await);

    // Its last member leaves, so the route is retired and its pump joined.
    reg.unsubscribe_channel(&key, a.id)
        .expect("the last member retires the route")
        .retire()
        .await;

    // Generation two, under the same name, with a different member and a
    // different pump.
    let ChannelJoin::Install(second) = reg
        .subscribe_channel(key.clone(), b.id)
        .expect("the daemon test grant funds a second subscription")
    else {
        panic!("the route was removed, so this installs a new one")
    };
    let (second_cancel, second_join) = fixture_pump(&reg);
    let successor = second_cancel.clone();
    assert!(reg
        .finish_channel_install(&key, &second, Some((second_cancel, second_join)))
        .is_none());
    assert!(second.wait().await);
    assert!(
        !std::ptr::eq(&*predecessor, &*successor),
        "non-vacuity: these are different route identities"
    );

    // The predecessor's in-flight frame asks for its next subscriber.
    let mut position = crate::ipc::ChannelFanout::frame();
    assert!(
        matches!(
            reg.subscriber_after(
                &key,
                crate::ipc::RouteOwner::Pump(&predecessor),
                &mut position
            ),
            crate::ipc::ChannelFanoutStep::Gone
        ),
        "the old pump is told its route is gone rather than being handed the \
         successor's members"
    );

    // And the successor's own frame reaches its own member.
    let mut position = crate::ipc::ChannelFanout::frame();
    let crate::ipc::ChannelFanoutStep::Next { client, .. } = reg.subscriber_after(
        &key,
        crate::ipc::RouteOwner::Pump(&successor),
        &mut position,
    ) else {
        panic!("non-vacuity: the live route answers its own pump")
    };
    assert_eq!(
        client.id, b.id,
        "with the member that subscribed to it, and no other"
    );

    reg.unsubscribe_channel(&key, b.id)
        .expect("the last member retires the route")
        .retire()
        .await;
}

/// Exact capacity for a live client and a chosen number of pending calls.
///
/// Unlike [`registry_fixture_claim`], this intentionally carries no unrelated
/// table or cleanup headroom. Each term is one reservation production makes:
/// the client record and its index node, then the pending table node, the
/// pending value's off-node retention, and its cleanup-list node. The provider
/// prices every reservation and the registry scope itself, so the positive half
/// of the control below proves this exact composite is sufficient.
fn pending_fixture_claim(
    clients: u64,
    pending: u64,
    network: &str,
    method: &str,
    remote_peer: &str,
    remote_request_id: &str,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let planned = |claim| {
        myownmesh_core::FiniteResourceProvider::reservation_planning_charge(claim)
            .expect("a fixture reservation charge is representable")
    };
    let client = planned(client_record_claim()?)
        .checked_add(planned(
            LeasedMap::<ClientId, FundedArc<ClientHandle>>::entry_claim()?,
        ))?;
    let pending_entry = planned(LeasedMap::<PendingKey, PendingRecord>::entry_claim()?)
        .checked_add(planned(pending_retained_for(
            network,
            method,
            remote_peer,
            remote_request_id,
        )?))?
        .checked_add(planned(pending_cancellation_claim()?))?
        .checked_add(planned(
            crate::ipc::LeasedList::<PendingRecord>::node_claim()?,
        ))?;
    myownmesh_core::FiniteResourceProvider::scope_planning_charge()
        .checked_add(client.checked_scale(clients)?)?
        .checked_add(pending_entry.checked_scale(pending)?)
}

/// A pending inbound call under pressure is refused before any of it is built.
///
/// The property is an ordering, not a number. A refusal arriving after the
/// build would arrive after four copies of peer-chosen coordinates in a
/// `PendingKey`, the channel that would have carried the answer back, and — one
/// layer up, in the bridge — a clone of the peer's own payload. A remote peer
/// chooses how
/// many inbound calls there are, so a daemon that allocated all of that in order
/// to say no was a daemon whose refusal path was the expensive one.
///
/// Three observations, and the second is the one a "did it refuse" control
/// misses. The refusal is a typed admission failure rather than a collision, so
/// a peer is not told to fix coordinates that were fine; the ledger is exactly
/// where it was before the call, so nothing was taken and returned either; and
/// no pending record exists, so nothing was half-filed.
///
/// The fourth allocation — the payload clone — is not here on purpose. It belongs to the outbound frame, which is admitted by the client's
/// writer mailbox from a borrowed measurement, and is the subject of
/// `v4_r2_daemon_a_measured_inbound_frame_matches_the_frame_it_becomes` in
/// `bridge`. Folding the two together would make one control that fails for two
/// unrelated reasons.
#[tokio::test]
async fn v4_r2_daemon_pending_ipc_pressure_refuses_before_the_call_is_built() {
    let key: ClaimKey = ("n".to_string(), "m".to_string());
    // One exact client and no pending-call capacity: the live owner is funded,
    // while all three reservations the pending call needs are absent.
    let starved = ClientRegistry::over_grant(
        pending_fixture_claim(1, 0, &key.0, &key.1, "peer", "req")
            .expect("the starved fixture claim is representable"),
    );
    let (a, _) = fresh_client(&starved);

    let baseline = starved
        .in_use()
        .expect("a fixture registry over its own grant answers its ledger");
    let refusal =
        match starved.prepare_exact_pending(&key, "peer", "req", HandlerMode::Single, a.id) {
            Ok(_) => panic!("a registry with no entry funding cannot admit a pending call"),
            Err(refusal) => refusal,
        };
    assert!(
        matches!(refusal, PendingRefusal::Admission(_)),
        "refused as pressure, not as a collision or a departed owner: {refusal}"
    );
    assert_eq!(
        starved.in_use(),
        Some(baseline),
        "and the refusal left the ledger exactly where it found it -- nothing was \
         taken on the way to being declined"
    );
    assert_eq!(starved.residue().pending_inbound, 0, "and filed nothing");

    // Non-vacuity: the same call and coordinates, with exactly one composite
    // pending-call charge and no unrelated table or cleanup capacity.
    let funded = ClientRegistry::over_grant(
        pending_fixture_claim(1, 1, &key.0, &key.1, "peer", "req")
            .expect("the funded fixture claim is representable"),
    );
    let (b, _) = fresh_client(&funded);
    let baseline = funded
        .in_use()
        .expect("a fixture registry over its own grant answers its ledger");
    let prepared = funded
        .prepare_exact_pending(&key, "peer", "req", HandlerMode::Single, b.id)
        .expect("a funded registry admits the same call");
    assert_ne!(
        funded.in_use(),
        Some(baseline),
        "non-vacuity: admitting it really does cost something, so the starved \
         half above was refusing a real acquisition"
    );
    let (ticket, _rx) = funded
        .commit_exact_single_pending(prepared, "peer", "req")
        .expect("and it files");
    assert_eq!(funded.residue().pending_inbound, 1);
    drop(ticket);
}

/// A prepared call cannot be filed in a class it was not funded for.
///
/// The two-phase filing measures a pending call from borrowed coordinates and
/// then builds it, and the class is fixed in the first half: it is part of the
/// key the record is stored under and part of what a later `RpcRespond` or
/// `RpcStreamChunk` is matched against. Production cannot get this wrong --
/// `commit_exact_single_pending` and `commit_exact_stream_pending` each pass a
/// constant that matches the preparation they accept, and there is no other way
/// in from outside this module. That is exactly why the check underneath them is
/// worth a control: an invariant kept only by "nobody calls it that way" is one
/// nothing would notice becoming false.
///
/// What it would cost is a stream's sender filed under a single-shot's funding
/// and a single-shot's key: chunks the peer sends would find a record whose
/// class says to resolve it once and finish, and the daemon would answer a
/// streaming call in a shape the peer never asked for.
///
/// Driven against the shared body directly, which is the only way to produce the
/// disagreement at all.
#[tokio::test]
async fn v4_r2_daemon_a_pending_call_cannot_be_filed_in_a_class_it_was_not_funded_for() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key: ClaimKey = ("n".to_string(), "m".to_string());

    let prepared = reg
        .prepare_exact_pending(&key, "peer", "req", HandlerMode::Single, a.id)
        .expect("a fresh registry funds one pending call");
    let mut built = false;
    let refusal =
        match reg.commit_exact_pending_as(prepared, "peer", "req", HandlerMode::Stream, || {
            built = true;
            let (tx, rx) = oneshot::channel();
            (PendingInbound::Single(tx), rx)
        }) {
            Ok(_) => panic!("a single-shot preparation cannot be filed as a stream"),
            Err(refusal) => refusal,
        };
    assert!(
        matches!(refusal, PendingRefusal::ClassMismatch),
        "and it says which invariant it kept, not that the coordinates collided: {refusal}"
    );
    assert!(
        !built,
        "and it refused before the effect was built, like every other refusal on \
         this path"
    );

    // Non-vacuity, and the proof that the refusal filed nothing: the same
    // coordinates, in the class they were funded for, are accepted. Had the
    // mismatched commit inserted a record, this would be refused as a duplicate
    // -- so one assertion covers both "the good path still works" and "the bad
    // path left no trace".
    let prepared = reg
        .prepare_exact_pending(&key, "peer", "req", HandlerMode::Single, a.id)
        .expect("a fresh registry funds one pending call");
    let (ticket, _rx) = reg
        .commit_exact_single_pending(prepared, "peer", "req")
        .expect("the same coordinates are still vacant, and the matching class files");
    drop(ticket);
}

#[tokio::test]
async fn exact_owner_coordinates_and_operation_identity_all_match() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "same".into(),
        class: HandlerMode::Single,
    };
    let (tx, rx) = oneshot::channel();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Single(tx)) else {
        panic!("first claim must be vacant")
    };
    assert!(!reg.resolve_exact_single(
        &key,
        b.id,
        ticket.operation_id(),
        Ok(serde_json::json!("foreign"))
    ));
    assert!(!reg.resolve_exact_single(
        &key,
        a.id,
        ticket.operation_id() + 1,
        Ok(serde_json::json!("stale"))
    ));
    assert!(reg.resolve_exact_single(
        &key,
        a.id,
        ticket.operation_id(),
        Ok(serde_json::json!("mine"))
    ));
    assert_eq!(
        rx.await.expect("settled").expect("success"),
        serde_json::json!("mine")
    );
}

#[test]
fn collision_refuses_newcomer_and_disconnect_truthfully_settles_owner() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "same".into(),
        class: HandlerMode::Single,
    };
    let (first_tx, first_rx) = oneshot::channel();
    let Ok(_ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Single(first_tx))
    else {
        panic!("incumbent must be vacant")
    };
    let (new_tx, _new_rx) = oneshot::channel();
    assert!(reg
        .insert_exact_pending(key, a.id, PendingInbound::Single(new_tx))
        .is_err());
    reg.unregister(a.id);
    assert!(
        matches!(first_rx.blocking_recv(), Ok(Err(message)) if message.contains("disconnected"))
    );
}

#[test]
fn identical_remote_id_in_distinct_scopes_does_not_displace() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = |network: &str| PendingKey {
        network: network.into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "same".into(),
        class: HandlerMode::Single,
    };
    let (tx_a, _) = oneshot::channel();
    let (tx_b, _) = oneshot::channel();
    assert!(reg
        .insert_exact_pending(key("a"), a.id, PendingInbound::Single(tx_a))
        .is_ok());
    assert!(reg
        .insert_exact_pending(key("b"), a.id, PendingInbound::Single(tx_b))
        .is_ok());
}

#[tokio::test]
async fn handler_displacement_settles_only_that_exact_claim() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    reg.claim_method(("n".into(), "m".into()), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    reg.claim_method(("n".into(), "other".into()), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds a second method claim");
    let key = |method: &str| PendingKey {
        network: "n".into(),
        method: method.into(),
        remote_peer: "peer".into(),
        remote_request_id: "same".into(),
        class: HandlerMode::Single,
    };
    let (m_tx, m_rx) = oneshot::channel();
    let (other_tx, other_rx) = oneshot::channel();
    let Ok(_m) = reg.insert_exact_pending(key("m"), a.id, PendingInbound::Single(m_tx)) else {
        panic!("m")
    };
    let Ok(other) = reg.insert_exact_pending(key("other"), a.id, PendingInbound::Single(other_tx))
    else {
        panic!("other")
    };
    assert_eq!(
        reg.claim_method(("n".into(), "m".into()), b.id, HandlerMode::Single)
            .expect("the daemon test grant funds the displacing claim"),
        Some(a.id)
    );
    assert!(matches!(m_rx.await, Ok(Err(message)) if message.contains("displaced")));
    assert!(reg.resolve_exact_single(
        &key("other"),
        a.id,
        other.operation_id(),
        Ok(serde_json::json!("still-owned"))
    ));
    assert!(matches!(other_rx.await, Ok(Ok(value)) if value == serde_json::json!("still-owned")));
}

/// A stream mailbox for one control, funded from the test grant.
fn stream_mailbox() -> (
    myownmesh_core::ResourceMailboxSender<myownmesh_core::rpc::RpcStreamItem>,
    myownmesh_core::ResourceMailboxReceiver<myownmesh_core::rpc::RpcStreamItem>,
) {
    myownmesh_core::resource_mailbox(crate::test_application_scope())
        .expect("the daemon test grant funds one inbound stream queue")
}

fn stream_key(request_id: &str) -> PendingKey {
    PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: request_id.into(),
        class: HandlerMode::Stream,
    }
}

/// Assert the next delivery carries `expected`, reading it through the
/// delivery rather than taking it out.
///
/// The comparison happens while the delivery is still whole and its funding is
/// still held; the delivery is dropped when this returns. The helper asserts
/// rather than returning the item because it cannot return one: a delivered
/// value is only reachable by borrow, and a borrow of the temporary this is
/// handed could not outlive the call.
fn assert_next_item(
    delivery: Option<myownmesh_core::ResourceMailboxDelivery<myownmesh_core::rpc::RpcStreamItem>>,
    expected: myownmesh_core::rpc::RpcStreamItem,
    context: &str,
) {
    assert_eq!(
        delivery
            .as_ref()
            .map(myownmesh_core::ResourceMailboxDelivery::value),
        Some(&expected),
        "{context}"
    );
}

/// Assert the stream has nothing further to deliver.
fn assert_no_next_item(
    delivery: Option<myownmesh_core::ResourceMailboxDelivery<myownmesh_core::rpc::RpcStreamItem>>,
    context: &str,
) {
    assert!(delivery.is_none(), "{context}");
}

/// The terminal item is delivered behind a chunk already resident in the
/// queue, never ahead of it.
///
/// The queue is bounded by what the owner funded, measured per chunk, not by
/// a number of chunks, so the ordering is asserted directly rather than by
/// filling a fixed-capacity channel and watching a closer block.
#[tokio::test]
async fn a_terminal_item_is_delivered_behind_a_resident_chunk() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = stream_key("ordered");
    let (tx, mut rx) = stream_mailbox();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx)) else {
        panic!("stream claim")
    };
    let operation_id = ticket.operation_id();
    assert!(reg.push_exact_stream(&key, a.id, operation_id, serde_json::json!(1)));
    assert!(reg.close_exact_stream(&key, a.id, operation_id, None));
    assert_next_item(
        rx.recv().await,
        myownmesh_core::rpc::RpcStreamItem::Chunk(serde_json::json!(1)),
        "the resident chunk is delivered first",
    );
    assert_next_item(
        rx.recv().await,
        myownmesh_core::rpc::RpcStreamItem::End(Ok(())),
        "the terminal item follows it rather than overtaking it",
    );
}

/// Once a stream has been settled, no further chunk can be written into it.
///
/// The settlement removes the record and fires its cancellation under the
/// registry's tables, before the terminal item goes out, so a later push
/// finds nothing to push into. That is what keeps a chunk from appearing
/// after the `End` its peer has already been told is final — and it is now
/// the whole of the guarantee, because with no queue capacity there is no
/// such thing as a chunk parked behind one.
#[tokio::test]
async fn a_chunk_cannot_be_written_after_terminal_settlement() {
    let reg = ClientRegistry::default();
    let (owner, _) = fresh_client(&reg);
    let owner_id = owner.id;
    let key = stream_key("settled");
    let (tx, mut rx) = stream_mailbox();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), owner_id, PendingInbound::Stream(tx))
    else {
        panic!("vacant stream")
    };
    let operation_id = ticket.operation_id();
    assert!(reg.push_exact_stream(&key, owner_id, operation_id, serde_json::json!(1)));
    assert!(reg.close_exact_stream(&key, owner_id, operation_id, None));
    assert!(
        !reg.push_exact_stream(&key, owner_id, operation_id, serde_json::json!(2)),
        "a chunk offered after settlement is refused rather than queued"
    );
    assert_next_item(
        rx.recv().await,
        myownmesh_core::rpc::RpcStreamItem::Chunk(serde_json::json!(1)),
        "the resident chunk is still delivered",
    );
    assert_next_item(
        rx.recv().await,
        myownmesh_core::rpc::RpcStreamItem::End(Ok(())),
        "and the terminal item after it",
    );
    assert_no_next_item(rx.recv().await, "nothing follows the terminal item");
}

#[tokio::test]
async fn stream_terminal_error_is_preserved_exactly() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "err".into(),
        class: HandlerMode::Stream,
    };
    let (tx, mut rx) = stream_mailbox();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx)) else {
        panic!("stream claim")
    };
    assert!(reg.close_exact_stream(&key, a.id, ticket.operation_id(), Some("denied".into())));
    assert_next_item(
        rx.recv().await,
        myownmesh_core::rpc::RpcStreamItem::End(Err("denied".into())),
        "the terminal error is preserved exactly",
    );
}

#[tokio::test]
async fn wrong_response_class_retains_same_operation_identity() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "typed".into(),
        class: HandlerMode::Stream,
    };
    let (tx, mut rx) = stream_mailbox();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx)) else {
        panic!("stream")
    };
    assert!(!reg.resolve_exact_single(
        &key,
        a.id,
        ticket.operation_id(),
        Ok(serde_json::json!("wrong"))
    ));
    assert!(reg.push_exact_stream(
        &key,
        a.id,
        ticket.operation_id(),
        serde_json::json!("same-op")
    ));
    assert_next_item(
        rx.recv().await,
        myownmesh_core::rpc::RpcStreamItem::Chunk(serde_json::json!("same-op")),
        "the chunk for the live operation is delivered",
    );
}

// ---- shutdown lifecycle -------------------------------------------------
//
// The daemon's control surface is terminal: once it starts closing it admits
// nothing further, and `control::serve` does not return while a task it accepted
// is still running. These controls are about the two ways that goes wrong --
// something slipping in after the transition, and something outliving the
// function that started it.

/// A registration barriered at the instant before it commits loses to `Closing`.
///
/// This is the race the lifecycle's placement exists for, and it is arranged
/// rather than hoped for. `register` funds the record and mints the capability
/// with the lock released, and this control begins the drain in exactly that
/// window by driving both halves from one thread in a fixed order: the funding
/// is done, the client is not in the table, and then `begin_closing` runs.
///
/// A version that checked the lifecycle only on the way in would pass its check,
/// be refused nothing, and insert into a table the drain had already walked --
/// an `EventsSubscribe` that answered success to a client the shutdown will
/// never clean up, holding a writer mailbox nothing will ever drain.
#[test]
fn a_registration_that_reaches_the_commit_after_closing_is_refused() {
    let reg = ClientRegistry::default();
    let (tx, _rx) = myownmesh_core::resource_mailbox(crate::test_application_scope())
        .expect("the daemon test grant funds one client writer mailbox");

    assert!(reg.begin_closing(), "the first caller owns the drain");
    let refusal = match reg.register(tx) {
        Ok(_) => panic!("a closing registry admits no client"),
        Err(refusal) => refusal,
    };
    assert!(
        matches!(refusal, IpcAdmissionError::Closing),
        "refused for closing, not for capacity: {refusal}"
    );
    assert_eq!(reg.lifecycle(), Lifecycle::Closing);
}

/// Every admitting path refuses once closing, not just registration.
///
/// Listed one by one rather than asserted over "the registry" as a whole,
/// because each is a separate lock acquisition with its own early returns, and a
/// guard omitted from one of them is invisible from any of the others. A client
/// is registered *before* the transition so that each refusal below is the
/// lifecycle's doing and not `ClientGone`.
#[test]
fn a_closing_registry_admits_no_new_work_on_any_path() {
    let reg = ClientRegistry::default();
    let (client, _rx) = fresh_client(&reg);
    let key: ClaimKey = ("net".to_string(), "method".to_string());

    assert!(reg.begin_closing());

    assert!(
        matches!(
            reg.claim_method(key.clone(), client.id, HandlerMode::Single),
            Err(RegistrationError::Admission(IpcAdmissionError::Closing))
        ),
        "a method claim is refused"
    );
    assert!(
        matches!(
            reg.subscribe_channel(key.clone(), client.id),
            Err(RegistrationError::Admission(IpcAdmissionError::Closing))
        ),
        "a channel subscription is refused"
    );
    assert!(
        matches!(reg.lease_task(), Err(IpcAdmissionError::Closing)),
        "a task is refused"
    );
    assert!(
        matches!(
            reg.lease_task_retaining(16),
            Err(IpcAdmissionError::Closing)
        ),
        "a task retaining captures is refused"
    );
    // And nothing was installed by any of them.
    assert!(reg.handler_owner(&key).is_none());
    assert!(!reg.for_each_subscriber(&key, |_| {}));
}

/// The drain runs once, whoever asks.
///
/// A second drain would close realtime flows already closed and forget handlers
/// already forgotten, through networks that have already been told. Two shutdown
/// signals, a supervisor racing a broadcast, or a second `serve` over the same
/// registry all reduce to this.
#[test]
fn only_the_first_caller_owns_the_drain() {
    let reg = ClientRegistry::default();
    assert!(reg.begin_closing(), "the first caller drains");
    assert!(!reg.begin_closing(), "the second does not");
    assert!(!reg.begin_closing(), "and neither does the third");
    assert_eq!(reg.lifecycle(), Lifecycle::Closing);
}

/// `serve` waits: the join does not resolve while an accepted task is live.
///
/// Both halves, because either alone is satisfiable by a bug. A `wait_for_tasks`
/// that always resolved would pass the second half; one that never resolved
/// would pass the first. The admission is dropped between them, which is exactly
/// what a finishing task does.
#[tokio::test]
async fn the_task_join_resolves_only_once_the_last_task_is_gone() {
    let reg = one_task_registry();
    let task = reg
        .lease_task()
        .expect("the daemon test grant funds one task");

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), reg.wait_for_tasks())
            .await
            .is_err(),
        "the join must not resolve while a task it accepted is still live"
    );
    // Closing does not release the wait either: the point of waiting is that the
    // accepted work finishes rather than being cut short.
    assert!(reg.begin_closing());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), reg.wait_for_tasks())
            .await
            .is_err(),
        "closing refuses new tasks; it does not abandon accepted ones"
    );

    drop(task);
    tokio::time::timeout(std::time::Duration::from_millis(500), reg.wait_for_tasks())
        .await
        .expect("the join resolves once the last accepted task ends");
}

/// A task dropped after the wait began still wakes it.
///
/// The subscription-before-check ordering in `wait_for_tasks` is what this is
/// about. With the check first, a task ending in the window between the read and
/// the first poll of the notification would send a wake nobody was listening for
/// -- and since the count only reaches zero once, no second wake would ever
/// come and `serve` would never return.
#[tokio::test]
async fn a_task_ending_during_the_wait_still_wakes_it() {
    let reg = one_task_registry();
    let task = reg
        .lease_task()
        .expect("the daemon test grant funds one task");
    let waiting = reg.clone();
    let joined = tokio::spawn(async move { waiting.wait_for_tasks().await });
    // Long enough for the wait to be parked rather than merely constructed.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    drop(task);
    tokio::time::timeout(std::time::Duration::from_millis(500), joined)
        .await
        .expect("the wait is woken by the drop")
        .expect("the waiting task did not panic");
}

/// `Closed` is published only when it is true.
///
/// Three attempts, and only the last one is entitled to succeed: from `Running`
/// nothing has drained, from `Closing` with a live task nothing has finished,
/// and only with both conditions met is the claim a fact. `finish_closed`
/// answers the state rather than asserting one, so a caller that has not earned
/// `Closed` learns that instead of publishing it.
#[test]
fn closed_is_never_published_early() {
    let reg = one_task_registry();
    assert_eq!(
        reg.finish_closed(),
        Lifecycle::Running,
        "a runtime that never began closing is not closed"
    );

    let task = reg
        .lease_task()
        .expect("the daemon test grant funds one task");
    assert!(reg.begin_closing());
    assert_eq!(
        reg.finish_closed(),
        Lifecycle::Closing,
        "a live accepted task means the control surface is not over"
    );

    drop(task);
    assert_eq!(reg.finish_closed(), Lifecycle::Closed);
    assert_eq!(reg.lifecycle(), Lifecycle::Closed);
    // And a closed runtime still admits nothing, which is not the same statement
    // as `Closing` refusing: this one has to survive the state having moved on.
    assert!(matches!(reg.lease_task(), Err(IpcAdmissionError::Closing)));
}

/// An isolated registry whose grant contains exactly its process scope and one
/// task reservation. The three lifecycle controls below each hold one task;
/// they must not borrow the process-wide daemon fixture or a connector proxy.
fn one_task_registry() -> ClientRegistry {
    let grant = registry_fixture_claim(0, 0, 0)
        .expect("the isolated task registry scope claim is representable")
        .checked_add(
            super::task_reservation_planning_charge_for_test()
                .expect("the isolated task reservation is representable"),
        )
        .expect("the isolated one-task registry grant is representable");
    ClientRegistry::over_grant(grant)
}

/// The closing signal is already-signalled for a task that arrives late.
///
/// A connection accepted microseconds before the drain, or a pump whose select
/// first runs after the transition, has no second signal coming -- `Notify`
/// delivers `notify_waiters` to whoever is listening at that moment and to
/// nobody else. Resolving immediately when the state has already left `Running`
/// is what stops such a task from parking forever on a signal already sent, with
/// `serve` waiting on it.
#[tokio::test]
async fn the_closing_signal_resolves_for_a_task_that_arrives_after_it() {
    let reg = ClientRegistry::default();
    assert!(reg.begin_closing(), "signalled with nobody listening");
    tokio::time::timeout(std::time::Duration::from_millis(500), reg.closing())
        .await
        .expect("a late arrival sees the state, not the missed wake");
}

/// One isolated fixture can fund an exact IPC task cohort beside a connector
/// structural floor without changing the process-wide daemon grant.
///
/// The connector floor is held first, then the exact owner list's IPC task
/// cohort is held beside it. The next task refuses for the worker dimension,
/// proving the cohort is finite and that it did not silently consume a
/// connector slot.
/// Dropping both owners must return the private provider to the exact baseline;
/// this control never reads or mutates the process-wide fixture provider.
#[test]
fn isolated_task_cohort_is_admitted_without_borrowing_connector_floor() {
    let structural = myownmesh_core::connector_resource_structural_claims();
    let connector = structural.connector_opening();
    let connector_charge =
        myownmesh_core::FiniteResourceProvider::reservation_planning_charge(connector)
            .expect("the connector opening reservation is representable");
    let task = super::task_claim_for_test().expect("the IPC task claim is representable");
    // Keep the cohort isolated to this control. Its owner list is explicit and
    // the grant is priced from that list, so N is the number of leases this
    // fixture really retains rather than a process-wide guessed constant.
    let task_owners: Vec<usize> = (0..crate::TEST_PROCESS_CONNECTOR_CAPACITY).collect();
    let task_charge = super::task_cohort_reservation_planning_charge_for_test(task_owners.len())
        .expect("the IPC task cohort reservation is representable");
    let grant = myownmesh_core::FiniteResourceProvider::scope_planning_charge()
        .checked_add(connector_charge)
        .and_then(|grant| grant.checked_add(task_charge))
        .expect("the connector and IPC task grant is representable");
    let provider = myownmesh_core::FiniteResourceProvider::new(grant);
    let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
        .expect("the private grant funds its process scope");
    let scope = port.process_scope();
    let baseline = provider.in_use();

    let connector_lease = port
        .acquire(
            &scope,
            myownmesh_core::ResourceAuthorityClass::Admitted,
            connector,
        )
        .expect("the connector floor is admitted before IPC tasks");
    let mut tasks = Vec::new();
    for index in &task_owners {
        tasks.push(
            port.acquire(
                &scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                task,
            )
            .unwrap_or_else(|error| panic!("IPC task {index} must be admitted: {error:?}")),
        );
    }
    assert_eq!(tasks.len(), task_owners.len());
    let refusal = port
        .acquire(
            &scope,
            myownmesh_core::ResourceAuthorityClass::Admitted,
            task,
        )
        .expect_err("the N+1 IPC task exceeds its named finite cohort");
    assert!(
        matches!(
            refusal,
            myownmesh_core::ResourceUnavailable::Pressure(pressure)
                if pressure.dimension == myownmesh_core::ResourceClass::WorkerOrTask
        ),
        "the refusal is IPC task pressure, not connector-floor pressure: {refusal:?}"
    );

    drop(tasks);
    drop(connector_lease);
    assert_eq!(
        provider.in_use(),
        baseline,
        "dropping the connector and IPC task owners returns the exact baseline"
    );
}

// ---- off-node retention -------------------------------------------------

/// A long coordinate costs more than a short one, at every record shape.
///
/// The claim helpers are the thing under test, not a proxy for it: they are what
/// `claim_method`, `subscribe_channel` and the pending table actually charge, so
/// a shape that went back to funding only the node would fail here by producing
/// equal claims for a one-byte name and a megabyte one. That equality is exactly
/// the defect — `LeasedMap::entry_claim` funds a fixed-size node no matter how
/// long the key is, and every table in this registry is keyed by a name a local
/// client chose.
///
/// Strict inequality on the claim, not a threshold: what matters is that cost
/// *tracks* the name, and any constant would be a number this control invented.
#[test]
fn a_longer_coordinate_costs_strictly_more_to_retain() {
    let short: ClaimKey = ("n".to_string(), "m".to_string());
    let long: ClaimKey = ("n".repeat(4096), "m".repeat(4096));
    let short_claim = claim_key_retained(&short).expect("a short claim key is representable");
    let long_claim = claim_key_retained(&long).expect("a long claim key is representable");
    assert!(
        long_claim.amount(ResourceClass::AccountedMemoryBytes)
            > short_claim.amount(ResourceClass::AccountedMemoryBytes),
        "a client that picks an eight-kilobyte name is charged for one"
    );
    assert_eq!(
        long_claim.amount(ResourceClass::OpaqueDependencyResidual),
        short_claim.amount(ResourceClass::OpaqueDependencyResidual),
        "both are two allocations; only the bytes in them differ"
    );

    let pending = |len: usize| PendingKey {
        network: "n".repeat(len),
        method: "m".repeat(len),
        remote_peer: "p".repeat(len),
        remote_request_id: "r".repeat(len),
        class: HandlerMode::Single,
    };
    assert!(
        pending_key_retained(&pending(4096))
            .expect("representable")
            .amount(ResourceClass::AccountedMemoryBytes)
            > pending_key_retained(&pending(1))
                .expect("representable")
                .amount(ResourceClass::AccountedMemoryBytes),
        "and the same holds for the four coordinates of a pending call"
    );
}

/// A length sum this code cannot represent is refused, not silently reduced.
///
/// The failure this rules out is specific. `saturating_add` on the four
/// attacker-influenced lengths of a `PendingKey` turns an unrepresentable total
/// into `usize::MAX`, which fits in a `u64` and is therefore *accepted* as a
/// claim — so the single input crafted to overflow would be charged less than
/// the truth rather than being turned away. Refusal is the only honest answer.
///
/// Built from capacities rather than real bytes: allocating two half-address-
/// space strings is not something a control can do, and the arithmetic is the
/// subject either way.
#[test]
fn an_unrepresentable_coordinate_is_refused_rather_than_truncated() {
    let huge = usize::MAX / 2;
    assert!(
        total_len([huge, huge, huge]).is_err(),
        "three half-usize lengths do not fit in a usize"
    );
    assert!(
        matches!(
            total_len([usize::MAX, 1]),
            Err(ResourceClaimArithmeticError::Overflow { .. })
        ),
        "and the refusal is the typed arithmetic one, not a saturated number"
    );
    assert_eq!(
        total_len([1, 2, 3]).expect("a representable sum"),
        6,
        "non-vacuity: ordinary sums still add"
    );
}

/// A grant that funds one client record and one entry in every table, priced at
/// `coordinate` bytes of client-chosen name.
///
/// Deliberately generous: it pays for an entry in each of the eight tables and
/// eight copies of the widest retained key shape, with every reservation and the
/// registry scope priced by the provider's own planners. The control below sizes
/// its refused coordinate from this grant's total byte budget, so name bytes
/// alone exceed the whole budget regardless of how the node shapes change.
fn registry_granting_coordinate(coordinate: usize) -> ClientRegistry {
    let grant = registry_fixture_claim(1, 1, coordinate)
        .expect("the control grant is representable")
        .checked_add(
            ResourceClaim::try_from_entries([(ResourceClass::OpaqueDependencyResidual, 1 << 20)])
                .expect("the bookkeeping headroom is representable"),
        )
        .expect("the control grant is representable");
    ClientRegistry::over_grant(grant)
}

/// The same filing, admitted with a short coordinate and refused with a long
/// one.
///
/// This is the production path, not the claim helpers: `claim_method` is what a
/// client reaches through `RpcServe`, and the two calls below differ in exactly
/// one thing — the number of bytes in the name. A registry that funded only the
/// node would admit both, because the node is the same size either way, and
/// that equality is the defect.
///
/// The grant is sized from the same function the daemon's own test grant uses.
/// The long case is derived from that grant's complete accounted-memory budget,
/// so its name bytes alone exceed the whole grant rather than relying on a fixed
/// multiplier that can drift when a node shape changes.
///
/// The release half matters as much as the refusal, and it is asserted rather
/// than inferred. A registry that charged for a name and never gave it back
/// would pass a refusal assertion and still leak, so this reads the provider's
/// in-use figure directly: the delta the filing added must be exactly the delta
/// the release returns. Inferring it from a later admission would prove only
/// that *enough* came back, and "enough" is what a partial release also looks
/// like.
#[test]
fn a_long_coordinate_is_refused_where_a_short_one_is_admitted() {
    const SHORT: usize = 8;
    let reg = registry_granting_coordinate(SHORT);
    let (client, _rx) = fresh_client(&reg);

    let baseline = reg.in_use().expect("this registry owns its provider");

    let short: ClaimKey = ("n".repeat(SHORT), "m".repeat(SHORT));
    reg.claim_method(short.clone(), client.id, HandlerMode::Single)
        .expect("one entry at the granted coordinate is funded");
    let filed = reg.in_use().expect("this registry owns its provider");
    assert_ne!(
        filed, baseline,
        "non-vacuity: filing a claim really does consume from the grant"
    );

    // Same shape, same client, same tables -- only the name is longer. Size it
    // from the grant rather than a multiplier: nodes and names share the byte
    // dimension, so a fixed multiple would be refused only by coincidence.
    let budget = registry_fixture_claim(1, 1, SHORT)
        .expect("the control grant is representable")
        .amount(ResourceClass::AccountedMemoryBytes);
    let long_len = usize::try_from(budget).expect("the grant's byte budget is a length") + 1;
    let long: ClaimKey = ("n".repeat(long_len), "m".repeat(long_len));
    assert!(
        matches!(
            reg.claim_method(long.clone(), client.id, HandlerMode::Single),
            Err(RegistrationError::Admission(IpcAdmissionError::Resources(
                _
            )))
        ),
        "the name alone costs more accounted memory than the whole grant holds"
    );
    // And nothing of the refused claim was installed.
    assert!(reg.handler_owner(&long).is_none());
    assert_eq!(reg.handler_owner(&short), Some(client.id));

    // Releasing the short claim returns its name's funding, not just its node,
    // and returns exactly what it took -- read off the provider rather than
    // inferred from what is admissible afterwards.
    let release = reg.release_method(&short, client.id);
    assert!(release.released);
    assert!(reg.handler_owner(&short).is_none());
    // The release carries the installed record out, and that record still holds
    // the lease funding its own copy of the name. The ledger returns to the
    // baseline when the caller drops it, which is the point: the funding
    // follows the last live copy rather than the moment the entry left a table.
    drop(release);
    assert_eq!(
        reg.in_use().expect("this registry owns its provider"),
        baseline,
        "release returns the filing's delta exactly: not part of it, and not more"
    );

    // A name whose bytes alone exceed the whole grant still does not fit. The
    // refusal is the same one, so the release above did not silently hand back
    // more than it took.
    assert!(
        matches!(
            reg.claim_method(long.clone(), client.id, HandlerMode::Single),
            Err(RegistrationError::Admission(IpcAdmissionError::Resources(
                _
            )))
        ),
        "release returns what was taken, not more"
    );
    // But the short one is admissible again, which is what proves the release
    // was real rather than the refusal above being permanent.
    reg.claim_method(short.clone(), client.id, HandlerMode::Single)
        .expect("the released funding is available again");
    assert_eq!(reg.handler_owner(&short), Some(client.id));
}

/// A pending call's funding survives the record and goes with the ticket.
///
/// The defect this rules out is a lease stored beside the map record alone. A
/// `PendingTicket` holds its own clone of all four coordinate strings and can
/// outlive the record's removal — that is the entire reason it exists, since it
/// is what lets a late cleanup identify one exact operation. Funding tied to the
/// record would therefore be returned while an identical set of buffers was
/// still live in the ticket.
///
/// Read off the provider rather than inferred. Three points: nothing pending,
/// pending with both halves alive, and pending removed with only the ticket
/// alive. The middle-to-third step is the assertion — usage must *not* fall back
/// to baseline while the ticket lives, and must return to it exactly once the
/// ticket drops too.
#[test]
fn a_pending_calls_funding_outlives_its_record_and_ends_with_its_ticket() {
    let reg = registry_granting_coordinate(64);
    // Before the client exists, deliberately. `unregister` below releases the
    // client's own record as well as its pending call, so a baseline taken
    // after registration would be a figure the final assertion could never
    // return to.
    let baseline = reg.in_use().expect("this registry owns its provider");
    let (client, _rx) = fresh_client(&reg);

    let key = PendingKey {
        network: "n".repeat(64),
        method: "m".repeat(64),
        remote_peer: "p".repeat(64),
        remote_request_id: "r".repeat(64),
        class: HandlerMode::Single,
    };
    let (tx, _rx) = oneshot::channel();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), client.id, PendingInbound::Single(tx))
    else {
        panic!("the granted coordinate funds one pending call")
    };
    let accepted = reg.in_use().expect("this registry owns its provider");
    assert_ne!(
        accepted, baseline,
        "non-vacuity: accepting a pending call really does consume from the grant"
    );

    // Take the record out from under the ticket, exactly as a disconnect does.
    // The ticket is still alive and still holds four coordinate strings.
    //
    // Through `unregister` rather than a direct removal, so this is the path a
    // real disconnect takes: it sweeps the client's pending calls out of the
    // table and settles them, and the ticket outliving that sweep is the
    // ordinary case rather than a contrived one.
    reg.unregister(client.id).expect("a registered client");
    // The registry's reference to the client, and then this control's own.
    //
    // `unregister` removes the *table's* copy of the handle; it does not and
    // must not release the record, because the funding for a client record
    // follows the last live `FundedArc<ClientHandle>` rather than the table entry. A
    // real disconnect has several of those in flight -- the read loop, the
    // writer task, the released registrations -- and releasing the record when
    // the table entry went would unfund a handle those are still reading.
    //
    // This control held one of those copies. Dropping it here is what makes the
    // question below the ticket's alone: past this point the ticket is the only
    // thing left holding anything from this registry's grant.
    drop(client);
    assert_ne!(
        reg.in_use().expect("this registry owns its provider"),
        baseline,
        "the ticket alone still holds a full copy of the coordinates"
    );

    drop(ticket);
    assert_eq!(
        reg.in_use().expect("this registry owns its provider"),
        baseline,
        "and it is returned in full once the last copy is gone"
    );
}
