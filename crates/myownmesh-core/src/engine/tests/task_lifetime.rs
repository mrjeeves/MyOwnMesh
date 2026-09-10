//! Real application/connector paths on unchanged network owners. The barrier
//! only observes joins: removing the production driver's completion arm makes
//! these controls time out rather than letting the test itself drain history.
use super::*;

#[tokio::test]
async fn v1_unary_and_stream_batches_release_registrations_on_live_network() {
    let (near, near_inbound, near_commands, _, _) =
        build_test_state_parts_metered("v1-rpc-batches-near", None, 2, None);
    let (far, far_inbound, far_commands, _, _) =
        build_test_state_parts_metered("v1-rpc-batches-far", None, 2, None);
    let linked = install_promoted_session_over_real_link(&near, &far).await;
    let peer = linked.peer_device_id().to_owned();
    let original_owner = far.peers.owner(near.identity.public_id()).unwrap();
    let calling = crate::rpc::Rpc::attach(&near).unwrap();
    let serving = crate::rpc::Rpc::attach(&far).unwrap();
    serving
        .serve("v1-unary", |call: crate::rpc::RpcCall| async move {
            Ok(crate::rpc::RpcResponse::from_value(call.payload))
        })
        .unwrap();
    let producing = Arc::downgrade(&far);
    serving
        .serve_stream("v1-stream", move |call: crate::rpc::RpcCall| {
            let state = producing.upgrade();
            async move {
                let state = state.ok_or_else(|| "network ended".to_owned())?;
                let (tx, rx) = funded_stream_parts_with_one_chunk(&state, call.payload)?;
                // Success is an explicit funded item, not disappearance of
                // the producer after its first chunk.
                tx.send(crate::rpc::RpcStreamItem::End(Ok(())))
                    .map_err(|error| format!("stream success terminal admission: {error:?}"))?;
                drop(tx);
                Ok(rx)
            }
        })
        .unwrap();

    // Lexically owned production drivers, not a spawned reaper or test joiner.
    let near_driver = run_driver(Arc::clone(&near), near_inbound, near_commands);
    let far_driver = run_driver(Arc::clone(&far), far_inbound, far_commands);
    tokio::pin!(near_driver, far_driver);
    let mut near_done = false;
    let mut far_done = false;
    let exercise = async {
        let mut expected = 0;
        for batch in [1usize, 4, 8, 4] {
            for sequence in 0..batch {
                let value = serde_json::json!(sequence);
                let reply = calling
                    .call(&peer, "v1-unary", value.clone())
                    .await
                    .map_err(|error| format!("unary admission/delivery: {error}"))?;
                if reply.body != value {
                    return Err("wrong unary body".to_owned());
                }
                let mut stream = calling
                    .call_stream(&peer, "v1-stream", value.clone())
                    .await
                    .map_err(|error| format!("stream admission/delivery: {error}"))?;
                let chunk = stream
                    .recv()
                    .await
                    .ok_or_else(|| "stream omitted chunk".to_owned())??;
                if chunk.value() != &value {
                    return Err("wrong stream body".to_owned());
                }
                drop(chunk);
                match stream.recv().await {
                    None => {}
                    Some(Err(error)) => {
                        return Err(format!("stream returned failure terminal: {error}"));
                    }
                    Some(Ok(_)) => {
                        return Err("stream returned an unexpected extra chunk".to_owned())
                    }
                }
                drop(stream);
                expected += 2;
                // Await exact joined terminal evidence, never is_finished or
                // the handler's earlier epilogue/response receipt.
                far.wait_task_joins_for_test(expected, false).await;
            }
            let (occupancy, terminals) = far.task_registry_counts_for_test();
            if occupancy != 0 || terminals != [expected, 0, 0] {
                return Err(format!(
                    "completed history retained: {occupancy}, {terminals:?}"
                ));
            }
            let current = far
                .peers
                .owner(near.identity.public_id())
                .ok_or_else(|| "original peer disappeared".to_owned())?;
            if !Arc::ptr_eq(current.connection(), original_owner.connection()) {
                return Err("batch replaced the network peer".to_owned());
            }
        }
        Ok::<(), String>(())
    };
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::pin!(exercise);
        tokio::select! {
            result = &mut exercise => result,
            () = &mut near_driver => {
                near_done = true;
                Err("near driver ended before batch barrier".to_owned())
            }
            () = &mut far_driver => {
                far_done = true;
                Err("far driver ended before batch barrier".to_owned())
            }
        }
    })
    .await;
    near.request_shutdown();
    far.request_shutdown();
    let (_, _, closed) = tokio::join!(
        async {
            if !near_done {
                near_driver.await;
            }
        },
        async {
            if !far_done {
                far_driver.await;
            }
        },
        linked.close_outcomes(),
    );
    drop((calling, serving, original_owner));
    assert!(
        closed.iter().all(|outcome| outcome.is_ok()),
        "native cleanup: {closed:?}"
    );
    assert!(matches!(result, Ok(Ok(()))), "real RPC batches: {result:?}");
}

#[tokio::test]
async fn v1_native_pump_retirement_batches_join_without_network_shutdown() {
    let (state, inbound, commands, provider, _) =
        build_test_state_parts_metered("v1-native-pump-batches", None, 2, None);
    let driver = run_driver(Arc::clone(&state), inbound, commands);
    tokio::pin!(driver);
    let mut driver_done = false;
    let exercise = async {
        let mut expected = 0;
        let mut baseline = None;
        for batch in [1usize, 4, 8, 4] {
            for _ in 0..batch {
                let pump_registration =
                    state.begin_peer_event_pump_registration().ok_or_else(|| {
                        "pump reservation refused before native construction".to_owned()
                    })?;
                let (worker, events) = state
                    .transport
                    .open_connector_peer(
                        Role::Answerer,
                        &[],
                        &[],
                        state.peer_connection_resource_scope(),
                    )
                    .await
                    .map_err(|error| format!("native constructor: {error}"))?;
                let worker = Arc::new(worker);
                let peer_id = crate::identity::Identity::ephemeral()
                    .public_id()
                    .to_owned();
                spawn_registered_peer_event_pump(
                    &state,
                    pump_registration,
                    Arc::clone(&state),
                    peer_id,
                    Arc::clone(&worker),
                    events,
                    None,
                );
                let registered = state.peer_event_pump_counts_for_test() == (0, 1);
                // Actual native EOF, then the registry's separate exact join.
                let closed = worker.retire_and_close().await;
                drop(worker);
                if !registered {
                    return Err("pump registration refused".to_owned());
                }
                closed.map_err(|error| format!("native retirement: {error}"))?;
                expected += 1;
                state.wait_task_joins_for_test(expected, true).await;
            }
            if state.peer_event_pump_counts_for_test() != (0, 0) {
                return Err("completed pump history retained".to_owned());
            }
            let use_now = (
                provider.in_use(),
                provider.active_reservations(),
                provider.active_scopes(),
            );
            if let Some(first) = baseline {
                if use_now != first {
                    return Err("successive native batches retained custody".to_owned());
                }
            } else {
                baseline = Some(use_now);
            }
        }
        Ok::<(), String>(())
    };
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::pin!(exercise);
        tokio::select! {
            result = &mut exercise => result,
            () = &mut driver => {
                driver_done = true;
                Err("driver ended before pump completion barrier".to_owned())
            }
        }
    })
    .await;
    state.request_shutdown();
    if !driver_done {
        driver.await;
    }
    assert!(
        matches!(result, Ok(Ok(()))),
        "native pump batches: {result:?}"
    );
}

/// These are actual constructor entry paths under a finite full provider seal.
/// The counter observes only the real pump-node acquisition refusal, so a
/// different earlier failure cannot satisfy the no-publication oracle.
#[tokio::test]
async fn v1_speculative_and_ordinary_pump_pressure_precedes_publication() {
    let (near, mut near_inbound, near_commands, provider, grant) =
        build_test_state_parts_metered("v1-pump-pressure-near", None, 2, None);
    let (far, far_inbound, far_commands, _, _) =
        build_test_state_parts_metered("v1-pump-pressure-far", None, 2, None);
    near.park_command_receiver_for_test(near_commands);
    far.park_command_receiver_for_test(far_commands);
    let linked = install_promoted_session_over_real_link(&near, &far).await;
    let target = linked.peer_device_id().to_owned();
    let owner = near.peers.owner(&target).unwrap();
    let worker = owner.connection().current_worker().unwrap();
    let fresh = crate::identity::Identity::ephemeral();
    let mut outbound = near.take_signaling_outbound_rx().unwrap();
    while outbound.try_recv().is_some() {}
    let runtime = signaling_ingress::SignalingRuntime::new(
        near.signaling_inbound_tx.clone(),
        near.local_application_resource_scope().unwrap(),
    );
    near.publish_signaling_runtime(&runtime);
    let ingress = signaling_ingress::SignalingRuntime::attach(
        &runtime,
        signaling_ingress::SignalingCarrier::Nostr,
    );
    let offer = || {
        ingress.directed(
            target.clone(),
            myownmesh_signaling::SignalingMessage::Offer {
                peer_id: target.clone(),
                offer_id: "pressure-answer".into(),
                sdp: "not-consumed".into(),
            },
        )
    };
    let first_delivered = ingress.deliver(offer());
    let token = near_inbound
        .try_recv()
        .and_then(|delivery| delivery.value().dedup_token());
    let token_present = token.is_some();
    let duplicate_delivered = ingress.deliver(offer());
    let duplicate_suppressed = near_inbound.try_recv().is_none();
    let refused_before = near.peer_event_pump_refusals_for_test();
    let record = crate::resource::FiniteResourceProvider::reservation_charge_for_test(
        crate::resource::ResourceClaim::ZERO,
    )
    .unwrap();
    let remaining = grant
        .checked_sub(provider.in_use())
        .unwrap()
        .checked_sub(record)
        .unwrap();
    let seal = near.cmd_tx.reserve_for_test(remaining).unwrap();
    let sealed = provider.in_use();
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let local = start_speculative_local_offer(&near, &owner).await;
        let local_refused = matches!(
            local,
            Err(SpeculativeLocalOfferStartError {
                reason: "speculative pump registration was refused",
                ..
            })
        );
        let local_observed = near.peer_event_pump_refusals_for_test() == refused_before + 1;
        ensure_peer_session_with_introduction(&near, fresh.public_id(), Role::Answerer, None).await;
        let ordinary_observed = near.peer_event_pump_refusals_for_test() == refused_before + 2;
        let pre_answer_unchanged = provider.in_use() == sealed;
        start_speculative_offer(
            &near,
            &target,
            "pressure-answer",
            "not-consumed".into(),
            token,
        )
        .await;
        let answer_observed = near.peer_event_pump_refusals_for_test() == refused_before + 3;
        let unchanged_owner = near.peers.owner(&target).is_some_and(|current| {
            Arc::ptr_eq(current.connection(), owner.connection())
                && current
                    .connection()
                    .current_worker()
                    .is_some_and(|current_worker| Arc::ptr_eq(&current_worker, &worker))
        });
        local_refused
            && local_observed
            && answer_observed
            && ordinary_observed
            && unchanged_owner
            && worker.live_connector_incarnation().is_some()
            && owner.connection().speculative_resources_empty_for_test()
            && !near.peers.contains_key(fresh.public_id())
            && near.peer_event_pump_counts_for_test() == (0, 0)
            && outbound.try_recv().is_none()
            && sealed == grant
            && pre_answer_unchanged
            && first_delivered
            && token_present
            && duplicate_delivered
            && duplicate_suppressed
    })
    .await;
    drop(seal);
    // Exact duplicate becomes admissible again only if the refused attempt
    // released its original runtime-owned dedup entry.
    let delivered_again = ingress.deliver(offer());
    let token_again = near_inbound
        .try_recv()
        .and_then(|delivery| delivery.value().dedup_token());
    let dedup_released = delivered_again && token_again.is_some();
    if let Some(token_again) = token_again {
        runtime.forget_token(token_again);
    }
    drop((ingress, runtime));
    let (_, _, closed) = tokio::join!(near.shutdown(), far.shutdown(), linked.close_outcomes());
    drop((outbound, near_inbound, far_inbound, owner, worker));
    assert!(
        closed.iter().all(|outcome| outcome.is_ok()),
        "native cleanup: {closed:?}"
    );
    assert!(
        matches!(result, Ok(true)) && dedup_released,
        "pump pressure publication boundary: {result:?}, dedup released: {dedup_released}"
    );
}
