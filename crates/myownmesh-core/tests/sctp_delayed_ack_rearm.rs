//! Public-API regression for expiry followed by rearming a normal delayed ACK.
//! No mesh, sockets, private SCTP state, ACK-policy override, or timer tuning.
//! Message delivery and acknowledgement are deliberately separate observations.

use std::net::Shutdown;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use myownmesh_core::protocol::{ClosedRoutedPayload, MeshMessage, RoutedApplicationEnvelope};
use myownmesh_core::semantic::{DeviceId, MeshContextId};
use tokio::time::{sleep, timeout, Instant};
use webrtc::sctp::association::{Association, Config};
use webrtc::sctp::chunk::chunk_payload_data::PayloadProtocolIdentifier;
use webrtc::sctp::stream::Stream;
use webrtc::util::conn::{conn_pipe::pipe, Conn};

const SETUP_BOUND: Duration = Duration::from_secs(5);
const OPERATION_BOUND: Duration = Duration::from_secs(2);
// Locked SCTP uses a 200ms normal delayed ACK and a >=1000ms data RTO.
// 600ms affords 400ms of scheduling margin without accepting retransmission
// recovery as a successful normal delayed ACK. No dependency timer is changed.
const ACK_BOUND: Duration = Duration::from_millis(600);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CLEANUP_BOUND: Duration = Duration::from_secs(2);
const PAYLOAD_LEN: usize = 32; // each write is one complete DATA chunk
                               // This is a pinned characteristic of the locked webrtc-sctp 0.12 dependency,
                               // used only to prove the public encoder produced a fragmented test message. It
                               // does not alter the association's MTU, congestion window, ACK mode or timers.
const LOCKED_INITIAL_MTU: usize = 1_228;

#[derive(Clone, Copy, Debug, Default)]
struct MessageObservation {
    written: bool,
    delivered: bool,
    buffered_at_delivery: usize,
    delivery_us: u128,
    ack_within_bound: bool,
    ack_elapsed_us: u128,
    remaining_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct FragmentedObservation {
    frame_bytes: usize,
    second_ack_elapsed_us: u128,
    third_ack_elapsed_us: u128,
    delivered_within_ack_bound: bool,
    delivery_elapsed_us: u128,
    recovered_within_operation_bound: bool,
    recovery_elapsed_us: u128,
}

fn representative_routed_frame() -> Bytes {
    let origin_key = SigningKey::from_bytes(&[41; 32]);
    let forwarding_key = SigningKey::from_bytes(&[42; 32]);
    let destination_key = SigningKey::from_bytes(&[43; 32]);
    let device = |key: &SigningKey| {
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes())
            .expect("the fixed public test key has a canonical device id")
    };
    let mut envelope = RoutedApplicationEnvelope::new(
        MeshContextId::from_bytes([44; 32]),
        device(&origin_key),
        device(&destination_key),
        [45; 16],
        4,
        ClosedRoutedPayload::ChannelFrame {
            channel: "pilot10-perf".to_owned(),
            payload: serde_json::json!({
                "protocol": "myownmesh.live-payload.v1",
                "network": "pilot10-open-tree-4cdc19e-c1",
                "channel": "pilot10-perf",
                "kind": "request",
                "run_id": "sctp-delayed-ack-fragment-regression",
                "seq": 0,
                "body": "0123456789abcdef".repeat(64),
            }),
        },
        &origin_key,
    )
    .expect("the same-shaped routed workload envelope is valid");
    envelope
        .append_hop(device(&forwarding_key), &forwarding_key)
        .expect("one native forwarding hop is valid");
    let frame = Bytes::from(
        serde_json::to_vec(&MeshMessage::RoutedApplication(envelope))
            .expect("the public native protocol frame serializes"),
    );
    assert!(
        frame.len() > LOCKED_INITIAL_MTU,
        "the public encoder must produce more than one locked SCTP DATA chunk"
    );
    frame
}

async fn observe_ack(stream: &Stream, started: Instant, row: &mut MessageObservation) {
    // Fixed iteration count as well as a monotonic deadline: no busy wait,
    // retrying a write, or accepting a late zero after the deadline.
    for _ in 0..=60 {
        let elapsed = started.elapsed();
        let remaining = stream.buffered_amount();
        row.ack_elapsed_us = elapsed.as_micros();
        row.remaining_bytes = remaining;
        if elapsed > ACK_BOUND {
            return;
        }
        if remaining == 0 {
            row.ack_within_bound = true;
            return;
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn exercise(
    client: &Association,
    server: &Association,
    streams: &mut [Option<Arc<Stream>>; 2],
    rows: &mut [MessageObservation; 2],
) -> Result<(), &'static str> {
    streams[0] = Some(
        timeout(
            OPERATION_BOUND,
            client.open_stream(1, PayloadProtocolIdentifier::Binary),
        )
        .await
        .map_err(|_| "open_stream_timeout")?
        .map_err(|_| "open_stream_error")?,
    );
    for index in 0..2 {
        let payload = Bytes::from(vec![index as u8 + 1; PAYLOAD_LEN]);
        let sender = streams[0].as_ref().ok_or("sender_missing")?;
        if sender.buffered_amount() != 0 {
            return Err("prior_write_still_buffered");
        }
        let started = Instant::now();
        let written = timeout(
            OPERATION_BOUND,
            sender.write_sctp(&payload, PayloadProtocolIdentifier::Binary),
        )
        .await
        .map_err(|_| "write_timeout")?
        .map_err(|_| "write_error")?;
        rows[index].written = written == PAYLOAD_LEN;
        if !rows[index].written {
            return Err("write_length");
        }
        if index == 0 {
            streams[1] = Some(
                timeout(OPERATION_BOUND, server.accept_stream())
                    .await
                    .map_err(|_| "accept_stream_timeout")?
                    .ok_or("accept_stream_closed")?,
            );
        }
        let receiver = streams[1].as_ref().ok_or("receiver_missing")?;
        let mut received = [0_u8; PAYLOAD_LEN];
        let (length, ppi) = timeout(OPERATION_BOUND, receiver.read_sctp(&mut received))
            .await
            .map_err(|_| "read_timeout")?
            .map_err(|_| "read_error")?;
        rows[index].delivery_us = started.elapsed().as_micros();
        rows[index].delivered = length == PAYLOAD_LEN
            && ppi == PayloadProtocolIdentifier::Binary
            && received.as_slice() == payload.as_ref();
        if !rows[index].delivered {
            return Err("delivery_mismatch");
        }
        let sender = streams[0].as_ref().ok_or("sender_missing")?;
        rows[index].buffered_at_delivery = sender.buffered_amount();
        if started.elapsed() > ACK_BOUND {
            return Err(if index == 0 {
                "first_delivery_late"
            } else {
                "second_delivery_late"
            });
        }
        observe_ack(sender, started, &mut rows[index]).await;
        println!(
            "sctp_rearm_message index={index} observation={:?}",
            rows[index]
        );
        if !rows[index].ack_within_bound {
            return Err(if index == 0 {
                "first_ack_deadline"
            } else {
                "second_ack_deadline"
            });
        }
        if index == 0 {
            // Do not let an already-ACKed message or an immediate ACK stand in
            // for the expired delayed-ACK precondition. No private clock/state
            // is injected: the real first timer must run to completion.
            if rows[0].buffered_at_delivery != PAYLOAD_LEN || rows[0].ack_elapsed_us < 200_000 {
                return Err("first_delayed_ack_precondition");
            }
            // Idle after the first ACK; do not send warm-up packets. This also
            // allows the one-shot timer task to finish before the second write.
            sleep(Duration::from_millis(50)).await;
        }
    }
    Ok(())
}

async fn write_and_deliver_small(
    sender: &Stream,
    receiver: &Stream,
    value: u8,
) -> Result<(Instant, MessageObservation), &'static str> {
    if sender.buffered_amount() != 0 {
        return Err("fragment_prior_write_still_buffered");
    }
    let payload = Bytes::from(vec![value; PAYLOAD_LEN]);
    let started = Instant::now();
    let written = timeout(
        OPERATION_BOUND,
        sender.write_sctp(&payload, PayloadProtocolIdentifier::Binary),
    )
    .await
    .map_err(|_| "fragment_small_write_timeout")?
    .map_err(|_| "fragment_small_write_error")?;
    if written != PAYLOAD_LEN {
        return Err("fragment_small_write_length");
    }
    let mut received = [0_u8; PAYLOAD_LEN];
    let (length, ppi) = timeout(OPERATION_BOUND, receiver.read_sctp(&mut received))
        .await
        .map_err(|_| "fragment_small_read_timeout")?
        .map_err(|_| "fragment_small_read_error")?;
    if length != PAYLOAD_LEN
        || ppi != PayloadProtocolIdentifier::Binary
        || received.as_slice() != payload.as_ref()
    {
        return Err("fragment_small_delivery_mismatch");
    }
    Ok((
        started,
        MessageObservation {
            written: true,
            delivered: true,
            buffered_at_delivery: sender.buffered_amount(),
            delivery_us: started.elapsed().as_micros(),
            ..MessageObservation::default()
        },
    ))
}

async fn wait_for_buffered_zero(
    stream: &Stream,
    started: Instant,
    bound: Duration,
) -> Option<u128> {
    let deadline = started + bound;
    loop {
        let remaining_bytes = stream.buffered_amount();
        let elapsed = started.elapsed();
        if elapsed > bound {
            return None;
        }
        if remaining_bytes == 0 {
            return Some(elapsed.as_micros());
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        sleep(POLL_INTERVAL.min(deadline - now)).await;
    }
}

async fn exercise_fragmented_delivery(
    client: &Association,
    server: &Association,
    frame: Bytes,
    streams: &mut [Option<Arc<Stream>>; 2],
    observation: &mut FragmentedObservation,
) -> Result<(), &'static str> {
    observation.frame_bytes = frame.len();
    streams[0] = Some(
        timeout(
            OPERATION_BOUND,
            client.open_stream(1, PayloadProtocolIdentifier::Binary),
        )
        .await
        .map_err(|_| "fragment_open_stream_timeout")?
        .map_err(|_| "fragment_open_stream_error")?,
    );
    let sender = Arc::clone(streams[0].as_ref().ok_or("fragment_sender_missing")?);

    // First let the normal delayed-ACK timer expire. This is the same public
    // precondition as the smaller rearm regression above.
    let first_payload = Bytes::from(vec![1; PAYLOAD_LEN]);
    let first_started = Instant::now();
    let first_written = timeout(
        OPERATION_BOUND,
        sender.write_sctp(&first_payload, PayloadProtocolIdentifier::Binary),
    )
    .await
    .map_err(|_| "fragment_first_write_timeout")?
    .map_err(|_| "fragment_first_write_error")?;
    if first_written != PAYLOAD_LEN {
        return Err("fragment_first_write_length");
    }
    streams[1] = Some(
        timeout(OPERATION_BOUND, server.accept_stream())
            .await
            .map_err(|_| "fragment_accept_stream_timeout")?
            .ok_or("fragment_accept_stream_closed")?,
    );
    let receiver = Arc::clone(streams[1].as_ref().ok_or("fragment_receiver_missing")?);
    let mut first_received = [0_u8; PAYLOAD_LEN];
    let (first_length, first_ppi) =
        timeout(OPERATION_BOUND, receiver.read_sctp(&mut first_received))
            .await
            .map_err(|_| "fragment_first_read_timeout")?
            .map_err(|_| "fragment_first_read_error")?;
    if first_length != PAYLOAD_LEN
        || first_ppi != PayloadProtocolIdentifier::Binary
        || first_received.as_slice() != first_payload.as_ref()
    {
        return Err("fragment_first_delivery_mismatch");
    }
    let mut first = MessageObservation {
        written: true,
        delivered: true,
        buffered_at_delivery: sender.buffered_amount(),
        delivery_us: first_started.elapsed().as_micros(),
        ..MessageObservation::default()
    };
    observe_ack(&sender, first_started, &mut first).await;
    if !first.ack_within_bound
        || first.buffered_at_delivery != PAYLOAD_LEN
        || first.ack_elapsed_us < 200_000
    {
        return Err("fragment_first_delayed_ack_precondition");
    }
    sleep(Duration::from_millis(50)).await;

    // On the defective dependency this ACK cannot rearm, so recovery is the
    // natural T3 retransmission and the sender's ordinary congestion window is
    // reduced. On a corrected dependency it is simply another delayed ACK.
    // Both branches continue; no private mode/window/timer is injected.
    let (second_started, second) = write_and_deliver_small(&sender, &receiver, 2).await?;
    if second.buffered_at_delivery != PAYLOAD_LEN {
        return Err("fragment_second_buffer_precondition");
    }
    observation.second_ack_elapsed_us =
        wait_for_buffered_zero(&sender, second_started, OPERATION_BOUND)
            .await
            .ok_or("fragment_second_natural_recovery_timeout")?;
    sleep(Duration::from_millis(50)).await;

    // Expire one more genuine delayed ACK. With the defect this leaves the
    // one-shot marker stale after the natural RTO has reduced cwnd; with the
    // repair the timer is reusable. This priming is regression mechanics, not
    // a field-workload warm-up or a latency workaround.
    let (third_started, mut third) = write_and_deliver_small(&sender, &receiver, 3).await?;
    observe_ack(&sender, third_started, &mut third).await;
    observation.third_ack_elapsed_us = third.ack_elapsed_us;
    if !third.ack_within_bound
        || third.buffered_at_delivery != PAYLOAD_LEN
        || third.ack_elapsed_us < 200_000
    {
        return Err("fragment_third_delayed_ack_precondition");
    }
    sleep(Duration::from_millis(50)).await;

    if sender.buffered_amount() != 0 {
        return Err("fragment_frame_prior_write_still_buffered");
    }
    let started = Instant::now();
    let written = timeout(
        OPERATION_BOUND,
        sender.write_sctp(&frame, PayloadProtocolIdentifier::Binary),
    )
    .await
    .map_err(|_| "fragment_frame_write_timeout")?
    .map_err(|_| "fragment_frame_write_error")?;
    if written != frame.len() {
        return Err("fragment_frame_write_length");
    }

    // Keep one owned read alive across the 600ms correctness boundary. If the
    // boundary is missed, allow only the remainder of the existing 2s
    // operation bound to observe natural retransmission recovery, then join or
    // abort+join that exact read before association cleanup.
    let expected = frame.clone();
    let read_receiver = Arc::clone(&receiver);
    let mut read_task = tokio::spawn(async move {
        let mut received = vec![0_u8; expected.len()];
        let (length, ppi) = read_receiver
            .read_sctp(&mut received)
            .await
            .map_err(|_| "fragment_frame_read_error")?;
        if length != expected.len()
            || ppi != PayloadProtocolIdentifier::Binary
            || received.as_slice() != expected.as_ref()
        {
            return Err("fragment_frame_delivery_mismatch");
        }
        Ok(Instant::now())
    });
    let delivery_deadline = started + ACK_BOUND;
    let operation_deadline = started + OPERATION_BOUND;
    let delivery_remaining = delivery_deadline.saturating_duration_since(Instant::now());
    let completed = if delivery_remaining.is_zero() {
        None
    } else {
        timeout(delivery_remaining, &mut read_task).await.ok()
    };
    if let Some(joined) = completed {
        let finished = joined.map_err(|_| "fragment_frame_read_task_panicked")??;
        observation.delivery_elapsed_us = finished.duration_since(started).as_micros();
        if finished <= delivery_deadline {
            observation.delivered_within_ack_bound = true;
            return Ok(());
        }
        observation.recovered_within_operation_bound = finished <= operation_deadline;
        observation.recovery_elapsed_us = observation.delivery_elapsed_us;
        return Err(if observation.recovered_within_operation_bound {
            "fragmented_delivery_deadline"
        } else {
            "fragment_frame_natural_recovery_timeout"
        });
    }

    let recovery_remaining = operation_deadline.saturating_duration_since(Instant::now());
    if !recovery_remaining.is_zero() {
        if let Ok(joined) = timeout(recovery_remaining, &mut read_task).await {
            let finished = joined.map_err(|_| "fragment_frame_read_task_panicked")??;
            observation.delivery_elapsed_us = finished.duration_since(started).as_micros();
            if finished <= delivery_deadline {
                observation.delivered_within_ack_bound = true;
                return Ok(());
            }
            observation.recovery_elapsed_us = observation.delivery_elapsed_us;
            observation.recovered_within_operation_bound = finished <= operation_deadline;
            return Err(if observation.recovered_within_operation_bound {
                "fragmented_delivery_deadline"
            } else {
                "fragment_frame_natural_recovery_timeout"
            });
        }
    }
    read_task.abort();
    let _ = read_task.await;
    observation.recovery_elapsed_us = started.elapsed().as_micros();
    Err("fragment_frame_natural_recovery_timeout")
}

#[test]
fn normal_delayed_ack_rearms_after_expiry() {
    // Explicit shutdown bounds the dependency's private task teardown even on
    // failure. No assertion is made while the runtime still owns the pair.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the isolated test runtime is available");
    let (measurement, cleanup_ok, connections_released, rows) = runtime.block_on(async {
        let (left, right) = pipe();
        let left: Arc<dyn Conn + Send + Sync> = Arc::new(left);
        let right: Arc<dyn Conn + Send + Sync> = Arc::new(right);
        let left_weak = Arc::downgrade(&left);
        let right_weak = Arc::downgrade(&right);
        let config = |net_conn, name: &str| Config {
            net_conn,
            max_receive_buffer_size: 0,
            max_message_size: 0,
            name: name.to_owned(),
        };
        println!("sctp_rearm_stage stage=setup");
        // Both constructors are polled together. Each result is retained even
        // if the other fails, so an established side can still be closed.
        let (client_result, server_result) = tokio::join!(
            timeout(
                SETUP_BOUND,
                Association::client(config(left, "rearm-client"))
            ),
            timeout(
                SETUP_BOUND,
                Association::server(config(right, "rearm-server"))
            ),
        );
        let client = client_result.ok().and_then(Result::ok);
        let server = server_result.ok().and_then(Result::ok);
        let mut streams = [None, None];
        let mut rows = [MessageObservation::default(); 2];
        let measurement = match (&client, &server) {
            (Some(client), Some(server)) => {
                use futures::FutureExt;
                match std::panic::AssertUnwindSafe(exercise(
                    client,
                    server,
                    &mut streams,
                    &mut rows,
                ))
                .catch_unwind()
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err("measurement_panicked"),
                }
            }
            _ => Err("association_setup_failed"),
        };
        // Retain the failure stage and both delivery observations BEFORE
        // shutdown traffic could acknowledge data or alter buffered_amount.
        println!("sctp_rearm_stage measurement={measurement:?} rows={rows:?}");
        let mut cleanup_ok = true;
        for stream in &mut streams {
            if let Some(stream) = stream.take() {
                cleanup_ok &= matches!(
                    timeout(CLEANUP_BOUND, stream.shutdown(Shutdown::Both)).await,
                    Ok(Ok(()))
                );
                drop(stream);
            }
        }
        // Close, not graceful shutdown: the regression deliberately leaves
        // unacknowledged data on failure and must not wait for a lost ACK.
        for association in [client, server].into_iter().flatten() {
            cleanup_ok &= matches!(
                timeout(CLEANUP_BOUND, association.close()).await,
                Ok(Ok(()))
            );
            drop(association);
        }
        // Public Association exposes no read/write JoinHandles. Its close
        // broadcasts stop; wait for the REAL pipe objects retained by those
        // tasks to be released instead of inventing a task-complete witness.
        let connections_released = timeout(CLEANUP_BOUND, async {
            loop {
                if left_weak.upgrade().is_none() && right_weak.upgrade().is_none() {
                    break;
                }
                sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .is_ok();
        println!(
            "sctp_rearm_cleanup closed={cleanup_ok} connections_released={connections_released}"
        );
        (measurement, cleanup_ok, connections_released, rows)
    });
    runtime.shutdown_timeout(CLEANUP_BOUND);
    assert!(
        cleanup_ok && connections_released,
        "bounded SCTP teardown failed; measurement={measurement:?}"
    );
    assert_eq!(
        measurement,
        Ok(()),
        "normal delayed ACK must rearm after expiry; rows={rows:?}"
    );
    assert!(rows
        .iter()
        .all(|row| row.written && row.delivered && row.ack_within_bound));
}

#[test]
fn fragmented_routed_message_delivers_without_natural_retransmission() {
    // Build and validate the representative public wire shape before opening
    // any association-owned task. Fixed public keys provide signatures only;
    // no home, stored identity or private runtime configuration is read.
    let frame = representative_routed_frame();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the isolated fragmented test runtime is available");
    let (measurement, cleanup_ok, connections_released, observation) =
        runtime.block_on(async move {
            let (left, right) = pipe();
            let left: Arc<dyn Conn + Send + Sync> = Arc::new(left);
            let right: Arc<dyn Conn + Send + Sync> = Arc::new(right);
            let left_weak = Arc::downgrade(&left);
            let right_weak = Arc::downgrade(&right);
            let config = |net_conn, name: &str| Config {
                net_conn,
                max_receive_buffer_size: 0,
                max_message_size: 0,
                name: name.to_owned(),
            };
            println!(
                "sctp_fragment_rearm_stage stage=setup frame_bytes={}",
                frame.len()
            );
            let (client_result, server_result) = tokio::join!(
                timeout(
                    SETUP_BOUND,
                    Association::client(config(left, "fragment-rearm-client"))
                ),
                timeout(
                    SETUP_BOUND,
                    Association::server(config(right, "fragment-rearm-server"))
                ),
            );
            let client = client_result.ok().and_then(Result::ok);
            let server = server_result.ok().and_then(Result::ok);
            let mut streams = [None, None];
            let mut observation = FragmentedObservation::default();
            let measurement = match (&client, &server) {
                (Some(client), Some(server)) => {
                    use futures::FutureExt;
                    match std::panic::AssertUnwindSafe(exercise_fragmented_delivery(
                        client,
                        server,
                        frame,
                        &mut streams,
                        &mut observation,
                    ))
                    .catch_unwind()
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => Err("fragment_measurement_panicked"),
                    }
                }
                _ => Err("fragment_association_setup_failed"),
            };
            println!(
                "sctp_fragment_rearm_stage measurement={measurement:?} observation={observation:?}"
            );

            let mut cleanup_ok = true;
            for stream in &mut streams {
                if let Some(stream) = stream.take() {
                    cleanup_ok &= matches!(
                        timeout(CLEANUP_BOUND, stream.shutdown(Shutdown::Both)).await,
                        Ok(Ok(()))
                    );
                    drop(stream);
                }
            }
            for association in [client, server].into_iter().flatten() {
                cleanup_ok &= matches!(
                    timeout(CLEANUP_BOUND, association.close()).await,
                    Ok(Ok(()))
                );
                drop(association);
            }
            let connections_released = timeout(CLEANUP_BOUND, async {
                loop {
                    if left_weak.upgrade().is_none() && right_weak.upgrade().is_none() {
                        break;
                    }
                    sleep(POLL_INTERVAL).await;
                }
            })
            .await
            .is_ok();
            println!(
                "sctp_fragment_rearm_cleanup closed={cleanup_ok} connections_released={connections_released}"
            );
            (measurement, cleanup_ok, connections_released, observation)
        });
    runtime.shutdown_timeout(CLEANUP_BOUND);

    assert!(
        cleanup_ok && connections_released,
        "bounded fragmented SCTP teardown failed; measurement={measurement:?} observation={observation:?}"
    );
    assert_eq!(
        measurement,
        Ok(()),
        "a representative fragmented routed message must complete inside the normal delayed-ACK bound; observation={observation:?}"
    );
    assert!(
        observation.frame_bytes > LOCKED_INITIAL_MTU
            && observation.second_ack_elapsed_us > 0
            && observation.third_ack_elapsed_us >= 200_000
            && observation.delivered_within_ack_bound,
        "the public fragmented-message regression preconditions and delivery must all be observed: {observation:?}"
    );
}
