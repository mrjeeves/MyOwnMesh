//! Exercise the actual patched dependency and our replay fence, not a model.
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use webrtc::interceptor::nack::generator::Generator;
use webrtc::interceptor::stream_info::{RTCPFeedback, StreamInfo};
use webrtc::interceptor::{Attributes, InterceptorBuilder, RTCPWriter, RTPReader};
use webrtc::interceptor::{RTCPReader, RTPWriter};
use webrtc::rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use webrtc::rtp::packet::Packet;

type RtcpPacket = Box<dyn webrtc::rtcp::packet::Packet + Send + Sync>;

struct RepeatedNack;
#[async_trait]
impl RTCPReader for RepeatedNack {
    async fn read(
        &self,
        _: &mut [u8],
        a: &Attributes,
    ) -> Result<(Vec<RtcpPacket>, Attributes), webrtc::interceptor::Error> {
        Ok((vec![Box::new(TransportLayerNack {
            media_ssrc: 7,
            nacks: webrtc::rtcp::transport_feedbacks::transport_layer_nack::nack_pairs_from_sequence_numbers(
                &(0..32).map(|i| 65520u16.wrapping_add(i)).collect::<Vec<_>>()
            ),
            ..Default::default()
        })], a.clone()))
    }
}

struct GatedRepairs {
    blocked: std::sync::atomic::AtomicBool,
    gate: tokio::sync::Semaphore,
    started: mpsc::UnboundedSender<u16>,
}
#[async_trait]
impl RTPWriter for GatedRepairs {
    async fn write(&self, p: &Packet, _: &Attributes) -> Result<usize, webrtc::interceptor::Error> {
        if self.blocked.load(std::sync::atomic::Ordering::Relaxed) {
            self.started.send(p.header.sequence_number).unwrap();
            self.gate.acquire().await.unwrap().forget();
        }
        Ok(p.payload.len())
    }
}

#[tokio::test(start_paused = true)]
async fn overlapping_nacks_coalesce_pending_repairs_without_delaying_new_retries() {
    use std::sync::atomic::Ordering;
    let responder = webrtc::interceptor::nack::responder::Responder::builder()
        .with_log2_size(13)
        .build("repair-overlap")
        .unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let sink = Arc::new(GatedRepairs {
        blocked: std::sync::atomic::AtomicBool::new(false),
        gate: tokio::sync::Semaphore::new(0),
        started: tx,
    });
    let info = StreamInfo {
        ssrc: 7,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let writer = responder.bind_local_stream(&info, sink.clone()).await;
    for i in 0..32 {
        writer
            .write(
                &Packet {
                    header: webrtc::rtp::header::Header {
                        ssrc: 7,
                        sequence_number: 65520u16.wrapping_add(i),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &Attributes::new(),
            )
            .await
            .unwrap();
    }
    sink.blocked.store(true, Ordering::Relaxed);
    let feedback = responder.bind_rtcp_reader(Arc::new(RepeatedNack)).await;
    for _ in 0..6 {
        feedback
            .read(&mut [0; 1500], &Attributes::new())
            .await
            .unwrap();
        tokio::task::yield_now().await;
    }
    assert_eq!(rx.try_recv().unwrap(), 65520);
    assert!(
        rx.try_recv().is_err(),
        "overlapping feedback started duplicate repair writers"
    );
    sink.gate.add_permits(32);
    for i in 1..32 {
        assert_eq!(rx.recv().await.unwrap(), 65520u16.wrapping_add(i));
    }
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(rx.try_recv().is_err(), "duplicate feedback remained queued");
    // A subsequent NACK is a real retry, not something to suppress by time.
    feedback
        .read(&mut [0; 1500], &Attributes::new())
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap(), 65520);
    sink.gate.add_permits(32);
    for _ in 1..32 {
        rx.recv().await.unwrap();
    }
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    feedback
        .read(&mut [0; 1500], &Attributes::new())
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap(), 65520);
    responder.unbind_local_stream(&info).await;
    sink.gate.add_permits(32);
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(
        rx.try_recv().is_err(),
        "unbound stream retained a repair worker"
    );
    responder.close().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn nack_timer_does_not_replay_missed_feedback_ticks() {
    let info = StreamInfo {
        ssrc: 7,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let generator = Generator::builder()
        .with_interval(super::webrtc::NACK_INTERVAL)
        .build("feedback-catchup")
        .unwrap();
    let reader = generator
        .bind_remote_stream(&info, Arc::new(Input(Mutex::new(VecDeque::from([0, 2])))))
        .await;
    for _ in 0..2 {
        reader
            .read(&mut [0; 1500], &Attributes::new())
            .await
            .unwrap();
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    generator.bind_rtcp_writer(Arc::new(Feedback(tx))).await;
    assert_eq!(rx.recv().await.unwrap(), vec![1]);
    // A scheduler pause does not create six independent loss observations.
    tokio::time::advance(super::webrtc::NACK_INTERVAL * 6).await;
    for _ in 0..12 {
        tokio::task::yield_now().await;
    }
    assert_eq!(rx.try_recv().unwrap(), vec![1]);
    assert!(
        rx.try_recv().is_err(),
        "stale timer ticks produced a repair burst"
    );
    tokio::time::advance(super::webrtc::NACK_INTERVAL).await;
    assert_eq!(rx.recv().await.unwrap(), vec![1]);
    generator.close().await.unwrap();
}

struct Input(Mutex<VecDeque<u16>>);

#[async_trait]
impl RTPReader for Input {
    async fn read(
        &self,
        _: &mut [u8],
        attributes: &Attributes,
    ) -> Result<(Packet, Attributes), webrtc::interceptor::Error> {
        let seq = self.0.lock().pop_front().expect("test input available");
        Ok((
            Packet {
                header: webrtc::rtp::header::Header {
                    ssrc: 7,
                    sequence_number: seq,
                    ..Default::default()
                },
                ..Default::default()
            },
            attributes.clone(),
        ))
    }
}

struct Feedback(mpsc::UnboundedSender<Vec<u16>>);

#[async_trait]
impl RTCPWriter for Feedback {
    async fn write(
        &self,
        packets: &[RtcpPacket],
        _: &Attributes,
    ) -> Result<usize, webrtc::interceptor::Error> {
        for packet in packets {
            if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>() {
                assert_eq!(nack.media_ssrc, 7);
                let missing = nack
                    .nacks
                    .iter()
                    .flat_map(|pair| pair.into_iter())
                    .collect();
                self.0.send(missing).expect("feedback receiver alive");
            }
        }
        Ok(0)
    }
}

async fn check_repair(start: u16, separation: u16) {
    let old = start.wrapping_add(1);
    let missing = old.wrapping_add(separation);
    let mut sequence: VecDeque<_> = (0..=separation + 11)
        .map(|offset| start.wrapping_add(offset))
        .filter(|seq| *seq != old && *seq != missing)
        .collect();
    sequence.push_back(old);
    let expected = sequence.clone();
    let input = Arc::new(Input(Mutex::new(sequence)));
    let info = StreamInfo {
        ssrc: 7,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let generator = Generator::builder()
        .with_log2_size_minus_6(super::webrtc::NACK_GENERATOR_LOG2_SIZE_MINUS_6)
        .with_skip_last_n(super::webrtc::NACK_REORDER_TAIL_PACKETS)
        .with_max_nacks_per_tick(super::webrtc::NACK_MAX_REQUESTS_PER_TICK)
        .with_interval(super::webrtc::NACK_INTERVAL)
        .build("nack-history-regression")
        .unwrap();
    let fence = super::rtp_replay::ReplayFence(super::webrtc::SRTP_REPLAY_WINDOW_PACKETS)
        .build("nack-history-regression")
        .unwrap();
    let reader = fence.bind_remote_stream(&info, input.clone()).await;
    let reader = generator.bind_remote_stream(&info, reader).await;
    let mut buf = [0; 1500];
    for seq in expected {
        let (packet, _) = reader.read(&mut buf, &Attributes::new()).await.unwrap();
        assert_eq!(
            packet.header.sequence_number, seq,
            "including the old repair"
        );
    }
    // Start feedback only after the deterministic input is consumed, avoiding
    // timing-sensitive assertions about intermediate NACK batches.
    let (tx, mut rx) = mpsc::unbounded_channel();
    generator.bind_rtcp_writer(Arc::new(Feedback(tx))).await;
    let first = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
    let legacy = std::env::var("MYOWNMESH_DIAG_LEGACY_NACK_HISTORY").as_deref() == Ok("1");
    if legacy && separation >= (64 << super::webrtc::NACK_GENERATOR_LOG2_SIZE_MINUS_6) {
        // Explicit A/B mode must reproduce the old corruption. Run this in
        // a separate process; never mutate the environment between tests.
        assert!(first.is_err(), "legacy mode should reproduce the lost NACK");
    } else {
        assert_eq!(first.unwrap().unwrap(), vec![missing]);
    }
    input.0.lock().push_back(missing);
    let (packet, _) = reader.read(&mut buf, &Attributes::new()).await.unwrap();
    assert_eq!(packet.header.sequence_number, missing);
    assert!(tokio::time::timeout(Duration::from_millis(60), rx.recv())
        .await
        .is_err());
    generator.unbind_remote_stream(&info).await;
    generator.close().await.unwrap();
    fence.close().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn late_repair_keeps_newer_hole_nacked() {
    for start in [1000, 65400] {
        let history = 64 << super::webrtc::NACK_GENERATOR_LOG2_SIZE_MINUS_6;
        for separation in [history, history * 2] {
            check_repair(start, separation).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn in_window_repair_and_wrap_still_work() {
    for start in [1000, 65530] {
        check_repair(start, 32).await;
    }
}

#[tokio::test(start_paused = true)]
async fn feedback_limit_does_not_forget_waiting_repairs() {
    let input = Arc::new(Input(Mutex::new(VecDeque::from([0, 700]))));
    let info = StreamInfo {
        ssrc: 7,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let generator = Generator::builder()
        .with_log2_size_minus_6(super::webrtc::NACK_GENERATOR_LOG2_SIZE_MINUS_6)
        .with_skip_last_n(super::webrtc::NACK_REORDER_TAIL_PACKETS)
        .with_max_nacks_per_tick(super::webrtc::NACK_MAX_REQUESTS_PER_TICK)
        .with_interval(super::webrtc::NACK_INTERVAL)
        .build("nack-feedback-bound")
        .unwrap();
    let reader = generator.bind_remote_stream(&info, input.clone()).await;
    for _ in 0..2 {
        reader
            .read(&mut [0; 1500], &Attributes::new())
            .await
            .unwrap();
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    generator.bind_rtcp_writer(Arc::new(Feedback(tx))).await;
    let first = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let limit = super::webrtc::NACK_MAX_REQUESTS_PER_TICK as u16;
    assert_eq!(first, (1..=limit).collect::<Vec<_>>());
    for sequence in first {
        input.0.lock().push_back(sequence);
        reader
            .read(&mut [0; 1500], &Attributes::new())
            .await
            .unwrap();
    }
    let next = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        next,
        (limit + 1..=700 - super::webrtc::NACK_REORDER_TAIL_PACKETS).collect::<Vec<_>>()
    );
    generator.unbind_remote_stream(&info).await;
    generator.close().await.unwrap();
}
