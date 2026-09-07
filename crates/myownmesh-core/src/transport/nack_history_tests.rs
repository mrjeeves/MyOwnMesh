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
use webrtc::rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack;
use webrtc::rtp::packet::Packet;

type RtcpPacket = Box<dyn webrtc::rtcp::packet::Packet + Send + Sync>;

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
    if legacy && separation >= 512 {
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
        for separation in [512, 1024] {
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
