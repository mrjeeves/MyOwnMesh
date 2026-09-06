//! Authenticated RTP duplicate fence, including repairs across sequence wrap.
//! webrtc-util 0.11's wrapped replay detector checks a wrapped offset but marks
//! acceptance with an unwrapped subtraction. A pre-wrap repair can consequently
//! be accepted repeatedly. Keep SRTP authentication/replay protection enabled,
//! and apply this bounded fence before the NACK reader sees authenticated RTP.

use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;
use webrtc::interceptor::{
    stream_info::StreamInfo, Attributes, Interceptor, InterceptorBuilder, RTCPReader, RTCPWriter,
    RTPReader, RTPWriter,
};

pub(super) struct ReplayWindow {
    latest: Option<u16>,
    bits: Vec<u64>,
    size: usize,
}

impl ReplayWindow {
    pub(super) fn new(size: usize) -> Self {
        assert!(size.is_power_of_two() && size < 32_768);
        Self {
            latest: None,
            bits: vec![0; size.div_ceil(64)],
            size,
        }
    }

    pub(super) fn accept(&mut self, seq: u16) -> bool {
        if let Some(latest) = self.latest {
            let delta = seq.wrapping_sub(latest) as i16;
            if delta > 0 {
                if delta as usize >= self.size {
                    self.bits.fill(0);
                } else {
                    for step in 1..=delta as u16 {
                        let slot = usize::from(latest.wrapping_add(step)) % self.size;
                        self.bits[slot / 64] &= !(1u64 << (slot % 64));
                    }
                }
                self.latest = Some(seq);
            } else if usize::from(latest.wrapping_sub(seq)) >= self.size {
                return false;
            }
        } else {
            self.latest = Some(seq);
        }
        let slot = usize::from(seq) % self.size;
        let bit = 1u64 << (slot % 64);
        if self.bits[slot / 64] & bit != 0 {
            return false;
        }
        self.bits[slot / 64] |= bit;
        true
    }
}

pub(super) struct ReplayFence(pub usize);

impl InterceptorBuilder for ReplayFence {
    fn build(
        &self,
        _: &str,
    ) -> Result<Arc<dyn Interceptor + Send + Sync>, webrtc::interceptor::Error> {
        Ok(Arc::new(Self(self.0)))
    }
}

#[async_trait]
impl Interceptor for ReplayFence {
    async fn bind_rtcp_reader(
        &self,
        reader: Arc<dyn RTCPReader + Send + Sync>,
    ) -> Arc<dyn RTCPReader + Send + Sync> {
        reader
    }
    async fn bind_rtcp_writer(
        &self,
        writer: Arc<dyn RTCPWriter + Send + Sync>,
    ) -> Arc<dyn RTCPWriter + Send + Sync> {
        writer
    }
    async fn bind_local_stream(
        &self,
        _: &StreamInfo,
        writer: Arc<dyn RTPWriter + Send + Sync>,
    ) -> Arc<dyn RTPWriter + Send + Sync> {
        writer
    }
    async fn unbind_local_stream(&self, _: &StreamInfo) {}
    async fn bind_remote_stream(
        &self,
        _: &StreamInfo,
        reader: Arc<dyn RTPReader + Send + Sync>,
    ) -> Arc<dyn RTPReader + Send + Sync> {
        Arc::new(ReplayReader {
            reader,
            window: Mutex::new(ReplayWindow::new(self.0)),
        })
    }
    async fn unbind_remote_stream(&self, _: &StreamInfo) {}
    async fn close(&self) -> Result<(), webrtc::interceptor::Error> {
        Ok(())
    }
}

struct ReplayReader {
    reader: Arc<dyn RTPReader + Send + Sync>,
    window: Mutex<ReplayWindow>,
}

#[async_trait]
impl RTPReader for ReplayReader {
    async fn read(
        &self,
        buf: &mut [u8],
        attributes: &Attributes,
    ) -> Result<(webrtc::rtp::packet::Packet, Attributes), webrtc::interceptor::Error> {
        loop {
            let (packet, attributes) = self.reader.read(buf, attributes).await?;
            if self.window.lock().accept(packet.header.sequence_number) {
                return Ok((packet, attributes));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_fence_preserves_repairs_but_rejects_duplicates_and_expired_packets() {
        for start in [1000u16, 65_500] {
            let mut window = ReplayWindow::new(8192);
            assert!(window.accept(start));
            assert!(window.accept(start.wrapping_add(201)));
            assert!(window.accept(start.wrapping_add(1)));
            assert!(
                !window.accept(start.wrapping_add(1)),
                "repaired pre-wrap packet is remembered"
            );
            assert!(!window.accept(start.wrapping_add(201)));
            assert!(window.accept(start.wrapping_add(8194)));
            assert!(
                !window.accept(start.wrapping_add(2)),
                "unseen but expired packet is rejected"
            );
            assert!(
                window.accept(start.wrapping_add(3)),
                "unseen packet inside the boundary is admitted"
            );
            assert!(!window.accept(start.wrapping_add(3)));
        }
    }
}
