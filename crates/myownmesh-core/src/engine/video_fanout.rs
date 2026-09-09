//! Immediate video fan-out bounded by pictures, bytes and fragments.
//! RTP repair releases paced fragments, not necessarily complete pictures.
//! A message-count broadcast ring can lose one picture before IPC sees it.

use super::InboundVideoSample;
use parking_lot::Mutex;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Weak},
};
use tokio::sync::{
    broadcast::error::{RecvError, SendError},
    Notify,
};

const MAX_PICTURES: usize = crate::transport::webrtc::VIDEO_RECEIVE_REPAIR_MAX_FRAMES;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_SAMPLES: usize = 4096;
type Picture = (String, u8, u32);

fn picture(sample: &InboundVideoSample) -> Picture {
    (
        sample.from.clone(),
        sample.sample.lane,
        sample.sample.rtp_timestamp,
    )
}

#[derive(Default)]
struct Queue {
    samples: VecDeque<InboundVideoSample>,
    pictures: HashMap<Picture, usize>,
    bytes: usize,
    lagged: u64,
    closed: bool,
}

impl Queue {
    fn pop(&mut self) -> Option<InboundVideoSample> {
        let sample = self.samples.pop_front()?;
        self.bytes -= sample.sample.data.len() + sample.from.len();
        let key = picture(&sample);
        let count = self.pictures.get_mut(&key).expect("queued picture");
        *count -= 1;
        if *count == 0 {
            self.pictures.remove(&key);
        }
        Some(sample)
    }

    fn push(&mut self, sample: InboundVideoSample) {
        let key = picture(&sample);
        let bytes = sample.sample.data.len() + sample.from.len();
        // Evict oldest samples on real pressure, preserving the original
        // freshness policy and an ordered loss notification to the consumer.
        while !self.samples.is_empty()
            && ((!self.pictures.contains_key(&key) && self.pictures.len() >= MAX_PICTURES)
                || bytes > MAX_BYTES.saturating_sub(self.bytes)
                || self.samples.len() >= MAX_SAMPLES)
        {
            self.pop();
            self.lagged += 1;
        }
        if bytes > MAX_BYTES {
            self.lagged += 1;
            return;
        }
        self.bytes += bytes;
        *self.pictures.entry(key).or_default() += 1;
        self.samples.push_back(sample);
    }
}

#[derive(Default)]
struct Subscription {
    queue: Mutex<Queue>,
    ready: Notify,
}

/// Nonblocking sender. Each subscriber drains independently; a stalled
/// subscriber cannot stall the engine or another subscriber.
#[derive(Default)]
pub struct VideoFanout(Mutex<Vec<Weak<Subscription>>>);

impl VideoFanout {
    pub fn subscribe(&self) -> VideoReceiver {
        let sub = Arc::new(Subscription::default());
        let mut subscribers = self.0.lock();
        subscribers.retain(|weak| weak.strong_count() != 0);
        subscribers.push(Arc::downgrade(&sub));
        VideoReceiver(sub)
    }

    pub fn send(&self, sample: InboundVideoSample) -> Result<usize, SendError<InboundVideoSample>> {
        let mut sent = 0;
        self.0.lock().retain(|weak| {
            let Some(sub) = weak.upgrade() else {
                return false;
            };
            sub.queue.lock().push(sample.clone());
            sub.ready.notify_one();
            sent += 1;
            true
        });
        if sent == 0 {
            Err(SendError(sample))
        } else {
            Ok(sent)
        }
    }
}

impl Drop for VideoFanout {
    fn drop(&mut self) {
        for sub in self.0.get_mut().iter().filter_map(Weak::upgrade) {
            sub.queue.lock().closed = true;
            sub.ready.notify_one();
        }
    }
}

/// One consumer, retaining the existing ordered `Lagged`/`Closed` contract.
pub struct VideoReceiver(Arc<Subscription>);

impl VideoReceiver {
    pub async fn recv(&mut self) -> Result<InboundVideoSample, RecvError> {
        loop {
            {
                let mut queue = self.0.queue.lock();
                if queue.lagged != 0 {
                    return Err(RecvError::Lagged(std::mem::take(&mut queue.lagged)));
                }
                if let Some(sample) = queue.pop() {
                    return Ok(sample);
                }
                if queue.closed {
                    return Err(RecvError::Closed);
                }
            }
            // One reader per subscription: notify_one retains a permit if
            // send/close races the empty check, including cancelled receives.
            self.0.ready.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::VideoSample;

    fn sample(timestamp: u32, sequence: u64) -> InboundVideoSample {
        InboundVideoSample {
            from: "peer".into(),
            sample: VideoSample {
                rtp_timestamp: timestamp,
                sequence,
                lane: 0,
                key: timestamp == 1,
                data: bytes::Bytes::from_static(&[1]),
            },
        }
    }

    #[tokio::test]
    async fn repair_fanout_preserves_paced_pictures_for_a_busy_subscriber() {
        let tx = VideoFanout::default();
        let mut rx = tx.subscribe();
        let (legacy, mut legacy_rx) = tokio::sync::broadcast::channel(16);
        // Busy subscriber, one bounded release: gap + fifteen pictures, with
        // eight paced fragments apiece. No sleeps or scheduler assumptions.
        let mut gap = sample(0, 1);
        gap.sample.data = bytes::Bytes::new();
        tx.send(gap.clone()).unwrap();
        legacy.send(gap).unwrap();
        let mut sequence = 1;
        for timestamp in 1..MAX_PICTURES as u32 {
            for _ in 0..8 {
                sequence += 1;
                let body = sample(timestamp, sequence);
                tx.send(body.clone()).unwrap();
                legacy.send(body).unwrap();
            }
        }
        assert!(matches!(legacy_rx.recv().await, Err(RecvError::Lagged(_))));
        drop(tx);
        for expected in 1..=sequence {
            assert_eq!(rx.recv().await.unwrap().sample.sequence, expected);
        }
        assert_eq!(rx.recv().await.unwrap_err(), RecvError::Closed);
    }

    #[tokio::test]
    async fn real_pressure_is_bounded_and_does_not_delay_a_fast_subscriber() {
        let tx = VideoFanout::default();
        let mut slow = tx.subscribe();
        let mut fast = tx.subscribe();
        for timestamp in 0..=MAX_PICTURES as u32 {
            tx.send(sample(timestamp, timestamp as u64)).unwrap();
            assert_eq!(fast.recv().await.unwrap().sample.rtp_timestamp, timestamp);
        }
        assert_eq!(slow.recv().await.unwrap_err(), RecvError::Lagged(1));
        assert_eq!(slow.recv().await.unwrap().sample.rtp_timestamp, 1);
        assert!(slow.0.queue.lock().pictures.len() < MAX_PICTURES);
        drop(slow);
        drop(fast);
        assert!(tx.send(sample(100, 100)).is_err());
    }

    #[test]
    fn fragment_bytes_peer_and_lane_limits_are_independent() {
        let mut queue = Queue::default();
        for sequence in 0..=MAX_SAMPLES as u64 {
            queue.push(sample(1, sequence));
        }
        assert_eq!(queue.samples.len(), MAX_SAMPLES);
        assert_eq!(queue.lagged, 1);
        let mut oversized = sample(1, 5000);
        oversized.sample.data = bytes::Bytes::from(vec![0; MAX_BYTES]);
        queue.push(oversized); // peer metadata puts it over the byte bound
        assert!(queue.samples.is_empty());
        assert_eq!(queue.bytes, 0);
        assert!(queue.pictures.is_empty());
        let payload = bytes::Bytes::from(vec![0; 1024 * 1024]);
        for sequence in 0..65 {
            let mut body = sample(1, sequence);
            body.sample.data = payload.clone();
            queue.push(body);
        }
        assert!(queue.bytes <= MAX_BYTES);
        assert_eq!(
            queue.samples.len(),
            63,
            "aggregate bytes include peer metadata"
        );
        queue = Queue::default();
        for lane in 0..MAX_PICTURES as u8 {
            let mut body = sample(1, lane as u64);
            body.sample.lane = lane;
            queue.push(body);
        }
        let mut other = sample(1, 100);
        other.from = "other".into();
        queue.push(other);
        assert_eq!(queue.pictures.len(), MAX_PICTURES);
        assert!(!queue.pictures.contains_key(&("peer".into(), 0, 1)));
    }

    #[tokio::test]
    async fn empty_reader_wakes_for_send_and_close() {
        let tx = VideoFanout::default();
        let mut rx = tx.subscribe();
        tokio::join!(
            async {
                assert_eq!(rx.recv().await.unwrap().sample.sequence, 1);
                assert_eq!(rx.recv().await.unwrap_err(), RecvError::Closed);
            },
            async {
                tokio::task::yield_now().await;
                tx.send(sample(1, 1)).unwrap();
                drop(tx);
            }
        );
    }
}
