//! Nonblocking media handoff bounded by pictures and bytes, not paced slices.
//! A repaired picture may contain dozens of samples at one RTP timestamp.
//! Counting those as independent pictures drops valid data during a brief
//! socket-writer stall. No sample is delayed waiting for a picture to finish.

use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Picture {
    peer: Vec<u8>,
    lane: u8,
    timestamp: u32,
}

fn picture(body: &[u8]) -> Option<Picture> {
    if !matches!(
        *body.first()?,
        crate::control::MEDIA_KIND_VIDEO | crate::control::MEDIA_KIND_VIDEO_DISCONTINUITY
    ) {
        return None; // audio/unknown messages each consume one slot
    }
    let head = body.get(..9)?;
    let len = u16::from_le_bytes([head[7], head[8]]) as usize;
    Some(Picture {
        peer: body.get(9..9 + len)?.to_vec(),
        lane: head[2],
        timestamp: u32::from_le_bytes(head[3..7].try_into().ok()?),
    })
}

#[derive(Default)]
struct Budget {
    pictures: HashMap<Picture, usize>,
    other: usize,
    bytes: usize,
    items: usize,
}

struct Item {
    body: Vec<u8>,
    picture: Option<Picture>,
    bytes: usize,
    budget: Arc<Mutex<Budget>>,
    enqueued: Option<std::time::Instant>,
}

impl Drop for Item {
    fn drop(&mut self) {
        let mut budget = self.budget.lock();
        budget.bytes -= self.bytes;
        budget.items -= 1;
        if let Some(picture) = &self.picture {
            let count = budget.pictures.get_mut(picture).expect("reserved picture");
            *count -= 1;
            if *count == 0 {
                budget.pictures.remove(picture);
            }
        } else {
            budget.other -= 1;
        }
    }
}

#[derive(Clone)]
pub struct Sender {
    tx: mpsc::UnboundedSender<Item>,
    budget: Arc<Mutex<Budget>>,
    capacity: usize,
    other_capacity: usize,
    byte_capacity: usize,
}

pub struct Receiver(mpsc::UnboundedReceiver<Item>);

// Bound metadata for tiny same-timestamp samples as well as payload bytes.
// Matches the transport assembler's aggregate packet budget, permitting even
// a one-sample-per-packet repair train without an unlimited queue-node count.
const MAX_QUEUED_SAMPLES: usize = 4096;

pub fn channel(capacity: usize) -> (Sender, Receiver) {
    // Reuse the existing maximum wire-body allocation as an aggregate queue
    // byte ceiling. Previously eight separate bodies could each reach it.
    channel_with_bytes(capacity, crate::control::MAX_MEDIA_FRAME_BYTES)
}

/// Admit one bounded transport repair release while retaining the smaller
/// non-video packet budget. No timer, playout delay or producer wait is added.
pub fn channel_with_other_capacity(capacity: usize, other_capacity: usize) -> (Sender, Receiver) {
    assert!(other_capacity > 0 && other_capacity <= capacity);
    let (mut tx, rx) = channel(capacity);
    tx.other_capacity = other_capacity;
    (tx, rx)
}

fn channel_with_bytes(capacity: usize, byte_capacity: usize) -> (Sender, Receiver) {
    assert!(capacity > 0 && byte_capacity > 0);
    let (tx, rx) = mpsc::unbounded_channel();
    (
        Sender {
            tx,
            budget: Arc::new(Mutex::new(Budget::default())),
            capacity,
            other_capacity: capacity,
            byte_capacity,
        },
        Receiver(rx),
    )
}

impl Sender {
    pub fn try_send(&self, body: Vec<u8>) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        if self.tx.is_closed() {
            return Err(mpsc::error::TrySendError::Closed(body));
        }
        let picture = picture(&body);
        {
            let mut budget = self.budget.lock();
            let known = picture
                .as_ref()
                .is_some_and(|p| budget.pictures.contains_key(p));
            if (!known && budget.pictures.len() + budget.other >= self.capacity)
                || (picture.is_none() && budget.other >= self.other_capacity)
                || body.len() > self.byte_capacity.saturating_sub(budget.bytes)
                || budget.items >= MAX_QUEUED_SAMPLES
            {
                return Err(mpsc::error::TrySendError::Full(body));
            }
            budget.bytes += body.len();
            budget.items += 1;
            if let Some(p) = &picture {
                *budget.pictures.entry(p.clone()).or_default() += 1;
            } else {
                budget.other += 1;
            }
        }
        // The unbounded primitive is private: every item reserves a finite
        // picture/byte budget before entering it, and releases it on all exits.
        let item = Item {
            enqueued: tracing::enabled!(target: "myownmesh::video_timing", tracing::Level::DEBUG)
                .then(std::time::Instant::now),
            bytes: body.len(),
            body,
            picture,
            budget: self.budget.clone(),
        };
        self.tx.send(item).map_err(|mut error| {
            mpsc::error::TrySendError::Closed(std::mem::take(&mut error.0.body))
        })
    }

    pub fn capacity(&self) -> usize {
        let budget = self.budget.lock();
        self.capacity - budget.pictures.len() - budget.other
    }

    pub fn max_capacity(&self) -> usize {
        self.capacity
    }

    /// Only sampled when an existing overflow diagnostic is emitted.
    pub(super) fn pressure(&self) -> (usize, usize, usize, usize) {
        let budget = self.budget.lock();
        (
            budget.pictures.len(),
            budget.other,
            budget.items,
            budget.bytes,
        )
    }
}

impl Receiver {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.recv_timed().await.map(|(body, _)| body)
    }

    pub(crate) async fn recv_timed(&mut self) -> Option<(Vec<u8>, std::time::Duration)> {
        let mut item = self.0.recv().await?;
        let age = item
            .enqueued
            .map_or(std::time::Duration::ZERO, |at| at.elapsed());
        Some((std::mem::take(&mut item.body), age))
    }

    #[cfg(test)]
    pub fn try_recv(&mut self) -> Result<Vec<u8>, mpsc::error::TryRecvError> {
        let mut item = self.0.try_recv()?;
        Ok(std::mem::take(&mut item.body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{encode_inbound_frame, MEDIA_KIND_VIDEO};

    fn fragment(peer: &str, lane: u8, ts: u32) -> Vec<u8> {
        encode_inbound_frame(MEDIA_KIND_VIDEO, false, lane, ts, peer, &[0x61; 32])
    }

    #[test]
    fn picture_slots_and_bytes_are_independently_bounded() {
        let body = fragment("peer", 0, 1);
        let (tx, mut rx) = channel_with_bytes(2, body.len() * 3);
        tx.try_send(body.clone()).unwrap();
        tx.try_send(body.clone()).unwrap();
        tx.try_send(body.clone()).unwrap();
        assert_eq!(tx.capacity(), 1);
        assert!(matches!(
            tx.try_send(body.clone()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(rx.try_recv().unwrap(), body);
        tx.try_send(fragment("peer", 0, 2)).unwrap();
        assert_eq!(tx.capacity(), 0);
        rx.try_recv().unwrap();
        assert!(matches!(
            tx.try_send(fragment("peer", 0, 3)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        rx.try_recv().unwrap();
        assert_eq!(tx.capacity(), 1);
        tx.try_send(fragment("peer", 0, 3)).unwrap();
        drop(rx);
        assert_eq!(tx.capacity(), 2);
        assert!(matches!(
            tx.try_send(body),
            Err(mpsc::error::TrySendError::Closed(_))
        ));
    }

    #[test]
    fn equal_timestamps_on_different_peers_or_lanes_do_not_share_a_slot() {
        let (tx, _rx) = channel(2);
        tx.try_send(fragment("a", 0, 1)).unwrap();
        tx.try_send(fragment("a", 1, 1)).unwrap();
        assert!(matches!(
            tx.try_send(fragment("b", 0, 1)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }

    #[tokio::test]
    async fn timed_receive_preserves_body_budget_and_reports_residence() {
        let (tx, mut rx) = channel(2);
        let body = fragment("peer", 0, 1);
        tx.try_send(body.clone()).unwrap();
        assert_eq!(tx.pressure(), (1, 0, 1, body.len()));
        // Inject a synthetic enqueue age: no sleep or live pipe needed.
        let mut item = rx.0.try_recv().unwrap();
        item.enqueued = Some(std::time::Instant::now() - std::time::Duration::from_millis(25));
        tx.tx
            .send(item)
            .unwrap_or_else(|_| panic!("receiver is open"));
        let (received, age) = rx.recv_timed().await.unwrap();
        assert_eq!(received, body);
        assert!(age >= std::time::Duration::from_millis(25));
        assert_eq!(tx.pressure(), (0, 0, 0, 0));
        tx.try_send(body.clone()).unwrap();
        assert_eq!(rx.recv().await.unwrap(), body, "untimed API is unchanged");
        assert_eq!(tx.pressure(), (0, 0, 0, 0));
    }

    #[test]
    fn tiny_samples_cannot_evade_the_metadata_bound() {
        let (tx, rx) = channel(1);
        let body = fragment("peer", 0, 1);
        for _ in 0..MAX_QUEUED_SAMPLES {
            tx.try_send(body.clone()).unwrap();
        }
        assert!(matches!(
            tx.try_send(body),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        drop(rx);
        let budget = tx.budget.lock();
        assert_eq!((budget.items, budget.bytes, budget.other), (0, 0, 0));
        assert!(budget.pictures.is_empty());
    }

    #[test]
    fn audio_and_malformed_messages_remain_individually_bounded() {
        let (tx, mut rx) = channel(2);
        let audio =
            encode_inbound_frame(crate::control::MEDIA_KIND_AUDIO, false, 0, 1, "peer", &[1]);
        tx.try_send(audio.clone()).unwrap();
        tx.try_send(vec![MEDIA_KIND_VIDEO]).unwrap();
        assert!(matches!(
            tx.try_send(audio.clone()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(rx.try_recv().unwrap(), audio);
        assert_eq!(tx.capacity(), 1);
    }
}
