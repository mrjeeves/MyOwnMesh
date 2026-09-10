//! In-process loopback signaling. Used by tests and by embedding
//! apps that want to wire two `Mesh` instances together in the
//! same process without taking a dependency on a Nostr relay.
//!
//! A single [`LocalBroker`] owns the routing table. Each peer joins with the
//! outbound queue the engine fills and somewhere to put what arrives; the
//! broker fans the engine's outbound messages to the matching destination.
//! There is no inbound queue in between — see [`crate::InboundSink`].

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::trace;

use crate::{CarrierAttribution, InboundSink, OutboundSource, SignalingMessage};

/// Engine-side outbound message — the engine emits these for the
/// signaling driver to deliver.
#[derive(Debug, Clone)]
pub enum LocalOutbound {
    /// Sent on join: "I'm here, room handle = X".
    Announce { device_id: String },
    /// Sent during a peer exchange.
    DirectedToPeer { to: String, msg: SignalingMessage },
    /// Leave broadcast.
    Leave { device_id: String },
}

/// Engine-side inbound message — broker delivers these into the
/// engine's command queue.
#[derive(Debug, Clone)]
pub enum LocalInbound {
    PeerAnnounced {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Message {
        from: String,
        msg: SignalingMessage,
    },
    PeerLeft {
        device_id: String,
        attribution: CarrierAttribution,
    },
}

/// One peer's hook into the broker. Stored in the broker's
/// routing table.
struct PeerHandle {
    device_id: String,
    inbound: InboundSink<LocalInbound>,
}

#[derive(Default)]
struct BrokerInner {
    /// Room-handle → vec of currently-joined peer handles.
    rooms: HashMap<String, Vec<PeerHandle>>,
}

/// Local broker. Shareable across mesh instances in the same
/// process; each `join` returns the per-peer outbound sender the
/// engine writes to.
#[derive(Default, Clone)]
pub struct LocalBroker {
    inner: Arc<Mutex<BrokerInner>>,
}

impl LocalBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Join a peer to the named room, delivering into the caller's sink.
    ///
    /// The broker keeps no inbound queue: every report is offered to `inbound`
    /// on the task that produced it, so a consumer that will not admit a value
    /// is not turned into a place the broker stores it.
    ///
    /// The broker keeps no outbound queue either: it pulls `outbound`, so a
    /// translated value exists only when the broker is ready to route it. See
    /// [`OutboundSource`].
    ///
    /// # The sink is called under the routing lock
    ///
    /// Registration and fan-out both offer while the routing table is held, so
    /// a sink that tried to call back into this broker would deadlock. Admitting
    /// a value is all a sink is for, and the consumers here do exactly that; the
    /// alternative — copying the peer list out and offering afterwards — would
    /// let a peer that left in between be delivered to.
    ///
    /// Returns the exact outbound forwarder task. Lifecycle owners must retain
    /// and await it so room membership and the final leave are observed.
    pub fn join_with_sink<O: Send + 'static>(
        &self,
        room: &str,
        device_id: &str,
        mut outbound: Box<dyn OutboundSource<LocalOutbound, Owner = O>>,
        inbound: InboundSink<LocalInbound>,
    ) -> tokio::task::JoinHandle<()> {
        // Register and announce to existing peers.
        {
            let mut inner = self.inner.lock();
            let peers = inner.rooms.entry(room.to_string()).or_default();
            // Existing peers learn about us, and we learn about
            // them. Both directions fire so each side initiates
            // its handshake from the same announce signal.
            for p in peers.iter() {
                let _ = p.inbound.send(LocalInbound::PeerAnnounced {
                    device_id: device_id.to_string(),
                    attribution: CarrierAttribution::CarrierObserved,
                });
                let _ = inbound.send(LocalInbound::PeerAnnounced {
                    device_id: p.device_id.clone(),
                    attribution: CarrierAttribution::CarrierObserved,
                });
            }
            peers.push(PeerHandle {
                device_id: device_id.to_string(),
                inbound,
            });
        }

        // Forward outbound messages from this peer to the room.
        let inner = self.inner.clone();
        let room = room.to_string();
        let device_id_for_task = device_id.to_string();
        tokio::spawn(async move {
            while let Some(out) = outbound.recv().await {
                // Routed by *borrowing* the owned signal, and dropped only after
                // every inbound offer this fan-out makes has completed. The
                // owner therefore outlives every copy `route_outbound` hands to
                // a peer, which is the whole invariant: nothing derived from
                // this value exists after what funded it is gone.
                let routed = route_outbound(&inner, &room, &device_id_for_task, out.value());
                // The local carrier commits only after the synchronous route
                // has transferred ownership to at least one live destination.
                // A refused/closed sink drops the completion unit as refusal.
                if routed > 0 {
                    out.accept();
                }
                trace!(routed, "broker fanout");
                drop(out);
            }
            // Sender dropped → leave the room.
            let mut guard = inner.lock();
            if let Some(peers) = guard.rooms.get_mut(&room) {
                let left = device_id_for_task.clone();
                peers.retain(|p| p.device_id != left);
                let leave = LocalInbound::PeerLeft {
                    device_id: left,
                    attribution: CarrierAttribution::CarrierObserved,
                };
                for p in peers.iter() {
                    let _ = p.inbound.send(leave.clone());
                }
                if peers.is_empty() {
                    guard.rooms.remove(&room);
                }
            }
        })
    }
}

fn route_outbound(
    inner: &Arc<Mutex<BrokerInner>>,
    room: &str,
    from: &str,
    out: &LocalOutbound,
) -> usize {
    let inner = inner.lock();
    let Some(peers) = inner.rooms.get(room) else {
        return 0;
    };
    let mut delivered = 0;
    for p in peers.iter() {
        if p.device_id == from {
            continue;
        }
        let msg = match out {
            // Attributed to the registered handle that sent, not to the id
            // in the payload. The two are the same for an honest peer, and when
            // they differ the sender was naming somebody else.
            LocalOutbound::Announce { device_id: _ } => LocalInbound::PeerAnnounced {
                device_id: from.to_string(),
                attribution: CarrierAttribution::CarrierObserved,
            },
            LocalOutbound::DirectedToPeer { to, msg } => {
                if &p.device_id != to {
                    continue;
                }
                LocalInbound::Message {
                    from: from.to_string(),
                    msg: msg.clone(),
                }
            }
            LocalOutbound::Leave { device_id: _ } => LocalInbound::PeerLeft {
                device_id: from.to_string(),
                attribution: CarrierAttribution::CarrierObserved,
            },
        };
        if matches!(p.inbound.offer(msg), crate::InboundOutcome::Accepted) {
            delivered += 1;
        }
    }
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CarrierCommit, OwnedSignal};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc;

    /// An owner that records its own release — see the mDNS control of the same
    /// shape.
    struct ReleaseFlag(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for ReleaseFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct CommitCounts {
        accepted: Arc<AtomicUsize>,
        refused: Arc<AtomicUsize>,
    }

    impl CarrierCommit for CommitCounts {
        fn accepted(&self) {
            self.accepted.fetch_add(1, Ordering::SeqCst);
        }

        fn refused(&self) {
            self.refused.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A source that yields a fixed script of owned values and then ends.
    struct ScriptedSource(std::collections::VecDeque<OwnedSignal<LocalOutbound, ReleaseFlag>>);

    #[async_trait::async_trait]
    impl OutboundSource<LocalOutbound> for ScriptedSource {
        type Owner = ReleaseFlag;

        async fn recv(&mut self) -> Option<OwnedSignal<LocalOutbound, ReleaseFlag>> {
            self.0.pop_front()
        }
    }

    /// **A value's owner outlives the fan-out of that value, and is gone before
    /// the next one is pulled.**
    ///
    /// Both halves are observed from inside the sink, which the broker calls
    /// while the routing lock is held and — for the first message — while the
    /// signal that produced it is still alive. So the same flag reads `false` at
    /// the delivery of the first message and `true` at the delivery of the
    /// second, and neither reading is a race: the broker's loop drops a signal
    /// before it calls `recv` again, so by the time the second message exists the
    /// first owner has certainly been released.
    ///
    /// The two readings discriminate in opposite directions. A broker that
    /// released the owner before offering its value would read `true` first; a
    /// broker that parked signals in a queue instead of dropping them would read
    /// `false` second.
    #[tokio::test]
    async fn an_outbound_owner_spans_its_own_fanout_and_no_longer() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let broker = LocalBroker::new();

        let first_released = Arc::new(AtomicBool::new(false));
        let (probe_tx, mut probe_rx) = mpsc::unbounded_channel::<bool>();
        let flag_for_sink = Arc::clone(&first_released);
        // Bob is a peer with no outbound of its own; the sender is held so the
        // broker does not treat him as having left.
        let (bob_tx, bob_rx) = mpsc::unbounded_channel::<LocalOutbound>();
        let bob_outbound: Box<dyn OutboundSource<LocalOutbound, Owner = ()>> =
            Box::new(crate::UnboundedSource::new(bob_rx));
        let bob_task = broker.join_with_sink(
            "room1",
            "bob",
            bob_outbound,
            InboundSink::new(move |value: LocalInbound| {
                if matches!(value, LocalInbound::Message { .. }) {
                    let _ = probe_tx.send(flag_for_sink.load(Ordering::SeqCst));
                }
                true
            }),
        );

        let directed = |peer_id: &str| LocalOutbound::DirectedToPeer {
            to: "bob".to_string(),
            msg: SignalingMessage::Announce {
                peer_id: peer_id.to_string(),
            },
        };
        let mut script = std::collections::VecDeque::new();
        script.push_back(OwnedSignal::new(
            directed("one"),
            ReleaseFlag(Arc::clone(&first_released)),
        ));
        script.push_back(OwnedSignal::new(
            directed("two"),
            ReleaseFlag(Arc::new(AtomicBool::new(false))),
        ));
        let alice_outbound: Box<dyn OutboundSource<LocalOutbound, Owner = ReleaseFlag>> =
            Box::new(ScriptedSource(script));
        let alice_task =
            broker.join_with_sink("room1", "alice", alice_outbound, InboundSink::new(|_| true));

        assert_eq!(
            probe_rx.recv().await,
            Some(false),
            "the first message was offered to a peer after its owner had already \
             been released"
        );
        assert_eq!(
            probe_rx.recv().await,
            Some(true),
            "the broker pulled a second value while still holding the first — \
             that is a queue, and the broker is not supposed to be one"
        );
        alice_task
            .await
            .expect("finite outbound source forwarder joined");
        drop(bob_tx);
        bob_task.await.expect("bob forwarder leaves explicitly");
    }

    #[tokio::test]
    async fn local_carrier_commits_after_route_admission() {
        let broker = LocalBroker::new();
        let (bob_tx, bob_rx) = mpsc::unbounded_channel::<LocalOutbound>();
        let bob_outbound: Box<dyn OutboundSource<LocalOutbound, Owner = ()>> =
            Box::new(crate::UnboundedSource::new(bob_rx));
        let bob_task = broker.join_with_sink(
            "commit-room",
            "bob",
            bob_outbound,
            InboundSink::new_typed(|_| crate::InboundOutcome::Accepted),
        );

        let accepted = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let signal = OwnedSignal::with_commit(
            LocalOutbound::DirectedToPeer {
                to: "bob".to_string(),
                msg: SignalingMessage::Announce {
                    peer_id: "alice".to_string(),
                },
            },
            ReleaseFlag(Arc::new(std::sync::atomic::AtomicBool::new(false))),
            crate::CarrierCommitUnit::new(CommitCounts {
                accepted: Arc::clone(&accepted),
                refused: Arc::clone(&refused),
            }),
        );
        let source: Box<dyn OutboundSource<LocalOutbound, Owner = ReleaseFlag>> =
            Box::new(ScriptedSource(std::collections::VecDeque::from([signal])));
        broker
            .join_with_sink(
                "commit-room",
                "alice",
                source,
                InboundSink::new_typed(|_| crate::InboundOutcome::Accepted),
            )
            .await
            .expect("local carrier forwarder joined");
        drop(bob_tx);
        bob_task.await.expect("bob forwarder leaves explicitly");

        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        assert_eq!(refused.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn local_carrier_refuses_when_route_has_no_live_destination() {
        let broker = LocalBroker::new();
        let accepted = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let signal = OwnedSignal::with_commit(
            LocalOutbound::DirectedToPeer {
                to: "absent".to_string(),
                msg: SignalingMessage::Announce {
                    peer_id: "alice".to_string(),
                },
            },
            ReleaseFlag(Arc::new(std::sync::atomic::AtomicBool::new(false))),
            crate::CarrierCommitUnit::new(CommitCounts {
                accepted: Arc::clone(&accepted),
                refused: Arc::clone(&refused),
            }),
        );
        let source: Box<dyn OutboundSource<LocalOutbound, Owner = ReleaseFlag>> =
            Box::new(ScriptedSource(std::collections::VecDeque::from([signal])));
        broker
            .join_with_sink(
                "empty-commit-room",
                "alice",
                source,
                InboundSink::new_typed(|_| crate::InboundOutcome::Accepted),
            )
            .await
            .expect("local carrier forwarder joined");

        assert_eq!(accepted.load(Ordering::SeqCst), 0);
        assert_eq!(refused.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn join_announces_existing_peers() {
        let broker = LocalBroker::new();
        let (tx_a, out_a) = mpsc::unbounded_channel();
        let (in_a, mut rx_a) = mpsc::unbounded_channel();
        let alice_task = broker.join_with_sink(
            "room1",
            "alice",
            Box::new(crate::UnboundedSource::new(out_a)),
            InboundSink::from_unbounded(in_a),
        );
        // No peers in the room yet — alice gets nothing.
        let none = tokio::time::timeout(std::time::Duration::from_millis(50), rx_a.recv()).await;
        assert!(none.is_err(), "alice received unexpected event");

        let (tx_b, out_b) = mpsc::unbounded_channel();
        let (in_b, mut rx_b) = mpsc::unbounded_channel();
        let bob_task = broker.join_with_sink(
            "room1",
            "bob",
            Box::new(crate::UnboundedSource::new(out_b)),
            InboundSink::from_unbounded(in_b),
        );
        // alice learns about bob; bob learns about alice.
        match tokio::time::timeout(std::time::Duration::from_millis(100), rx_a.recv())
            .await
            .unwrap()
            .unwrap()
        {
            LocalInbound::PeerAnnounced { device_id, .. } => assert_eq!(device_id, "bob"),
            other => panic!("alice expected PeerAnnounced(bob), got {other:?}"),
        }
        match tokio::time::timeout(std::time::Duration::from_millis(100), rx_b.recv())
            .await
            .unwrap()
            .unwrap()
        {
            LocalInbound::PeerAnnounced { device_id, .. } => assert_eq!(device_id, "alice"),
            other => panic!("bob expected PeerAnnounced(alice), got {other:?}"),
        }
        drop(tx_a);
        drop(tx_b);
        alice_task.await.expect("alice forwarder leaves explicitly");
        bob_task.await.expect("bob forwarder leaves explicitly");
    }

    #[tokio::test]
    async fn directed_messages_route_to_recipient() {
        let broker = LocalBroker::new();
        let (tx_a, out_a) = mpsc::unbounded_channel();
        let (in_a, mut _rx_a) = mpsc::unbounded_channel();
        let alice_task = broker.join_with_sink(
            "room1",
            "alice",
            Box::new(crate::UnboundedSource::new(out_a)),
            InboundSink::from_unbounded(in_a),
        );
        let (tx_b, out_b) = mpsc::unbounded_channel();
        let (in_b, mut rx_b) = mpsc::unbounded_channel();
        let bob_task = broker.join_with_sink(
            "room1",
            "bob",
            Box::new(crate::UnboundedSource::new(out_b)),
            InboundSink::from_unbounded(in_b),
        );
        // Drain announces
        let _ = tokio::time::timeout(std::time::Duration::from_millis(50), rx_b.recv()).await;

        tx_a.send(LocalOutbound::DirectedToPeer {
            to: "bob".into(),
            msg: SignalingMessage::Offer {
                peer_id: "alice".into(),
                offer_id: "o1".into(),
                sdp: "fake-sdp".into(),
            },
        })
        .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx_b.recv())
            .await
            .unwrap()
            .unwrap();
        match got {
            LocalInbound::Message { from, msg } => {
                assert_eq!(from, "alice");
                if let SignalingMessage::Offer { sdp, .. } = msg {
                    assert_eq!(sdp, "fake-sdp");
                } else {
                    panic!("expected Offer");
                }
            }
            other => panic!("expected Message, got {other:?}"),
        }
        drop(tx_a);
        drop(tx_b);
        alice_task.await.expect("alice forwarder leaves explicitly");
        bob_task.await.expect("bob forwarder leaves explicitly");
    }
}
