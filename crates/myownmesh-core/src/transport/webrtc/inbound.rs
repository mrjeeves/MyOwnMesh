//! The inbound half of one session-gated real-time flow.
//!
//! One task per negotiated inbound track, started by `on_track` once the
//! connector's binding table has admitted the track, and ending when its flow
//! does. It reads RTP, reassembles or passes through according to the framing
//! the application registered, and hands each unit to the engine as an opaque
//! labelled delivery.
//!
//! **Two facts govern every unit, and the peer supplies neither.** The
//! destination is a label resolved from a binding token this side minted before
//! the transceiver that could carry the track existed. The framing is the
//! strategy the local application registered, arriving here as a
//! [`RealtimeUnitPolicy`] decided at bind time. Nothing here reads a MIME name
//! or branches on a codec, so a peer can influence neither where its media lands
//! nor how it is reassembled.

use super::*;

/// Exact ownership retained by one session-flow inbound track pump.
pub(super) struct SessionInboundTrackOwner {
    pub(super) task_observation: Option<ObservationLease>,
    /// A weak claim on the flow this feeds, upgraded per packet.
    ///
    /// Not a [`RealtimeFlowPort`]. The flow is already open and already holds
    /// its one active-flow lease; a strong port here would be a second owner of
    /// that lease and would hold it for the whole life of this task.
    pub(super) port: RealtimeFlowPortHandle,
    /// The flow's end-of-life wake, watched alongside the read.
    ///
    /// Without it a close would leave this task parked in `read_rtp` until the
    /// peer happened to send again — holding a native read lease against a flow
    /// that no longer exists.
    pub(super) end: Arc<LeasedWake>,
    /// The connector's track table and this track's token, for the one
    /// retirement this task may perform.
    ///
    /// The transceiver itself is deliberately not held: stopping it is a
    /// single-owner decision and the table is where that is decided, so a task
    /// that could reach the transceiver directly could stop one someone else
    /// had already claimed.
    pub(super) tracks: Arc<super::RealtimeSessionTracks>,
    pub(super) identity: Arc<RealtimeTrackIdentity>,
    /// The flow this track may deliver to, resolved once at admission.
    ///
    /// It comes from the binding table, so it is a fact this side established
    /// rather than a coordinate derived from anything the peer sent.
    pub(super) label: RealtimeFlowLabel,
    /// Whether payloads are fragments to reassemble or whole units to pass
    /// through, chosen by the application's registered framing.
    pub(super) policy: RealtimeUnitPolicy,
}

/// Drain one remote session-flow track onto the flow it was negotiated for.
///
/// **`Assembled` versus `PayloadPerUnit` is not a flag on one path.**
/// [`RealtimeUnitAssembler`] completes a unit on the RTP marker bit; a stream
/// whose payloads are each already whole does not reliably set it — Opus marks
/// a talkspurt start and nothing after — so routing whole payloads through the
/// assembler would emit the first unit of each talkspurt and silently swallow
/// the rest. That failure is inaudible as an error and audible as broken audio,
/// so the two stay structurally distinct.
///
/// The delivery is constructed **leaseless** and handed to `emit_realtime`,
/// which enqueues it and attaches the payload lease there. Attaching one here
/// would either double-count the bytes or move the conversion ahead of the
/// ownership validation `enqueue_checked` performs.
pub(super) async fn pump_session_flow_track(
    track: Arc<TrackRemote>,
    tx: ConnectorEventSink,
    owner: SessionInboundTrackOwner,
) {
    let SessionInboundTrackOwner {
        task_observation: _task_observation,
        port,
        end,
        tracks,
        identity,
        label,
        policy,
    } = owner;
    let mut assembler = match policy {
        RealtimeUnitPolicy::Assembled(framing) => {
            Some(RealtimeUnitAssembler::guarded(framing, port.clone()))
        }
        RealtimeUnitPolicy::PayloadPerUnit => None,
    };
    // Created once and polled repeatedly rather than rebuilt each turn, so a
    // wake that lands between two turns is still there on the next poll.
    let ended = end.notify().notified();
    tokio::pin!(ended);
    loop {
        // Upgraded per packet and held across nothing that awaits. This is the
        // close check as well as the accounting route: a closed flow answers
        // `None`, and there is nothing left to deliver to.
        let Some(flow) = port.port() else {
            break;
        };
        let native_read = match flow.lifetime.registry.begin_native_read_checked() {
            Ok(read) => read,
            Err(_) => break,
        };
        drop(flow);
        let pkt = tokio::select! {
            // The close wake. Without it this task would stay parked in
            // `read_rtp` — holding the native read lease above — until the peer
            // happened to send again, which for a peer that has stopped sending
            // is never.
            () = &mut ended => break,
            read = track.read_rtp() => match read {
                Ok((pkt, _)) => pkt,
                Err(_) => break, // track ended with its connection
            },
        };
        let Some(flow) = port.port() else {
            break;
        };
        // Every packet this task reads belongs to a flow the promoted session
        // opened, so there is no admission question left to ask and no second
        // gate here to answer it. What remains is the accounting: an exact,
        // content-sized work lease covering the classification and framing this
        // packet is about to cost.
        let _packet_work = match flow
            .lifetime
            .registry
            .admit_session_packet_checked(pkt.payload.len())
        {
            Ok(work) => work,
            Err(_) => break,
        };
        // The exact content-byte work lease now owns the returned packet. The
        // opaque native-read lease no longer has to cover dependency output.
        drop(native_read);
        let (unit, output) = match assembler.as_mut() {
            Some(assembler) => match assembler.push(&pkt) {
                Ok(Some(mut assembled)) => {
                    let Some(output) = assembled.output.take() else {
                        break;
                    };
                    (
                        RealtimeRecvUnit {
                            timestamp: assembled.rtp_timestamp,
                            marker: assembled.entry_point,
                            data: assembled.data,
                        },
                        output,
                    )
                }
                Ok(None) => continue,
                // One malformed packet costs the current unit only; the stream
                // re-syncs on the next timestamp.
                Err(error) => {
                    trace!("session flow depacketize: {error}");
                    continue;
                }
            },
            None => {
                if pkt.payload.is_empty() {
                    continue; // padding / probe
                }
                // Whole-payload flows still account their bytes through the
                // same reservation, so the two shapes are bounded identically.
                let Some(output) = flow.reserve_output(pkt.payload.len()) else {
                    continue;
                };
                (
                    RealtimeRecvUnit {
                        timestamp: pkt.header.timestamp,
                        marker: pkt.header.marker,
                        data: pkt.payload.clone(),
                    },
                    output,
                )
            }
        };
        // Cloned per unit: the pump keeps its own copy for the next iteration,
        // and the delivery carries one that lives as long as the queued unit
        // does. Both are the same shared record, so this is a refcount rather
        // than a second name.
        let delivery = RealtimeInboundDelivery::new(label.clone(), unit);
        if !tx.emit_realtime(&flow, TransportEvent::RealtimeUnit(delivery), output) {
            break;
        }
    }
    // However that ended — closed flow, close wake, dead track, refused
    // resources — this task's transceiver is retired here. Through the table, so
    // that a close or a session replacement racing the same record wins or loses
    // it cleanly; and awaited, so a `stop` someone else is running is finished
    // before this task's own observation leases go back.
    tracks.stop_claimed(&identity).await;
}
