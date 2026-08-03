//! Legacy WebRTC media-lane compatibility over generic real-time owners.

use super::*;

/// Which media pool a lane belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneKind {
    Video,
    Audio,
}

/// One lifecycle-managed lane slot's state. (`None` in the pool =
/// never opened / fully reaped.)
#[derive(Clone)]
pub(super) enum LaneSlot {
    /// Negotiated (or negotiating) and writable.
    Open(Arc<TrackLocalStaticSample>),
    /// Closed by the app, track still attached: a reopen within
    /// [`LANE_DRAIN_GRACE`] revives it with zero SDP work; the reaper
    /// tears it down for real once the grace lapses.
    Draining {
        track: Arc<TrackLocalStaticSample>,
        since: Instant,
    },
}

/// Build the local track for one lane. The id carries the lane index
/// (`video-3`) — that's how the far side routes inbound samples.
pub(super) fn make_media_track(kind: LaneKind, lane: u8) -> Arc<TrackLocalStaticSample> {
    let (mime, prefix) = match kind {
        LaneKind::Video => (MIME_TYPE_H264, "video"),
        LaneKind::Audio => (MIME_TYPE_OPUS, "audio"),
    };
    Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: mime.to_owned(),
            ..Default::default()
        },
        format!("{prefix}-{lane}"),
        "myownmesh".to_string(),
    ))
}

/// Attach a local track to the connection and drain its sender's RTCP
/// so the interceptors (NACK responder, reports) actually run; the
/// drain task ends with the connection.
pub(super) async fn attach_track(
    pc: &Arc<RTCPeerConnection>,
    track: &Arc<TrackLocalStaticSample>,
    resource_scope: Option<&PeerConnectionResourceScope>,
) -> Result<()> {
    let sender = pc
        .add_track(Arc::clone(track) as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .map_err(|e| Error::Transport(format!("add_track ({}): {e}", track.id())))?;
    let task_observation =
        observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Task, 1, 1);
    tokio::spawn(async move {
        let _task_observation = task_observation;
        let mut buf = vec![0u8; 1500];
        while sender.read(&mut buf).await.is_ok() {}
    });
    Ok(())
}

/// Drain one remote audio track: every RTP packet carries exactly one
/// Opus frame (RFC 7587 — no fragmentation, no aggregation), so each
/// non-empty payload surfaces directly as [`TransportEvent::AudioSample`].
/// Ends when the track does (peer connection closed).
pub(super) async fn pump_audio_track(
    track: Arc<TrackRemote>,
    tx: ConnectorEventSink,
    _task_observation: Option<ObservationLease>,
    remote_tracks: Arc<SyncMutex<std::collections::HashSet<(bool, u8)>>>,
    track_key: (bool, u8),
    flow: RealtimeFlowPort,
) {
    let lane = lane_of_track_id(&track.id());
    loop {
        let pkt = match track.read_rtp().await {
            Ok((pkt, _)) => pkt,
            Err(_) => break, // track ended with its connection
        };
        if pkt.payload.is_empty() {
            continue; // padding / probe
        }
        if !tx.realtime_delivery.load(Ordering::Acquire) {
            continue;
        }
        let Some(mut fragment) = flow.begin_unit() else {
            continue;
        };
        if !fragment.retain_fragment(pkt.payload.len()) {
            continue;
        }
        let Some(output) = flow.reserve_output(pkt.payload.len()) else {
            continue;
        };
        let sample = AudioSample {
            rtp_timestamp: pkt.header.timestamp,
            lane,
            data: pkt.payload.clone(),
            _reservation: None,
        };
        drop(fragment);
        if !tx.emit_realtime(&flow, TransportEvent::AudioSample(sample), output) {
            break;
        }
    }
    remote_tracks.lock().remove(&track_key);
}

/// Drain one remote video track: depacketize H.264 RTP into access
/// units and surface each as [`TransportEvent::VideoSample`]. Ends
/// when the track does (peer connection closed).
pub(super) async fn pump_video_track(
    track: Arc<TrackRemote>,
    tx: ConnectorEventSink,
    _task_observation: Option<ObservationLease>,
    remote_tracks: Arc<SyncMutex<std::collections::HashSet<(bool, u8)>>>,
    track_key: (bool, u8),
    flow: RealtimeFlowPort,
) {
    let lane = lane_of_track_id(&track.id());
    let mut assembler = H264AuAssembler::guarded(flow.clone());
    loop {
        let pkt = match track.read_rtp().await {
            Ok((pkt, _)) => pkt,
            Err(_) => break, // track ended with its connection
        };
        if !tx.realtime_delivery.load(Ordering::Acquire) {
            continue;
        }
        match assembler.push_guarded(&pkt) {
            Ok(Some(mut sample)) => {
                sample.sample.lane = lane;
                let Some(output) = sample.output.take() else {
                    break;
                };
                if !tx.emit_realtime(&flow, TransportEvent::VideoSample(sample.sample), output) {
                    break;
                }
            }
            Ok(None) => {}
            // A malformed packet (or one straddling a loss the NACK
            // retransmit didn't cover) costs the current unit only —
            // the stream re-syncs on the next timestamp, and the
            // sender's periodic IDR bounds any visible damage.
            Err(e) => trace!("video depacketize: {e}"),
        }
    }
    remote_tracks.lock().remove(&track_key);
}
