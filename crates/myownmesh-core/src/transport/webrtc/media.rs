//! Legacy WebRTC media-lane compatibility over generic real-time owners.

#![allow(
    deprecated,
    reason = "this module is the frozen implementation behind the deprecated legacy media facade"
)]

use super::*;

/// One H.264 access unit off a peer's video track. This compatibility-adapter
/// value contains Annex-B bytes ready for a decoder. `rtp_timestamp` ticks at
/// the 90 kHz video clock, `key` marks an IDR, and `lane` identifies the
/// adapter lane on which it arrived.
#[derive(Debug, Clone)]
#[deprecated(
    since = "0.3.2",
    note = "temporary legacy H.264 compatibility value; use a session-bound codec-neutral flow"
)]
pub struct VideoSample {
    pub rtp_timestamp: u32,
    pub key: bool,
    pub lane: u8,
    pub data: Bytes,
    pub(super) _reservation: Option<RealtimePayloadLease>,
}

/// One Opus frame from the temporary compatibility adapter. Each RTP packet
/// contains one frame, so no assembly is required. `rtp_timestamp` ticks at
/// the 48 kHz Opus clock and `lane` identifies the compatibility lane.
#[derive(Debug, Clone)]
#[deprecated(
    since = "0.3.2",
    note = "temporary legacy Opus compatibility value; use a session-bound codec-neutral flow"
)]
pub struct AudioSample {
    pub rtp_timestamp: u32,
    pub lane: u8,
    pub data: Bytes,
    pub(super) _reservation: Option<RealtimePayloadLease>,
}

/// Historical per-kind lane ceiling for the temporary H.264 and Opus adapter.
/// The generic connector does not read this value or create media tracks.
#[deprecated(
    since = "0.3.2",
    note = "temporary legacy H.264/Opus lane compatibility ceiling"
)]
pub const MEDIA_LANES: usize = 8;

/// Historical adapter behavior pre-provisions lane zero. This constant is
/// available only to tests and the raw transport lab. A production owner must
/// put the value in an explicit [`LegacyWebRtcMediaProfile`].
#[cfg(any(test, feature = "transport-lab"))]
pub(super) const PRE_PROVISIONED_LANES: usize = 1;

/// Historical lane-drain input used only to construct the raw lab's explicit
/// compatibility profile. It is not a queue lifetime, resource authority, or
/// input to the generic real-time owner.
#[cfg(any(test, feature = "transport-lab"))]
pub(super) static LANE_DRAIN_GRACE: std::sync::LazyLock<Duration> =
    std::sync::LazyLock::new(|| {
        let secs = std::env::var("MYOWNMESH_LANE_DRAIN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(90)
            .clamp(1, 600);
        Duration::from_secs(secs)
    });

/// Resolve the historical raw-lab lane ceiling. Generic connector construction
/// does not call this function.
#[allow(
    deprecated,
    reason = "the frozen compatibility resolver uses its legacy ceiling"
)]
pub(super) fn resolve_media_lanes() -> usize {
    match std::env::var("MYOWNMESH_MEDIA_LANES") {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(n) => n.clamp(1, MEDIA_LANES),
            Err(_) => MEDIA_LANES,
        },
        Err(_) => MEDIA_LANES,
    }
}

/// Report the historical raw compatibility lane ceiling.
#[deprecated(
    since = "0.3.2",
    note = "temporary legacy H.264/Opus lane compatibility query"
)]
pub fn resolved_media_lanes() -> usize {
    resolve_media_lanes()
}

#[allow(
    deprecated,
    reason = "legacy track identifiers use the frozen lane ceiling"
)]
pub(super) fn lane_of_track_id(id: &str) -> u8 {
    id.rsplit_once('-')
        .and_then(|(_, n)| n.parse::<u8>().ok())
        .filter(|n| (*n as usize) < MEDIA_LANES)
        .unwrap_or(0)
}

/// Which media pool a lane belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[deprecated(
    since = "0.3.2",
    note = "temporary legacy H.264/Opus lane compatibility type"
)]
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
    /// Closed by the app with its track retained until the explicit legacy
    /// profile permits reaping. Reopening before then revives the same track.
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

impl PeerSession {
    pub(super) fn realtime_enabled(&self) -> bool {
        self.legacy_media_profile.is_some() && self.events_tx.realtime_flows.is_enabled()
    }

    /// Write one encoded H.264 access unit (Annex-B) onto `lane` of this
    /// peer's video pool. `duration` paces the RTP timestamp advance
    /// (1/fps). Before the lane's negotiation completes, webrtc-rs treats
    /// the write as a no-op (the track has no bound sender yet) — callers
    /// can simply start writing once the peer is up. A lane past the pool
    /// (or one a pre-pool peer never negotiated) errors rather than writing
    /// to the wrong stream.
    pub(super) async fn send_video(
        &self,
        lane: u8,
        data: Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        let (track, flow) = self.ensure_owned_lane(LaneKind::Video, lane).await?;
        let _reservation = flow.reserve_output(data.len()).ok_or_else(|| {
            Error::Transport(
                "outbound real-time unit was refused by its owner-selected byte envelope"
                    .to_string(),
            )
        })?;
        track
            .write_sample(&Sample {
                data,
                duration,
                ..Default::default()
            })
            .await
            .map_err(|e| Error::Transport(format!("video write_sample (lane {lane}): {e}")))
    }

    /// Write one encoded Opus frame onto `lane` of this peer's audio pool.
    /// `duration` paces the RTP timestamp advance (the frame length —
    /// 20 ms for the canonical Opus frame). Same pre-negotiation no-op and
    /// out-of-range semantics as [`Self::send_video`].
    pub(super) async fn send_audio(
        &self,
        lane: u8,
        data: Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        let (track, flow) = self.ensure_owned_lane(LaneKind::Audio, lane).await?;
        let _reservation = flow.reserve_output(data.len()).ok_or_else(|| {
            Error::Transport(
                "outbound real-time unit was refused by its owner-selected byte envelope"
                    .to_string(),
            )
        })?;
        track
            .write_sample(&Sample {
                data,
                duration,
                ..Default::default()
            })
            .await
            .map_err(|e| Error::Transport(format!("audio write_sample (lane {lane}): {e}")))
    }

    fn acquire_outbound_realtime_flow(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<(RealtimeFlowPort, bool)> {
        let key = (kind == LaneKind::Video, lane);
        let mut flows = self.outbound_realtime_flows.lock();
        if let Some(flow) = flows.get(&key) {
            return Ok((flow.clone(), false));
        }
        let flow = self
            .events_tx
            .open_outbound_realtime_flow()
            .ok_or_else(|| {
                Error::Transport(
                    "outbound real-time flow was refused by its owner-selected flow envelope"
                        .to_string(),
                )
            })?;
        flows.insert(key, flow.clone());
        Ok((flow, true))
    }

    fn rollback_outbound_realtime_flow(&self, kind: LaneKind, lane: u8, flow: &RealtimeFlowPort) {
        let key = (kind == LaneKind::Video, lane);
        let mut flows = self.outbound_realtime_flows.lock();
        if flows
            .get(&key)
            .is_some_and(|owned| Arc::ptr_eq(&owned.lifetime, &flow.lifetime))
        {
            flows.remove(&key);
        }
    }

    fn lane_has_track(&self, kind: LaneKind, lane: u8) -> bool {
        self.pool(kind)
            .lock()
            .expect("lane pool")
            .get(lane as usize)
            .is_some_and(Option::is_some)
    }

    async fn ensure_owned_lane(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<(Arc<TrackLocalStaticSample>, RealtimeFlowPort)> {
        let _operation = self.lane_operations.lock().await;
        let (flow, newly_owned) = self.acquire_outbound_realtime_flow(kind, lane)?;
        match self.ensure_lane_after_owner(kind, lane).await {
            Ok(track) => Ok((track, flow)),
            Err(error) => {
                if newly_owned && !self.lane_has_track(kind, lane) {
                    self.rollback_outbound_realtime_flow(kind, lane, &flow);
                }
                Err(error)
            }
        }
    }

    fn pool(&self, kind: LaneKind) -> &std::sync::Mutex<Vec<Option<LaneSlot>>> {
        match kind {
            LaneKind::Video => &self.video_tracks,
            LaneKind::Audio => &self.audio_tracks,
        }
    }

    /// The lane's track, opening it on demand: the first write to a
    /// lane that doesn't exist yet creates the track, attaches it, and
    /// flags a renegotiation — writes are no-ops until the new m-line
    /// negotiates, exactly the semantics callers already tolerate at
    /// stream start. A *draining* lane revives in place: the track
    /// never left the SDP, so the write flows immediately and nothing
    /// is renegotiated — this is the settings stop→start fast path. A
    /// lane at or past the device ceiling errors.
    async fn ensure_lane_after_owner(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<Arc<TrackLocalStaticSample>> {
        if lane as usize >= self.max_lanes {
            let k = if kind == LaneKind::Video {
                "video"
            } else {
                "audio"
            };
            return Err(Error::Transport(format!("no {k} lane {lane}")));
        }
        {
            let mut pool = self.pool(kind).lock().expect("lane pool");
            match &pool[lane as usize] {
                Some(LaneSlot::Open(track)) => return Ok(track.clone()),
                Some(LaneSlot::Draining { track, .. }) => {
                    let track = track.clone();
                    pool[lane as usize] = Some(LaneSlot::Open(track.clone()));
                    return Ok(track);
                }
                None => {}
            }
        }
        let track = make_media_track(kind, lane);
        #[cfg(test)]
        if self.fail_next_track_attach.swap(false, Ordering::AcqRel) {
            return Err(Error::Transport(
                "injected native track attachment failure".to_string(),
            ));
        }
        attach_track(&self.pc, &track, self.resource_scope.as_ref()).await?;
        // First writer wins if two racers opened the same lane; the
        // loser's track was attached too, but the slot's track is the
        // one everyone writes — the duplicate is harmless and gone on
        // the next renegotiation sweep. (In practice lane opens are
        // serialized by the engine driver.)
        let stored = {
            let mut pool = self.pool(kind).lock().expect("lane pool");
            match &pool[lane as usize] {
                None => {
                    pool[lane as usize] = Some(LaneSlot::Open(track.clone()));
                    track
                }
                Some(LaneSlot::Open(winner)) => winner.clone(),
                Some(LaneSlot::Draining { track: winner, .. }) => {
                    let winner = winner.clone();
                    pool[lane as usize] = Some(LaneSlot::Open(winner.clone()));
                    winner
                }
            }
        };
        if !self
            .events_tx
            .emit(TransportEvent::RenegotiationNeeded)
            .await
        {
            return Err(Error::Transport(
                "connector event queue overloaded during renegotiation".to_string(),
            ));
        }
        Ok(stored)
    }

    /// Open a lane of `kind`, returning its id. The explicit twin of
    /// the write-time auto-open, for callers that want to reserve a
    /// lane before producing media. Prefers reviving a draining lane
    /// (its track is still negotiated — the open costs zero SDP work)
    /// over claiming a fresh slot (one in-place renegotiation); errors
    /// only when every slot is genuinely open.
    pub(super) async fn open_media_lane(&self, kind: LaneKind) -> Result<u8> {
        let _operation = self.lane_operations.lock().await;
        let target = {
            let pool = self.pool(kind).lock().expect("lane pool");
            pool.iter()
                .position(|slot| matches!(slot, Some(LaneSlot::Draining { .. })))
                .or_else(|| pool.iter().position(|slot| slot.is_none()))
        };
        let Some(lane) = target else {
            return Err(Error::Transport(format!(
                "all {} media lanes are open (device ceiling)",
                self.max_lanes
            )));
        };
        let lane = lane as u8;
        let (flow, newly_owned) = self.acquire_outbound_realtime_flow(kind, lane)?;
        if let Err(error) = self.ensure_lane_after_owner(kind, lane).await {
            if newly_owned && !self.lane_has_track(kind, lane) {
                self.rollback_outbound_realtime_flow(kind, lane, &flow);
            }
            return Err(error);
        }
        Ok(lane)
    }

    /// Mark an open legacy lane as draining. The profile's compatibility grace
    /// determines when the reaper may remove its track. Reopening first revives
    /// that track. Closing a missing or already-draining lane is idempotent.
    pub(super) async fn close_media_lane(&self, kind: LaneKind, lane: u8) -> Result<()> {
        let _operation = self.lane_operations.lock().await;
        if lane as usize >= self.max_lanes {
            return Ok(());
        }
        let mut pool = self.pool(kind).lock().expect("lane pool");
        if let Some(LaneSlot::Open(track)) = &pool[lane as usize] {
            pool[lane as usize] = Some(LaneSlot::Draining {
                track: track.clone(),
                since: Instant::now(),
            });
        }
        Ok(())
    }

    /// Whether any drained lane has outlived `grace` and owes the
    /// connection a teardown. Cheap sync scan — the engine's tick uses
    /// it to decide whether this peer needs a renegotiation pass at
    /// all.
    pub(super) fn has_reapable_lanes(&self) -> bool {
        let Some(profile) = self.legacy_media_profile else {
            return false;
        };
        let grace = profile.lane_drain_grace();
        [LaneKind::Video, LaneKind::Audio].iter().any(|kind| {
            let pinned = match kind {
                LaneKind::Video => profile.preprovisioned_video_lanes(),
                LaneKind::Audio => profile.preprovisioned_audio_lanes(),
            };
            self.pool(*kind)
                .lock()
                .expect("lane pool")
                .iter()
                .enumerate()
                .any(|(idx, slot)| {
                    idx >= pinned
                        && matches!(slot, Some(LaneSlot::Draining { since, .. }) if since.elapsed() >= grace)
                })
        })
    }

    /// Finalize every drain that outlived `grace`: free the slots and
    /// remove their tracks from the connection, so the caller's next
    /// offer drops the m-lines' send side. Returns how many lanes were
    /// reaped. Slots free first, under the lock, then the webrtc-rs
    /// `remove_track` calls run outside it — a concurrent revive can't
    /// resurrect a slot the reaper already committed to tearing down.
    pub(super) async fn reap_drained_lanes(&self) -> usize {
        let Some(profile) = self.legacy_media_profile else {
            return 0;
        };
        let grace = profile.lane_drain_grace();
        let _operation = self.lane_operations.lock().await;
        let mut victims: Vec<(LaneKind, u8, Arc<TrackLocalStaticSample>)> = Vec::new();
        for kind in [LaneKind::Video, LaneKind::Audio] {
            let pinned = match kind {
                LaneKind::Video => profile.preprovisioned_video_lanes(),
                LaneKind::Audio => profile.preprovisioned_audio_lanes(),
            };
            let mut pool = self.pool(kind).lock().expect("lane pool");
            for (idx, slot) in pool.iter_mut().enumerate() {
                // The pre-provisioned lane is pinned: it drains silent but
                // never loses its track, so a re-open always hits the
                // zero-SDP free-revive path instead of a recycled-m-line
                // renegotiation (which doesn't reliably re-`ontrack` on the
                // viewer — the CEC console re-open hang). Only transient
                // lanes (1+) are reaped once past the grace.
                if idx < pinned {
                    continue;
                }
                let due = matches!(slot, Some(LaneSlot::Draining { since, .. }) if since.elapsed() >= grace);
                if due {
                    if let Some(LaneSlot::Draining { track, .. }) = slot.take() {
                        victims.push((kind, idx as u8, track));
                    }
                }
            }
        }
        if victims.is_empty() {
            return 0;
        }
        // A victim absent from `get_senders` is already detached. A failed
        // `remove_track` is the only case that must retain its flow claim.
        let mut failed_reaps = Vec::new();
        for sender in self.pc.get_senders().await {
            let victim = sender.track().await.and_then(|sender_track| {
                victims
                    .iter()
                    .find(|(_, _, track)| sender_track.id() == track.id())
                    .map(|(kind, lane, _)| (*kind, *lane))
            });
            if let Some((kind, lane)) = victim {
                if let Err(e) = self.pc.remove_track(&sender).await {
                    warn!("reap: remove_track failed: {e}");
                    failed_reaps.push((kind, lane));
                }
            }
        }
        let fully_reaped = victims
            .iter()
            .map(|(kind, lane, _)| (*kind, *lane))
            .filter(|victim| !failed_reaps.contains(victim))
            .collect::<Vec<_>>();
        let mut flows = self.outbound_realtime_flows.lock();
        for (kind, lane) in &fully_reaped {
            flows.remove(&(*kind == LaneKind::Video, *lane));
        }
        fully_reaped.len()
    }

    /// How many lanes of `kind` are currently occupied. Draining lanes count
    /// because they retain their negotiated track until reaped.
    #[cfg(test)]
    pub(super) fn open_lane_count(&self, kind: LaneKind) -> usize {
        self.pool(kind)
            .lock()
            .expect("lane pool")
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }
}
