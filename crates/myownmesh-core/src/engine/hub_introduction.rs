//! Demand-only introduction custody. This is not authentication or membership.
//!
//! The engine admits the current promoted carrier before calling this synchronous
//! controller, and executes returned actions outside its locks. No SDP, candidate,
//! application payload, waiter, task, or native connector is retained here.
//! Every map node is admitted before allocation; active records, reverse-route
//! breadcrumbs and replay tombstones share the SAME finite pool.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand_core::RngCore;
use sha2::Digest;

use crate::config::HubIntroductionPolicyConfig;
use crate::protocol::hub_introduction::{
    HubIntroductionBody, HubIntroductionEnvelope, IntroductionChallenge,
};
use crate::resource::{
    LeasedMap, LocalApplicationResourceScope, ResourceClaim, ResourceClaimArithmeticError,
    ResourceClass, ResourceLease,
};
use crate::semantic::{DeviceId, MeshContextId};

use super::peer_registry::{PeerOwnerToken, WeakPeerOwnerToken};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum IntroductionError {
    #[error("introduction policy or coordinates invalid")]
    Invalid,
    #[error("introduction record capacity exhausted")]
    Capacity,
    #[error("introduction resource admission refused")]
    Pressure,
    #[error("introduction expired")]
    Expired,
    #[error("introduction carrier or generation is stale")]
    Stale,
    #[error("introduction replay or duplicate")]
    Replay,
    #[error("introduction phase refused")]
    Phase,
    #[error("an incompatible introduction already owns this target")]
    Glare,
    #[error("no admitted introduction route")]
    NoRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct IntroductionTicket {
    id: [u8; 16],
    generation: u64,
}

impl IntroductionTicket {
    /// Correlation only. Callers must bind the exact native owner before opening
    /// it; a matching string alone never admits a native attempt.
    pub(crate) fn attempt(self) -> String {
        hex::encode(self.id)
    }

    /// Compare the existing canonical correlation without allocating. This does
    /// not compare generations: a reused ID has the same correlation, so callers
    /// must separately fence the full ticket and exact native installation.
    pub(crate) fn matches_attempt(self, attempt: &str) -> bool {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bytes = attempt.as_bytes();
        bytes.len() == 32
            && self.id.iter().enumerate().all(|(index, byte)| {
                bytes[2 * index] == HEX[usize::from(byte >> 4)]
                    && bytes[2 * index + 1] == HEX[usize::from(byte & 15)]
            })
    }
}

/// Synchronous controller facts only, not native-owner authority or evidence
/// of completed cleanup. Both successful promotion and failure become Terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntroductionLifetime {
    Live {
        deadline: Instant,
    },
    Elapsed {
        deadline: Instant,
    },
    /// Takes precedence over Elapsed; the original deadline remains available.
    Terminal {
        deadline: Instant,
    },
    /// No record for this exact ID and generation, including a replaced ticket.
    Missing,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DemandAdmission {
    pub(crate) ticket: IntroductionTicket,
    pub(crate) coalesced: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct IntroductionCoordinates {
    pub(crate) source: [u8; 32],
    pub(crate) destination: [u8; 32],
    pub(crate) introduction_id: [u8; 16],
    pub(crate) challenge: Option<IntroductionChallenge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntroductionAction {
    Accept(IntroductionTicket),
    AcceptReplacing {
        ticket: IntroductionTicket,
        retired: IntroductionTicket,
    },
    BeginOffer(IntroductionTicket),
    Forward {
        ticket: IntroductionTicket,
        reverse: bool,
    },
    Signal(IntroductionTicket),
    Terminal(IntroductionTicket),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Requested,
    Accepted,
    Offered,
    Answered,
    Terminal,
}

#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntroductionPhaseForLab {
    Requested,
    Accepted,
    Offered,
    Answered,
    Terminal,
}

/// Scalar observation only: no ticket authority or retained strong owner.
#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IntroductionRecordForLab {
    pub(crate) introduction_id: [u8; 16],
    /// Current phase. Terminal does not identify the last successful phase.
    pub(crate) phase: IntroductionPhaseForLab,
    pub(crate) sequences: [Option<u64>; 2],
    pub(crate) request_sent: bool,
    pub(crate) challenge_present: bool,
    pub(crate) signal_pending: [bool; 2],
    pub(crate) forward_pending: [bool; 2],
    /// Weak upgrade succeeded; this is NOT a current-registry/authentication check.
    pub(crate) native_upgraded: bool,
    pub(crate) native_worker_present: bool,
    pub(crate) expired: bool,
}

#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IntroductionSnapshotForLab {
    /// Dense Some prefix in introduction-ID order; absence is not success.
    pub(crate) records: [Option<IntroductionRecordForLab>; 16],
    /// True only when a seventeenth matching record was observed.
    pub(crate) truncated: bool,
}

struct IntroductionRecord {
    ticket: IntroductionTicket,
    coordinates: IntroductionCoordinates,
    deadline: Instant,
    retain_until: Instant,
    phase: Phase,
    // Index zero is the Request origin, index one the responder. These are
    // independent signed sequences, not a route-global arrival counter.
    sequences: [Option<u64>; 2],
    candidates: u64,
    signaling_bytes: u64,
    request_sent: bool,
    signal_pending: [Option<(u64, [u8; 32])>; 2],
    request_hash: Option<[u8; 32]>,
    forward_pending: [Option<(u64, [u8; 32])>; 2],
    upstream: Option<PeerOwnerToken>,
    downstream: Option<PeerOwnerToken>,
    // This weak witness is intentionally retained in the tombstone. Queued
    // SignalingOutbound values retain their strong owner, so a producer cannot
    // outlive the interception record and accidentally fall through to fanout.
    native: Option<WeakPeerOwnerToken>,
}

pub(crate) struct HubIntroduction {
    records: LeasedMap<[u8; 16], IntroductionRecord>,
    policy: HubIntroductionPolicyConfig,
    scope: LocalApplicationResourceScope,
    context: MeshContextId,
    local: [u8; 32],
    generation: u64,
    count: u64,
    cursor: Option<[u8; 16]>,
    _root: ResourceLease,
}

impl HubIntroduction {
    /// One-shot bounded-output observation of the exact ordered ORIGINAL pair.
    /// Scans only the existing finite record pool, without refreshing deadlines,
    /// pruning tombstones, moving the maintenance cursor, or admitting work.
    /// `now` is supplied by the caller; even an observation beyond retention
    /// does not remove a record. No hash, challenge bytes, or payload escapes.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn snapshot_for_lab(
        &self,
        source: [u8; 32],
        destination: [u8; 32],
        now: Instant,
    ) -> IntroductionSnapshotForLab {
        let mut snapshot = IntroductionSnapshotForLab {
            records: [None; 16],
            truncated: false,
        };
        let mut cursor = None;
        let mut count = 0;
        while let Some((id, record)) = self.records.successor_after(cursor.as_ref()) {
            cursor = Some(*id);
            if record.coordinates.source != source || record.coordinates.destination != destination
            {
                continue;
            }
            if count == snapshot.records.len() {
                snapshot.truncated = true;
                break;
            }
            let (native_upgraded, native_worker_present) = {
                let native = record.native.as_ref().and_then(WeakPeerOwnerToken::upgrade);
                (
                    native.is_some(),
                    native
                        .as_ref()
                        .is_some_and(|owner| owner.worker().is_some()),
                )
            }; // Any temporary strong witness is dropped before storing the scalar row.
            snapshot.records[count] = Some(IntroductionRecordForLab {
                introduction_id: *id,
                phase: match record.phase {
                    Phase::Requested => IntroductionPhaseForLab::Requested,
                    Phase::Accepted => IntroductionPhaseForLab::Accepted,
                    Phase::Offered => IntroductionPhaseForLab::Offered,
                    Phase::Answered => IntroductionPhaseForLab::Answered,
                    Phase::Terminal => IntroductionPhaseForLab::Terminal,
                },
                sequences: record.sequences,
                request_sent: record.request_sent,
                challenge_present: record.coordinates.challenge.is_some(),
                signal_pending: record.signal_pending.map(|pending| pending.is_some()),
                forward_pending: record.forward_pending.map(|pending| pending.is_some()),
                native_upgraded,
                native_worker_present,
                expired: now >= record.deadline,
            });
            count += 1;
        }
        snapshot
    }

    /// Raw claims; each acquire additionally owns its independent provider
    /// reservation record. The existing local-application scope is reused.
    pub(crate) fn root_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        ResourceClaim::try_from_entries([(
            ResourceClass::AccountedMemoryBytes,
            std::mem::size_of::<Self>() as u64,
        )])
    }

    pub(crate) fn entry_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        LeasedMap::<[u8; 16], IntroductionRecord>::entry_claim()
    }

    /// Additional temporary canonical verification/encoding work, separate
    /// from retained decoded input and from map-node custody. The existing
    /// conservative JSON-work convention covers adversarial escaping/shape.
    pub(crate) fn frame_work_claim(
        encoded_bytes: usize,
    ) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        crate::application_gateway::structural_json_claim(encoded_bytes)
    }

    fn admit_frame_work(
        &self,
        frame: &HubIntroductionEnvelope,
    ) -> Result<ResourceLease, IntroductionError> {
        let bytes = frame
            .complete_encoded_len()
            .ok_or(IntroductionError::Invalid)?;
        if bytes > crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_WIRE_BYTES {
            return Err(IntroductionError::Invalid);
        }
        self.scope
            .acquire(Self::frame_work_claim(bytes).map_err(|_| IntroductionError::Invalid)?)
            .map_err(|_| IntroductionError::Pressure)
    }

    pub(crate) fn new(
        policy: HubIntroductionPolicyConfig,
        scope: LocalApplicationResourceScope,
        context: MeshContextId,
        local: &DeviceId,
    ) -> Result<Self, IntroductionError> {
        let policy = policy.checked().map_err(|_| IntroductionError::Invalid)?;
        let root = scope
            .acquire(Self::root_claim().map_err(|_| IntroductionError::Invalid)?)
            .map_err(|_| IntroductionError::Pressure)?;
        Ok(Self {
            records: LeasedMap::new(),
            policy,
            scope,
            context,
            local: local.as_bytes(),
            generation: 0,
            count: 0,
            cursor: None,
            _root: root,
        })
    }

    fn target_record(&self, target: [u8; 32]) -> Option<&IntroductionRecord> {
        let mut key = None;
        self.records.for_each(|id, record| {
            if record.phase != Phase::Terminal
                && ((record.coordinates.source == self.local
                    && record.coordinates.destination == target)
                    || (record.coordinates.destination == self.local
                        && record.coordinates.source == target))
            {
                key = Some(*id);
            }
        });
        self.records.get(&key?)
    }

    fn insert(
        &mut self,
        coordinates: IntroductionCoordinates,
        phase: Phase,
        upstream: Option<&PeerOwnerToken>,
        downstream: Option<&PeerOwnerToken>,
        now: Instant,
    ) -> Result<IntroductionTicket, IntroductionError> {
        if self.count >= self.policy.max_records {
            return Err(IntroductionError::Capacity);
        }
        if self.records.get(&coordinates.introduction_id).is_some() {
            return Err(IntroductionError::Replay);
        }
        let deadline = now
            .checked_add(Duration::from_millis(self.policy.attempt_timeout_ms))
            .ok_or(IntroductionError::Invalid)?;
        let retain_until = deadline
            .checked_add(Duration::from_millis(self.policy.terminal_retention_ms))
            .ok_or(IntroductionError::Invalid)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(IntroductionError::Capacity)?;
        let lease = self
            .scope
            .acquire(Self::entry_claim().map_err(|_| IntroductionError::Invalid)?)
            .map_err(|_| IntroductionError::Pressure)?;
        let ticket = IntroductionTicket {
            id: coordinates.introduction_id,
            generation,
        };
        let record = IntroductionRecord {
            ticket,
            coordinates,
            deadline,
            retain_until,
            phase,
            sequences: [Some(0), None],
            candidates: 0,
            signaling_bytes: 0,
            request_sent: upstream.is_some(),
            signal_pending: [None, None],
            request_hash: None,
            forward_pending: [None, None],
            upstream: upstream.cloned(),
            downstream: downstream.cloned(),
            native: None,
        };
        self.records
            .insert(ticket.id, record, lease)
            .map_err(|_| IntroductionError::Replay)?;
        self.generation = generation;
        self.count += 1;
        Ok(ticket)
    }

    /// Only explicit application/connect demand may call this; directory hints
    /// must not. The existing connect waiter registry owns all coalesced callers.
    pub(crate) fn begin_demand(
        &mut self,
        target: &DeviceId,
        carrier: &PeerOwnerToken,
        now: Instant,
    ) -> Result<DemandAdmission, IntroductionError> {
        if target.as_bytes() == self.local || carrier.worker().is_none() {
            return Err(IntroductionError::Invalid);
        }
        if let Some(record) = self.target_record(target.as_bytes()) {
            if now >= record.deadline {
                return Err(IntroductionError::Expired);
            }
            return Ok(DemandAdmission {
                ticket: record.ticket,
                coalesced: true,
            });
        }
        let mut id = [0; 16];
        rand_core::OsRng.fill_bytes(&mut id);
        if id == [0; 16] {
            return Err(IntroductionError::Invalid);
        }
        let coordinates = IntroductionCoordinates {
            source: self.local,
            destination: target.as_bytes(),
            introduction_id: id,
            challenge: None,
        };
        let ticket = self.insert(coordinates, Phase::Requested, None, Some(carrier), now)?;
        Ok(DemandAdmission {
            ticket,
            coalesced: false,
        })
    }

    pub(crate) fn coordinates(
        &self,
        ticket: IntroductionTicket,
    ) -> Option<IntroductionCoordinates> {
        self.record(ticket).map(|record| record.coordinates)
    }

    fn record(&self, ticket: IntroductionTicket) -> Option<&IntroductionRecord> {
        self.records
            .get(&ticket.id)
            .filter(|record| record.ticket == ticket)
    }

    /// Historical binding only, without upgrading or retaining the weak owner.
    /// True survives owner loss and Terminal; None is missing/replaced, not proof
    /// of clean settlement. This grants no native or current-owner authority.
    pub(crate) fn native_was_bound(&self, ticket: IntroductionTicket) -> Option<bool> {
        self.record(ticket).map(|record| record.native.is_some())
    }

    pub(crate) fn is_current(&self, ticket: IntroductionTicket, now: Instant) -> bool {
        self.remaining(ticket, now).is_some()
    }

    /// Read the original admission deadline without expiring, pruning, renewing
    /// or retaining any owner. Terminal never identifies why negotiation ended.
    pub(crate) fn lifetime(
        &self,
        ticket: IntroductionTicket,
        now: Instant,
    ) -> IntroductionLifetime {
        let Some(record) = self.record(ticket) else {
            return IntroductionLifetime::Missing;
        };
        let deadline = record.deadline;
        if record.phase == Phase::Terminal {
            IntroductionLifetime::Terminal { deadline }
        } else if now >= deadline {
            IntroductionLifetime::Elapsed { deadline }
        } else {
            IntroductionLifetime::Live { deadline }
        }
    }

    /// Time left on the original admitted demand, never a refreshed timeout.
    /// Zero remaining time, terminal custody and a replaced ticket cannot
    /// authorize another native operation.
    pub(crate) fn remaining(&self, ticket: IntroductionTicket, now: Instant) -> Option<Duration> {
        let record = self.record(ticket)?;
        if record.phase == Phase::Terminal {
            return None;
        }
        record
            .deadline
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
    }

    pub(crate) fn route(
        &self,
        ticket: IntroductionTicket,
        reverse: bool,
    ) -> Option<PeerOwnerToken> {
        let record = self.record(ticket)?;
        if reverse {
            record.upstream.clone()
        } else {
            record.downstream.clone()
        }
    }

    /// Must run after exact installation but BEFORE native open/SDP emission.
    /// A second installation cannot take over an admitted introduction.
    pub(crate) fn bind_native_owner(
        &mut self,
        ticket: IntroductionTicket,
        owner: &PeerOwnerToken,
    ) -> Result<(), IntroductionError> {
        let local = self.local;
        let record = self
            .records
            .get_mut(&ticket.id)
            .filter(|r| r.ticket == ticket)
            .ok_or(IntroductionError::Stale)?;
        if Instant::now() >= record.deadline {
            return Err(IntroductionError::Expired);
        }
        if record.phase == Phase::Terminal
            || record.phase == Phase::Requested
            || record.coordinates.challenge.is_none()
        {
            return Err(IntroductionError::Phase);
        }
        let remote = if record.coordinates.source == local {
            record.coordinates.destination
        } else {
            record.coordinates.source
        };
        if canonical_key(owner.device_id()) != Some(remote) {
            return Err(IntroductionError::Invalid);
        }
        if let Some(prior) = &record.native {
            if !prior
                .upgrade()
                .is_some_and(|prior| same_native_owner(&prior, owner))
            {
                return Err(IntroductionError::Stale);
            }
        } else {
            record.native = Some(owner.downgrade());
        }
        Ok(())
    }

    /// Includes expired and terminal records. Never classify by hex spelling:
    /// ordinary attempts can have the same representation without intro custody.
    pub(crate) fn ticket_for_attempt(
        &self,
        target: &str,
        attempt: &str,
    ) -> Option<IntroductionTicket> {
        let mut id = [0; 16];
        if attempt.len() != 32 || hex::decode_to_slice(attempt, &mut id).is_err() {
            return None;
        }
        let record = self.records.get(&id)?;
        let target = canonical_key(target)?;
        let remote = if record.coordinates.source == self.local {
            record.coordinates.destination
        } else if record.coordinates.destination == self.local {
            record.coordinates.source
        } else {
            return None;
        };
        (remote == target).then_some(record.ticket)
    }

    pub(crate) fn next_sequence(&self, ticket: IntroductionTicket) -> Option<u64> {
        let record = self.record(ticket)?;
        let direction = usize::from(record.coordinates.source != self.local);
        if direction == 0 && !record.request_sent && record.phase == Phase::Requested {
            return Some(0);
        }
        record.sequences[direction].map_or(Some(0), |seq| seq.checked_add(1))
    }

    /// `carrier` is the CURRENT promoted dispatch owner, not a lookup by a
    /// peer-supplied ID. `next_hop` is captured under the same engine admission.
    pub(crate) fn receive(
        &mut self,
        carrier: &PeerOwnerToken,
        frame: &HubIntroductionEnvelope,
        next_hop: Option<&PeerOwnerToken>,
        now: Instant,
    ) -> Result<IntroductionAction, IntroductionError> {
        if carrier.worker().is_none() {
            return Err(IntroductionError::Stale);
        }
        let _verification = self.admit_frame_work(frame)?;
        if canonical_key(carrier.device_id()) != Some(frame.current_carrier().as_bytes()) {
            return Err(IntroductionError::Stale);
        }
        frame
            .verify_for_previous_hop(frame.current_carrier(), self.context)
            .map_err(|_| IntroductionError::Invalid)?;
        if matches!(frame.body(), HubIntroductionBody::Request {}) {
            if self.records.get(&frame.introduction_id()).is_some() {
                return Err(IntroductionError::Replay);
            }
            let destination = frame.destination().as_bytes();
            let mut retired = None;
            if destination == self.local {
                if let Some(prior) = self.target_record(frame.source().as_bytes()) {
                    // Both Requests precede native allocation. Resolve crossed
                    // requests by full endpoint key; once accepted, an existing
                    // native attempt is never replaced by a competing request.
                    retired = Some(glare_replacement(
                        prior,
                        self.local,
                        frame.source().as_bytes(),
                    )?);
                }
            } else if next_hop.is_none() || frame.remaining_ttl() == 0 {
                return Err(IntroductionError::NoRoute);
            }
            if next_hop.is_some_and(|next| next.worker().is_none() || same_owner(next, carrier)) {
                return Err(IntroductionError::NoRoute);
            }
            let coordinates = IntroductionCoordinates {
                source: frame.source().as_bytes(),
                destination,
                introduction_id: frame.introduction_id(),
                challenge: None,
            };
            let request_hash = frame
                .request_digest()
                .map_err(|_| IntroductionError::Invalid)?;
            let bytes = wire_length(frame)?;
            if bytes > self.policy.max_signaling_bytes {
                return Err(IntroductionError::Capacity);
            }
            let ticket =
                self.insert(coordinates, Phase::Requested, Some(carrier), next_hop, now)?;
            let record = self.records.get_mut(&ticket.id).expect("just admitted");
            record.signaling_bytes = bytes;
            record.request_hash = Some(request_hash);
            if destination == self.local {
                // Only a funded record may retain a responder challenge. No
                // native/SDP/candidate work exists at this boundary.
                let mut responder_challenge = [0; 32];
                rand_core::OsRng.fill_bytes(&mut responder_challenge);
                if responder_challenge == [0; 32] {
                    record.phase = Phase::Terminal;
                    return Err(IntroductionError::Invalid);
                }
                record.coordinates.challenge = Some(IntroductionChallenge {
                    request_hash,
                    responder_challenge,
                });
            } else {
                record.forward_pending[0] = Some((frame.sequence(), immutable_digest(frame)?));
            }
            if let Some(retired) = retired {
                self.cancel(retired);
                return Ok(IntroductionAction::AcceptReplacing { ticket, retired });
            }
            return Ok(if destination == self.local {
                IntroductionAction::Accept(ticket)
            } else {
                IntroductionAction::Forward {
                    ticket,
                    reverse: false,
                }
            });
        }
        let record = self
            .records
            .get_mut(&frame.introduction_id())
            .ok_or(IntroductionError::Stale)?;
        let reverse = direction(record, frame)?;
        let expected = if reverse {
            &record.downstream
        } else {
            &record.upstream
        };
        if !expected
            .as_ref()
            .is_some_and(|expected| same_owner(expected, carrier))
        {
            return Err(IntroductionError::Stale);
        }
        advance(record, frame, now, self.policy)?;
        let ticket = record.ticket;
        if frame.destination().as_bytes() != self.local {
            let pending = &mut record.forward_pending[usize::from(reverse)];
            if pending.is_some() {
                record.phase = Phase::Terminal;
                return Err(IntroductionError::Capacity);
            }
            *pending = Some((frame.sequence(), immutable_digest(frame)?));
            return Ok(IntroductionAction::Forward { ticket, reverse });
        }
        if record.phase == Phase::Terminal {
            return Ok(IntroductionAction::Terminal(ticket));
        }
        Ok(match frame.body() {
            HubIntroductionBody::Accept {} => IntroductionAction::BeginOffer(ticket),
            HubIntroductionBody::Offer { .. }
            | HubIntroductionBody::Answer { .. }
            | HubIntroductionBody::Candidate { .. } => {
                let index = usize::from(reverse);
                if record.signal_pending[index].is_some() {
                    record.phase = Phase::Terminal;
                    return Err(IntroductionError::Capacity);
                }
                record.signal_pending[index] = Some((frame.sequence(), wire_digest(frame)?));
                IntroductionAction::Signal(ticket)
            }
            _ => return Err(IntroductionError::Phase),
        })
    }

    /// Reserve sequence/traffic exactly once before the engine sends. An error
    /// or unknown write outcome is terminal, never a fresh-sequence retry.
    pub(crate) fn observe_outbound(
        &mut self,
        ticket: IntroductionTicket,
        native: Option<&PeerOwnerToken>,
        frame: &HubIntroductionEnvelope,
        now: Instant,
    ) -> Result<(), IntroductionError> {
        if frame.source().as_bytes() != self.local || frame.context_id() != self.context {
            return Err(IntroductionError::Invalid);
        }
        let _verification = self.admit_frame_work(frame)?;
        frame
            .verify_for_previous_hop(frame.source(), self.context)
            .map_err(|_| IntroductionError::Invalid)?;
        let record = self
            .records
            .get_mut(&ticket.id)
            .filter(|r| r.ticket == ticket)
            .ok_or(IntroductionError::Stale)?;
        if matches!(
            frame.body(),
            HubIntroductionBody::Offer { .. }
                | HubIntroductionBody::Answer { .. }
                | HubIntroductionBody::Candidate { .. }
        ) {
            let expected = record
                .native
                .as_ref()
                .and_then(WeakPeerOwnerToken::upgrade)
                .ok_or(IntroductionError::Stale)?;
            if !native.is_some_and(|native| same_native_owner(&expected, native)) {
                return Err(IntroductionError::Stale);
            }
        }
        if matches!(frame.body(), HubIntroductionBody::Request {}) {
            if record.request_sent
                || record.phase != Phase::Requested
                || now >= record.deadline
                || frame.sequence() != 0
                || frame.introduction_id() != ticket.id
                || frame.challenge().is_some()
                || frame.destination().as_bytes() != record.coordinates.destination
            {
                return Err(IntroductionError::Phase);
            }
            let bytes = wire_length(frame)?;
            if bytes > self.policy.max_signaling_bytes {
                return Err(IntroductionError::Capacity);
            }
            record.request_sent = true;
            record.request_hash = Some(
                frame
                    .request_digest()
                    .map_err(|_| IntroductionError::Invalid)?,
            );
            record.signaling_bytes = bytes;
            return Ok(());
        }
        advance(record, frame, now, self.policy)
    }

    /// Consume the exact accepted forwarding action after appending the local
    /// signed hop. Counts BOTH received and transmitted complete wire bytes;
    /// a replay cannot become a second forwarding write or renew a deadline.
    pub(crate) fn observe_forward(
        &mut self,
        ticket: IntroductionTicket,
        frame: &HubIntroductionEnvelope,
        now: Instant,
    ) -> Result<(), IntroductionError> {
        if frame.context_id() != self.context || frame.current_carrier().as_bytes() != self.local {
            return Err(IntroductionError::Invalid);
        }
        let _verification = self.admit_frame_work(frame)?;
        frame
            .verify_for_previous_hop(frame.current_carrier(), self.context)
            .map_err(|_| IntroductionError::Invalid)?;
        let record = self
            .records
            .get_mut(&ticket.id)
            .filter(|r| r.ticket == ticket)
            .ok_or(IntroductionError::Stale)?;
        if now >= record.deadline {
            return Err(IntroductionError::Expired);
        }
        let reverse = direction(record, frame)?;
        let pending = &mut record.forward_pending[usize::from(reverse)];
        if *pending != Some((frame.sequence(), immutable_digest(frame)?)) {
            return Err(IntroductionError::Replay);
        }
        *pending = None;
        let total = record
            .signaling_bytes
            .checked_add(wire_length(frame)?)
            .ok_or(IntroductionError::Capacity)?;
        if total > self.policy.max_signaling_bytes {
            record.phase = Phase::Terminal;
            return Err(IntroductionError::Capacity);
        }
        record.signaling_bytes = total;
        Ok(())
    }

    /// Single-consumer transfer to SignalingRuntime. It cannot mint a signal
    /// from a ticket alone or consume a second frame with the same sequence.
    pub(crate) fn take_signal(
        &mut self,
        ticket: IntroductionTicket,
        carrier: &PeerOwnerToken,
        frame: &HubIntroductionEnvelope,
        now: Instant,
    ) -> Result<(), IntroductionError> {
        let record = self
            .records
            .get_mut(&ticket.id)
            .filter(|r| r.ticket == ticket)
            .ok_or(IntroductionError::Stale)?;
        if now >= record.deadline || record.phase == Phase::Terminal {
            return Err(IntroductionError::Expired);
        }
        let reverse = direction(record, frame)?;
        if frame.challenge().is_none() || frame.challenge() != record.coordinates.challenge {
            return Err(IntroductionError::Invalid);
        }
        let expected = if reverse {
            &record.downstream
        } else {
            &record.upstream
        };
        if !expected
            .as_ref()
            .is_some_and(|expected| same_owner(expected, carrier))
        {
            return Err(IntroductionError::Stale);
        }
        let pending = &mut record.signal_pending[usize::from(reverse)];
        if *pending != Some((frame.sequence(), wire_digest(frame)?)) {
            return Err(IntroductionError::Replay);
        }
        *pending = None;
        Ok(())
    }

    pub(crate) fn cancel(&mut self, ticket: IntroductionTicket) -> bool {
        let Some(record) = self
            .records
            .get_mut(&ticket.id)
            .filter(|r| r.ticket == ticket)
        else {
            return false;
        };
        record.phase = Phase::Terminal;
        true
    }
    pub(crate) fn failed(&mut self, ticket: IntroductionTicket) -> bool {
        self.cancel(ticket)
    }
    pub(crate) fn promoted(&mut self, ticket: IntroductionTicket) -> bool {
        self.cancel(ticket)
    }

    /// One bounded cursor step per call. The engine caps calls by the configured
    /// maintenance quantum; no collecting/draining vector or background task.
    pub(crate) fn poll_expired(&mut self, now: Instant) -> Option<IntroductionTicket> {
        let next = self
            .records
            .successor_after(self.cursor.as_ref())
            .map(|(id, _)| *id);
        let Some(id) = next else {
            self.cursor = None;
            return None;
        };
        self.cursor = Some(id);
        let record = self.records.get_mut(&id)?;
        let ticket = record.ticket;
        let expired = now >= record.deadline;
        let newly_terminal = expired && record.phase != Phase::Terminal;
        if expired {
            record.phase = Phase::Terminal;
        }
        if now >= record.retain_until
            && record
                .native
                .as_ref()
                .is_none_or(|owner| owner.upgrade().is_none())
        {
            self.records.remove(&id);
            self.count -= 1;
        }
        newly_terminal.then_some(ticket)
    }

    /// Engine shutdown first stops/joins signaling producers; only then may
    /// this controller and its sticky interception tombstones be destroyed.
    pub(crate) fn shutdown(&mut self) {
        while self.records.pop_first_entry().is_some() {}
        self.count = 0;
        self.cursor = None;
    }
}

fn same_owner(left: &PeerOwnerToken, right: &PeerOwnerToken) -> bool {
    Arc::ptr_eq(left.connection(), right.connection()) && left.same_exact_owner(right)
}

fn glare_replacement(
    prior: &IntroductionRecord,
    local: [u8; 32],
    remote: [u8; 32],
) -> Result<IntroductionTicket, IntroductionError> {
    if prior.coordinates.source == local
        && prior.phase == Phase::Requested
        && remote < local
        && prior.native.is_none()
    {
        Ok(prior.ticket)
    } else {
        Err(IntroductionError::Glare)
    }
}

fn same_native_owner(bound: &PeerOwnerToken, emitted: &PeerOwnerToken) -> bool {
    if !Arc::ptr_eq(bound.connection(), emitted.connection()) {
        return false;
    }
    match (bound.worker(), emitted.worker()) {
        // Refine only the captured installation. Stamping clones existing Arcs;
        // it neither looks up a successor nor allocates a binding coordinate.
        (None, Some(worker)) => bound
            .for_worker(Arc::clone(worker))
            .same_exact_owner(emitted),
        _ => bound.same_exact_owner(emitted),
    }
}

// Allocation-free comparison against fixed retained endpoint keys. No new
// interned DeviceId/String is constructed before the operation's admission.
fn canonical_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 52 {
        return None;
    }
    let mut encoded = [0; 52];
    for (out, byte) in encoded.iter_mut().zip(value.bytes()) {
        if !(byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)) {
            return None;
        }
        *out = byte.to_ascii_uppercase();
    }
    let mut key = [0; 32];
    if data_encoding::BASE32_NOPAD
        .decode_mut(&encoded, &mut key)
        .ok()?
        != 32
    {
        return None;
    }
    Some(key)
}

fn direction(
    record: &IntroductionRecord,
    frame: &HubIntroductionEnvelope,
) -> Result<bool, IntroductionError> {
    if record.coordinates.introduction_id != frame.introduction_id() {
        return Err(IntroductionError::Invalid);
    }
    if frame.source().as_bytes() == record.coordinates.source
        && frame.destination().as_bytes() == record.coordinates.destination
    {
        Ok(false)
    } else if frame.source().as_bytes() == record.coordinates.destination
        && frame.destination().as_bytes() == record.coordinates.source
    {
        Ok(true)
    } else {
        Err(IntroductionError::Invalid)
    }
}

fn advance(
    record: &mut IntroductionRecord,
    frame: &HubIntroductionEnvelope,
    now: Instant,
    policy: HubIntroductionPolicyConfig,
) -> Result<(), IntroductionError> {
    if now >= record.deadline {
        return Err(IntroductionError::Expired);
    }
    if record.phase == Phase::Terminal {
        return Err(IntroductionError::Stale);
    }
    let reverse = direction(record, frame)?;
    let index = usize::from(reverse);
    if record.sequences[index].is_some_and(|previous| frame.sequence() <= previous) {
        return Err(IntroductionError::Replay);
    }
    let challenge = frame.challenge();
    if matches!(frame.body(), HubIntroductionBody::Accept {}) {
        let proposed = challenge.ok_or(IntroductionError::Invalid)?;
        if Some(proposed.request_hash) != record.request_hash
            || proposed.responder_challenge == [0; 32]
            || record
                .coordinates
                .challenge
                .is_some_and(|current| current != proposed)
        {
            return Err(IntroductionError::Invalid);
        }
    } else if !(matches!(frame.body(), HubIntroductionBody::Refuse { .. })
        && reverse
        && record.phase == Phase::Requested
        && record.native.is_none()
        && record.coordinates.challenge.is_none()
        && challenge.is_none())
        && (challenge.is_none() || challenge != record.coordinates.challenge)
    {
        return Err(IntroductionError::Invalid);
    }
    let phase = match frame.body() {
        HubIntroductionBody::Accept {} if reverse && record.phase == Phase::Requested => {
            Phase::Accepted
        }
        HubIntroductionBody::Offer { .. } if !reverse && record.phase == Phase::Accepted => {
            Phase::Offered
        }
        HubIntroductionBody::Answer { .. } if reverse && record.phase == Phase::Offered => {
            Phase::Answered
        }
        HubIntroductionBody::Candidate { .. }
            if matches!(record.phase, Phase::Offered | Phase::Answered) =>
        {
            record.phase
        }
        HubIntroductionBody::Cancel {} | HubIntroductionBody::Refuse { .. } => Phase::Terminal,
        _ => return Err(IntroductionError::Phase),
    };
    let total = record
        .signaling_bytes
        .checked_add(wire_length(frame)?)
        .ok_or(IntroductionError::Capacity)?;
    // Charge attempted candidates even when their traffic cap refuses them.
    if matches!(frame.body(), HubIntroductionBody::Candidate { .. }) {
        record.candidates = record
            .candidates
            .checked_add(1)
            .ok_or(IntroductionError::Capacity)?;
        if record.candidates > policy.max_candidates_per_attempt {
            record.phase = Phase::Terminal;
            return Err(IntroductionError::Capacity);
        }
    }
    if total > policy.max_signaling_bytes {
        record.phase = Phase::Terminal;
        return Err(IntroductionError::Capacity);
    }
    record.signaling_bytes = total;
    record.sequences[index] = Some(frame.sequence());
    if matches!(frame.body(), HubIntroductionBody::Accept {}) {
        record.coordinates.challenge = challenge;
    }
    record.phase = phase;
    Ok(())
}

struct WireDigest(sha2::Sha256);
impl std::io::Write for WireDigest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn wire_digest(frame: &HubIntroductionEnvelope) -> Result<[u8; 32], IntroductionError> {
    let mut hash = WireDigest(sha2::Sha256::new());
    serde_json::to_writer(&mut hash, frame).map_err(|_| IntroductionError::Invalid)?;
    Ok(hash.0.finalize().into())
}
fn immutable_digest(frame: &HubIntroductionEnvelope) -> Result<[u8; 32], IntroductionError> {
    let mut hash = WireDigest(sha2::Sha256::new());
    serde_json::to_writer(
        &mut hash,
        &(
            frame.context_id(),
            frame.source(),
            frame.destination(),
            frame.introduction_id(),
            frame.sequence(),
            frame.challenge(),
            frame.initial_hop_budget(),
            frame.body(),
        ),
    )
    .map_err(|_| IntroductionError::Invalid)?;
    Ok(hash.0.finalize().into())
}
fn wire_length(frame: &HubIntroductionEnvelope) -> Result<u64, IntroductionError> {
    frame
        .complete_encoded_len()
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(IntroductionError::Invalid)
}

#[cfg(all(test, feature = "transport-lab"))]
mod tests {
    use super::*;
    use crate::resource::{FiniteResourceProvider, ResourceProviderPort};

    fn policy(records: u64) -> HubIntroductionPolicyConfig {
        HubIntroductionPolicyConfig {
            max_records: records,
            max_waiters_per_target: 1,
            max_signaling_bytes: 16_384,
            max_candidates_per_attempt: 2,
            attempt_timeout_ms: 100,
            terminal_retention_ms: 10,
            max_transient_links: 1,
            idle_timeout_ms: 100,
            max_maintenance_per_tick: 1,
        }
    }

    fn device(value: u8) -> DeviceId {
        let key = ed25519_dalek::SigningKey::from_bytes(&[value; 32]);
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap()
    }

    fn fixture(records: u64, funded_entries: u64) -> (HubIntroduction, FiniteResourceProvider) {
        fixture_with_work(records, funded_entries, 0)
    }

    fn fixture_with_work(
        records: u64,
        funded_entries: u64,
        work_bytes: usize,
    ) -> (HubIntroduction, FiniteResourceProvider) {
        let root = FiniteResourceProvider::reservation_planning_charge(
            HubIntroduction::root_claim().unwrap(),
        )
        .unwrap();
        let entries = FiniteResourceProvider::reservation_planning_charge(
            HubIntroduction::entry_claim().unwrap(),
        )
        .unwrap()
        .checked_scale(funded_entries)
        .unwrap();
        let mut grant = FiniteResourceProvider::scope_planning_charge()
            .checked_scale(2)
            .unwrap()
            .checked_add(root)
            .unwrap()
            .checked_add(entries)
            .unwrap();
        if work_bytes != 0 {
            grant = grant
                .checked_add(
                    FiniteResourceProvider::reservation_planning_charge(
                        HubIntroduction::frame_work_claim(work_bytes).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
        (
            HubIntroduction::new(
                policy(records),
                scope,
                MeshContextId::from_bytes([7; 32]),
                &device(1),
            )
            .unwrap(),
            provider,
        )
    }

    fn coordinates(id: u8) -> IntroductionCoordinates {
        IntroductionCoordinates {
            source: device(1).as_bytes(),
            destination: device(2).as_bytes(),
            introduction_id: [id; 16],
            challenge: None,
        }
    }

    fn insert(controller: &mut HubIntroduction, id: u8, now: Instant) -> IntroductionTicket {
        let ticket = controller
            .insert(coordinates(id), Phase::Requested, None, None, now)
            .unwrap();
        controller.records.get_mut(&ticket.id).unwrap().request_hash =
            Some(request(id).request_digest().unwrap());
        ticket
    }

    fn request(id: u8) -> HubIntroductionEnvelope {
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        HubIntroductionEnvelope::new(
            MeshContextId::from_bytes([7; 32]),
            device(1),
            device(2),
            [id; 16],
            0,
            None,
            4,
            HubIntroductionBody::Request {},
            &key,
        )
        .unwrap()
    }

    fn frame(
        id: u8,
        reverse: bool,
        sequence: u64,
        body: HubIntroductionBody,
    ) -> HubIntroductionEnvelope {
        let key = ed25519_dalek::SigningKey::from_bytes(&[if reverse { 2 } else { 1 }; 32]);
        HubIntroductionEnvelope::new(
            MeshContextId::from_bytes([7; 32]),
            device(if reverse { 2 } else { 1 }),
            device(if reverse { 1 } else { 2 }),
            [id; 16],
            sequence,
            Some(IntroductionChallenge {
                request_hash: request(id).request_digest().unwrap(),
                responder_challenge: [9; 32],
            }),
            4,
            body,
            &key,
        )
        .unwrap()
    }

    #[test]
    fn introduction_snapshot_filters_ordered_pair_and_reports_matching_overflow() {
        let (mut controller, provider) = fixture(19, 19);
        let now = Instant::now();
        let source = device(1).as_bytes();
        let destination = device(2).as_bytes();
        for id in 1..=16 {
            insert(&mut controller, id, now);
        }
        // Private observation fixtures, not admitted wire/native transactions.
        let mut foreign = coordinates(18);
        foreign.source = device(3).as_bytes();
        controller
            .insert(foreign, Phase::Requested, None, None, now)
            .unwrap();
        let mut reversed = coordinates(19);
        reversed.source = destination;
        reversed.destination = source;
        controller
            .insert(reversed, Phase::Requested, None, None, now)
            .unwrap();

        let exact = controller.snapshot_for_lab(source, destination, now);
        assert!(
            !exact.truncated,
            "nonmatching rows beyond the cap are not overflow"
        );
        for (index, row) in exact.records.iter().enumerate() {
            assert_eq!(row.unwrap().introduction_id, [(index + 1) as u8; 16]);
        }
        let reverse = controller.snapshot_for_lab(destination, source, now);
        assert_eq!(reverse.records[0].unwrap().introduction_id, [19; 16]);
        assert!(reverse.records[1..].iter().all(Option::is_none));
        assert!(!reverse.truncated);
        let absent = controller.snapshot_for_lab(source, device(3).as_bytes(), now);
        assert_eq!(absent.records, [None; 16]);
        assert!(!absent.truncated);

        insert(&mut controller, 17, now);
        let retained = provider.in_use();
        let reservations = provider.active_reservations();
        let scopes = provider.active_scopes();
        let overflow = controller.snapshot_for_lab(source, destination, now);
        assert!(overflow.truncated, "the seventeenth MATCH is explicit");
        assert_eq!(overflow.records, exact.records);
        assert_eq!(controller.count, 19);
        assert_eq!(provider.in_use(), retained);
        assert_eq!(provider.active_reservations(), reservations);
        assert_eq!(provider.active_scopes(), scopes);
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
    }

    #[test]
    fn introduction_snapshot_preserves_records_deadlines_and_weak_custody() {
        let (mut controller, provider) = fixture(5, 5);
        let now = Instant::now();
        let source = device(1).as_bytes();
        let destination = device(2).as_bytes();
        let phases = [
            Phase::Requested,
            Phase::Accepted,
            Phase::Offered,
            Phase::Answered,
            Phase::Terminal,
        ];
        let observed_phases = [
            IntroductionPhaseForLab::Requested,
            IntroductionPhaseForLab::Accepted,
            IntroductionPhaseForLab::Offered,
            IntroductionPhaseForLab::Answered,
            IntroductionPhaseForLab::Terminal,
        ];
        // Populate scalar states directly to test observation, not phase admission.
        for (index, phase) in phases.iter().enumerate() {
            let ticket = insert(&mut controller, (index + 1) as u8, now);
            controller.records.get_mut(&ticket.id).unwrap().phase = *phase;
        }
        let producer = PeerOwnerToken::detached_for_control(&device(2));
        let first = controller.records.get_mut(&[1; 16]).unwrap();
        first.native = Some(producer.downgrade());
        first.coordinates.challenge = Some(IntroductionChallenge {
            request_hash: [7; 32],
            responder_challenge: [8; 32],
        });
        first.sequences = [Some(3), Some(2)];
        first.request_sent = true;
        first.signal_pending = [Some((3, [9; 32])), None];
        first.forward_pending = [None, Some((2, [10; 32]))];
        first.candidates = 2;
        first.signaling_bytes = 100;
        let request_hash = first.request_hash;
        controller.cursor = Some([2; 16]);
        let generation = controller.generation;
        let retained = provider.in_use();
        let reservations = provider.active_reservations();
        let scopes = provider.active_scopes();
        let owners = Arc::strong_count(producer.connection());

        let snapshot = controller.snapshot_for_lab(source, destination, now);
        assert!(!snapshot.truncated);
        assert_eq!(
            snapshot.records[0],
            Some(IntroductionRecordForLab {
                introduction_id: [1; 16],
                phase: IntroductionPhaseForLab::Requested,
                sequences: [Some(3), Some(2)],
                request_sent: true,
                challenge_present: true,
                signal_pending: [true, false],
                forward_pending: [false, true],
                native_upgraded: true,
                native_worker_present: false,
                expired: false,
            })
        );
        for (index, phase) in observed_phases.iter().enumerate() {
            assert_eq!(snapshot.records[index].unwrap().phase, *phase);
        }
        assert!(snapshot.records[5..].iter().all(Option::is_none));
        assert_eq!(
            controller.snapshot_for_lab(source, destination, now),
            snapshot
        );
        assert_eq!(
            Arc::strong_count(producer.connection()),
            owners,
            "snapshot drops its temporary upgrade even while the copied result lives"
        );
        let before_deadline =
            controller.snapshot_for_lab(source, destination, now + Duration::from_millis(99));
        assert!(!before_deadline.records[0].unwrap().expired);
        let at_deadline =
            controller.snapshot_for_lab(source, destination, now + Duration::from_millis(100));
        assert!(at_deadline.records[0].unwrap().expired);
        drop(producer);
        let after_retention =
            controller.snapshot_for_lab(source, destination, now + Duration::from_millis(200));
        let first_observed = after_retention.records[0].unwrap();
        assert!(first_observed.expired);
        assert!(!first_observed.native_upgraded && !first_observed.native_worker_present);
        assert_eq!(
            first_observed.phase,
            IntroductionPhaseForLab::Requested,
            "observation does not expire or prune records, even beyond retention"
        );
        assert_eq!(
            after_retention.records[4].unwrap().phase,
            IntroductionPhaseForLab::Terminal,
            "terminal is current state, not a reconstructed successful phase"
        );
        for index in 1..=5 {
            let record = controller.records.get(&[index; 16]).unwrap();
            assert_eq!(record.deadline, now + Duration::from_millis(100));
            assert_eq!(record.retain_until, now + Duration::from_millis(110));
            assert_eq!(record.phase, phases[usize::from(index - 1)]);
        }
        let first = controller.records.get(&[1; 16]).unwrap();
        assert_eq!(first.signal_pending, [Some((3, [9; 32])), None]);
        assert_eq!(first.forward_pending, [None, Some((2, [10; 32]))]);
        assert_eq!(first.request_hash, request_hash);
        assert_eq!(
            first.coordinates.challenge.unwrap().responder_challenge,
            [8; 32]
        );
        assert_eq!(first.candidates, 2);
        assert_eq!(first.signaling_bytes, 100);
        assert!(
            first.native.is_some(),
            "observation does not clear an expired weak witness"
        );
        assert_eq!(controller.cursor, Some([2; 16]));
        assert_eq!(controller.generation, generation);
        assert_eq!(controller.count, 5);
        assert_eq!(provider.in_use(), retained);
        assert_eq!(provider.active_reservations(), reservations);
        assert_eq!(provider.active_scopes(), scopes);
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
    }

    #[test]
    fn introduction_native_binding_history_survives_owner_loss_but_not_replacement() {
        let (mut controller, provider) = fixture(1, 1);
        // Prepare signed inputs before the original finite admission clock.
        // The detached owner exercises controller binding, not WebRTC authority.
        let coordinates = coordinates(9);
        let source = coordinates.source;
        let destination = coordinates.destination;
        let request_hash = request(9).request_digest().unwrap();
        let accept = frame(9, true, 0, HubIntroductionBody::Accept {});
        let owner = PeerOwnerToken::detached_for_control(&device(2));
        let now = Instant::now();
        let ticket = controller
            .insert(coordinates, Phase::Requested, None, None, now)
            .unwrap();
        controller.records.get_mut(&ticket.id).unwrap().request_hash = Some(request_hash);
        assert_eq!(controller.native_was_bound(ticket), Some(false));
        advance(
            controller.records.get_mut(&ticket.id).unwrap(),
            &accept,
            now,
            policy(1),
        )
        .unwrap();
        controller.bind_native_owner(ticket, &owner).unwrap();
        assert_eq!(controller.native_was_bound(ticket), Some(true));
        let wrong_generation = IntroductionTicket {
            generation: ticket.generation + 1,
            ..ticket
        };
        let wrong_id = IntroductionTicket {
            id: [10; 16],
            ..ticket
        };
        assert_eq!(controller.native_was_bound(wrong_generation), None);
        assert_eq!(controller.native_was_bound(wrong_id), None);

        controller.cursor = Some(ticket.id);
        let claim = provider.in_use();
        let reservations = provider.active_reservations();
        let scopes = provider.active_scopes();
        let generation = controller.generation;
        let owner_count = Arc::strong_count(owner.connection());
        let snapshot = controller.snapshot_for_lab(source, destination, now);
        let record = controller.record(ticket).unwrap();
        let signal_pending = record.signal_pending;
        let forward_pending = record.forward_pending;
        let candidates = record.candidates;
        let signaling_bytes = record.signaling_bytes;
        for _ in 0..4 {
            assert_eq!(controller.native_was_bound(ticket), Some(true));
        }
        assert_eq!(Arc::strong_count(owner.connection()), owner_count);
        assert_eq!(
            controller.snapshot_for_lab(source, destination, now),
            snapshot
        );
        drop(owner);
        assert!(controller
            .record(ticket)
            .unwrap()
            .native
            .as_ref()
            .unwrap()
            .upgrade()
            .is_none());
        assert_eq!(controller.native_was_bound(ticket), Some(true));
        assert!(controller.failed(ticket));
        let terminal = controller.snapshot_for_lab(source, destination, now);
        for _ in 0..4 {
            assert_eq!(controller.native_was_bound(ticket), Some(true));
        }
        assert_eq!(
            controller.snapshot_for_lab(source, destination, now),
            terminal
        );
        let record = controller.record(ticket).unwrap();
        assert_eq!(record.phase, Phase::Terminal);
        assert_eq!(record.deadline, now + Duration::from_millis(100));
        assert_eq!(record.retain_until, now + Duration::from_millis(110));
        assert_eq!(record.request_hash, Some(request_hash));
        assert_eq!(record.coordinates.challenge, accept.challenge());
        assert_eq!(record.signal_pending, signal_pending);
        assert_eq!(record.forward_pending, forward_pending);
        assert_eq!(record.candidates, candidates);
        assert_eq!(record.signaling_bytes, signaling_bytes);
        assert_eq!(controller.cursor, Some(ticket.id));
        assert_eq!(controller.generation, generation);
        assert_eq!(controller.count, 1);
        assert_eq!(provider.in_use(), claim);
        assert_eq!(provider.active_reservations(), reservations);
        assert_eq!(provider.active_scopes(), scopes);

        // Existing maintenance actually prunes the terminal, expired weak record.
        controller.cursor = None;
        let replacement_time = now + Duration::from_millis(111);
        assert_eq!(controller.poll_expired(replacement_time), None);
        assert_eq!(controller.native_was_bound(ticket), None);
        let successor = insert(&mut controller, 9, replacement_time);
        assert_ne!(successor, ticket);
        assert_eq!(controller.native_was_bound(ticket), None);
        assert_eq!(controller.native_was_bound(successor), Some(false));
        assert_eq!(
            controller.record(successor).unwrap().phase,
            Phase::Requested
        );
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
    }

    #[test]
    fn introduction_attempt_comparison_is_exact_canonical_correlation_only() {
        let ticket = IntroductionTicket {
            id: [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ],
            generation: 1,
        };
        let canonical = "0123456789abcdeffedcba9876543210";
        assert_eq!(ticket.attempt(), canonical);
        assert!(ticket.matches_attempt(canonical));
        for invalid in [
            "",
            "0123456789abcdeffedcba987654321",
            "0123456789abcdeffedcba98765432100",
            "0123456789ABCDEFFEDCBA9876543210",
            " 123456789abcdeffedcba9876543210",
            "0123456789abcdeffedcba987654321\n",
            "0123456789abcdeffedcba987654321g",
            "0123456789abcdeffedcba987654321\0",
            "\u{00e9}23456789abcdeffedcba9876543210",
        ] {
            assert!(!ticket.matches_attempt(invalid));
        }
        for index in 0..32 {
            let mut different = *b"0123456789abcdeffedcba9876543210";
            different[index] = if different[index] == b'0' { b'1' } else { b'0' };
            assert!(!ticket.matches_attempt(std::str::from_utf8(&different).unwrap()));
        }
        let other_id = IntroductionTicket {
            id: [0; 16],
            generation: 1,
        };
        assert!(!other_id.matches_attempt(canonical));
        let reused_id = IntroductionTicket {
            generation: 2,
            ..ticket
        };
        assert_ne!(ticket, reused_id);
        assert!(
            reused_id.matches_attempt(canonical),
            "correlation cannot distinguish generations; full-ticket fencing is mandatory"
        );
    }

    #[test]
    fn introduction_lifetime_keeps_exact_generation_and_original_deadline() {
        let (mut controller, provider) = fixture(1, 1);
        let now = Instant::now();
        let ticket = insert(&mut controller, 9, now);
        let deadline = now + Duration::from_millis(100);
        for at in [now, deadline - Duration::from_nanos(1)] {
            assert_eq!(
                controller.lifetime(ticket, at),
                IntroductionLifetime::Live { deadline }
            );
        }
        for at in [deadline, deadline + Duration::from_nanos(1)] {
            assert_eq!(
                controller.lifetime(ticket, at),
                IntroductionLifetime::Elapsed { deadline }
            );
        }
        let wrong_generation = IntroductionTicket {
            generation: ticket.generation + 1,
            ..ticket
        };
        let wrong_id = IntroductionTicket {
            id: [10; 16],
            ..ticket
        };
        assert_eq!(
            controller.lifetime(wrong_generation, now),
            IntroductionLifetime::Missing
        );
        assert_eq!(
            controller.lifetime(wrong_id, now),
            IntroductionLifetime::Missing
        );
        // Reads after expiry did not terminalize or prune the original record.
        assert_eq!(controller.record(ticket).unwrap().phase, Phase::Requested);
        assert_eq!(
            controller.remaining(ticket, now),
            Some(Duration::from_millis(100))
        );
        let replacement_time = now + Duration::from_millis(111);
        assert_eq!(controller.poll_expired(replacement_time), Some(ticket));
        assert_eq!(
            controller.lifetime(ticket, replacement_time),
            IntroductionLifetime::Missing
        );
        let successor = insert(&mut controller, 9, replacement_time);
        assert_ne!(ticket, successor);
        assert!(successor.matches_attempt(&ticket.attempt()));
        assert_eq!(
            controller.lifetime(ticket, replacement_time),
            IntroductionLifetime::Missing
        );
        assert_eq!(
            controller.lifetime(successor, replacement_time),
            IntroductionLifetime::Live {
                deadline: replacement_time + Duration::from_millis(100)
            }
        );
        assert!(!controller.failed(ticket));
        assert!(!controller.promoted(ticket));
        assert_eq!(
            controller.record(successor).unwrap().phase,
            Phase::Requested
        );
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
    }

    #[test]
    fn introduction_lifetime_terminal_reads_preserve_custody_without_failure_inference() {
        let (mut controller, provider) = fixture(3, 3);
        let now = Instant::now();
        let live = insert(&mut controller, 1, now);
        let failed = insert(&mut controller, 2, now);
        let promoted = insert(&mut controller, 3, now);
        assert!(controller.failed(failed));
        assert!(controller.promoted(promoted));
        // Scalar readback fixture only: no new native or authenticated authority.
        let producer = PeerOwnerToken::detached_for_control(&device(2));
        let record = controller.records.get_mut(&live.id).unwrap();
        record.native = Some(producer.downgrade());
        record.phase = Phase::Answered;
        record.request_sent = true;
        record.sequences = [Some(3), Some(2)];
        record.signal_pending = [Some((4, [11; 32])), None];
        record.forward_pending = [None, Some((3, [12; 32]))];
        record.coordinates.challenge = Some(IntroductionChallenge {
            request_hash: [13; 32],
            responder_challenge: [14; 32],
        });
        record.candidates = 1;
        record.signaling_bytes = 123;
        let request_hash = record.request_hash;
        controller.cursor = Some(failed.id);
        let generation = controller.generation;
        let claim = provider.in_use();
        let reservations = provider.active_reservations();
        let scopes = provider.active_scopes();
        let owners = Arc::strong_count(producer.connection());
        let source = device(1).as_bytes();
        let destination = device(2).as_bytes();
        let before = controller.snapshot_for_lab(source, destination, now);
        let deadline = now + Duration::from_millis(100);
        for at in [now, deadline, now + Duration::from_millis(200)] {
            for _ in 0..3 {
                assert_eq!(
                    controller.lifetime(live, at),
                    if at < deadline {
                        IntroductionLifetime::Live { deadline }
                    } else {
                        IntroductionLifetime::Elapsed { deadline }
                    }
                );
                for ticket in [failed, promoted] {
                    assert_eq!(
                        controller.lifetime(ticket, at),
                        IntroductionLifetime::Terminal { deadline },
                        "Terminal reports neither failure nor completed cleanup"
                    );
                }
            }
        }
        assert_eq!(
            controller.snapshot_for_lab(source, destination, now),
            before
        );
        let record = controller.record(live).unwrap();
        assert_eq!(record.ticket, live);
        assert_eq!(record.coordinates.source, source);
        assert_eq!(record.coordinates.destination, destination);
        assert_eq!(record.coordinates.introduction_id, live.id);
        assert_eq!(
            record.coordinates.challenge,
            Some(IntroductionChallenge {
                request_hash: [13; 32],
                responder_challenge: [14; 32],
            })
        );
        assert_eq!(record.request_hash, request_hash);
        assert_eq!(record.signal_pending, [Some((4, [11; 32])), None]);
        assert_eq!(record.forward_pending, [None, Some((3, [12; 32]))]);
        assert_eq!(record.candidates, 1);
        assert_eq!(record.signaling_bytes, 123);
        assert!(record.native.is_some());
        assert!(record.upstream.is_none() && record.downstream.is_none());
        for ticket in [live, failed, promoted] {
            let record = controller.record(ticket).unwrap();
            assert_eq!(record.deadline, deadline);
            assert_eq!(record.retain_until, now + Duration::from_millis(110));
        }
        assert_eq!(controller.cursor, Some(failed.id));
        assert_eq!(controller.generation, generation);
        assert_eq!(controller.count, 3);
        assert_eq!(Arc::strong_count(producer.connection()), owners);
        assert_eq!(provider.in_use(), claim);
        assert_eq!(provider.active_reservations(), reservations);
        assert_eq!(provider.active_scopes(), scopes);
        drop(producer);
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
    }

    #[test]
    fn introduction_remaining_uses_original_deadline_through_phase_changes() {
        let (mut controller, provider) = fixture(1, 1);
        let now = Instant::now();
        let ticket = insert(&mut controller, 9, now);
        assert_eq!(
            controller.remaining(ticket, now),
            Some(Duration::from_millis(100))
        );
        let later = now + Duration::from_millis(40);
        advance(
            controller.records.get_mut(&ticket.id).unwrap(),
            &frame(9, true, 0, HubIntroductionBody::Accept {}),
            later,
            policy(1),
        )
        .unwrap();
        assert_eq!(
            controller.remaining(ticket, later),
            Some(Duration::from_millis(60))
        );
        advance(
            controller.records.get_mut(&ticket.id).unwrap(),
            &frame(
                9,
                false,
                1,
                HubIntroductionBody::Offer {
                    sdp: "offer".into(),
                },
            ),
            now + Duration::from_millis(99),
            policy(1),
        )
        .unwrap();
        assert_eq!(
            controller.remaining(ticket, now + Duration::from_millis(99)),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            controller.remaining(ticket, now + Duration::from_millis(100)),
            None
        );
        assert_eq!(
            controller.remaining(ticket, now + Duration::from_millis(101)),
            None
        );
        assert!(!controller.is_current(ticket, now + Duration::from_millis(100)));
        assert!(controller.cancel(ticket));
        assert_eq!(
            controller.remaining(ticket, later),
            None,
            "terminal never authorizes work"
        );
        controller.poll_expired(now + Duration::from_millis(111));
        let replacement = insert(&mut controller, 9, now + Duration::from_millis(111));
        assert_ne!(ticket, replacement);
        assert_eq!(
            controller.remaining(ticket, now + Duration::from_millis(111)),
            None
        );
        assert_eq!(
            controller.remaining(replacement, now + Duration::from_millis(111)),
            Some(Duration::from_millis(100))
        );
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn introduction_same_connection_other_installation_is_not_native_owner() {
        use crate::engine::{connection::PeerConnection, peer_registry::PeerRegistry};
        let first_registry = PeerRegistry::new("first".into());
        let second_registry = PeerRegistry::new("second".into());
        let peer = Arc::new(PeerConnection::new(device(2).to_string(), None));
        let first = first_registry
            .install_unpromoted_if_absent(Arc::clone(&peer))
            .unwrap();
        // The same Arc can be installed under another registry namespace. No
        // authentication or native work is fabricated by this pure control.
        let second = second_registry
            .install_unpromoted_if_absent(Arc::clone(&peer))
            .unwrap();
        assert!(Arc::ptr_eq(first.connection(), second.connection()));
        assert!(same_native_owner(&first, &first.clone()));
        assert!(!same_native_owner(&first, &second));
        assert!(!same_owner(&first, &second));
    }

    #[tokio::test]
    #[ignore = "opens one local WebRTC connector; run explicitly in the isolated native harness"]
    async fn introduction_native_worker_refinement_keeps_exact_installation() {
        use crate::engine::{connection::PeerConnection, peer_registry::PeerRegistry};
        let state = crate::engine::build_test_state("intro-native-refinement");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let (worker, events) = tokio::time::timeout_at(
            deadline,
            state.transport.open_connector_peer(
                crate::transport::Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            ),
        )
        .await
        .expect("bounded native open")
        .expect("funded connector opens");
        let worker = Arc::new(worker);
        let first_registry = PeerRegistry::new("first".into());
        let second_registry = PeerRegistry::new("second".into());
        let peer = Arc::new(PeerConnection::new(device(2).to_string(), None));
        let first = first_registry
            .install_unpromoted_if_absent(Arc::clone(&peer))
            .unwrap();
        let second = second_registry
            .install_unpromoted_if_absent(Arc::clone(&peer))
            .unwrap();
        let emitted = first.for_worker(Arc::clone(&worker));
        let wrong_installation = second.for_worker(Arc::clone(&worker));
        let valid = same_native_owner(&first, &emitted);
        let repeated = same_native_owner(&emitted, &emitted);
        let substituted = same_native_owner(&first, &wrong_installation);
        let lost_stamp = same_native_owner(&emitted, &first);
        let exact_does_not_refine = first.same_exact_owner(&emitted);
        drop((
            emitted,
            wrong_installation,
            first,
            second,
            peer,
            first_registry,
            second_registry,
        ));
        let close = tokio::time::timeout_at(deadline, worker.retire_and_close()).await;
        drop(events);
        drop(worker);
        tokio::time::timeout_at(deadline, state.shutdown())
            .await
            .expect("bounded joined cleanup");
        assert!(tokio::time::Instant::now() < deadline);
        assert!(
            matches!(close, Ok(Ok(()))),
            "native close observed before releasing the fixture"
        );
        assert!(valid && repeated);
        assert!(!substituted && !lost_stamp && !exact_does_not_refine);
        // Worker identity refinement only: this does not claim promotion or
        // authentication of either placeholder.
    }

    #[test]
    fn introduction_record_pressure_and_terminal_lifetime_are_exact() {
        let (mut controller, provider) = fixture(2, 1);
        let baseline = provider.in_use();
        let reservations = provider.active_reservations();
        let scopes = provider.active_scopes();
        let now = Instant::now();
        let ticket = insert(&mut controller, 1, now);
        let retained = baseline
            .checked_add(
                FiniteResourceProvider::reservation_planning_charge(
                    HubIntroduction::entry_claim().unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(provider.in_use(), retained);
        assert_eq!(provider.active_reservations(), reservations + 1);
        assert_eq!(provider.active_scopes(), scopes);
        assert_eq!(
            controller.insert(coordinates(2), Phase::Requested, None, None, now),
            Err(IntroductionError::Pressure)
        );
        assert_eq!(controller.count, 1);
        assert_eq!(provider.in_use(), retained);
        assert!(controller.cancel(ticket));
        assert_eq!(
            provider.in_use(),
            retained,
            "terminal retains replay custody"
        );
        assert_eq!(
            controller.ticket_for_attempt(&device(2), &ticket.attempt()),
            Some(ticket)
        );
        controller.poll_expired(now + Duration::from_millis(111));
        assert_eq!(provider.in_use(), baseline);
        assert_eq!(provider.active_reservations(), reservations);
        assert_eq!(provider.active_scopes(), scopes);
        assert!(!controller.cancel(ticket));
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
    }

    #[test]
    fn introduction_phase_sequences_and_candidate_attempts_refuse_before_reduction() {
        let (mut controller, provider) = fixture(1, 1);
        let now = Instant::now();
        let ticket = insert(&mut controller, 3, now);
        let record = controller.records.get_mut(&ticket.id).unwrap();
        let limits = policy(1);
        let offer = frame(
            3,
            false,
            1,
            HubIntroductionBody::Offer {
                sdp: "offer".into(),
            },
        );
        assert_eq!(
            advance(record, &offer, now, limits),
            Err(IntroductionError::Invalid)
        );
        let accept = frame(3, true, 0, HubIntroductionBody::Accept {});
        advance(record, &accept, now, limits).unwrap();
        assert_eq!(
            advance(record, &accept, now, limits),
            Err(IntroductionError::Replay)
        );
        advance(record, &offer, now, limits).unwrap();
        assert_eq!(
            advance(record, &offer, now, limits),
            Err(IntroductionError::Replay)
        );
        let answer = frame(
            3,
            true,
            1,
            HubIntroductionBody::Answer {
                sdp: "answer".into(),
            },
        );
        advance(record, &answer, now, limits).unwrap();
        for sequence in 2..=4 {
            let candidate = frame(
                3,
                false,
                sequence,
                HubIntroductionBody::Candidate {
                    candidate: "candidate".into(),
                    sdp_mid: None,
                    sdp_mline_index: None,
                    username_fragment: None,
                },
            );
            let result = advance(record, &candidate, now, limits);
            assert_eq!(
                result,
                if sequence == 4 {
                    Err(IntroductionError::Capacity)
                } else {
                    Ok(())
                }
            );
        }
        assert_eq!(
            record.candidates, 3,
            "refused attempt counted, no free retry loop"
        );
        assert_eq!(record.phase, Phase::Terminal);
        assert_eq!(
            advance(record, &answer, now, limits),
            Err(IntroductionError::Stale)
        );
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn introduction_original_deadline_and_reused_id_cannot_complete_successor() {
        let (mut controller, provider) = fixture(1, 1);
        let now = Instant::now();
        let old = insert(&mut controller, 4, now);
        let accept = frame(4, true, 0, HubIntroductionBody::Accept {});
        assert_eq!(
            advance(
                controller.records.get_mut(&old.id).unwrap(),
                &accept,
                now + Duration::from_millis(100),
                policy(1)
            ),
            Err(IntroductionError::Expired)
        );
        assert_eq!(
            controller.poll_expired(now + Duration::from_millis(111)),
            Some(old)
        );
        let mut next = coordinates(4);
        next.challenge = Some(IntroductionChallenge {
            request_hash: request(4).request_digest().unwrap(),
            responder_challenge: [8; 32],
        });
        let successor = controller
            .insert(
                next,
                Phase::Requested,
                None,
                None,
                now + Duration::from_millis(111),
            )
            .unwrap();
        controller
            .records
            .get_mut(&successor.id)
            .unwrap()
            .request_hash = Some(request(4).request_digest().unwrap());
        assert_ne!(old, successor);
        assert!(!controller.promoted(old));
        assert_eq!(
            controller.record(successor).unwrap().phase,
            Phase::Requested
        );
        assert_eq!(
            advance(
                controller.records.get_mut(&successor.id).unwrap(),
                &accept,
                now + Duration::from_millis(111),
                policy(1)
            ),
            Err(IntroductionError::Invalid),
            "old signed transcript cannot match newly funded responder challenge"
        );
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn introduction_coalescing_and_glare_are_pre_native_only() {
        let (mut controller, provider) = fixture(2, 2);
        let now = Instant::now();
        let first = insert(&mut controller, 5, now);
        let baseline = provider.in_use();
        let matching = controller.target_record(device(2).as_bytes()).unwrap();
        assert_eq!(
            matching.ticket, first,
            "all callers observe one target record"
        );
        assert!(controller.target_record(device(3).as_bytes()).is_none());
        assert_eq!(
            provider.in_use(),
            baseline,
            "coalescing retains no second waiter/map allocation"
        );
        let local = controller.local;
        let peer = device(2).as_bytes();
        let expected = if peer < local {
            Ok(first)
        } else {
            Err(IntroductionError::Glare)
        };
        assert_eq!(glare_replacement(matching, local, peer), expected);
        let record = controller.records.get_mut(&first.id).unwrap();
        record.phase = Phase::Accepted;
        assert_eq!(
            glare_replacement(record, local, peer),
            Err(IntroductionError::Glare)
        );
        assert!(controller.cancel(first));
        assert!(controller.target_record(peer).is_none());
        assert_eq!(
            provider.in_use(),
            baseline,
            "terminal still owns replay record"
        );
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn introduction_signal_receipt_is_payload_bound_and_single_consumer() {
        let (mut controller, provider) = fixture(1, 1);
        let now = Instant::now();
        let ticket = insert(&mut controller, 6, now);
        // This is a pure ownership/receipt control, NOT a promoted-carrier
        // admission test. Production receive/admit additionally fence registry.
        let carrier = PeerOwnerToken::detached_for_control(&device(1));
        let replacement = PeerOwnerToken::detached_for_control(&device(1));
        let offer = frame(
            6,
            false,
            1,
            HubIntroductionBody::Offer {
                sdp: "first".into(),
            },
        );
        let other = frame(
            6,
            false,
            1,
            HubIntroductionBody::Offer {
                sdp: "different".into(),
            },
        );
        let record = controller.records.get_mut(&ticket.id).unwrap();
        record.phase = Phase::Offered;
        record.coordinates.challenge = offer.challenge();
        record.upstream = Some(carrier.clone());
        record.signal_pending[0] = Some((1, wire_digest(&offer).unwrap()));
        assert_eq!(
            controller.take_signal(ticket, &replacement, &offer, now),
            Err(IntroductionError::Stale)
        );
        assert_eq!(
            controller.take_signal(ticket, &carrier, &other, now),
            Err(IntroductionError::Replay)
        );
        controller
            .take_signal(ticket, &carrier, &offer, now)
            .unwrap();
        assert_eq!(
            controller.take_signal(ticket, &carrier, &offer, now),
            Err(IntroductionError::Replay)
        );
        drop(controller);
        drop(carrier);
        drop(replacement);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn introduction_forward_receipt_counts_actual_hop_and_refuses_second_write() {
        let (mut controller, provider) = fixture_with_work(
            1,
            1,
            crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_WIRE_BYTES,
        );
        controller.local = device(3).as_bytes();
        let now = Instant::now();
        let ticket = insert(&mut controller, 7, now);
        let received = request(7);
        let record = controller.records.get_mut(&ticket.id).unwrap();
        record.forward_pending[0] = Some((0, immutable_digest(&received).unwrap()));
        record.signaling_bytes = wire_length(&received).unwrap();
        let baseline = provider.in_use();
        let reservations = provider.active_reservations();
        let scopes = provider.active_scopes();
        let mut forwarded = received.clone();
        forwarded
            .append_hop(device(3), &ed25519_dalek::SigningKey::from_bytes(&[3; 32]))
            .unwrap();
        controller.observe_forward(ticket, &forwarded, now).unwrap();
        assert_eq!(
            controller.record(ticket).unwrap().signaling_bytes,
            wire_length(&received).unwrap() + wire_length(&forwarded).unwrap()
        );
        assert_eq!(
            controller.observe_forward(ticket, &forwarded, now),
            Err(IntroductionError::Replay)
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "temporary verification lease released on success/refusal"
        );
        assert_eq!(provider.active_reservations(), reservations);
        assert_eq!(provider.active_scopes(), scopes);
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn introduction_terminal_interception_outlives_last_native_producer() {
        let (mut controller, provider) = fixture(1, 1);
        let now = Instant::now();
        let ticket = insert(&mut controller, 8, now);
        let producer = PeerOwnerToken::detached_for_control(&device(2));
        // Pure lifetime control: no native connection or authentication is
        // claimed by this detached fixture owner.
        controller.records.get_mut(&ticket.id).unwrap().native = Some(producer.downgrade());
        let retained = provider.in_use();
        controller.cancel(ticket);
        controller.poll_expired(now + Duration::from_millis(111));
        assert_eq!(
            controller.ticket_for_attempt(&device(2), &ticket.attempt()),
            Some(ticket)
        );
        assert_eq!(provider.in_use(), retained);
        drop(producer);
        controller.poll_expired(now + Duration::from_millis(112)); // wrap cursor
        controller.poll_expired(now + Duration::from_millis(112));
        assert_eq!(
            controller.ticket_for_attempt(&device(2), &ticket.attempt()),
            None
        );
        drop(controller);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
    }
}
