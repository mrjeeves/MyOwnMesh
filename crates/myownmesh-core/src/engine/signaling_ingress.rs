//! The Signaling Node's ephemeral-transport ingress: the one place a carrier
//! observation is admitted, and the only place it becomes an engine domain
//! value.
//!
//! `ARCHITECTURE.md` §4 states that signaling carries two disjoint categories —
//! durable semantic exchange and ephemeral transport control — and
//! `CURRENT-TO-TARGET-MIGRATION-MATRIX.md` requires that the two be
//! distinguished "before domain parsing". **This module is the ephemeral one,
//! and it is the only one that exists.** No carrier variant carries a durable
//! signed fact, so there is no durable ingress to write and none is pretended:
//! the distinction is carried by the type this module produces rather than by a
//! tag whose other value nothing can hold.
//!
//! What is enforced, and enforced by the compiler rather than by convention:
//!
//! - A carrier pump can only build a [`CarrierObservation`], whose constructors
//!   decide the [`EphemeralSignal`] kind. The parse into a domain value lives
//!   behind [`CarrierObservation::into_ingress`] and is private here, so
//!   "admit, then parse" is the only sequence that compiles.
//! - [`admit`] and [`outbound_signal`] are exhaustive with no wildcard arm. A
//!   new carrier variant does not inherit a kind; whoever adds one has to come
//!   here and say what it is, and a variant that is *not* ephemeral transport
//!   control has no kind to choose — which is the review this boundary exists
//!   to force.
//!
//! [`SignalingRuntime`] is the owner on this side of the boundary: it mints one
//! opaque [`CarrierInstance`] per attach and owns cross-carrier de-duplication,
//! whose every retained key is funded by the finite provider rather than capped
//! by a constant. It retains no unfunded availability record: the only retained
//! carrier-supplied data is an exact duplicate key paired with weak lifecycle
//! custody, and the provider funds both the key and its guard index. The
//! availability map that used to live here is described in the runtime docs,
//! along with why it was removed rather than repaired.
//!
//! # What this boundary is not
//!
//! It moves no traffic on its own. It adds no anti-entropy, no proof delivery,
//! no retry, timer, poll, or acknowledgement, and it changes no eviction
//! behaviour. Nothing here can grant, revoke, or record membership.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tracing::{trace, warn};

use myownmesh_signaling::nostr::AdmissionSource;
use myownmesh_signaling::SignalingMessage;

use crate::resource::{
    strings_measure, LocalApplicationResourceScope, MailboxMeasurement, ResourceClaim,
    ResourceLease, ResourceMailboxItem, ResourceMailboxItemError, ResourceMailboxSendError,
    ResourceMailboxSender,
};
use crate::transport::LocalIceCandidate;

use super::state::{
    NetworkState, RecoveryCarrierInstance, RecoveryPublishId, SignalingEmissionId,
    SignalingInbound, SignalingOutbound,
};
use crate::runtime::peer_session::DedupToken;

/// Which carrier observed a signaling message.
///
/// **Bounded provenance, and the bound is the point.** A closed set of four
/// unit variants: it records that a message arrived over the LAN rather than a
/// relay, and nothing else. No relay URL, no socket, no address, no key and no
/// peer-supplied string, so it cannot grow into a second identity for a device.
/// `Signaling Node` in `TRANSITION-PLAYBOOK.md` §6 owns "bounded carrier
/// provenance" and must never own "endpoint identity"; a closed enum is how
/// those two stay different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalingCarrier {
    /// The in-process [`myownmesh_signaling::local::LocalBroker`].
    #[cfg(any(test, feature = "transport-lab"))]
    Local,
    /// The Nostr relay driver.
    Nostr,
    /// The LAN mDNS driver.
    Mdns,
    /// Signed endpoint introduction over an already promoted mesh carrier.
    /// This transports native signaling only, never application authority.
    Hub,
}

impl SignalingCarrier {
    /// Stable lowercase name for traces and diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            #[cfg(any(test, feature = "transport-lab"))]
            Self::Local => "local",
            Self::Nostr => "nostr",
            Self::Mdns => "mdns",
            Self::Hub => "hub",
        }
    }

    /// Whether this carrier can return one emission as two different-looking
    /// messages, which is the only thing de-duplication is for.
    ///
    /// Nostr and mDNS each stamp their own envelope — a different event id, a
    /// different offer id — around a payload the engine sent once, so a fan-out
    /// to both comes back twice and only the content identifies the pair.
    /// Applying the same remote description twice wedges WebRTC permanently.
    ///
    /// The in-process broker stamps nothing: a repeat over it is a genuine
    /// repeat send, which is the engine's own retry pacing, and swallowing it
    /// would silently change the behaviour the deterministic suite runs on.
    fn restamps_duplicates(self) -> bool {
        match self {
            #[cfg(any(test, feature = "transport-lab"))]
            Self::Local => false,
            Self::Nostr | Self::Mdns | Self::Hub => true,
        }
    }
}

/// One attach of one carrier, as an opaque process-local receipt.
///
/// **Opaque, process-local, and not peer-choosable.** The wrapped counter is
/// minted by [`SignalingRuntime::attach`] and never leaves the process: it is
/// not on any wire, not derived from anything a peer sends, and carries no
/// address, relay or key. It is a receipt for "this attach of this carrier", so
/// a consumer can tell one attach of a driver from the next without either of
/// them naming anything.
///
/// It is **provenance handed outward with the value, not state retained here**.
/// Nothing on this side keeps a record keyed by an instance, which is why a
/// carrier that detaches has nothing to clean up and a receipt cannot go stale:
/// the earlier design that did keep such records is described on
/// [`SignalingRuntime`], along with why it was removed rather than repaired.
///
/// It is deliberately **not** a route identity and not a path generation: it
/// names no path, orders nothing, and no decision anywhere reads it as a
/// preference. The only question it answers is "same attach?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CarrierInstance(u64);

/// Exact lifecycle custody for one carrier attach.
///
/// The bridge records only the recovery generations and signaling attempts it
/// actually presents to this instance. Dropping the attach settles those
/// exact records as refusals; it never searches by device, carrier kind, or
/// URL. The state-side owner remains authoritative for stale-generation and
/// successor checks.
pub(crate) struct CarrierInstanceGuard {
    instance: Option<RecoveryCarrierInstance>,
    state: Weak<NetworkState>,
    scope: Option<LocalApplicationResourceScope>,
    detached: std::sync::atomic::AtomicBool,
    attempts: Mutex<Option<Box<GuardedAttempt>>>,
    recoveries: Mutex<Option<Box<GuardedRecovery>>>,
}

struct GuardedAttempt {
    emission: SignalingEmissionId,
    attempt: String,
    claimed: bool,
    fenced: bool,
    source: Option<AdmissionSource>,
    event_id: Option<[u8; 32]>,
    _lease: ResourceLease,
    next: Option<Box<GuardedAttempt>>,
}

struct GuardedRecovery {
    id: RecoveryPublishId,
    _lease: ResourceLease,
    next: Option<Box<GuardedRecovery>>,
}

impl CarrierInstanceGuard {
    pub(crate) fn noop(_instance: Option<RecoveryCarrierInstance>) -> Arc<Self> {
        Arc::new(Self {
            instance: None,
            state: Weak::new(),
            scope: None,
            detached: std::sync::atomic::AtomicBool::new(false),
            attempts: Mutex::new(None),
            recoveries: Mutex::new(None),
        })
    }

    pub(crate) fn for_state(
        state: &Arc<NetworkState>,
        instance: Option<RecoveryCarrierInstance>,
    ) -> Arc<Self> {
        Arc::new(Self {
            instance,
            state: Arc::downgrade(state),
            scope: state.local_application_resource_scope().ok(),
            detached: std::sync::atomic::AtomicBool::new(false),
            attempts: Mutex::new(None),
            recoveries: Mutex::new(None),
        })
    }

    pub(crate) fn track_attempt(&self, emission: SignalingEmissionId, attempt: &str) -> bool {
        if self.detached.load(Ordering::Acquire) || attempt.is_empty() {
            return false;
        }
        let mut attempts = self.attempts.lock();
        if self.detached.load(Ordering::Acquire) {
            return false;
        }
        let mut cursor = attempts.as_deref();
        while let Some(known) = cursor {
            if known.emission == emission {
                return true;
            }
            cursor = known.next.as_deref();
        }
        let Some(scope) = self.scope.as_ref() else {
            return false;
        };
        let bytes = std::mem::size_of::<GuardedAttempt>()
            .checked_add(attempt.len())
            .and_then(|bytes| u64::try_from(bytes).ok());
        let Some(bytes) = bytes else {
            return false;
        };
        let Ok(claim) = ResourceClaim::try_from_entries([
            (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
            (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
        ]) else {
            return false;
        };
        let Ok(lease) = scope.acquire(claim) else {
            return false;
        };
        let mut node = Box::new(GuardedAttempt {
            emission,
            attempt: attempt.to_owned(),
            claimed: false,
            fenced: false,
            source: None,
            event_id: None,
            _lease: lease,
            next: None,
        });
        node.next = attempts.take();
        *attempts = Some(node);
        true
    }

    pub(crate) fn settle_attempt(&self, emission: SignalingEmissionId) {
        let mut attempts = self.attempts.lock();
        let mut link = &mut *attempts;
        loop {
            if link
                .as_ref()
                .is_some_and(|known| known.emission == emission)
            {
                let mut removed = link.take().expect("matched emission custody");
                *link = removed.next.take();
                return;
            }
            match link.as_mut() {
                Some(known) => link = &mut known.next,
                None => return,
            }
        }
    }

    /// Fence one exact physical copy without fencing a successor that reuses
    /// the peer-visible attempt correlation. The attempt is an additional
    /// stale-identity check; the process-local emission id is the authority
    /// for the retained node.
    #[cfg(test)]
    pub(crate) fn fence_emission(&self, emission: SignalingEmissionId, attempt: &str) -> bool {
        let mut attempts = self.attempts.lock();
        let mut cursor = attempts.as_deref_mut();
        while let Some(known) = cursor {
            if known.emission == emission && known.attempt == attempt {
                known.fenced = true;
                return true;
            }
            cursor = known.next.as_deref_mut();
        }
        false
    }

    /// Settle one exact guard node and release its carrier-instance custody.
    /// Returns whether this guard owned the exact `(emission, attempt)` pair.
    pub(crate) fn settle_emission(&self, emission: SignalingEmissionId, attempt: &str) -> bool {
        let mut attempts = self.attempts.lock();
        let mut link = &mut *attempts;
        loop {
            if link
                .as_ref()
                .is_some_and(|known| known.emission == emission && known.attempt == attempt)
            {
                let mut removed = link.take().expect("matched exact emission custody");
                *link = removed.next.take();
                return true;
            }
            match link.as_mut() {
                Some(known) => link = &mut known.next,
                None => return false,
            }
        }
    }

    /// Settle the exact guard node, then notify state of a terminal carrier
    /// copy after the guard lock is released.  The state call is exact and
    /// idempotent: an outcome may already have removed its carrier node, while
    /// a lifecycle-fenced late callback still needs the acknowledgement.
    pub(crate) fn settle_attempt_and_acknowledge(
        &self,
        state: &NetworkState,
        emission: SignalingEmissionId,
        attempt: &str,
        instance: RecoveryCarrierInstance,
    ) {
        self.settle_attempt(emission);
        if state.carrier_emission_is_terminal(emission, attempt) {
            state.acknowledge_terminal_carrier_emission(emission, attempt, instance);
        }
    }

    /// Claim the exact physical copy being pulled from this carrier.
    ///
    /// Attempts are peer-visible strings and may be reused by independent
    /// emissions.  The list is newest-first, so the last matching unclaimed
    /// node is the oldest funded copy and is the one a FIFO carrier pull must
    /// consume.  The returned opaque id is carried to the provider boundary;
    /// no later operation is allowed to resolve a copy by attempt name.
    pub(crate) fn claim_attempt(&self, attempt: &str) -> Option<SignalingEmissionId> {
        if self.detached.load(Ordering::Acquire) {
            return None;
        }
        let mut attempts = self.attempts.lock();
        if self.detached.load(Ordering::Acquire) {
            return None;
        }
        let mut candidate = None;
        let mut cursor = attempts.as_deref();
        while let Some(known) = cursor {
            if known.attempt == attempt && !known.claimed && !known.fenced {
                candidate = Some(known.emission);
            }
            cursor = known.next.as_deref();
        }
        let emission = candidate?;
        let mut cursor = attempts.as_deref_mut();
        while let Some(known) = cursor {
            if known.emission == emission && known.attempt == attempt {
                known.claimed = true;
                return Some(emission);
            }
            cursor = known.next.as_deref_mut();
        }
        None
    }

    /// Return one exact fenced physical copy for a delayed carrier pull.
    ///
    /// Lifecycle settlement deliberately leaves fenced records in the guard
    /// until the carrier observes its queued value.  This is the only lookup
    /// permitted on that delayed path: it is still an opaque emission token,
    /// never an attempt-name re-admission or a successor selection.
    pub(crate) fn fenced_emission_for(&self, attempt: &str) -> Option<SignalingEmissionId> {
        let attempts = self.attempts.lock();
        let mut candidate = None;
        let mut cursor = attempts.as_deref();
        while let Some(known) = cursor {
            if known.attempt == attempt && known.fenced && !known.claimed {
                // Nodes are newest-first; a FIFO carrier pull must consume the
                // oldest delayed copy before the newer one, just like
                // claim_attempt does for live copies.
                candidate = Some(known.emission);
            }
            cursor = known.next.as_deref();
        }
        candidate
    }

    /// Claim one physical copy, then run state-side admission after releasing
    /// the guard lock. The callback is deliberately outside the lock:
    /// admission may synchronously settle or fence this exact emission, and
    /// allowing callback reentry while `attempts` is held would self-deadlock.
    /// The callback receives the already-claimed opaque token, so it cannot
    /// select a successor by the peer-visible attempt string.
    pub(crate) fn claim_attempt_with<R>(
        &self,
        attempt: &str,
        admit: impl FnOnce(SignalingEmissionId) -> R,
    ) -> Option<(SignalingEmissionId, R)> {
        if self.detached.load(Ordering::Acquire) {
            return None;
        }
        let emission = {
            let mut attempts = self.attempts.lock();
            if self.detached.load(Ordering::Acquire) {
                return None;
            }
            let mut candidate = None;
            let mut cursor = attempts.as_deref();
            while let Some(known) = cursor {
                if known.attempt == attempt && !known.claimed && !known.fenced {
                    candidate = Some(known.emission);
                }
                cursor = known.next.as_deref();
            }
            let emission = candidate?;
            let mut cursor = attempts.as_deref_mut();
            while let Some(known) = cursor {
                if known.emission == emission && known.attempt == attempt {
                    known.claimed = true;
                    break;
                }
                cursor = known.next.as_deref_mut();
            }
            emission
        };
        let result = admit(emission);
        Some((emission, result))
    }

    pub(crate) fn fence_attempt(&self, attempt: &str) {
        let mut attempts = self.attempts.lock();
        let mut cursor = attempts.as_deref_mut();
        while let Some(known) = cursor {
            if known.attempt == attempt {
                known.fenced = true;
            }
            cursor = known.next.as_deref_mut();
        }
    }

    pub(crate) fn clear_attempt(&self, attempt: &str) {
        // Do not erase a queued carrier's exact record here.  The state-side
        // fence has already happened; retaining this funded node until the
        // delayed physical pull acknowledges it is what releases the matching
        // carrier-instance custody without allowing a fresh admission.
        self.fence_attempt(attempt);
    }

    pub(crate) fn bind_event_id(
        &self,
        attempt: &str,
        event_id: &str,
    ) -> Option<SignalingEmissionId> {
        let key = event_key(event_id)?;
        let mut attempts = self.attempts.lock();
        let mut candidate = None;
        let mut cursor = attempts.as_deref_mut();
        while let Some(known) = cursor {
            if known.attempt == attempt && known.claimed && known.event_id.is_none() {
                // The same Nostr event id may be observed for two
                // process-local emissions.  Never return an already
                // bound node: the next unbound node gets its own exact
                // custody and remains independently settleable.
                candidate = Some(known.emission);
            }
            cursor = known.next.as_deref_mut();
        }
        let emission = candidate?;
        let mut cursor = attempts.as_deref_mut();
        while let Some(known) = cursor {
            if known.emission == emission && known.attempt == attempt {
                known.event_id = Some(key);
                return Some(emission);
            }
            cursor = known.next.as_deref_mut();
        }
        None
    }

    pub(crate) fn bind_admission_source(&self, source: AdmissionSource, attempt: &str) -> bool {
        let mut attempts = self.attempts.lock();
        let mut candidate = None;
        let mut cursor = attempts.as_deref();
        while let Some(known) = cursor {
            if known.attempt == attempt && known.claimed && known.source.is_none() {
                candidate = Some(known.emission);
            }
            cursor = known.next.as_deref();
        }
        let Some(emission) = candidate else {
            return false;
        };
        let mut cursor = attempts.as_deref_mut();
        while let Some(known) = cursor {
            if known.emission == emission && known.attempt == attempt {
                known.source = Some(source);
                return true;
            }
            cursor = known.next.as_deref_mut();
        }
        false
    }

    pub(crate) fn emission_for_source(
        &self,
        source: AdmissionSource,
    ) -> Option<SignalingEmissionId> {
        let attempts = self.attempts.lock();
        let mut cursor = attempts.as_deref();
        while let Some(known) = cursor {
            if known.source == Some(source) {
                return Some(known.emission);
            }
            cursor = known.next.as_deref();
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn emission_for_event(
        &self,
        attempt: &str,
        event_id: &str,
    ) -> Option<SignalingEmissionId> {
        let key = event_key(event_id)?;
        let attempts = self.attempts.lock();
        let mut cursor = attempts.as_deref();
        while let Some(known) = cursor {
            if known.attempt == attempt && known.event_id == Some(key) {
                return Some(known.emission);
            }
            cursor = known.next.as_deref();
        }
        None
    }

    pub(crate) fn track_recovery(&self, id: RecoveryPublishId) -> bool {
        if self.detached.load(Ordering::Acquire) {
            return false;
        }
        let mut recoveries = self.recoveries.lock();
        if self.detached.load(Ordering::Acquire) {
            return false;
        }
        let mut cursor = recoveries.as_deref();
        while let Some(known) = cursor {
            if known.id == id {
                return true;
            }
            cursor = known.next.as_deref();
        }
        let Some(scope) = self.scope.as_ref() else {
            return false;
        };
        let Ok(claim) = ResourceClaim::try_from_entries([
            (
                crate::resource::ResourceClass::AccountedMemoryBytes,
                u64::try_from(std::mem::size_of::<GuardedRecovery>()).unwrap_or(u64::MAX),
            ),
            (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
        ]) else {
            return false;
        };
        let Ok(lease) = scope.acquire(claim) else {
            return false;
        };
        let mut node = Box::new(GuardedRecovery {
            id,
            _lease: lease,
            next: None,
        });
        node.next = recoveries.take();
        *recoveries = Some(node);
        true
    }

    pub(crate) fn settle_recovery(&self, id: RecoveryPublishId) {
        let mut recoveries = self.recoveries.lock();
        let mut link = &mut *recoveries;
        loop {
            if link.as_ref().is_some_and(|known| known.id == id) {
                let mut removed = link.take().expect("matched recovery custody");
                *link = removed.next.take();
                return;
            }
            match link.as_mut() {
                Some(known) => link = &mut known.next,
                None => return,
            }
        }
    }

    /// Release every exact record owned by this carrier instance now.  This is
    /// used by canonical self-eviction/reconcile before the driver task has
    /// necessarily observed shutdown; it is idempotent because custody is
    /// removed from the intrusive lists before any callbacks are made.
    pub(crate) fn detach(&self) {
        if self.detached.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(state) = self.state.upgrade() else {
            self.recoveries.lock().take();
            self.attempts.lock().take();
            return;
        };
        let mut recoveries = self.recoveries.lock().take();
        while let Some(mut recovery) = recoveries {
            recoveries = recovery.next.take();
            if let Some(instance) = self.instance {
                state.record_recovery_carrier(recovery.id, instance, false);
            }
        }
        let mut attempts = self.attempts.lock().take();
        while let Some(mut attempt) = attempts {
            attempts = attempt.next.take();
            if let Some(instance) = self.instance {
                let record = state.record_carrier_emission(
                    attempt.emission,
                    &attempt.attempt,
                    instance,
                    false,
                );
                if record == crate::engine::state::CarrierEmissionRecord::FinalRefusal {
                    state.settle_final_refusal_carrier(attempt.emission, &attempt.attempt);
                } else if record == crate::engine::state::CarrierEmissionRecord::Stale {
                    state.acknowledge_terminal_carrier_emission(
                        attempt.emission,
                        &attempt.attempt,
                        instance,
                    );
                }
            }
        }
    }
}

fn event_key(event_id: &str) -> Option<[u8; 32]> {
    let bytes = event_id.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        key[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(key)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl Drop for CarrierInstanceGuard {
    fn drop(&mut self) {
        self.detach();
    }
}

/// How a carrier came by the device id in a presence or withdrawal report.
///
/// Re-exported from the signaling crate rather than restated here: the driver
/// that saw the message arrive is the only thing that can honestly decide this,
/// so the type belongs where the decision is made and a second copy on this side
/// would be a place for the two to disagree.
///
/// What this side does with it: **nothing, and that is the current design.** An
/// earlier revision held a withdrawal back while some other attach still
/// observed the device, and the map that decided it was deleted rather than
/// repaired — see [`SignalingRuntime`]. The value now travels with the report,
/// unread, to the engine's withdrawal arm, which is the one place entitled to
/// act on it: a [`CarrierAttribution::SenderClaimed`] withdrawal is
/// teardown-inert in every state, and a [`CarrierAttribution::CarrierObserved`]
/// one may cancel an exact unpromoted attempt and never a promoted session.
///
/// So a hostile payload naming a third party *is* delivered here as a
/// withdrawal for that third party, on every network carrier. It is inert when
/// it lands, which is a stronger place to stop it than a suppression rule
/// keyed on ids an attacker chooses. Neither value mints authority — a device is
/// admitted by endpoint authentication and policy, never by being named here.
pub(crate) use myownmesh_signaling::CarrierAttribution;

/// The ephemeral transport signal kinds this ingress admits.
///
/// `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md` §2.2 defines the ephemeral
/// transport signal as a typed, bounded union unavailable as a generic
/// application byte carrier. This is that union as this codebase inhabits it,
/// and its closure is the implementation refinement `FORMAL-PROOFS.md` Theorem
/// 11.1 asks for: the theorem holds only if the signaling union has no variant
/// containing application bytes and an application consumer, and this has no
/// such variant. It equally has no durable-authority, roster-mutation or
/// durable-leave kind, which is how a carrier observation stays unable to grant,
/// revoke or record membership however the carrier is fed.
///
/// It is decided from the carrier value **before** the domain parse, and it is
/// read in production — the engine's inbound handler dispatches on it and it is
/// the kind carried on every diagnostic — so it is a working part rather than a
/// tag kept alive to look complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EphemeralSignal {
    /// A carrier saw a device advertise itself. Discovery evidence only: it
    /// records nothing durable and admits nobody.
    Presence,
    /// A carrier stopped seeing a device, or a device said it was going.
    /// Reachability evidence about the live attempt — never the roster, never a
    /// durable fact, and never enough to retire an authenticated session.
    Withdrawal,
    /// Connect intent: the offer that opens one transport attempt.
    ConnectIntent,
    /// The answer to one transport attempt.
    ConnectAnswer,
    /// One ICE candidate hint for an attempt in progress.
    CandidateHint,
}

impl EphemeralSignal {
    /// Stable name for traces and diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Presence => "presence",
            Self::Withdrawal => "withdrawal",
            Self::ConnectIntent => "connect_intent",
            Self::ConnectAnswer => "connect_answer",
            Self::CandidateHint => "candidate_hint",
        }
    }
}

/// One carrier observation whose kind has been decided and whose domain value
/// does not exist yet.
///
/// Built by a driver pump directly from what the carrier reported, which is why
/// the constructors take the carrier's own shape rather than anything the engine
/// understands. The kind is fixed at construction, so by the time
/// [`Self::into_ingress`] runs the admission has already happened and cannot be
/// influenced by the parse.
///
/// No `Debug`, deliberately: this holds the undecided carrier message whole —
/// SDP body, candidate string, device ids — one step upstream of the point where
/// [`EphemeralIngress`]'s redacting formatter takes over. A derive here would
/// hand that payload a formatter before the redaction exists.
#[must_use = "an observation that is never delivered is a message silently dropped"]
pub(crate) struct CarrierObservation {
    carrier: SignalingCarrier,
    instance: CarrierInstance,
    signal: EphemeralSignal,
    body: ObservationBody,
    hub: Option<HubIngressWitness>,
}

pub(crate) struct HubIngressWitness {
    ticket: super::hub_introduction::IntroductionTicket,
    carrier: super::peer_registry::WeakPeerOwnerToken,
}

impl HubIngressWitness {
    pub(crate) fn ticket(&self) -> super::hub_introduction::IntroductionTicket {
        self.ticket
    }

    /// Recheck the original carrier after each asynchronous native boundary.
    /// This is move-only provenance, not ownership or a device-id lookup.
    /// The caller must separately recheck the ticket's original deadline.
    pub(crate) fn is_current(&self, state: &NetworkState) -> bool {
        self.carrier
            .upgrade()
            .is_some_and(|owner| state.peers.has_usable_authenticated_current(&owner))
    }
}

/// What the carrier actually reported. Private: the parse below is the only
/// consumer, and keeping the shape closed here is what stops a caller from
/// assembling a domain value without an admission. No `Debug`, for the reason
/// given on [`CarrierObservation`]: this is where the payload lives.
enum ObservationBody {
    Presence {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Withdrawal {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Directed {
        from: String,
        message: SignalingMessage,
    },
}

impl CarrierObservation {
    /// Measure the carrier-owned value while it is still in its raw shape.
    ///
    /// This is separate from [`EphemeralIngress::retained_claim`]: the raw
    /// observation is admitted before parsing, while the parsed value is
    /// admitted again only if the inbound mailbox retains it.
    /// This core boundary does not retroactively account allocations already
    /// made by the WebSocket, mDNS, or Nostr carrier libraries.
    fn raw_claim(&self) -> Result<ResourceClaim, ResourceMailboxItemError> {
        let (bytes, _queued, allocations) = match &self.body {
            ObservationBody::Presence { device_id, .. }
            | ObservationBody::Withdrawal { device_id, .. } => {
                strings_measure([device_id.as_str()])?
            }
            ObservationBody::Directed { from, message } => match message {
                SignalingMessage::Announce { peer_id } | SignalingMessage::Leave { peer_id } => {
                    strings_measure([from.as_str(), peer_id.as_str()])?
                }
                SignalingMessage::Offer {
                    peer_id,
                    offer_id,
                    sdp,
                }
                | SignalingMessage::Answer {
                    peer_id,
                    offer_id,
                    sdp,
                } => strings_measure([
                    from.as_str(),
                    peer_id.as_str(),
                    offer_id.as_str(),
                    sdp.as_str(),
                ])?,
                SignalingMessage::Candidate {
                    peer_id,
                    candidate,
                    offer_id,
                    sdp_mid,
                    username_fragment,
                    ..
                } => strings_measure(
                    [
                        Some(from.as_str()),
                        Some(peer_id.as_str()),
                        Some(candidate.as_str()),
                        Some(offer_id.as_str()),
                        sdp_mid.as_deref(),
                        username_fragment.as_deref(),
                    ]
                    .into_iter()
                    .flatten(),
                )?,
            },
        };
        let fixed = std::mem::size_of::<Self>().checked_add(bytes).ok_or(
            ResourceMailboxItemError::Claim(
                crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
                },
            ),
        )?;
        let allocations = allocations
            .checked_add(1)
            .ok_or(ResourceMailboxItemError::Claim(
                crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                },
            ))?;
        let fixed = u64::try_from(fixed).map_err(|_| {
            ResourceMailboxItemError::Claim(
                crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
                },
            )
        })?;
        let parsing = u64::try_from(bytes).map_err(|_| {
            ResourceMailboxItemError::Claim(
                crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::ParsingOrCpuWork,
                },
            )
        })?;
        let allocations = u64::try_from(allocations).map_err(|_| {
            ResourceMailboxItemError::Claim(
                crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                },
            )
        })?;
        ResourceClaim::try_from_entries([
            (crate::resource::ResourceClass::AccountedMemoryBytes, fixed),
            (crate::resource::ResourceClass::ParsingOrCpuWork, parsing),
            (
                crate::resource::ResourceClass::OpaqueDependencyResidual,
                allocations,
            ),
        ])
        .map_err(Into::into)
    }

    /// Parse into the engine's domain value, keeping the provenance.
    ///
    /// The only route from a carrier value to a [`SignalingInbound`] the engine
    /// can be handed, and it is reachable only from a value already admitted.
    pub(super) fn into_ingress(self) -> EphemeralIngress {
        let Self {
            carrier,
            instance,
            signal,
            body,
            hub,
        } = self;
        let (inbound, attribution) = match body {
            ObservationBody::Presence {
                device_id,
                attribution,
            } => (SignalingInbound::PeerAnnounced { device_id }, attribution),
            ObservationBody::Withdrawal {
                device_id,
                attribution,
            } => (SignalingInbound::PeerLeft { device_id }, attribution),
            // A directed message is attributed to the sender the carrier routed
            // from, which for the two network carriers is itself a decoded
            // field — hence `SenderClaimed`. See [`parse_directed`].
            ObservationBody::Directed { from, message } => (
                parse_directed(from, message),
                CarrierAttribution::SenderClaimed,
            ),
        };
        EphemeralIngress {
            carrier,
            instance,
            signal,
            attribution,
            inbound,
            dedup: None,
            hub,
        }
    }
}

/// An admitted, parsed ephemeral transport signal on its way to the engine.
///
/// This is what the engine's inbound mailbox carries. The carrier, the attach
/// instance and the attribution travel with the value rather than being computed
/// and discarded at the boundary, because "retained provenance" only means
/// something if the consumer can still see it.
pub(crate) struct EphemeralIngress {
    carrier: SignalingCarrier,
    instance: CarrierInstance,
    signal: EphemeralSignal,
    attribution: CarrierAttribution,
    inbound: SignalingInbound,
    dedup: Option<DedupToken>,
    hub: Option<HubIngressWitness>,
}

/// Redacting, and the derive it replaces was the reason.
///
/// A derived `Debug` prints the whole [`SignalingInbound`]: the full SDP body of
/// an offer or answer, the candidate string with its addresses, and the device
/// id. Those reach a log the moment anything formats a value with `{:?}` — a
/// `tracing` field, an `unwrap` message, a panic payload — and none of those call
/// sites has to be reviewed for it to happen.
///
/// What remains is bounded and closed — three field-less enums, a process-local
/// counter, and a `&'static str` — so nothing peer-supplied can appear here
/// however the peer builds its message. `finish_non_exhaustive` prints the
/// trailing `..`, so a reader sees that something was withheld rather than
/// believing the value is this small. The payload is not lost, only unprinted.
impl std::fmt::Debug for EphemeralIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralIngress")
            // The stable names rather than the derived variant spellings, so a
            // `Debug` line and a `tracing` line read the same way.
            .field("carrier", &self.carrier.name())
            .field("instance", &self.instance.0)
            .field("signal", &self.signal.name())
            .field("attribution", &self.attribution)
            .field("kind", &self.inbound.kind_name())
            .finish_non_exhaustive()
    }
}

impl EphemeralIngress {
    /// Engine rechecks this exact carrier AND the returned ticket at dequeue,
    /// before any asynchronous offer/answer work can begin. Non-Hub inputs
    /// preserve their existing carrier policy.
    pub(crate) fn introduction_ticket(
        &self,
    ) -> Option<super::hub_introduction::IntroductionTicket> {
        self.hub.as_ref().map(|witness| witness.ticket)
    }

    pub(crate) fn introduction_carrier_is_current(&self, state: &NetworkState) -> bool {
        match (&self.hub, self.carrier) {
            (Some(witness), SignalingCarrier::Hub) => witness.is_current(state),
            (None, SignalingCarrier::Hub) => false,
            (None, _) => true,
            _ => false,
        }
    }
    /// Which carrier observed it.
    pub(crate) fn carrier(&self) -> SignalingCarrier {
        self.carrier
    }

    /// Which attach of that carrier observed it.
    ///
    /// `cfg(test)`: production acts on the instance only inside this module,
    /// where the runtime owns the value and reads it off the field. The controls
    /// read it through here to assert what the engine would see if it ever
    /// asked, which is the one question the field access cannot answer.
    #[cfg(test)]
    pub(crate) fn instance(&self) -> CarrierInstance {
        self.instance
    }

    /// The kind this input was admitted as, before it was parsed.
    pub(crate) fn signal(&self) -> EphemeralSignal {
        self.signal
    }

    /// How the carrier came by the device id.
    ///
    /// **Production, and narrowly so.** One consumer outside this module: the
    /// carrier-withdrawal arm in `engine/mod.rs`, where a `SenderClaimed`
    /// withdrawal is teardown-inert in every session state and only a
    /// `CarrierObserved` one may cancel an exact unpromoted attempt — never an
    /// entry holding a promoted `SessionCapability`. **That decision is not
    /// made here.** This module admits and delivers; it owns no view of the
    /// Peer Session lifecycle and could not decide a teardown if it wanted to,
    /// which is why the value has to survive the boundary rather than being
    /// consumed at it. Nothing else reads it.
    pub(crate) fn attribution(&self) -> CarrierAttribution {
        self.attribution
    }

    /// The parsed input, borrowed.
    pub(crate) fn inbound(&self) -> &SignalingInbound {
        &self.inbound
    }

    /// Move the admitted input and its exact Hub witness together. The engine
    /// keeps the witness across native awaits; ordinary carriers return None.
    pub(crate) fn into_inbound_with_introduction(
        self,
    ) -> (SignalingInbound, Option<HubIngressWitness>) {
        (self.inbound, self.hub)
    }

    pub(crate) fn dedup_token(&self) -> Option<DedupToken> {
        self.dedup.clone()
    }

    /// Variant name for driver-liveness traces — cheap, no payload.
    pub(crate) fn kind_name(&self) -> &'static str {
        self.inbound.kind_name()
    }

    fn with_dedup_token(mut self, token: DedupToken) -> Self {
        self.dedup = Some(token);
        self
    }
}

#[cfg(test)]
impl EphemeralIngress {
    /// Build a delivered value without a runtime, for engine controls that hand
    /// one straight to a handler instead of driving a carrier.
    ///
    /// **This bypasses the runtime, not the admission.** The kind still comes
    /// from the same constructors production uses, and the parse is still
    /// [`CarrierObservation::into_ingress`], so a control cannot manufacture a
    /// shape production could not produce — it only skips the de-duplication the
    /// runtime would have applied on the way past, which is exactly what a
    /// handler-level control is not testing.
    fn for_control(
        carrier: SignalingCarrier,
        signal: EphemeralSignal,
        body: ObservationBody,
    ) -> Self {
        CarrierObservation {
            carrier,
            instance: CarrierInstance(0),
            signal,
            body,
            hub: None,
        }
        .into_ingress()
    }

    /// A carrier saw a device advertise itself. See [`Self::for_control`].
    ///
    /// The attribution is a parameter for the same reason it is on
    /// [`Self::withdrawal_for_control`], and for one more: only `LocalBroker`
    /// produces a carrier-observed presence, so a control that could build only
    /// that shape could not describe an mDNS or Nostr announce at all.
    pub(crate) fn presence_for_control(
        carrier: SignalingCarrier,
        device_id: &str,
        attribution: CarrierAttribution,
    ) -> Self {
        Self::for_control(
            carrier,
            EphemeralSignal::Presence,
            ObservationBody::Presence {
                device_id: device_id.to_string(),
                attribution,
            },
        )
    }

    /// A carrier stopped seeing a device, or a payload said it had.
    ///
    /// The attribution is a parameter and not a default, because it is the one
    /// thing the engine's withdrawal arm reads: a control that could only build
    /// the carrier-observed shape could not tell the two rules apart. See
    /// [`Self::for_control`].
    pub(crate) fn withdrawal_for_control(
        carrier: SignalingCarrier,
        device_id: &str,
        attribution: CarrierAttribution,
    ) -> Self {
        Self::for_control(
            carrier,
            EphemeralSignal::Withdrawal,
            ObservationBody::Withdrawal {
                device_id: device_id.to_string(),
                attribution,
            },
        )
    }

    /// A peer addressed us directly. See [`Self::for_control`].
    pub(crate) fn directed_for_control(
        carrier: SignalingCarrier,
        from: &str,
        message: SignalingMessage,
    ) -> Self {
        Self::for_control(
            carrier,
            admit(&message),
            ObservationBody::Directed {
                from: from.to_string(),
                message,
            },
        )
    }
}

unsafe impl ResourceMailboxItem for EphemeralIngress {
    fn measured_claim(
        &self,
    ) -> std::result::Result<MailboxMeasurement<Self>, ResourceMailboxItemError> {
        // Scalar provenance and the optional introduction ticket/weak exact
        // carrier witness are inline in size_of::<Self>(). Cloning a weak
        // witness allocates no new backing storage and grants no authority;
        // the existing peer/session owners retain their own resource custody.
        // Dynamic retained strings are the inbound value's own measurement.
        let measure = self.inbound.string_measure()?;
        MailboxMeasurement::from_parts(measure.0, measure.1, measure.2)
    }
}

/// Admit one carrier message as an ephemeral transport signal, before it is
/// translated.
///
/// Exhaustive with no wildcard arm, by design: a new carrier variant must not be
/// able to reach the engine by inheriting some default kind. Adding one to
/// [`SignalingMessage`] breaks this match, and the break is the review — a
/// variant that carries a durable signed fact has no kind here to choose and
/// needs its own ingress rather than a seat in this one.
fn admit(message: &SignalingMessage) -> EphemeralSignal {
    match message {
        SignalingMessage::Announce { .. } => EphemeralSignal::Presence,
        SignalingMessage::Leave { .. } => EphemeralSignal::Withdrawal,
        SignalingMessage::Offer { .. } => EphemeralSignal::ConnectIntent,
        SignalingMessage::Answer { .. } => EphemeralSignal::ConnectAnswer,
        SignalingMessage::Candidate { .. } => EphemeralSignal::CandidateHint,
    }
}

/// Admit one outbound emission.
///
/// The boundary is two-sided for the same reason it is exhaustive: a new
/// outbound variant must choose a kind rather than acquire one, where the fan-out
/// can see it rather than at whichever driver happens to carry it.
pub(crate) fn outbound_signal(outbound: &SignalingOutbound) -> EphemeralSignal {
    match outbound {
        SignalingOutbound::Announce | SignalingOutbound::RecoveryAnnounce { .. } => {
            EphemeralSignal::Presence
        }
        SignalingOutbound::Leave => EphemeralSignal::Withdrawal,
        SignalingOutbound::Offer { .. } => EphemeralSignal::ConnectIntent,
        SignalingOutbound::Answer { .. } => EphemeralSignal::ConnectAnswer,
        SignalingOutbound::Candidate { .. } => EphemeralSignal::CandidateHint,
    }
}

/// Translate one directed carrier message into the engine's inbound shape.
///
/// **Private, and reachable only through [`CarrierObservation::into_ingress`].**
/// This is the domain parse the migration matrix requires admission to precede;
/// a `pub` version, or one beside the driver pumps, would let a caller skip
/// straight to a domain value and the ordering would be a convention again.
///
/// # `from` wins over the body, and what that is worth by carrier
///
/// Every variant with a device id in its body is attributed to `from` instead.
/// On `LocalBroker` that is genuine routing attribution — the broker stamps the
/// sending handle's registered id and the sender cannot choose it. On Nostr and
/// mDNS it is a decoded field of the signaling envelope, never checked against
/// the relay event's pubkey or the wire source, so there it buys consistency
/// rather than proof; that is why a directed observation is delivered as
/// [`CarrierAttribution::SenderClaimed`].
///
/// The load-bearing part does not depend on either field being trustworthy:
/// **neither one mints authority**, because no kind in [`EphemeralSignal`] could.
/// What the rule buys everywhere is that when the two fields disagree — exactly
/// when somebody is naming a third party — the effect lands on the sender rather
/// than on a device that sent nothing.
fn parse_directed(from: String, message: SignalingMessage) -> SignalingInbound {
    match message {
        SignalingMessage::Announce { peer_id } => {
            let _ = peer_id;
            SignalingInbound::PeerAnnounced { device_id: from }
        }
        SignalingMessage::Leave { peer_id } => {
            let _ = peer_id;
            SignalingInbound::PeerLeft { device_id: from }
        }
        // `offer_id` is the sender's attempt correlation and it is kept, not
        // dropped. Discarding it here is what left de-duplication with nothing
        // but content to key on, so a candidate that recurs verbatim on a
        // replacement attempt was indistinguishable from the second relay's
        // copy of the retired one — and the live copy lost.
        SignalingMessage::Offer { sdp, offer_id, .. } => SignalingInbound::Offer {
            device_id: from,
            attempt: offer_id,
            sdp,
        },
        SignalingMessage::Answer { sdp, offer_id, .. } => SignalingInbound::Answer {
            device_id: from,
            attempt: offer_id,
            sdp,
        },
        SignalingMessage::Candidate {
            candidate,
            offer_id,
            sdp_mid,
            sdp_mline_index,
            username_fragment,
            ..
        } => SignalingInbound::Candidate {
            device_id: from,
            attempt: offer_id,
            candidate: LocalIceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
                username_fragment,
            },
        },
    }
}

/// What became of one value offered to the engine.
///
/// Typed outcomes rather than a bool distinguish provider refusal, mailbox
/// pressure, duplicates, shutdown, and the one case where the engine has the value.
/// No downstream reducer effect occurs for any non-accepted outcome.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Delivered {
    /// The engine's mailbox took it and will hand it to the handler.
    Accepted,
    /// The mailbox refused the value under local pressure or because it was
    /// unrepresentable. Nothing downstream happened; a later copy may recover.
    Refused,
    /// Provider custody could not be preclaimed, so no allocation, key
    /// retention, or reducer dispatch was attempted.
    Unavailable,
    /// The exact key is already live on another carrier instance.
    Duplicate,
    /// The engine is gone. The driver's pump exits.
    Closed,
}

/// One retained de-duplication node, the attempt key it carries, and the lease
/// that funds the node and its owned key bytes.
///
/// The lease is held for exactly as long as the key is remembered and released
/// by the same `Drop` that forgets it, so the list cannot outlive what pays for
/// it. The `next` link is inline in the provider-funded node: there is no
/// separately allocated container whose capacity could outrun its claims.
/// `_lease` is never read: holding it *is* the effect.
///
/// `attempt` is what makes the key mean something. Without it the key would be
/// pure content, and two different questions would be indistinguishable: "is
/// this the second relay's copy of the offer I already took?" and "is this the
/// same host candidate again, on the attempt that replaced the one I retired?".
/// The first must be dropped and the second must be delivered.
struct SeenKey {
    key: DedupKey,
    token: std::sync::Weak<crate::runtime::peer_session::DedupTokenInner>,
    _lease: ResourceLease,
    next: Option<Box<SeenKey>>,
}

/// Exact, length-framed bytes for one duplicate-sensitive signal.
///
/// Hashes are intentionally not used here.  A collision in a de-duplication
/// key is a false refusal of live signaling, so equality must compare the
/// complete attempt and payload identity.  Length framing also prevents field
/// boundary ambiguity (for example, `ab` + `c` versus `a` + `bc`).
#[derive(Clone, PartialEq, Eq)]
struct DedupKey {
    attempt: Box<str>,
    payload: Box<[u8]>,
}

struct DedupKeyPlan<'a> {
    attempt: &'a str,
    payload_bytes: usize,
}

impl DedupKeyPlan<'_> {
    fn retained_bytes(&self) -> Option<u64> {
        u64::try_from(
            std::mem::size_of::<SeenKey>()
                .checked_add(self.attempt.len())?
                .checked_add(self.payload_bytes)?,
        )
        .ok()
    }
}

/// The Signaling Node's runtime owner for one network.
///
/// Owns two things, and each is one this side of the boundary is entitled to:
/// the [`CarrierInstance`] receipts it mints at attach, and cross-carrier
/// de-duplication. It owns no roster decision, no endpoint identity and no
/// application delivery, and it has no way to acquire one — everything it can
/// emit is a [`SignalingInbound`], which is the [`EphemeralSignal`] union and
/// nothing else.
///
/// # It used to own availability, and removing that was the correction
///
/// An earlier revision kept a per-device map of which attaches currently
/// observed each device, so a withdrawal could be held back while another
/// carrier still saw the peer. Three things were wrong with it and they
/// compounded:
///
/// - the map was keyed by **attacker-chosen device ids** and capped by an
///   invented constant, so filling it with 2,048 fabricated ids evicted real
///   peers and turned the next withdrawal into "the last observation";
/// - none of that retained state was funded, so the cap was the only bound and
///   the cap was a guess;
/// - an attach that stopped never removed its receipts, so a dead carrier's
///   observation suppressed a live carrier's withdrawal forever.
///
/// The map is gone rather than repaired. What it was protecting no longer needs
/// protecting: a delivered withdrawal can now cancel only an attempt that never
/// became a session, which is exactly what a withdrawal is allowed to do, so
/// suppressing one on the strength of another carrier's *claim* bought a
/// refinement at the price of an unbounded untrusted keyspace. **No untrusted
/// observation record is retained here**: the only per-attach state is the
/// exact funded guard used for carrier-emission and recovery settlement.
pub(crate) struct SignalingRuntime {
    tx: ResourceMailboxSender<EphemeralIngress>,
    /// Funds every retained de-duplication key and every weak guard index. The
    /// provider is the bound; this module names no count.
    scope: LocalApplicationResourceScope,
    instances: AtomicU64,
    dedup_instances: AtomicU64,
    seen: Mutex<Option<Box<SeenKey>>>,
    guards: Mutex<Option<Box<GuardIndex>>>,
}

struct GuardIndex {
    guard: Weak<CarrierInstanceGuard>,
    _lease: ResourceLease,
    next: Option<Box<GuardIndex>>,
}

fn guard_index_claim() -> Option<ResourceClaim> {
    let bytes = u64::try_from(std::mem::size_of::<GuardIndex>()).ok()?;
    ResourceClaim::try_from_entries([
        (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
    ])
    .ok()
}

/// Remove nodes whose exact lifecycle token has no remaining owner.
///
/// This runs under `SignalingRuntime::seen`, so duplicate admission and weak
/// token pruning remain one atomic operation. Each removed node drops its own
/// provider lease; no container capacity or side allocation is involved.
fn prune_seen(seen: &mut Option<Box<SeenKey>>) {
    let mut link = seen;
    loop {
        let remove = link
            .as_ref()
            .is_some_and(|entry| entry.token.strong_count() == 0);
        if remove {
            let mut removed = link.take().expect("matched stale seen node");
            *link = removed.next.take();
            continue;
        }
        match link.as_mut() {
            Some(entry) => link = &mut entry.next,
            None => return,
        }
    }
}

/// Remove one exact retained key by its lifecycle token identity.
fn remove_seen_for_token(
    seen: &mut Option<Box<SeenKey>>,
    token: &std::sync::Weak<crate::runtime::peer_session::DedupTokenInner>,
) {
    let mut link = seen;
    loop {
        let remove = link.as_ref().is_some_and(|entry| entry.token.ptr_eq(token));
        if remove {
            let mut removed = link.take().expect("matched seen token");
            *link = removed.next.take();
            return;
        }
        match link.as_mut() {
            Some(entry) => link = &mut entry.next,
            None => return,
        }
    }
}

fn next_non_wrapping(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .ok()
}

impl SignalingRuntime {
    pub(crate) fn new(
        tx: ResourceMailboxSender<EphemeralIngress>,
        scope: LocalApplicationResourceScope,
    ) -> Arc<Self> {
        Arc::new(Self {
            tx,
            scope,
            instances: AtomicU64::new(0),
            dedup_instances: AtomicU64::new(0),
            seen: Mutex::new(None),
            guards: Mutex::new(None),
        })
    }

    /// Register one carrier attach and hand back its ingress.
    ///
    /// The receipt is minted here and nowhere else, which is what makes it a
    /// receipt: a pump cannot invent an instance, and two attaches of the same
    /// carrier are distinguishable without either of them naming anything.
    #[cfg(test)]
    pub(crate) fn attach(runtime: &Arc<Self>, carrier: SignalingCarrier) -> CarrierAttach {
        Self::attach_with_guard(runtime, carrier, Self::noop_guard(runtime))
    }

    pub(crate) fn attach_for_state(
        runtime: &Arc<Self>,
        carrier: SignalingCarrier,
        state: &Arc<NetworkState>,
        recovery_instance: Option<RecoveryCarrierInstance>,
    ) -> Option<CarrierAttach> {
        let instance = CarrierInstance(next_non_wrapping(&runtime.instances)?);
        let guard = CarrierInstanceGuard::for_state(state, recovery_instance);
        let lease = runtime.scope.acquire(guard_index_claim()?).ok()?;
        let mut index = Box::new(GuardIndex {
            guard: Arc::downgrade(&guard),
            _lease: lease,
            next: None,
        });
        let mut guards = runtime.guards.lock();
        index.next = guards.take();
        *guards = Some(index);
        Some(CarrierAttach {
            carrier,
            instance,
            runtime: Arc::clone(runtime),
            guard,
        })
    }

    /// Detach all current carrier guards synchronously. The weak registry is
    /// a provider-funded index; each guard still owns and settles its exact
    /// intrusive records, so a later task/drop cannot touch a successor
    /// generation.
    pub(crate) fn detach_guards(&self) {
        {
            let guards = self.guards.lock();
            let mut cursor = guards.as_deref();
            while let Some(entry) = cursor {
                if let Some(guard) = Weak::upgrade(&entry.guard) {
                    guard.detach();
                }
                cursor = entry.next.as_deref();
            }
        }
        self.prune_guard_index();
    }

    pub(crate) fn fence_attempt(&self, attempt: &str) {
        let guards = self.guards.lock();
        let mut cursor = guards.as_deref();
        while let Some(entry) = cursor {
            if let Some(guard) = Weak::upgrade(&entry.guard) {
                guard.fence_attempt(attempt);
            }
            cursor = entry.next.as_deref();
        }
    }

    pub(crate) fn clear_attempt(&self, attempt: &str) {
        {
            let guards = self.guards.lock();
            let mut cursor = guards.as_deref();
            while let Some(entry) = cursor {
                if let Some(guard) = Weak::upgrade(&entry.guard) {
                    guard.clear_attempt(attempt);
                }
                cursor = entry.next.as_deref();
            }
        }
        self.prune_guard_index();
    }

    /// Fence one exact emission across the registered carrier guards. Unlike
    /// [`Self::fence_attempt`], this cannot fence a successor using the same
    /// peer-visible attempt correlation.
    #[cfg(test)]
    pub(crate) fn fence_emission(&self, emission: SignalingEmissionId, attempt: &str) -> bool {
        let guards = self.guards.lock();
        let mut found = false;
        let mut cursor = guards.as_deref();
        while let Some(entry) = cursor {
            if let Some(guard) = Weak::upgrade(&entry.guard) {
                found |= guard.fence_emission(emission, attempt);
            }
            cursor = entry.next.as_deref();
        }
        found
    }

    /// Settle one exact emission on every registered guard and release only
    /// that physical copy's custody.
    pub(crate) fn settle_emission(&self, emission: SignalingEmissionId, attempt: &str) -> bool {
        let guards = self.guards.lock();
        let mut found = false;
        let mut cursor = guards.as_deref();
        while let Some(entry) = cursor {
            if let Some(guard) = Weak::upgrade(&entry.guard) {
                found |= guard.settle_emission(emission, attempt);
            }
            cursor = entry.next.as_deref();
        }
        drop(guards);
        self.prune_guard_index();
        found
    }

    fn prune_guard_index(&self) {
        let mut guards = self.guards.lock();
        let mut link = &mut *guards;
        loop {
            let remove = link
                .as_ref()
                .is_some_and(|entry| entry.guard.strong_count() == 0);
            if remove {
                let mut removed = link.take().expect("matched stale guard index");
                *link = removed.next.take();
                continue;
            }
            match link.as_mut() {
                Some(entry) => link = &mut entry.next,
                None => return,
            }
        }
    }

    #[cfg(test)]
    fn seen_len(&self) -> usize {
        let seen = self.seen.lock();
        let mut count = 0usize;
        let mut cursor = seen.as_deref();
        while let Some(entry) = cursor {
            count = count.saturating_add(1);
            cursor = entry.next.as_deref();
        }
        count
    }

    #[cfg(test)]
    fn noop_guard(runtime: &Arc<Self>) -> Arc<CarrierInstanceGuard> {
        let _ = runtime;
        CarrierInstanceGuard::noop(None)
    }

    #[cfg(test)]
    fn attach_with_guard(
        runtime: &Arc<Self>,
        carrier: SignalingCarrier,
        guard: Arc<CarrierInstanceGuard>,
    ) -> CarrierAttach {
        CarrierAttach {
            carrier,
            instance: CarrierInstance(
                next_non_wrapping(&runtime.instances)
                    .expect("test carrier-instance counter must not be exhausted"),
            ),
            runtime: Arc::clone(runtime),
            guard,
        }
    }

    /// Deliver an admitted observation, unless it is a duplicate the engine has
    /// already been handed.
    ///
    /// Returns a typed outcome. [`Delivered::Closed`] is the pump's signal to
    /// exit; [`Delivered::Refused`] and [`Delivered::Unavailable`] are
    /// fail-closed pressure outcomes that leave no reducer-visible value and
    /// allow a later copy to recover the connection. [`Delivered::Duplicate`]
    /// means an equal attempt-and-payload key is already live.
    ///
    /// # A key is retained only after its full claim is funded
    ///
    /// The full key claim is acquired before allocation and retention. If the
    /// mailbox then refuses the value, the retained key is removed immediately
    /// and its lease is released, so a retransmission can recover.
    ///
    /// "Accepted" is the mailbox taking it and nothing weaker. A send refused
    /// under pressure, or as unrepresentable, still returns the driver to its
    /// loop — signaling ingress is lossy on purpose — but it leaves no key,
    /// because nothing downstream happened for a later copy to be a duplicate
    /// of. That distinction is why [`Delivered`] is typed and `send`
    /// does not return a bool: the bool read "keep pumping" as "the engine has
    /// it"; typed outcomes preserve whether dispatch happened.
    ///
    /// The key-check-and-retain step runs under the `seen` lock. `send` is
    /// synchronous and nothing is awaited, so holding it is cheap and it makes
    /// the sequence atomic: two identical copies arriving on two carriers at
    /// once cannot both pass the check, which is the exact case a reservation
    /// would otherwise be needed for.
    fn deliver(&self, observation: CarrierObservation) -> Delivered {
        if observation.carrier == SignalingCarrier::Hub && observation.hub.is_none() {
            return Delivered::Refused;
        }
        // The carrier value is still raw here. Admit its bounded temporary
        // representation before parsing it into an engine value; pressure
        // therefore refuses before any parse/reducer hand-off.
        let raw_lease = match observation.raw_claim() {
            Ok(claim) => match self.scope.acquire(claim) {
                Ok(lease) => lease,
                Err(error) => {
                    trace!(?error, "raw signaling observation refused before parse");
                    return Delivered::Unavailable;
                }
            },
            Err(error) => {
                trace!(?error, "raw signaling observation is not representable");
                return Delivered::Unavailable;
            }
        };
        let ingress = observation.into_ingress();
        drop(raw_lease);
        if attempt_is_empty(&ingress) {
            trace!(
                kind = ingress.kind_name(),
                "empty attempt refused before reducer"
            );
            return Delivered::Refused;
        }
        let key_plan = if ingress.carrier.restamps_duplicates() {
            match dedup_key_plan(&ingress) {
                Ok(key_plan) => key_plan,
                Err(()) => {
                    trace!(kind = ingress.kind_name(), "invalid duplicate key refused");
                    return Delivered::Refused;
                }
            }
        } else {
            None
        };
        let Some(key_plan) = key_plan else {
            // Nothing to remember, so only the engine being gone matters.
            return self.send(ingress);
        };

        let Some(key_lease) = self.reserve_key(&key_plan) else {
            trace!(kind = ingress.kind_name(), "dedup key unfunded");
            return Delivered::Unavailable;
        };
        let Some(key) = dedup_key(&ingress, &key_plan) else {
            drop(key_lease);
            trace!(kind = ingress.kind_name(), "dedup key construction failed");
            return Delivered::Unavailable;
        };
        let Some(dedup_id) = next_non_wrapping(&self.dedup_instances) else {
            drop(key_lease);
            trace!(kind = ingress.kind_name(), "dedup id exhausted");
            return Delivered::Unavailable;
        };
        let Some(token) = DedupToken::try_new(dedup_id, &self.scope) else {
            // Duplicate-sensitive traffic cannot be admitted without its
            // lifecycle token: forwarding it would make the engine observe a
            // value that cannot later be fenced or forgotten exactly.
            drop(key_lease);
            trace!(kind = ingress.kind_name(), "dedup token unfunded");
            return Delivered::Unavailable;
        };
        let weak_token = token.weak();
        let ingress = ingress.with_dedup_token(token);

        let mut seen = self.seen.lock();
        // The remembered key is non-owning. If every lifecycle owner forgot or
        // dropped its token, release the lease before considering this copy;
        // the ingress list must never become a peer-lifetime tombstone.
        prune_seen(&mut seen);
        let mut cursor = seen.as_deref();
        let duplicate = loop {
            let Some(entry) = cursor else { break false };
            if entry.key == key {
                break true;
            }
            cursor = entry.next.as_deref();
        };
        if duplicate {
            drop(key_lease);
            trace!(
                kind = ingress.kind_name(),
                "cross-carrier duplicate dropped"
            );
            return Delivered::Duplicate;
        }
        let mut node = Box::new(SeenKey {
            key,
            token: weak_token.clone(),
            _lease: key_lease,
            next: None,
        });
        node.next = seen.take();
        *seen = Some(node);
        drop(seen);
        let kind = ingress.kind_name();
        match self.send(ingress) {
            Delivered::Closed => {
                self.remove_key_for_token(&weak_token);
                return Delivered::Closed;
            }
            Delivered::Unavailable => {
                self.remove_key_for_token(&weak_token);
                trace!(kind, "unavailable after preclaim; exact key released");
                return Delivered::Unavailable;
            }
            // Refused, so there is nothing for a later copy to be a duplicate
            // *of*. No key remains committed, and the retransmission that rescues
            // this attempt finds a clean slate because the preclaimed key is
            // removed before the retransmission can be admitted.
            Delivered::Refused => {
                self.remove_key_for_token(&weak_token);
                trace!(kind, "refused after preclaim; exact key released");
                return Delivered::Refused;
            }
            Delivered::Accepted => {}
            Delivered::Duplicate => unreachable!("mailbox send cannot produce duplicate"),
        }
        // Accepted, and only now. The exact key and lifecycle token were
        // pre-funded before dispatch, so pressure can never turn
        // duplicate-sensitive traffic into an untracked reducer delivery. A
        // key that cannot be funded returned `Unavailable` above; it was never
        // forwarded and never entered the remembered set.
        Delivered::Accepted
    }

    fn remove_key_for_token(
        &self,
        token: &std::sync::Weak<crate::runtime::peer_session::DedupTokenInner>,
    ) {
        remove_seen_for_token(&mut self.seen.lock(), token);
    }

    /// Forget exactly one retained ingress key.
    ///
    /// Called by the engine when an attempt ends or is replaced — the two
    /// moments after which nothing belonging to it can legitimately arrive
    /// again. Each forgotten key releases its own lease, so the funding goes
    /// back at exactly the same time the record does.
    ///
    /// This is the other half of scoping the key. Scoping alone stops a retired
    /// attempt from suppressing a live one; releasing on the exact end is what
    /// stops the list from being a slowly filling record of every attempt the
    /// process ever made, emptied only by provider pressure.
    pub(crate) fn forget_token(&self, token: DedupToken) {
        // Consume the exact lifecycle owner before checking the weak key. Two
        // terminal callbacks can otherwise both observe the pre-drop strong
        // count and leave a dead key behind forever; consuming makes exactly
        // the last owner remove it, even when the callbacks race.
        let mut seen = self.seen.lock();
        let weak = token.weak();
        drop(token);
        if weak.strong_count() != 0 {
            return;
        }
        remove_seen_for_token(&mut seen, &weak);
    }

    #[cfg(test)]
    pub(crate) fn remembers_attempt_for_test(&self, attempt: &str) -> bool {
        let seen = self.seen.lock();
        let mut cursor = seen.as_deref();
        while let Some(entry) = cursor {
            if entry.key.attempt.as_ref() == attempt {
                return true;
            }
            cursor = entry.next.as_deref();
        }
        false
    }

    /// Fund one remembered key without evicting any live key.
    ///
    /// No capacity constant: the list is exactly as long as the provider will
    /// pay for, which is the bound `TRANSITION-PLAYBOOK.md` asks for and an
    /// invented count is not.
    fn reserve_key(&self, key: &DedupKeyPlan<'_>) -> Option<ResourceLease> {
        let bytes = key.retained_bytes()?;
        let claim = ResourceClaim::try_from_entries([
            (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
            (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .ok()?;
        self.scope.acquire(claim).ok()
    }

    /// Hand one admitted value to the engine.
    ///
    /// The caller needs two different things from this and a bool can only carry
    /// one: whether to keep pumping, and whether the engine actually has the
    /// value. Only [`Delivered::Accepted`] answers yes to the second.
    fn send(&self, ingress: EphemeralIngress) -> Delivered {
        let kind = ingress.kind_name();
        match self.tx.send(ingress) {
            Ok(()) => Delivered::Accepted,
            Err(ResourceMailboxSendError::Closed(_)) => Delivered::Closed,
            Err(ResourceMailboxSendError::Pressure { error, .. }) => {
                warn!(
                    kind,
                    ?error,
                    "inbound signaling dropped under declared resource pressure"
                );
                Delivered::Refused
            }
            Err(ResourceMailboxSendError::Claim { error, .. }) => {
                warn!(kind, %error, "unrepresentable inbound signaling dropped");
                Delivered::Refused
            }
        }
    }
}

/// One carrier's attach: the handle a driver pump observes through.
///
/// It cannot reach anything but its own instance and the runtime's delivery
/// path, so a pump can neither mint a second receipt nor build a domain value
/// without going through the admission above.
pub(crate) struct CarrierAttach {
    runtime: Arc<SignalingRuntime>,
    carrier: SignalingCarrier,
    instance: CarrierInstance,
    guard: Arc<CarrierInstanceGuard>,
}

/// The ephemeral-transport port. Its only input is a carrier observation and
/// its only output is the typed admission result; it has no durable semantic
/// or endpoint-authentication arm. The attach remains the owner of runtime,
/// provenance, and exact carrier-emission custody.
pub(crate) struct EphemeralTransportPort;

/// A single network-owned introduction carrier. It borrows the existing
/// SignalingRuntime mailbox/dedup path; no direct SignalingInbound injection.
pub(crate) struct HubSignalingCarrier {
    runtime: Arc<SignalingRuntime>,
    instance: CarrierInstance,
}

impl HubSignalingCarrier {
    pub(crate) fn new(state: &Arc<NetworkState>) -> Option<Self> {
        let runtime = state.signaling_runtime()?;
        let instance = CarrierInstance(next_non_wrapping(&runtime.instances)?);
        // No Nostr/mDNS publication guard or extra Arc allocation: the mesh
        // introduction record already owns exact carrier/attempt lifecycle.
        // Only the existing runtime's admitted delivery/dedup port is reused.
        Some(Self { runtime, instance })
    }

    /// Caller holds the introduction controller only for this synchronous
    /// transfer, never across native work. Both current-carrier and one-shot
    /// accepted-frame custody are checked here before domain delivery.
    pub(crate) fn admit(
        &self,
        state: &Arc<NetworkState>,
        controller: &mut super::hub_introduction::HubIntroduction,
        ticket: super::hub_introduction::IntroductionTicket,
        carrier: &super::peer_registry::PeerOwnerToken,
        frame: &crate::protocol::hub_introduction::HubIntroductionEnvelope,
        now: std::time::Instant,
    ) -> Delivered {
        use crate::protocol::hub_introduction::HubIntroductionBody;
        if !state.peers.has_usable_authenticated_current(carrier)
            || &**frame.destination() != state.identity.public_id()
            || frame.context_id() != state.mesh_context_id()
        {
            return Delivered::Refused;
        }
        // Exact borrowed measurement, BEFORE cloning any carrier strings.
        let source: &str = frame.source().as_ref();
        let attempt_bytes = [b'0'; 32];
        let attempt_shape = std::str::from_utf8(&attempt_bytes).expect("ASCII shape");
        let base = [Some(source), Some(source), Some(attempt_shape)];
        let extra = match frame.body() {
            HubIntroductionBody::Offer { sdp } | HubIntroductionBody::Answer { sdp } => {
                [Some(sdp.as_str()), None, None]
            }
            HubIntroductionBody::Candidate {
                candidate,
                sdp_mid,
                username_fragment,
                ..
            } => [
                Some(candidate.as_str()),
                sdp_mid.as_deref(),
                username_fragment.as_deref(),
            ],
            _ => return Delivered::Refused,
        };
        let Ok((bytes, _, allocations)) = strings_measure(base.into_iter().chain(extra).flatten())
        else {
            return Delivered::Unavailable;
        };
        let Some(bytes) = bytes.checked_add(std::mem::size_of::<CarrierObservation>()) else {
            return Delivered::Unavailable;
        };
        let Ok(claim) = ResourceClaim::try_from_entries([
            (
                crate::resource::ResourceClass::AccountedMemoryBytes,
                bytes as u64,
            ),
            (
                crate::resource::ResourceClass::OpaqueDependencyResidual,
                allocations as u64,
            ),
        ]) else {
            return Delivered::Unavailable;
        };
        let Ok(_translation) = self.runtime.scope.acquire(claim) else {
            return Delivered::Unavailable;
        };
        if controller.take_signal(ticket, carrier, frame, now).is_err() {
            return Delivered::Refused;
        }
        let peer_id = source.to_owned();
        let offer_id = ticket.attempt();
        let message = match frame.body() {
            HubIntroductionBody::Offer { sdp } => SignalingMessage::Offer {
                peer_id,
                offer_id,
                sdp: sdp.clone(),
            },
            HubIntroductionBody::Answer { sdp } => SignalingMessage::Answer {
                peer_id,
                offer_id,
                sdp: sdp.clone(),
            },
            HubIntroductionBody::Candidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
                username_fragment,
            } => SignalingMessage::Candidate {
                peer_id,
                offer_id,
                candidate: candidate.clone(),
                sdp_mid: sdp_mid.clone(),
                sdp_mline_index: *sdp_mline_index,
                username_fragment: username_fragment.clone(),
            },
            _ => return Delivered::Refused,
        };
        let observation = CarrierObservation {
            carrier: SignalingCarrier::Hub,
            instance: self.instance,
            signal: admit(&message),
            body: ObservationBody::Directed {
                from: source.to_owned(),
                message,
            },
            hub: Some(HubIngressWitness {
                ticket,
                carrier: carrier.downgrade(),
            }),
        };
        self.runtime.deliver(observation)
    }
}

impl EphemeralTransportPort {
    /// Admit an already carrier-owned observation before domain parsing.
    pub(crate) fn admit(attach: &CarrierAttach, observation: CarrierObservation) -> Delivered {
        attach.runtime.deliver(observation)
    }
}

impl CarrierAttach {
    /// A carrier reported that a device is present.
    ///
    /// Presence paces dialling and nothing else. The device id is not a claim of
    /// membership — the engine still runs the full endpoint-authentication and
    /// policy path before this peer is anything.
    pub(crate) fn presence(
        &self,
        device_id: String,
        attribution: CarrierAttribution,
    ) -> CarrierObservation {
        self.observation(
            EphemeralSignal::Presence,
            ObservationBody::Presence {
                device_id,
                attribution,
            },
        )
    }

    /// A carrier stopped seeing a device, or the device announced its departure.
    ///
    /// Reachability evidence. It cannot be a durable leave: this boundary has no
    /// kind that records one, the roster is the Semantic Node's to change, and
    /// the engine will not let it retire a promoted session.
    pub(crate) fn withdrawal(
        &self,
        device_id: String,
        attribution: CarrierAttribution,
    ) -> CarrierObservation {
        self.observation(
            EphemeralSignal::Withdrawal,
            ObservationBody::Withdrawal {
                device_id,
                attribution,
            },
        )
    }

    /// A peer addressed us directly over this carrier.
    pub(crate) fn directed(&self, from: String, message: SignalingMessage) -> CarrierObservation {
        // Admission happens on the carrier value, before anything is translated:
        // this is the whole ordering the module exists to fix.
        let signal = admit(&message);
        self.observation(signal, ObservationBody::Directed { from, message })
    }

    fn observation(&self, signal: EphemeralSignal, body: ObservationBody) -> CarrierObservation {
        CarrierObservation {
            carrier: self.carrier,
            instance: self.instance,
            signal,
            body,
            hub: None,
        }
    }

    /// Hand an observation to the runtime. `false` once the engine side is gone.
    #[cfg(test)]
    pub(crate) fn deliver(&self, observation: CarrierObservation) -> bool {
        !matches!(self.admit(observation), Delivered::Closed)
    }

    /// Admit one carrier observation and preserve the exact typed result for
    /// production consumers that need to distinguish refusal, unavailability,
    /// duplicate suppression, acceptance, and shutdown.
    pub(crate) fn admit(&self, observation: CarrierObservation) -> Delivered {
        EphemeralTransportPort::admit(self, observation)
    }

    pub(crate) fn guard(&self) -> Arc<CarrierInstanceGuard> {
        Arc::clone(&self.guard)
    }
}

fn attempt_is_empty(ingress: &EphemeralIngress) -> bool {
    match ingress.inbound() {
        SignalingInbound::Offer { attempt, .. }
        | SignalingInbound::Answer { attempt, .. }
        | SignalingInbound::Candidate { attempt, .. } => attempt.is_empty(),
        SignalingInbound::PeerAnnounced { .. } | SignalingInbound::PeerLeft { .. } => false,
    }
}

/// De-duplication key: which attempt, and which message within it. `None` =
/// never deduped. `Err` means a duplicate-sensitive message carried an empty
/// attempt and must be refused before it reaches the engine reducer.
///
/// **Content, and deliberately not the carrier.** The duplicate this exists to
/// catch is one engine emission that fanned out to Nostr and mDNS and came back
/// over both, so the two copies differ in exactly the field a carrier-aware key
/// would separate them by. Applying an offer twice via `set_remote_description`
/// wedges WebRTC permanently.
///
/// **Scoped to the attempt, and that is the correction.** Content alone was not
/// enough in the other direction: a host candidate carries no `username_fragment`
/// on many stacks, so the same candidate recurs byte-identically on the attempt
/// that replaces a retired one. The live copy was dropped as a duplicate of
/// something that no longer existed. The attempt correlation is what tells
/// those two apart, and it is why the engine mints one per attempt instead of
/// each carrier inventing its own.
///
/// **Presence and withdrawal signals are not de-duplicated.** They carry no
/// attempt and are intentionally handled as reachability evidence. In
/// contrast, an Offer, Answer, or Candidate without an attempt is refused
/// before the reducer: without a correlation there is nothing that distinguishes
/// a relay copy from a fresh attempt, so duplicate-sensitive traffic never
/// proceeds without exact lifecycle custody.
fn add_framed_len(total: &mut usize, len: usize) -> Option<()> {
    *total = total.checked_add(std::mem::size_of::<u64>())?;
    *total = total.checked_add(len)?;
    Some(())
}

fn dedup_key_plan(ingress: &EphemeralIngress) -> Result<Option<DedupKeyPlan<'_>>, ()> {
    let mut payload_bytes = 1usize;
    let attempt = match ingress.inbound() {
        SignalingInbound::Offer {
            device_id,
            attempt,
            sdp,
        }
        | SignalingInbound::Answer {
            device_id,
            attempt,
            sdp,
        } => {
            add_framed_len(&mut payload_bytes, device_id.len()).ok_or(())?;
            add_framed_len(&mut payload_bytes, sdp.len()).ok_or(())?;
            attempt
        }
        SignalingInbound::Candidate {
            device_id,
            attempt,
            candidate,
        } => {
            add_framed_len(&mut payload_bytes, device_id.len()).ok_or(())?;
            add_framed_len(&mut payload_bytes, candidate.candidate.len()).ok_or(())?;
            payload_bytes = payload_bytes.checked_add(1).ok_or(())?;
            if let Some(mid) = &candidate.sdp_mid {
                add_framed_len(&mut payload_bytes, mid.len()).ok_or(())?;
            }
            payload_bytes = payload_bytes.checked_add(1).ok_or(())?;
            if candidate.sdp_mline_index.is_some() {
                payload_bytes = payload_bytes.checked_add(2).ok_or(())?;
            }
            payload_bytes = payload_bytes.checked_add(1).ok_or(())?;
            if let Some(fragment) = &candidate.username_fragment {
                add_framed_len(&mut payload_bytes, fragment.len()).ok_or(())?;
            }
            attempt
        }
        SignalingInbound::PeerAnnounced { .. } | SignalingInbound::PeerLeft { .. } => {
            return Ok(None)
        }
    };
    if attempt.is_empty() {
        return Err(());
    }
    Ok(Some(DedupKeyPlan {
        attempt,
        payload_bytes,
    }))
}

fn dedup_key(ingress: &EphemeralIngress, plan: &DedupKeyPlan<'_>) -> Option<DedupKey> {
    let mut payload = Vec::new();
    let append = |payload: &mut Vec<u8>, bytes: &[u8]| -> Option<()> {
        payload.extend_from_slice(&u64::try_from(bytes.len()).ok()?.to_le_bytes());
        payload.extend_from_slice(bytes);
        Some(())
    };
    let attempt = match ingress.inbound() {
        SignalingInbound::Offer {
            device_id,
            attempt,
            sdp,
        } => {
            payload.push(1);
            append(&mut payload, device_id.as_bytes())?;
            append(&mut payload, sdp.as_bytes())?;
            attempt
        }
        SignalingInbound::Answer {
            device_id,
            attempt,
            sdp,
        } => {
            payload.push(2);
            append(&mut payload, device_id.as_bytes())?;
            append(&mut payload, sdp.as_bytes())?;
            attempt
        }
        SignalingInbound::Candidate {
            device_id,
            attempt,
            candidate,
        } => {
            payload.push(3);
            append(&mut payload, device_id.as_bytes())?;
            append(&mut payload, candidate.candidate.as_bytes())?;
            match &candidate.sdp_mid {
                Some(mid) => {
                    payload.push(1);
                    append(&mut payload, mid.as_bytes())?;
                }
                None => payload.push(0),
            }
            match candidate.sdp_mline_index {
                Some(index) => {
                    payload.push(1);
                    payload.extend_from_slice(&index.to_le_bytes());
                }
                None => payload.push(0),
            }
            match &candidate.username_fragment {
                Some(fragment) => {
                    payload.push(1);
                    append(&mut payload, fragment.as_bytes())?;
                }
                None => payload.push(0),
            }
            attempt
        }
        SignalingInbound::PeerAnnounced { .. } | SignalingInbound::PeerLeft { .. } => return None,
    };
    let key = DedupKey {
        attempt: attempt.as_str().into(),
        payload: payload.into_boxed_slice(),
    };
    debug_assert_eq!(key.attempt.as_ref(), plan.attempt);
    debug_assert_eq!(key.payload.len(), plan.payload_bytes);
    Some(key)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    const EVERY_CARRIER: [SignalingCarrier; 4] = [
        SignalingCarrier::Local,
        SignalingCarrier::Nostr,
        SignalingCarrier::Mdns,
        SignalingCarrier::Hub,
    ];

    #[test]
    fn ordinary_ingress_move_has_no_introduction_witness() {
        let attach = lone_attach(SignalingCarrier::Nostr);
        let ingress = attach
            .directed("peer-a".into(), offer("ordinary"))
            .into_ingress();
        let (inbound, witness) = ingress.into_inbound_with_introduction();
        assert!(witness.is_none());
        assert!(matches!(inbound, SignalingInbound::Offer { .. }));
    }

    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    #[ignore = "opens one promoted local link; run explicitly in the isolated native harness"]
    async fn hub_ingress_moved_witness_rechecks_revocation_and_replacement() {
        use crate::config::HubIntroductionPolicyConfig;
        use crate::engine::hub_introduction::HubIntroduction;
        use crate::semantic::DeviceId;
        let state = crate::engine::build_test_state("hub-witness-near");
        let far = crate::engine::build_test_state("hub-witness-far");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let link = tokio::time::timeout_at(
            deadline,
            crate::engine::install_promoted_session_over_real_link(&state, &far),
        )
        .await
        .expect("bounded promoted carrier");
        let owner = state
            .peers
            .owner(link.peer_device_id())
            .expect("installed carrier");
        let owner = owner.for_worker(owner.connection().current_worker().expect("carrier worker"));
        let funded = funded(|_| 1_000_000);
        let local =
            DeviceId::from_canonical_str(state.identity.public_id()).expect("canonical local id");
        let target_key = ed25519_dalek::SigningKey::from_bytes(&[93; 32]);
        let target =
            DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes()).unwrap();
        let mut controller = HubIntroduction::new(
            HubIntroductionPolicyConfig {
                max_records: 1,
                max_waiters_per_target: 1,
                max_signaling_bytes: 16_384,
                max_candidates_per_attempt: 2,
                attempt_timeout_ms: 1_000,
                terminal_retention_ms: 100,
                max_transient_links: 1,
                idle_timeout_ms: 1_000,
                max_maintenance_per_tick: 1,
            },
            funded.scope.clone(),
            state.mesh_context_id(),
            &local,
        )
        .unwrap();
        let ticket = controller
            .begin_demand(&target, &owner, std::time::Instant::now())
            .unwrap()
            .ticket;
        // This control isolates the admitted value's ownership transfer. It
        // uses the real mailbox and a genuinely promoted carrier, but does not
        // claim to exercise the separate signed challenge/Offer parser.
        let observation = CarrierObservation {
            carrier: SignalingCarrier::Hub,
            instance: CarrierInstance(1),
            signal: EphemeralSignal::ConnectIntent,
            body: ObservationBody::Directed {
                from: target.to_string(),
                message: SignalingMessage::Offer {
                    peer_id: target.to_string(),
                    offer_id: ticket.attempt(),
                    sdp: "witness-transfer-only".into(),
                },
            },
            hub: Some(HubIngressWitness {
                ticket,
                carrier: owner.downgrade(),
            }),
        };
        assert_eq!(funded.runtime.deliver(observation), Delivered::Accepted);
        let mut rx = funded.rx;
        let delivered = rx.try_recv().expect("admitted ingress reaches mailbox");
        let current_before_dequeue = delivered.value().introduction_carrier_is_current(&state);
        let mut observed = [false; 5];
        // Retention stays inside the same consuming terminal-effect seam used
        // by the engine. Only scalar observations escape this closure.
        delivered
            .run_terminal_effect(|ingress| async {
                let (inbound, witness) = ingress.into_inbound_with_introduction();
                let witness = witness.expect("move retains original Hub witness");
                let same_ticket = witness.ticket() == ticket;
                tokio::task::yield_now().await;
                let current_after_await = witness.is_current(&state);
                owner.connection().revoke_promoted_session();
                let accepted_after_revoke = witness.is_current(&state);
                state
                    .peers
                    .install(Arc::new(crate::engine::connection::PeerConnection::new(
                        owner.device_id().to_string(),
                        None,
                    )));
                let accepted_after_replace = witness.is_current(&state);
                observed = [
                    same_ticket,
                    current_after_await,
                    accepted_after_revoke,
                    accepted_after_replace,
                    matches!(inbound, SignalingInbound::Offer { .. }),
                ];
                drop((inbound, witness));
            })
            .await;
        drop((owner, rx));
        controller.shutdown();
        drop(controller);
        let provider = funded.provider.clone();
        drop((funded.runtime, funded.scope));
        let close_outcomes = tokio::time::timeout_at(deadline, link.close_outcomes())
            .await
            .expect("bounded link cleanup");
        tokio::time::timeout_at(deadline, async {
            state.shutdown().await;
            far.shutdown().await;
        })
        .await
        .expect("bounded joined state cleanup");
        assert!(tokio::time::Instant::now() < deadline);
        assert!(close_outcomes.iter().all(Result::is_ok));
        assert!(current_before_dequeue && observed[0] && observed[1] && observed[4]);
        assert!(!observed[2] && !observed[3]);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
    }

    fn offer(sdp: &str) -> SignalingMessage {
        offer_with_id("offer-1", sdp)
    }

    fn offer_with_id(offer_id: &str, sdp: &str) -> SignalingMessage {
        SignalingMessage::Offer {
            peer_id: "body-claimed-id".into(),
            offer_id: offer_id.into(),
            sdp: sdp.into(),
        }
    }

    /// A runtime, the receiver to drain, and the scope that funds both.
    struct Funded {
        runtime: Arc<SignalingRuntime>,
        rx: crate::resource::ResourceMailboxReceiver<EphemeralIngress>,
        /// The same finite provider the runtime and its mailbox draw on, so a
        /// control can take funding away in the open rather than by guessing how
        /// many bytes a message happens to weigh.
        scope: crate::resource::LocalApplicationResourceScope,
        provider: crate::resource::FiniteResourceProvider,
    }

    /// A runtime on an isolated provider whose per-dimension grant is `budget`.
    fn funded(budget: impl Fn(crate::resource::ResourceClass) -> u64) -> Funded {
        let grant = crate::resource::ResourceClaim::try_from_entries(
            crate::resource::ResourceClass::ALL.map(|dimension| (dimension, budget(dimension))),
        )
        .expect("test grant is representable");
        let accountant = crate::resource::FiniteResourceProvider::new(grant);
        let provider = crate::resource::ResourceProviderPort::new(accountant.clone())
            .expect("test grant funds process bookkeeping");
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_local_application_provider(provider)
            .expect("isolated root accepts its provider");
        let scope = root
            .issue_local_application_scope()
            .expect("test local-application scope");
        let (tx, rx) = crate::resource::resource_mailbox(scope.clone()).expect("test mailbox");
        Funded {
            runtime: SignalingRuntime::new(tx, scope.clone()),
            rx,
            scope,
            provider: accountant,
        }
    }

    /// A generously funded runtime and the receiver to drain.
    ///
    /// Shared with `signaling_bridge`'s controls rather than copied into them:
    /// two harnesses that build the same isolated provider are two places for
    /// the funding a control depends on to drift.
    pub(crate) fn runtime_with_rx() -> (
        Arc<SignalingRuntime>,
        crate::resource::ResourceMailboxReceiver<EphemeralIngress>,
    ) {
        let funded = funded(|_| 1_000_000);
        (funded.runtime, funded.rx)
    }

    /// Raw provider pressure refuses one observation before parsing, without
    /// consuming a carrier or changing the runtime's baseline. The next
    /// observation proves this is a value-local refusal rather than a carrier
    /// shutdown or a retained raw-payload queue.
    #[test]
    fn raw_observation_pressure_refuses_before_parse_and_recovers_next_value() {
        let funded = funded(|_| 1_000_000);
        let before = funded.provider.in_use();
        let attach = SignalingRuntime::attach(&funded.runtime, SignalingCarrier::Nostr);
        let mut rx = funded.rx;
        funded
            .provider
            .script_pressure(crate::resource::ResourceClass::ParsingOrCpuWork);

        assert_eq!(
            attach.admit(attach.directed("peer-a".into(), offer("first"))),
            Delivered::Unavailable,
            "raw pressure refuses before the observation is parsed"
        );
        assert!(
            rx.try_recv().is_none(),
            "a raw refusal never reaches the inbound mailbox"
        );
        assert_eq!(
            funded.provider.in_use(),
            before,
            "raw refusal releases no retained claim because it acquired none"
        );

        assert_eq!(
            attach.admit(attach.directed("peer-a".into(), offer_with_id("second", "sdp"))),
            Delivered::Accepted,
            "a later observation on the same carrier remains admissible"
        );
        assert!(rx.try_recv().is_some());
    }

    /// One attach, for the admission-only controls that never deliver.
    fn lone_attach(carrier: SignalingCarrier) -> CarrierAttach {
        SignalingRuntime::attach(&runtime_with_rx().0, carrier)
    }

    /// **Negative control: a body-claimed identity never displaces the `from`
    /// that reached this boundary.**
    ///
    /// # Scope, because the obvious reading is wider than the truth
    ///
    /// This is a rule about values that reach [`parse_directed`]. Offer, answer
    /// and candidate reach it from all carrier shapes, so there it is the live
    /// behaviour everywhere. A directed announce or leave reaches it from
    /// `LocalBroker` alone — the two network drivers normalize those into their
    /// own presence and withdrawal reports first, and what *they* attribute is
    /// covered by [`CarrierAttribution`] and, for what a delivered withdrawal is
    /// then allowed to do, by the engine's withdrawal controls.
    ///
    /// The stronger property holds on every carrier and is structural rather
    /// than asserted: neither field mints authority, because no kind could.
    #[test]
    fn a_body_claimed_identity_never_displaces_the_sender_attribution() {
        for carrier in EVERY_CARRIER {
            let attach = lone_attach(carrier);
            let offered = attach
                .directed(
                    "sender-peer".into(),
                    SignalingMessage::Offer {
                        peer_id: "third-party-peer".into(),
                        offer_id: "offer-1".into(),
                        sdp: "sdp-1".into(),
                    },
                )
                .into_ingress();
            assert_eq!(offered.signal(), EphemeralSignal::ConnectIntent);
            assert_eq!(offered.carrier(), carrier, "provenance survives the parse");
            assert_eq!(offered.attribution(), CarrierAttribution::SenderClaimed);
            match offered.inbound() {
                SignalingInbound::Offer { device_id, .. } => assert_eq!(
                    device_id, "sender-peer",
                    "a negotiation frame is attributed to the sender the carrier \
                     routed from, on every carrier"
                ),
                other => panic!("an offer parses as connect intent, got {other:?}"),
            }

            let left = attach
                .directed(
                    "sender-peer".into(),
                    SignalingMessage::Leave {
                        peer_id: "third-party-peer".into(),
                    },
                )
                .into_ingress();
            assert_eq!(left.signal(), EphemeralSignal::Withdrawal);
            match left.inbound() {
                SignalingInbound::PeerLeft { device_id } => assert_eq!(
                    device_id, "sender-peer",
                    "a departure the sender did not make is not the sender's to declare"
                ),
                other => panic!("a leave parses as a withdrawal, got {other:?}"),
            }
        }
    }

    /// **The union has no application-delivery and no durable-authority kind.**
    ///
    /// The implementation half of `FORMAL-PROOFS.md` Theorem 11.1: every input
    /// this boundary can produce lands in the closed [`EphemeralSignal`] set, so
    /// application payload and durable authority are absent from the union rather
    /// than merely unreachable from today's inputs. Both directions are checked,
    /// because an outbound variant that acquired a kind by default would widen
    /// the same union.
    #[test]
    fn every_admitted_signal_is_ephemeral_transport_control() {
        let inbound = [
            SignalingMessage::Announce {
                peer_id: "peer-a".into(),
            },
            SignalingMessage::Leave {
                peer_id: "peer-a".into(),
            },
            offer("sdp-1"),
            SignalingMessage::Answer {
                peer_id: "peer-a".into(),
                offer_id: "offer-1".into(),
                sdp: "sdp-1".into(),
            },
            SignalingMessage::Candidate {
                peer_id: "peer-a".into(),
                offer_id: "attempt-1".into(),
                candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            },
        ];
        let admitted: Vec<EphemeralSignal> = inbound.iter().map(admit).collect();
        assert_eq!(
            admitted,
            [
                EphemeralSignal::Presence,
                EphemeralSignal::Withdrawal,
                EphemeralSignal::ConnectIntent,
                EphemeralSignal::ConnectAnswer,
                EphemeralSignal::CandidateHint,
            ],
            "no current carrier variant carries a durable signed fact"
        );

        // One attempt to one peer, so the three directed emissions carry the
        // same correlation — that is what a real offer/answer/candidate run
        // looks like, and the fixture should not describe a shape the engine
        // never produces. It is a concrete value rather than an empty one on
        // purpose: an empty correlation is precisely what `attempt_is_current`
        // refuses, so writing one here would leave a bypass-shaped constant
        // sitting in a fixture for the next reader to copy.
        let outbound = [
            SignalingOutbound::Announce,
            SignalingOutbound::Leave,
            SignalingOutbound::Offer {
                device_id: "peer-a".into(),
                attempt: "attempt-1".into(),
                sdp: "sdp-1".into(),
                owner: None,
            },
            SignalingOutbound::Answer {
                device_id: "peer-a".into(),
                attempt: "attempt-1".into(),
                sdp: "sdp-1".into(),
                owner: None,
            },
            SignalingOutbound::Candidate {
                device_id: "peer-a".into(),
                attempt: "attempt-1".into(),
                candidate: LocalIceCandidate {
                    candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
                    sdp_mid: Some("0".into()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                },
                owner: None,
            },
        ];
        for emission in &outbound {
            let signal = outbound_signal(emission);
            assert!(
                matches!(
                    signal,
                    EphemeralSignal::Presence
                        | EphemeralSignal::Withdrawal
                        | EphemeralSignal::ConnectIntent
                        | EphemeralSignal::ConnectAnswer
                        | EphemeralSignal::CandidateHint
                ),
                "unexpected kind {signal:?} — the union has grown"
            );
        }
    }

    /// **The instance receipt is per-attach, opaque, and not peer-choosable.**
    ///
    /// Two attaches of the *same* carrier are distinguishable, so a restarted
    /// driver's reports are not the old attach's; and nothing a peer sends
    /// changes the receipt, which is what keeps it from becoming a route
    /// identity.
    #[test]
    fn each_attach_receives_its_own_opaque_instance() {
        let (runtime, _rx) = runtime_with_rx();
        let first = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        let second = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        assert_ne!(
            first.instance, second.instance,
            "two attaches of one carrier are not one attach"
        );

        let a = first
            .directed("peer-a".into(), offer("sdp-1"))
            .into_ingress();
        let b = first
            .directed("hostile".into(), offer("v=0 whatever"))
            .into_ingress();
        assert_eq!(
            a.instance(),
            b.instance(),
            "the receipt is the attach's, not the message's"
        );
        assert_ne!(a.instance(), second.instance);
    }

    /// **One emission that fanned out to two carriers reaches the engine once;
    /// everything else still gets through, in any order.**
    ///
    /// The wedge case the de-duplication owner exists for, and its three
    /// discriminations in one control: the duplicate is caught *across* carriers
    /// (a carrier-aware key would miss it, since provenance is the only field
    /// the two copies differ in), distinct content is never held back however
    /// similar, and nothing waits for a predecessor — a candidate that overtakes
    /// its offer on a relay still lands.
    #[test]
    fn cross_carrier_duplicates_are_swallowed_and_distinct_content_is_not() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        let lan = SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns);

        let candidate = |mid: &str| SignalingMessage::Candidate {
            peer_id: "body-claimed-id".into(),
            offer_id: "attempt-1".into(),
            candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
            sdp_mid: Some(mid.to_string()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        };

        // Candidates ahead of the offer they belong to, then the same offer over
        // both carriers, then a distinct one.
        assert!(lan.deliver(lan.directed("peer-a".into(), candidate("1"))));
        assert!(relay.deliver(relay.directed("peer-a".into(), candidate("0"))));
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-1"))));
        assert!(lan.deliver(lan.directed("peer-a".into(), offer("sdp-1"))));
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-2"))));
        assert!(relay.deliver(relay.directed("peer-b".into(), offer("sdp-1"))));

        let mut delivered = Vec::new();
        while let Some(item) = rx.try_recv() {
            delivered.push((item.value().signal(), item.value().carrier()));
        }
        assert_eq!(
            delivered,
            [
                (EphemeralSignal::CandidateHint, SignalingCarrier::Mdns),
                (EphemeralSignal::CandidateHint, SignalingCarrier::Nostr),
                // The carrier that got there first is the provenance the engine
                // sees; the mDNS copy of the same offer is the one swallowed.
                (EphemeralSignal::ConnectIntent, SignalingCarrier::Nostr),
                (EphemeralSignal::ConnectIntent, SignalingCarrier::Nostr),
                (EphemeralSignal::ConnectIntent, SignalingCarrier::Nostr),
            ],
            "one duplicate swallowed, five distinct inputs through"
        );
    }

    /// **The same candidate on a different attempt is not a duplicate, and the
    /// keys of an attempt go back when the attempt ends.**
    ///
    /// This is the defect the correlation exists for, driven directly. A host
    /// candidate carries no `username_fragment`, so the *identical* line recurs
    /// on the attempt that replaces a retired one — same content, same peer,
    /// same everything a content-only key could see. That key answered "already
    /// had it" and the live attempt lost the candidate it needed.
    ///
    /// Three discriminations, and each is another's non-vacuity:
    ///
    /// - within one attempt the duplicate is still caught, so scoping did not
    ///   simply disable de-duplication;
    /// - across two attempts the identical candidate is delivered, which is the
    ///   correction;
    /// - after exact-token forget the first attempt's own candidate is delivered
    ///   again, which proves the keys were released rather than merely
    ///   out-competed — a retained list that had kept them would still swallow it.
    #[test]
    fn a_key_is_scoped_to_its_attempt_and_released_when_the_attempt_ends() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);

        // Byte-identical but for the attempt it names — the case a content-only
        // key cannot tell apart.
        let candidate = |attempt: &str| SignalingMessage::Candidate {
            peer_id: "body-claimed-id".into(),
            offer_id: attempt.to_string(),
            candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        };
        let deliver =
            |attempt: &str| relay.deliver(relay.directed("peer-a".into(), candidate(attempt)));
        let drain = |rx: &mut crate::resource::ResourceMailboxReceiver<EphemeralIngress>| {
            let mut n = 0;
            while rx.try_recv().is_some() {
                n += 1;
            }
            n
        };

        assert!(deliver("attempt-1"));
        let first_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("the first accepted candidate carries exact dedup custody");
        assert!(deliver("attempt-1"));
        assert_eq!(
            drain(&mut rx),
            0,
            "within one attempt the second copy is still a duplicate"
        );

        assert!(deliver("attempt-2"));
        let second_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("the replacement attempt carries its own exact dedup custody");
        assert_eq!(
            drain(&mut rx),
            0,
            "the replacement attempt has exactly one delivered candidate"
        );

        runtime.forget_token(first_token);
        assert!(deliver("attempt-1"));
        assert_eq!(
            drain(&mut rx),
            1,
            "and the ended attempt's key really went back — a list that still \
             held it would swallow this"
        );

        // Non-vacuity for the release itself: forgetting one attempt leaves the
        // other's keys alone.
        assert!(deliver("attempt-2"));
        assert_eq!(
            drain(&mut rx),
            0,
            "forgetting one attempt does not empty the list"
        );
        runtime.forget_token(second_token);
    }

    #[test]
    fn exact_token_release_does_not_erase_same_correlation_successor() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);

        let first = relay.deliver(relay.directed("peer-a".into(), offer("sdp-first")));
        assert!(first);
        let first_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("the first candidate owns an exact dedup token");

        let second = relay.deliver(relay.directed("peer-a".into(), offer("sdp-second")));
        assert!(second);
        let second_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("the successor owns a distinct exact dedup token");

        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-second"))));
        assert!(
            rx.try_recv().is_none(),
            "the successor duplicate is suppressed"
        );

        runtime.forget_token(first_token);
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-second"))));
        assert!(
            rx.try_recv().is_none(),
            "releasing W1 cannot erase W2's key"
        );

        runtime.forget_token(second_token);
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-second"))));
        assert!(
            rx.try_recv().is_some(),
            "W2 admits a fresh copy after its own end"
        );
    }

    #[test]
    fn live_answer_and_candidate_custody_suppresses_restamped_duplicates() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay_a = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        let relay_b = SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns);
        let answer = || SignalingMessage::Answer {
            peer_id: "peer-a".into(),
            offer_id: "live-attempt".into(),
            sdp: "answer-sdp".into(),
        };
        assert!(relay_a.deliver(relay_a.directed("peer-a".into(), answer())));
        let answer_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("accepted Answer carries lifecycle custody");
        assert!(relay_b.deliver(relay_b.directed("peer-a".into(), answer())));
        assert!(
            rx.try_recv().is_none(),
            "a restamped Answer stays suppressed while its exact owner lives"
        );
        runtime.forget_token(answer_token);
        assert!(relay_b.deliver(relay_b.directed("peer-a".into(), answer())));
        assert!(rx.try_recv().is_some(), "Answer re-enters after exact end");

        let candidate = || SignalingMessage::Candidate {
            peer_id: "peer-a".into(),
            offer_id: "live-attempt".into(),
            candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        };
        assert!(relay_a.deliver(relay_a.directed("peer-a".into(), candidate())));
        let candidate_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("accepted Candidate carries lifecycle custody");
        assert!(relay_b.deliver(relay_b.directed("peer-a".into(), candidate())));
        assert!(
            rx.try_recv().is_none(),
            "a restamped Candidate stays suppressed while its exact owner lives"
        );
        runtime.forget_token(candidate_token);
        assert!(relay_b.deliver(relay_b.directed("peer-a".into(), candidate())));
        assert!(
            rx.try_recv().is_some(),
            "Candidate re-enters after exact end"
        );
    }

    #[test]
    fn consumed_last_owner_releases_shared_key_without_prune() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("shared-owner"))));
        let owner = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("the accepted Offer carries funded lifecycle custody");
        let second_owner = owner.clone();
        assert!(runtime.remembers_attempt_for_test("offer-1"));

        runtime.forget_token(owner);
        assert!(
            runtime.remembers_attempt_for_test("offer-1"),
            "the first terminal owner cannot release a key still owned by its clone"
        );
        runtime.forget_token(second_owner);
        assert!(
            !runtime.remembers_attempt_for_test("offer-1"),
            "the consumed last owner releases the key without an unrelated ingress prune"
        );
    }

    /// **The de-duplication list is bounded by the provider, and unfunded
    /// duplicate-sensitive traffic fails closed.**
    ///
    /// The bound is not a constant in this module, so the control cannot assert
    /// one: what it asserts is the two properties a constant was standing in for.
    /// The list stops well short of the number of distinct values offered to it.
    /// When pressure prevents either the exact key claim or the mailbox claim,
    /// the typed `Unavailable` or `Refused` result fails closed and the next
    /// copy can retry after pressure clears. No duplicate-sensitive value
    /// proceeds untracked, and a postclaim refusal rolls back exact custody.
    #[test]
    fn the_dedup_list_is_provider_bounded_and_unfunded_traffic_refuses() {
        const PUSHED: usize = 512;
        const RESIDUALS: u64 = 32;

        let Funded {
            runtime,
            mut rx,
            provider,
            ..
        } = funded(|dimension| match dimension {
            crate::resource::ResourceClass::OpaqueDependencyResidual => RESIDUALS,
            _ => 1_000_000,
        });
        let baseline = provider.in_use();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);

        let mut accepted = 0usize;
        let mut unavailable = 0usize;
        let mut refused = 0usize;
        let mut retained_deliveries = Vec::new();
        for i in 0..PUSHED {
            match relay.admit(relay.directed("peer-a".into(), offer(&format!("sdp-{i}")))) {
                Delivered::Accepted => {
                    accepted += 1;
                    // Retain each accepted value so its mailbox, key, and
                    // lifecycle token custody remains live while pressure is
                    // exercised. This makes the provider bound observable.
                    retained_deliveries
                        .push(rx.try_recv().expect("accepted value reaches the engine"));
                }
                Delivered::Unavailable => unavailable += 1,
                Delivered::Refused => refused += 1,
                other => panic!("distinct pressure offer had unexpected outcome: {other:?}"),
            }
        }

        assert!(accepted > 0, "the control admitted some funded values");
        assert!(
            unavailable + refused > 0,
            "the control exercised typed provider or mailbox pressure"
        );
        assert_eq!(accepted + unavailable + refused, PUSHED);
        let retained = runtime.seen_len();
        assert!(
            retained <= usize::try_from(RESIDUALS).expect("small"),
            "the list outgrew what funds it: {retained}"
        );
        assert!(
            retained < PUSHED,
            "the list grew with the traffic instead of with its funding: {retained}"
        );

        drop(retained_deliveries);
        // Dropping the last accepted owner releases its exact leases. A fresh
        // admission performs the weak-entry prune and proves that old offers
        // no longer occupy the remembered set before the retry is retained.
        assert_eq!(
            relay.admit(relay.directed("peer-a".into(), offer_with_id("cleanup", "sdp-cleanup"),)),
            Delivered::Accepted,
            "funding returns after accepted custody is released"
        );
        let cleanup = rx.try_recv().expect("cleanup retry reaches the engine");
        let cleanup_token = cleanup
            .value()
            .dedup_token()
            .expect("cleanup retry carries exact dedup custody");
        drop(cleanup);
        runtime.forget_token(cleanup_token);
        assert!(
            !runtime.remembers_attempt_for_test("offer-1"),
            "released accepted offers no longer retain exact key custody"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "intrusive key nodes and their exact leases return to the provider baseline"
        );
    }

    /// **An offer the engine refused leaves no de-duplication history, and the
    /// identical retransmission lands.**
    ///
    /// The exact failure the preclaim-and-remove ordering exists for. A key is
    /// installed before the send so concurrent copies are serialized, but a
    /// refusal removes that key before returning. The engine therefore never
    /// receives an unfunded offer, and its retransmission can rescue the
    /// connection instead of being discarded as a duplicate of something that
    /// never arrived — a permanently wedged attempt from one moment of local
    /// pressure.
    ///
    /// The refusal is produced by taking the funding away rather than by sizing a
    /// message against a budget, so the control asserts the ordering and not an
    /// arithmetic coincidence.
    ///
    /// It has already earned its place: the first implementation committed on
    /// the boolean `send` returned — which is `true` for "refused under
    /// pressure" as well as for "accepted", because both mean the driver keeps
    /// pumping — and this control failed on exactly the swallowed
    /// retransmission. [`Delivered`] exists because of it.
    #[test]
    fn a_refused_offer_leaves_no_dedup_history_and_its_retransmission_lands() {
        const QUEUE_BYTES: u64 = 4096;

        let Funded {
            runtime,
            mut rx,
            scope,
            ..
        } = funded(|dimension| match dimension {
            crate::resource::ResourceClass::QueuedBytes => QUEUE_BYTES,
            _ => 1_000_000,
        });
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);

        // Take the queue funding away a byte at a time until the provider says
        // no. Whatever the mailbox already holds, what is left afterwards is
        // nothing, so the refusal below is certain without this control knowing
        // what an offer weighs.
        let mut squeeze = Vec::new();
        while let Ok(lease) = scope.acquire(ResourceClaim::single(
            crate::resource::ResourceClass::QueuedBytes,
            1,
        )) {
            squeeze.push(lease);
        }
        assert!(
            !squeeze.is_empty(),
            "the control never took any funding away"
        );

        assert_eq!(
            relay.admit(relay.directed("peer-a".into(), offer("sdp-1"))),
            Delivered::Refused,
            "a pressure refusal is typed as refused, not closed"
        );
        assert!(
            rx.try_recv().is_none(),
            "the offer was refused, so nothing should have arrived"
        );

        drop(squeeze);
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-1"))));

        let arrived: Vec<_> = std::iter::from_fn(|| rx.try_recv())
            .map(|item| item.value().signal())
            .collect();
        assert_eq!(
            arrived,
            [EphemeralSignal::ConnectIntent],
            "the retransmission of a refused offer must reach the engine exactly once"
        );
    }

    #[test]
    fn key_pressure_drops_new_key_without_evicting_a_live_key() {
        let Funded {
            runtime,
            mut rx,
            scope,
            ..
        } = funded(|_| 1_000_000);
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);

        assert!(relay.deliver(relay.directed("peer-a".into(), offer("live"))));
        let live_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("the live key owns a token");
        assert!(runtime.remembers_attempt_for_test("offer-1"));

        let mut holds = Vec::new();
        while let Ok(lease) = scope.acquire(ResourceClaim::single(
            crate::resource::ResourceClass::OpaqueDependencyResidual,
            1,
        )) {
            holds.push(lease);
        }
        assert!(
            !holds.is_empty(),
            "the control exhausted remaining key funding"
        );
        assert_eq!(
            relay.admit(relay.directed("peer-b".into(), offer("new"))),
            Delivered::Unavailable,
            "a new key is refused when its full lease cannot be preclaimed"
        );
        assert!(
            rx.try_recv().is_none(),
            "an unfunded key must not reach the reducer mailbox"
        );
        assert!(runtime.remembers_attempt_for_test("offer-1"));

        drop(holds);
        assert!(relay.deliver(relay.directed("peer-b".into(), offer("new"))));
        let recovered = rx
            .try_recv()
            .expect("the refused key is recoverable after pressure clears");
        assert!(
            rx.try_recv().is_none(),
            "the recovered copy is admitted exactly once"
        );
        drop(recovered);
        assert!(
            relay.deliver(relay.directed("peer-a".into(), offer("live"))),
            "the original live key remains a normal duplicate decision"
        );
        assert!(rx.try_recv().is_none(), "the live key was not evicted");
        drop(live_token);
        assert!(relay
            .deliver(relay.directed("peer-c".into(), offer_with_id("cleanup", "sdp-cleanup"),)));
        drop(
            rx.try_recv()
                .expect("cleanup admission reaches the mailbox"),
        );
        assert!(
            !runtime.remembers_attempt_for_test("offer-1"),
            "settled live and refused keys release their exact custody"
        );
    }

    #[test]
    fn duplicate_sensitive_traffic_is_refused_when_token_funding_fails() {
        let Funded {
            runtime,
            mut rx,
            scope,
            ..
        } = funded(|_| 1_000_000);
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        let mut holds = Vec::new();
        while let Ok(lease) = scope.acquire(ResourceClaim::single(
            crate::resource::ResourceClass::OpaqueDependencyResidual,
            1,
        )) {
            holds.push(lease);
        }
        assert!(!holds.is_empty(), "the control exhausted token funding");

        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-1"))));
        assert!(
            rx.try_recv().is_none(),
            "duplicate-sensitive traffic is not forwarded without lifecycle custody"
        );

        drop(holds);
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-1"))));
        assert!(
            rx.try_recv().is_some(),
            "the same offer can recover after token funding returns"
        );
    }

    #[test]
    fn empty_attempt_offer_answer_and_candidate_are_refused_before_reducer() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        let messages = [
            SignalingMessage::Offer {
                peer_id: "peer-a".into(),
                offer_id: String::new(),
                sdp: "sdp".into(),
            },
            SignalingMessage::Answer {
                peer_id: "peer-a".into(),
                offer_id: String::new(),
                sdp: "sdp".into(),
            },
            SignalingMessage::Candidate {
                peer_id: "peer-a".into(),
                offer_id: String::new(),
                candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            },
        ];

        for message in messages {
            assert!(relay.deliver(relay.directed("peer-a".into(), message)));
            assert!(
                rx.try_recv().is_none(),
                "an empty attempt must not reach the engine mailbox"
            );
        }
    }

    #[test]
    fn exact_framed_keys_distinguish_field_boundary_variants() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        let first = SignalingMessage::Offer {
            peer_id: "ignored".into(),
            offer_id: "same-attempt".into(),
            sdp: "c".into(),
        };
        let second = SignalingMessage::Offer {
            peer_id: "ignored".into(),
            offer_id: "same-attempt".into(),
            sdp: "bc".into(),
        };

        assert!(relay.deliver(relay.directed("ab".into(), first.clone())));
        assert!(relay.deliver(relay.directed("a".into(), second.clone())));
        let first_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("the first exact key carries lifecycle custody");
        let second_token = rx
            .try_recv()
            .and_then(|delivery| delivery.value().dedup_token())
            .expect("the second exact key carries lifecycle custody");

        assert!(relay.deliver(relay.directed("ab".into(), first)));
        assert!(
            rx.try_recv().is_none(),
            "an exact duplicate is still suppressed"
        );
        drop(first_token);
        drop(second_token);
    }

    #[test]
    fn carrier_and_dedup_ids_fail_closed_at_their_maximum_without_wrapping() {
        let (runtime, _rx) = runtime_with_rx();
        runtime.instances.store(u64::MAX, Ordering::Relaxed);
        runtime.dedup_instances.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(next_non_wrapping(&runtime.instances), None);
        assert_eq!(next_non_wrapping(&runtime.dedup_instances), None);
        assert_eq!(runtime.instances.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(runtime.dedup_instances.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn registered_guard_reentry_settles_exact_emission_without_successor_substitution() {
        let (runtime, _rx) = runtime_with_rx();
        let state = crate::engine::build_test_state("registered-guard-reentry");
        let instance = state
            .next_recovery_carrier_instance()
            .expect("carrier instance");
        let attach = SignalingRuntime::attach_for_state(
            &runtime,
            SignalingCarrier::Nostr,
            &state,
            Some(instance),
        )
        .expect("registered carrier guard");
        let guard = Arc::clone(&attach.guard);
        let attempt = "registered-reentry";
        let predecessor = SignalingEmissionId::next().expect("emission id");
        assert!(state.begin_carrier_emission(predecessor, attempt, [instance]));
        assert!(guard.track_attempt(predecessor, attempt));

        // This callback re-enters the registered runtime/guard path. It must
        // complete: claim_attempt_with no longer holds `attempts` while
        // invoking admission. The exact predecessor is fenced and removed;
        // no operation here is allowed to select by attempt name.
        let observed = guard.claim_attempt_with(attempt, |claimed| {
            assert!(runtime.fence_emission(claimed, attempt));
            assert!(runtime.fence_emission(claimed, attempt));
            assert!(runtime.settle_emission(claimed, attempt));
            assert!(!runtime.settle_emission(claimed, attempt));
            claimed
        });
        assert_eq!(observed, Some((predecessor, predecessor)));

        let successor = SignalingEmissionId::next().expect("successor emission id");
        assert!(state.begin_carrier_emission(successor, attempt, [instance]));
        assert!(guard.track_attempt(successor, attempt));
        assert_eq!(guard.claim_attempt(attempt), Some(successor));
        assert_eq!(guard.claim_attempt(attempt), None);
    }

    /// **The `Debug` output carries the diagnostic fields and none of the
    /// payload.**
    ///
    /// Every sentinel is a value a derived `Debug` would have printed, checked by
    /// its own substring rather than by an overall shape, so a partial leak fails
    /// as loudly as a total one. The positive half is asserted too — a `Debug`
    /// that printed nothing would pass a redaction check while being useless.
    #[test]
    fn the_debug_output_omits_payload_and_keeps_the_bounded_fields() {
        const SECRET_SDP: &str = "v=0-SENTINEL-SDP-BODY-a=fingerprint";
        const SECRET_DEVICE: &str = "SENTINEL-DEVICE-ID";
        const SECRET_ADDRESS: &str = "203.0.113.7";

        let attach = lone_attach(SignalingCarrier::Nostr);
        let offered = attach
            .directed(
                SECRET_DEVICE.into(),
                SignalingMessage::Offer {
                    peer_id: SECRET_DEVICE.into(),
                    offer_id: "offer-1".into(),
                    sdp: SECRET_SDP.into(),
                },
            )
            .into_ingress();
        let rendered = format!("{offered:?}");
        for secret in [SECRET_SDP, SECRET_DEVICE] {
            assert!(
                !rendered.contains(secret),
                "payload must not reach a log through Debug: {secret} in {rendered}"
            );
        }
        assert!(
            rendered.contains("nostr") && rendered.contains("connect_intent"),
            "carrier and kind are the point of the value and must survive, got {rendered}"
        );

        // A candidate carries an address rather than an SDP body, so it is
        // checked separately: one redacted field does not imply the other.
        let mdns = lone_attach(SignalingCarrier::Mdns);
        let candidate = mdns
            .directed(
                SECRET_DEVICE.into(),
                SignalingMessage::Candidate {
                    peer_id: SECRET_DEVICE.into(),
                    offer_id: "attempt-1".into(),
                    candidate: format!("candidate:1 1 UDP 1 {SECRET_ADDRESS} 5000 typ host"),
                    sdp_mid: Some("0".into()),
                    sdp_mline_index: Some(0),
                    username_fragment: Some("SENTINEL-UFRAG".into()),
                },
            )
            .into_ingress();
        let rendered = format!("{candidate:?}");
        for secret in [SECRET_ADDRESS, SECRET_DEVICE, "SENTINEL-UFRAG"] {
            assert!(
                !rendered.contains(secret),
                "candidate payload must not reach a log through Debug: {secret} in {rendered}"
            );
        }
        assert!(rendered.contains("mdns") && rendered.contains("candidate_hint"));
    }
}
