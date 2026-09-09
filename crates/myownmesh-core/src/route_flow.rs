//! Bounded, opted-in routed disposition evidence. Historical echo-selected
//! v2 rows and ciphertext-metadata v1 rows are explicitly different schemas.
//!
//! The whole module is feature-gated at the crate root. A diagnostic build is
//! still inert unless `MYOWNMESH_ROUTE_FLOW_RUN_ID` contains one bounded ASCII
//! run id. Native callback timestamps are captured before the frame is parsed,
//! but a row is qualified and emitted only after the ordinary routed-envelope
//! admission path has accepted that frame.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::engine::routing::RouteDispatchReport;
use crate::engine::NetworkState;
use crate::events::{DiagEntry, DiagLevel, MeshEvent};
use crate::protocol::{ClosedRoutedPayload, RoutedApplicationEnvelope};

const RUN_ID_ENV: &str = "MYOWNMESH_ROUTE_FLOW_RUN_ID";
const MAX_RUN_ID_BYTES: usize = 80;
const MAX_SELECTED_SEQUENCE_EXCLUSIVE: u64 = 10_000;
const MAX_DATA_ROWS: u8 = 64;
const CIPHERTEXT_SCHEMA: &str = "myownmesh.route-flow-ciphertext/v1";
const MAX_MEASURED_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Exact compact-JSON ceiling for historical and ciphertext data/overflow
/// event shapes below.
///
/// The longest data row uses an 80-byte run id, a 32-byte route id, a
/// 20-digit owner epoch, seven 11-digit (24-hour microsecond) timestamps or
/// durations and the fixed outer `MeshEvent::Diag` fields. The unit control serializes that
/// maximal shape and pins this ceiling. The event hub's framing is priced by
/// its existing envelope limit rather than by this source-local ceiling.
#[cfg(test)]
pub(crate) const MAX_SERIALIZED_EVENT_BYTES: usize = 1_536;

static ACTIVE_RUN: RuntimeGate = RuntimeGate::new();
static EMISSIONS: EmissionLimiter = EmissionLimiter::new();
static MONOTONIC_ANCHOR: OnceLock<Instant> = OnceLock::new();

#[cfg(test)]
static TEST_NOW: OnceLock<std::sync::Mutex<Option<Instant>>> = OnceLock::new();

fn route_flow_now() -> Instant {
    #[cfg(test)]
    if let Some(now) = *TEST_NOW
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("route-flow test clock mutex is not poisoned")
    {
        return now;
    }
    Instant::now()
}

#[cfg(test)]
pub(crate) struct TestClockGuard;

#[cfg(test)]
impl TestClockGuard {
    pub(crate) fn set(&self, now: Instant) {
        let mut slot = TEST_NOW
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("route-flow test clock mutex is not poisoned");
        assert!(slot.is_some(), "the route-flow test clock is installed");
        *slot = Some(now);
    }
}

#[cfg(test)]
impl Drop for TestClockGuard {
    fn drop(&mut self) {
        *TEST_NOW
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("route-flow test clock mutex is not poisoned") = None;
    }
}

#[cfg(test)]
pub(crate) fn install_test_clock(now: Instant) -> TestClockGuard {
    let mut slot = TEST_NOW
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("route-flow test clock mutex is not poisoned");
    assert!(slot.is_none(), "the route-flow test clock is single-owner");
    *slot = Some(now);
    TestClockGuard
}

struct RuntimeGate {
    run_id: OnceLock<Option<String>>,
}

impl RuntimeGate {
    const fn new() -> Self {
        Self {
            run_id: OnceLock::new(),
        }
    }

    fn active_with<F>(&self, read: F) -> Option<&str>
    where
        F: FnOnce() -> Option<String>,
    {
        self.run_id
            .get_or_init(|| read().filter(|value| valid_run_id(value)))
            .as_deref()
    }
}

fn valid_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RUN_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn active_run_id() -> Option<&'static str> {
    ACTIVE_RUN.active_with(|| std::env::var(RUN_ID_ENV).ok())
}

#[cfg(test)]
pub(crate) fn active_run_id_for_test() -> Option<&'static str> {
    active_run_id()
}

/// Three same-process native callback timestamps carried with one accepted
/// event. The type is `Copy`; it owns no allocation, payload, peer identity or
/// transport capability.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeReceipt {
    callback_enter: Instant,
    mailbox_attempt: Option<Instant>,
    dequeued: Option<Instant>,
}

impl NativeReceipt {
    /// Stamp the actual insertion attempt. A refused insertion drops this
    /// receipt with the refused event and cannot produce a qualified row.
    pub(crate) fn mark_mailbox_attempt(&mut self) {
        self.mailbox_attempt = Some(route_flow_now());
    }

    /// Stamp exposure of the exact accepted queued item to the engine.
    pub(crate) fn mark_dequeued(&mut self) {
        self.dequeued = Some(route_flow_now());
    }

    #[cfg(test)]
    pub(crate) fn for_test(callback_enter: Instant) -> Self {
        Self {
            callback_enter,
            mailbox_attempt: None,
            dequeued: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn mark_mailbox_attempt_at_for_test(&mut self, at: Instant) {
        self.mailbox_attempt = Some(at);
    }

    #[cfg(test)]
    pub(crate) fn mark_dequeued_at_for_test(&mut self, at: Instant) {
        self.dequeued = Some(at);
    }

    #[cfg(test)]
    pub(crate) fn timestamps_for_test(self) -> (Instant, Option<Instant>, Option<Instant>) {
        (self.callback_enter, self.mailbox_attempt, self.dequeued)
    }
}

/// Start the transport receipt only for a valid runtime opt-in. The first call
/// may allocate while the process environment is read and validated; after
/// that one-time gate initialization, the disabled per-callback path allocates
/// nothing and never reaches `Instant::now`.
pub(crate) fn capture_native_receipt() -> Option<NativeReceipt> {
    capture_native_receipt_with(
        &ACTIVE_RUN,
        &MONOTONIC_ANCHOR,
        || std::env::var(RUN_ID_ENV).ok(),
        route_flow_now,
    )
}

fn capture_native_receipt_with<R, N>(
    gate: &RuntimeGate,
    anchor: &OnceLock<Instant>,
    read: R,
    mut now: N,
) -> Option<NativeReceipt>
where
    R: FnOnce() -> Option<String>,
    N: FnMut() -> Instant,
{
    gate.active_with(read)?;
    // Latch the anchor before the callback stamp. Even if two native
    // callbacks arrive concurrently, whichever initializes the anchor does so
    // before either callback can retain a timestamp. The disabled path above
    // still reaches neither clock nor anchor.
    anchor.get_or_init(|| now());
    Some(NativeReceipt {
        callback_enter: now(),
        mailbox_attempt: None,
        dequeued: None,
    })
}

#[cfg(test)]
pub(crate) fn capture_native_receipt_with_gate_for_test<F>(
    enabled: bool,
    now: F,
) -> Option<NativeReceipt>
where
    F: FnOnce() -> Instant,
{
    enabled.then(|| NativeReceipt {
        callback_enter: now(),
        mailbox_attempt: None,
        dequeued: None,
    })
}

/// Handler entry retained through decode, exact-session admission and routed
/// policy admission. Missing native timestamps stay missing rather than being
/// represented as zeroes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HandlerReceipt {
    native: Option<NativeReceipt>,
    handler_enter: Instant,
}

pub(crate) fn capture_handler_receipt(native: Option<NativeReceipt>) -> Option<HandlerReceipt> {
    active_run_id()?;
    // Origin rows have no native receipt, so establish the same process-wide
    // origin before their handler stamp. Inbound rows normally find the anchor
    // already latched by `capture_native_receipt`; this remains the safe
    // fallback for a retained receipt supplied by another bounded seam.
    MONOTONIC_ANCHOR.get_or_init(route_flow_now);
    Some(HandlerReceipt {
        native,
        handler_enter: route_flow_now(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteRole {
    Origin,
    Relay,
    Destination,
}

impl RouteRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::Relay => "relay",
            Self::Destination => "destination",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Request,
    Reply,
}

impl Direction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Reply => "reply",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteOutcome {
    /// A local forwarding enqueue completed, or the destination application
    /// gateway accepted the frame. This is not remote or wire delivery proof.
    Delivered,
    Unavailable,
    Refused,
    OutcomeUnknown,
}

impl RouteOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Unavailable => "unavailable",
            Self::Refused => "refused",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }

    /// Diagnostic classification only. It deliberately does not alter the
    /// operation's native result; ambiguity dominates a simultaneous success.
    pub(crate) fn from_dispatch(report: &RouteDispatchReport) -> Self {
        if report.outcome_unknown > 0 || report.failed > 0 {
            Self::OutcomeUnknown
        } else if report.delivered > 0 {
            Self::Delivered
        } else if report.refused > 0 {
            Self::Refused
        } else {
            Self::Unavailable
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SelectedPayload {
    direction: Direction,
    seq: u64,
}

#[derive(Clone, Copy, Debug)]
enum SelectedEvidence {
    HistoricalEcho(SelectedPayload),
    CiphertextMetadata,
}

fn select_payload(payload: &serde_json::Value, expected_run_id: &str) -> Option<SelectedPayload> {
    let object = payload.as_object()?;
    if object.get("run_id")?.as_str()? != expected_run_id {
        return None;
    }
    let seq = object.get("seq")?.as_u64()?;
    if seq >= MAX_SELECTED_SEQUENCE_EXCLUSIVE {
        return None;
    }
    let direction = match object.get("kind")?.as_str()? {
        "request" => Direction::Request,
        "echo" => Direction::Reply,
        _ => return None,
    };
    Some(SelectedPayload { direction, seq })
}

/// An admitted, selected routed disposition. All identity-bearing envelope
/// fields have been reduced to the opaque route id and bounded numeric shape.
/// Copying transfers only scalar observation data: no payload, capability,
/// resource lease or emission reservation is held here. The emission limiter
/// is consulted only after the actual terminal dispatch, never at selection.
#[derive(Clone, Copy)]
pub(crate) struct SelectedRouteFlow {
    run_id: &'static str,
    route_id: [u8; 16],
    evidence: SelectedEvidence,
    role: RouteRole,
    hop_index: u8,
    remaining_ttl: u8,
    owner_epoch: Option<u64>,
    receipt: HandlerReceipt,
    route_decision: Instant,
}

impl SelectedRouteFlow {
    /// Select only after the caller has obtained an ordinary successful
    /// `RouteAdmission`. The payload remains borrowed and is never copied into
    /// diagnostic custody. Ciphertext selection means only that this process
    /// opted into metadata observation, not that any application run/sequence
    /// was recognized. The caller must not use this as an admission check.
    pub(crate) fn after_admission(
        envelope: &RoutedApplicationEnvelope,
        role: RouteRole,
        owner_epoch: Option<u64>,
        receipt: Option<HandlerReceipt>,
    ) -> Option<Self> {
        Self::after_admission_with(
            envelope,
            role,
            owner_epoch,
            receipt,
            active_run_id(),
            route_flow_now,
        )
    }

    fn after_admission_with(
        envelope: &RoutedApplicationEnvelope,
        role: RouteRole,
        owner_epoch: Option<u64>,
        receipt: Option<HandlerReceipt>,
        local_run_label: Option<&'static str>,
        now: impl FnOnce() -> Instant,
    ) -> Option<Self> {
        let run_id = local_run_label.filter(|value| valid_run_id(value))?;
        let receipt = receipt?;
        let evidence = match envelope.payload() {
            ClosedRoutedPayload::ChannelFrame { payload, .. } => {
                SelectedEvidence::HistoricalEcho(select_payload(payload, run_id)?)
            }
            // Only outer routing metadata is observed. The process-local
            // opt-in does not identify an authenticated application workload.
            ClosedRoutedPayload::EndpointCiphertext { .. } => SelectedEvidence::CiphertextMetadata,
            ClosedRoutedPayload::EndpointControl { .. } => return None,
        };
        let hops = u8::try_from(envelope.hops().len()).ok()?;
        let hop_index = match role {
            RouteRole::Destination => hops,
            RouteRole::Origin | RouteRole::Relay => hops.checked_sub(1)?,
        };
        Some(Self {
            run_id,
            route_id: envelope.message_id(),
            evidence,
            role,
            hop_index,
            remaining_ttl: envelope.remaining_ttl(),
            owner_epoch,
            receipt,
            route_decision: now(),
        })
    }

    pub(crate) fn dispatch_started(&self) -> Instant {
        route_flow_now()
    }

    pub(crate) fn emit(
        self,
        state: &NetworkState,
        dispatch_started: Option<Instant>,
        outcome: RouteOutcome,
    ) {
        let finished = route_flow_now();
        if let Some(event) = self.limited_event(&EMISSIONS, dispatch_started, finished, outcome) {
            state.emit(event);
        }
    }

    fn limited_event(
        self,
        limiter: &EmissionLimiter,
        dispatch_started: Option<Instant>,
        finished: Instant,
        outcome: RouteOutcome,
    ) -> Option<MeshEvent> {
        match limiter.reserve() {
            EmissionPermit::Data => Some(self.event(dispatch_started, finished, outcome)),
            EmissionPermit::Overflow => Some(match self.evidence {
                SelectedEvidence::HistoricalEcho(_) => overflow_event(),
                SelectedEvidence::CiphertextMetadata => ciphertext_overflow_event(),
            }),
            EmissionPermit::Suppress => None,
        }
    }

    fn event(
        self,
        dispatch_started: Option<Instant>,
        finished: Instant,
        outcome: RouteOutcome,
    ) -> MeshEvent {
        let native = self.receipt.native;
        let callback_to_insert_us = native.and_then(|receipt| {
            receipt
                .mailbox_attempt
                .and_then(|end| checked_us(receipt.callback_enter, end))
        });
        let insert_to_dequeue_us = native.and_then(|receipt| {
            receipt
                .mailbox_attempt
                .and_then(|start| receipt.dequeued.and_then(|end| checked_us(start, end)))
        });
        let dequeue_to_handler_us = native.and_then(|receipt| {
            receipt
                .dequeued
                .and_then(|start| checked_us(start, self.receipt.handler_enter))
        });
        let handler_to_route_decision_us =
            checked_us(self.receipt.handler_enter, self.route_decision);
        let route_dispatch_us = dispatch_started.and_then(|start| checked_us(start, finished));
        let handler_total_us = checked_us(self.receipt.handler_enter, finished);
        let disposition_finished_mono_us = monotonic_offset_us(&MONOTONIC_ANCHOR, finished);
        let SelectedEvidence::HistoricalEcho(selected) = self.evidence else {
            return ciphertext_disposition_event(
                &self,
                [
                    callback_to_insert_us,
                    insert_to_dequeue_us,
                    dequeue_to_handler_us,
                    handler_to_route_decision_us,
                    route_dispatch_us,
                    handler_total_us,
                    disposition_finished_mono_us,
                ],
                outcome,
            );
        };
        disposition_event(
            self.run_id,
            self.route_id,
            selected.direction,
            selected.seq,
            self.role,
            self.hop_index,
            self.remaining_ttl,
            self.owner_epoch,
            callback_to_insert_us,
            insert_to_dequeue_us,
            dequeue_to_handler_us,
            handler_to_route_decision_us,
            route_dispatch_us,
            handler_total_us,
            disposition_finished_mono_us,
            outcome,
        )
    }
}

fn ciphertext_disposition_event(
    flow: &SelectedRouteFlow,
    times: [Option<u64>; 7],
    outcome: RouteOutcome,
) -> MeshEvent {
    MeshEvent::Diag(DiagEntry {
        ts: crate::engine::state::now_unix_ms(),
        network_id: "route_flow_diagnostic".to_string(),
        level: DiagLevel::Debug,
        category: "route_flow".to_string(),
        message: "routed ciphertext disposition".to_string(),
        detail: serde_json::json!({
            "schema": CIPHERTEXT_SCHEMA,
            "kind": "disposition",
            "local_run_label": flow.run_id,
            "label_attribution": "local_opt_in_only",
            "route_id": hex::encode(flow.route_id),
            "role": flow.role.as_str(),
            "hop_index": flow.hop_index,
            "remaining_ttl": flow.remaining_ttl,
            "owner_epoch": flow.owner_epoch.map(|value| value.to_string()),
            "callback_to_insert_us": times[0],
            "insert_to_dequeue_us": times[1],
            "dequeue_to_handler_us": times[2],
            "handler_to_route_decision_us": times[3],
            "route_dispatch_us": times[4],
            "handler_total_us": times[5],
            "disposition_finished_mono_us": times[6],
            "outcome": outcome.as_str(),
        }),
    })
}

fn ciphertext_overflow_event() -> MeshEvent {
    MeshEvent::Diag(DiagEntry {
        ts: crate::engine::state::now_unix_ms(),
        network_id: "route_flow_diagnostic".to_string(),
        level: DiagLevel::Debug,
        category: "route_flow".to_string(),
        message: "route ciphertext flow overflow".to_string(),
        detail: serde_json::json!({
            "schema": CIPHERTEXT_SCHEMA,
            "kind": "overflow",
            "capacity": MAX_DATA_ROWS,
            "outcome": "outcome_unknown",
        }),
    })
}

fn monotonic_offset_us(anchor: &OnceLock<Instant>, at: Instant) -> Option<u64> {
    checked_us(*anchor.get()?, at)
}

fn checked_us(start: Instant, end: Instant) -> Option<u64> {
    let elapsed = end.checked_duration_since(start)?;
    if elapsed > MAX_MEASURED_DURATION {
        return None;
    }
    u64::try_from(elapsed.as_micros()).ok()
}

#[allow(clippy::too_many_arguments)]
fn disposition_event(
    run_id: &str,
    route_id: [u8; 16],
    direction: Direction,
    seq: u64,
    role: RouteRole,
    hop_index: u8,
    remaining_ttl: u8,
    owner_epoch: Option<u64>,
    callback_to_insert_us: Option<u64>,
    insert_to_dequeue_us: Option<u64>,
    dequeue_to_handler_us: Option<u64>,
    handler_to_route_decision_us: Option<u64>,
    route_dispatch_us: Option<u64>,
    handler_total_us: Option<u64>,
    disposition_finished_mono_us: Option<u64>,
    outcome: RouteOutcome,
) -> MeshEvent {
    MeshEvent::Diag(DiagEntry {
        ts: crate::engine::state::now_unix_ms(),
        // One daemon in the field cohort owns one configured network. The
        // actual network token is intentionally not copied into this evidence.
        network_id: "route_flow_diagnostic".to_string(),
        level: DiagLevel::Debug,
        category: "route_flow".to_string(),
        message: "routed disposition".to_string(),
        detail: serde_json::json!({
            "schema": "myownmesh.route-flow/v2",
            "kind": "disposition",
            "run_id": run_id,
            "direction": direction.as_str(),
            "seq": seq,
            "route_id": hex::encode(route_id),
            "role": role.as_str(),
            "hop_index": hop_index,
            "remaining_ttl": remaining_ttl,
            "owner_epoch": owner_epoch.map(|value| value.to_string()),
            "callback_to_insert_us": callback_to_insert_us,
            "insert_to_dequeue_us": insert_to_dequeue_us,
            "dequeue_to_handler_us": dequeue_to_handler_us,
            "handler_to_route_decision_us": handler_to_route_decision_us,
            "route_dispatch_us": route_dispatch_us,
            "handler_total_us": handler_total_us,
            // This is an offset from one process-local monotonic anchor, not
            // Unix time. Together with the existing contiguous durations it
            // reconstructs callback entry, handler entry and dispatch start.
            // Each integer duration truncation can add at most one microsecond
            // of subtraction error (at most four across the ingress path).
            "disposition_finished_mono_us": disposition_finished_mono_us,
            "outcome": outcome.as_str(),
        }),
    })
}

fn overflow_event() -> MeshEvent {
    MeshEvent::Diag(DiagEntry {
        ts: crate::engine::state::now_unix_ms(),
        network_id: "route_flow_diagnostic".to_string(),
        level: DiagLevel::Debug,
        category: "route_flow".to_string(),
        message: "route flow overflow".to_string(),
        detail: serde_json::json!({
            "schema": "myownmesh.route-flow/v2",
            "kind": "overflow",
            "capacity": MAX_DATA_ROWS,
            "outcome": "outcome_unknown",
        }),
    })
}

struct EmissionLimiter {
    count: AtomicU8,
}

impl EmissionLimiter {
    const fn new() -> Self {
        Self {
            count: AtomicU8::new(0),
        }
    }

    fn reserve(&self) -> EmissionPermit {
        loop {
            let current = self.count.load(Ordering::Relaxed);
            if current > MAX_DATA_ROWS {
                return EmissionPermit::Suppress;
            }
            let next = current.saturating_add(1);
            if self
                .count
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return if current < MAX_DATA_ROWS {
                    EmissionPermit::Data
                } else {
                    EmissionPermit::Overflow
                };
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmissionPermit {
    Data,
    Overflow,
    Suppress,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    // Signed outer envelope, ciphertext-shaped body ONLY. These schema tests
    // do not establish endpoint AEAD confirmation or native gateway delivery.
    fn ciphertext_envelope() -> (RoutedApplicationEnvelope, ed25519_dalek::SigningKey) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
        let peer = ed25519_dalek::SigningKey::from_bytes(&[92; 32]);
        let source =
            crate::semantic::DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes())
                .unwrap();
        let destination =
            crate::semantic::DeviceId::from_public_key_bytes(*peer.verifying_key().as_bytes())
                .unwrap();
        let context = crate::semantic::MeshContextId::from_bytes([91; 32]);
        let payload = crate::protocol::topology::ciphertext_payload_for_test(
            context,
            &source,
            &destination,
            32,
        );
        let mut envelope = RoutedApplicationEnvelope::new(
            context,
            source.clone(),
            destination,
            [93; 16],
            4,
            payload,
            &key,
        )
        .unwrap();
        envelope.append_hop(source, &key).unwrap();
        envelope.verify().unwrap();
        (envelope, key)
    }

    fn ciphertext_selection(
        envelope: &RoutedApplicationEnvelope,
        role: RouteRole,
        at: Instant,
    ) -> SelectedRouteFlow {
        SelectedRouteFlow::after_admission_with(
            envelope,
            role,
            Some(9),
            Some(HandlerReceipt {
                native: Some(NativeReceipt {
                    callback_enter: at,
                    mailbox_attempt: Some(at + Duration::from_micros(5)),
                    dequeued: Some(at + Duration::from_micros(15)),
                }),
                handler_enter: at + Duration::from_micros(20),
            }),
            Some("local-ciphertext-test"),
            || at + Duration::from_micros(30),
        )
        .unwrap()
    }

    #[test]
    fn ciphertext_metadata_schema_preserves_outer_coordinates_and_receipt_intervals() {
        let (envelope, _) = ciphertext_envelope();
        let at = Instant::now();
        for (role, hop_index) in [
            (RouteRole::Origin, 0),
            (RouteRole::Relay, 0),
            (RouteRole::Destination, 1),
        ] {
            let flow = ciphertext_selection(&envelope, role, at);
            let value = serde_json::to_value(flow.event(
                Some(at + Duration::from_micros(40)),
                at + Duration::from_micros(90),
                RouteOutcome::Delivered,
            ))
            .unwrap();
            let detail = value["detail"].as_object().unwrap();
            assert_eq!(detail["schema"], CIPHERTEXT_SCHEMA);
            assert_eq!(detail["local_run_label"], "local-ciphertext-test");
            assert_eq!(detail["label_attribution"], "local_opt_in_only");
            assert_eq!(detail["route_id"], hex::encode(envelope.message_id()));
            assert_eq!(detail["role"], role.as_str());
            assert_eq!(detail["hop_index"], hop_index);
            assert_eq!(detail["remaining_ttl"], envelope.remaining_ttl());
            assert_eq!(detail["owner_epoch"], "9");
            assert_eq!(detail["outcome"], "delivered");
            for (name, expected) in [
                ("callback_to_insert_us", 5),
                ("insert_to_dequeue_us", 10),
                ("dequeue_to_handler_us", 5),
                ("handler_to_route_decision_us", 10),
                ("route_dispatch_us", 50),
                ("handler_total_us", 70),
            ] {
                assert_eq!(detail[name].as_u64(), Some(expected));
            }
            let mut names: Vec<_> = detail.keys().map(String::as_str).collect();
            names.sort_unstable();
            assert_eq!(
                names,
                [
                    "callback_to_insert_us",
                    "dequeue_to_handler_us",
                    "disposition_finished_mono_us",
                    "handler_to_route_decision_us",
                    "handler_total_us",
                    "hop_index",
                    "insert_to_dequeue_us",
                    "kind",
                    "label_attribution",
                    "local_run_label",
                    "outcome",
                    "owner_epoch",
                    "remaining_ttl",
                    "role",
                    "route_dispatch_us",
                    "route_id",
                    "schema"
                ]
            );
            assert_eq!(value["network_id"], "route_flow_diagnostic");
            let text = serde_json::to_string(&value).unwrap();
            assert!(!text.contains(&envelope.origin().to_string()));
            assert!(!text.contains(&envelope.destination().to_string()));
            for excluded in [
                "channel",
                "payload",
                "sender",
                "ephemeral",
                "transcript",
                "sequence",
                "direction",
                "run_id",
            ] {
                assert!(!detail.contains_key(excluded));
            }
        }
    }

    #[test]
    fn ciphertext_selection_requires_opt_in_receipt_and_excludes_endpoint_control() {
        let (envelope, key) = ciphertext_envelope();
        let at = Instant::now();
        let receipt = Some(HandlerReceipt {
            native: None,
            handler_enter: at,
        });
        for label in [None, Some(""), Some("invalid.label")] {
            assert!(SelectedRouteFlow::after_admission_with(
                &envelope,
                RouteRole::Destination,
                None,
                receipt,
                label,
                || panic!("disabled selection must not sample clock")
            )
            .is_none());
        }
        assert!(SelectedRouteFlow::after_admission_with(
            &envelope,
            RouteRole::Destination,
            None,
            None,
            Some("local-only"),
            || panic!("missing receipt")
        )
        .is_none());
        let ClosedRoutedPayload::EndpointCiphertext { packet } = envelope.payload() else {
            unreachable!()
        };
        let control = crate::protocol::topology::EndpointCipherControl::Confirmation(
            crate::protocol::endpoint_cipher::KeyConfirmation {
                binding: packet.binding.clone(),
                sender: packet.sender,
                transcript_hash: [1; 32],
                tag: [2; 16],
            },
        );
        let control = RoutedApplicationEnvelope::new(
            envelope.context_id(),
            envelope.origin().clone(),
            envelope.destination().clone(),
            [94; 16],
            4,
            ClosedRoutedPayload::EndpointControl { control },
            &key,
        )
        .unwrap();
        assert!(SelectedRouteFlow::after_admission_with(
            &control,
            RouteRole::Destination,
            None,
            receipt,
            Some("local-only"),
            || panic!("control is not application delivery")
        )
        .is_none());
        let flow = SelectedRouteFlow::after_admission_with(
            &envelope,
            RouteRole::Destination,
            None,
            receipt,
            Some("local-only"),
            || at,
        )
        .unwrap();
        let value = serde_json::to_value(flow.event(None, at, RouteOutcome::Refused)).unwrap();
        assert!(value["detail"]["callback_to_insert_us"].is_null());
        assert!(value["detail"]["route_dispatch_us"].is_null());
        assert!(value["detail"]["owner_epoch"].is_null());
        assert_eq!(value["detail"]["outcome"], "refused");
    }

    #[test]
    fn ciphertext_maximal_event_and_shared_limiter_remain_bounded() {
        let (envelope, _) = ciphertext_envelope();
        let at = Instant::now();
        let mut flow = ciphertext_selection(&envelope, RouteRole::Relay, at);
        flow.run_id = concat!(
            "rrrrrrrrrrrrrrrrrrrr",
            "rrrrrrrrrrrrrrrrrrrr",
            "rrrrrrrrrrrrrrrrrrrr",
            "rrrrrrrrrrrrrrrrrrrr"
        );
        flow.route_id = [255; 16];
        flow.hop_index = u8::MAX;
        flow.remaining_ttl = u8::MAX;
        flow.owner_epoch = Some(u64::MAX);
        let mut event = ciphertext_disposition_event(
            &flow,
            [Some(MAX_MEASURED_DURATION.as_micros() as u64); 7],
            RouteOutcome::OutcomeUnknown,
        );
        let MeshEvent::Diag(entry) = &mut event else {
            unreachable!()
        };
        entry.ts = u64::MAX;
        let bytes = serde_json::to_vec(&event).unwrap();
        assert!(bytes.len() <= MAX_SERIALIZED_EVENT_BYTES, "{}", bytes.len());
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(
            value["detail"]["disposition_finished_mono_us"],
            86_400_000_000u64
        );

        let limiter = EmissionLimiter::new();
        for index in 0..MAX_DATA_ROWS {
            let mut flow = ciphertext_selection(&envelope, RouteRole::Relay, at);
            if index % 2 == 0 {
                flow.evidence = SelectedEvidence::HistoricalEcho(SelectedPayload {
                    direction: Direction::Request,
                    seq: 0,
                });
            }
            let value = serde_json::to_value(
                flow.limited_event(
                    &limiter,
                    None,
                    at + Duration::from_micros(90),
                    RouteOutcome::OutcomeUnknown,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(value["detail"]["kind"], "disposition");
            assert_eq!(value["detail"]["outcome"], "outcome_unknown");
        }
        let overflow = ciphertext_selection(&envelope, RouteRole::Relay, at)
            .limited_event(&limiter, None, at, RouteOutcome::Delivered)
            .unwrap();
        assert!(serde_json::to_vec(&overflow).unwrap().len() <= MAX_SERIALIZED_EVENT_BYTES);
        let value = serde_json::to_value(overflow).unwrap();
        assert_eq!(
            value["detail"],
            serde_json::json!({"schema": CIPHERTEXT_SCHEMA,
            "kind": "overflow", "capacity": 64, "outcome": "outcome_unknown"})
        );
        assert!(ciphertext_selection(&envelope, RouteRole::Relay, at)
            .limited_event(&limiter, None, at, RouteOutcome::Delivered)
            .is_none());
    }

    #[test]
    fn copied_origin_metadata_has_no_emission_permit_and_obeys_terminal_limiter() {
        fn requires_copy<T: Copy>() {}
        requires_copy::<SelectedRouteFlow>();
        let (envelope, _) = ciphertext_envelope();
        let at = Instant::now();
        let selected = ciphertext_selection(&envelope, RouteRole::Origin, at);
        let limiter = EmissionLimiter::new();
        let queued = Some(selected);
        let dispatch = queued;
        assert_eq!(
            limiter.count.load(Ordering::Relaxed),
            0,
            "selection and scalar handoff reserve no terminal emission"
        );
        // Pure observation/limiter boundary, not repeated production writes
        // or native outcome qualification. Each terminal emission shares the
        // same limiter; copying never duplicates a pre-reserved permit.
        for _ in 0..MAX_DATA_ROWS {
            let event = dispatch
                .unwrap()
                .limited_event(&limiter, Some(at), at, RouteOutcome::Delivered)
                .unwrap();
            let value = serde_json::to_value(event).unwrap();
            assert_eq!(value["detail"]["role"], "origin");
            assert_eq!(value["detail"]["schema"], CIPHERTEXT_SCHEMA);
        }
        let event = dispatch
            .unwrap()
            .limited_event(&limiter, Some(at), at, RouteOutcome::Delivered)
            .unwrap();
        assert_eq!(
            serde_json::to_value(event).unwrap()["detail"]["kind"],
            "overflow"
        );
        assert!(dispatch
            .unwrap()
            .limited_event(&limiter, Some(at), at, RouteOutcome::Delivered)
            .is_none());
    }

    #[test]
    fn disabled_gate_does_not_call_clock() {
        let calls = AtomicUsize::new(0);
        let receipt = capture_native_receipt_with_gate_for_test(false, || {
            calls.fetch_add(1, AtomicOrdering::SeqCst);
            Instant::now()
        });
        assert!(receipt.is_none());
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 0);
    }

    #[test]
    fn runtime_gate_reads_once_and_uses_the_production_selector_grammar() {
        let valid_reads = AtomicUsize::new(0);
        let valid = RuntimeGate::new();
        assert_eq!(
            valid.active_with(|| {
                valid_reads.fetch_add(1, AtomicOrdering::SeqCst);
                Some("first-echo-route-cc6-c1".to_string())
            }),
            Some("first-echo-route-cc6-c1")
        );
        assert_eq!(
            valid.active_with(|| panic!("the gate is already initialized")),
            Some("first-echo-route-cc6-c1")
        );
        assert_eq!(valid_reads.load(AtomicOrdering::SeqCst), 1);

        for rejected in [
            None,
            Some(String::new()),
            Some("contains.dot".to_string()),
            Some("x".repeat(MAX_RUN_ID_BYTES + 1)),
        ] {
            let gate = RuntimeGate::new();
            assert_eq!(gate.active_with(|| rejected), None);
            assert_eq!(
                gate.active_with(|| panic!("a disabled gate is still latched")),
                None
            );
        }
    }

    #[test]
    fn production_capture_seam_checks_runtime_gate_before_clock() {
        let clock_calls = AtomicUsize::new(0);
        let disabled = RuntimeGate::new();
        let disabled_anchor = OnceLock::new();
        assert!(capture_native_receipt_with(
            &disabled,
            &disabled_anchor,
            || Some("contains.dot".to_string()),
            || {
                clock_calls.fetch_add(1, AtomicOrdering::SeqCst);
                Instant::now()
            },
        )
        .is_none());
        assert_eq!(clock_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(disabled_anchor.get().is_none());

        let enabled = RuntimeGate::new();
        let enabled_anchor = OnceLock::new();
        assert!(capture_native_receipt_with(
            &enabled,
            &enabled_anchor,
            || Some("first-echo-route-cc6-c1".to_string()),
            || {
                clock_calls.fetch_add(1, AtomicOrdering::SeqCst);
                Instant::now()
            },
        )
        .is_some());
        assert_eq!(clock_calls.load(AtomicOrdering::SeqCst), 2);
        let first_anchor = *enabled_anchor
            .get()
            .expect("enabled capture latches anchor");
        assert!(capture_native_receipt_with(
            &enabled,
            &enabled_anchor,
            || panic!("the runtime gate is already initialized"),
            || {
                clock_calls.fetch_add(1, AtomicOrdering::SeqCst);
                Instant::now()
            },
        )
        .is_some());
        assert_eq!(clock_calls.load(AtomicOrdering::SeqCst), 3);
        assert_eq!(enabled_anchor.get(), Some(&first_anchor));
    }

    #[test]
    fn receipt_retains_exact_three_stamps() {
        let start = Instant::now();
        let mut receipt = NativeReceipt::for_test(start);
        receipt.mark_mailbox_attempt_at_for_test(start + Duration::from_micros(7));
        receipt.mark_dequeued_at_for_test(start + Duration::from_micros(19));
        assert_eq!(
            receipt.timestamps_for_test(),
            (
                start,
                Some(start + Duration::from_micros(7)),
                Some(start + Duration::from_micros(19))
            )
        );
    }

    #[test]
    fn selector_accepts_only_bounded_request_or_echo_rows() {
        let run = "first-echo-route-cc6-c1";
        let request = serde_json::json!({"run_id": run, "seq": 0, "kind": "request"});
        let reply = serde_json::json!({"run_id": run, "seq": 9_999, "kind": "echo"});
        assert_eq!(
            select_payload(&request, run).unwrap().direction,
            Direction::Request
        );
        assert_eq!(
            select_payload(&reply, run).unwrap().direction,
            Direction::Reply
        );
        for value in [
            serde_json::json!({"run_id": "wrong", "seq": 0, "kind": "request"}),
            serde_json::json!({"run_id": run, "seq": 10_000, "kind": "request"}),
            serde_json::json!({"run_id": run, "seq": 0, "kind": "finish"}),
            serde_json::json!({"run_id": run, "seq": "0", "kind": "request"}),
            serde_json::json!([run, 0, "request"]),
        ] {
            assert!(select_payload(&value, run).is_none());
        }
    }

    #[test]
    fn run_id_gate_is_bounded_ascii() {
        assert!(valid_run_id("first-echo-route-cc6-c1"));
        assert!(valid_run_id("A_z-09"));
        assert!(!valid_run_id(""));
        assert!(!valid_run_id("contains space"));
        assert!(!valid_run_id("contains/slash"));
        assert!(!valid_run_id(&"x".repeat(81)));
    }

    #[test]
    fn unknown_dispatch_dominates_simultaneous_delivery_without_mutation() {
        let report = RouteDispatchReport {
            delivered: 1,
            outcome_unknown: 1,
            ..RouteDispatchReport::default()
        };
        assert_eq!(
            RouteOutcome::from_dispatch(&report),
            RouteOutcome::OutcomeUnknown
        );
        assert_eq!(report.delivered, 1);
    }

    #[test]
    fn limiter_allows_sixty_four_rows_and_one_overflow_only() {
        let limiter = EmissionLimiter::new();
        for _ in 0..MAX_DATA_ROWS {
            assert_eq!(limiter.reserve(), EmissionPermit::Data);
        }
        assert_eq!(limiter.reserve(), EmissionPermit::Overflow);
        assert_eq!(limiter.reserve(), EmissionPermit::Suppress);
        assert_eq!(limiter.reserve(), EmissionPermit::Suppress);
    }

    #[test]
    fn maximal_event_is_bounded_and_contains_no_network_or_payload_identity() {
        let event = disposition_event(
            &"r".repeat(MAX_RUN_ID_BYTES),
            [0xff; 16],
            Direction::Reply,
            MAX_SELECTED_SEQUENCE_EXCLUSIVE - 1,
            RouteRole::Relay,
            u8::MAX,
            u8::MAX,
            Some(u64::MAX),
            Some(MAX_MEASURED_DURATION.as_micros() as u64),
            Some(MAX_MEASURED_DURATION.as_micros() as u64),
            Some(MAX_MEASURED_DURATION.as_micros() as u64),
            Some(MAX_MEASURED_DURATION.as_micros() as u64),
            Some(MAX_MEASURED_DURATION.as_micros() as u64),
            Some(MAX_MEASURED_DURATION.as_micros() as u64),
            Some(MAX_MEASURED_DURATION.as_micros() as u64),
            RouteOutcome::OutcomeUnknown,
        );
        let bytes = serde_json::to_vec(&event).unwrap();
        assert!(bytes.len() <= MAX_SERIALIZED_EVENT_BYTES, "{}", bytes.len());
        let text = String::from_utf8(bytes).unwrap();
        for forbidden in ["payload", "body", "channel", "peer", "sdp", "error"] {
            assert!(!text.contains(forbidden));
        }
        assert!(text.contains("\"schema\":\"myownmesh.route-flow/v2\""));
        assert!(text.contains("\"disposition_finished_mono_us\":86400000000"));
        assert!(text.contains("\"network_id\":\"route_flow_diagnostic\""));
    }

    #[test]
    fn held_handler_and_dispatch_durations_use_exact_same_process_intervals() {
        let start = Instant::now();
        let anchor = *MONOTONIC_ANCHOR.get_or_init(|| start);
        let finished = start + Duration::from_micros(90);
        let flow = SelectedRouteFlow {
            run_id: "first-echo-route-cc6-c1",
            route_id: [7; 16],
            evidence: SelectedEvidence::HistoricalEcho(SelectedPayload {
                direction: Direction::Request,
                seq: 3,
            }),
            role: RouteRole::Relay,
            hop_index: 2,
            remaining_ttl: 5,
            owner_epoch: Some(9),
            receipt: HandlerReceipt {
                native: Some(NativeReceipt {
                    callback_enter: start,
                    mailbox_attempt: Some(start + Duration::from_micros(5)),
                    dequeued: Some(start + Duration::from_micros(15)),
                }),
                handler_enter: start + Duration::from_micros(20),
            },
            route_decision: start + Duration::from_micros(30),
        };
        let event = flow.event(
            Some(start + Duration::from_micros(40)),
            finished,
            RouteOutcome::Delivered,
        );
        let value = serde_json::to_value(event).unwrap();
        let detail = value
            .get("detail")
            .and_then(serde_json::Value::as_object)
            .unwrap();
        for (key, expected) in [
            ("callback_to_insert_us", 5),
            ("insert_to_dequeue_us", 10),
            ("dequeue_to_handler_us", 5),
            ("handler_to_route_decision_us", 10),
            ("route_dispatch_us", 50),
            ("handler_total_us", 70),
        ] {
            assert_eq!(
                detail.get(key).and_then(serde_json::Value::as_u64),
                Some(expected)
            );
        }
        assert_eq!(
            detail.get("schema").and_then(serde_json::Value::as_str),
            Some("myownmesh.route-flow/v2")
        );
        let finished_offset = detail
            .get("disposition_finished_mono_us")
            .and_then(serde_json::Value::as_u64)
            .expect("the exact finish has one bounded monotonic offset");
        assert_eq!(finished_offset, checked_us(anchor, finished).unwrap());
        let reconstructed_callback = finished_offset
            .checked_sub(detail["handler_total_us"].as_u64().unwrap())
            .and_then(|value| value.checked_sub(detail["dequeue_to_handler_us"].as_u64().unwrap()))
            .and_then(|value| value.checked_sub(detail["insert_to_dequeue_us"].as_u64().unwrap()))
            .and_then(|value| value.checked_sub(detail["callback_to_insert_us"].as_u64().unwrap()))
            .expect("the contiguous spans reconstruct callback entry");
        assert!(
            reconstructed_callback.abs_diff(checked_us(anchor, start).unwrap()) <= 4,
            "four truncated interval subtractions bound reconstruction error"
        );
        assert_eq!(
            detail.get("outcome").and_then(serde_json::Value::as_str),
            Some("delivered")
        );
    }

    #[test]
    fn overflow_schema_is_fixed_and_contains_no_selector_or_route_identity() {
        let value = serde_json::to_value(overflow_event()).unwrap();
        assert_eq!(
            value.get("event_kind").and_then(serde_json::Value::as_str),
            Some("diag")
        );
        assert_eq!(
            value.get("network_id").and_then(serde_json::Value::as_str),
            Some("route_flow_diagnostic")
        );
        let detail = value
            .get("detail")
            .and_then(serde_json::Value::as_object)
            .unwrap();
        let mut keys = detail.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["capacity", "kind", "outcome", "schema"]);
        assert_eq!(
            detail.get("capacity").and_then(serde_json::Value::as_u64),
            Some(64)
        );
        assert!(detail.get("run_id").is_none());
        assert!(detail.get("route_id").is_none());
        assert_eq!(
            detail.get("schema").and_then(serde_json::Value::as_str),
            Some("myownmesh.route-flow/v2")
        );
    }

    #[test]
    fn missing_or_reversed_timestamps_are_null_not_zero() {
        let start = Instant::now();
        let missing_anchor = OnceLock::new();
        assert_eq!(monotonic_offset_us(&missing_anchor, start), None);
        let reversed_anchor = OnceLock::new();
        reversed_anchor
            .set(start)
            .expect("the reversed-offset anchor is empty");
        assert_eq!(
            monotonic_offset_us(&reversed_anchor, start - Duration::from_micros(1)),
            None
        );
        assert_eq!(checked_us(start, start + Duration::from_micros(5)), Some(5));
        assert_eq!(checked_us(start, start - Duration::from_micros(1)), None);
        assert_eq!(
            checked_us(
                start,
                start + MAX_MEASURED_DURATION + Duration::from_micros(1)
            ),
            None
        );
    }

    #[test]
    fn finish_offsets_share_one_anchor_and_keep_the_twenty_four_hour_bound() {
        let anchor = OnceLock::new();
        let start = Instant::now();
        anchor.set(start).expect("the local test anchor is empty");
        let first = monotonic_offset_us(&anchor, start + Duration::from_micros(7)).unwrap();
        let second = monotonic_offset_us(&anchor, start + Duration::from_micros(107)).unwrap();
        assert_eq!(first, 7);
        assert_eq!(second, 107);
        assert_eq!(second - first, 100);
        assert_eq!(
            monotonic_offset_us(
                &anchor,
                start + MAX_MEASURED_DURATION + Duration::from_micros(1)
            ),
            None
        );
    }
}
