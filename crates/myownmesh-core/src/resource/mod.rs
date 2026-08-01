//! Observation-only resource accounting for the V4 transition.
//!
//! This module measures current resource use. It does not reserve capacity,
//! enforce limits, authorize work, or create a permit. See `BOUNDARY.md`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Number of independently measurable pre-authentication resource families.
pub const PRE_AUTH_RESOURCE_FAMILY_COUNT: usize = 22;

/// Number of independently measurable post-authentication resource families.
pub const POST_AUTH_RESOURCE_FAMILY_COUNT: usize = 10;

/// Resource families that may be consumed before endpoint authentication.
///
/// This is a closed set derived from section 14.1 of
/// `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`. Combined prose categories
/// are split where their measurements can vary independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PreAuthResourceFamily {
    AcceptedConnection,
    HalfOpenHandshake,
    FrameBytes,
    ParserBytes,
    DurableFactHashWork,
    DurableFactSignatureWork,
    EphemeralSignalingParseWork,
    CandidateObject,
    Socket,
    TransportObject,
    DnsWork,
    StunWork,
    IceWork,
    RelayWork,
    ConnectorSpecificWork,
    MediaQuarantine,
    PacketQuarantine,
    Timer,
    Task,
    Callback,
    DiagnosticQueue,
    Cleanup,
}

impl PreAuthResourceFamily {
    pub const ALL: [Self; PRE_AUTH_RESOURCE_FAMILY_COUNT] = [
        Self::AcceptedConnection,
        Self::HalfOpenHandshake,
        Self::FrameBytes,
        Self::ParserBytes,
        Self::DurableFactHashWork,
        Self::DurableFactSignatureWork,
        Self::EphemeralSignalingParseWork,
        Self::CandidateObject,
        Self::Socket,
        Self::TransportObject,
        Self::DnsWork,
        Self::StunWork,
        Self::IceWork,
        Self::RelayWork,
        Self::ConnectorSpecificWork,
        Self::MediaQuarantine,
        Self::PacketQuarantine,
        Self::Timer,
        Self::Task,
        Self::Callback,
        Self::DiagnosticQueue,
        Self::Cleanup,
    ];
}

/// Resource families that may be consumed after endpoint authentication.
///
/// This is a closed set derived from section 14.2 of
/// `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`. Pre-authentication
/// observations cannot be converted into one of these families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PostAuthResourceFamily {
    AuthenticatedSession,
    ApplicationQueue,
    MediaDecode,
    MediaEncode,
    RelayBandwidth,
    RelayBuffer,
    SessionRecovery,
    ApplicationCallback,
    LocalHandle,
    SubscriptionState,
}

impl PostAuthResourceFamily {
    pub const ALL: [Self; POST_AUTH_RESOURCE_FAMILY_COUNT] = [
        Self::AuthenticatedSession,
        Self::ApplicationQueue,
        Self::MediaDecode,
        Self::MediaEncode,
        Self::RelayBandwidth,
        Self::RelayBuffer,
        Self::SessionRecovery,
        Self::ApplicationCallback,
        Self::LocalHandle,
        Self::SubscriptionState,
    ];
}

/// An observed quantity of resources.
///
/// Values are measurements only. Constructing this value does not reserve the
/// represented resources and does not authorize their use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceUse {
    items: u64,
    bytes: u64,
    tasks: u64,
}

impl ResourceUse {
    pub const ZERO: Self = Self::observed(0, 0, 0);

    /// Describe an observed quantity without reserving or permitting it.
    pub const fn observed(items: u64, bytes: u64, tasks: u64) -> Self {
        Self {
            items,
            bytes,
            tasks,
        }
    }

    pub const fn items(self) -> u64 {
        self.items
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    pub const fn tasks(self) -> u64 {
        self.tasks
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            items: self.items.checked_add(other.items)?,
            bytes: self.bytes.checked_add(other.bytes)?,
            tasks: self.tasks.checked_add(other.tasks)?,
        })
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            items: self.items.saturating_add(other.items),
            bytes: self.bytes.saturating_add(other.bytes),
            tasks: self.tasks.saturating_add(other.tasks),
        }
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            items: self.items.checked_sub(other.items)?,
            bytes: self.bytes.checked_sub(other.bytes)?,
            tasks: self.tasks.checked_sub(other.tasks)?,
        })
    }

    fn saturating_sub(self, other: Self) -> Self {
        Self {
            items: self.items.saturating_sub(other.items),
            bytes: self.bytes.saturating_sub(other.bytes),
            tasks: self.tasks.saturating_sub(other.tasks),
        }
    }

    fn componentwise_max(self, other: Self) -> Self {
        Self {
            items: self.items.max(other.items),
            bytes: self.bytes.max(other.bytes),
            tasks: self.tasks.max(other.tasks),
        }
    }
}

/// Snapshot for one resource family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceFamilyReport<F> {
    pub family: F,
    pub active: ResourceUse,
    pub peak_active: ResourceUse,
    pub active_lease_count: u64,
    pub peak_active_lease_count: u64,
    pub oldest_active_lifetime: Option<Duration>,
    pub completed_lease_count: u64,
    /// Sum of each completed lease's last measured quantity.
    pub completed_total_use: ResourceUse,
    pub completed_total_lifetime: Duration,
    /// True when overflow or inconsistent internal subtraction made an exact
    /// measurement impossible. Counters still never wrap or underflow.
    pub measurement_inexact: bool,
}

/// Complete observation snapshot, including families with zero activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceReport {
    pub pre_authentication:
        [ResourceFamilyReport<PreAuthResourceFamily>; PRE_AUTH_RESOURCE_FAMILY_COUNT],
    pub post_authentication:
        [ResourceFamilyReport<PostAuthResourceFamily>; POST_AUTH_RESOURCE_FAMILY_COUNT],
}

/// A per-instance, observation-only resource accountant.
///
/// Instances share no global state. Cloning an accountant only creates another
/// handle to the same explicitly created observation instance.
#[derive(Clone, Debug)]
pub struct ResourceAccountant {
    inner: Arc<Inner>,
}

impl ResourceAccountant {
    /// Create an isolated observation instance.
    ///
    /// This does not establish limits, reserve capacity, or grant authority.
    pub fn observation_only() -> Self {
        Self {
            inner: Arc::new(Inner::default()),
        }
    }

    /// Start measuring pre-authentication resource use until the returned
    /// lease is dropped.
    pub fn observe_pre_authentication(
        &self,
        family: PreAuthResourceFamily,
        observed: ResourceUse,
    ) -> ObservationLease {
        self.observe_at(FamilyKey::PreAuth(family), observed, Instant::now())
    }

    /// Start measuring post-authentication resource use until the returned
    /// lease is dropped.
    pub fn observe_post_authentication(
        &self,
        family: PostAuthResourceFamily,
        observed: ResourceUse,
    ) -> ObservationLease {
        self.observe_at(FamilyKey::PostAuth(family), observed, Instant::now())
    }

    /// Read all family measurements without changing them.
    pub fn report(&self) -> ResourceReport {
        let state = self.inner.lock_state();
        state.report(Instant::now())
    }

    fn observe_at(
        &self,
        family: FamilyKey,
        observed: ResourceUse,
        started_at: Instant,
    ) -> ObservationLease {
        let mut state = self.inner.lock_state();
        state
            .families
            .entry(family)
            .or_default()
            .begin(observed, started_at);
        drop(state);

        ObservationLease {
            observation: Some(Observation {
                inner: Arc::clone(&self.inner),
                family,
                observed,
                started_at,
            }),
        }
    }

    #[cfg(test)]
    fn report_at(&self, now: Instant) -> ResourceReport {
        self.inner.lock_state().report(now)
    }
}

/// RAII observation interval returned by [`ResourceAccountant`].
///
/// Dropping a lease ends measurement and records its lifetime. A lease carries
/// no authority and cannot be converted into a reservation or permit.
#[derive(Debug)]
#[must_use = "dropping the observation lease immediately ends the observation"]
pub struct ObservationLease {
    observation: Option<Observation>,
}

impl ObservationLease {
    /// Replace the measured quantity for a live collection or buffer.
    ///
    /// The caller supplies a fresh measurement from the object it owns. This
    /// changes observation only. It does not resize, reserve, admit, or refuse
    /// the underlying resource.
    pub fn replace_observed(&mut self, observed: ResourceUse) {
        let Some(observation) = self.observation.as_mut() else {
            return;
        };
        let mut state = observation.inner.lock_state();
        state
            .families
            .entry(observation.family)
            .or_default()
            .replace(observation.observed, observed);
        observation.observed = observed;
    }

    #[cfg(test)]
    fn finish_at(mut self, finished_at: Instant) {
        self.complete(finished_at);
    }

    fn complete(&mut self, finished_at: Instant) {
        let Some(observation) = self.observation.take() else {
            return;
        };
        let lifetime = finished_at.saturating_duration_since(observation.started_at);
        let mut state = observation.inner.lock_state();
        state
            .families
            .entry(observation.family)
            .or_default()
            .finish(observation.observed, observation.started_at, lifetime);
    }
}

impl Drop for ObservationLease {
    fn drop(&mut self) {
        self.complete(Instant::now());
    }
}

#[derive(Debug)]
struct Observation {
    inner: Arc<Inner>,
    family: FamilyKey,
    observed: ResourceUse,
    started_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FamilyKey {
    PreAuth(PreAuthResourceFamily),
    PostAuth(PostAuthResourceFamily),
}

#[derive(Debug, Default)]
struct Inner {
    state: Mutex<State>,
}

impl Inner {
    fn lock_state(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.measurement_inexact = true;
                state
            }
        }
    }
}

#[derive(Debug, Default)]
struct State {
    families: BTreeMap<FamilyKey, FamilyState>,
    measurement_inexact: bool,
}

impl State {
    fn report(&self, now: Instant) -> ResourceReport {
        ResourceReport {
            pre_authentication: PreAuthResourceFamily::ALL
                .map(|family| self.snapshot(FamilyKey::PreAuth(family), family, now)),
            post_authentication: PostAuthResourceFamily::ALL
                .map(|family| self.snapshot(FamilyKey::PostAuth(family), family, now)),
        }
    }

    fn snapshot<F: Copy>(
        &self,
        key: FamilyKey,
        family: F,
        now: Instant,
    ) -> ResourceFamilyReport<F> {
        let state = self.families.get(&key);
        ResourceFamilyReport {
            family,
            active: state.map_or(ResourceUse::ZERO, |state| state.active),
            peak_active: state.map_or(ResourceUse::ZERO, |state| state.peak_active),
            active_lease_count: state.map_or(0, |state| state.active_lease_count),
            peak_active_lease_count: state.map_or(0, |state| state.peak_active_lease_count),
            oldest_active_lifetime: state
                .and_then(|state| state.active_starts.keys().next().copied())
                .map(|started_at| now.saturating_duration_since(started_at)),
            completed_lease_count: state.map_or(0, |state| state.completed_lease_count),
            completed_total_use: state.map_or(ResourceUse::ZERO, |state| state.completed_total_use),
            completed_total_lifetime: state
                .map_or(Duration::ZERO, |state| state.completed_total_lifetime),
            measurement_inexact: self.measurement_inexact
                || state.is_some_and(|state| state.measurement_inexact),
        }
    }
}

#[derive(Debug, Default)]
struct FamilyState {
    active: ResourceUse,
    peak_active: ResourceUse,
    active_lease_count: u64,
    peak_active_lease_count: u64,
    active_starts: BTreeMap<Instant, u64>,
    completed_lease_count: u64,
    completed_total_use: ResourceUse,
    completed_total_lifetime: Duration,
    measurement_inexact: bool,
}

impl FamilyState {
    fn begin(&mut self, observed: ResourceUse, started_at: Instant) {
        self.active = match self.active.checked_add(observed) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                self.active.saturating_add(observed)
            }
        };
        self.active_lease_count = match self.active_lease_count.checked_add(1) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                u64::MAX
            }
        };
        self.peak_active = self.peak_active.componentwise_max(self.active);
        self.peak_active_lease_count = self.peak_active_lease_count.max(self.active_lease_count);

        let count = self.active_starts.entry(started_at).or_default();
        *count = match count.checked_add(1) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                u64::MAX
            }
        };
    }

    fn replace(&mut self, previous: ResourceUse, observed: ResourceUse) {
        self.active = match self.active.checked_sub(previous) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                self.active.saturating_sub(previous)
            }
        };
        self.active = match self.active.checked_add(observed) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                self.active.saturating_add(observed)
            }
        };
        self.peak_active = self.peak_active.componentwise_max(self.active);
    }

    fn finish(&mut self, observed: ResourceUse, started_at: Instant, lifetime: Duration) {
        self.active = match self.active.checked_sub(observed) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                self.active.saturating_sub(observed)
            }
        };
        self.active_lease_count = match self.active_lease_count.checked_sub(1) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                0
            }
        };

        let remove_start = match self.active_starts.get_mut(&started_at) {
            Some(count) => match count.checked_sub(1) {
                Some(0) => true,
                Some(next) => {
                    *count = next;
                    false
                }
                None => {
                    self.measurement_inexact = true;
                    true
                }
            },
            None => {
                self.measurement_inexact = true;
                false
            }
        };
        if remove_start {
            self.active_starts.remove(&started_at);
        }

        self.completed_lease_count = match self.completed_lease_count.checked_add(1) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                u64::MAX
            }
        };
        self.completed_total_use = match self.completed_total_use.checked_add(observed) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                self.completed_total_use.saturating_add(observed)
            }
        };
        self.completed_total_lifetime = match self.completed_total_lifetime.checked_add(lifetime) {
            Some(next) => next,
            None => {
                self.measurement_inexact = true;
                Duration::MAX
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_len(fixture: &[u8]) -> u64 {
        u64::try_from(fixture.len()).expect("fixture length fits in u64")
    }

    fn fixture_count<T>(fixtures: &[T]) -> u64 {
        u64::try_from(fixtures.len()).expect("fixture count fits in u64")
    }

    fn family_report<F: Copy + PartialEq>(
        reports: &[ResourceFamilyReport<F>],
        family: F,
    ) -> ResourceFamilyReport<F> {
        *reports
            .iter()
            .find(|report| report.family == family)
            .expect("closed family is present in every report")
    }

    #[test]
    fn v4_arc02_reports_every_closed_family_without_activity() {
        let accountant = ResourceAccountant::observation_only();
        let report = accountant.report();

        assert_eq!(
            report.pre_authentication.map(|entry| entry.family),
            PreAuthResourceFamily::ALL
        );
        assert_eq!(
            report.post_authentication.map(|entry| entry.family),
            PostAuthResourceFamily::ALL
        );
        assert!(report
            .pre_authentication
            .iter()
            .all(|entry| entry.active == ResourceUse::ZERO));
        assert!(report
            .post_authentication
            .iter()
            .all(|entry| entry.active == ResourceUse::ZERO));
    }

    #[test]
    fn v4_arc02_active_and_completed_measurements_are_per_family() {
        let accountant = ResourceAccountant::observation_only();
        let base = Instant::now();
        let first_fixture = b"candidate-fixture";
        let second_fixture = b"candidate-fixture-with-more-bytes";
        let first_use = ResourceUse::observed(
            fixture_count(&[first_fixture.as_slice(), second_fixture.as_slice()]),
            fixture_len(first_fixture),
            fixture_count(&[b"candidate-task".as_slice()]),
        );
        let second_use = ResourceUse::observed(
            fixture_count(&[second_fixture.as_slice()]),
            fixture_len(second_fixture),
            ResourceUse::ZERO.tasks(),
        );
        let second_start_offset = Duration::from_millis(fixture_len(b"start-offset"));
        let observation_point =
            base + second_start_offset + Duration::from_millis(fixture_len(b"observation-window"));

        let first = accountant.observe_at(
            FamilyKey::PreAuth(PreAuthResourceFamily::CandidateObject),
            first_use,
            base,
        );
        let second = accountant.observe_at(
            FamilyKey::PreAuth(PreAuthResourceFamily::CandidateObject),
            second_use,
            base + second_start_offset,
        );

        let active = family_report(
            &accountant.report_at(observation_point).pre_authentication,
            PreAuthResourceFamily::CandidateObject,
        );
        assert_eq!(
            active.active,
            first_use.checked_add(second_use).expect("fixture sum fits")
        );
        assert_eq!(active.peak_active, active.active);
        assert_eq!(
            active.active_lease_count,
            fixture_count(&[first_fixture.as_slice(), second_fixture.as_slice()])
        );
        assert_eq!(active.peak_active_lease_count, active.active_lease_count);
        assert_eq!(
            active.oldest_active_lifetime,
            Some(observation_point.duration_since(base))
        );

        let first_lifetime = Duration::from_millis(fixture_len(b"first-lifetime"));
        let second_lifetime = Duration::from_millis(fixture_len(b"second-lifetime"));
        first.finish_at(base + first_lifetime);
        second.finish_at(base + second_start_offset + second_lifetime);

        let completed = family_report(
            &accountant.report_at(observation_point).pre_authentication,
            PreAuthResourceFamily::CandidateObject,
        );
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(
            completed.peak_active,
            first_use.checked_add(second_use).expect("fixture sum fits")
        );
        assert_eq!(completed.active_lease_count, ResourceUse::ZERO.items());
        assert_eq!(completed.oldest_active_lifetime, None);
        assert_eq!(
            completed.completed_lease_count,
            fixture_count(&[first_fixture.as_slice(), second_fixture.as_slice()])
        );
        assert_eq!(
            completed.completed_total_use,
            first_use.checked_add(second_use).expect("fixture sum fits")
        );
        assert_eq!(
            completed.completed_total_lifetime,
            first_lifetime + second_lifetime
        );
        assert!(!completed.measurement_inexact);
    }

    #[test]
    fn v4_arc02_adjustable_observation_preserves_peak_and_final_quantity() {
        let accountant = ResourceAccountant::observation_only();
        let base = Instant::now();
        let initial_fixture = b"queue-entry";
        let expanded_fixture = b"queue-entry-after-growth";
        let initial = ResourceUse::observed(
            fixture_count(&[initial_fixture.as_slice()]),
            fixture_len(initial_fixture),
            ResourceUse::ZERO.tasks(),
        );
        let expanded = ResourceUse::observed(
            fixture_count(&[initial_fixture.as_slice(), expanded_fixture.as_slice()]),
            fixture_len(expanded_fixture),
            fixture_count(&[b"queue-task".as_slice()]),
        );
        let mut lease = accountant.observe_at(
            FamilyKey::PostAuth(PostAuthResourceFamily::ApplicationQueue),
            initial,
            base,
        );

        lease.replace_observed(expanded);
        lease.replace_observed(initial);
        let active = family_report(
            &accountant.report_at(base).post_authentication,
            PostAuthResourceFamily::ApplicationQueue,
        );
        assert_eq!(active.active, initial);
        assert_eq!(active.peak_active, expanded);

        lease.finish_at(base + Duration::from_millis(fixture_len(expanded_fixture)));
        let completed = family_report(
            &accountant.report_at(base).post_authentication,
            PostAuthResourceFamily::ApplicationQueue,
        );
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.peak_active, expanded);
        assert_eq!(completed.completed_total_use, initial);
    }

    #[test]
    fn v4_arc02_pre_authentication_observations_do_not_enter_post_authentication_reports() {
        let accountant = ResourceAccountant::observation_only();
        let base = Instant::now();
        let fixture = b"authenticated-session-fixture";
        let use_ = ResourceUse::observed(
            fixture_count(&[fixture.as_slice()]),
            fixture_len(fixture),
            fixture_count(&[b"session-task".as_slice()]),
        );
        let lease = accountant.observe_at(
            FamilyKey::PreAuth(PreAuthResourceFamily::HalfOpenHandshake),
            use_,
            base,
        );

        let report = accountant.report_at(base + Duration::from_millis(fixture_len(fixture)));
        let post_auth = family_report(
            &report.post_authentication,
            PostAuthResourceFamily::AuthenticatedSession,
        );
        assert_eq!(post_auth.active, ResourceUse::ZERO);
        assert_eq!(post_auth.active_lease_count, ResourceUse::ZERO.items());

        lease.finish_at(base + Duration::from_millis(fixture_len(b"handshake")));
    }

    #[test]
    fn v4_arc02_defensive_drop_cannot_underflow_corrupted_active_measurements() {
        let accountant = ResourceAccountant::observation_only();
        let base = Instant::now();
        let fixture = b"drop-underflow-fixture";
        let observed = ResourceUse::observed(
            fixture_count(&[fixture.as_slice()]),
            fixture_len(fixture),
            fixture_count(&[b"cleanup-task".as_slice()]),
        );
        let lease = accountant.observe_at(
            FamilyKey::PostAuth(PostAuthResourceFamily::SessionRecovery),
            observed,
            base,
        );

        {
            let mut state = accountant.inner.lock_state();
            let family = state
                .families
                .get_mut(&FamilyKey::PostAuth(
                    PostAuthResourceFamily::SessionRecovery,
                ))
                .expect("observation created family state");
            family.active = ResourceUse::ZERO;
            family.active_lease_count = ResourceUse::ZERO.items();
            family.active_starts.clear();
        }

        drop(lease);
        let report = family_report(
            &accountant.report_at(base).post_authentication,
            PostAuthResourceFamily::SessionRecovery,
        );
        assert_eq!(report.active, ResourceUse::ZERO);
        assert_eq!(report.active_lease_count, ResourceUse::ZERO.items());
        assert!(report.measurement_inexact);
        assert_eq!(
            report.completed_lease_count,
            fixture_count(&[fixture.as_slice()])
        );
    }

    #[test]
    fn v4_arc02_poisoned_state_is_reported_as_inexact() {
        let accountant = ResourceAccountant::observation_only();
        let inner = Arc::clone(&accountant.inner);
        let poisoned = std::thread::spawn(move || {
            let _state = inner.state.lock().expect("fixture lock begins healthy");
            panic!("poison the fixture mutex while it is held");
        })
        .join();
        assert!(poisoned.is_err());

        let report = accountant.report();
        assert!(report
            .pre_authentication
            .iter()
            .all(|family| family.measurement_inexact));
        assert!(report
            .post_authentication
            .iter()
            .all(|family| family.measurement_inexact));
    }

    #[test]
    fn v4_arc02_overflow_saturates_and_remains_inexact_after_cleanup() {
        let accountant = ResourceAccountant::observation_only();
        let base = Instant::now();
        let maximum = ResourceUse::observed(u64::MAX, u64::MAX, u64::MAX);
        let one = ResourceUse::observed(
            fixture_count(&[b"item".as_slice()]),
            fixture_count(&[b"byte".as_slice()]),
            fixture_count(&[b"task".as_slice()]),
        );
        let first = accountant.observe_at(
            FamilyKey::PreAuth(PreAuthResourceFamily::ParserBytes),
            maximum,
            base,
        );
        let second = accountant.observe_at(
            FamilyKey::PreAuth(PreAuthResourceFamily::ParserBytes),
            one,
            base,
        );

        let active = family_report(
            &accountant.report_at(base).pre_authentication,
            PreAuthResourceFamily::ParserBytes,
        );
        assert_eq!(active.active, maximum);
        assert_eq!(active.peak_active, maximum);
        assert!(active.measurement_inexact);

        second.finish_at(base);
        first.finish_at(base);
        let completed = family_report(
            &accountant.report_at(base).pre_authentication,
            PreAuthResourceFamily::ParserBytes,
        );
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.completed_total_use, maximum);
        assert_eq!(
            completed.completed_lease_count,
            fixture_count(&[b"first".as_slice(), b"second".as_slice()])
        );
        assert!(completed.measurement_inexact);
    }
}
