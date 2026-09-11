//! Resource ownership and observation for the V4 transition.
//!
//! The provider submodule grants finite resource leases. The existing
//! accountant below remains observation-only and cannot authorize work.
//! Keeping those roles distinct prevents measurements from becoming permits.
//!
//! The queue and map submodules are containers built on those leases rather
//! than a second kind of permit: they store what an owner already paid for, one
//! funded allocation per entry, and they grant nothing of their own. Both exist
//! because the standard collections cannot state an entry's cost — a ring's
//! spare capacity belongs to no entry, and a B-tree's node belongs to several —
//! so an owner using one can charge per entry or release per entry, but not
//! both truthfully.

mod mailbox;
mod map;
pub mod provider;
pub(crate) mod queue;

pub(crate) use mailbox::strings_measure;
/// The borrowed-measurement kit: measure a source, combine the parts, claim,
/// acquire, and only then build the owned value. Public because an owner
/// outside this crate has the same obligation to fund a snapshot before it
/// allocates one, and reimplementing these would be a second source of truth
/// for the same arithmetic.
pub use mailbox::{
    checked_measure_add, mailbox_measure_serialized, measure_serialized_mailbox_item,
    measure_serialized_mailbox_item_after_funded,
};
pub use mailbox::{
    prepare_resource_mailbox, resource_mailbox, MailboxMeasurement, PreparedResourceMailbox,
    ResourceMailboxAdmissionError, ResourceMailboxCreateError, ResourceMailboxDelivery,
    ResourceMailboxItem, ResourceMailboxItemBuilder, ResourceMailboxItemError,
    ResourceMailboxPlanningError, ResourceMailboxReceiver, ResourceMailboxSendError,
    ResourceMailboxSender,
};
pub use map::{LeasedMap, LeasedMapInsertRefusal};
pub(crate) use queue::LeasedQueue;

pub use provider::{
    FiniteResourceProvider, FundedArc, FundedWeak, ResourceAuthorityClass, ResourceClaim,
    ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourcePressure, ResourceProvider,
    ResourceProviderAuthority, ResourceProviderConflict, ResourceProviderPort,
    ResourceReservationState, ResourceScope, ResourceScopeId, ResourceUnavailable,
    RESOURCE_CLASS_COUNT,
};

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
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
#[repr(usize)]
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

    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

/// Resource families that may be consumed after endpoint authentication.
///
/// This is a closed set derived from section 14.2 of
/// `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`. Pre-authentication
/// observations cannot be converted into one of these families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
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

    const fn index(self) -> usize {
        self as usize
    }
}

/// An observed quantity of resources.
///
/// Values are measurements only. Constructing this value does not reserve the
/// represented resources and does not authorize their use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceUse {
    items: u64,
    logical_bytes: u64,
    retained_bytes: u64,
    tasks: u64,
}

impl ResourceUse {
    pub const ZERO: Self = Self::observed(0, 0, 0, 0);

    /// Describe an observed quantity without reserving or permitting it.
    pub const fn observed(items: u64, logical_bytes: u64, retained_bytes: u64, tasks: u64) -> Self {
        Self {
            items,
            logical_bytes,
            retained_bytes,
            tasks,
        }
    }

    pub const fn items(self) -> u64 {
        self.items
    }

    /// Bytes that belong to the observed value's logical content.
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }

    /// Bytes retained by the observed owner under that producer's documented
    /// measurement contract, including unused capacity when it is reported.
    pub const fn retained_bytes(self) -> u64 {
        self.retained_bytes
    }

    pub const fn tasks(self) -> u64 {
        self.tasks
    }

    pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            items: self.items.checked_add(other.items)?,
            logical_bytes: self.logical_bytes.checked_add(other.logical_bytes)?,
            retained_bytes: self.retained_bytes.checked_add(other.retained_bytes)?,
            tasks: self.tasks.checked_add(other.tasks)?,
        })
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            items: self.items.saturating_add(other.items),
            logical_bytes: self.logical_bytes.saturating_add(other.logical_bytes),
            retained_bytes: self.retained_bytes.saturating_add(other.retained_bytes),
            tasks: self.tasks.saturating_add(other.tasks),
        }
    }

    pub(crate) fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            items: self.items.checked_sub(other.items)?,
            logical_bytes: self.logical_bytes.checked_sub(other.logical_bytes)?,
            retained_bytes: self.retained_bytes.checked_sub(other.retained_bytes)?,
            tasks: self.tasks.checked_sub(other.tasks)?,
        })
    }

    fn saturating_sub(self, other: Self) -> Self {
        Self {
            items: self.items.saturating_sub(other.items),
            logical_bytes: self.logical_bytes.saturating_sub(other.logical_bytes),
            retained_bytes: self.retained_bytes.saturating_sub(other.retained_bytes),
            tasks: self.tasks.saturating_sub(other.tasks),
        }
    }

    fn componentwise_max(self, other: Self) -> Self {
        Self {
            items: self.items.max(other.items),
            logical_bytes: self.logical_bytes.max(other.logical_bytes),
            retained_bytes: self.retained_bytes.max(other.retained_bytes),
            tasks: self.tasks.max(other.tasks),
        }
    }
}

/// One caller-supplied measurement and whether all of its components were
/// representable exactly.
///
/// Observation producers use this when a platform-sized allocation must be
/// converted into the fixed-width report. An unrepresentable or overflowing
/// component is saturated and remains visibly inexact in every affected
/// scope. This type still grants no authority and reserves no capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResourceMeasurement {
    observed: ResourceUse,
    inexact: bool,
}

impl ResourceMeasurement {
    pub(crate) const fn exact(observed: ResourceUse) -> Self {
        Self {
            observed,
            inexact: false,
        }
    }

    pub(crate) const fn inexact(observed: ResourceUse) -> Self {
        Self {
            observed,
            inexact: true,
        }
    }

    #[cfg(test)]
    pub(crate) const fn observed(self) -> ResourceUse {
        self.observed
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
    /// True when active leases remain but constant-space tracking cannot
    /// identify which remaining lease is oldest.
    pub oldest_active_lifetime_inexact: bool,
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

/// The one resource root shared by all MyOwnMesh runtime objects in this
/// process. Its accountant remains observation-only. Its separate connector
/// owner slot binds one owner-selected resource-provider identity.
static PROCESS_RESOURCE_ROOT: OnceLock<ProcessResourceRoot> = OnceLock::new();

/// Return a process-wide observation snapshot.
pub fn process_resource_report() -> ResourceReport {
    ProcessResourceRoot::global().report()
}

/// The root of the production resource hierarchy.
///
/// Child scopes are created in one fixed ownership order: process, Mesh
/// runtime, joined network instance, then attempt or peer connection. These
/// are runtime aggregation scopes, not claims of immutable mesh identity.
/// Carrier, ingress source, attempt, and known-origin attribution remain
/// independent dimensions. An observation made at a leaf is recorded at that
/// leaf and every ancestor.
#[derive(Clone)]
pub struct ProcessResourceRoot {
    accountant: ResourceAccountant,
    provider: Arc<OnceLock<ResourceProviderPort>>,
    connector_owner: Arc<OnceLock<crate::runtime::attempt::ConnectorResourceOwnerPort>>,
}

impl std::fmt::Debug for ProcessResourceRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessResourceRoot")
            .field("accountant", &self.accountant)
            .field(
                "resource_provider_installed",
                &self.provider.get().is_some(),
            )
            .finish()
    }
}

impl ProcessResourceRoot {
    /// Get the observation root for this process.
    pub fn global() -> Self {
        PROCESS_RESOURCE_ROOT
            .get_or_init(|| Self {
                accountant: ResourceAccountant::observation_only(),
                provider: Arc::new(OnceLock::new()),
                connector_owner: Arc::new(OnceLock::new()),
            })
            .clone()
    }

    /// Install or reuse the one resource provider for this process root.
    ///
    /// The first owner-selected provider identity wins. A later Mesh runtime
    /// can share it only by cloning the exact same port. Replacing it while
    /// leases may exist would split the process grant.
    pub fn install_resource_provider(
        &self,
        provider: ResourceProviderPort,
    ) -> std::result::Result<
        crate::runtime::attempt::ConnectorResourceOwnerPort,
        ResourceProviderConflict,
    > {
        let installed_provider = self.install_local_application_provider(provider)?;
        let installed = self.connector_owner.get_or_init(|| {
            crate::runtime::attempt::ConnectorResourceOwnerPort::new(installed_provider.clone())
        });
        if installed.same_provider(&installed_provider) {
            Ok(installed.clone())
        } else {
            Err(ResourceProviderConflict)
        }
    }

    /// Install or reuse the one owner-selected provider without installing
    /// connector authority. Infrastructure-only runtimes use this boundary.
    pub fn install_local_application_provider(
        &self,
        provider: ResourceProviderPort,
    ) -> Result<ResourceProviderPort, ResourceProviderConflict> {
        let installed = self.provider.get_or_init(|| provider.clone());
        if installed.same_provider(&provider) {
            Ok(installed.clone())
        } else {
            Err(ResourceProviderConflict)
        }
    }

    /// Issue one local-application scope from the exact process provider.
    /// This does not install connector authority and is available to an
    /// infrastructure-only runtime whose owner supplied the provider directly.
    pub fn issue_local_application_scope(
        &self,
    ) -> Result<LocalApplicationResourceScope, LocalApplicationResourceScopeIssueError> {
        let provider = self
            .provider
            .get()
            .ok_or(LocalApplicationResourceScopeIssueError::ResourceProviderMissing)?
            .clone();
        let scope = provider
            .create_scope(&provider.process_scope())
            .map_err(LocalApplicationResourceScopeIssueError::ResourcesUnavailable)?;
        Ok(LocalApplicationResourceScope { provider, scope })
    }

    /// Return the installed process connector owner, if the process owner has
    /// selected a policy.
    pub fn connector_resource_owner(
        &self,
    ) -> Option<crate::runtime::attempt::ConnectorResourceOwnerPort> {
        self.connector_owner.get().cloned()
    }

    /// Issue one unforgeable connector admission scope for an exact live
    /// [`crate::Mesh`] runtime.
    ///
    /// The process provider must already be installed. Scope creation grants
    /// no capacity and all Mesh scopes draw from the same process grant.
    pub fn issue_mesh_connector_scope(
        &self,
    ) -> Result<
        crate::runtime::attempt::MeshConnectorResourceScope,
        crate::runtime::attempt::MeshConnectorResourceScopeIssueError,
    > {
        let owner = self.connector_owner.get().ok_or(
            crate::runtime::attempt::MeshConnectorResourceScopeIssueError::ResourceProviderMissing,
        )?;
        owner.issue_mesh_scope()
    }

    /// Read the process aggregate without changing it.
    pub fn report(&self) -> ResourceReport {
        self.accountant.report()
    }

    pub(crate) fn mesh_runtime_scope(&self) -> MeshRuntimeResourceScope {
        MeshRuntimeResourceScope {
            accountant: self.accountant.child_scope(),
        }
    }

    #[cfg(test)]
    pub(crate) fn isolated() -> Self {
        Self {
            accountant: ResourceAccountant::observation_only(),
            provider: Arc::new(OnceLock::new()),
            connector_owner: Arc::new(OnceLock::new()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LocalApplicationResourceScopeIssueError {
    #[error("the process resource provider is not installed")]
    ResourceProviderMissing,
    #[error("the process resource provider refused the local application scope: {0:?}")]
    ResourcesUnavailable(ResourceUnavailable),
}

/// Acquisition port for daemon and local-application state that is not owned
/// by any connector or remote session.
#[derive(Clone)]
pub struct LocalApplicationResourceScope {
    provider: ResourceProviderPort,
    scope: ResourceScope,
}

impl LocalApplicationResourceScope {
    pub fn child(&self) -> Result<Self, ResourceUnavailable> {
        let scope = self.provider.create_scope(&self.scope)?;
        Ok(Self {
            provider: self.provider.clone(),
            scope,
        })
    }

    /// One application scope under an explicitly supplied port, for another
    /// crate's controls.
    ///
    /// **A private owner, not a wider door.** A daemon control that wants to
    /// watch a charge appear and go away needs a provider whose whole grant it
    /// chose, and it cannot get one through the ordinary issuer: that reads the
    /// installed process provider, so a control sized against it would either be
    /// measuring a pool other tests share or be quietly starving
    /// `ProcessResourceRoot`. Handing the port in makes the owner exactly as
    /// private as the control's own `FiniteResourceProvider`.
    ///
    /// This is deliberately a *factory over the same two calls the production
    /// issuer makes* — `create_scope` under the port's process scope — and not
    /// raw construction from a port and a scope. Raw construction would let a
    /// caller pair a port with a scope it does not own, which is a shape no
    /// production path can produce, and controls built on it would be proving
    /// something about an arrangement that cannot occur.
    ///
    /// Feature-gated and hidden because it exists for cross-crate controls. It
    /// widens no authority: everything reachable through the returned scope is
    /// bounded by the grant the caller already had.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn transport_lab_child_of(
        provider: &ResourceProviderPort,
    ) -> Result<Self, ResourceUnavailable> {
        let scope = provider.create_scope(&provider.process_scope())?;
        Ok(Self {
            provider: provider.clone(),
            scope,
        })
    }

    pub fn acquire(&self, claim: ResourceClaim) -> Result<ResourceLease, ResourceUnavailable> {
        self.provider
            .acquire(&self.scope, ResourceAuthorityClass::Admitted, claim)
    }
}

/// Observation scope for one live [`crate::Mesh`] runtime.
#[derive(Clone, Debug)]
pub(crate) struct MeshRuntimeResourceScope {
    accountant: ResourceAccountant,
}

impl MeshRuntimeResourceScope {
    pub(crate) fn network_instance_scope(&self) -> NetworkInstanceResourceScope {
        NetworkInstanceResourceScope {
            accountant: self.accountant.child_scope(),
        }
    }

    pub(crate) fn report(&self) -> ResourceReport {
        self.accountant.report()
    }
}

/// Observation scope for one live joined network instance.
///
/// This scope does not claim an immutable context identity. Future carrier,
/// anonymous-ingress, attempt, and known-origin attribution must remain
/// orthogonal rather than being inferred from this runtime owner.
#[derive(Clone, Debug)]
pub(crate) struct NetworkInstanceResourceScope {
    accountant: ResourceAccountant,
}

impl NetworkInstanceResourceScope {
    pub(crate) fn peer_connection_scope(&self) -> PeerConnectionResourceScope {
        PeerConnectionResourceScope {
            accountant: self.accountant.child_scope(),
        }
    }

    pub(crate) fn report(&self) -> ResourceReport {
        self.accountant.report()
    }
}

/// Observation scope for one attempt or live peer-connection owner.
#[derive(Clone, Debug)]
pub(crate) struct PeerConnectionResourceScope {
    accountant: ResourceAccountant,
}

impl PeerConnectionResourceScope {
    #[cfg(test)]
    pub(crate) fn observe_pre_authentication(
        &self,
        family: PreAuthResourceFamily,
        observed: ResourceUse,
    ) -> ObservationLease {
        self.accountant.observe_pre_authentication(family, observed)
    }

    pub(crate) fn observe_pre_authentication_measurement(
        &self,
        family: PreAuthResourceFamily,
        measurement: ResourceMeasurement,
    ) -> ObservationLease {
        self.accountant.observe_measurement_at(
            FamilyKey::PreAuth(family),
            measurement,
            Instant::now(),
        )
    }

    #[cfg(test)]
    pub(crate) fn report(&self) -> ResourceReport {
        self.accountant.report()
    }
}

/// One node in an observation hierarchy.
///
/// `observation_only` creates an isolated root for tests and non-production
/// consumers of the primitive. Production code enters through
/// [`ProcessResourceRoot`] and its typed descendants.
#[derive(Clone, Debug)]
pub struct ResourceAccountant {
    ancestors: Arc<[Arc<Inner>]>,
    leaf: Arc<Inner>,
}

impl ResourceAccountant {
    /// Create an isolated observation root.
    ///
    /// This does not establish limits, reserve capacity, or grant authority.
    pub fn observation_only() -> Self {
        Self {
            ancestors: Arc::from([]),
            leaf: Arc::new(Inner::default()),
        }
    }

    fn child_scope(&self) -> Self {
        let mut ancestors = self.ancestors.to_vec();
        ancestors.push(Arc::clone(&self.leaf));
        Self {
            ancestors: Arc::from(ancestors),
            leaf: Arc::new(Inner::default()),
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

    /// Read all family measurements at this scope without changing them.
    pub fn report(&self) -> ResourceReport {
        self.leaf.lock_state().report(Instant::now())
    }

    fn observe_at(
        &self,
        family: FamilyKey,
        observed: ResourceUse,
        started_at: Instant,
    ) -> ObservationLease {
        self.observe_measurement_at(family, ResourceMeasurement::exact(observed), started_at)
    }

    fn observe_measurement_at(
        &self,
        family: FamilyKey,
        measurement: ResourceMeasurement,
        started_at: Instant,
    ) -> ObservationLease {
        self.for_each_scope(|scope| {
            let mut state = scope.lock_state();
            if measurement.inexact {
                state.measurement_inexact = true;
            }
            state
                .family_mut(family)
                .begin(measurement.observed, started_at);
        });

        ObservationLease {
            observation: Some(Observation {
                accountant: self.clone(),
                family,
                observed: measurement.observed,
                started_at,
            }),
        }
    }

    fn replace_measurement(
        &self,
        family: FamilyKey,
        previous: ResourceUse,
        measurement: ResourceMeasurement,
    ) {
        self.for_each_scope(|scope| {
            let mut state = scope.lock_state();
            if measurement.inexact {
                state.measurement_inexact = true;
            }
            state
                .family_mut(family)
                .replace(previous, measurement.observed);
        });
    }

    fn finish_observation(
        &self,
        family: FamilyKey,
        observed: ResourceUse,
        started_at: Instant,
        lifetime: Duration,
    ) {
        self.for_each_scope(|scope| {
            scope
                .lock_state()
                .family_mut(family)
                .finish(observed, started_at, lifetime);
        });
    }

    fn for_each_scope(&self, mut update: impl FnMut(&Inner)) {
        for scope in self.ancestors.iter() {
            update(scope);
        }
        update(&self.leaf);
    }

    #[cfg(test)]
    fn report_at(&self, now: Instant) -> ResourceReport {
        self.leaf.lock_state().report(now)
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
        self.replace_measurement(ResourceMeasurement::exact(observed));
    }

    pub(crate) fn replace_measurement(&mut self, measurement: ResourceMeasurement) {
        let Some(observation) = self.observation.as_mut() else {
            return;
        };
        observation.accountant.replace_measurement(
            observation.family,
            observation.observed,
            measurement,
        );
        observation.observed = measurement.observed;
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
        observation.accountant.finish_observation(
            observation.family,
            observation.observed,
            observation.started_at,
            lifetime,
        );
    }
}

impl Drop for ObservationLease {
    fn drop(&mut self) {
        self.complete(Instant::now());
    }
}

#[derive(Debug)]
struct Observation {
    accountant: ResourceAccountant,
    family: FamilyKey,
    observed: ResourceUse,
    started_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Debug)]
struct State {
    pre_authentication: [FamilyState; PRE_AUTH_RESOURCE_FAMILY_COUNT],
    post_authentication: [FamilyState; POST_AUTH_RESOURCE_FAMILY_COUNT],
    measurement_inexact: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            pre_authentication: std::array::from_fn(|_| FamilyState::default()),
            post_authentication: std::array::from_fn(|_| FamilyState::default()),
            measurement_inexact: false,
        }
    }
}

impl State {
    fn report(&self, now: Instant) -> ResourceReport {
        ResourceReport {
            pre_authentication: PreAuthResourceFamily::ALL
                .map(|family| self.snapshot(self.family(FamilyKey::PreAuth(family)), family, now)),
            post_authentication: PostAuthResourceFamily::ALL
                .map(|family| self.snapshot(self.family(FamilyKey::PostAuth(family)), family, now)),
        }
    }

    fn snapshot<F: Copy>(
        &self,
        state: &FamilyState,
        family: F,
        now: Instant,
    ) -> ResourceFamilyReport<F> {
        ResourceFamilyReport {
            family,
            active: state.active,
            peak_active: state.peak_active,
            active_lease_count: state.active_lease_count,
            peak_active_lease_count: state.peak_active_lease_count,
            oldest_active_lifetime: state
                .oldest_active_started_at
                .map(|started_at| now.saturating_duration_since(started_at)),
            oldest_active_lifetime_inexact: state.oldest_active_lifetime_inexact,
            completed_lease_count: state.completed_lease_count,
            completed_total_use: state.completed_total_use,
            completed_total_lifetime: state.completed_total_lifetime,
            measurement_inexact: self.measurement_inexact || state.measurement_inexact,
        }
    }

    fn family(&self, key: FamilyKey) -> &FamilyState {
        match key {
            FamilyKey::PreAuth(family) => &self.pre_authentication[family.index()],
            FamilyKey::PostAuth(family) => &self.post_authentication[family.index()],
        }
    }

    fn family_mut(&mut self, key: FamilyKey) -> &mut FamilyState {
        match key {
            FamilyKey::PreAuth(family) => &mut self.pre_authentication[family.index()],
            FamilyKey::PostAuth(family) => &mut self.post_authentication[family.index()],
        }
    }
}

#[derive(Debug, Default)]
struct FamilyState {
    active: ResourceUse,
    peak_active: ResourceUse,
    active_lease_count: u64,
    peak_active_lease_count: u64,
    oldest_active_started_at: Option<Instant>,
    oldest_active_start_count: u64,
    oldest_active_lifetime_inexact: bool,
    completed_lease_count: u64,
    completed_total_use: ResourceUse,
    completed_total_lifetime: Duration,
    measurement_inexact: bool,
}

impl FamilyState {
    fn begin(&mut self, observed: ResourceUse, started_at: Instant) {
        let was_empty = self.active_lease_count == 0;
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

        if was_empty {
            self.oldest_active_started_at = Some(started_at);
            self.oldest_active_start_count = 1;
            self.oldest_active_lifetime_inexact = false;
        } else if let Some(oldest) = self.oldest_active_started_at {
            match started_at.cmp(&oldest) {
                std::cmp::Ordering::Less => {
                    self.oldest_active_started_at = Some(started_at);
                    self.oldest_active_start_count = 1;
                }
                std::cmp::Ordering::Equal => {
                    self.oldest_active_start_count =
                        match self.oldest_active_start_count.checked_add(1) {
                            Some(next) => next,
                            None => {
                                self.measurement_inexact = true;
                                u64::MAX
                            }
                        };
                }
                std::cmp::Ordering::Greater => {}
            }
        }
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

        if self.oldest_active_started_at == Some(started_at) {
            self.oldest_active_start_count = match self.oldest_active_start_count.checked_sub(1) {
                Some(next) => next,
                None => {
                    self.measurement_inexact = true;
                    0
                }
            };
            if self.oldest_active_start_count == 0 {
                self.oldest_active_started_at = None;
                if self.active_lease_count != 0 {
                    // The next-oldest start cannot be recovered without
                    // retaining one timestamp per active lease. Keep metadata
                    // constant-space and stop claiming exact recency instead.
                    self.oldest_active_lifetime_inexact = true;
                }
            }
        } else if self.oldest_active_started_at.is_none() && self.active_lease_count == 0 {
            self.oldest_active_start_count = 0;
            self.oldest_active_lifetime_inexact = false;
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
            fixture_len(second_fixture),
            fixture_count(&[b"candidate-task".as_slice()]),
        );
        let second_use = ResourceUse::observed(
            fixture_count(&[second_fixture.as_slice()]),
            fixture_len(second_fixture),
            fixture_len(first_fixture),
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
            fixture_len(initial_fixture),
            ResourceUse::ZERO.tasks(),
        );
        let expanded = ResourceUse::observed(
            fixture_count(&[initial_fixture.as_slice(), expanded_fixture.as_slice()]),
            fixture_len(expanded_fixture),
            fixture_len(initial_fixture) + fixture_len(expanded_fixture),
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
            fixture_len(fixture),
            fixture_count(&[b"cleanup-task".as_slice()]),
        );
        let lease = accountant.observe_at(
            FamilyKey::PostAuth(PostAuthResourceFamily::SessionRecovery),
            observed,
            base,
        );

        {
            let mut state = accountant.leaf.lock_state();
            let family =
                state.family_mut(FamilyKey::PostAuth(PostAuthResourceFamily::SessionRecovery));
            family.active = ResourceUse::ZERO;
            family.active_lease_count = ResourceUse::ZERO.items();
            family.oldest_active_started_at = None;
            family.oldest_active_start_count = 0;
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
        let inner = Arc::clone(&accountant.leaf);
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
        let maximum = ResourceUse::observed(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        let one = ResourceUse::observed(
            fixture_count(&[b"item".as_slice()]),
            fixture_count(&[b"byte".as_slice()]),
            fixture_count(&[b"retained".as_slice()]),
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

    #[test]
    fn v4_arc02_bounded_oldest_tracking_stops_claiming_exactness() {
        let accountant = ResourceAccountant::observation_only();
        let base = Instant::now();
        let later = base + Duration::from_millis(1);
        let observed = ResourceUse::observed(1, 0, 0, 0);
        let first = accountant.observe_at(
            FamilyKey::PreAuth(PreAuthResourceFamily::CandidateObject),
            observed,
            base,
        );
        let second = accountant.observe_at(
            FamilyKey::PreAuth(PreAuthResourceFamily::CandidateObject),
            observed,
            later,
        );

        first.finish_at(later);
        let report = family_report(
            &accountant.report_at(later).pre_authentication,
            PreAuthResourceFamily::CandidateObject,
        );
        assert_eq!(report.active_lease_count, 1);
        assert_eq!(report.oldest_active_lifetime, None);
        assert!(report.oldest_active_lifetime_inexact);
        assert!(!report.measurement_inexact);

        second.finish_at(later);
    }

    #[test]
    fn v4_arc02_unsupported_measurement_saturates_and_marks_report_inexact() {
        let accountant = ResourceAccountant::observation_only();
        let base = Instant::now();
        let measurement =
            ResourceMeasurement::inexact(ResourceUse::observed(1, u64::MAX, u64::MAX, 0));
        let lease = accountant.observe_measurement_at(
            FamilyKey::PreAuth(PreAuthResourceFamily::CandidateObject),
            measurement,
            base,
        );

        let report = family_report(
            &accountant.report_at(base).pre_authentication,
            PreAuthResourceFamily::CandidateObject,
        );
        assert_eq!(report.active.logical_bytes(), u64::MAX);
        assert_eq!(report.active.retained_bytes(), u64::MAX);
        assert!(report.measurement_inexact);
        drop(lease);
    }

    #[test]
    #[ignore = "manual timing run; set MYOWNMESH_ARC02_BENCH_ITERATIONS"]
    fn v4_arc02_observer_overhead_measurement() {
        let iterations = std::env::var("MYOWNMESH_ARC02_BENCH_ITERATIONS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .expect("set MYOWNMESH_ARC02_BENCH_ITERATIONS to a nonzero measurement workload");
        let process = ProcessResourceRoot::isolated();
        let runtime = process.mesh_runtime_scope();
        let instance = runtime.network_instance_scope();
        let peer = instance.peer_connection_scope();
        let observed = ResourceUse::observed(1, 64, 96, 0);

        let started = Instant::now();
        for _ in 0..iterations {
            drop(peer.observe_pre_authentication(PreAuthResourceFamily::CandidateObject, observed));
        }
        let elapsed = started.elapsed();
        let average_nanos = elapsed.as_nanos() / u128::from(iterations);
        println!(
            "arc02_observer iterations={iterations} elapsed_ns={} average_begin_drop_ns={average_nanos}",
            elapsed.as_nanos()
        );
        println!(
            "arc02_metadata_bytes family_state={} scope_state={} scope_inner={} accountant={} lease={}",
            std::mem::size_of::<FamilyState>(),
            std::mem::size_of::<State>(),
            std::mem::size_of::<Inner>(),
            std::mem::size_of::<ResourceAccountant>(),
            std::mem::size_of::<ObservationLease>()
        );
    }

    #[test]
    fn v4_arc02_logical_and_retained_bytes_are_independent_axes() {
        let logical_fixture = b"candidate-text";
        let retained_fixture = b"candidate-allocation-capacity";
        let observed = ResourceUse::observed(
            fixture_count(&[logical_fixture.as_slice()]),
            fixture_len(logical_fixture),
            fixture_len(retained_fixture),
            ResourceUse::ZERO.tasks(),
        );

        assert_eq!(observed.logical_bytes(), fixture_len(logical_fixture));
        assert_eq!(observed.retained_bytes(), fixture_len(retained_fixture));
        assert_ne!(observed.logical_bytes(), observed.retained_bytes());
    }

    #[test]
    fn v4_arc02_leaf_observation_updates_all_four_scopes() {
        let process = ProcessResourceRoot::isolated();
        let mesh = process.mesh_runtime_scope();
        let context = mesh.network_instance_scope();
        let peer = context.peer_connection_scope();
        let fixture = b"four-scope-candidate";
        let observed = ResourceUse::observed(
            fixture_count(&[fixture.as_slice()]),
            fixture_len(fixture),
            fixture_len(fixture) + fixture_len(b"retained-slack"),
            ResourceUse::ZERO.tasks(),
        );

        let lease =
            peer.observe_pre_authentication(PreAuthResourceFamily::CandidateObject, observed);

        for report in [
            process.report(),
            mesh.report(),
            context.report(),
            peer.report(),
        ] {
            let candidate = family_report(
                &report.pre_authentication,
                PreAuthResourceFamily::CandidateObject,
            );
            assert_eq!(candidate.active, observed);
            assert_eq!(candidate.active_lease_count, 1);
        }

        drop(lease);
        for report in [
            process.report(),
            mesh.report(),
            context.report(),
            peer.report(),
        ] {
            let candidate = family_report(
                &report.pre_authentication,
                PreAuthResourceFamily::CandidateObject,
            );
            assert_eq!(candidate.active, ResourceUse::ZERO);
            assert_eq!(candidate.completed_total_use, observed);
            assert_eq!(candidate.completed_lease_count, 1);
        }
    }

    #[test]
    fn v4_arc02_sibling_contexts_do_not_observe_each_other() {
        let process = ProcessResourceRoot::isolated();
        let mesh = process.mesh_runtime_scope();
        let first_context = mesh.network_instance_scope();
        let second_context = mesh.network_instance_scope();
        let first_peer = first_context.peer_connection_scope();
        let fixture = b"first-context-only";
        let observed = ResourceUse::observed(
            fixture_count(&[fixture.as_slice()]),
            fixture_len(fixture),
            fixture_len(fixture),
            ResourceUse::ZERO.tasks(),
        );

        let _lease =
            first_peer.observe_pre_authentication(PreAuthResourceFamily::CandidateObject, observed);

        let mesh_candidate = family_report(
            &mesh.report().pre_authentication,
            PreAuthResourceFamily::CandidateObject,
        );
        let first_candidate = family_report(
            &first_context.report().pre_authentication,
            PreAuthResourceFamily::CandidateObject,
        );
        let second_candidate = family_report(
            &second_context.report().pre_authentication,
            PreAuthResourceFamily::CandidateObject,
        );
        assert_eq!(mesh_candidate.active, observed);
        assert_eq!(first_candidate.active, observed);
        assert_eq!(second_candidate.active, ResourceUse::ZERO);
    }
}
