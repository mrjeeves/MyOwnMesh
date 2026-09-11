//! The MyOwnMesh **daemon**, as a library.
//!
//! The `myownmesh` binary (this package's bin target) is a thin CLI over the
//! modules here. They are exposed as a library for one reason: so a host
//! application that is **forbidden from spawning processes**, such as an iOS
//! app where the sandbox allows neither fork nor exec, can run the same daemon
//! inside its own process via [`embedded::start_connector_capable`], instead of
//! re-implementing the daemon's behaviour piece by piece.
//!
//! Everything else about the daemon is unchanged: it still listens on the
//! control socket (a unix socket inside the app sandbox on iOS; sockets are
//! allowed; processes aren't), speaks the same wire protocol, and hosts the
//! same registry/services, so existing clients (`myownmesh ctl`, the GUIs, and
//! any embedding application's own sidecar) work against it identically whether
//! it runs as a process or embedded.

pub mod control;
pub mod embedded;
pub mod ipc;
pub mod registry;
pub mod services;
pub mod supervisor;

/// One real two-peer link, shared by the families whose controls need one.
///
/// Test-only and crate-private: it compiles into no production build and is
/// nameable from no production path. It sits beside the fixtures below for the
/// same reason they do — more than one family needs it, so no single family can
/// own it without the others copying it.
#[cfg(test)]
pub(crate) mod test_link;

#[cfg(test)]
pub(crate) const TEST_PROCESS_CONNECTOR_CAPACITY: usize = 4;
/// The largest single payload this binary's fixtures fund, per callback class.
///
/// Two numbers rather than one, and named rather than inlined, because a single
/// byte figure multiplied across the combined callback count is a grant in which
/// neither class's budget means what it says: the larger class silently pays for
/// the smaller, and removing the larger leaves the smaller funded for nothing.
/// Control covers one gathered ICE candidate's JSON; endpoint data keeps the
/// figure these fixtures have always run with, now stated as what it is.
///
/// They live at the provider rather than on a policy because the connector
/// policies in `ipc::bridge`, `registry` and `embedded` all draw on this one
/// grant, so there is no single policy that could state them for the rest.
#[cfg(test)]
const TEST_CONTROL_CALLBACK_BYTES: u64 = 4 * 1024;
#[cfg(test)]
const TEST_ENDPOINT_CALLBACK_BYTES: u64 = 16 * 1024 * 1024;

/// The largest JSON frame this binary's fixtures fund the *parse* of.
///
/// Its own number, deliberately not borrowed from either callback ceiling
/// above. Those bound what a connector may hold queued; this bounds what the
/// application gateway may allocate while turning one frame into a
/// `serde_json::Value` tree, which is a different quantity with a different
/// denomination — the tree's claim is per input byte because a JSON value can
/// hold as many independent allocations as it has bytes. Sizing one from the
/// other is what left this provider granting a residual counted in records
/// against a claim counted in bytes, so the first inbound `Hello` was refused
/// with every latch false and nothing logged above `trace!`.
///
/// Test workload capacity only. It gates nothing on the wire: a frame is
/// admitted against its own actual length, and a fixture that funds too little
/// sees a refusal, never a truncation.
#[cfg(test)]
const TEST_JSON_FRAME_BYTES: usize = 8 * 1024;

/// Simultaneous JSON input claims one connector can hold.
///
/// Exactly two, and both are real rather than headroom: the peer's `Hello`
/// retains its claim for the connection's whole life (the engine parks it in
/// `hello_retention`), and one further protocol or application frame is being
/// parsed at any moment. One would fund the retained `Hello` and refuse every
/// frame after it; more would be capacity nothing here can name a holder for.
#[cfg(test)]
const TEST_JSON_CLAIMS_PER_CONNECTOR: u64 = 2;

/// Event-subscribed IPC clients whose outbound mailboxes this binary's
/// fixtures fund at once.
///
/// Peak *concurrent* across the whole test binary, not per test: the provider
/// is a `OnceLock`, so its grant belongs to the binary, and the default harness
/// runs tests on as many threads as the machine has cores. Several client
/// fixtures per test, times those threads, is the figure this has to cover — a
/// per-test number would be right for one test and wrong for the suite.
#[cfg(test)]
const TEST_IPC_CLIENT_MAILBOXES: u64 = 64;

/// IPC task owners this daemon-wide fixture may hold concurrently.
///
/// This is a separately named cohort from connector workers. Its reservation
/// is priced by the IPC task owner, so adding task headroom cannot silently
/// enlarge the connector capacity.
#[cfg(test)]
const TEST_IPC_TASKS: u64 = 16;

/// Outbound frames one fixture client may hold queued at once.
///
/// The mailbox is count-unbounded by design — nothing in the daemon names a
/// frame count — so this is a *funding* decision here and not a ceiling
/// anywhere. A fixture that queues more than this sees a truthful `Pressure`
/// refusal, which is the correct failure for a test binary that under-funded
/// itself, and not a dropped or truncated frame.
#[cfg(test)]
const TEST_IPC_FRAMES_IN_FLIGHT: u64 = 8;

/// The largest outbound IPC frame this binary's fixtures fund the retention of.
///
/// Its own number rather than a share of [`TEST_JSON_FRAME_BYTES`]: that one
/// bounds what the gateway allocates decoding an *inbound* frame, and this
/// bounds what the daemon retains holding an *outbound* one until its client
/// reads it. Same units, different holder, different lifetime.
#[cfg(test)]
const TEST_IPC_FRAME_BYTES: usize = 4 * 1024;

/// Entries this binary's fixtures hold in each of the IPC registry's tables at
/// once.
///
/// Every registry index node is separately funded now — a client record, a
/// method claim, a channel subscriber, a pending inbound call, an open flow —
/// so a fixture that registers clients and claims methods is making real
/// admissions and can be refused. Peak *concurrent* across the whole binary, on
/// the same reasoning as [`TEST_IPC_CLIENT_MAILBOXES`]: the provider is a
/// `OnceLock`, so its grant belongs to the binary rather than to a test.
#[cfg(test)]
const TEST_IPC_REGISTRY_ENTRIES: u64 = 512;

/// How long a client-chosen coordinate a fixture entry may carry, in bytes.
///
/// Entries cost node *plus* the heap their keys own, so the grant has to name a
/// name length or every control would be refused the moment its fixture used a
/// string. Generous on purpose: a control that means to prove pressure builds
/// its own tight provider and says so, while a control that merely needs a
/// registry should never be refused for calling a channel `"telemetry"` rather
/// than `"t"`.
#[cfg(test)]
const TEST_IPC_REGISTRY_COORDINATE_BYTES: usize = 256;

/// Inbound control frames this binary's fixtures buffer at once.
///
/// The control reader funds every byte it buffers, which is what lets the
/// `MYOWNMESH_IPC_*` byte ceilings be optional: absence means the grant decides
/// at measured size rather than that nothing decides. Priced at
/// [`TEST_JSON_FRAME_BYTES`] a frame — the same bound the gateway's own input
/// work is priced at, because it is the same frame.
#[cfg(test)]
const TEST_CONTROL_INBOUND_FRAMES: u64 = 16;

/// Maximum simultaneously live semantic network owners in one daemon-library
/// test. The transport pair fixture and the two-network control/registry
/// fixtures are the largest in this binary; single-network fixtures do not
/// increase this bound.
#[cfg(test)]
const TEST_SEMANTIC_NETWORKS_PER_WORKER: u64 = 2;

/// One explicitly finite provider shared by daemon-library tests.
///
/// These are fixture resources, not production defaults. The callback and
/// payload quantities are derived from the existing test policies below. The
/// opaque residual covers this test binary's process, Mesh, connector, and
/// provider-bookkeeping objects.
#[cfg(test)]
pub(crate) fn test_resource_provider() -> myownmesh_core::ResourceProviderPort {
    test_resource_pair().0
}

/// The same grant's ledger, for controls that assert about what it holds.
///
/// It is the *provider*, not a second one: `in_use` read through this is the
/// figure every acquisition in this binary moves. A control that built its own
/// provider to look at would be looking at a different accounting than the code
/// under test spends from.
///
/// **Whatever reads this must run alone.** The grant is process-wide and shared
/// by every control in the binary, so a delta taken across a step is only
/// attributable to that step if nothing else is running -- which is what
/// `#[ignore]` plus an exact-name invocation buys, and why the one control that
/// reads it is marked that way.
#[cfg(all(test, unix))]
pub(crate) fn test_resource_ledger() -> myownmesh_core::FiniteResourceProvider {
    test_resource_pair().1
}

#[cfg(test)]
fn test_resource_pair() -> (
    myownmesh_core::ResourceProviderPort,
    myownmesh_core::FiniteResourceProvider,
) {
    static PROVIDER: std::sync::OnceLock<(
        myownmesh_core::ResourceProviderPort,
        myownmesh_core::FiniteResourceProvider,
    )> = std::sync::OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let connectors = TEST_PROCESS_CONNECTOR_CAPACITY as u64;
            let test_workers = std::env::var("RUST_TEST_THREADS")
                .ok()
                .map(|raw| {
                    raw.parse::<std::num::NonZeroUsize>()
                        .expect("RUST_TEST_THREADS must be a nonzero integer")
                })
                .unwrap_or_else(|| {
                    std::thread::available_parallelism()
                        .expect("daemon test worker concurrency must be observable")
                });
            let test_workers =
                u64::try_from(test_workers.get()).expect("daemon test workers fit u64");
            let semantic_owner_count = test_workers
                .checked_mul(TEST_SEMANTIC_NETWORKS_PER_WORKER)
                .expect("daemon semantic owner concurrency is representable");
            let callback_items_per_connector = 32_u64;
            // Each class funds its own callback slots from its own stated
            // ceiling, summed — not one figure spread across both.
            let queued_bytes = connectors
                .checked_mul(callback_items_per_connector)
                .and_then(|items| {
                    let control = items.checked_mul(TEST_CONTROL_CALLBACK_BYTES)?;
                    let endpoint = items.checked_mul(TEST_ENDPOINT_CALLBACK_BYTES)?;
                    control.checked_add(endpoint)
                })
                .expect("daemon test queued-byte grant is representable");
            let work_items = connectors
                .checked_mul(callback_items_per_connector)
                .expect("daemon test work-item grant is representable");
            let residual = 1u64
                .checked_add(connectors)
                .and_then(|value| value.checked_add(connectors.checked_mul(3)?))
                .and_then(|value| value.checked_add(work_items))
                .expect("daemon test provider bookkeeping is representable");
            let structural = myownmesh_core::connector_resource_structural_claims();
            let structural = structural
                .connector_opening()
                .checked_scale(connectors)
                .and_then(|claim| claim.checked_add(structural.process_infrastructure()))
                .expect("daemon test structural claims are representable");
            let workload = myownmesh_core::ResourceClaim::try_from_entries([
                (
                    myownmesh_core::ResourceClass::AccountedMemoryBytes,
                    queued_bytes,
                ),
                (myownmesh_core::ResourceClass::QueuedBytes, queued_bytes),
                (
                    myownmesh_core::ResourceClass::CallbackOrScheduledWork,
                    connectors * (1 + callback_items_per_connector),
                ),
                (myownmesh_core::ResourceClass::StorageBytes, 0),
                (myownmesh_core::ResourceClass::StorageObject, work_items),
                (myownmesh_core::ResourceClass::RelayOrProviderAllocation, 0),
                (
                    myownmesh_core::ResourceClass::ParsingOrCpuWork,
                    queued_bytes,
                ),
                (
                    myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                    residual,
                ),
            ])
            .expect("daemon test workload claim is representable");
            // JSON input work, kept as its own term. The claim is taken from the
            // gateway rather than restated here, so this grant and the admission
            // it has to satisfy can never be derived from two different formulas
            // — which is exactly how they diverged. It is added separately from
            // the provider-record `residual` above because the two are different
            // quantities that happen to share a dimension: one counts this
            // fixture's own bookkeeping objects, the other covers a decoded JSON
            // tree's allocations.
            let json_input_work =
                myownmesh_core::application_gateway::json_input_work_claim(TEST_JSON_FRAME_BYTES)
                    .expect("daemon test JSON input claim is representable")
                    .checked_scale(
                        connectors
                            .checked_mul(TEST_JSON_CLAIMS_PER_CONNECTOR)
                            .expect("daemon test JSON claim count is representable"),
                    )
                    .expect("daemon test JSON input grant is representable");
            // Outbound IPC frame queues, priced from the mailbox's own API
            // rather than from a formula restated here. Every term below comes
            // out of the same functions that will charge against it —
            // `root_claim`, `node_claim`, and the frame's own
            // `retained_claim` — so this grant and the admission it has to
            // satisfy cannot be derived from two different formulas. That is
            // the failure mode the JSON term above already records.
            let ipc_frame = crate::ipc::ServerOut::ChannelInbound {
                network: String::new(),
                from: String::new(),
                channel: String::new(),
                // Priced at the bound, not at a typical frame. Every term of
                // `retained_claim` grows with the encoded length, so funding
                // the largest frame this binary's fixtures may hold funds every
                // smaller one — no fixture has to be audited against it.
                payload: serde_json::Value::String("x".repeat(TEST_IPC_FRAME_BYTES)),
            };
            let ipc_entry =
                myownmesh_core::ResourceMailboxSender::<crate::ipc::ServerOut>::
                    accepted_item_planning_charge(&ipc_frame)
                    .expect("daemon test IPC mailbox entry charge is representable");
            let ipc_mailboxes =
                myownmesh_core::ResourceMailboxSender::<crate::ipc::ServerOut>::root_claim()
                    .expect("daemon test IPC mailbox root claim is representable")
                    .checked_add(
                        ipc_entry
                            .checked_scale(TEST_IPC_FRAMES_IN_FLIGHT)
                            .expect("daemon test IPC in-flight grant is representable"),
                    )
                    .and_then(|per_client| per_client.checked_scale(TEST_IPC_CLIENT_MAILBOXES))
                    .expect("daemon test IPC mailbox grant is representable");
            // The IPC registry's own admissions: client records, and one entry
            // in each of its tables per [`TEST_IPC_REGISTRY_ENTRIES`]. Priced by
            // the module that owns those node types, for the same reason the
            // mailbox term above is priced by the mailbox.
            let ipc_registry = crate::ipc::clients::registry_fixture_claim(
                TEST_IPC_CLIENT_MAILBOXES,
                TEST_IPC_REGISTRY_ENTRIES,
                TEST_IPC_REGISTRY_COORDINATE_BYTES,
            )
            .expect("daemon test IPC registry grant is representable");
            // IPC watchdog and pump tasks are a separate finite cohort from
            // connector workers. Charge the exact task reservation, including
            // its provider bookkeeping record, through the owner module rather
            // than restating its WorkerOrTask shape here.
            let ipc_tasks = crate::ipc::clients::task_reservation_planning_charge_for_test()
                .expect("daemon test IPC task reservation is representable")
                .checked_scale(TEST_IPC_TASKS)
                .expect("daemon test IPC task cohort grant is representable");
            // One process-owned route join worker, plus the actual separately
            // acquired route custody reservations for the existing task cohort.
            let ipc_route_custody = crate::ipc::clients::route_join_root_planning_charge()
                .and_then(|root| {
                    root.checked_add(
                        crate::ipc::clients::route_custody_planning_charge()?
                            .checked_scale(TEST_IPC_TASKS)
                            .map_err(crate::ipc::clients::IpcAdmissionError::Claim)?,
                    )
                    .map_err(crate::ipc::clients::IpcAdmissionError::Claim)
                })
                .expect("daemon route terminal custody is representable");
            // Inbound control frames, buffered and funded as they are read.
            let control_inbound = myownmesh_core::ResourceClaim::try_from_entries([(
                myownmesh_core::ResourceClass::AccountedMemoryBytes,
                TEST_CONTROL_INBOUND_FRAMES
                    .checked_mul(TEST_JSON_FRAME_BYTES as u64)
                    .expect("daemon test control inbound grant is representable"),
            )])
            .expect("daemon test control inbound claim is representable");
            // One embedded daemon per active test worker. Standalone control
            // fixtures fund their own outside root explicitly instead. These
            // are the owning modules' exact added claims, not worker headroom.
            let embedded_cleanup = myownmesh_services::ServiceCleanupOwner::planning_charge()
                .expect("embedded service root plan")
                .checked_add(
                    myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
                        crate::embedded::cleanup_storage_claim()
                            .expect("embedded transfer storage"),
                    )
                    .expect("embedded transfer storage normalization"),
                )
                .and_then(|claim| claim.checked_scale(test_workers))
                .expect("one embedded cleanup root per active test worker");
            // The live-service runtime-destruction embedded control owns one
            // STUN. Armed-startup/cancelled-shutdown now uses its own private
            // Mesh/STUN provider, as do the hosted constructor controls.
            let embedded_stun = myownmesh_services::StunServer::startup_planning_charge()
                .expect("embedded live STUN constructor plan");
            let claim = structural
                .checked_add(workload)
                .and_then(|claim| claim.checked_add(json_input_work))
                .and_then(|claim| claim.checked_add(ipc_mailboxes))
                .and_then(|claim| claim.checked_add(ipc_registry))
                .and_then(|claim| claim.checked_add(ipc_tasks))
                .and_then(|claim| claim.checked_add(ipc_route_custody))
                .and_then(|claim| claim.checked_add(control_inbound))
                .and_then(|claim| claim.checked_add(embedded_cleanup))
                .and_then(|claim| claim.checked_add(embedded_stun))
                .expect("daemon test resource grant is representable");
            // Every live NetworkState retains one semantic database. Charge
            // the real default policy budget once per possible live owner and
            // apply the provider's exact reservation bookkeeping before
            // scaling; scaling the raw claim would omit one record per owner.
            let semantic_policy = myownmesh_core::config::SemanticPolicyConfig::default();
            let semantic_storage_claim = myownmesh_core::ResourceClaim::single(
                myownmesh_core::ResourceClass::StorageBytes,
                semantic_policy.max_database_bytes,
            );
            let semantic_storage_grant =
                myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
                    semantic_storage_claim,
                )
                .expect("daemon semantic storage reservation is representable")
                .checked_scale(semantic_owner_count)
                .expect("daemon semantic storage owner capacity is representable");
            assert_eq!(
                semantic_storage_grant.amount(myownmesh_core::ResourceClass::StorageBytes),
                semantic_policy
                    .max_database_bytes
                    .checked_mul(semantic_owner_count)
                    .expect("daemon semantic storage byte capacity is representable"),
                "daemon semantic storage equals the default policy per live owner"
            );
            assert_eq!(
                semantic_storage_grant
                    .amount(myownmesh_core::ResourceClass::OpaqueDependencyResidual,),
                semantic_owner_count,
                "daemon semantic storage includes one reservation record per live owner"
            );
            let claim = claim
                .checked_add(semantic_storage_grant)
                .expect("daemon semantic storage grant combines without overflow");
            let provider = myownmesh_core::FiniteResourceProvider::new(claim);
            let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
                .expect("daemon test resource provider admits its process scope");
            (port, provider)
        })
        .clone()
}

/// One local-application acquisition scope over the same binary-wide grant.
///
/// Daemon-library tests that build an IPC writer mailbox need the acquisition
/// port a live daemon gets from its `MeshHandle`, and a unit test has no mesh
/// to ask. This reaches the same place the daemon does — the process resource
/// root — rather than inventing a second provider beside
/// [`test_resource_provider`]: two grants over one process is exactly the split
/// `install_local_application_provider` exists to refuse.
///
/// Installation is idempotent by identity, so every caller in the binary shares
/// one provider and each gets its own child scope off the process scope.
#[cfg(test)]
pub(crate) fn test_application_scope() -> myownmesh_core::LocalApplicationResourceScope {
    let root = myownmesh_core::ProcessResourceRoot::global();
    root.install_local_application_provider(test_resource_provider())
        .expect("the daemon test binary installs exactly one provider identity");
    root.issue_local_application_scope()
        .expect("the installed daemon test provider issues a local application scope")
}

/// Exclusive use of the connector budget above, for the whole lifetime of one
/// connector-consuming test's fixture.
///
/// One owner, because there is one budget. [`test_resource_provider`] is a
/// `OnceLock`, so its grant — [`TEST_PROCESS_CONNECTOR_CAPACITY`] connectors —
/// belongs to the test *binary* and not to each module that draws on it. Any
/// fixture that installs a connector policy is therefore spending from the same
/// finite pool as every other module's, and must serialize against them rather
/// than only against its own.
///
/// That is the whole claim, and it is the only one this guard can make good on.
/// A daemon test that opens a `Mesh` without a connector policy draws nothing
/// here and correctly takes no guard — `services`'s infrastructure-only tests
/// are the live example. Nothing in this workspace enforces one `Mesh` per
/// process, so do not read this guard as an identity or incarnation lock.
///
/// This replaces one mutex per test module — `ipc::bridge`, `embedded` and
/// `registry` each had their own. Each stopped a family racing itself and none
/// stopped the families racing each other, so with `libtest` running the binary
/// in parallel, three tests could draw on a budget of four connectors at once.
/// Three owners for one resource is the same defect shape the registry
/// supervisor itself exists to remove, and correcting that ownership is the
/// whole reason this guard exists — not a repair for any particular observed
/// failure. It was written while the bridge round trips were timing out waiting
/// for `PeerApproved`, and it did not fix them: they time out identically when
/// run alone with no other connector fixture in flight, so whatever those tests
/// are waiting on, it is not this budget.
///
/// Hold the guard for the fixture's whole life, teardown included. Releasing it
/// at the last assertion would let the next test ask for capacity the previous
/// one has not finished returning.
///
/// The `static` lives inside this function so there is exactly one and no module
/// can declare a second by accident.
#[cfg(test)]
pub(crate) async fn exclusive_connector_fixture() -> tokio::sync::MutexGuard<'static, ()> {
    static FIXTURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    FIXTURE.lock().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The aggregate provider this binary actually hands out admits two
    /// simultaneous JSON inputs per connector.
    ///
    /// This is deliberately an aggregate-capacity control, not evidence that
    /// the separately named JSON term is a partitioned allowance. IPC mailboxes,
    /// control input and connector work share dimensions with JSON parsing, and
    /// the finite provider is intentionally work-conserving across that whole
    /// grant. The control therefore proves only the production-relevant fact it
    /// can observe: all stated inputs can be admitted and held together.
    ///
    /// Takes the connector fixture guard because it spends from the one binary
    /// budget every connector-consuming fixture draws on.
    #[tokio::test]
    async fn v4_f8_the_daemon_aggregate_admits_two_json_inputs_per_connector() {
        let _fixture = exclusive_connector_fixture().await;
        let provider = test_resource_provider();
        let scope = provider.process_scope();
        let one = myownmesh_core::application_gateway::json_input_work_claim(TEST_JSON_FRAME_BYTES)
            .expect("one JSON input claim is representable");

        let funded = (TEST_PROCESS_CONNECTOR_CAPACITY as u64)
            .checked_mul(TEST_JSON_CLAIMS_PER_CONNECTOR)
            .expect("the fixture JSON claim count is representable");
        let mut leases = Vec::new();
        for index in 0..funded {
            let lease = provider
                .acquire(
                    &scope,
                    myownmesh_core::ResourceAuthorityClass::Admitted,
                    one,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "JSON input {index} of {funded} must be funded while the earlier ones are \
                         still held: {error:?}"
                    )
                });
            leases.push(lease);
        }

        // Held to the end so the control proves simultaneous capacity rather
        // than repeatedly reacquiring one returned slot.
        drop(leases);
    }
}
