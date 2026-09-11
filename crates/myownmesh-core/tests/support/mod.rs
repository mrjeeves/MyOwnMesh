use std::num::NonZeroUsize;
use std::sync::OnceLock;

use myownmesh_core::transport::Transport;
use myownmesh_core::{
    ConnectorCallbackPolicy, FiniteResourceProvider, ResourceClaim, ResourceClass,
    ResourceProviderPort, WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};

static TEST_RESOURCE_PROVIDER: OnceLock<ResourceProviderPort> = OnceLock::new();

/// The largest JSON frame these fixtures fund the *parse* of.
///
/// Its own number, deliberately not borrowed from the callback payload ceilings
/// below. Those bound what a connector may hold queued; this bounds what the
/// application gateway may allocate turning one frame into a `serde_json::Value`
/// tree, which is a different quantity with a different denomination — the
/// tree's claim is per input byte because a JSON value can hold as many
/// independent allocations as it has bytes.
///
/// Test workload capacity only, and no wire gate: a frame is admitted against
/// its own actual length. This fixture's grant used to leave that claim funded
/// only by a residual counted in records, which is why it passed at eight
/// libtest workers and failed the same handshake at one — the record count
/// happened to exceed the frame length, or happened not to.
const FIXTURE_JSON_FRAME_BYTES: usize = 8 * 1024;

/// Simultaneous JSON input claims one connector can hold: the peer's `Hello`,
/// whose claim is retained for the connection's whole life, plus one protocol
/// or application frame being parsed. One would fund the retained `Hello` and
/// refuse everything after it; more would be capacity with no nameable holder.
const FIXTURE_JSON_CLAIMS_PER_CONNECTOR: u64 = 2;

/// One application owner per libtest worker is the largest concurrent
/// application workload in the integration fixtures. Each such owner can
/// retain one RPC dispatcher and one local capability advertisement.
const FIXTURE_APPLICATIONS_PER_WORKER: u64 = 1;

/// Each fixture worker keeps two live network/application owners (sender and
/// receiver). This names their local gateway scopes separately from the one
/// RPC child scope retained by the application workload below.
const FIXTURE_APPLICATION_SCOPES_PER_WORKER: u64 = 2;

/// The largest encoded capability advert used by the integration fixtures.
/// The R3 advert is below this exact byte ceiling; its provider charge is
/// derived by the production gateway planner rather than by a copied formula.
const FIXTURE_CAPABILITY_ADVERT_BYTES: usize = 128;

/// `mint_attempt` encodes eight random bytes as 13 unpadded base32 characters.
/// The fixture uses this exact shape to price the promoted channel's owned
/// correlation allocation through the broker planner.
const FIXTURE_CHANNEL_CORRELATION: &str = "aaaaaaaaaaaaa";

/// Canonical base32 wire representation of one 32-byte Ed25519 device id.
/// This is a fixture representation length, not a product capacity selector.
const FIXTURE_MDNS_DEVICE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Explicit integration-test resource owner.
///
/// These values cover the known in-process multi-device test fixtures. They
/// are test inputs only and make no production sizing claim.
pub fn test_transport() -> Transport {
    // Every integration-test binary has one real process resource root, while
    // libtest runs up to one test case per worker concurrently. The fixture
    // grant is process-global and work-conserving. This count sizes only the
    // explicit test workload and does not partition capacity by Mesh.
    let mesh_connector_count =
        NonZeroUsize::new(16).expect("fixture per-Mesh connector bound is nonzero");
    let test_workers = std::env::var("RUST_TEST_THREADS")
        .ok()
        .map(|raw| {
            raw.parse::<NonZeroUsize>()
                .expect("RUST_TEST_THREADS must be a nonzero integer")
        })
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .expect("integration-test worker concurrency must be observable")
        });
    let process_connector_count = NonZeroUsize::new(
        mesh_connector_count
            .get()
            .checked_mul(test_workers.get())
            .expect("integration-test process connector bound must fit usize"),
    )
    .expect("derived integration-test process connector bound is nonzero");
    let callback_capacity = NonZeroUsize::new(16).expect("fixture callback capacity is nonzero");
    // The largest single payload this fixture funds, stated per callback class.
    //
    // This provider is minted here rather than drawn from a process owner, so
    // these two numbers are the only thing that can size its byte grant, and the
    // arithmetic below reads them back off the policy rather than repeating
    // them. They are fixture inputs and make no production sizing claim, and
    // neither is borrowed from another layer — not the protocol's endpoint frame
    // maximum, not the signaling frame limit.
    //
    // Control covers one gathered ICE candidate's JSON. Endpoint covers the
    // application payloads these multi-device fixtures exchange; it keeps the
    // byte figure this fixture has always run with, now stated as what it is
    // instead of appearing once as an unnamed multiplier.
    let control_payload_ceiling =
        NonZeroUsize::new(4_096).expect("fixture control payload ceiling is nonzero");
    let endpoint_payload_ceiling =
        NonZeroUsize::new(16 * 1024 * 1024).expect("fixture endpoint payload ceiling is nonzero");
    let webrtc_profile = WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only());
    let provider = TEST_RESOURCE_PROVIDER.get_or_init(|| {
        let connectors = u64::try_from(process_connector_count.get())
            .expect("fixture connector concurrency fits u64");
        let mesh_scopes =
            u64::try_from(test_workers.get()).expect("fixture worker concurrency fits u64");
        let queued_items = connectors
            .checked_mul(
                u64::try_from(callback_capacity.get()).expect("fixture callback count fits u64"),
            )
            .expect("fixture queued-item envelope fits u64");
        // Each class funds its own slots from its own stated ceiling, summed.
        // One number multiplied across the combined slot count is what this
        // replaces: it made the endpoint figure silently pay for every control
        // callback too, so neither class's budget meant what it said and removing
        // the figure would have left control funded for nothing.
        //
        // The two ceilings used to be read back off the installed policy so the
        // grant and the declaration could not drift. The policy no longer
        // carries them — nothing enforces a per-class payload ceiling any more —
        // so they are what they always really were here: this fixture's own
        // statement of the largest payload it intends to fund.
        let ceiling = |bytes: NonZeroUsize, class: &str| -> u64 {
            u64::try_from(bytes.get())
                .unwrap_or_else(|_| panic!("the stated {class} payload ceiling fits u64"))
        };
        let control_bytes = queued_items
            .checked_mul(ceiling(control_payload_ceiling, "control"))
            .expect("fixture control byte envelope fits u64");
        let endpoint_bytes = queued_items
            .checked_mul(ceiling(endpoint_payload_ceiling, "endpoint-data"))
            .expect("fixture endpoint byte envelope fits u64");
        let retained_bytes = control_bytes
            .checked_add(endpoint_bytes)
            .expect("fixture retained-byte envelope fits u64");
        let residual = 1u64
            .checked_add(mesh_scopes)
            .and_then(|value| value.checked_add(connectors.checked_mul(3)?))
            .and_then(|value| value.checked_add(queued_items))
            .expect("fixture provider bookkeeping fits u64");
        let structural = myownmesh_core::connector_resource_structural_claims();
        let structural = structural
            .connector_opening()
            .checked_scale(connectors)
            .and_then(|claim| claim.checked_add(structural.process_infrastructure()))
            .expect("fixture structural claims are representable");
        let workload = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, retained_bytes),
            (ResourceClass::QueuedBytes, retained_bytes),
            (
                ResourceClass::CallbackOrScheduledWork,
                connectors
                    .checked_add(queued_items)
                    .expect("fixture callback-work envelope fits u64"),
            ),
            (ResourceClass::StorageObject, queued_items),
            (ResourceClass::ParsingOrCpuWork, retained_bytes),
            (ResourceClass::OpaqueDependencyResidual, residual),
        ])
        .expect("the fixture workload claim is representable");
        // JSON input work, as its own term. The claim comes from the gateway
        // rather than being restated here, so the grant and the admission it has
        // to satisfy cannot be derived from two different formulas. Added apart
        // from the provider-record `residual` above because the two are
        // different quantities that merely share a dimension: one counts this
        // fixture's bookkeeping objects, the other a decoded JSON tree's
        // allocations.
        let json_input_work =
            myownmesh_core::application_gateway::json_input_work_claim(FIXTURE_JSON_FRAME_BYTES)
                .expect("the fixture JSON input claim is representable")
                .checked_scale(
                    connectors
                        .checked_mul(FIXTURE_JSON_CLAIMS_PER_CONNECTOR)
                        .expect("the fixture JSON claim count is representable"),
                )
                .expect("the fixture JSON input grant is representable");
        let grant = structural
            .checked_add(workload)
            .and_then(|claim| claim.checked_add(json_input_work))
            .expect("the fixture provider grant is representable");
        // One post-authentication Session Broker reservation per connector.
        //
        // The connector count is the ceiling on *concurrent promoted sessions*,
        // not an estimate of them: a session is promoted from the authenticated
        // channel of exactly one live connector and is dropped with it, so no
        // fixture here can hold more sessions than it has connector slots to
        // promote them from. Scaling by anything else would be a guess.
        //
        // The charge is taken from the broker rather than restated. It is
        // denominated in the accounted memory of the session record and the
        // roots promotion allocates, plus the record the provider keeps for the
        // lease carrying it — none of which this fixture may name for itself,
        // and all of which change on the broker's side rather than this one.
        //
        // Budgeting it explicitly is the point. The session claim used to be one
        // `WorkerOrTask` unit, which could bind on slack the connector
        // structural capacity above happened to leave, so an unbudgeted session
        // was invisible until some unrelated term moved. Nothing else here is
        // denominated in what the session claim now names, so a shortfall
        // surfaces as a refused promotion rather than as a fixture that quietly
        // stopped promoting.
        //
        // Unconditional because default-feature connectors promote the same
        // sessions as transport-lab connectors. Omitting this exact broker term
        // would make promotion depend on unrelated residual slack.
        let grant = myownmesh_core::session_reservation_planning_claim_for_correlation(
            FIXTURE_CHANNEL_CORRELATION,
        )
        .checked_scale(connectors)
        .and_then(|sessions| grant.checked_add(sessions))
        .expect("the fixture session reservation capacity is representable");
        let applications = mesh_scopes
            .checked_mul(FIXTURE_APPLICATIONS_PER_WORKER)
            .expect("fixture application concurrency fits u64");
        let application_scopes = mesh_scopes
            .checked_mul(FIXTURE_APPLICATION_SCOPES_PER_WORKER)
            .expect("fixture local application scope concurrency fits u64");
        let application_scope_claim =
            myownmesh_core::FiniteResourceProvider::scope_planning_charge()
                .checked_scale(application_scopes)
                .expect("the fixture application scope capacity is representable");
        // Each live network/application owner retains one semantic database.
        // Charge the real default database budget once per owner, then apply
        // the provider's exact reservation bookkeeping charge before scaling;
        // scaling the raw storage claim would underfund one reservation record
        // for every additional owner.
        let semantic_policy = myownmesh_core::config::SemanticPolicyConfig::default();
        let semantic_storage_owner_count = mesh_scopes
            .checked_mul(FIXTURE_APPLICATION_SCOPES_PER_WORKER)
            .expect("fixture semantic storage owner concurrency fits u64");
        assert_eq!(
            semantic_storage_owner_count, application_scopes,
            "semantic storage is funded for exactly the live application-owner bound"
        );
        let semantic_storage_claim = ResourceClaim::single(
            ResourceClass::StorageBytes,
            semantic_policy.max_database_bytes,
        );
        let semantic_storage_grant =
            myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
                semantic_storage_claim,
            )
            .expect("the fixture semantic storage reservation is representable")
            .checked_scale(semantic_storage_owner_count)
            .expect("the fixture semantic storage owner capacity is representable");
        assert_eq!(
            semantic_storage_grant.amount(ResourceClass::StorageBytes),
            semantic_policy
                .max_database_bytes
                .checked_mul(semantic_storage_owner_count)
                .expect("the fixture semantic storage byte capacity is representable"),
            "semantic storage bytes equal the default policy per live owner"
        );
        assert_eq!(
            semantic_storage_grant.amount(ResourceClass::OpaqueDependencyResidual),
            semantic_storage_owner_count,
            "semantic storage includes one reservation record per live owner"
        );
        let grant = grant
            .checked_add(semantic_storage_grant)
            .expect("the fixture semantic storage grant combines without overflow");
        // Rpc::attach retains one dispatcher per application and advertise
        // retains one encoded local advert. Both terms are provider-planned by
        // the production constructors, and both are bounded by the explicit
        // one-application-per-worker fixture workload above.
        let application_claim = myownmesh_core::rpc_dispatcher_attachment_planning_claim()
            .expect("the fixture RPC dispatcher claim is representable")
            .checked_scale(applications)
            .and_then(|claim| {
                myownmesh_core::capability_advert_planning_claim(FIXTURE_CAPABILITY_ADVERT_BYTES)
                    .expect("the fixture capability advert claim is representable")
                    .checked_scale(applications)
                    .and_then(|adverts| claim.checked_add(adverts))
            })
            .expect("the fixture application retention capacity is representable");
        let grant = grant
            .checked_add(application_scope_claim)
            .and_then(|grant| grant.checked_add(application_claim))
            .expect("the fixture application retention grant is representable");
        // One bounded two-peer mDNS fixture retains one known-peer outbound
        // endpoint, one unknown-peer inbound endpoint, and one inbound sender
        // identity buffer. Price each exact production plan, including the
        // finite provider's reservation bookkeeping, and scale only by the
        // existing test-worker concurrency.
        let mdns_limits = myownmesh_signaling::mdns::driver::MdnsLimits::default();
        let mdns_outbound = myownmesh_core::mdns_connection_planning_claim(
            Some(FIXTURE_MDNS_DEVICE_ID),
            mdns_limits.outbound_queue_capacity,
        )
        .expect("the exact mDNS outbound plan is available");
        let mdns_inbound = myownmesh_core::mdns_connection_planning_claim(
            None,
            mdns_limits.outbound_queue_capacity,
        )
        .expect("the exact mDNS inbound plan is available");
        let mdns_identity =
            myownmesh_core::mdns_connection_identity_planning_claim(FIXTURE_MDNS_DEVICE_ID)
                .expect("the exact mDNS identity plan is available");
        let mdns_connection_pair = mdns_outbound
            .checked_add(mdns_inbound)
            .and_then(|pair| pair.checked_add(mdns_identity))
            .and_then(|pair| pair.checked_scale(mesh_scopes))
            .expect("the bounded mDNS connection-pair workload is representable");
        let grant = grant
            .checked_add(mdns_connection_pair)
            .expect("the fixture mDNS connection grant is representable");
        // The transport-lab mDNS workload has two live network owners per
        // test worker. Fund each owner's four startup reservations from the
        // same policy/backend planners used by attachment, independently of
        // the TCP pair above. No startup term is borrowed from connector slack.
        #[cfg(feature = "transport-lab")]
        let grant = {
            let startup =
                myownmesh_core::engine::transport_lab::mdns_startup_planning_claim_for_lab(
                    &myownmesh_core::config::MdnsPolicyConfig::default(),
                )
                .expect("the configured mDNS startup reservations are representable");
            let startup = startup
                .checked_scale(application_scopes)
                .expect("the two-owner mDNS startup workload is representable");
            grant
                .checked_add(startup)
                .expect("the fixture mDNS startup grant combines without overflow")
        };
        ResourceProviderPort::new(FiniteResourceProvider::new(grant))
            .expect("the fixture provider accounts for its process scope")
    });
    let policy = WebRtcConnectorCapablePolicy::new(provider.clone(), webrtc_profile);
    Transport::new()
        .expect("transport")
        .with_connector_resource_policy(policy)
        .expect("fixture process connector policy is consistent")
}
