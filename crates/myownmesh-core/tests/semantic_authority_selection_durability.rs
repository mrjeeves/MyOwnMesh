#![cfg(feature = "transport-lab")]

//! Actual SQLite checkpoint/shutdown/reopen coverage for G/M/O/R/T/U/F1/F2.
//! Export replay checks signed bodies and supplies a complete graph for fresh
//! projection recomputation. Live commitments and roster observations are
//! checked separately; replay alone is not evidence of durable restoration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SemanticPolicyConfig,
    SignalingConfig, TopologyMode, SQLITE_DEFAULT_PAGE_SIZE_BYTES,
};
use myownmesh_core::semantic::{
    Admission, DeviceId, ExclusiveCell, FactBody, FactContent, FactGraph, FactId, MeshContextId,
    Role, SemanticFactPage, SemanticFactPageRequest, SemanticRecentFactsRequest, SignedFact,
    VerifiedBootstrap,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, FiniteResourceProvider, Identity, JoinedNetwork, Mesh, MeshConfig,
    ResourceClaim, ResourceClass, ResourceProviderPort, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};

const BEFORE_REOPEN_FACTS: usize = 12;
const TOTAL_FACTS: usize = BEFORE_REOPEN_FACTS + 1;
const MEMBERSHIP_BEFORE_REOPEN: usize = 16;
const MEMBERSHIP_TOTAL_FACTS: usize = MEMBERSHIP_BEFORE_REOPEN + 1;
const PAGE_FACTS: u32 = 3;
const PAGE_BYTES: u32 =
    myownmesh_core::protocol::topology::MAX_ROUTED_APPLICATION_PAYLOAD_BYTES as u32;
static HOME_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct ScopedMeshHome {
    _lock: MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
}

impl ScopedMeshHome {
    fn new(path: &Path) -> Self {
        let lock = HOME_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("mesh-home environment lock");
        let previous = std::env::var_os("MYOWNMESH_HOME");
        std::env::set_var("MYOWNMESH_HOME", path);
        Self {
            _lock: lock,
            previous,
        }
    }
}

impl Drop for ScopedMeshHome {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var("MYOWNMESH_HOME", previous);
        } else {
            std::env::remove_var("MYOWNMESH_HOME");
        }
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn device(key: &SigningKey) -> DeviceId {
    DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("canonical device")
}

fn connector_policy(
    policy: SemanticPolicyConfig,
) -> (WebRtcConnectorCapablePolicy, FiniteResourceProvider) {
    let storage = policy
        .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, policy.storage_workload())
        .expect("actual policy has a finite storage envelope")
        .total_bytes;
    // Retain the working group fixture's historical non-storage test budget.
    // Only storage is derived from the actual selected policy's envelope;
    // these non-storage values are not a claim about exact workload cost.
    let requested = ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|class| {
        (
            class,
            if class == ResourceClass::StorageBytes {
                storage
            } else {
                1_000_000_000
            },
        )
    }))
    .expect("finite fixture claim");
    let grant = FiniteResourceProvider::reservation_planning_charge(requested)
        .expect("fixture reservation bookkeeping");
    let provider = FiniteResourceProvider::new(grant);
    let resources = ResourceProviderPort::new(provider.clone()).expect("fixture provider");
    (
        WebRtcConnectorCapablePolicy::new(
            resources,
            WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
        ),
        provider,
    )
}

fn config(name: &str) -> NetworkConfig {
    let semantic_policy = SemanticPolicyConfig {
        max_hot_history_facts: 1,
        ..SemanticPolicyConfig::default()
    };
    assert!(semantic_policy.validate());
    NetworkConfig {
        id: name.to_string(),
        network_id: name.to_string(),
        label: name.to_string(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        kind: NetworkKind::Closed,
        semantic_policy,
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        application_transport: None,
        tree: None,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: false,
        closed_relay: ClosedRelayPolicyConfig::default(),
    }
}

fn authored(
    graph: &FactGraph,
    signer: &SigningKey,
    body: FactBody,
    support: Vec<FactId>,
) -> SignedFact {
    let witness = graph.authoring_witness(&body, &device(signer));
    let mut content = FactContent::from_authoring_witness(graph, body, &witness, support);
    content.parents.sort();
    content.parents.dedup();
    SignedFact::sign(content, signer).expect("production witness signs")
}

fn admit(graph: &mut FactGraph, fact: &SignedFact) {
    assert_eq!(graph.admit(fact.clone()), Ok(Admission::Inserted));
    assert!(graph.quarantined().next().is_none());
}

fn page(context: MeshContextId, facts: &[SignedFact]) -> SemanticFactPage {
    let mut facts = facts.to_vec();
    facts.sort_by_key(|fact| fact.id);
    assert!(facts.windows(2).all(|pair| pair[0].id < pair[1].id));
    serde_json::from_value(serde_json::json!({
        "context_id": context, "facts": facts, "next_cursor": null, "complete": true,
    }))
    .expect("strict canonical page decodes")
}

fn export_all(network: &JoinedNetwork, context: MeshContextId, count: usize) -> Vec<SignedFact> {
    export_bounded(network, context, count, TOTAL_FACTS)
}

fn export_bounded(
    network: &JoinedNetwork,
    context: MeshContextId,
    count: usize,
    transcript_bound: usize,
) -> Vec<SignedFact> {
    assert!(count <= transcript_bound && transcript_bound <= MEMBERSHIP_TOTAL_FACTS);
    let mut facts = Vec::new();
    let mut cursor = None;
    // Even if the byte limit fits only one row, count+1 pages is sufficient.
    for _ in 0..=count {
        let page = network
            .export_semantic_fact_page(SemanticFactPageRequest {
                context_id: context,
                cursor,
                max_facts: PAGE_FACTS,
                max_encoded_bytes: PAGE_BYTES,
            })
            .expect("bounded durable export");
        assert_eq!(page.context_id(), context);
        for fact in page.facts() {
            assert!(facts
                .last()
                .is_none_or(|last: &SignedFact| last.id < fact.id));
            facts.push(fact.clone());
        }
        assert!(facts.len() <= count, "no extra durable facts");
        if page.is_complete() {
            assert_eq!(facts.len(), count);
            return facts;
        }
        let next = page.next_cursor().expect("incomplete page has a cursor");
        assert!(cursor.is_none_or(|old| old < next));
        assert_eq!(facts.last().map(|fact| fact.id), Some(next));
        cursor = Some(next);
    }
    panic!("durable export exceeded its finite transcript page bound");
}

fn replay_export(
    bootstrap: &VerifiedBootstrap,
    transcript: &[SignedFact],
    exported: Vec<SignedFact>,
) -> FactGraph {
    let mut by_id = BTreeMap::new();
    for fact in exported {
        assert!(by_id.insert(fact.id, fact).is_none());
    }
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for expected in transcript {
        let actual = by_id
            .remove(&expected.id)
            .expect("every recorded fact was exported");
        assert_eq!(
            &actual, expected,
            "exact body AND signature survive storage"
        );
        assert_eq!(
            actual.content.canonical_bytes(),
            expected.content.canonical_bytes()
        );
        admit(&mut graph, &actual);
    }
    assert!(by_id.is_empty());
    graph
}

// The same canonical v2 state transcript used by the existing differential
// integration test. No unresolved facts are permitted by this fixture.
fn state_root(graph: &FactGraph) -> [u8; 32] {
    assert!(graph.quarantined().next().is_none());
    let ids = graph.ids().copied().collect::<Vec<_>>();
    let mut hash = Sha256::new();
    hash.update(b"myownmesh-semantic-state-v2\0context\0");
    hash.update(graph.context_id().as_bytes());
    hash.update(b"\0admitted-count\0");
    hash.update((ids.len() as u64).to_le_bytes());
    hash.update(b"\0admitted\0");
    for id in ids {
        hash.update(id.as_bytes());
        hash.update(serde_json::to_vec(graph.get(&id).expect("full oracle row")).unwrap());
        hash.update([0]);
    }
    hash.update(b"\0unresolved-count\0");
    hash.update(0u64.to_le_bytes());
    hash.update(b"\0unresolved\0");
    hash.finalize().into()
}

#[derive(Debug, PartialEq, Eq)]
struct IdentitySnapshot {
    context: MeshContextId,
    admitted: u64,
    unresolved: u64,
    projection: [u8; 32],
    state: [u8; 32],
}

fn identity(network: &JoinedNetwork) -> IdentitySnapshot {
    let value = network
        .semantic_state_identity()
        .expect("live durable identity");
    // The observation's funding is released before shutdown comparisons.
    IdentitySnapshot {
        context: value.context_id(),
        admitted: value.admitted_fact_count(),
        unresolved: value.unresolved_fact_count(),
        projection: value.projection_commitment(),
        state: value.state_commitment(),
    }
}

struct Scenario {
    bootstrap: VerifiedBootstrap,
    controller_key: SigningKey,
    old_target: DeviceId,
    future_target: DeviceId,
    tail_target: DeviceId,
    operation: FactId,
    selected: FactId,
    selector: FactId,
    regrant: FactId,
    // Exact arrival transcript: G, M, O/R, R/O, T, U, F1, F2, four successors.
    facts: Vec<SignedFact>,
}

fn scenario(name: &str, root: &SigningKey, select_o: bool, reverse: bool) -> Scenario {
    let bootstrap = VerifiedBootstrap::create_closed(name, [root], [0x71; 32]).unwrap();
    let controller_key = key(231);
    let controller = device(&controller_key);
    let old_target = device(&key(232));
    let future_target = device(&key(233));
    let tail_target = device(&key(234));
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let g = authored(
        &graph,
        root,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    admit(&mut graph, &g);
    let m = authored(
        &graph,
        root,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );
    admit(&mut graph, &m);
    let o = authored(
        &graph,
        &controller_key,
        FactBody::RoleGrant {
            target: old_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let r = authored(
        &graph,
        root,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let operation = o.id;
    let selected = if select_o { o.id } else { r.id };
    let mut heads = vec![o.id, r.id];
    heads.sort();
    let mut facts = vec![g, m];
    for fact in if reverse { [r, o] } else { [o, r] } {
        admit(&mut graph, &fact);
        facts.push(fact);
    }
    assert_eq!(graph.authority_use_heads(&controller), heads);
    let t = authored(
        &graph,
        root,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: heads,
            selected_head: selected,
        },
        Vec::new(),
    );
    let selector = t.id;
    admit(&mut graph, &t);
    facts.push(t);
    let u = authored(
        &graph,
        root,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    let regrant = u.id;
    assert!(u.content.parents.contains(&selector));
    admit(&mut graph, &u);
    facts.push(u);
    for target in [&future_target, &tail_target] {
        let fact = authored(
            &graph,
            &controller_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        assert!(
            !fact.content.parents.contains(&selector),
            "future operation does not recite T"
        );
        admit(&mut graph, &fact);
        facts.push(fact);
    }
    // Replacing one role repeatedly leaves old F2 outside all current heads
    // and their direct witness layer. Unlike unrelated new targets, these
    // four operations can actually release a specific old hot row.
    for role in [
        Role::Controller,
        Role::Member,
        Role::Controller,
        Role::Member,
    ] {
        let fact = authored(
            &graph,
            &controller_key,
            FactBody::RoleGrant {
                target: tail_target.clone(),
                role,
            },
            Vec::new(),
        );
        admit(&mut graph, &fact);
        facts.push(fact);
    }
    assert_eq!(facts.len(), BEFORE_REOPEN_FACTS);
    Scenario {
        bootstrap,
        controller_key,
        old_target,
        future_target,
        tail_target,
        operation,
        selected,
        selector,
        regrant,
        facts,
    }
}

async fn assert_phase(network: &JoinedNetwork, scenario: &Scenario, transcript: &[SignedFact]) {
    let graph = replay_export(
        &scenario.bootstrap,
        transcript,
        export_all(network, scenario.bootstrap.context_id(), transcript.len()),
    );
    let (full, full_root) = graph.full_projection_for_lab();
    assert_eq!(
        graph.projection(),
        full,
        "incremental replay equals fresh full projection"
    );
    assert_eq!(
        identity(network),
        IdentitySnapshot {
            context: scenario.bootstrap.context_id(),
            admitted: transcript.len() as u64,
            unresolved: 0,
            projection: full_root,
            state: state_root(&graph),
        },
        "live durable roots and counts equal the full transcript oracle"
    );
    let controller = device(&scenario.controller_key);
    if transcript.len() >= 5 {
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(scenario.selected)
        );
        let expected = (scenario.selected == scenario.operation).then_some(Role::Member);
        assert_eq!(
            graph.evaluator().effective_role(&scenario.old_target),
            expected,
            "O's old target X is absent when R won, including after U/F1/F2"
        );
        assert_eq!(
            full.value(&ExclusiveCell::role(scenario.old_target.clone())),
            expected.map(|_| scenario.operation),
            "full projection suppresses the losing O cell"
        );
        let roster = network.roster_list().await.expect("live projected roster");
        let old = scenario.old_target.to_string();
        assert_eq!(
            roster
                .iter()
                .find(|row| row.device_id == old)
                .map(|row| row.role),
            expected,
            "the actual network roster follows branch selection"
        );
    }
    if transcript.len() >= 6 {
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            Some(Role::Owner)
        );
        assert_eq!(
            full.value(&ExclusiveCell::role(controller)),
            Some(scenario.regrant)
        );
    }
    if transcript.len() >= 7 {
        assert_eq!(
            graph.evaluator().effective_role(&scenario.future_target),
            Some(Role::Member)
        );
    }
    if transcript.len() >= 8 {
        let expected = transcript
            .iter()
            .rev()
            .find_map(|fact| match &fact.content.body {
                FactBody::RoleGrant { target, role } if target == &scenario.tail_target => {
                    Some(*role)
                }
                _ => None,
            });
        assert_eq!(
            graph.evaluator().effective_role(&scenario.tail_target),
            expected
        );
    }
}

fn assert_hot_boundary(network: &JoinedNetwork, fact: FactId, count: usize, resident: bool) {
    assert_hot_boundary_bounded(network, fact, count, resident, TOTAL_FACTS);
}

fn assert_hot_boundary_bounded(
    network: &JoinedNetwork,
    fact: FactId,
    count: usize,
    resident: bool,
    transcript_bound: usize,
) {
    assert!(count <= transcript_bound && transcript_bound <= MEMBERSHIP_TOTAL_FACTS);
    let recent = network
        .recent_semantic_facts(SemanticRecentFactsRequest {
            max_facts: transcript_bound as u32,
            max_encoded_bytes: PAGE_BYTES,
        })
        .expect("complete bounded hot cache observation");
    assert_eq!(recent.total_admitted_fact_count(), count as u64);
    assert_eq!(
        recent.facts().len() as u64,
        recent.cached_fact_count(),
        "absence is meaningful only when every hot row fits the observation"
    );
    assert_eq!(recent.facts().iter().any(|row| row.id == fact), resident);
    if !resident {
        assert!(recent.cached_fact_count() < count as u64);
        assert!(
            export_bounded(network, recent.context_id(), count, transcript_bound)
                .iter()
                .any(|row| row.id == fact),
            "the absent hot row remains an exact SQLite-owned exported fact"
        );
    }
}

fn resources(provider: &FiniteResourceProvider) -> (ResourceClaim, usize, usize, ResourceClaim) {
    (
        provider.in_use(),
        provider.active_reservations(),
        provider.active_scopes(),
        provider.retained_after_failed_cleanup(),
    )
}

async fn run_order(
    mesh: &myownmesh_core::MeshHandle,
    provider: &FiniteResourceProvider,
    scenario: Scenario,
    config: NetworkConfig,
) {
    let baseline = resources(provider);
    let network = mesh
        .create_network(config.clone(), [0x71; 32])
        .await
        .expect("create Closed slot");
    assert_eq!(
        network.export_bootstrap_record().unwrap(),
        *scenario.bootstrap.record()
    );
    // One fact per public transaction preserves the recorded O/R schedule.
    // page() still canonicalizes all input to satisfy the strict wire contract.
    for (index, fact) in scenario.facts.iter().enumerate() {
        drop(
            network
                .import_semantic_fact_page(page(
                    scenario.bootstrap.context_id(),
                    std::slice::from_ref(fact),
                ))
                .await
                .expect("commit actual semantic delta"),
        );
        assert_phase(&network, &scenario, &scenario.facts[..=index]).await;
        if index == 7 {
            assert_hot_boundary(&network, fact.id, 8, true);
        }
    }
    let cold = scenario.facts[7].id; // F2, observed resident before its four successors.
    assert_hot_boundary(&network, cold, BEFORE_REOPEN_FACTS, false);
    let before = identity(&network);
    network
        .compact_semantic_state()
        .expect("actual WAL checkpoint and compaction");
    assert_eq!(identity(&network), before);
    assert_phase(&network, &scenario, &scenario.facts).await;
    network.leave().await.expect("join durable owner shutdown");
    assert_eq!(
        resources(provider),
        baseline,
        "leave releases all network scopes and leases"
    );

    let reopened = mesh
        .join(config)
        .await
        .expect("reopen the same SQLite slot");
    assert_eq!(
        reopened.export_bootstrap_record().unwrap(),
        *scenario.bootstrap.record()
    );
    assert_eq!(identity(&reopened), before);
    assert_phase(&reopened, &scenario, &scenario.facts).await;
    assert_hot_boundary(&reopened, cold, BEFORE_REOPEN_FACTS, false);

    // Author from exact exported bodies after reopen. The import below still
    // validates/applies/commits against the restored live production graph.
    // Explicit signed support names the verified cold F2 row, exercising the
    // store's causal-history hydration path on this actual next transaction.
    let oracle = replay_export(
        &scenario.bootstrap,
        &scenario.facts,
        export_all(
            &reopened,
            scenario.bootstrap.context_id(),
            BEFORE_REOPEN_FACTS,
        ),
    );
    let continuation = authored(
        &oracle,
        &scenario.controller_key,
        FactBody::RoleGrant {
            target: scenario.tail_target.clone(),
            role: Role::Controller,
        },
        vec![cold],
    );
    assert!(continuation.content.parents.contains(&cold));
    assert!(!continuation.content.parents.contains(&scenario.selector));
    let mut transcript = scenario.facts.clone();
    drop(
        reopened
            .import_semantic_fact_page(page(
                scenario.bootstrap.context_id(),
                std::slice::from_ref(&continuation),
            ))
            .await
            .expect("commit after reopen with cold support"),
    );
    transcript.push(continuation);
    assert_phase(&reopened, &scenario, &transcript).await;
    let after = identity(&reopened);
    assert_eq!(after.admitted, TOTAL_FACTS as u64);
    assert_ne!(after.state, before.state);
    reopened
        .compact_semantic_state()
        .expect("checkpoint post-reopen continuation");
    assert_eq!(identity(&reopened), after);
    reopened
        .leave()
        .await
        .expect("join reopened durable owner shutdown");
    assert_eq!(
        resources(provider),
        baseline,
        "reopened owner releases exact provider custody"
    );
}

struct MembershipHistory {
    bootstrap: VerifiedBootstrap,
    root: DeviceId,
    controller_key: SigningKey,
    tail_target: DeviceId,
    old_m: FactId,
    eviction: FactId,
    fresh_q: FactId,
    revoke: FactId,
    facts: Vec<SignedFact>,
}

// Independent of FactGraph's ancestry, head indexes, authority eligibility,
// and projection caches. This fixture has only the five typed bodies below.
fn signed_membership_maxima(transcript: &[SignedFact], subject: &DeviceId) -> Vec<FactId> {
    assert!(transcript.len() <= MEMBERSHIP_TOTAL_FACTS);
    let by_id = transcript
        .iter()
        .map(|fact| (fact.id, fact))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(by_id.len(), transcript.len());
    let is_ancestor = |ancestor: FactId, descendant: FactId| {
        let mut pending = vec![descendant];
        let mut visited = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            let fact = by_id
                .get(&id)
                .expect("signed transcript dependency is present");
            if id == ancestor {
                return true;
            }
            pending.extend(fact.content.parents.iter().copied());
            for authority_use in &fact.content.authority_uses {
                pending.extend(authority_use.predecessors.iter().copied());
            }
            match &fact.content.body {
                FactBody::AuthorityLineageResolution { cited_heads, .. } => {
                    pending.extend(cited_heads.iter().copied());
                }
                FactBody::RoleGrant { .. }
                | FactBody::RoleRevoke { .. }
                | FactBody::MembershipAdmit { .. }
                | FactBody::Evict { .. } => {}
                _ => panic!("unexpected body in bounded independent membership oracle"),
            }
            assert!(visited.len() <= transcript.len());
        }
        false
    };
    let candidates = transcript
        .iter()
        .filter_map(|fact| match &fact.content.body {
            FactBody::MembershipAdmit { target } | FactBody::Evict { target }
                if target == subject =>
            {
                Some(fact.id)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut maxima = candidates
        .iter()
        .copied()
        .filter(|id| {
            !candidates
                .iter()
                .any(|other| other != id && is_ancestor(*id, *other))
        })
        .collect::<Vec<_>>();
    maxima.sort();
    maxima
}

fn membership_history(name: &str, root: &SigningKey) -> MembershipHistory {
    fn append(
        graph: &mut FactGraph,
        facts: &mut Vec<SignedFact>,
        signer: &SigningKey,
        body: FactBody,
        support: Vec<FactId>,
    ) -> FactId {
        let fact = authored(graph, signer, body, support);
        let id = fact.id;
        admit(graph, &fact);
        facts.push(fact);
        id
    }
    let bootstrap = VerifiedBootstrap::create_closed(name, [root], [0x71; 32]).unwrap();
    let controller_key = key(240);
    let owner_a = key(241);
    let controller = device(&controller_key);
    let tail_target = device(&key(243));
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let mut facts = Vec::new();
    append(
        &mut graph,
        &mut facts,
        root,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    // M and V are authored against the SAME G baseline, not serialized into
    // a chain. M is self-authored; a root-authored M would miss this defect.
    let m = authored(
        &graph,
        &controller_key,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let v = authored(
        &graph,
        root,
        FactBody::Evict {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let old_m = m.id;
    let eviction = v.id;
    for fact in [m, v] {
        admit(&mut graph, &fact);
        facts.push(fact);
    }
    let mut old_heads = vec![old_m, eviction];
    old_heads.sort();
    assert_eq!(graph.authority_use_heads(&controller), old_heads);
    append(
        &mut graph,
        &mut facts,
        root,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: old_heads.clone(),
            selected_head: eviction,
        },
        Vec::new(),
    );
    append(
        &mut graph,
        &mut facts,
        root,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    append(
        &mut graph,
        &mut facts,
        root,
        FactBody::RoleGrant {
            target: device(&owner_a),
            role: Role::Owner,
        },
        Vec::new(),
    );
    // Q is a new self-membership after T0/N, not a Resolution selecting M.
    // R is concurrent with Q. Neither is authored after observing the other.
    let q = authored(
        &graph,
        &controller_key,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let r = authored(
        &graph,
        root,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let fresh_q = q.id;
    let revoke = r.id;
    assert_ne!(fresh_q, old_m);
    assert!(
        !q.content.parents.contains(&old_m),
        "M dominance must traverse the signed intermediate history"
    );
    assert!(q
        .content
        .authority_uses
        .iter()
        .all(|usage| !usage.predecessors.contains(&old_m)));
    assert!(!q.content.parents.contains(&revoke));
    assert!(!r.content.parents.contains(&fresh_q));
    assert_eq!(signed_membership_maxima(&facts, &controller), old_heads);
    for fact in [q, r] {
        admit(&mut graph, &fact);
        facts.push(fact);
    }
    assert_eq!(signed_membership_maxima(&facts, &controller), vec![fresh_q]);
    let mut qr_heads = vec![fresh_q, revoke];
    qr_heads.sort();
    assert_eq!(graph.authority_use_heads(&controller), qr_heads);
    let t2 = append(
        &mut graph,
        &mut facts,
        &owner_a,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: qr_heads,
            selected_head: revoke,
        },
        Vec::new(),
    );
    append(
        &mut graph,
        &mut facts,
        root,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        vec![revoke],
    );
    assert!(facts.last().unwrap().content.parents.contains(&t2));
    assert!(facts.last().unwrap().content.parents.contains(&revoke));
    for target in [device(&key(242)), tail_target.clone()] {
        append(
            &mut graph,
            &mut facts,
            &controller_key,
            FactBody::RoleGrant {
                target,
                role: Role::Member,
            },
            Vec::new(),
        );
    }
    // Retire the exact F2 intermediate, without changing Membership(C) or
    // adding another selector that could mask the two-selector regression.
    for role in [
        Role::Controller,
        Role::Member,
        Role::Controller,
        Role::Member,
    ] {
        append(
            &mut graph,
            &mut facts,
            &controller_key,
            FactBody::RoleGrant {
                target: tail_target.clone(),
                role,
            },
            Vec::new(),
        );
    }
    assert_eq!(facts.len(), MEMBERSHIP_BEFORE_REOPEN);
    assert_eq!(signed_membership_maxima(&facts, &controller), vec![fresh_q]);
    MembershipHistory {
        bootstrap,
        root: device(root),
        controller_key,
        tail_target,
        old_m,
        eviction,
        fresh_q,
        revoke,
        facts,
    }
}

async fn assert_membership_phase(
    network: &JoinedNetwork,
    scenario: &MembershipHistory,
    transcript: &[SignedFact],
) {
    let graph = replay_export(
        &scenario.bootstrap,
        transcript,
        export_bounded(
            network,
            scenario.bootstrap.context_id(),
            transcript.len(),
            MEMBERSHIP_TOTAL_FACTS,
        ),
    );
    let (full, full_root) = graph.full_projection_for_lab();
    assert_eq!(
        graph.projection(),
        full,
        "historical membership full/incremental parity"
    );
    assert_eq!(
        identity(network),
        IdentitySnapshot {
            context: scenario.bootstrap.context_id(),
            admitted: transcript.len() as u64,
            unresolved: 0,
            projection: full_root,
            state: state_root(&graph),
        },
        "live SQLite identity equals exact signed transcript and full projection"
    );
    let count = transcript.len();
    if count < 4 {
        return;
    } // M was legitimately active before the first fork/selector.
    let controller = device(&scenario.controller_key);
    let (membership, value, role) = match count {
        4 => (Some(false), Some(scenario.eviction), None), // T0 selects V.
        5 | 6 => (Some(false), Some(scenario.eviction), Some(Role::Owner)), // N / Owner A.
        7 => (Some(true), Some(scenario.fresh_q), Some(Role::Owner)), // genuinely new Q.
        8 | 9 => (None, None, None),                       // Q/R fork / distinct Owner A selects R.
        _ => (None, None, Some(Role::Owner)),              // U2 and later ordinary operations.
    };
    let mut expected_raw = if count < 7 {
        vec![scenario.old_m, scenario.eviction]
    } else {
        vec![scenario.fresh_q]
    };
    expected_raw.sort();
    assert_eq!(
        signed_membership_maxima(transcript, &controller),
        expected_raw,
        "raw maxima come from complete signed ancestry, before authority filtering"
    );
    assert_eq!(
        graph.evaluator().effective_membership(&controller),
        membership,
        "stage {count}: old M never becomes current after T0"
    );
    assert_eq!(
        full.value(&ExclusiveCell::membership(controller.clone())),
        value,
        "stage {count}: full projection cannot revive a dominated or excluded membership"
    );
    assert_eq!(
        graph.cell_heads(&ExclusiveCell::membership(controller.clone())),
        value.into_iter().collect::<Vec<_>>(),
        "stage {count}: authority-filtered public heads must not fall back to historical M"
    );
    assert_ne!(value, Some(scenario.old_m));
    assert_eq!(
        graph.evaluator().effective_role(&controller),
        role,
        "stage {count}: role"
    );
    if count >= 9 {
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(scenario.revoke)
        );
    }
    // This checks the actual two-endpoint policy, not a claim that absence of
    // one membership value alone denies Closed access. In particular U2's
    // Owner plus unset membership can admit a session without reviving M.
    let admitted = graph.admits_policy_session(&scenario.bootstrap, &scenario.root, &controller);
    assert_eq!(
        admitted,
        count == 7 || count >= 10,
        "stage {count}: both-endpoint policy"
    );
    let roster = network.roster_list().await.expect("live canonical roster");
    let controller_name = controller.to_string();
    assert_eq!(
        roster
            .iter()
            .find(|row| row.device_id == controller_name)
            .map(|row| row.role),
        if admitted { role } else { None },
        "stage {count}: live roster agrees with canonical policy"
    );
}

async fn run_membership_history(
    mesh: &myownmesh_core::MeshHandle,
    provider: &FiniteResourceProvider,
    scenario: MembershipHistory,
    config: NetworkConfig,
) {
    let baseline = resources(provider);
    let network = mesh
        .create_network(config.clone(), [0x71; 32])
        .await
        .unwrap();
    assert_eq!(
        network.export_bootstrap_record().unwrap(),
        *scenario.bootstrap.record()
    );
    for (index, fact) in scenario.facts.iter().enumerate() {
        drop(
            network
                .import_semantic_fact_page(page(
                    scenario.bootstrap.context_id(),
                    std::slice::from_ref(fact),
                ))
                .await
                .expect("durable historical-membership admission"),
        );
        assert_membership_phase(&network, &scenario, &scenario.facts[..=index]).await;
        if index == 11 {
            assert_hot_boundary_bounded(&network, fact.id, 12, true, MEMBERSHIP_TOTAL_FACTS);
        }
    }
    let cold = scenario.facts[11].id;
    assert_hot_boundary_bounded(
        &network,
        cold,
        MEMBERSHIP_BEFORE_REOPEN,
        false,
        MEMBERSHIP_TOTAL_FACTS,
    );
    let before = identity(&network);
    network
        .compact_semantic_state()
        .expect("checkpoint both selector contexts");
    assert_eq!(identity(&network), before);
    assert_membership_phase(&network, &scenario, &scenario.facts).await;
    network.leave().await.unwrap();
    assert_eq!(
        resources(provider),
        baseline,
        "historical membership first owner fully released"
    );

    let reopened = mesh
        .join(config)
        .await
        .expect("reopen same historical-membership SQLite slot");
    assert_eq!(
        reopened.export_bootstrap_record().unwrap(),
        *scenario.bootstrap.record()
    );
    assert_eq!(identity(&reopened), before);
    assert_membership_phase(&reopened, &scenario, &scenario.facts).await;
    assert_hot_boundary_bounded(
        &reopened,
        cold,
        MEMBERSHIP_BEFORE_REOPEN,
        false,
        MEMBERSHIP_TOTAL_FACTS,
    );
    let oracle = replay_export(
        &scenario.bootstrap,
        &scenario.facts,
        export_bounded(
            &reopened,
            scenario.bootstrap.context_id(),
            MEMBERSHIP_BEFORE_REOPEN,
            MEMBERSHIP_TOTAL_FACTS,
        ),
    );
    let next = authored(
        &oracle,
        &scenario.controller_key,
        FactBody::RoleGrant {
            target: scenario.tail_target.clone(),
            role: Role::Controller,
        },
        vec![cold],
    );
    assert!(next.content.parents.contains(&cold));
    drop(
        reopened
            .import_semantic_fact_page(page(
                scenario.bootstrap.context_id(),
                std::slice::from_ref(&next),
            ))
            .await
            .expect("actual next commit with cold signed support"),
    );
    let mut transcript = scenario.facts.clone();
    transcript.push(next);
    assert_eq!(transcript.len(), MEMBERSHIP_TOTAL_FACTS);
    assert_membership_phase(&reopened, &scenario, &transcript).await;
    let after = identity(&reopened);
    assert_ne!(after.state, before.state);
    reopened.compact_semantic_state().unwrap();
    assert_eq!(identity(&reopened), after);
    assert_membership_phase(&reopened, &scenario, &transcript).await;
    reopened.leave().await.unwrap();
    assert_eq!(
        resources(provider),
        baseline,
        "historical membership reopened owner fully released"
    );
}

#[tokio::test]
async fn selected_authority_branch_survives_compact_reopen_and_cold_hydration() {
    let home = TempDir::new().expect("selection mesh home");
    let _home = ScopedMeshHome::new(home.path());
    let identity = Arc::new(Identity::from_signing_key(key(230), "selection root"));
    // Build all four finite signed scenarios before constructing runtime
    // owners. This catches authoring/precondition errors before SQLite work.
    let cases = [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .map(|(select_o, reverse)| {
            let name = format!("selection-{}-{}", u8::from(select_o), u8::from(reverse));
            (
                scenario(&name, identity.signing_key(), select_o, reverse),
                config(&name),
            )
        })
        .collect::<Vec<_>>();
    let membership = membership_history("membership-history", identity.signing_key());
    let membership_config = config("membership-history");
    let (policy, provider) = connector_policy(cases[0].1.semantic_policy);
    let mesh = Mesh::open_connector_capable_with_identity(MeshConfig::default(), identity, policy)
        .await
        .expect("open one finite process provider and mesh");
    let baseline = resources(&provider);
    for (scenario, config) in cases {
        run_order(&mesh, &provider, scenario, config).await;
    }
    run_membership_history(&mesh, &provider, membership, membership_config).await;
    assert_eq!(
        resources(&provider),
        baseline,
        "four branch cases and historical membership return to the same Mesh/process-root baseline"
    );
}
