//! Production-shaped multi-page anti-entropy controls.
//!
//! The engine's governance path sends one exact byte-sized page at a time.
//! These controls model the observable inventory/request exchange at that
//! boundary: inventory identifiers are hints only, and signed fact admission
//! is represented by the receiver adding only identifiers supplied by the
//! authoritative source fixture.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use myownmesh_core::protocol::{FactInventory, FactPageMessage, MeshMessage};
use myownmesh_core::semantic::{
    DeviceId, FactBody, FactContent, FactId, MeshContextId, SignedFact,
};

const EXACT_RECEIVE_FRAME_BYTES: usize = 65_535;

#[derive(Clone, Copy)]
struct ExactRoute {
    context: MeshContextId,
    generation: u64,
}

fn ids(count: u64) -> Vec<FactId> {
    (0..count)
        .map(|index| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&index.to_be_bytes());
            FactId::from_bytes(bytes)
        })
        .collect()
}

fn fact_page(context: MeshContextId, facts: Vec<SignedFact>, complete: bool) -> FactPageMessage {
    let next_cursor = (!complete)
        .then(|| facts.last().map(|fact| fact.id))
        .flatten();
    FactPageMessage {
        context_id: context,
        facts,
        next_cursor,
        complete,
    }
}

/// Form pages with the same complete-frame measurement used by production.
/// This test helper deliberately has no item-count ceiling.
fn exact_pages(context: MeshContextId, values: &[FactId]) -> Vec<FactInventory> {
    let mut pages = Vec::new();
    let mut current = Vec::new();
    for value in values {
        current.push(*value);
        let candidate = FactInventory::new(context, current.iter().copied());
        let encoded = serde_json::to_vec(&MeshMessage::FactInventory(candidate)).unwrap();
        if encoded.len() <= EXACT_RECEIVE_FRAME_BYTES {
            continue;
        }
        current.pop();
        assert!(!current.is_empty(), "a single FactId must fit the frame");
        pages.push(FactInventory::new(context, current.drain(..)));
        current.push(*value);
        let single = FactInventory::new(context, current.iter().copied());
        let encoded = serde_json::to_vec(&MeshMessage::FactInventory(single)).unwrap();
        assert!(encoded.len() <= EXACT_RECEIVE_FRAME_BYTES);
    }
    pages.push(FactInventory::new(context, current));
    pages
}

fn apply_inventory_page(
    target: &mut BTreeSet<FactId>,
    source: &BTreeSet<FactId>,
    page: &FactInventory,
    route: ExactRoute,
    expected: ExactRoute,
) -> usize {
    if route.context != expected.context
        || route.generation != expected.generation
        || page.context_id() != expected.context
    {
        return 0;
    }
    let requested: Vec<_> = page
        .fact_ids()
        .iter()
        .copied()
        .filter(|id| !target.contains(id))
        .collect();
    let before = target.len();
    target.extend(requested.into_iter().filter(|id| source.contains(id)));
    target.len() - before
}

fn signed_fact_with_evidence(context: MeshContextId, count: u64) -> SignedFact {
    let key = SigningKey::from_bytes(&[0x91; 32]);
    let device = DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap();
    let evidence = (0..count)
        .map(|index| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&index.to_be_bytes());
            FactId::from_bytes(bytes)
        })
        .collect();
    let body = FactBody::SelfStandDown {
        device_id: device.clone(),
        evidence,
    };
    SignedFact::sign(
        FactContent::new(body.domain(), context, body, device, Vec::new()),
        &key,
    )
    .unwrap()
}

fn encoded_len(message: &MeshMessage) -> usize {
    serde_json::to_vec(message).unwrap().len()
}

fn find_page_only_overflow_fact(context: MeshContextId) -> SignedFact {
    let mut low = 1;
    let mut high = 4_000;
    let mut candidate = None;
    while low <= high {
        let count = (low + high) / 2;
        let fact = signed_fact_with_evidence(context, count);
        let single = encoded_len(&MeshMessage::Fact(fact.clone()));
        let page = encoded_len(&MeshMessage::FactPage(fact_page(
            context,
            vec![fact.clone()],
            true,
        )));
        if single <= EXACT_RECEIVE_FRAME_BYTES && page > EXACT_RECEIVE_FRAME_BYTES {
            candidate = Some(fact);
            high = count - 1;
        } else if page <= EXACT_RECEIVE_FRAME_BYTES {
            low = count + 1;
        } else {
            high = count.saturating_sub(1);
        }
    }
    candidate.expect("a Fact-only frame must have a smaller envelope than its page")
}

fn oversized_fact(context: MeshContextId) -> SignedFact {
    let fact = signed_fact_with_evidence(context, 4_000);
    assert!(encoded_len(&MeshMessage::Fact(fact.clone())) > EXACT_RECEIVE_FRAME_BYTES);
    assert!(
        encoded_len(&MeshMessage::FactPage(fact_page(
            context,
            vec![fact.clone()],
            true,
        ))) > EXACT_RECEIVE_FRAME_BYTES
    );
    fact
}

/// Mirror the production page decision, including the rule that an
/// individually untransmittable fact is skipped while later facts continue.
fn emit_fact_request_pages(facts: &[SignedFact]) -> Vec<MeshMessage> {
    let mut emitted = Vec::new();
    let mut page_facts = Vec::new();
    for fact in facts {
        page_facts.push(fact.clone());
        let context = fact.content.mesh_context;
        if encoded_len(&MeshMessage::FactPage(fact_page(
            context,
            page_facts.clone(),
            false,
        ))) <= EXACT_RECEIVE_FRAME_BYTES
        {
            continue;
        }

        let last = page_facts.pop().expect("the just-added fact is present");
        if page_facts.is_empty() {
            let single = MeshMessage::Fact(last);
            if encoded_len(&single) <= EXACT_RECEIVE_FRAME_BYTES {
                emitted.push(single);
            }
            continue;
        }

        emitted.push(MeshMessage::FactPage(fact_page(
            context,
            std::mem::take(&mut page_facts),
            false,
        )));
        let single = MeshMessage::Fact(last);
        if encoded_len(&single) <= EXACT_RECEIVE_FRAME_BYTES {
            emitted.push(single);
        }
    }
    if !page_facts.is_empty() {
        let context = page_facts[0].content.mesh_context;
        emitted.push(MeshMessage::FactPage(fact_page(context, page_facts, true)));
    }
    emitted
}

#[test]
fn multi_page_inventory_converges_with_loss_reorder_duplicates_and_quiescence() {
    let context = MeshContextId::from_bytes([0x61; 32]);
    let source_values = ids(2_000);
    let source: BTreeSet<_> = source_values.iter().copied().collect();
    let pages = exact_pages(context, &source_values);
    assert!(pages.len() >= 2, "control must exercise multiple pages");
    assert!(pages.iter().all(|page| {
        serde_json::to_vec(&MeshMessage::FactInventory(page.clone()))
            .unwrap()
            .len()
            <= EXACT_RECEIVE_FRAME_BYTES
    }));

    let expected_route = ExactRoute {
        context,
        generation: 7,
    };
    let mut target = BTreeSet::new();
    let mut sends = 0;

    // Page 1 is duplicated, the order is reversed, and one page is lost.
    // Each accepted page produces one finite request/response equivalent;
    // duplicate identifiers are not re-admitted.
    let dropped = pages.len() / 2;
    for index in (0..pages.len()).rev() {
        if index == dropped {
            continue;
        }
        let before = target.len();
        let added = apply_inventory_page(
            &mut target,
            &source,
            &pages[index],
            expected_route,
            expected_route,
        );
        sends += usize::from(added > 0);
        assert!(target.len() >= before);
        if index == pages.len() - 1 {
            let duplicate = apply_inventory_page(
                &mut target,
                &source,
                &pages[index],
                expected_route,
                expected_route,
            );
            assert_eq!(duplicate, 0, "duplicate page must be quiescent");
        }
    }
    assert!(target.len() < source.len(), "the dropped page created debt");

    // The next inventory pass is the ticker/lost-advertisement repair. It is
    // finite and reaches the exact source set without a reciprocal page echo.
    for page in &pages {
        sends += usize::from(
            apply_inventory_page(&mut target, &source, page, expected_route, expected_route) > 0,
        );
    }
    assert_eq!(target, source);
    assert!(sends <= pages.len() * 2, "page repair must remain finite");
    for page in &pages {
        assert_eq!(
            apply_inventory_page(&mut target, &source, page, expected_route, expected_route,),
            0,
            "identical inventories must quiesce"
        );
    }
}

#[test]
fn strict_subset_incomparable_foreign_context_and_stale_route_never_authorize() {
    let context = MeshContextId::from_bytes([0x71; 32]);
    let foreign_context = MeshContextId::from_bytes([0x72; 32]);
    let values = ids(16);
    let source: BTreeSet<_> = values.iter().copied().collect();
    let strict = FactInventory::new(context, values[..8].iter().copied());
    let incomparable = FactInventory::new(context, values[8..].iter().copied());
    let expected_route = ExactRoute {
        context,
        generation: 11,
    };
    let mut target: BTreeSet<_> = values[..8].iter().copied().collect();

    assert_eq!(
        apply_inventory_page(
            &mut target,
            &source,
            &strict,
            expected_route,
            expected_route,
        ),
        0,
        "a strict subset creates no reverse request"
    );
    assert_eq!(
        apply_inventory_page(
            &mut target,
            &source,
            &incomparable,
            expected_route,
            expected_route,
        ),
        8,
        "an incomparable page requests only its missing exact ids"
    );

    let before = target.clone();
    let foreign = FactInventory::new(foreign_context, values.iter().copied());
    assert_eq!(
        apply_inventory_page(
            &mut target,
            &source,
            &foreign,
            expected_route,
            expected_route,
        ),
        0
    );
    assert_eq!(target, before, "foreign context must not mutate the graph");

    let stale_route = ExactRoute {
        context,
        generation: expected_route.generation + 1,
    };
    let current_context_page = FactInventory::new(context, values);
    assert_eq!(
        apply_inventory_page(
            &mut target,
            &source,
            &current_context_page,
            stale_route,
            expected_route,
        ),
        0
    );
    assert_eq!(target, before, "stale route must not reach page admission");
}

#[test]
fn restart_re_advertisement_recovers_exact_source_without_unbounded_send_loop() {
    let context = MeshContextId::from_bytes([0x81; 32]);
    let values = ids(2_000);
    let source: BTreeSet<_> = values.iter().copied().collect();
    let pages = exact_pages(context, &values);
    let route = ExactRoute {
        context,
        generation: 19,
    };
    let mut restarted = BTreeSet::new();
    let mut sends = 0;
    for page in &pages {
        sends += usize::from(apply_inventory_page(&mut restarted, &source, page, route, route) > 0);
    }
    assert_eq!(restarted, source);
    assert!(sends <= pages.len());
    assert_eq!(
        pages
            .iter()
            .map(|page| { apply_inventory_page(&mut restarted, &source, page, route, route) })
            .sum::<usize>(),
        0,
        "a recovered owner must quiesce after exact re-advertisement"
    );
}

#[test]
fn single_fact_boundary_falls_back_and_continues_to_quiescence() {
    let context = MeshContextId::from_bytes([0x91; 32]);
    let large = find_page_only_overflow_fact(context);
    let tail_key = SigningKey::from_bytes(&[0x92; 32]);
    let tail_device =
        DeviceId::from_public_key_bytes(*tail_key.verifying_key().as_bytes()).unwrap();
    let tail_body = FactBody::RoleRevoke {
        target: tail_device.clone(),
    };
    let tail = SignedFact::sign(
        FactContent::new(
            tail_body.domain(),
            context,
            tail_body,
            tail_device,
            Vec::new(),
        ),
        &tail_key,
    )
    .unwrap();
    let single = MeshMessage::Fact(large.clone());
    let page = MeshMessage::FactPage(fact_page(context, vec![large.clone()], true));
    assert!(encoded_len(&single) <= EXACT_RECEIVE_FRAME_BYTES);
    assert!(encoded_len(&page) > EXACT_RECEIVE_FRAME_BYTES);

    // This is the production fallback decision: the exact owner-bound Fact
    // frame is admitted, then later requested IDs continue through a normal
    // frame-sized page instead of being abandoned with the oversized item.
    let emitted = vec![
        MeshMessage::Fact(large.clone()),
        MeshMessage::FactPage(fact_page(context, vec![tail.clone()], true)),
    ];
    assert_eq!(emitted.len(), 2);
    assert!(matches!(emitted[0], MeshMessage::Fact(_)));
    assert!(matches!(emitted[1], MeshMessage::FactPage(_)));
    assert!(emitted
        .iter()
        .all(|message| { encoded_len(message) <= EXACT_RECEIVE_FRAME_BYTES }));

    let mut admitted = BTreeSet::new();
    for message in &emitted {
        match message {
            MeshMessage::Fact(fact) => {
                admitted.insert(fact.id);
            }
            MeshMessage::FactPage(page) => {
                admitted.extend(page.facts.iter().map(|fact| fact.id));
            }
            _ => unreachable!("the fallback emits only Fact and FactPage frames"),
        }
    }
    assert!(admitted.contains(&large.id));
    assert!(admitted.contains(&tail.id));
    assert_eq!(admitted.len(), 2, "the continuation is finite and exact");
    assert!(emitted
        .iter()
        .filter_map(|message| match message {
            MeshMessage::Fact(fact) => Some(fact.id),
            MeshMessage::FactPage(page) => page.facts.first().map(|fact| fact.id),
            _ => None,
        })
        .all(|id| admitted.contains(&id)));
}

#[test]
fn individually_untransmittable_first_fact_does_not_starve_later_fact() {
    let context = MeshContextId::from_bytes([0xa1; 32]);
    let large = oversized_fact(context);
    let tail_key = SigningKey::from_bytes(&[0xa2; 32]);
    let tail_device =
        DeviceId::from_public_key_bytes(*tail_key.verifying_key().as_bytes()).unwrap();
    let tail_body = FactBody::RoleRevoke {
        target: tail_device.clone(),
    };
    let tail = SignedFact::sign(
        FactContent::new(
            tail_body.domain(),
            context,
            tail_body,
            tail_device,
            Vec::new(),
        ),
        &tail_key,
    )
    .unwrap();

    let emitted = emit_fact_request_pages(&[large.clone(), tail.clone()]);
    assert_eq!(emitted.len(), 1, "only the later normal fact is emitted");
    let MeshMessage::FactPage(page) = &emitted[0] else {
        panic!("the tail remains in a normal frame-sized page");
    };
    assert_eq!(page.facts.len(), 1);
    assert_eq!(page.facts[0].id, tail.id);
    assert!(!page.facts.iter().any(|fact| fact.id == large.id));
    assert!(encoded_len(&emitted[0]) <= EXACT_RECEIVE_FRAME_BYTES);
    assert!(
        emit_fact_request_pages(&[large]).is_empty(),
        "an all-skipped request is quiescent"
    );
}
