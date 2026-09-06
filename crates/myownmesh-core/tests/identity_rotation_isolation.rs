//! Public semantic controls for identity replacement isolation.
//!
//! These controls intentionally model no reset or rotation protocol.  They
//! establish only the cryptographic and canonical-authority boundaries that
//! remain true when an operator has a distinct signing identity.

use ed25519_dalek::SigningKey;

use myownmesh_core::identity::Identity;
use myownmesh_core::semantic::{
    Admission, DeviceId, FactBody, FactContent, FactDomain, FactGraph, FactId, Role, SemanticError,
    SignedFact, VerifiedBootstrap,
};

fn identity(seed: u8) -> Identity {
    Identity::from_signing_key(
        SigningKey::from_bytes(&[seed; 32]),
        format!("identity-{seed}"),
    )
}

fn device(identity: &Identity) -> DeviceId {
    DeviceId::from_public_key_bytes(*identity.verifying_key().as_bytes())
        .expect("identity key is a valid DeviceId")
}

#[test]
fn a_new_key_cannot_reauthor_or_replace_retained_history() {
    let old = identity(0x31);
    let new = identity(0x32);
    assert_ne!(old.public_id(), new.public_id());

    let bootstrap = VerifiedBootstrap::create_closed(
        "identity-rotation-isolation",
        [old.signing_key()],
        [0x71; 32],
    )
    .expect("closed bootstrap verifies");
    let old_device = device(&old);
    let new_device = device(&new);
    let target = device(&identity(0x33));
    let old_content = FactContent::new(
        FactDomain::Governance,
        bootstrap.context_id(),
        FactBody::RoleGrant {
            target: new_device.clone(),
            role: Role::Controller,
        },
        old_device.clone(),
        Vec::new(),
    );
    let old_fact = SignedFact::sign(old_content.clone(), old.signing_key())
        .expect("the old identity authors its historical fact");
    old_fact
        .verify()
        .expect("retained old history still verifies");
    let mut history = FactGraph::from_bootstrap(&bootstrap);
    history
        .admit(old_fact.clone())
        .expect("old history remains admitted under its original authority");
    assert!(history.get(&old_fact.id).is_some());

    let claimed_old = SignedFact::sign(old_content, new.signing_key());
    assert_eq!(claimed_old, Err(SemanticError::AuthorMismatch));

    let new_content = FactContent::new(
        FactDomain::Governance,
        bootstrap.context_id(),
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        new_device,
        Vec::new(),
    );
    let new_fact = SignedFact::sign(new_content, new.signing_key())
        .expect("the new identity signs only as its own DeviceId");
    new_fact
        .verify()
        .expect("new identity fact verifies as new");

    let old_claimed_content = FactContent::new(
        FactDomain::Governance,
        new_fact.content.mesh_context,
        FactBody::RoleGrant {
            target,
            role: Role::Member,
        },
        old_device,
        new_fact.content.parents.clone(),
    );
    let replacement = SignedFact {
        id: FactId::from_content(&old_claimed_content),
        content: old_claimed_content,
        signature: new_fact.signature.clone(),
    };
    assert_eq!(
        replacement.verify(),
        Err(SemanticError::InvalidSignature),
        "a new-key signature cannot be presented as old-key history"
    );
}

#[test]
fn new_identity_authors_only_after_canonical_authority_grant() {
    let old = identity(0x41);
    let new = identity(0x42);
    let target = identity(0x43);
    let bootstrap = VerifiedBootstrap::create_closed(
        "identity-rotation-authority",
        [old.signing_key()],
        [0x72; 32],
    )
    .expect("closed bootstrap verifies");
    let old_device = device(&old);
    let new_device = device(&new);
    let target_device = device(&target);
    let grant = SignedFact::sign(
        FactContent::new(
            FactDomain::Governance,
            bootstrap.context_id(),
            FactBody::RoleGrant {
                target: new_device.clone(),
                role: Role::Controller,
            },
            old_device,
            Vec::new(),
        ),
        old.signing_key(),
    )
    .expect("old identity grants the new controller role");

    let body = FactBody::RoleGrant {
        target: target_device,
        role: Role::Member,
    };
    let mut ungranted_graph = FactGraph::from_bootstrap(&bootstrap);
    let ungranted_witness = ungranted_graph.authoring_witness(&body, &new_device);
    let ungranted = SignedFact::sign(
        FactContent::from_authoring_witness(
            &ungranted_graph,
            body.clone(),
            &ungranted_witness,
            std::iter::empty(),
        ),
        new.signing_key(),
    )
    .expect("an ungranted key can still produce a signed candidate");
    assert!(
        !matches!(ungranted_graph.admit(ungranted), Ok(Admission::Inserted)),
        "a new identity is not admitted before the canonical grant"
    );

    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    graph
        .admit(grant)
        .expect("the canonical old-authority grant admits");

    let witness = graph.authoring_witness(&body, &new_device);
    let new_fact = SignedFact::sign(
        FactContent::from_authoring_witness(&graph, body, &witness, std::iter::empty()),
        new.signing_key(),
    )
    .expect("new identity authors through the canonical witness");
    assert_eq!(
        graph.admit(new_fact),
        Ok(Admission::Inserted),
        "new content is admitted only through the existing authority projection"
    );
}
