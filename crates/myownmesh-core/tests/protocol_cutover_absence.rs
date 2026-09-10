//! Protocol-v2 hard-cutover controls for retired roster/network wire tags.

use myownmesh_core::protocol::{FactInventory, FactPageMessage, FactRequest, MeshMessage};
use myownmesh_core::semantic::{FactId, MeshContextId};

#[test]
fn retired_lowercase_tags_fail_closed_at_mesh_message_decode() {
    for tag in [
        "network_state",
        "roster_summary",
        "roster_request",
        "roster_entries",
    ] {
        let wire = format!(r#"{{"kind":"{tag}"}}"#);
        assert!(
            serde_json::from_str::<MeshMessage>(&wire).is_err(),
            "retired wire tag {tag} must be refused by the closed MeshMessage enum"
        );
    }
}

#[test]
fn current_fact_coordination_tags_round_trip_at_mesh_message_decode() {
    let context = MeshContextId::from_bytes([0x37; 32]);
    let first = FactId::from_bytes([0x01; 32]);
    let second = FactId::from_bytes([0x02; 32]);
    let messages = [
        MeshMessage::FactInventory(FactInventory::new(context, [second, first])),
        MeshMessage::FactRequest(FactRequest::new(context, [second, first])),
        MeshMessage::FactPage(FactPageMessage {
            context_id: context,
            facts: Vec::new(),
            next_cursor: None,
            complete: true,
        }),
    ];

    for message in messages {
        let wire = serde_json::to_vec(&message).expect("current fact message serializes");
        let decoded =
            serde_json::from_slice::<MeshMessage>(&wire).expect("current fact message decodes");
        match (&message, decoded) {
            (MeshMessage::FactInventory(expected), MeshMessage::FactInventory(actual)) => {
                assert_eq!(&actual, expected);
            }
            (MeshMessage::FactRequest(expected), MeshMessage::FactRequest(actual)) => {
                assert_eq!(&actual, expected);
            }
            (MeshMessage::FactPage(expected), MeshMessage::FactPage(actual)) => {
                assert_eq!(&actual, expected);
            }
            _ => panic!("current fact message changed wire variant"),
        }
    }
}
