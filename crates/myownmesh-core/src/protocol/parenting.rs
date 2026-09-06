//! Direct, shallow hub-tree relation messages.
//!
//! These messages request or report one relation on an already-authenticated
//! session.  The engine owns the configured root, level/depth rules, relation
//! slot reservation, and exact owner generation checks; nothing here grants
//! authority or carries an address, ancestry list, or transferable offer.

use serde::{de::Deserializer, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::hub::HubTrickleProfile;
use crate::semantic::{DeviceId, MeshContextId};

/// Explicit protocol page bound for the fixed-size attach request/response
/// shapes. The largest compact encoding is the accepted response at 486
/// bytes (52-byte canonical IDs/context, a 129-byte `[255; 32]` JSON array,
/// and two maximal `u64` values); 512 leaves only fixed-shape headroom and is
/// independent of the smaller resource policy bound.
pub const HUB_TREE_ATTACH_MAX_WIRE_BYTES: usize = 512;

/// Domain separation from the legacy Hubs advertisement digest and every
/// semantic graph commitment.
pub const HUB_TREE_CONFIGURATION_DIGEST_DOMAIN: &[u8] = b"myownmesh-hub-tree-configuration-v1\0";

/// The only tree shape represented by this protocol seam: root -> hub -> leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubTreeTopologyKind {
    ShallowV1,
}

impl HubTreeTopologyKind {
    fn wire_tag(self) -> u8 {
        match self {
            Self::ShallowV1 => 1,
        }
    }
}

/// Fixed primary depth for [`HubTreeTopologyKind::ShallowV1`].
pub const HUB_TREE_PRIMARY_DEPTH: u8 = 2;

fn normalized_ids(ids: &[DeviceId]) -> Vec<DeviceId> {
    let mut normalized = ids.to_vec();
    normalized.sort();
    normalized.dedup();
    normalized
}

/// Compute the exact configuration identity for one shallow HubTree.
///
/// This is deliberately a different domain from [`super::hub::configuration_digest`].
/// It binds the context envelope, topology kind/depth, canonical root,
/// normalized configured hub set, the configured per-leaf backup-candidate
/// count, and the full local Trickle scalar profile. Backup identities are not
/// included: candidate ranking is leaf-relative, so selected backup identities
/// differ between peers and cannot be a shared configuration identity. The
/// result is a comparison key only: it is not a semantic commitment and cannot
/// be applied as remote configuration.
pub fn hub_tree_configuration_digest(
    context_id: MeshContextId,
    topology: HubTreeTopologyKind,
    root: &DeviceId,
    hubs: &[DeviceId],
    configured_backup_count: u32,
    trickle: HubTrickleProfile,
) -> [u8; 32] {
    let hubs = normalized_ids(hubs);
    let mut hasher = Sha256::new();
    hasher.update(HUB_TREE_CONFIGURATION_DIGEST_DOMAIN);
    hasher.update([1u8, topology.wire_tag(), HUB_TREE_PRIMARY_DEPTH]);
    hasher.update(context_id.as_bytes());
    hasher.update(root.as_bytes());
    hasher.update((hubs.len() as u64).to_le_bytes());
    for hub in hubs {
        hasher.update(hub.as_bytes());
    }
    hasher.update(configured_backup_count.to_le_bytes());
    hasher.update(trickle.imin_ms.to_le_bytes());
    hasher.update(trickle.imax_ms.to_le_bytes());
    hasher.update(trickle.k.to_le_bytes());
    hasher.update(trickle.reset_window_ms.to_le_bytes());
    hasher.update(trickle.max_resets_per_window.to_le_bytes());
    hasher.finalize().into()
}

fn deserialize_nonzero_sequence<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if value == 0 {
        return Err(serde::de::Error::custom(
            "hub-tree request sequence must be nonzero",
        ));
    }
    Ok(value)
}

/// Bounded, typed reasons why a requested parent relation was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HubTreeAttachRejection {
    InvalidContext,
    InvalidConfiguration,
    ParentUnavailable,
    RelationCapacity,
    UnsupportedDepth,
    StaleRequest,
    OwnerMismatch,
    AlreadyAttached,
}

/// Request one primary parent relation for one child in the configured
/// shallow hub tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HubTreeAttachRequest {
    context_id: MeshContextId,
    configuration_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_nonzero_sequence")]
    request_sequence: u64,
    child: DeviceId,
    parent: DeviceId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HubTreeAttachRequestWire {
    context_id: MeshContextId,
    configuration_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_nonzero_sequence")]
    request_sequence: u64,
    child: DeviceId,
    parent: DeviceId,
}

impl<'de> Deserialize<'de> for HubTreeAttachRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = HubTreeAttachRequestWire::deserialize(deserializer)?;
        Self::new(
            wire.context_id,
            wire.configuration_digest,
            wire.request_sequence,
            wire.child,
            wire.parent,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl HubTreeAttachRequest {
    pub fn new(
        context_id: MeshContextId,
        configuration_digest: [u8; 32],
        request_sequence: u64,
        child: DeviceId,
        parent: DeviceId,
    ) -> Result<Self, &'static str> {
        if request_sequence == 0 {
            return Err("hub-tree request sequence must be nonzero");
        }
        if child == parent {
            return Err("hub-tree child and parent must be distinct");
        }
        Ok(Self {
            context_id,
            configuration_digest,
            request_sequence,
            child,
            parent,
        })
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn configuration_digest(&self) -> [u8; 32] {
        self.configuration_digest
    }

    pub fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    pub fn child(&self) -> &DeviceId {
        &self.child
    }

    pub fn parent(&self) -> &DeviceId {
        &self.parent
    }
}

/// Response to one exact [`HubTreeAttachRequest`]. An accepted response
/// carries a nonzero relation generation; a refusal carries only a bounded
/// typed reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum HubTreeAttachResponse {
    Accepted {
        context_id: MeshContextId,
        configuration_digest: [u8; 32],
        #[serde(deserialize_with = "deserialize_nonzero_sequence")]
        request_sequence: u64,
        child: DeviceId,
        parent: DeviceId,
        #[serde(deserialize_with = "deserialize_nonzero_sequence")]
        relation_generation: u64,
    },
    Rejected {
        context_id: MeshContextId,
        configuration_digest: [u8; 32],
        #[serde(deserialize_with = "deserialize_nonzero_sequence")]
        request_sequence: u64,
        child: DeviceId,
        parent: DeviceId,
        reason: HubTreeAttachRejection,
    },
}

impl HubTreeAttachResponse {
    pub fn accepted(
        request: &HubTreeAttachRequest,
        relation_generation: u64,
    ) -> Result<Self, &'static str> {
        if relation_generation == 0 {
            return Err("hub-tree relation generation must be nonzero");
        }
        Ok(Self::Accepted {
            context_id: request.context_id,
            configuration_digest: request.configuration_digest,
            request_sequence: request.request_sequence,
            child: request.child.clone(),
            parent: request.parent.clone(),
            relation_generation,
        })
    }

    pub fn rejected(request: &HubTreeAttachRequest, reason: HubTreeAttachRejection) -> Self {
        Self::Rejected {
            context_id: request.context_id,
            configuration_digest: request.configuration_digest,
            request_sequence: request.request_sequence,
            child: request.child.clone(),
            parent: request.parent.clone(),
            reason,
        }
    }

    pub fn context_id(&self) -> MeshContextId {
        match self {
            Self::Accepted { context_id, .. } | Self::Rejected { context_id, .. } => *context_id,
        }
    }

    pub fn configuration_digest(&self) -> [u8; 32] {
        match self {
            Self::Accepted {
                configuration_digest,
                ..
            }
            | Self::Rejected {
                configuration_digest,
                ..
            } => *configuration_digest,
        }
    }

    pub fn request_sequence(&self) -> u64 {
        match self {
            Self::Accepted {
                request_sequence, ..
            }
            | Self::Rejected {
                request_sequence, ..
            } => *request_sequence,
        }
    }

    pub fn child(&self) -> &DeviceId {
        match self {
            Self::Accepted { child, .. } | Self::Rejected { child, .. } => child,
        }
    }

    pub fn parent(&self) -> &DeviceId {
        match self {
            Self::Accepted { parent, .. } | Self::Rejected { parent, .. } => parent,
        }
    }

    pub fn relation_generation(&self) -> Option<u64> {
        match self {
            Self::Accepted {
                relation_generation,
                ..
            } => Some(*relation_generation),
            Self::Rejected { .. } => None,
        }
    }

    pub fn rejection(&self) -> Option<HubTreeAttachRejection> {
        match self {
            Self::Accepted { .. } => None,
            Self::Rejected { reason, .. } => Some(*reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{classify_frame, FailurePolicy, FrameAdmission, MeshMessage};

    fn device(seed: u8) -> DeviceId {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("valid device")
    }

    #[test]
    fn tree_digest_binds_context_root_hubs_backup_count_profile_and_domain() {
        let context = MeshContextId::from_bytes([18; 32]);
        let root = device(19);
        let first_hub = device(20);
        let second_hub = device(21);
        let trickle = HubTrickleProfile::new(100, 10_000, 3, 60_000, 4);
        let base = hub_tree_configuration_digest(
            context,
            HubTreeTopologyKind::ShallowV1,
            &root,
            &[second_hub.clone(), first_hub.clone(), second_hub.clone()],
            2,
            trickle,
        );
        assert_eq!(
            base,
            hub_tree_configuration_digest(
                context,
                HubTreeTopologyKind::ShallowV1,
                &root,
                &[first_hub.clone(), second_hub.clone()],
                2,
                trickle,
            )
        );
        assert_ne!(
            base,
            hub_tree_configuration_digest(
                context,
                HubTreeTopologyKind::ShallowV1,
                &device(23),
                &[first_hub.clone(), second_hub.clone()],
                2,
                trickle,
            )
        );
        assert_ne!(
            base,
            hub_tree_configuration_digest(
                context,
                HubTreeTopologyKind::ShallowV1,
                &root,
                &[first_hub.clone(), second_hub.clone()],
                3,
                trickle,
            )
        );
        assert_ne!(
            base,
            hub_tree_configuration_digest(
                MeshContextId::from_bytes([24; 32]),
                HubTreeTopologyKind::ShallowV1,
                &root,
                &[first_hub.clone(), second_hub.clone()],
                2,
                trickle,
            )
        );
        assert_ne!(
            base,
            hub_tree_configuration_digest(
                context,
                HubTreeTopologyKind::ShallowV1,
                &root,
                &[first_hub.clone(), second_hub.clone()],
                2,
                HubTrickleProfile::new(101, 10_000, 3, 60_000, 4),
            )
        );
        assert_ne!(
            base,
            super::super::hub::configuration_digest(&[first_hub, second_hub], 2, trickle,)
        );
    }

    #[test]
    fn attach_request_has_stable_shape_and_typed_response_round_trip() {
        let context = MeshContextId::from_bytes([21; 32]);
        let child = device(22);
        let parent = device(23);
        let request = HubTreeAttachRequest::new(context, [24; 32], 5, child, parent)
            .expect("distinct typed relation");
        let encoded = serde_json::to_string(&MeshMessage::HubTreeAttachRequest(request.clone()))
            .expect("request serializes");
        assert!(encoded.len() <= HUB_TREE_ATTACH_MAX_WIRE_BYTES);
        let digest = serde_json::to_string(&vec![24u8; 32]).expect("digest serializes");
        let expected = format!(
            r#"{{"kind":"hub_tree_attach_request","context_id":"{}","configuration_digest":{digest},"request_sequence":5,"child":"{}","parent":"{}"}}"#,
            context.base32(),
            request.child().base32(),
            request.parent().base32(),
        );
        assert_eq!(encoded, expected);
        let decoded: MeshMessage = serde_json::from_str(&encoded).expect("request decodes");
        let MeshMessage::HubTreeAttachRequest(decoded) = decoded else {
            panic!("request changed wire variant");
        };
        assert_eq!(decoded, request);

        let accepted = HubTreeAttachResponse::accepted(&request, 9).expect("accepted generation");
        let accepted_wire =
            serde_json::to_vec(&MeshMessage::HubTreeAttachResponse(accepted.clone()))
                .expect("accepted response serializes");
        assert!(accepted_wire.len() <= HUB_TREE_ATTACH_MAX_WIRE_BYTES);
        let decoded: MeshMessage =
            serde_json::from_slice(&accepted_wire).expect("response decodes");
        let MeshMessage::HubTreeAttachResponse(decoded) = decoded else {
            panic!("response changed wire variant");
        };
        assert_eq!(decoded, accepted);
        assert_eq!(decoded.relation_generation(), Some(9));

        let worst_request = HubTreeAttachRequest::new(
            context,
            [255; 32],
            u64::MAX,
            request.child().clone(),
            request.parent().clone(),
        )
        .expect("maximal values preserve relation invariants");
        let worst_request_wire =
            serde_json::to_vec(&MeshMessage::HubTreeAttachRequest(worst_request.clone()))
                .expect("maximal request serializes");
        assert_eq!(worst_request_wire.len(), 422);
        assert!(worst_request_wire.len() <= HUB_TREE_ATTACH_MAX_WIRE_BYTES);

        let worst_accepted = HubTreeAttachResponse::accepted(&worst_request, u64::MAX)
            .expect("maximal generation remains nonzero");
        let worst_accepted_wire =
            serde_json::to_vec(&MeshMessage::HubTreeAttachResponse(worst_accepted))
                .expect("maximal response serializes");
        assert_eq!(worst_accepted_wire.len(), 486);
        assert_eq!(
            worst_accepted_wire.len() + 26,
            HUB_TREE_ATTACH_MAX_WIRE_BYTES
        );
        let worst_rejected = HubTreeAttachResponse::rejected(
            &worst_request,
            HubTreeAttachRejection::InvalidConfiguration,
        );
        let worst_rejected_wire =
            serde_json::to_vec(&MeshMessage::HubTreeAttachResponse(worst_rejected))
                .expect("longest typed refusal serializes");
        assert_eq!(worst_rejected_wire.len(), 476);
        assert!(worst_rejected_wire.len() <= HUB_TREE_ATTACH_MAX_WIRE_BYTES);
        assert!(HUB_TREE_ATTACH_MAX_WIRE_BYTES < crate::protocol::RECEIVE_FRAME_BYTES);
    }

    #[test]
    fn attach_rejects_zero_or_self_relation_and_preserves_typed_refusal() {
        let context = MeshContextId::from_bytes([25; 32]);
        let child = device(26);
        assert!(
            HubTreeAttachRequest::new(context, [27; 32], 0, child.clone(), device(28)).is_err()
        );
        assert!(
            HubTreeAttachRequest::new(context, [27; 32], 1, child.clone(), child.clone()).is_err()
        );

        let request = HubTreeAttachRequest::new(context, [27; 32], 1, child, device(28))
            .expect("valid relation");
        assert!(HubTreeAttachResponse::accepted(&request, 0).is_err());
        let rejected =
            HubTreeAttachResponse::rejected(&request, HubTreeAttachRejection::RelationCapacity);
        assert_eq!(rejected.relation_generation(), None);
        assert_eq!(
            rejected.rejection(),
            Some(HubTreeAttachRejection::RelationCapacity)
        );

        let mut unknown =
            serde_json::to_value(MeshMessage::HubTreeAttachResponse(rejected)).unwrap();
        unknown["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MeshMessage>(unknown).is_err());
    }

    #[test]
    fn attach_frames_are_application_not_privileged_control() {
        for kind in ["hub_tree_attach_request", "hub_tree_attach_response"] {
            assert_eq!(
                classify_frame(format!(r#"{{"kind":"{kind}","payload":[}}"#).as_bytes()),
                Some(crate::protocol::ClassifiedFrame {
                    admission: FrameAdmission::Application,
                    on_failure: FailurePolicy::EndSession,
                })
            );
        }
    }
}
