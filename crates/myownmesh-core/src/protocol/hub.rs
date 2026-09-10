//! Session-local, advisory topology information.
//!
//! A hub advertisement is a hint for one already-authenticated session.  It
//! is not a signed peer record, a routing instruction, or a remotely applied
//! configuration.  The carrier session supplies authenticity; the origin is
//! only a canonical identity used by the receiving engine's exact-owner and
//! replay checks.

use std::cmp::Ordering;

use serde::{de::Deserializer, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::semantic::{DeviceId, MeshContextId};

/// Domain separation for the normalized local hub configuration commitment.
pub const HUB_CONFIGURATION_DIGEST_DOMAIN: &[u8] =
    b"myownmesh-hub-advertisement-configuration-v1\0";

/// The scalar Trickle profile committed by a hub advertisement's local
/// configuration. This is digest input only, not remotely applied policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubTrickleProfile {
    pub imin_ms: u64,
    pub imax_ms: u64,
    pub k: u64,
    pub reset_window_ms: u64,
    pub max_resets_per_window: u64,
}

/// Fixed wire-page ceiling for one unicast discovery response.  This is a
/// protocol page limit, independent of the caller's smaller policy limit, so
/// hostile JSON cannot cause an unbounded vector reservation.  A canonical
/// DeviceId is 52 ASCII characters on the wire; 64 entries leave room for
/// the response envelope, cursors, separators, and future framing beneath the
/// existing receive-frame ceiling.
pub const HUB_DISCOVERY_HARD_MAX_PEERS: usize = 64;

impl HubTrickleProfile {
    pub const fn new(
        imin_ms: u64,
        imax_ms: u64,
        k: u64,
        reset_window_ms: u64,
        max_resets_per_window: u64,
    ) -> Self {
        Self {
            imin_ms,
            imax_ms,
            k,
            reset_window_ms,
            max_resets_per_window,
        }
    }
}

/// A bounded advisory topology advertisement for one authenticated session.
///
/// The fields are private so programmatic callers must pass the same checked
/// sequence boundary as wire callers.  This message does not carry a
/// signature: endpoint authentication supplies the carrier authenticity, and
/// the receiving engine must still verify context, current owner, configured
/// hub membership, and the exact replay cursor before using it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubAdvertisement {
    context_id: MeshContextId,
    origin: DeviceId,
    #[serde(deserialize_with = "deserialize_nonzero_sequence")]
    sequence: u64,
    configuration_digest: [u8; 32],
}

fn deserialize_nonzero_sequence<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let sequence = u64::deserialize(deserializer)?;
    if sequence == 0 {
        return Err(serde::de::Error::custom(
            "hub advertisement sequence must be nonzero",
        ));
    }
    Ok(sequence)
}

impl HubAdvertisement {
    /// Construct an advertisement after checking its replay sequence.
    pub fn new(
        context_id: MeshContextId,
        origin: DeviceId,
        sequence: u64,
        configuration_digest: [u8; 32],
    ) -> Result<Self, &'static str> {
        if sequence == 0 {
            return Err("hub advertisement sequence must be nonzero");
        }
        Ok(Self {
            context_id,
            origin,
            sequence,
            configuration_digest,
        })
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn origin(&self) -> &DeviceId {
        &self.origin
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn configuration_digest(&self) -> [u8; 32] {
        self.configuration_digest
    }
}

/// A bounded unicast request for a page of peer identities known by one
/// configured hub. It carries no addresses, authority, or forwarding intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubDiscoveryRequest {
    context_id: MeshContextId,
    #[serde(deserialize_with = "deserialize_nonzero_sequence")]
    request_sequence: u64,
    after: Option<DeviceId>,
    #[serde(deserialize_with = "deserialize_nonzero_max_peers")]
    max_peers: u16,
}

fn deserialize_nonzero_max_peers<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let max_peers = u16::deserialize(deserializer)?;
    if max_peers == 0 || usize::from(max_peers) > HUB_DISCOVERY_HARD_MAX_PEERS {
        return Err(serde::de::Error::custom(
            "hub discovery max_peers is outside the protocol bound",
        ));
    }
    Ok(max_peers)
}

impl HubDiscoveryRequest {
    pub fn new(
        context_id: MeshContextId,
        request_sequence: u64,
        after: Option<DeviceId>,
        max_peers: u16,
    ) -> Result<Self, &'static str> {
        if request_sequence == 0 {
            return Err("hub discovery request sequence must be nonzero");
        }
        if max_peers == 0 || usize::from(max_peers) > HUB_DISCOVERY_HARD_MAX_PEERS {
            return Err("hub discovery max_peers is outside the protocol bound");
        }
        Ok(Self {
            context_id,
            request_sequence,
            after,
            max_peers,
        })
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    pub fn after(&self) -> Option<&DeviceId> {
        self.after.as_ref()
    }

    pub fn max_peers(&self) -> u16 {
        self.max_peers
    }
}

/// A bounded unicast response containing only canonical peer identities.
///
/// The vector deserializer reads at most one item beyond the hard page limit
/// and never trusts a remote sequence size hint for allocation.  The engine
/// must still discard this response unless its exact authenticated hub owner,
/// context, and outstanding request sequence match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HubDiscoveryResponse {
    context_id: MeshContextId,
    request_sequence: u64,
    peers: Vec<DeviceId>,
    /// The last included peer when another page may follow. `None` means the
    /// page is terminal, or that an empty page wraps on the next scheduled
    /// round rather than triggering an immediate query.
    next_after: Option<DeviceId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HubDiscoveryResponseWire {
    context_id: MeshContextId,
    #[serde(deserialize_with = "deserialize_nonzero_sequence")]
    request_sequence: u64,
    #[serde(deserialize_with = "deserialize_bounded_peer_list")]
    peers: Vec<DeviceId>,
    next_after: Option<DeviceId>,
}

struct BoundedPeerListVisitor;

impl<'de> serde::de::Visitor<'de> for BoundedPeerListVisitor {
    type Value = Vec<DeviceId>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a sorted unique bounded list of canonical DeviceIds")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut peers = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or(0)
                .min(HUB_DISCOVERY_HARD_MAX_PEERS),
        );
        while let Some(peer) = sequence.next_element::<DeviceId>()? {
            if peers.len() == HUB_DISCOVERY_HARD_MAX_PEERS {
                return Err(serde::de::Error::custom(
                    "hub discovery peer page exceeds the protocol bound",
                ));
            }
            if let Some(previous) = peers.last() {
                if peer.cmp(previous) != Ordering::Greater {
                    return Err(serde::de::Error::custom(
                        "hub discovery peers must be strictly sorted and unique",
                    ));
                }
            }
            peers.push(peer);
        }
        Ok(peers)
    }
}

fn deserialize_bounded_peer_list<'de, D>(deserializer: D) -> Result<Vec<DeviceId>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedPeerListVisitor)
}

impl<'de> Deserialize<'de> for HubDiscoveryResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = HubDiscoveryResponseWire::deserialize(deserializer)?;
        Self::new(
            wire.context_id,
            wire.request_sequence,
            None,
            wire.peers,
            wire.next_after,
            HUB_DISCOVERY_HARD_MAX_PEERS as u16,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl HubDiscoveryResponse {
    /// Build a response for a request, enforcing the request's page and
    /// cursor bounds before the response can be serialized.
    pub fn for_request(
        request: &HubDiscoveryRequest,
        peers: Vec<DeviceId>,
        next_after: Option<DeviceId>,
    ) -> Result<Self, &'static str> {
        Self::new(
            request.context_id,
            request.request_sequence,
            request.after.as_ref(),
            peers,
            next_after,
            request.max_peers,
        )
    }

    /// Construct a response with an explicit request cursor and page limit.
    pub fn new(
        context_id: MeshContextId,
        request_sequence: u64,
        after: Option<&DeviceId>,
        peers: Vec<DeviceId>,
        next_after: Option<DeviceId>,
        requested_max_peers: u16,
    ) -> Result<Self, &'static str> {
        if request_sequence == 0 {
            return Err("hub discovery request sequence must be nonzero");
        }
        if requested_max_peers == 0
            || usize::from(requested_max_peers) > HUB_DISCOVERY_HARD_MAX_PEERS
            || peers.len() > usize::from(requested_max_peers)
        {
            return Err("hub discovery response exceeds the requested page bound");
        }
        for pair in peers.windows(2) {
            if pair[0].cmp(&pair[1]) != Ordering::Less {
                return Err("hub discovery peers must be strictly sorted and unique");
            }
        }
        if let (Some(after), Some(first)) = (after, peers.first()) {
            if first.cmp(after) != Ordering::Greater {
                return Err("hub discovery response does not advance its cursor");
            }
        }
        if let Some(next) = next_after.as_ref() {
            let Some(last) = peers.last() else {
                return Err("an empty hub discovery page must wrap with next_after=None");
            };
            if next != last {
                return Err("hub discovery next_after must equal the last included peer");
            }
        }
        Ok(Self {
            context_id,
            request_sequence,
            peers,
            next_after,
        })
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    pub fn peers(&self) -> &[DeviceId] {
        &self.peers
    }

    pub fn next_after(&self) -> Option<&DeviceId> {
        self.next_after.as_ref()
    }
}

/// Compute the configuration digest carried by [`HubAdvertisement`].
///
/// Hub IDs are normalized by canonical `DeviceId` ordering and duplicate
/// identities are removed.  `spoke_redundancy` is the `R` term in the local
/// hub configuration.  The five fixed-width little-endian fields in
/// [`HubTrickleProfile`] bind the exact local Trickle schedule as well.
/// Length/count framing prevents concatenation ambiguity; no semantic graph
/// commitment or remote configuration is included.
pub fn configuration_digest(
    hubs: &[DeviceId],
    spoke_redundancy: u32,
    trickle: HubTrickleProfile,
) -> [u8; 32] {
    let mut normalized = hubs.to_vec();
    normalized.sort();
    normalized.dedup();

    let mut hasher = Sha256::new();
    hasher.update(HUB_CONFIGURATION_DIGEST_DOMAIN);
    hasher.update([1u8]);
    hasher.update((normalized.len() as u64).to_le_bytes());
    for hub in normalized {
        hasher.update(hub.as_bytes());
    }
    hasher.update(spoke_redundancy.to_le_bytes());
    hasher.update(trickle.imin_ms.to_le_bytes());
    hasher.update(trickle.imax_ms.to_le_bytes());
    hasher.update(trickle.k.to_le_bytes());
    hasher.update(trickle.reset_window_ms.to_le_bytes());
    hasher.update(trickle.max_resets_per_window.to_le_bytes());
    hasher.finalize().into()
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
    fn digest_is_canonical_over_sorted_unique_hubs_and_redundancy() {
        let first = device(1);
        let second = device(2);
        let trickle = HubTrickleProfile::new(100, 10_000, 3, 60_000, 4);
        assert_eq!(
            configuration_digest(&[second.clone(), first.clone(), second.clone()], 2, trickle,),
            configuration_digest(&[first.clone(), second.clone()], 2, trickle)
        );
        assert_ne!(
            configuration_digest(&[second.clone()], 1, trickle),
            configuration_digest(&[second.clone()], 2, trickle)
        );
        assert_ne!(
            configuration_digest(&[second.clone()], 1, trickle),
            configuration_digest(
                &[second.clone()],
                1,
                HubTrickleProfile::new(101, 10_000, 3, 60_000, 4)
            )
        );
    }

    #[test]
    fn advertisement_has_stable_strict_wire_shape_and_round_trips() {
        let context = MeshContextId::from_bytes([3; 32]);
        let origin = device(4);
        let advertisement =
            HubAdvertisement::new(context, origin.clone(), 7, [9; 32]).expect("nonzero sequence");
        let encoded = serde_json::to_string(&MeshMessage::HubAdvertisement(advertisement.clone()))
            .expect("advertisement serializes");
        let digest = serde_json::to_string(&vec![9u8; 32]).expect("digest serializes");
        let expected = format!(
            r#"{{"kind":"hub_advertisement","context_id":"{}","origin":"{}","sequence":7,"configuration_digest":{digest}}}"#,
            context.base32(),
            origin.base32(),
        );
        assert_eq!(encoded, expected);

        let decoded: MeshMessage = serde_json::from_str(&encoded).expect("decodes");
        let MeshMessage::HubAdvertisement(decoded) = decoded else {
            panic!("decoded message changed wire variant");
        };
        assert_eq!(decoded, advertisement);
    }

    #[test]
    fn advertisement_rejects_zero_sequence_noncanonical_identity_and_unknown_fields() {
        let context = MeshContextId::from_bytes([6; 32]).base32();
        let origin = device(5).base32();
        let zero = serde_json::json!({
            "context_id": context.clone(),
            "origin": origin.clone(),
            "sequence": 0,
            "configuration_digest": vec![0u8; 32],
        });
        assert!(serde_json::from_value::<HubAdvertisement>(zero).is_err());

        let noncanonical_context = serde_json::json!({
            "context_id": context.to_uppercase(),
            "origin": device(5).base32(),
            "sequence": 1,
            "configuration_digest": vec![0u8; 32],
        });
        assert!(serde_json::from_value::<HubAdvertisement>(noncanonical_context).is_err());

        let noncanonical_origin = serde_json::json!({
            "context_id": context,
            "origin": device(5).base32().to_uppercase(),
            "sequence": 1,
            "configuration_digest": vec![0u8; 32],
        });
        assert!(serde_json::from_value::<HubAdvertisement>(noncanonical_origin).is_err());

        let mut unknown = serde_json::to_value(
            HubAdvertisement::new(MeshContextId::from_bytes([6; 32]), device(5), 1, [0; 32])
                .unwrap(),
        )
        .unwrap();
        unknown["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HubAdvertisement>(unknown).is_err());
    }

    #[test]
    fn advertisement_is_application_not_control_or_durable_fact() {
        assert_eq!(
            classify_frame(br#"{"kind":"hub_advertisement","payload":[}}"#),
            Some(crate::protocol::ClassifiedFrame {
                admission: FrameAdmission::Application,
                on_failure: FailurePolicy::EndSession,
            })
        );
    }

    #[test]
    fn discovery_request_and_response_round_trip_with_strict_cursor() {
        let context = MeshContextId::from_bytes([7; 32]);
        let mut peers = vec![device(8), device(9), device(10)];
        peers.sort();
        let request = HubDiscoveryRequest::new(context, 4, None, 2).expect("bounded request");
        let response = HubDiscoveryResponse::for_request(
            &request,
            peers[..2].to_vec(),
            Some(peers[1].clone()),
        )
        .expect("response carries its continuation marker");

        let second_request = HubDiscoveryRequest::new(context, 5, Some(peers[1].clone()), 2)
            .expect("second bounded request");
        let second_response =
            HubDiscoveryResponse::for_request(&second_request, vec![peers[2].clone()], None)
                .expect("terminal response");
        let mut concatenated = response.peers().to_vec();
        concatenated.extend_from_slice(second_response.peers());
        assert_eq!(
            concatenated, peers,
            "cursor pages must not skip or duplicate peers"
        );
        assert!(HubDiscoveryResponse::for_request(
            &request,
            peers[..2].to_vec(),
            Some(peers[2].clone()),
        )
        .is_err());

        for message in [
            MeshMessage::HubDiscoveryRequest(request.clone()),
            MeshMessage::HubDiscoveryResponse(response.clone()),
        ] {
            let encoded = serde_json::to_string(&message).expect("discovery message serializes");
            let decoded: MeshMessage = serde_json::from_str(&encoded).expect("discovery decodes");
            match (message, decoded) {
                (
                    MeshMessage::HubDiscoveryRequest(expected),
                    MeshMessage::HubDiscoveryRequest(actual),
                ) => assert_eq!(actual, expected),
                (
                    MeshMessage::HubDiscoveryResponse(expected),
                    MeshMessage::HubDiscoveryResponse(actual),
                ) => assert_eq!(actual, expected),
                _ => panic!("discovery message changed wire variant"),
            }
        }
    }

    #[test]
    fn discovery_rejects_oversized_or_noncanonical_pages_and_sequences() {
        let context = MeshContextId::from_bytes([11; 32]);
        let first = device(12);
        let second = device(13);
        let request =
            HubDiscoveryRequest::new(context, 1, Some(first.clone()), 2).expect("bounded request");
        assert!(HubDiscoveryResponse::for_request(
            &request,
            vec![second.clone(), first.clone()],
            None,
        )
        .is_err());
        assert!(HubDiscoveryResponse::for_request(
            &request,
            vec![second.clone()],
            Some(first.clone()),
        )
        .is_err());

        let too_many = serde_json::json!({
            "context_id": context,
            "request_sequence": 1,
            "peers": (1..=(HUB_DISCOVERY_HARD_MAX_PEERS as u8 + 1))
                .map(device)
                .map(|peer| peer.base32())
                .collect::<Vec<_>>(),
            "next_after": null,
        });
        assert!(serde_json::from_value::<HubDiscoveryResponse>(too_many).is_err());

        let zero_sequence = serde_json::json!({
            "context_id": context,
            "request_sequence": 0,
            "after": null,
            "max_peers": 1,
        });
        assert!(serde_json::from_value::<HubDiscoveryRequest>(zero_sequence).is_err());

        let too_large_page = serde_json::json!({
            "context_id": context,
            "request_sequence": 1,
            "after": null,
            "max_peers": HUB_DISCOVERY_HARD_MAX_PEERS + 1,
        });
        assert!(serde_json::from_value::<HubDiscoveryRequest>(too_large_page).is_err());
    }

    #[test]
    fn discovery_frames_are_application_not_privileged_control() {
        for kind in ["hub_discovery_request", "hub_discovery_response"] {
            assert_eq!(
                classify_frame(format!(r#"{{"kind":"{kind}","peers":[}}"#).as_bytes()),
                Some(crate::protocol::ClassifiedFrame {
                    admission: FrameAdmission::Application,
                    on_failure: FailurePolicy::EndSession,
                })
            );
        }
    }
}
