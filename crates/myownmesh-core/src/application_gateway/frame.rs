//! Encoded application frames, and the claim their parse is admitted against.

use bytes::Bytes;

use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};
use crate::runtime::session_broker::SessionCapability;

use super::GatewayRefusal;

/// An encoded application frame whose bytes and parse work were admitted by
/// the exact promoted session before full payload deserialization.
pub(crate) struct AdmittedApplicationFrame {
    encoded: Bytes,
    claim: ResourceClaim,
    _work: ResourceLease,
}

pub(crate) struct DecodedApplicationFrame {
    message: DecodedApplicationMessage,
    claim: ResourceClaim,
    _work: ResourceLease,
}

/// Binary units are never reconstructed as JSON. The body slice shares the
/// admitted input allocation and remains owned by the same work lease.
// The JSON variant is intentionally kept inline: boxing it would change the
// admitted decode layout and its existing resource-claim boundary.
#[allow(clippy::large_enum_variant)]
pub(crate) enum DecodedApplicationMessage {
    Json(crate::protocol::MeshMessage),
    OpaqueFlow {
        coordinate: crate::protocol::application_flow::ApplicationFlowCoordinate,
        direction: crate::protocol::application_flow::FlowDirection,
        mode_tag: u8,
        body: Bytes,
    },
}

impl AdmittedApplicationFrame {
    pub(crate) fn claim(
        encoded_bytes: usize,
    ) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        structural_json_claim(encoded_bytes)?.checked_add(frame_identity_decode_claim()?)
    }

    pub(crate) fn admit(
        session: &SessionCapability,
        encoded: Bytes,
    ) -> Result<Self, GatewayRefusal> {
        if encoded.len() > crate::protocol::RECEIVE_FRAME_BYTES {
            return Err(GatewayRefusal::Malformed);
        }
        if crate::protocol::application_flow::is_application_flow_frame(&encoded) {
            // Fixed-header validation only, before taking retained custody.
            crate::protocol::application_flow::decode_application_flow(
                &encoded,
                crate::protocol::application_flow::MAX_APPLICATION_FLOW_BODY_BYTES,
            )
            .map_err(|_| GatewayRefusal::Malformed)?;
        }
        let claim = Self::claim(encoded.len()).map_err(|_| GatewayRefusal::Malformed)?;
        let work = session
            .reserve_retained(claim)
            .map_err(GatewayRefusal::Pressure)?;
        Ok(Self {
            encoded,
            claim,
            _work: work,
        })
    }

    pub(crate) fn decode(self) -> Result<DecodedApplicationFrame, GatewayRefusal> {
        use crate::protocol::application_flow as flow;
        let message = if flow::is_application_flow_frame(&self.encoded) {
            let frame =
                flow::decode_application_flow(&self.encoded, flow::MAX_APPLICATION_FLOW_BODY_BYTES)
                    .map_err(|_| GatewayRefusal::Malformed)?;
            DecodedApplicationMessage::OpaqueFlow {
                coordinate: frame.coordinate,
                direction: frame.direction,
                mode_tag: frame.mode_tag,
                body: self.encoded.slice(flow::APPLICATION_FLOW_HEADER_BYTES..),
            }
        } else {
            let message: crate::protocol::MeshMessage =
                serde_json::from_slice(&self.encoded).map_err(|_| GatewayRefusal::Malformed)?;
            if let crate::protocol::MeshMessage::ApplicationFlowControl(control) = &message {
                control.validate().map_err(|_| GatewayRefusal::Malformed)?;
            }
            DecodedApplicationMessage::Json(message)
        };
        Ok(DecodedApplicationFrame {
            message,
            claim: self.claim,
            _work: self._work,
        })
    }
}

/// The exact claim one JSON input of `max_frame_bytes` will be admitted
/// against, for an owner that has to size a resource provider.
///
/// This exists because the derivation below is the only thing that can answer
/// it, and a provider owner outside this crate previously had to guess. Guessing
/// is what left self-funded test providers granting a residual denominated in
/// records against a claim denominated in bytes, so their first inbound `Hello`
/// was refused with no latch set and no warning. The formula is not restated
/// here — this calls the same function — so the two cannot drift.
///
/// **This sizes a grant. It is not a wire gate and not a limit.** Nothing
/// consults it at admission; a frame is admitted against
/// [`AdmittedApplicationFrame::claim`] at its own actual length. Passing a value
/// here says only how large an input the owner is willing to fund, and an owner
/// that funds too little sees a refusal rather than a truncation.
///
/// Until decoding identifies the message, this includes the fixed maximum
/// hub-introduction identity backing, even for JSON without those fields.
/// Binary application units use this same conservative claim: their fixed
/// header/body sharing is unchanged, but no cheaper byte-classified admission
/// diverges from this length-only planner. It is not a minimal binary cost.
pub fn json_input_work_claim(
    max_frame_bytes: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    AdmittedApplicationFrame::claim(max_frame_bytes)
}

/// Additional predecode backing for two endpoints and the bounded
/// hub-introduction hop list.
///
/// Structural JSON already prices scalar fragments, escaped-string parser
/// storage and inline DTO slots. It does not own these independent Arc/Box
/// allocations. Reserve each identity's intrinsic backing and two allocation
/// residuals, plus one opaque Ed25519 validation operation per identity. The
/// 52-byte parsed-text allowance is a conservative single-visitor scratch
/// reserve; fixed validator buffers (52+32+52) are stack, not retained heap.
/// Byte-work counts canonical input bytes, not measured crypto CPU time.
///
/// This adds no global interner claim, signature verification, output clone,
/// provider metadata or second lease. Later transaction work cannot replace
/// this admission, which must precede the first serde-owned identity.
fn frame_identity_decode_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let max_hops = u64::from(crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_HOPS);
    let overflow = |dimension| ResourceClaimArithmeticError::Overflow { dimension };
    let count = max_hops
        .checked_add(2)
        .ok_or_else(|| overflow(ResourceClass::AccountedMemoryBytes))?;
    let backing = u64::try_from(crate::semantic::DeviceId::uninterned_backing_bytes())
        .map_err(|_| overflow(ResourceClass::AccountedMemoryBytes))?;
    let memory = backing
        .checked_mul(count)
        .and_then(|n| n.checked_add(52))
        .ok_or_else(|| overflow(ResourceClass::AccountedMemoryBytes))?;
    let work = count
        .checked_mul(52)
        .ok_or_else(|| overflow(ResourceClass::ParsingOrCpuWork))?;
    let residual = count
        .checked_mul(3)
        .ok_or_else(|| overflow(ResourceClass::OpaqueDependencyResidual))?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, memory),
        (ResourceClass::ParsingOrCpuWork, work),
        (ResourceClass::OpaqueDependencyResidual, residual),
    ])
}

/// A mechanically conservative JSON-tree claim derived from the only quantity
/// available before parsing. A JSON value cannot contain more structural values
/// or owned scalar fragments than input bytes. Charging one full `Value` slot
/// and one opaque allocation per byte therefore covers adversarial tree
/// amplification instead of pretending wire length equals decoded retention.
pub(crate) fn structural_json_claim(
    encoded_bytes: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let bytes =
        u64::try_from(encoded_bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let value_slot = u64::try_from(std::mem::size_of::<serde_json::Value>()).map_err(|_| {
        ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    let bytes_per_input =
        value_slot
            .checked_add(1)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
    let decoded =
        bytes
            .checked_mul(bytes_per_input)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, decoded),
        (ResourceClass::ParsingOrCpuWork, bytes),
        (ResourceClass::OpaqueDependencyResidual, bytes),
    ])
}

impl DecodedApplicationFrame {
    pub(crate) fn into_parts(self) -> (DecodedApplicationMessage, ResourceClaim, ResourceLease) {
        (self.message, self.claim, self._work)
    }
}

#[cfg(test)]
mod decode_fence_controls {
    use super::*;
    use crate::runtime::session_broker::{session_and_provider_for_test, session_funding_for_test};

    fn identity_probes(message: &crate::protocol::MeshMessage) -> Vec<impl Fn() -> bool + 'static> {
        use crate::protocol::MeshMessage;
        let (source, destination, hops) = match message {
            MeshMessage::HubIntroduction(value) => {
                (value.source(), value.destination(), value.hops())
            }
            _ => panic!("control requires an introduction frame"),
        };
        [source, destination]
            .into_iter()
            .chain(hops.iter().map(|hop| &hop.forwarder))
            .map(crate::semantic::DeviceId::backing_liveness_for_test)
            .collect()
    }

    /// Only raw wire leaves this setup: all six signing-fixture identities
    /// have already lost their last strong owner before admission is tested.
    fn cold_frame_wire() -> Bytes {
        use crate::protocol::{hub_introduction::*, MeshMessage};
        use crate::semantic::{DeviceId, MeshContextId};
        use sha2::{Digest, Sha256};
        let keys: [ed25519_dalek::SigningKey; 6] = std::array::from_fn(|index| {
            let mut hash = Sha256::new();
            hash.update(b"gateway-predecode-cold-identity-v1");
            hash.update([index as u8]);
            ed25519_dalek::SigningKey::from_bytes(&hash.finalize().into())
        });
        let device = |key: &ed25519_dalek::SigningKey| {
            let spelling = data_encoding::BASE32_NOPAD
                .encode(key.verifying_key().as_bytes())
                .to_ascii_lowercase();
            DeviceId::from_canonical_str_uninterned(&spelling).unwrap()
        };
        let context = MeshContextId::from_bytes([119; 32]);
        let mut envelope = HubIntroductionEnvelope::new(
            context,
            device(&keys[0]),
            device(&keys[1]),
            [119; 16],
            0,
            None,
            HUB_INTRODUCTION_MAX_HOPS,
            HubIntroductionBody::Request {},
            &keys[0],
        )
        .unwrap();
        for key in keys.iter().skip(2) {
            envelope.append_hop(device(key), key).unwrap();
        }
        let message = MeshMessage::HubIntroduction(envelope);
        let probes = identity_probes(&message);
        assert_eq!(probes.len(), 6);
        let wire = Bytes::from(serde_json::to_vec(&message).unwrap());
        drop(message);
        assert!(probes.iter().all(|alive| !alive()));
        drop(probes);
        wire
    }

    #[test]
    fn identity_predecode_pressure_refuses_old_and_one_work_unit_short_grants() {
        let wire = cold_frame_wire();
        let required = AdmittedApplicationFrame::claim(wire.len()).unwrap();
        let short = required
            .checked_sub(ResourceClaim::single(ResourceClass::ParsingOrCpuWork, 1))
            .unwrap();
        for budget in [structural_json_claim(wire.len()).unwrap(), short] {
            let (session, provider) =
                session_and_provider_for_test(crate::runtime::runtime_for_test(), budget);
            let baseline = provider.in_use();
            assert_eq!(baseline.amount(ResourceClass::ParsingOrCpuWork), 0);
            assert!(matches!(
                AdmittedApplicationFrame::admit(&session, wire.clone()),
                Err(GatewayRefusal::Pressure(_))
            ));
            // No DecodedApplicationFrame exists and admission contains no
            // serde call; refused reservation leaves no parse custody.
            assert_eq!(provider.in_use(), baseline);
        }
    }

    fn assert_cold_decode_custody() {
        let wire = cold_frame_wire();
        let claim = AdmittedApplicationFrame::claim(wire.len()).unwrap();
        let (session, provider) =
            session_and_provider_for_test(crate::runtime::runtime_for_test(), claim);
        let baseline = provider.in_use();
        let charged = baseline
            .checked_add(
                crate::resource::FiniteResourceProvider::reservation_planning_charge(claim)
                    .unwrap(),
            )
            .unwrap();
        let admitted = AdmittedApplicationFrame::admit(&session, wire.clone()).unwrap();
        assert_eq!(admitted.encoded.as_ptr(), wire.as_ptr());
        assert_eq!(provider.in_use(), charged, "funding precedes decode");
        let decoded = admitted.decode().unwrap();
        assert_eq!(provider.in_use(), charged, "decode moves the same lease");
        let (message, actual_claim, work) = decoded.into_parts();
        assert_eq!(actual_claim, claim);
        let DecodedApplicationMessage::Json(message) = message else {
            panic!("expected JSON")
        };
        let probes = identity_probes(&message);
        assert_eq!(probes.len(), 6);
        assert!(probes.iter().all(|alive| alive()));
        assert_eq!(
            serde_json::to_vec(&message).unwrap().as_slice(),
            wire.as_ref()
        );
        assert!(
            matches!(
                AdmittedApplicationFrame::admit(&session, wire.clone()),
                Err(GatewayRefusal::Pressure(_))
            ),
            "no unpriced concurrent decode"
        );
        drop(message);
        assert!(probes.iter().all(|alive| !alive()));
        assert_eq!(provider.in_use(), charged, "lease outlives decoded backing");
        drop(probes); // Weak tail ends before its backing funding.
        drop(work);
        assert_eq!(provider.in_use(), baseline);

        // Cancel before decode, then cancel after successful decode. Neither
        // changes the exact baseline or leaves an identity strongly retained.
        drop(AdmittedApplicationFrame::admit(&session, wire.clone()).unwrap());
        assert_eq!(provider.in_use(), baseline);
        let decoded = AdmittedApplicationFrame::admit(&session, wire.clone())
            .unwrap()
            .decode()
            .unwrap();
        let DecodedApplicationMessage::Json(message) = &decoded.message else {
            panic!("expected JSON")
        };
        let probes = identity_probes(message);
        assert!(probes.iter().all(|alive| alive()));
        // Do not create a test-only weak allocation tail beyond frame funding.
        drop(probes);
        drop(decoded);
        assert_eq!(provider.in_use(), baseline);

        // Same-length malformed JSON is admitted without parsing. Deserializer
        // error drops the original work lease rather than acquiring another.
        let mut malformed = wire.to_vec();
        malformed[0] = b'!';
        let admitted = AdmittedApplicationFrame::admit(&session, Bytes::from(malformed)).unwrap();
        assert_eq!(provider.in_use(), charged);
        assert_eq!(admitted.decode().err(), Some(GatewayRefusal::Malformed));
        assert_eq!(provider.in_use(), baseline);

        // A truncated valid prefix also exercises deserializer unwinding,
        // rather than only rejection at the initial JSON byte.
        let truncated = wire.slice(..wire.len() - 1);
        let admitted = AdmittedApplicationFrame::admit(&session, truncated).unwrap();
        assert_eq!(admitted.decode().err(), Some(GatewayRefusal::Malformed));
        assert_eq!(provider.in_use(), baseline);
    }

    #[test]
    fn cold_introduction_decode_retains_prepaid_identity_backing_until_output_drop() {
        assert_cold_decode_custody();
    }

    #[test]
    fn application_frame_limit_precedes_reservation_and_max_plan_funds_admission() {
        let maximum = crate::protocol::RECEIVE_FRAME_BYTES;
        let claim = json_input_work_claim(maximum).unwrap();
        let (session, provider) =
            session_and_provider_for_test(crate::runtime::runtime_for_test(), claim);
        let baseline = provider.in_use();
        assert_eq!(
            AdmittedApplicationFrame::admit(&session, Bytes::from(vec![b' '; maximum + 1]),).err(),
            Some(GatewayRefusal::Malformed)
        );
        assert_eq!(provider.in_use(), baseline);
        let admitted =
            AdmittedApplicationFrame::admit(&session, Bytes::from(vec![b' '; maximum])).unwrap();
        assert_eq!(admitted.claim, claim);
        assert_eq!(admitted.decode().err(), Some(GatewayRefusal::Malformed));
        assert_eq!(provider.in_use(), baseline);
    }

    /// The property the inbound path's three-phase split rests on: admission
    /// decides whether the parse may happen **without performing it**.
    ///
    /// Stated as a control because it is load-bearing and invisible. If `admit`
    /// ever grew a parse — a validation pass, a cheap shape check, a length
    /// probe that deserializes — the engine would be back to holding the
    /// registry's single mutation lock across peer-chosen work, and every other
    /// control in this batch would still pass. Bytes that cannot possibly parse
    /// are what makes it discriminating: they are admitted and funded, and only
    /// the separate `decode` step refuses them.
    #[test]
    fn admission_funds_a_frame_it_has_not_parsed() {
        let garbage = Bytes::from_static(b"{ this is not json");
        let claim = AdmittedApplicationFrame::claim(garbage.len())
            .expect("the structural claim over a short frame is representable");
        // Funded for exactly this frame and nothing else, so `admit` succeeding
        // below is attributable to it not needing to parse — and not to slack
        // the fixture happened to have.
        let session = session_funding_for_test(crate::runtime::runtime_for_test(), claim);

        let frame = AdmittedApplicationFrame::admit(&session, garbage.clone())
            .expect("admission measures the encoded length; it does not read the bytes");
        assert_eq!(
            frame.claim, claim,
            "non-vacuity: funded against its own length, so the lease is real and \
             the escape below carries it"
        );

        // Only here, outside every fence in production, does the input's shape
        // matter — and this is the step whose duration the sender chooses.
        assert_eq!(frame.decode().err(), Some(GatewayRefusal::Malformed));
    }

    #[test]
    fn admitted_binary_unit_keeps_original_bytes_and_rejects_malformed_before_retention() {
        use crate::protocol::application_flow::*;
        let coordinate = ApplicationFlowCoordinate {
            flow_id: 1,
            generation: 1,
        };
        let wire = Bytes::from(
            encode_application_flow(
                coordinate,
                FlowDirection::Outbound,
                ApplicationFlowMode::ReliableOrdered,
                b"\xff\0{not json}",
                100,
            )
            .unwrap(),
        );
        let original_body = wire.slice(APPLICATION_FLOW_HEADER_BYTES..);
        let claim = AdmittedApplicationFrame::claim(wire.len()).unwrap();
        let session = session_funding_for_test(crate::runtime::runtime_for_test(), claim);
        let frame = AdmittedApplicationFrame::admit(&session, wire)
            .unwrap()
            .decode()
            .unwrap();
        let (decoded, actual_claim, work) = frame.into_parts();
        assert_eq!(actual_claim, claim);
        let DecodedApplicationMessage::OpaqueFlow {
            coordinate: actual,
            body,
            ..
        } = decoded
        else {
            panic!("binary unit was reinterpreted as JSON")
        };
        assert_eq!(actual, coordinate);
        assert_eq!(body, original_body);
        assert_eq!(body.as_ptr(), original_body.as_ptr());
        drop(body);
        drop(work);
        let malformed = Bytes::from_static(b"MOMF\x01");
        assert_eq!(
            AdmittedApplicationFrame::admit(&session, malformed).err(),
            Some(GatewayRefusal::Malformed)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_identity_delta_and_length_planner_are_checked_and_identical() {
        let delta = frame_identity_decode_claim().unwrap();
        assert_eq!(
            crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_HOPS,
            4
        );
        assert_eq!(
            delta.amount(ResourceClass::AccountedMemoryBytes),
            6 * crate::semantic::DeviceId::uninterned_backing_bytes() as u64 + 52
        );
        assert_eq!(delta.amount(ResourceClass::ParsingOrCpuWork), 6 * 52);
        assert_eq!(
            delta.amount(ResourceClass::OpaqueDependencyResidual),
            6 * (2 + 1)
        );
        for length in [
            0,
            1,
            52,
            16_384,
            crate::protocol::RECEIVE_FRAME_BYTES,
            crate::protocol::RECEIVE_FRAME_BYTES + 1,
        ] {
            let expected = structural_json_claim(length)
                .unwrap()
                .checked_add(delta)
                .unwrap();
            assert_eq!(AdmittedApplicationFrame::claim(length).unwrap(), expected);
            assert_eq!(json_input_work_claim(length).unwrap(), expected);
        }
        if usize::BITS >= 64 {
            assert!(json_input_work_claim(usize::MAX).is_err());
        }
        assert!(
            ResourceClaim::single(ResourceClass::AccountedMemoryBytes, u64::MAX)
                .checked_add(delta)
                .is_err()
        );
    }

    #[test]
    fn json_admission_does_not_equate_wire_length_with_decoded_tree_retention() {
        let wire = 7usize;
        let claim = structural_json_claim(wire).expect("the small claim is representable");
        assert_eq!(claim.amount(ResourceClass::ParsingOrCpuWork), wire as u64);
        assert_eq!(
            claim.amount(ResourceClass::OpaqueDependencyResidual),
            wire as u64,
            "every possible owned fragment has an explicit residual"
        );
        assert!(
            claim.amount(ResourceClass::AccountedMemoryBytes) > wire as u64,
            "decoded Value slots, rather than wire bytes alone, are funded"
        );
    }
}
