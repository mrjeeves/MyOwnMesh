//! Native-lane discrimination for the existing admitted application frame.
//! This creates neither a flow registry nor application authority. The engine
//! still commits under the captured promoted session; the provider checks the
//! exact flow coordinate, direction, negotiated limit and full native mode.

use super::{DecodedApplicationMessage, GatewayRefusal};
use crate::protocol::application_flow::{
    ApplicationFlowCoordinate, ApplicationFlowMode, ApplicationFlowRefusal, FlowDirection,
};
use crate::realtime::OpaqueFlowMode;
use crate::resource::{LocalApplicationResourceScope, ResourceClaim, ResourceClass, ResourceLease};

/// Borrowed mirror of the wire control. Counting this view allocates no label
/// or JSON tree. The complete-message discriminator is included in the count.
#[derive(serde::Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum OpaqueControlView<'a> {
    Open {
        coordinate: ApplicationFlowCoordinate,
        label: &'a [u8],
        direction: FlowDirection,
        mode: ApplicationFlowMode,
        max_body_bytes: u32,
    },
    Accept {
        coordinate: ApplicationFlowCoordinate,
        label: &'a [u8],
        direction: FlowDirection,
        mode: ApplicationFlowMode,
        max_body_bytes: u32,
    },
    Change {
        previous_generation: u64,
        coordinate: ApplicationFlowCoordinate,
        label: &'a [u8],
        direction: FlowDirection,
        mode: ApplicationFlowMode,
        max_body_bytes: u32,
    },
    Close {
        coordinate: ApplicationFlowCoordinate,
        direction: FlowDirection,
    },
    Refuse {
        coordinate: ApplicationFlowCoordinate,
        reason: ApplicationFlowRefusal,
    },
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OpaqueMessageView<'a> {
    ApplicationFlowControl(&'a OpaqueControlView<'a>),
}

/// One encoded control, with its actual output backing held through the last
/// native send. Command/node storage is acquired separately by the mailbox.
pub(crate) struct FundedOpaqueControl {
    bytes: bytes::Bytes,
    _lease: ResourceLease,
}

impl FundedOpaqueControl {
    pub(crate) fn bytes(&self) -> &bytes::Bytes {
        &self.bytes
    }

    pub(crate) fn encode(
        resources: &LocalApplicationResourceScope,
        view: &OpaqueControlView<'_>,
    ) -> Result<Self, GatewayRefusal> {
        let message = OpaqueMessageView::ApplicationFlowControl(view);
        let (_, encoded, _) = crate::resource::mailbox_measure_serialized(&message)
            .map_err(|_| GatewayRefusal::Malformed)?;
        if encoded > crate::protocol::RECEIVE_FRAME_BYTES {
            return Err(GatewayRefusal::Malformed);
        }
        // Requested Vec capacity plus Bytes' shared allocation bookkeeping.
        // The inline owner is priced by NetworkCmd, not this pointee claim.
        let memory = encoded
            .checked_add(std::mem::size_of::<bytes::Bytes>())
            .ok_or(GatewayRefusal::Malformed)?;
        let claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(memory).map_err(|_| GatewayRefusal::Malformed)?,
            ),
            (
                ResourceClass::QueuedBytes,
                u64::try_from(encoded).map_err(|_| GatewayRefusal::Malformed)?,
            ),
            (
                ResourceClass::ParsingOrCpuWork,
                u64::try_from(encoded).map_err(|_| GatewayRefusal::Malformed)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| GatewayRefusal::Malformed)?;
        let lease = resources.acquire(claim).map_err(GatewayRefusal::Pressure)?;
        let mut bytes = Vec::with_capacity(encoded);
        serde_json::to_writer(&mut bytes, &message).map_err(|_| GatewayRefusal::Malformed)?;
        if bytes.len() != encoded {
            return Err(GatewayRefusal::Malformed);
        }
        Ok(Self {
            bytes: bytes.into(),
            _lease: lease,
        })
    }
}

/// The lane mode comes from the native callback, never from packet bytes.
/// MOMF cannot enter on the ordinary JSON channel, and an opaque native lane
/// cannot carry JSON signaling, channel messages or governance traffic.
pub(crate) fn validate_native_application_lane(
    message: &DecodedApplicationMessage,
    native_mode: Option<OpaqueFlowMode>,
) -> Result<(), GatewayRefusal> {
    match (message, native_mode) {
        (DecodedApplicationMessage::Json(_), None) => Ok(()),
        (DecodedApplicationMessage::OpaqueFlow { mode_tag, .. }, Some(mode)) => {
            let expected = match mode {
                OpaqueFlowMode::ReliableOrdered => 0,
                OpaqueFlowMode::PartialUnordered { .. } => 1,
            };
            if *mode_tag == expected {
                Ok(())
            } else {
                Err(GatewayRefusal::Malformed)
            }
        }
        _ => Err(GatewayRefusal::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::application_flow::{ApplicationFlowCoordinate, FlowDirection};
    use bytes::Bytes;

    fn binary(mode_tag: u8) -> DecodedApplicationMessage {
        DecodedApplicationMessage::OpaqueFlow {
            coordinate: ApplicationFlowCoordinate {
                flow_id: 7,
                generation: 3,
            },
            direction: FlowDirection::Outbound,
            mode_tag,
            body: Bytes::from_static(b"\xff\0{not-json}"),
        }
    }

    #[test]
    fn opaque_native_lane_rejects_json_and_ordinary_lane_rejects_binary() {
        let json = DecodedApplicationMessage::Json(crate::protocol::MeshMessage::Channel {
            channel: "app".into(),
            payload: serde_json::Value::Null,
        });
        assert!(validate_native_application_lane(&json, None).is_ok());
        assert!(
            validate_native_application_lane(&json, Some(OpaqueFlowMode::ReliableOrdered)).is_err()
        );
        assert!(validate_native_application_lane(&binary(0), None).is_err());
    }

    #[test]
    fn opaque_header_cannot_change_trusted_native_ordering() {
        let reliable = OpaqueFlowMode::ReliableOrdered;
        let partial = OpaqueFlowMode::PartialUnordered { max_retransmits: 2 };
        assert!(validate_native_application_lane(&binary(0), Some(reliable)).is_ok());
        assert!(validate_native_application_lane(&binary(1), Some(partial)).is_ok());
        assert!(validate_native_application_lane(&binary(1), Some(reliable)).is_err());
        assert!(validate_native_application_lane(&binary(0), Some(partial)).is_err());
        assert!(validate_native_application_lane(&binary(2), Some(partial)).is_err());
    }

    #[test]
    fn opaque_control_borrowed_encoding_matches_complete_wire_without_label_copy() {
        use crate::protocol::{ApplicationFlowControl as Control, MeshMessage};
        let label = vec![255; crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES];
        let coordinate = ApplicationFlowCoordinate {
            flow_id: u64::MAX,
            generation: u64::MAX,
        };
        for direction in [FlowDirection::Inbound, FlowDirection::Outbound] {
            for mode in [
                ApplicationFlowMode::ReliableOrdered,
                ApplicationFlowMode::PartialUnordered { max_retransmits: 0 },
            ] {
                let limit =
                    crate::protocol::application_flow::MAX_APPLICATION_FLOW_BODY_BYTES as u32;
                let views = [
                    OpaqueControlView::Open {
                        coordinate,
                        label: &label,
                        direction,
                        mode,
                        max_body_bytes: limit,
                    },
                    OpaqueControlView::Accept {
                        coordinate,
                        label: &label,
                        direction,
                        mode,
                        max_body_bytes: limit,
                    },
                    OpaqueControlView::Change {
                        previous_generation: u64::MAX - 1,
                        coordinate,
                        label: &label,
                        direction,
                        mode,
                        max_body_bytes: limit,
                    },
                    OpaqueControlView::Close {
                        coordinate,
                        direction,
                    },
                    OpaqueControlView::Refuse {
                        coordinate,
                        reason: ApplicationFlowRefusal::Capacity,
                    },
                ];
                let owned = [
                    Control::Open {
                        coordinate,
                        label: label.clone(),
                        direction,
                        mode,
                        max_body_bytes: limit,
                    },
                    Control::Accept {
                        coordinate,
                        label: label.clone(),
                        direction,
                        mode,
                        max_body_bytes: limit,
                    },
                    Control::Change {
                        previous_generation: u64::MAX - 1,
                        coordinate,
                        label: label.clone(),
                        direction,
                        mode,
                        max_body_bytes: limit,
                    },
                    Control::Close {
                        coordinate,
                        direction,
                    },
                    Control::Refuse {
                        coordinate,
                        reason: ApplicationFlowRefusal::Capacity,
                    },
                ];
                for (view, control) in views.iter().zip(owned) {
                    control.validate().unwrap();
                    let mirror = OpaqueMessageView::ApplicationFlowControl(view);
                    let wire =
                        serde_json::to_vec(&MeshMessage::ApplicationFlowControl(control)).unwrap();
                    let (_, counted, _) =
                        crate::resource::mailbox_measure_serialized(&mirror).unwrap();
                    assert_eq!(counted, wire.len());
                    assert_eq!(serde_json::to_vec(&mirror).unwrap(), wire);
                    assert!(counted <= crate::protocol::RECEIVE_FRAME_BYTES);
                }
            }
        }
    }
}
