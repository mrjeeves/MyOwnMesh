//! Binary application units and closed negotiation vocabulary. Coordinates
//! are locators within an already authenticated current session, not bearer
//! capabilities. The existing flow registry owns admission and generations.
pub use crate::realtime::RealtimeFlowDirection as FlowDirection;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const APPLICATION_FLOW_MAGIC: &[u8; 4] = b"MOMF";
pub const APPLICATION_FLOW_HEADER_BYTES: usize = 28;
pub const MAX_APPLICATION_FLOW_BODY_BYTES: usize =
    super::RECEIVE_FRAME_BYTES - APPLICATION_FLOW_HEADER_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationFlowCoordinate {
    pub flow_id: u64,
    pub generation: u64,
}
impl ApplicationFlowCoordinate {
    pub fn validate(self) -> Result<(), ApplicationFlowError> {
        if self.flow_id == 0 || self.generation == 0 {
            Err(ApplicationFlowError::Coordinate)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicationFlowMode {
    ReliableOrdered,
    PartialUnordered { max_retransmits: u16 },
}
impl ApplicationFlowMode {
    pub fn tag(self) -> u8 {
        match self {
            Self::ReliableOrdered => 0,
            Self::PartialUnordered { .. } => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationFlowRefusal {
    NotAdmitted,
    StaleGeneration,
    UnsupportedMode,
    Capacity,
    Malformed,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicationFlowControl {
    Open {
        coordinate: ApplicationFlowCoordinate,
        #[serde(deserialize_with = "bounded_label")]
        label: Vec<u8>,
        direction: FlowDirection,
        mode: ApplicationFlowMode,
        max_body_bytes: u32,
    },
    Accept {
        coordinate: ApplicationFlowCoordinate,
        #[serde(deserialize_with = "bounded_label")]
        label: Vec<u8>,
        direction: FlowDirection,
        mode: ApplicationFlowMode,
        max_body_bytes: u32,
    },
    Change {
        previous_generation: u64,
        coordinate: ApplicationFlowCoordinate,
        #[serde(deserialize_with = "bounded_label")]
        label: Vec<u8>,
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
impl ApplicationFlowControl {
    pub fn coordinate(&self) -> ApplicationFlowCoordinate {
        match self {
            Self::Open { coordinate, .. }
            | Self::Accept { coordinate, .. }
            | Self::Change { coordinate, .. }
            | Self::Close { coordinate, .. }
            | Self::Refuse { coordinate, .. } => *coordinate,
        }
    }
    /// Representation validation only. Accept/Change is not a grant until the
    /// exact session/old incarnation and fresh provider reservation commit.
    pub fn validate(&self) -> Result<(), ApplicationFlowError> {
        self.coordinate().validate()?;
        match self {
            Self::Open {
                max_body_bytes,
                label,
                ..
            }
            | Self::Accept {
                max_body_bytes,
                label,
                ..
            }
            | Self::Change {
                max_body_bytes,
                label,
                ..
            } => {
                validate_limit(*max_body_bytes as usize)?;
                if label.is_empty() || label.len() > crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES
                {
                    return Err(ApplicationFlowError::Limit);
                }
            }
            _ => {}
        }
        if let Self::Change {
            previous_generation,
            coordinate,
            ..
        } = self
        {
            if *previous_generation == 0
                || previous_generation.checked_add(1) != Some(coordinate.generation)
            {
                return Err(ApplicationFlowError::Generation);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationFlowError {
    #[error("malformed binary flow header or length")]
    Malformed,
    #[error("unsupported binary flow version")]
    Version,
    #[error("unsupported flow mode")]
    Mode,
    #[error("flow direction mismatch")]
    Direction,
    #[error("invalid or mismatched flow coordinate")]
    Coordinate,
    #[error("stale flow generation")]
    Generation,
    #[error("flow body or label limit refused")]
    Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationFlowFrame<'a> {
    pub coordinate: ApplicationFlowCoordinate,
    /// Direction in the opener's coordinate system, not the receiver's local
    /// inbound/outbound view. The flow owner supplies the expected value.
    pub direction: FlowDirection,
    pub mode_tag: u8,
    pub body: &'a [u8],
}
impl ApplicationFlowFrame<'_> {
    pub fn validate_expected(
        &self,
        coordinate: ApplicationFlowCoordinate,
        direction: FlowDirection,
        mode: ApplicationFlowMode,
    ) -> Result<(), ApplicationFlowError> {
        if self.coordinate.flow_id != coordinate.flow_id {
            return Err(ApplicationFlowError::Coordinate);
        }
        if self.coordinate.generation != coordinate.generation {
            return Err(ApplicationFlowError::Generation);
        }
        if self.direction != direction {
            return Err(ApplicationFlowError::Direction);
        }
        if self.mode_tag != mode.tag() {
            return Err(ApplicationFlowError::Mode);
        }
        Ok(())
    }
}

pub fn is_application_flow_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(APPLICATION_FLOW_MAGIC)
}

fn bounded_label<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    struct Label;
    impl<'de> serde::de::Visitor<'de> for Label {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("1..255 opaque label bytes")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            if seq
                .size_hint()
                .is_some_and(|n| n > crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES)
            {
                return Err(serde::de::Error::custom("label bound"));
            }
            let mut label = Vec::new();
            while let Some(byte) = seq.next_element::<u8>()? {
                if label.len() == crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES {
                    return Err(serde::de::Error::custom("label bound"));
                }
                label.push(byte);
            }
            if label.is_empty() {
                return Err(serde::de::Error::custom("empty label"));
            }
            Ok(label)
        }
    }
    d.deserialize_seq(Label)
}

fn validate_limit(limit: usize) -> Result<(), ApplicationFlowError> {
    if limit == 0 || limit > MAX_APPLICATION_FLOW_BODY_BYTES {
        Err(ApplicationFlowError::Limit)
    } else {
        Ok(())
    }
}

/// Borrows the caller's funded input. Header, complete length and negotiated
/// unit bound are checked before a body is returned, with no allocation or
/// UTF-8/JSON/codec interpretation. Current-session/flow checks remain required.
pub fn decode_application_flow(
    bytes: &[u8],
    max_body_bytes: usize,
) -> Result<ApplicationFlowFrame<'_>, ApplicationFlowError> {
    validate_limit(max_body_bytes)?;
    if bytes.len() < APPLICATION_FLOW_HEADER_BYTES
        || bytes.len() > super::RECEIVE_FRAME_BYTES
        || !is_application_flow_frame(bytes)
    {
        return Err(ApplicationFlowError::Malformed);
    }
    if bytes[4] != 1 {
        return Err(ApplicationFlowError::Version);
    }
    if bytes[5] > 1 {
        return Err(ApplicationFlowError::Mode);
    }
    let direction = match bytes[6] {
        0 => FlowDirection::Outbound,
        1 => FlowDirection::Inbound,
        _ => return Err(ApplicationFlowError::Direction),
    };
    if bytes[7] != 0 {
        return Err(ApplicationFlowError::Malformed);
    }
    let coordinate = ApplicationFlowCoordinate {
        flow_id: u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| ApplicationFlowError::Malformed)?,
        ),
        generation: u64::from_le_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| ApplicationFlowError::Malformed)?,
        ),
    };
    coordinate.validate()?;
    let len = u32::from_le_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| ApplicationFlowError::Malformed)?,
    ) as usize;
    if len > max_body_bytes {
        return Err(ApplicationFlowError::Limit);
    }
    if len != bytes.len() - APPLICATION_FLOW_HEADER_BYTES {
        return Err(ApplicationFlowError::Malformed);
    }
    Ok(ApplicationFlowFrame {
        coordinate,
        direction,
        mode_tag: bytes[5],
        body: &bytes[APPLICATION_FLOW_HEADER_BYTES..],
    })
}

/// The caller must reserve exact encoded bytes before this allocating encoder.
pub fn encode_application_flow(
    coordinate: ApplicationFlowCoordinate,
    direction: FlowDirection,
    mode: ApplicationFlowMode,
    body: &[u8],
    max_body_bytes: usize,
) -> Result<Vec<u8>, ApplicationFlowError> {
    coordinate.validate()?;
    validate_limit(max_body_bytes)?;
    if body.len() > max_body_bytes {
        return Err(ApplicationFlowError::Limit);
    }
    let mut out = Vec::with_capacity(APPLICATION_FLOW_HEADER_BYTES + body.len());
    out.extend_from_slice(APPLICATION_FLOW_MAGIC);
    out.extend_from_slice(&[
        1,
        mode.tag(),
        match direction {
            FlowDirection::Outbound => 0,
            FlowDirection::Inbound => 1,
        },
        0,
    ]);
    out.extend_from_slice(&coordinate.flow_id.to_le_bytes());
    out.extend_from_slice(&coordinate.generation.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_bytes_are_borrowed_with_exact_generation_mode_and_direction() {
        let coordinate = ApplicationFlowCoordinate {
            flow_id: 1,
            generation: 2,
        };
        for mode in [
            ApplicationFlowMode::ReliableOrdered,
            ApplicationFlowMode::PartialUnordered { max_retransmits: 0 },
        ] {
            for body in [
                &b"\xff\0{not-json}"[..],
                &b"application-defined-other-packetization"[..],
            ] {
                let wire =
                    encode_application_flow(coordinate, FlowDirection::Outbound, mode, body, 100)
                        .unwrap();
                let decoded = decode_application_flow(&wire, 100).unwrap();
                assert_eq!(decoded.body, body);
                assert_eq!(
                    decoded.body.as_ptr(),
                    wire[APPLICATION_FLOW_HEADER_BYTES..].as_ptr()
                );
                decoded
                    .validate_expected(coordinate, FlowDirection::Outbound, mode)
                    .unwrap();
                assert_eq!(
                    decoded.validate_expected(
                        ApplicationFlowCoordinate {
                            generation: 3,
                            ..coordinate
                        },
                        FlowDirection::Outbound,
                        mode
                    ),
                    Err(ApplicationFlowError::Generation)
                );
                assert_eq!(
                    decoded.validate_expected(coordinate, FlowDirection::Inbound, mode),
                    Err(ApplicationFlowError::Direction)
                );
                let other_mode = if mode.tag() == 0 {
                    ApplicationFlowMode::PartialUnordered { max_retransmits: 0 }
                } else {
                    ApplicationFlowMode::ReliableOrdered
                };
                assert_eq!(
                    decoded.validate_expected(coordinate, FlowDirection::Outbound, other_mode),
                    Err(ApplicationFlowError::Mode)
                );
            }
        }
    }
    #[test]
    fn binary_header_max_and_plus_one_are_checked_before_body_access() {
        let coordinate = ApplicationFlowCoordinate {
            flow_id: 1,
            generation: 1,
        };
        let body = vec![255; MAX_APPLICATION_FLOW_BODY_BYTES];
        let mut wire = encode_application_flow(
            coordinate,
            FlowDirection::Outbound,
            ApplicationFlowMode::ReliableOrdered,
            &body,
            MAX_APPLICATION_FLOW_BODY_BYTES,
        )
        .unwrap();
        assert_eq!(wire.len(), super::super::RECEIVE_FRAME_BYTES);
        assert_eq!(
            decode_application_flow(&wire, MAX_APPLICATION_FLOW_BODY_BYTES)
                .unwrap()
                .body
                .len(),
            body.len()
        );
        assert_eq!(
            decode_application_flow(&wire, MAX_APPLICATION_FLOW_BODY_BYTES - 1),
            Err(ApplicationFlowError::Limit)
        );
        wire.push(0);
        assert_eq!(
            decode_application_flow(&wire, MAX_APPLICATION_FLOW_BODY_BYTES),
            Err(ApplicationFlowError::Malformed)
        );
        wire.pop();
        wire[4] = 2;
        assert_eq!(
            decode_application_flow(&wire, MAX_APPLICATION_FLOW_BODY_BYTES),
            Err(ApplicationFlowError::Version)
        );
        assert_eq!(
            decode_application_flow(&wire[..20], 100),
            Err(ApplicationFlowError::Malformed)
        );
    }
    #[test]
    fn control_is_closed_and_generation_changes_do_not_wrap() {
        let control = ApplicationFlowControl::Change {
            previous_generation: u64::MAX,
            coordinate: ApplicationFlowCoordinate {
                flow_id: 1,
                generation: 1,
            },
            direction: FlowDirection::Outbound,
            label: vec![1],
            mode: ApplicationFlowMode::ReliableOrdered,
            max_body_bytes: 1024,
        };
        assert_eq!(control.validate(), Err(ApplicationFlowError::Generation));
        assert!(
            serde_json::from_str::<ApplicationFlowControl>(r#"{"op":"codec","body":[1,2]}"#)
                .is_err()
        );
    }
    #[test]
    fn control_label_and_body_bounds_preserve_exact_open_change_close_coordinates() {
        let coordinate = ApplicationFlowCoordinate {
            flow_id: 7,
            generation: 1,
        };
        let controls = [
            ApplicationFlowControl::Open {
                coordinate,
                label: vec![255; 255],
                direction: FlowDirection::Outbound,
                mode: ApplicationFlowMode::ReliableOrdered,
                max_body_bytes: MAX_APPLICATION_FLOW_BODY_BYTES as u32,
            },
            ApplicationFlowControl::Change {
                previous_generation: 1,
                coordinate: ApplicationFlowCoordinate {
                    generation: 2,
                    ..coordinate
                },
                label: vec![255; 255],
                direction: FlowDirection::Outbound,
                mode: ApplicationFlowMode::ReliableOrdered,
                max_body_bytes: 1024,
            },
            ApplicationFlowControl::Close {
                coordinate: ApplicationFlowCoordinate {
                    generation: 2,
                    ..coordinate
                },
                direction: FlowDirection::Outbound,
            },
        ];
        for control in controls {
            control.validate().unwrap();
            let json = serde_json::to_value(&control).unwrap();
            assert_eq!(
                serde_json::from_value::<ApplicationFlowControl>(json.clone()).unwrap(),
                control
            );
            let mut foreign = json;
            foreign["codec"] = serde_json::json!("not a core schema");
            assert!(serde_json::from_value::<ApplicationFlowControl>(foreign).is_err());
        }
        let mut open = serde_json::json!({"op":"open","coordinate":{"flow_id":7,"generation":1},
            "label":vec![255u8;256],"direction":"outbound","mode":{"kind":"reliable_ordered"},"max_body_bytes":1024});
        assert!(serde_json::from_value::<ApplicationFlowControl>(open.clone()).is_err());
        open["label"] = serde_json::json!([1]);
        open["max_body_bytes"] = serde_json::json!(MAX_APPLICATION_FLOW_BODY_BYTES + 1);
        assert_eq!(
            serde_json::from_value::<ApplicationFlowControl>(open)
                .unwrap()
                .validate(),
            Err(ApplicationFlowError::Limit)
        );
    }
}
