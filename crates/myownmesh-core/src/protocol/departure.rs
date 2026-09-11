//! Authenticated departure correlation metadata.
//!
//! A departure is scoped by the authenticated session carrying it. The
//! correlation is only a bounded opaque value used to match the one receipt;
//! it is not a device id, session identity, generation, retry token, or
//! durable authority.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};

/// The cryptographic width of one departure correlation premise.
pub const DEPARTURE_CORRELATION_BYTES: usize = 32;

/// The exact lowercase base32-without-padding width of one correlation.
pub const DEPARTURE_CORRELATION_WIRE_CHARS: usize = 52;

/// Opaque correlation for one authenticated `Depart`/`DepartObserved` pair.
///
/// The stored form is already the one canonical wire form: 32 cryptographic
/// bytes, encoded as 52 lowercase base32 characters without padding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepartureCorrelation(String);

impl DepartureCorrelation {
    /// Construct directly from the already-selected 32-byte cryptographic
    /// premise. Arbitrary UTF-8 or caller-chosen wire text cannot enter this
    /// type; the wire parser accepts only the exact canonical representation.
    pub fn from_bytes(bytes: [u8; DEPARTURE_CORRELATION_BYTES]) -> Self {
        Self(BASE32_NOPAD.encode(&bytes).to_lowercase())
    }

    /// Parse exactly the canonical lowercase base32-no-padding wire form.
    pub fn from_wire(value: &str) -> Result<Self, DepartureCorrelationError> {
        if value.len() != DEPARTURE_CORRELATION_WIRE_CHARS {
            return Err(DepartureCorrelationError::WrongWidth {
                chars: value.len(),
                expected: DEPARTURE_CORRELATION_WIRE_CHARS,
            });
        }
        let decoded = BASE32_NOPAD
            .decode(value.to_ascii_uppercase().as_bytes())
            .map_err(|_| DepartureCorrelationError::NonCanonical)?;
        if decoded.len() != DEPARTURE_CORRELATION_BYTES
            || BASE32_NOPAD.encode(&decoded).to_lowercase() != value
        {
            return Err(DepartureCorrelationError::NonCanonical);
        }
        let mut bytes = [0u8; DEPARTURE_CORRELATION_BYTES];
        bytes.copy_from_slice(&decoded);
        Ok(Self::from_bytes(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DepartureCorrelation {
    type Error = DepartureCorrelationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_wire(&value)
    }
}

impl AsRef<str> for DepartureCorrelation {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DepartureCorrelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for DepartureCorrelation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DepartureCorrelation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_wire(&value).map_err(D::Error::custom)
    }
}

/// A malformed or noncanonical departure correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepartureCorrelationError {
    WrongWidth { chars: usize, expected: usize },
    NonCanonical,
}

impl fmt::Display for DepartureCorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongWidth { chars, expected } => {
                write!(
                    f,
                    "departure correlation is {chars} characters; exact width is {expected}"
                )
            }
            Self::NonCanonical => {
                f.write_str("departure correlation is not canonical lowercase base32")
            }
        }
    }
}

impl std::error::Error for DepartureCorrelationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_is_fixed_width_and_premise_is_opaque() {
        let correlation = DepartureCorrelation::from_bytes([1u8; DEPARTURE_CORRELATION_BYTES]);
        assert_eq!(correlation.as_str().len(), DEPARTURE_CORRELATION_WIRE_CHARS);
        assert_eq!(
            DepartureCorrelation::from_wire(correlation.as_str()),
            Ok(correlation.clone())
        );
        assert_ne!(
            correlation,
            DepartureCorrelation::from_bytes([2u8; DEPARTURE_CORRELATION_BYTES])
        );
    }

    #[test]
    fn wire_rejects_wrong_width_case_and_noncanonical_trailing_bits() {
        let canonical = DepartureCorrelation::from_bytes([0u8; DEPARTURE_CORRELATION_BYTES]);
        assert_eq!(
            DepartureCorrelation::from_wire(""),
            Err(DepartureCorrelationError::WrongWidth {
                chars: 0,
                expected: DEPARTURE_CORRELATION_WIRE_CHARS,
            })
        );
        assert_eq!(
            DepartureCorrelation::from_wire(&canonical.as_str()[..51]),
            Err(DepartureCorrelationError::WrongWidth {
                chars: 51,
                expected: DEPARTURE_CORRELATION_WIRE_CHARS,
            })
        );
        assert!(matches!(
            DepartureCorrelation::from_wire(&format!("{canonical}=")),
            Err(DepartureCorrelationError::WrongWidth { .. })
        ));
        assert_eq!(
            DepartureCorrelation::from_wire(&canonical.as_str().to_ascii_uppercase()),
            Err(DepartureCorrelationError::NonCanonical)
        );
        let mut altered = canonical.as_str().to_owned();
        altered.pop();
        altered.push('b');
        assert_eq!(
            DepartureCorrelation::from_wire(&altered),
            Err(DepartureCorrelationError::NonCanonical)
        );
    }
}
