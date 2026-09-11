//! Who is asking, and which of their things they are asking about.
//!
//! Four names and nothing else: a routing coordinate, a table key, and two
//! unforgeable authorities. None of them knows what a registry is, none holds a
//! resource, and none can be constructed from outside this module tree — which
//! is the point of putting them together. An authority that any caller could
//! mint would authorise nothing.
//!
//! The split is by what a value *is*, not by what uses it. These are all reached
//! from the registry, the handle and the pending table alike, so filing them
//! under any one of those would have made the other two reach across.

/// Process-unique identifier for a connected client.
///
/// Just a monotonic counter; the daemon never reuses ids, so a
/// stale reference in a forwarder task that races with
/// disconnect resolves to a `None` lookup instead of routing to
/// a different client.
///
/// Wire form is the `Display` shape `c<n>` — clients pass it
/// back verbatim on subsequent RPC/channel-management requests
/// to identify which event-subscribed connection a handler
/// claim belongs to.
/// `Ord` is derived because this is a [`LeasedMap`] key, and the order is the
/// counter's own: ids sort by the sequence they were issued in. Nothing depends
/// on that ordering being meaningful — it exists so the tables can be searched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(pub u64);

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "c{}", self.0)
    }
}

impl std::str::FromStr for ClientId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n_str = s
            .strip_prefix('c')
            .ok_or_else(|| format!("ClientId must start with 'c', got '{s}'"))?;
        let n: u64 = n_str.parse().map_err(|e| format!("ClientId parse: {e}"))?;
        if ClientId(n).to_string() != s {
            return Err(format!("ClientId is not canonical: '{s}'"));
        }
        Ok(ClientId(n))
    }
}

impl serde::Serialize for ClientId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ClientId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Per-network handler-claim key. `network` is the
/// configuration id (matching the rest of the control surface).
pub type ClaimKey = (String, String);

/// Unforgeable authority issued to one event-stream connection. `ClientId`
/// remains a routing coordinate; possession of this value is the authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCapability(String);

impl ClientCapability {
    const RAW_BYTES: usize = 32;
    pub(super) const ENCODED_LEN: usize = (Self::RAW_BYTES * 8).div_ceil(6);

    pub(super) fn mint() -> Self {
        let mut bytes = [0_u8; Self::RAW_BYTES];
        getrandom::getrandom(&mut bytes)
            .expect("OS randomness is required for local IPC authority");
        Self(data_encoding::BASE64URL_NOPAD.encode(&bytes))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub(super) fn matches(&self, presented: &str) -> bool {
        if self.0.len() != presented.len() {
            return false;
        }
        self.0
            .bytes()
            .zip(presented.bytes())
            .fold(0_u8, |d, (a, b)| d | (a ^ b))
            == 0
    }
}

/// Unforgeable authority naming one realtime flow a client has open.
///
/// Minted when the flow is opened, and the daemon keeps the move-only core
/// handle behind it. A client presents it to write on that flow or to close it;
/// there is no coordinate that substitutes, which is the whole point — the peer
/// selector and the flow label it replaces were both re-resolvable, so a client
/// whose session had been replaced was writing into the successor's flow of the
/// same name.
///
/// Separate from [`ClientCapability`] rather than reusing it, because the two
/// answer different questions: that one says *who* is asking, this one says
/// *which of that client's flows*. One value doing both would make a client's
/// second flow indistinguishable from its first.
///
/// Compared by map lookup rather than in constant time, and that is sound here
/// where it would not be for [`ClientCapability`]: this table is only ever
/// reached after the client capability has authenticated, and it holds only
/// that client's own flows. What a timing probe could learn is which of its own
/// flows it already has.
#[derive(Clone, PartialEq, Eq)]
pub struct RealtimeFlowCapability(String);

impl RealtimeFlowCapability {
    pub(super) fn mint() -> Self {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .expect("OS randomness is required for local IPC authority");
        Self(data_encoding::BASE64URL_NOPAD.encode(&bytes))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}
