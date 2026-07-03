//! mDNS/DNS-SD signaling — LAN-local peer discovery plus a unicast
//! TCP exchange for the SDP/candidate traffic. Selected per network
//! via `SignalingConfig.mdns` (on by default) and usable alongside or
//! instead of the Nostr strategy: with both attached, co-located
//! peers keep meshing even when every relay/venue is unreachable.
//!
//! Structure mirrors [`crate::nostr`]:
//!
//! - [`driver`] — socket lifecycle: the DNS-SD registration/browse
//!   (via `mdns-sd`, pure Rust) and the TCP exchange listener.
//! - [`wire`] — deterministic wire logic: service type, instance
//!   naming, TXT records, and the JSON frame codec. Socket-free and
//!   fully unit-tested.
//!
//! The room handle is the same `SHA-256(app_id ":" network_id)` the
//! Nostr driver derives, so the two transports converge on one room
//! per network without extra configuration.

pub mod driver;
pub mod wire;

pub use driver::{start, MdnsDriverConfig, MdnsDriverHandle, MdnsInbound, MdnsOutbound};
