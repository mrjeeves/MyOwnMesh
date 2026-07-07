//! mDNS/DNS-SD signaling — LAN-local peer discovery plus a unicast
//! TCP exchange for the SDP/candidate traffic. Selected per network
//! via `SignalingConfig.mdns` (on by default) and usable alongside or
//! instead of the Nostr strategy: with both attached, co-located
//! peers keep meshing even when every relay/venue is unreachable.
//!
//! Structure mirrors [`crate::nostr`]:
//!
//! - [`driver`] — socket lifecycle: the DNS-SD registration/browse and
//!   the TCP exchange listener.
//! - [`discovery`] — the registration/browse backends: the pure-Rust
//!   `mdns-sd` daemon by default, or the platform's own DNS-SD daemon
//!   (the `dnssd` C API → mDNSResponder / Avahi) on iOS, where raw
//!   multicast sockets are entitlement-gated. Both speak standard
//!   mDNS/DNS-SD on the wire, so mixed backends interoperate.
//! - [`wire`] — deterministic wire logic: service type, instance
//!   naming, TXT records, and the JSON frame codec. Socket-free and
//!   fully unit-tested.
//!
//! The room handle is the same `SHA-256(app_id ":" network_id)` the
//! Nostr driver derives, so the two transports converge on one room
//! per network without extra configuration.

pub mod discovery;
pub mod driver;
pub mod wire;

pub use driver::{start, MdnsDriverConfig, MdnsDriverHandle, MdnsInbound, MdnsOutbound};
