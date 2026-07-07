//! The discovery half of the mDNS driver — DNS-SD registration and browsing —
//! behind one seam with two backends:
//!
//! - [`embedded`] (the default): the pure-Rust `mdns-sd` daemon, raw multicast
//!   sockets. Works anywhere the OS lets an application join the mDNS
//!   multicast group.
//! - [`system`] (iOS always; opt-in elsewhere via the `system-dnssd` feature):
//!   the platform's own DNS-SD daemon through the stable `dnssd` C API —
//!   mDNSResponder on Apple platforms, Avahi's `libdns_sd` compat shim on
//!   Linux. iOS 14+ blocks raw multicast sockets unless the app holds the
//!   Apple-granted `com.apple.developer.networking.multicast` entitlement, but
//!   talking to mDNSResponder needs no entitlement — only the standard
//!   `NSLocalNetworkUsageDescription` / `NSBonjourServices` Info.plist keys.
//!   This is what makes **local claiming** work properly on an iPhone.
//!
//! Both backends speak standard mDNS/DNS-SD on the wire — same service type,
//! same TXT records — so a peer using one discovers a peer using the other.
//! The signaling exchange itself (the unicast TCP connection) is
//! backend-independent and lives in [`super::driver`].

use std::collections::HashMap;
use std::net::IpAddr;

/// What a backend needs to advertise + browse one service instance.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// DNS-SD service type, in the `_x._tcp.local.` form ([`super::wire::SERVICE_TYPE`]).
    pub service_type: String,
    /// Our instance name (a bare DNS label, [`super::wire::instance_name`]).
    pub instance: String,
    /// Port the SRV record advertises (our TCP exchange listener).
    pub port: u16,
    /// TXT records for the advertisement ([`super::wire::txt_properties`]).
    pub txt: Vec<(String, String)>,
}

/// One discovery observation. `key` is a backend-opaque identifier that is
/// stable between a `Resolved` and the `Removed` that withdraws it — the
/// driver treats it as an opaque map key and never interprets it.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A service instance resolved (first sight or cache refresh): where its
    /// exchange listens and its TXT records.
    Resolved {
        key: String,
        addrs: Vec<IpAddr>,
        port: u16,
        txt: HashMap<String, String>,
    },
    /// An instance withdrew (goodbye) or expired from the cache.
    Removed { key: String },
}

#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
mod system;
#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
pub use system::Discovery;

#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
mod embedded;
#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
pub use embedded::Discovery;
