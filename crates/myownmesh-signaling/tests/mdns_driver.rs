//! Two mDNS drivers on one host discover each other and exchange a
//! directed signaling message — the driver-level proof that LAN
//! signaling works end to end (DNS-SD resolve → PeerAnnounced →
//! TCP exchange → Message).
//!
//! Multicast is not available in every environment (CI containers
//! frequently block it). When discovery doesn't happen inside the
//! grace window the test SKIPS — loudly — instead of failing, so the
//! suite stays deterministic; the wire-format logic is covered by
//! always-run unit tests in `mdns::wire`.

use std::time::Duration;

use myownmesh_signaling::mdns::discovery::DiscoveryBackend;
use myownmesh_signaling::mdns::driver::{
    AliasProvider, AliasRefusal, AliasRetention, ConnectionIdentityRetention, ConnectionRetention,
    DiscoveryRetention, MdnsLimits, PeerRetention,
};
use myownmesh_signaling::mdns::{self, MdnsDriverConfig, MdnsInbound, MdnsOutbound};
use myownmesh_signaling::{
    DedicatedTaskCustodian, ErasedOwner, InboundSink, SignalingMessage, TaskCustodian,
    UnboundedSource,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// How long we give same-host multicast discovery before deciding the
/// environment doesn't support it. Generous — resolution normally
/// lands in well under two seconds.
const DISCOVERY_GRACE: Duration = Duration::from_secs(15);

fn driver_custodian() -> std::sync::Arc<dyn TaskCustodian> {
    DedicatedTaskCustodian::new(1).expect("driver custodian starts")
        as std::sync::Arc<dyn TaskCustodian>
}

fn reaper_custodian() -> std::sync::Arc<dyn TaskCustodian> {
    DedicatedTaskCustodian::new(2).expect("reaper custodian starts")
        as std::sync::Arc<dyn TaskCustodian>
}

#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
fn backend_custodian(
    _limits: myownmesh_signaling::mdns::discovery::DiscoveryLimits,
) -> Option<std::sync::Arc<dyn TaskCustodian>> {
    let plan = myownmesh_signaling::mdns::discovery::checked_embedded_custody_plan()
        .expect("embedded custody plan is valid");
    assert_eq!(plan.observer_slots, 3);
    Some(
        DedicatedTaskCustodian::new(3).expect("embedded backend custodian starts")
            as std::sync::Arc<dyn TaskCustodian>,
    )
}

#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
fn backend_custodian(
    limits: myownmesh_signaling::mdns::discovery::DiscoveryLimits,
) -> Option<std::sync::Arc<dyn TaskCustodian>> {
    let capacity = limits
        .max_resolve_owners
        .checked_add(2)
        .expect("system worker capacity fits");
    Some(
        DedicatedTaskCustodian::new(capacity).expect("system backend custodian starts")
            as std::sync::Arc<dyn TaskCustodian>,
    )
}

fn close_custodian(owner: &std::sync::Arc<dyn TaskCustodian>) {
    owner.close();
}

struct CustodianGuards(Vec<std::sync::Arc<dyn TaskCustodian>>);

impl Drop for CustodianGuards {
    fn drop(&mut self) {
        for owner in &self.0 {
            close_custodian(owner);
        }
    }
}

fn driver_config(network: &str, device: &str) -> MdnsDriverConfig {
    MdnsDriverConfig {
        app_id: "myownmesh-mdns-test".into(),
        network_id: network.into(),
        device_id: device.into(),
        service_port: 0,
        device_id_validator: accept_any,
        alias_provider: std::sync::Arc::new(TestAliasProvider),
        limits: myownmesh_signaling::mdns::driver::MdnsLimits::default(),
    }
}

fn accept_any(_: &str) -> bool {
    true
}

fn configured_backend() -> DiscoveryBackend {
    #[cfg(any(target_os = "ios", feature = "system-dnssd"))]
    {
        DiscoveryBackend::System
    }
    #[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
    {
        DiscoveryBackend::Embedded
    }
}

struct TestAliasProvider;

impl AliasProvider for TestAliasProvider {
    fn retain_discovery(&self, retention: DiscoveryRetention) -> Result<ErasedOwner, AliasRefusal> {
        let expected = DiscoveryRetention::from_backend(
            myownmesh_signaling::mdns::driver::MdnsLimits::default().discovery,
            configured_backend(),
        )
        .expect("default discovery retention is valid");
        assert_eq!(
            retention, expected,
            "the fixture provider must account for every discovery dimension"
        );
        Ok(Box::new(retention))
    }

    fn retain_alias(
        &self,
        _key: &str,
        _peer: &str,
        _retention: AliasRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_peer(
        &self,
        _peer: &str,
        _retention: PeerRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_connection(
        &self,
        _peer: Option<&str>,
        _retention: ConnectionRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_connection_identity(
        &self,
        _peer: &str,
        _retention: ConnectionIdentityRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }
}

struct CountingOwner(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for CountingOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

struct DiscoveryOwner {
    active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    released: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for DiscoveryOwner {
    fn drop(&mut self) {
        self.active
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.released
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

struct RefusingAliasProvider;

impl AliasProvider for RefusingAliasProvider {
    fn retain_discovery(&self, retention: DiscoveryRetention) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(retention))
    }

    fn retain_alias(
        &self,
        _key: &str,
        _peer: &str,
        _retention: AliasRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Err(AliasRefusal::Provider("capacity".into()))
    }

    fn retain_peer(
        &self,
        _peer: &str,
        _retention: PeerRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_connection(
        &self,
        _peer: Option<&str>,
        _retention: ConnectionRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_connection_identity(
        &self,
        _peer: &str,
        _retention: ConnectionIdentityRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }
}

struct DiscoveryRefusalProvider {
    seen: std::sync::Arc<std::sync::Mutex<Option<DiscoveryRetention>>>,
}

impl AliasProvider for DiscoveryRefusalProvider {
    fn retain_discovery(&self, retention: DiscoveryRetention) -> Result<ErasedOwner, AliasRefusal> {
        *self.seen.lock().expect("discovery observation lock") = Some(retention);
        Err(AliasRefusal::Provider(
            "deliberate discovery pressure".into(),
        ))
    }

    fn retain_alias(
        &self,
        _key: &str,
        _peer: &str,
        _retention: AliasRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        unreachable!("discovery refusal happens before alias admission")
    }

    fn retain_peer(
        &self,
        _peer: &str,
        _retention: PeerRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        unreachable!("discovery refusal happens before peer admission")
    }

    fn retain_connection(
        &self,
        _peer: Option<&str>,
        _retention: ConnectionRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        unreachable!("discovery refusal happens before connection admission")
    }

    fn retain_connection_identity(
        &self,
        _peer: &str,
        _retention: ConnectionIdentityRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        unreachable!("discovery refusal happens before identity admission")
    }
}

struct RecordingDiscoveryProvider {
    seen: std::sync::Arc<std::sync::Mutex<Option<DiscoveryRetention>>>,
    active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    released: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AliasProvider for RecordingDiscoveryProvider {
    fn retain_discovery(&self, retention: DiscoveryRetention) -> Result<ErasedOwner, AliasRefusal> {
        *self.seen.lock().expect("discovery observation lock") = Some(retention);
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(DiscoveryOwner {
            active: std::sync::Arc::clone(&self.active),
            released: std::sync::Arc::clone(&self.released),
        }))
    }

    fn retain_alias(
        &self,
        _key: &str,
        _peer: &str,
        _retention: AliasRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_peer(
        &self,
        _peer: &str,
        _retention: PeerRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_connection(
        &self,
        _peer: Option<&str>,
        _retention: ConnectionRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_connection_identity(
        &self,
        _peer: &str,
        _retention: ConnectionIdentityRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }
}

#[test]
fn advertised_profile_excludes_other_room_and_recipient() {
    use myownmesh_signaling::mdns::wire::{frame_is_for_us, Frame, PROTOCOL_VERSION};

    let frame = Frame {
        v: PROTOCOL_VERSION,
        room: "room-a".into(),
        from: "peer-a".into(),
        to: "device-b".into(),
        msg: SignalingMessage::Offer {
            peer_id: "device-b".into(),
            offer_id: "attempt-1".into(),
            sdp: "v=0".into(),
        },
    };
    assert!(frame_is_for_us(&frame, "room-a", "device-b", accept_any));
    assert!(!frame_is_for_us(&frame, "room-b", "device-b", accept_any));
    assert!(!frame_is_for_us(&frame, "room-a", "device-c", accept_any));
}

#[test]
fn discovery_hints_are_bounded_and_coalesced_per_service_instance() {
    use myownmesh_signaling::mdns::discovery::{ResolveCompletion, ResolveHint, ResolveOwnership};

    let max_owners = 256;
    let ownership = ResolveOwnership::with_max_owners(max_owners);
    let first = match ownership.admit("service-a") {
        ResolveHint::Started(lease) => lease,
        other => panic!("first service hint was not admitted: {other:?}"),
    };
    assert_eq!(first.instance(), "service-a");
    assert_eq!(ownership.active_count(), 1);
    assert_eq!(ownership.pending_count(), 0);
    assert!(matches!(
        ownership.admit("service-a"),
        ResolveHint::Coalesced
    ));
    assert!(matches!(
        ownership.admit("service-a"),
        ResolveHint::Coalesced
    ));
    assert_eq!(ownership.active_count(), 1);
    assert_eq!(ownership.pending_count(), 1);

    let followup = match first.complete() {
        ResolveCompletion::Followup(lease) => lease,
        ResolveCompletion::Finished => panic!("coalesced hint lost its follow-up"),
    };
    assert_eq!(ownership.active_count(), 1);
    assert_eq!(ownership.pending_count(), 0);
    assert!(matches!(followup.complete(), ResolveCompletion::Finished));
    assert_eq!(ownership.active_count(), 0);

    let mut leases = Vec::new();
    for index in 0..max_owners {
        match ownership.admit(format!("service-{index}")) {
            ResolveHint::Started(lease) => leases.push(lease),
            other => panic!("bounded service hint {index} was not admitted: {other:?}"),
        }
    }
    assert_eq!(ownership.active_count(), max_owners);
    assert!(matches!(
        ownership.admit("service-over-capacity"),
        ResolveHint::Refused
    ));
    ownership.shutdown();
    assert_eq!(ownership.active_count(), 0);
    assert_eq!(ownership.pending_count(), 0);
    drop(leases);
}

#[test]
fn discovery_hint_cancellation_fences_stale_service_instance_owners() {
    use myownmesh_signaling::mdns::discovery::{ResolveHint, ResolveOwnership};

    let ownership = ResolveOwnership::with_max_owners(1);
    let stale = match ownership.admit("service-replaced") {
        ResolveHint::Started(lease) => lease,
        other => panic!("stale service hint was not admitted: {other:?}"),
    };
    assert!(matches!(
        ownership.admit("service-replaced"),
        ResolveHint::Coalesced
    ));
    assert!(ownership.cancel("service-replaced"));
    assert_eq!(ownership.active_count(), 0);
    assert_eq!(ownership.pending_count(), 0);

    let dropped = match ownership.admit("service-dropped") {
        ResolveHint::Started(lease) => lease,
        other => panic!("dropped service hint was not admitted: {other:?}"),
    };
    assert!(matches!(
        ownership.admit("service-dropped"),
        ResolveHint::Coalesced
    ));
    drop(dropped);
    assert_eq!(ownership.active_count(), 0);
    assert_eq!(ownership.pending_count(), 0);

    let current = match ownership.admit("service-replaced") {
        ResolveHint::Started(lease) => lease,
        other => panic!("replacement service hint was not admitted: {other:?}"),
    };
    assert!(
        !stale.cancel(),
        "stale generation cancelled the replacement"
    );
    assert_eq!(ownership.active_count(), 1);

    ownership.shutdown();
    assert_eq!(ownership.active_count(), 0);
    assert_eq!(ownership.pending_count(), 0);
    assert!(!current.cancel(), "shutdown left a live resolve owner");
}

#[test]
fn concurrent_full_resolve_pressure_refuses_n_plus_one_before_owner_start() {
    use myownmesh_signaling::mdns::discovery::{ResolveHint, ResolveOwnership};
    use std::sync::Arc;

    const MAX_OWNERS: usize = 3;
    let ownership = Arc::new(ResolveOwnership::with_max_owners(MAX_OWNERS));
    let attempts = (0..=MAX_OWNERS)
        .map(|index| {
            let ownership = Arc::clone(&ownership);
            std::thread::spawn(move || ownership.admit(format!("concurrent-{index}")))
        })
        .collect::<Vec<_>>();
    let mut leases = Vec::new();
    let mut refused = 0;
    for attempt in attempts {
        match attempt.join().expect("resolve admission worker") {
            ResolveHint::Started(lease) => leases.push(lease),
            ResolveHint::Refused => refused += 1,
            ResolveHint::Coalesced => panic!("distinct concurrent keys cannot coalesce"),
        }
    }
    assert_eq!(leases.len(), MAX_OWNERS);
    assert_eq!(
        refused, 1,
        "the N+1 resolve is refused before an owner starts"
    );
    assert_eq!(ownership.active_count(), MAX_OWNERS);
    drop(leases);
    assert_eq!(
        ownership.active_count(),
        0,
        "all admitted resolve owners release their exact slots"
    );
}

#[test]
fn discovery_retention_maps_each_backend_and_refusal_is_pre_backend() {
    use myownmesh_signaling::mdns::discovery::DiscoveryLimits;
    use myownmesh_signaling::mdns::driver::{DiscoveryRetention, MdnsLimits};

    let limits = DiscoveryLimits {
        max_resolve_owners: 3,
        event_capacity: 5,
        max_event_epochs: 7,
        max_txt_entries: 8,
        max_txt_bytes: 512,
        max_resolved_addresses: 4,
    };
    let per_resolve = limits
        .max_txt_bytes
        .checked_add(
            limits
                .max_resolved_addresses
                .checked_mul(std::mem::size_of::<std::net::IpAddr>())
                .expect("address bytes fit"),
        )
        .expect("per-resolve bytes fit");
    let aggregate = limits
        .max_resolve_owners
        .checked_mul(per_resolve)
        .expect("concurrent resolve aggregate fits");
    assert_eq!(aggregate, limits.max_resolve_owners * per_resolve);

    let embedded = DiscoveryRetention::from_backend(limits, DiscoveryBackend::Embedded)
        .expect("valid embedded discovery budget");
    assert_eq!(embedded.event_queue_slots, limits.event_capacity * 2);
    assert_eq!(embedded.resolve_owner_slots, limits.max_resolve_owners);
    assert_eq!(embedded.event_epoch_slots, 0);
    assert_eq!(
        embedded.txt_entry_slots,
        limits.max_resolve_owners * limits.max_txt_entries
    );
    assert_eq!(embedded.txt_bytes, aggregate);
    assert_eq!(
        embedded.resolved_address_slots,
        limits.max_resolve_owners * limits.max_resolved_addresses
    );
    assert_eq!(embedded.backend_task_slots, 3);
    assert_eq!(embedded.native_worker_slots, 0);
    assert_eq!(embedded.scratch_bytes, aggregate);
    let embedded_plan = limits
        .checked_residency(DiscoveryBackend::Embedded)
        .expect("embedded residency plan");
    assert_eq!(
        embedded_plan.payload_owner_slots,
        limits.max_resolve_owners + 2 * limits.event_capacity
    );

    let system = DiscoveryRetention::from_backend(limits, DiscoveryBackend::System)
        .expect("valid system discovery budget");
    assert_eq!(system.event_queue_slots, limits.event_capacity);
    assert_eq!(system.resolve_owner_slots, limits.max_resolve_owners);
    assert_eq!(system.event_epoch_slots, limits.max_event_epochs);
    assert_eq!(
        system.txt_entry_slots,
        limits.max_resolve_owners * limits.max_txt_entries
    );
    assert_eq!(system.txt_bytes, aggregate);
    assert_eq!(
        system.resolved_address_slots,
        limits.max_resolve_owners * limits.max_resolved_addresses
    );
    assert_eq!(system.backend_task_slots, 0);
    assert_eq!(system.native_worker_slots, limits.max_resolve_owners + 2);
    assert_eq!(system.scratch_bytes, aggregate);
    let system_plan = limits
        .checked_residency(DiscoveryBackend::System)
        .expect("system residency plan");
    assert_eq!(
        system_plan.payload_owner_slots,
        limits.max_resolve_owners + limits.event_capacity
    );

    let retention = DiscoveryRetention::from_backend(limits, configured_backend())
        .expect("valid configured discovery budget");

    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let (_out_tx, out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (in_tx, _in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let driver_owner = driver_custodian();
    let backend_owner = backend_custodian(limits);
    let reaper_owner = reaper_custodian();
    let _custody = CustodianGuards(
        std::iter::once(driver_owner.clone())
            .chain(backend_owner.clone())
            .chain(std::iter::once(reaper_owner.clone()))
            .collect(),
    );
    let result = mdns::start_with_custodian(
        MdnsDriverConfig {
            app_id: "mdns-pre-backend-refusal".into(),
            network_id: "pressure".into(),
            device_id: "device-a".into(),
            service_port: 0,
            device_id_validator: accept_any,
            alias_provider: std::sync::Arc::new(DiscoveryRefusalProvider {
                seen: std::sync::Arc::clone(&seen),
            }),
            limits: MdnsLimits {
                discovery: limits,
                ..MdnsLimits::default()
            },
        },
        Box::new(UnboundedSource::new(out_rx)),
        InboundSink::from_unbounded(in_tx),
        driver_owner.clone(),
        backend_owner.clone(),
        reaper_owner.clone(),
    );
    assert!(
        result.is_err(),
        "the provider refuses before backend startup"
    );
    assert_eq!(
        *seen.lock().expect("discovery observation lock"),
        Some(retention),
        "the provider sees the complete backend envelope before bind/start"
    );
}

#[tokio::test]
async fn live_driver_releases_discovery_provider_baseline_after_stop() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let released = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (_out_tx, out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (in_tx, _in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let driver_owner = driver_custodian();
    let backend_owner = backend_custodian(MdnsLimits::default().discovery);
    let reaper_owner = reaper_custodian();
    let _custody = CustodianGuards(
        std::iter::once(driver_owner.clone())
            .chain(backend_owner.clone())
            .chain(std::iter::once(reaper_owner.clone()))
            .collect(),
    );
    let driver = mdns::start_with_custodian(
        MdnsDriverConfig {
            app_id: "mdns-provider-baseline".into(),
            network_id: format!("baseline-{}", std::process::id()),
            device_id: "device-a".into(),
            service_port: 0,
            device_id_validator: accept_any,
            alias_provider: std::sync::Arc::new(RecordingDiscoveryProvider {
                seen: std::sync::Arc::clone(&seen),
                active: std::sync::Arc::clone(&active),
                released: std::sync::Arc::clone(&released),
            }),
            limits: MdnsLimits::default(),
        },
        Box::new(UnboundedSource::new(out_rx)),
        InboundSink::from_unbounded(in_tx),
        driver_owner.clone(),
        backend_owner.clone(),
        reaper_owner.clone(),
    );
    let driver = driver.expect("live mDNS backend must start for custody control");
    assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(released.load(std::sync::atomic::Ordering::SeqCst), 0);
    driver.stop_and_join().await;
    assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        released.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "startup or joined shutdown releases the one discovery owner"
    );
    assert_eq!(
        *seen.lock().expect("discovery observation lock"),
        Some(
            DiscoveryRetention::from_backend(
                MdnsLimits::default().discovery,
                configured_backend(),
            )
            .expect("default configured discovery budget")
        )
    );
}

#[test]
fn aliases_keep_a_peer_live_until_its_final_service_key_withdraws() {
    use myownmesh_signaling::mdns::AliasOwnership;

    let mut aliases = AliasOwnership::default();
    assert_eq!(
        aliases
            .bind("if-a".into(), "peer-a".into(), 1, Box::new(()))
            .unwrap(),
        None
    );
    assert_eq!(
        aliases
            .bind("if-b".into(), "peer-a".into(), 2, Box::new(()))
            .unwrap(),
        None
    );
    assert_eq!(aliases.alias_count("peer-a"), 2);
    assert_eq!(aliases.remove("if-a", 1), Some(("peer-a".into(), false)));
    assert_eq!(aliases.alias_count("peer-a"), 1);
    assert_eq!(aliases.remove("if-b", 2), Some(("peer-a".into(), true)));
    assert_eq!(aliases.alias_count("peer-a"), 0);
    assert_eq!(aliases.remove("if-b", 2), None);
}

#[test]
fn alias_replacement_withdraws_only_the_displaced_final_owner() {
    use myownmesh_signaling::mdns::AliasOwnership;

    let mut aliases = AliasOwnership::default();
    aliases
        .bind("shared".into(), "peer-old".into(), 1, Box::new(()))
        .unwrap();
    aliases
        .bind("other".into(), "peer-old".into(), 2, Box::new(()))
        .unwrap();
    assert_eq!(
        aliases
            .bind("shared".into(), "peer-new".into(), 3, Box::new(()))
            .unwrap(),
        None
    );
    assert_eq!(aliases.alias_count("peer-old"), 1);
    assert_eq!(aliases.alias_count("peer-new"), 1);
    assert_eq!(
        aliases.remove("shared", 1),
        None,
        "stale removal cannot delete successor"
    );
    assert_eq!(aliases.remove("other", 2), Some(("peer-old".into(), true)));
    assert_eq!(aliases.remove("shared", 3), Some(("peer-new".into(), true)));
}

#[test]
fn alias_provider_refusal_and_generation_fence_preserve_exact_state() {
    use myownmesh_signaling::mdns::driver::AliasOwnership;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let released = std::sync::Arc::new(AtomicUsize::new(0));
    let mut aliases = AliasOwnership::default();
    aliases
        .bind(
            "stable".into(),
            "canonical-peer".into(),
            7,
            Box::new(CountingOwner(std::sync::Arc::clone(&released))),
        )
        .unwrap();
    assert_eq!(aliases.alias_count("canonical-peer"), 1);

    // A provider refusal occurs before bind, so the existing entry is not
    // altered and its owner remains live.
    let refused = RefusingAliasProvider.retain_alias(
        "stable",
        "replacement-peer",
        AliasRetention {
            key_capacity: 6,
            peer_capacity: 16,
            node_bytes: 1,
        },
    );
    assert!(refused.is_err());
    assert_eq!(aliases.alias_count("canonical-peer"), 1);
    assert_eq!(released.load(Ordering::SeqCst), 0);

    // The old generation cannot remove a replacement; the replacement's
    // owner is released only by its exact generation.
    aliases
        .bind(
            "stable".into(),
            "replacement-peer".into(),
            8,
            Box::new(CountingOwner(std::sync::Arc::clone(&released))),
        )
        .unwrap();
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "displaced owner released once"
    );
    assert!(aliases.remove("stable", 7).is_none());
    assert_eq!(aliases.alias_count("replacement-peer"), 1);
    assert!(aliases.remove("stable", 8).is_some());
    assert_eq!(released.load(Ordering::SeqCst), 2);
}

async fn wait_for_announce(
    rx: &mut mpsc::UnboundedReceiver<MdnsInbound>,
    expect_peer: &str,
) -> Option<()> {
    loop {
        match timeout(DISCOVERY_GRACE, rx.recv()).await {
            Ok(Some(MdnsInbound::PeerAnnounced { device_id, .. })) if device_id == expect_peer => {
                return Some(());
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return None,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_drivers_discover_and_exchange() {
    let network = format!("mdns-driver-test-{}", std::process::id());

    let (a_out_tx, a_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (a_in_tx, mut a_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let (b_out_tx, b_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (b_in_tx, mut b_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();

    let a_in = InboundSink::from_unbounded(a_in_tx);
    let b_in = InboundSink::from_unbounded(b_in_tx);

    let a_owner = driver_custodian();
    let a_backend_owner = backend_custodian(MdnsLimits::default().discovery);
    let a_reaper_owner = reaper_custodian();
    let _a_custody = CustodianGuards(
        std::iter::once(a_owner.clone())
            .chain(a_backend_owner.clone())
            .chain(std::iter::once(a_reaper_owner.clone()))
            .collect(),
    );
    let a = match mdns::start_with_custodian(
        driver_config(&network, "device-a"),
        Box::new(UnboundedSource::new(a_out_rx)),
        a_in,
        a_owner.clone(),
        a_backend_owner.clone(),
        a_reaper_owner.clone(),
    ) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP mdns_driver test: driver A failed to start ({e}) — no mDNS here");
            return;
        }
    };
    let b_owner = driver_custodian();
    let b_backend_owner = backend_custodian(MdnsLimits::default().discovery);
    let b_reaper_owner = reaper_custodian();
    let _b_custody = CustodianGuards(
        std::iter::once(b_owner.clone())
            .chain(b_backend_owner.clone())
            .chain(std::iter::once(b_reaper_owner.clone()))
            .collect(),
    );
    let b = match mdns::start_with_custodian(
        driver_config(&network, "device-b"),
        Box::new(UnboundedSource::new(b_out_rx)),
        b_in,
        b_owner.clone(),
        b_backend_owner.clone(),
        b_reaper_owner.clone(),
    ) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP mdns_driver test: driver B failed to start ({e}) — no mDNS here");
            return;
        }
    };

    // Mutual discovery. If multicast is blocked in this environment,
    // neither side ever resolves the other — skip.
    if wait_for_announce(&mut a_in_rx, "device-b").await.is_none() {
        eprintln!(
            "SKIP mdns_driver test: no discovery within {DISCOVERY_GRACE:?} — \
             multicast appears unavailable in this environment"
        );
        return;
    }
    wait_for_announce(&mut b_in_rx, "device-a")
        .await
        .expect("B discovers A once A has discovered B");

    // Directed exchange: A offers B over the TCP exchange.
    let offer = SignalingMessage::Offer {
        peer_id: "device-a".into(),
        offer_id: "offer-1".into(),
        sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".into(),
    };
    a_out_tx
        .send(MdnsOutbound::DirectedToPeer {
            to: "device-b".into(),
            msg: offer.clone(),
        })
        .expect("outbound channel open");

    let got = loop {
        match timeout(DISCOVERY_GRACE, b_in_rx.recv()).await {
            Ok(Some(MdnsInbound::Message { from, msg })) => break (from, msg),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => panic!("offer never arrived over the mdns TCP exchange"),
        }
    };
    assert_eq!(got.0, "device-a");
    assert_eq!(got.1, offer);

    // Withdrawal: B leaves; A hears PeerLeft via the mDNS goodbye.
    b_out_tx.send(MdnsOutbound::Leave).expect("channel open");
    let left = loop {
        match timeout(DISCOVERY_GRACE, a_in_rx.recv()).await {
            Ok(Some(MdnsInbound::PeerLeft { device_id, .. })) => break device_id,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => panic!("goodbye never surfaced as PeerLeft"),
        }
    };
    assert_eq!(left, "device-b");

    a.stop_and_join().await;
    b.stop_and_join().await;
}
