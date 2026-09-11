//! Minimal single-threaded reproduction of the create_offer wedge, for
//! debugger PC-sampling under qemu-user: one guest thread, current-thread
//! tokio runtime, straight into the wedge path.
fn callback_grant() -> myownmesh_core::TransportLabCallbackGrant {
    let raw = std::env::var("MYOWNMESH_LAB_CALLBACK_CAPACITY")
        .expect("set MYOWNMESH_LAB_CALLBACK_CAPACITY for this transport-lab probe");
    let capacity = std::num::NonZeroUsize::new(
        raw.parse::<usize>()
            .expect("MYOWNMESH_LAB_CALLBACK_CAPACITY must be an integer"),
    )
    .expect("MYOWNMESH_LAB_CALLBACK_CAPACITY must be nonzero");
    // This probe opens a peer on a transport with no connector resource policy,
    // so the connector mints its own finite provider from this grant. Every
    // number here is a probe input stated by the probe; none is a product limit
    // and none is derived from a policy.
    myownmesh_core::TransportLabCallbackGrant {
        control_slots: capacity,
        endpoint_slots: capacity,
        control_payload_bytes: std::num::NonZeroUsize::new(4_096)
            .expect("the probe control payload ceiling is nonzero"),
        endpoint_payload_bytes: std::num::NonZeroUsize::new(4_096)
            .expect("the probe endpoint payload ceiling is nonzero"),
        // The reserved open and close plus the three pending observations this
        // probe can produce. Stated here for the same reason every other number
        // in this grant is.
        observation_slots: std::num::NonZeroUsize::new(5)
            .expect("the probe lifecycle slot count is nonzero"),
    }
}

fn callback_policy() -> myownmesh_core::ConnectorCallbackPolicy {
    myownmesh_core::ConnectorCallbackPolicy::elastic_data_only()
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let t = myownmesh_core::transport::Transport::new().unwrap();
        let (session, _rx) = myownmesh_core::engine::transport_lab::open_peer(
            &t,
            myownmesh_core::transport::Role::Offerer,
            &[],
            &[],
            callback_policy(),
            callback_grant(),
        )
        .await
        .unwrap();
        eprintln!("[min] entering create_offer");
        let offer = session.create_offer().await.unwrap();
        eprintln!("[min] create_offer done: {} sdp bytes", offer.sdp.len());
    });
}
