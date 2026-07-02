//! Minimal single-threaded reproduction of the create_offer wedge, for
//! debugger PC-sampling under qemu-user: one guest thread, current-thread
//! tokio runtime, straight into the wedge path.
fn main() {
    std::env::set_var("MYOWNMESH_MEDIA_LANES", "0");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let t = myownmesh_core::transport::Transport::new().unwrap();
        let (session, _rx) = t
            .open_peer(myownmesh_core::transport::Role::Offerer, &[], &[])
            .await
            .unwrap();
        eprintln!("[min] entering create_offer");
        let offer = session.create_offer().await.unwrap();
        eprintln!("[min] create_offer done: {} sdp bytes", offer.sdp.len());
    });
}
