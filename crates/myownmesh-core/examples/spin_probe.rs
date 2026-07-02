//! On-device probe for the NanoKVM create_offer wedge: walks the exact wedge
//! window (Transport::new → open_peer(Offerer) → create_offer, i.e. also
//! set_local_description) in staged, timeout-guarded steps with a print at
//! every boundary, so the wedge — invisible in the daemon because nothing in
//! the window logs — names its own stage. Run on the device:
//!
//!   scp spin_probe root@<device>:/tmp/ && ssh root@<device> \
//!     'MYOWNMESH_MEDIA_LANES=1 /tmp/spin_probe'
//!
//! Stage D runs with empty ICE servers, stage F with the public-venue
//! STUN+TURN defaults (what the daemon actually passes) — if only F wedges,
//! the server-config path is implicated. Each stage has a 15 s timeout; a
//! TIMEOUT print plus a jiffies delta tells us whether the stage parked or
//! spun. Primitives are sanity-checked first so a codegen-level failure in
//! the arithmetic the window depends on would show before any webrtc code.
use std::time::Duration;

fn jiffies() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let f: Vec<&str> = stat.split_whitespace().collect();
    f.get(13).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
        + f.get(14).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
}

async fn staged<T, F: std::future::Future<Output = T>>(name: &str, fut: F) -> Option<T> {
    let j0 = jiffies();
    let t0 = std::time::Instant::now();
    match tokio::time::timeout(Duration::from_secs(15), fut).await {
        Ok(v) => {
            println!(
                "[probe] {name}: OK in {:?} (+{} jiffies)",
                t0.elapsed(),
                jiffies() - j0
            );
            Some(v)
        }
        Err(_) => {
            println!(
                "[probe] {name}: TIMEOUT after 15s (+{} jiffies — high=spin, ~0=parked)",
                jiffies() - j0
            );
            None
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // A. primitives the window depends on.
    let lz = 52u64.leading_zeros();
    println!("[probe] A1 leading_zeros(52u64) = {lz} (expect 58)");
    let wide = (u64::MAX as u128) * (52u128);
    println!(
        "[probe] A2 widening mul hi/lo = {:x}/{:x} (expect 33/ffffffffffffffcc)",
        (wide >> 64) as u64,
        wide as u64
    );
    let j0 = jiffies();
    let mut acc = 0usize;
    for _ in 0..1_000_000 {
        acc = acc.wrapping_add(rand::Rng::gen_range(&mut rand::thread_rng(), 0..52));
    }
    println!(
        "[probe] A3 1e6 x gen_range(0..52): acc={acc} (+{} jiffies)",
        jiffies() - j0
    );

    // B. transport (lane count from env, like the daemon).
    let Some(Ok(t)) = staged("B Transport::new", async {
        myownmesh_core::transport::Transport::new()
    })
    .await
    else {
        return;
    };

    // C+D. open_peer + create_offer with EMPTY ICE servers.
    if let Some(Ok((session, _rx))) = staged(
        "C open_peer(Offerer, no ICE servers)",
        t.open_peer(myownmesh_core::transport::Role::Offerer, &[], &[]),
    )
    .await
    {
        if let Some(Ok(offer)) =
            staged("D create_offer (no ICE servers)", session.create_offer()).await
        {
            println!("[probe] D sdp bytes = {}", offer.sdp.len());
        }
    }

    // E+F. the daemon's actual config: public-venue STUN + TURN defaults.
    let stun = myownmesh_core::config::default_stun_servers();
    let turn = myownmesh_core::config::default_turn_servers();
    if let Some(Ok((session, _rx))) = staged(
        "E open_peer(Offerer, public-venue STUN+TURN)",
        t.open_peer(myownmesh_core::transport::Role::Offerer, &stun, &turn),
    )
    .await
    {
        if let Some(Ok(offer)) = staged("F create_offer (STUN+TURN)", session.create_offer()).await
        {
            println!("[probe] F sdp bytes = {}", offer.sdp.len());
        }
    }

    // G. idle burn: any spinner left behind by the stages above shows here.
    let j0 = jiffies();
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!(
        "[probe] G idle burn over 5s = {} jiffies (>400 means a task is spinning)",
        jiffies() - j0
    );
    println!("[probe] done");
}
