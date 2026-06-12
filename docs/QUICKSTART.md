# Quick start (embedder)

This guide walks through depending on `myownmesh-core` from your own
app: identity, joining a network, typed channels, RPC, and clean
shutdown.

If you just want a daemon to run on the box, install the binary
instead: `cargo install --path crates/myownmesh` then
`myownmesh serve`.

## 1. Dependencies

The library crates aren't on crates.io yet — pin them to a release
tag via git:

```toml
[dependencies]
myownmesh-core      = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.2.0" }
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.2.0" }  # only if you want the Nostr driver
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

`tag = "v0.2.0"` gets reproducible builds; switch to
`branch = "main"` if you're tracking the latest work. Both crates
resolve out of the same checkout because cargo dedupes git deps by
URL. See [`../RELEASE.md`](../RELEASE.md) for the published-artifact
catalogue.

## 2. Open the mesh

`Mesh::open` loads (or generates on first call) this device's
long-lived ed25519 identity from
`~/.myownmesh/.secrets/identity.json` and constructs the shared
WebRTC API.

```rust
use myownmesh_core::{Mesh, MeshConfig};

let mesh = Mesh::open(MeshConfig::default()).await?;
println!("device id: {}", mesh.identity().display_id());
```

The returned `MeshHandle` is cheap to clone — multiple subsystems in
your app can hold one.

## 3. Join a network

```rust
use myownmesh_core::{NetworkConfig, TopologyMode};

let net = mesh.join(NetworkConfig {
    id: "home".into(),                          // local config record id
    network_id: "my-cool-mesh".into(),          // wire-level rendezvous handle
    label: "Home mesh".into(),
    topology: TopologyMode::default(),          // Ring
    signaling: Default::default(),
    stun_servers: Default::default(),
    turn_servers: Default::default(),
    roster_path: None,
    auto_approve: false,
}).await?;
```

Then attach a signaling driver. For production, use Nostr:

```rust
let nostr_handle = myownmesh_core::engine::attach_nostr(&net.state());
```

For in-process testing (single-process app with multiple
`MeshHandle`s), use the local broker:

```rust
use myownmesh_signaling::local::LocalBroker;

let broker = LocalBroker::new();
myownmesh_core::engine::attach_local(&net.state(), &broker);
```

## 4. Subscribe to events

```rust
use myownmesh_core::{MeshEvent, PeerEvent};

let mut events = mesh.events();
tokio::spawn(async move {
    while let Ok(event) = events.recv().await {
        match event {
            MeshEvent::Peer(PeerEvent::Approved { device_id, label, .. }) => {
                println!("{label} ({device_id}) is now active");
            }
            MeshEvent::Peer(PeerEvent::Dropped { device_id, reason, .. }) => {
                println!("{device_id} gone: {reason:?}");
            }
            MeshEvent::Phase(p) => println!("phase: {p:?}"),
            MeshEvent::Diag(d) => tracing::debug!(?d),
            _ => {}
        }
    }
});
```

The full event surface lives in `myownmesh_core::events`. `PeerEvent`
carries every state transition the engine emits (`Sighted`,
`Authenticated`, `Approved`, `Shelved`, `Unshelved`,
`CapabilitiesChanged`, `Dropped`).

## 5. Typed channels

`Channel<T>` is a typed publish/subscribe channel keyed by name. The
same name on two peers binds their senders to receivers.

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Greeting { from: String, text: String }

let chan = net.channel::<Greeting>("greetings");

// Send to one peer
chan.send_to(&peer_id, &Greeting {
    from: "alice".into(),
    text: "hi bob".into(),
}).await?;

// Broadcast to every active peer
let delivered = chan.broadcast(&Greeting {
    from: "alice".into(),
    text: "hi everyone".into(),
}).await?;
println!("sent to {delivered} peers");

// Receive
let mut sub = chan.subscribe();
while let Some(Ok(msg)) = sub.recv().await {
    println!("{} says: {}", msg.from, msg.body.text);
}
```

## 6. RPC

Generic request/response over the same data channel as channels.
Handlers are registered by `method` name; callers invoke them with
opaque JSON payloads.

```rust
let rpc = net.rpc();

// Server side
rpc.serve("echo", |call| async move {
    Ok(myownmesh_core::RpcResponse::from_value(call.payload))
});

// Client side
let resp = rpc.call(
    &peer_id,
    "echo",
    serde_json::json!({ "hello": "world" }),
).await?;
println!("got back: {:?}", resp.body);
```

Streaming responses use `serve_stream` + `call_stream`:

```rust
use tokio::sync::mpsc;

rpc.serve_stream("count", |call| async move {
    let (tx, rx) = mpsc::channel(8);
    let n = call.payload.get("n").and_then(|v| v.as_u64()).unwrap_or(5);
    tokio::spawn(async move {
        for i in 0..n {
            let _ = tx.send(serde_json::json!({ "i": i })).await;
        }
    });
    Ok(rx)
});

let mut stream = rpc.call_stream(&peer_id, "count", serde_json::json!({"n": 3})).await?;
while let Some(chunk) = stream.recv().await {
    println!("{chunk:?}");
}
```

## 7. Roster

Per-network approved-peers list, persisted at
`~/.myownmesh/mesh/rosters/{network_id}.json`. Approved peers
auto-allow on reconnect without prompting.

```rust
net.roster_approve(&peer_id, "Alice's Laptop").await?;
let peers = net.roster_list().await?;
for entry in peers {
    println!("{}: {}", entry.device_id, entry.label);
}
net.roster_remove(&peer_id).await?;
```

`auto_approve = true` in `NetworkConfig` skips the user prompt for
new peers; the engine adds every authenticating peer to the roster
automatically. Useful for headless fleet members.

## 8. Topology

The selector is configured per-network and can be changed at runtime:

```rust
use myownmesh_core::TopologyMode;

// Default: ring with 3 preferred neighbors. `n_connect` caps how
// many peers get a WebRTC transport at all (preferred + warm
// standbys); peers beyond it are parked — tracked by signaling
// presence only. `None` = n_preferred + 2; `Some(0)` disables the cap.
net.set_topology(TopologyMode::Ring {
    n_preferred: Some(3),
    n_connect: None,
}).await?;

// Star with a fixed hub
net.set_topology(TopologyMode::Star {
    hub: hub_device_id.to_string(),
}).await?;

// Everyone connected to everyone
net.set_topology(TopologyMode::FullMesh).await?;
```

The engine re-runs the selector synchronously and emits
`Shelved` / `Unshelved` events for affected peers.

## 9. Clean shutdown

```rust
net.leave().await?;
```

`leave()` signals the driver to stop, tears down every peer session,
and aborts the event-fanout task. Subsequent calls on the same
`JoinedNetwork` will fail with `Error::Network`.

The `MeshHandle` itself doesn't need explicit cleanup — drop it.

## More

- `docs/PROTOCOL.md` — wire-level frame reference.
- `CONNECTION-ENGINE.md` — the 7-tier reconnection ladder, all
  tunables, every edge case.
- `examples/` — runnable demos.
- `tests/two_peer_handshake.rs` — the end-to-end integration test
  doubles as an executable spec for the full handshake stack.
