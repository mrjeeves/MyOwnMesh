# Quick start (embedder)

This guide walks through depending on `myownmesh-core` from your own
app: identity, joining a network, typed channels, RPC, and clean
shutdown.

If you just want a daemon to run on the box, install the binary
instead: `cargo install --path crates/myownmesh` then
`myownmesh serve`.

## 1. Dependencies

Depend on the exact `myownmesh-core` release tag selected for your deployment.
The repository tag is the source distribution; replace `vX.Y.Z` below with the
chosen tag:

```toml
[dependencies]
myownmesh-core = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "vX.Y.Z" }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

For a workspace checkout, use the corresponding path dependencies instead.

## 2. Open the mesh

`Mesh::open_connector_capable` loads (or generates on first call) this device's
long-lived ed25519 identity from `~/.myownmesh/.secrets/identity.json` and
constructs the shared WebRTC API with the caller's explicit connector policy.
Use `Mesh::open_infrastructure_only` only for a runtime that does not join a
network.

```rust
use myownmesh_core::{Mesh, MeshConfig, WebRtcConnectorCapablePolicy};

let mesh = Mesh::open_connector_capable(
    MeshConfig::default(),
    connector_policy,
).await?;
println!("device id: {}", mesh.identity().display_id());
```

The connector-capable constructor takes an explicit provider policy. Resource
ownership and transport admission stay inside the runtime; applications do not
need to reproduce internal resource formulas in this guide.

The returned `MeshHandle` is cheap to clone. Multiple subsystems in
your app can hold one.

## 3. Join a network

```rust
use myownmesh_core::{NetworkConfig, NetworkKind, TopologyMode};

let net = mesh.join(NetworkConfig {
    id: "home".into(),                          // local config record id
    network_id: "my-cool-mesh".into(),          // wire-level rendezvous handle
    label: "Home mesh".into(),
    kind: NetworkKind::Open,
    topology: TopologyMode::default(),          // FullMesh
    signaling: Default::default(),
    stun_servers: Default::default(),
    turn_servers: Default::default(),
    pinned_peers: Vec::new(),
    auto_approve: false,
}).await?;
```

Then attach a signaling driver. For a configured carrier, use the joined
network's typed attach method:

```rust
let _drivers = net.attach_signaling()?;
```

`LocalBroker` is a `transport-lab`-only control seam, not an advertised
production carrier. When compiling an integration control with that feature,
it still traverses the bounded ingress, authentication, and promotion path:

```rust
use myownmesh_core::LocalBroker;

let broker = LocalBroker::new();
net.attach_local(&broker);
```

For example, run the maintained two-peer control with:

```bash
cargo test -p myownmesh-core --features transport-lab --test two_peer_handshake -- --nocapture
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
let mut sub = chan.subscribe()?;
while let Some(Ok(msg)) = sub.recv().await {
    println!("{} says: {}", msg.from(), msg.body().text);
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
})?;

// Client side
let resp = rpc.call(
    &peer_id,
    "echo",
    serde_json::json!({ "hello": "world" }),
).await?;
println!("got back: {:?}", resp.body);
```

Streaming responses use the resource-backed `serve_stream` and `call_stream`
APIs. Their handler returns the core crate's funded mailbox receiver, so a
plain Tokio `mpsc::Receiver` is not a replacement.

## 7. Governance

Runtime authority is represented by signed semantic facts. Use the named
proposal methods on `JoinedNetwork`; do not mutate a roster as a substitute for
granting, revoking, or evicting a device.

```rust
use myownmesh_core::semantic::Role;

let grant_id = net
    .propose_role_grant(&peer_id, Role::Member, None)
    .await?;
let revoke_id = net.propose_role_revoke(&peer_id, None).await?;
let eviction_id = net.propose_evict(&peer_id, None).await?;
println!("grant={grant_id}, revoke={revoke_id}, eviction={eviction_id}");
```

Each method returns the resulting semantic `FactId` after the current
authority and exact network context have been checked. The optional MFA value
is passed as the final argument when the deployment requires it.

The base ledger is durable Closed authority/governance only. Open networks
have zero base durable semantic facts: an exact-context handshake and Device
key possession authenticate ephemeral participation. Join, leave, presence,
and reconnect are runtime observations for both Open and Closed and never
become semantic history. The owner-selected ledger limits (fact count, bytes,
causal edges, per-author usage, proof work, and indexed database bytes) are
checked before mutation; the exact `N+1` request is refused without changing
the graph, projection, ACK, identity, or authority.

## 8. Direct connections and TURN

Application channels, RPC and native opaque flows use authenticated WebRTC
connections between the actual endpoints. ICE uses a direct path when viable
and configured TURN when a relay is needed. A Hub may introduce endpoints but
never forwards their application payloads.

Configure `NetworkConfig.turn_servers` using `TurnServer` with `urls`,
`username` and `credential`. The existing reference TURN default applies when
the field is omitted; an explicit empty list disables TURN. Hosting TURN is a
separate opt-in device service described in [Services](SERVICES.md). Service
advertisements contain URLs, not passwords; credentials remain local config.

For bounded Hub-assisted connection setup, set `NetworkConfig.introduction`
to `Some(HubIntroductionPolicyConfig { ... })` with owner-selected setup and
demand limits. Removed `closed_relay`, `application_transport` and
`routing_policy` keys are rejected. No application bytes are carried by
discovery or signaling.

## 9. Topology

The selector is configured per-network and can be changed at runtime:

```rust
use myownmesh_core::TopologyMode;

// Default: ring with 3 preferred neighbors
net.set_topology(TopologyMode::Ring { n_preferred: Some(3) }).await?;

// Star with a fixed hub
net.set_topology(TopologyMode::Star {
    hub: hub_device_id.to_string(),
}).await?;

// Everyone connected to everyone
net.set_topology(TopologyMode::FullMesh).await?;
```

The engine re-runs the selector synchronously and emits
`Shelved` / `Unshelved` events for affected peers.

## 10. Clean shutdown

```rust
net.leave().await?;
```

`leave()` signals the driver to stop, tears down every peer session,
and stops the event-fanout task. Use `shutdown()` when shared ownership means
the handle cannot be consumed; it is idempotent and awaits driver retirement.

The `MeshHandle` itself doesn't need explicit cleanup. Drop it.

## More

- [`PROTOCOL.md`](PROTOCOL.md): wire-level frame reference.
- `../crates/myownmesh-core/examples/`: runnable demos.
- `../crates/myownmesh-core/tests/two_peer_handshake.rs`: the end-to-end integration test
  doubles as an executable spec for the full handshake stack.
