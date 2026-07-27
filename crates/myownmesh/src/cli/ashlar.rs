//! `myownmesh ashlar` — answer an Ashlar program's `mesh` space.
//!
//! Ashlar has one boundary for everything outside its builtin set: a space
//! declares a capability, and how that capability is reached is a deployment
//! fact. The space named `mesh` — who else is on the private network this
//! machine joined — derives to *this* command, because a mesh daemon is
//! installed once per machine and shared by everything on it, not supplied by
//! whichever project wants a roster. So an Ashlar site gets the roster with no
//! binding file, no shim and no shared library: MyOwnMesh is already here.
//!
//! The protocol is JSON Lines on stdin/stdout, one object per line:
//!
//! ```text
//! → {"call":"peers","args":[]}
//! ← {"ok":[{"id":"…","label":"ada","here":true}]}
//! ← {"error":"connect daemon socket — is `myownmesh serve` running?"}
//! ```
//!
//! Five calls, and the shapes are Ashlar's — `mesh.Here` and `mesh.Peer` in
//! its `lib/mesh` — so a field renamed here is a fault at the Ashlar call
//! site, not a silently missing value:
//!
//! | call | answers |
//! |---|---|
//! | `here()` | `{ id, label, network, peers }` — this node and its mesh |
//! | `peers(…)` | `[{ id, label, here }]` — the roster |
//! | `enter(network, label)` | join that mesh (idempotent), then `here()` |
//! | `revision()` | a number that changes when the roster does |
//! | `reread()` | the same number, as the call Ashlar marks the change with |
//!
//! `revision` is separate from `reread` on purpose. Ashlar's reactive
//! annotation marks a collection changed on every call that carries it, so a
//! poll that always marked would re-render every connected page on a timer.
//! The poll asks `revision`, which marks nothing, and only calls `reread` when
//! the answer moved.
//!
//! What this command deliberately does NOT answer is `mesh.sites` — publishing
//! a local port to peers and reaching theirs. That needs a proxy able to carry
//! a TCP connection, which lives in AllMyStuff, and one binary claiming both
//! would make "the mesh is installed" and "sites can be published" the same
//! claim. A machine with only this one answers the roster perfectly well and
//! says so.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use myownmesh_core::NetworkConfig;

use myownmesh::control::{Request, Response};

/// The mesh every Ashlar site lands on unless it names its own. It matches the
/// default in Ashlar's `lib/mesh` (`mesh.Mesh.network`), so a program that
/// says nothing and a machine that was told nothing agree by construction.
pub const DEFAULT_ASHLAR_NETWORK: &str = "ashlar";

/// One request Ashlar sent across the boundary.
#[derive(serde::Deserialize)]
struct Call {
    call: String,
    #[serde(default)]
    args: Vec<Value>,
}

/// Read a line, answer a line, until stdin closes. Never exits non-zero for a
/// failed CALL: a fault crosses the boundary as `{"error": …}` and Ashlar
/// raises it at the call site with the message intact, which is more use than
/// a dead co-process and a broken pipe.
pub async fn run() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut state = Session::default();

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Call>(line) {
            Ok(call) => match state.dispatch(&call).await {
                Ok(value) => json!({ "ok": value }),
                Err(e) => json!({ "error": format!("{e:#}") }),
            },
            Err(e) => json!({ "error": format!("not a call envelope: {e}") }),
        };
        writeln!(stdout, "{answer}")?;
        stdout.flush()?;
    }
    Ok(())
}

/// What one worker remembers: which mesh this program asked for, and the last
/// roster it described. The daemon holds everything that matters — a restarted
/// worker rejoins the same mesh and sees the same peers.
#[derive(Default)]
struct Session {
    network: Option<String>,
    revision: u64,
    fingerprint: Option<String>,
}

impl Session {
    async fn dispatch(&mut self, call: &Call) -> Result<Value> {
        match call.call.as_str() {
            "here" => self.here().await,
            "peers" => Ok(Value::Array(self.peers().await?)),
            "enter" => {
                let network = text_arg(call, 0)?;
                let label = text_arg(call, 1)?;
                self.enter(&network, &label).await
            }
            "revision" | "reread" => {
                self.refresh().await?;
                Ok(json!(self.revision))
            }
            other => Err(anyhow!(
                "no such call: `{other}`. This command answers Ashlar's `mesh` \
                 space: here, peers, enter, revision, reread."
            )),
        }
    }

    /// The mesh in force: what `enter` was told, else the default area.
    fn network(&self) -> String {
        self.network
            .clone()
            .unwrap_or_else(|| DEFAULT_ASHLAR_NETWORK.to_string())
    }

    async fn here(&mut self) -> Result<Value> {
        let identity = roundtrip(&Request::IdentityShow).await?;
        let peers = self.peers().await.unwrap_or_default();
        Ok(json!({
            "id": field(&identity, "device_id"),
            "label": field(&identity, "label"),
            "network": self.network(),
            "peers": peers.len(),
        }))
    }

    /// The roster, in Ashlar's shape. A peer is `here` when app traffic can
    /// actually flow to it — `Active` or a topology-shelved link, which still
    /// carries a heartbeat. Every other status is known-but-not-reachable, and
    /// saying otherwise would put a live dot on a peer nothing can reach.
    async fn peers(&self) -> Result<Vec<Value>> {
        let network = self.network();
        let answer = roundtrip(&Request::PeersList {
            network: network.clone(),
        })
        .await?;
        let list = answer
            .get("peers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(list
            .iter()
            .map(|p| {
                let status = p.get("status").and_then(Value::as_str).unwrap_or("");
                json!({
                    "id": p.get("device_id").and_then(Value::as_str).unwrap_or("").to_string(),
                    "label": peer_label(p),
                    "here": matches!(status, "active" | "Active" | "shelved" | "Shelved"),
                })
            })
            .collect())
    }

    /// Join the named mesh, or confirm we already have. `NetworkAdd` is the
    /// daemon's idempotent join: a config it already holds is a no-op, so a
    /// program calling this on every start does not churn the network.
    async fn enter(&mut self, network: &str, label: &str) -> Result<Value> {
        let network = if network.trim().is_empty() {
            DEFAULT_ASHLAR_NETWORK.to_string()
        } else {
            network.trim().to_string()
        };
        if !label.trim().is_empty() {
            // A label failing to stick is not a reason to refuse the mesh:
            // the roster works with the id, and the name is cosmetic.
            let _ = roundtrip(&Request::IdentitySetLabel {
                label: label.trim().to_string(),
            })
            .await;
        }
        let joined = roundtrip(&Request::NetworksList)
            .await
            .ok()
            .and_then(|v| v.get("networks").and_then(Value::as_array).cloned())
            .unwrap_or_default()
            .iter()
            .any(|n| n.get("network_id").and_then(Value::as_str) == Some(network.as_str()));
        if !joined {
            let mut config = NetworkConfig::from_network_id(network.clone(), network.clone());
            config.label = label.trim().to_string();
            // Open and auto-approving, because a roster nobody can join is
            // not a roster: the point is that everyone running the program
            // sees everyone else without a human approving each arrival.
            //
            // That makes the mesh id itself the secret. `ashlar` — the shared
            // default — is a public square by design, fine for a demo and
            // wrong for anything private. An app that wants a mesh of its own
            // names one, and a name worth keeping private should be
            // unguessable: `myownmesh ctl networks id` mints one.
            config.auto_approve = true;
            roundtrip(&Request::NetworkAdd { config }).await?;
        }
        self.network = Some(network);
        self.fingerprint = None;
        self.here().await
    }

    /// Move the revision if — and only if — the roster is not what it was.
    async fn refresh(&mut self) -> Result<()> {
        let peers = self.peers().await?;
        let mut seen: BTreeMap<String, bool> = BTreeMap::new();
        for p in &peers {
            seen.insert(
                p.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
                p.get("here").and_then(Value::as_bool).unwrap_or(false),
            );
        }
        let fingerprint = seen
            .iter()
            .map(|(id, here)| format!("{id}:{here}"))
            .collect::<Vec<_>>()
            .join(",");
        if self.fingerprint.as_deref() != Some(fingerprint.as_str()) {
            self.fingerprint = Some(fingerprint);
            self.revision += 1;
        }
        Ok(())
    }
}

/// A peer's display name, falling back to its id: a roster row with an empty
/// name is a row nobody can act on.
fn peer_label(peer: &Value) -> String {
    let label = peer.get("label").and_then(Value::as_str).unwrap_or("").trim();
    if !label.is_empty() {
        return label.to_string();
    }
    peer.get("device_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn text_arg(call: &Call, index: usize) -> Result<String> {
    match call.args.get(index) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(anyhow!(
            "`{}` wants a text for argument {}, not {}",
            call.call,
            index + 1,
            other
        )),
        None => Err(anyhow!(
            "`{}` wants {} argument(s); it got {}",
            call.call,
            index + 1,
            call.args.len()
        )),
    }
}

/// One request to the daemon, unwrapped: an `ok:false` response becomes an
/// error carrying the daemon's own words, so the message Ashlar raises at the
/// call site is the one the daemon wrote.
async fn roundtrip(request: &Request) -> Result<Value> {
    let response: Response = crate::cli::ctl::roundtrip(request).await?;
    if !response.ok {
        return Err(anyhow!(response
            .error
            .unwrap_or_else(|| "the daemon refused without saying why".to_string())));
    }
    Ok(response.data.unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(name: &str, args: Vec<Value>) -> Call {
        Call {
            call: name.to_string(),
            args,
        }
    }

    #[test]
    fn the_default_mesh_is_the_one_ashlar_ships_with() {
        // Both sides default to the same name, so a program that says nothing
        // and a machine told nothing meet on the same area rather than on two
        // empty ones.
        assert_eq!(DEFAULT_ASHLAR_NETWORK, "ashlar");
        let s = Session::default();
        assert_eq!(s.network(), "ashlar");
    }

    #[test]
    fn a_peer_is_here_only_when_traffic_can_flow() {
        let rows = [
            (json!({"device_id": "a", "label": "ada", "status": "active"}), true),
            (json!({"device_id": "b", "label": "bo", "status": "shelved"}), true),
            (json!({"device_id": "c", "label": "cy", "status": "sighted"}), false),
            (json!({"device_id": "d", "label": "di", "status": "reconnecting"}), false),
            (json!({"device_id": "e", "label": "ed", "status": "pending_approval"}), false),
        ];
        for (peer, expected) in rows {
            let status = peer.get("status").and_then(Value::as_str).unwrap();
            let here = matches!(status, "active" | "Active" | "shelved" | "Shelved");
            assert_eq!(here, expected, "status {status} decides presence");
        }
    }

    #[test]
    fn an_unlabelled_peer_falls_back_to_its_id() {
        assert_eq!(peer_label(&json!({"device_id": "abc", "label": ""})), "abc");
        assert_eq!(peer_label(&json!({"device_id": "abc", "label": " ada "})), "ada");
        assert_eq!(peer_label(&json!({"label": "ada"})), "ada");
        assert_eq!(peer_label(&json!({})), "unknown");
    }

    #[test]
    fn a_bad_argument_is_named_rather_than_guessed() {
        let c = call("enter", vec![json!(7)]);
        let e = text_arg(&c, 0).unwrap_err().to_string();
        assert!(e.contains("wants a text"), "{e}");
        let e = text_arg(&call("enter", vec![]), 0).unwrap_err().to_string();
        assert!(e.contains("wants 1 argument"), "{e}");
    }

    #[tokio::test]
    async fn an_unknown_call_names_what_this_command_answers() {
        // The other half of the contract lives in AllMyStuff, so a program
        // that reaches for it here is told which names exist rather than
        // getting an empty answer that looks like "no sites".
        let mut s = Session::default();
        let e = s.dispatch(&call("nearby", vec![])).await.unwrap_err().to_string();
        assert!(e.contains("no such call"), "{e}");
        assert!(e.contains("here, peers, enter, revision, reread"), "{e}");
    }
}
