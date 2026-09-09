#![cfg(all(unix, feature = "transport-lab"))]

//! Two shipped-daemon opaque-pipe acceptance. JSON is used only to mint and
//! bind exact capabilities; application bodies cross the dedicated sockets as
//! length-prefixed raw bytes and are never base64 or codec values.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::Instant;

const NETWORK_CONFIG_ID: &str = "opaque-app";
const NETWORK_ID: &str = "opaque-two-daemon-acceptance";
const RESOURCE_GRANT: &str = "accounted_memory_bytes=8000000000,queued_bytes=8000000000,\
socket_or_handle=8000000000,native_transport_object=8000000000,\
worker_or_task=8000000000,callback_or_scheduled_work=8000000000,\
storage_bytes=8000000000,storage_object=8000000000,\
relay_or_provider_allocation=8000000000,parsing_or_cpu_work=8000000000,\
opaque_dependency_residual=8000000000";
const REALTIME_PROFILE: &str = r#"{
  "codecs":[
    {"kind":"video","payload_type":96,"mime":"video/H264","clock_rate":90000,"framing":"annex_b"},
    {"kind":"audio","payload_type":111,"mime":"audio/opus","clock_rate":48000,"channels":2,"framing":"whole"}
  ]
}"#;

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.into())
}

async fn bounded<T>(
    deadline: Instant,
    work: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let value = tokio::time::timeout_at(deadline, work)
        .await
        .map_err(|_| "daemon stage exceeded its original absolute deadline".to_owned())??;
    require(
        Instant::now() <= deadline,
        "daemon stage completed after its original absolute deadline",
    )?;
    Ok(value)
}

async fn start_relay() -> Result<myownmesh_signaling::server::SignalingServerHandle, String> {
    let limits = myownmesh_signaling::server::Limits::default();
    let slots = myownmesh_signaling::server::SignalingServer::required_task_custody_slots(&limits)
        .map_err(|error| format!("relay custody plan refused: {error}"))?;
    let owner = myownmesh_signaling::DedicatedTaskCustodian::new(slots)
        .map_err(|error| format!("relay task custodian refused: {error:?}"))?;
    myownmesh_signaling::server::SignalingServer::start_with_custodian(
        "127.0.0.1",
        0,
        limits,
        owner,
    )
    .await
    .map_err(|error| format!("self-hosted signaling relay failed: {error}"))
}

fn daemon_config(home: &Path, socket: PathBuf, relay_url: &str) -> myownmesh_core::MeshConfig {
    let mut network = myownmesh_core::NetworkConfig::from_network_id(NETWORK_CONFIG_ID, NETWORK_ID);
    network.label = NETWORK_CONFIG_ID.to_owned();
    network.auto_approve = true;
    network.stun_servers.clear();
    network.turn_servers.clear();
    network.application_transport = None;
    network.signaling = myownmesh_core::config::SignalingConfig {
        strategy: "nostr".to_owned(),
        mdns: false,
        servers: vec![relay_url.to_owned()],
        redundancy: 1,
        denylist: Vec::new(),
        public_fallback: false,
        ..Default::default()
    };
    network
        .validate()
        .expect("daemon opaque-flow network validates");
    let mut daemon = myownmesh_core::MeshConfig::default().daemon;
    daemon.control_socket = Some(socket);
    myownmesh_core::MeshConfig {
        identity_path: Some(home.join("identity.json")),
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon,
        networks: vec![network],
        ..Default::default()
    }
}

fn save_config(home: &Path, config: &myownmesh_core::MeshConfig) {
    std::env::set_var("MYOWNMESH_HOME", home);
    config.save().expect("persist isolated daemon config");
}

fn spawn_daemon(home: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_myownmesh"))
        .arg("serve")
        .env("MYOWNMESH_HOME", home)
        .env("MYOWNMESH_RESOURCE_GRANT", RESOURCE_GRANT)
        .env("MYOWNMESH_CONNECTOR_REALTIME_POLICY", "enabled")
        .env("MYOWNMESH_REALTIME_PROFILE", REALTIME_PROFILE)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shipped connector-capable daemon")
}

async fn connect_socket(path: &Path, deadline: Instant) -> Result<LocalSocketStream, String> {
    let name = path
        .to_fs_name::<GenericFilePath>()
        .map_err(|error| format!("invalid control socket name: {error}"))?;
    bounded(deadline, async move {
        loop {
            match LocalSocketStream::connect(name.clone()).await {
                Ok(stream) => return Ok(stream),
                Err(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
}

async fn write_json_line(
    stream: &mut LocalSocketStream,
    request: &Value,
    deadline: Instant,
) -> Result<(), String> {
    let mut encoded = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    encoded.push(b'\n');
    bounded(deadline, async {
        stream
            .write_all(&encoded)
            .await
            .map_err(|error| format!("write control request: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("flush control request: {error}"))
    })
    .await
}

async fn read_json_line(
    stream: &mut LocalSocketStream,
    deadline: Instant,
) -> Result<Value, String> {
    bounded(deadline, async {
        let mut line = String::new();
        BufReader::new(&mut *stream)
            .read_line(&mut line)
            .await
            .map_err(|error| format!("read control response: {error}"))?;
        let response: Value =
            serde_json::from_str(&line).map_err(|error| format!("decode response: {error}"))?;
        require(
            response.get("ok").and_then(Value::as_bool) == Some(true),
            format!("daemon refused request: {response}"),
        )?;
        Ok(response)
    })
    .await
}

async fn request(path: &Path, request: Value, deadline: Instant) -> Result<Value, String> {
    let mut stream = connect_socket(path, deadline).await?;
    write_json_line(&mut stream, &request, deadline).await?;
    read_json_line(&mut stream, deadline).await
}

async fn request_unchecked(
    path: &Path,
    request: Value,
    deadline: Instant,
) -> Result<Value, String> {
    let mut stream = connect_socket(path, deadline).await?;
    write_json_line(&mut stream, &request, deadline).await?;
    bounded(deadline, async {
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .map_err(|error| format!("read unchecked control response: {error}"))?;
        serde_json::from_str(&line).map_err(|error| format!("decode unchecked response: {error}"))
    })
    .await
}

fn opaque_change_request(
    network: &str,
    label: &[u8],
    client_id: &str,
    client_capability: &str,
    flow_capability: &str,
    direction: &str,
    mode: Value,
    max_unit_bytes: u32,
) -> Value {
    json!({
        "op":"opaque_flow_change",
        "network":network,
        "label":label,
        "client_id":client_id,
        "client_capability":client_capability,
        "flow_capability":flow_capability,
        "direction":direction,
        "mode":mode,
        "max_unit_bytes":max_unit_bytes
    })
}

fn require_refusal(
    response: &Value,
    expected_code: Option<&str>,
    operation: &'static str,
) -> Result<(), String> {
    require(
        response.get("ok").and_then(Value::as_bool) == Some(false),
        format!("{operation}: daemon unexpectedly accepted request: {response}"),
    )?;
    require(
        response.get("error").and_then(Value::as_str).is_some(),
        format!("{operation}: refusal has no error text: {response}"),
    )?;
    if let Some(expected_code) = expected_code {
        require(
            response.pointer("/data/code").and_then(Value::as_str) == Some(expected_code),
            format!("{operation}: refusal code changed: {response}"),
        )?;
    }
    Ok(())
}

async fn write_opaque_body(
    pipe: &mut LocalSocketStream,
    body: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    bounded(deadline, async {
        let body_len = u32::try_from(body.len())
            .map_err(|_| "opaque body length is not representable".to_owned())?;
        pipe.write_all(&body_len.to_le_bytes())
            .await
            .map_err(|error| format!("write opaque body length: {error}"))?;
        pipe.write_all(body)
            .await
            .map_err(|error| format!("write opaque body: {error}"))?;
        pipe.flush()
            .await
            .map_err(|error| format!("flush opaque body: {error}"))
    })
    .await
}

async fn read_opaque_body(
    pipe: &mut LocalSocketStream,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    bounded(deadline, async {
        let payload_len = pipe
            .read_u32_le()
            .await
            .map_err(|error| format!("read opaque payload length: {error}"))?
            as usize;
        let label_len = pipe
            .read_u8()
            .await
            .map_err(|error| format!("read opaque label length: {error}"))?
            as usize;
        require(
            payload_len >= 1 + label_len,
            "opaque inbound payload length is shorter than its label",
        )?;
        let mut label = vec![0; label_len];
        pipe.read_exact(&mut label)
            .await
            .map_err(|error| format!("read opaque label: {error}"))?;
        let mut body = vec![0; payload_len - 1 - label_len];
        pipe.read_exact(&mut body)
            .await
            .map_err(|error| format!("read opaque body: {error}"))?;
        Ok((label, body))
    })
    .await
}

async fn require_pipe_eof(
    pipe: &mut LocalSocketStream,
    deadline: Instant,
    operation: &'static str,
) -> Result<(), String> {
    let mut byte = [0u8; 1];
    let read = bounded(deadline, async {
        pipe.read(&mut byte)
            .await
            .map_err(|error| format!("{operation}: read pipe termination: {error}"))
    })
    .await?;
    require(
        read == 0,
        format!("{operation}: pipe emitted unexpected bytes"),
    )
}

async fn subscribe_client(
    path: &Path,
    deadline: Instant,
) -> Result<(LocalSocketStream, String, String), String> {
    let mut stream = connect_socket(path, deadline).await?;
    write_json_line(&mut stream, &json!({"op":"events_subscribe"}), deadline).await?;
    let response = read_json_line(&mut stream, deadline).await?;
    let data = response
        .get("data")
        .ok_or_else(|| "events subscription response has no data".to_owned())?;
    let id = data
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "events subscription has no string client_id".to_owned())?
        .to_owned();
    let sequence = id
        .strip_prefix('c')
        .filter(|suffix| !suffix.is_empty())
        .ok_or_else(|| format!("events subscription client_id is not canonical: {id}"))?
        .parse::<u64>()
        .map_err(|error| format!("events subscription client_id is invalid: {error}"))?;
    require(
        id == format!("c{sequence}"),
        format!("events subscription client_id is not canonical: {id}"),
    )?;
    let capability = data
        .get("client_capability")
        .and_then(Value::as_str)
        .ok_or_else(|| "events subscription has no client capability".to_owned())?
        .to_owned();
    Ok((stream, id, capability))
}

async fn identity(path: &Path, deadline: Instant) -> Result<String, String> {
    let response = request(path, json!({"op":"identity_show"}), deadline).await?;
    response
        .pointer("/data/device_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "identity response has no device_id".to_owned())
}

async fn wait_for_peer(path: &Path, peer: &str, deadline: Instant) -> Result<(), String> {
    bounded(deadline, async {
        loop {
            let response = request(
                path,
                json!({"op":"peers_list","network":NETWORK_CONFIG_ID}),
                deadline,
            )
            .await?;
            let ready = response
                .pointer("/data/peers")
                .and_then(Value::as_array)
                .is_some_and(|peers| {
                    peers.iter().any(|candidate| {
                        candidate.get("device_id").and_then(Value::as_str) == Some(peer)
                            && candidate.get("authenticated").and_then(Value::as_bool) == Some(true)
                    })
                });
            if ready {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

async fn open_pipe(
    path: &Path,
    request: Value,
    deadline: Instant,
) -> Result<LocalSocketStream, String> {
    let mut stream = connect_socket(path, deadline).await?;
    write_json_line(&mut stream, &request, deadline).await?;
    let response = read_json_line(&mut stream, deadline).await?;
    require(
        response
            .pointer("/data/opaque_pipe")
            .and_then(Value::as_bool)
            == Some(true),
        "opaque pipe acknowledgement is missing",
    )?;
    Ok(stream)
}

async fn reap(child: &mut Child, deadline: Instant) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|error| format!("inspect daemon process: {error}"))?
        .is_none()
    {
        child
            .start_kill()
            .map_err(|error| format!("stop daemon process: {error}"))?;
    }
    bounded(deadline, async {
        child
            .wait()
            .await
            .map(|_| ())
            .map_err(|error| format!("reap daemon process: {error}"))
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two shipped daemon processes and a native WebRTC session"]
async fn two_daemons_carry_non_utf8_application_bytes_without_json_codec() {
    let alice_home = tempfile::tempdir().expect("isolated Alice daemon home");
    let bob_home = tempfile::tempdir().expect("isolated Bob daemon home");
    let alice_socket = alice_home.path().join("private").join("daemon.sock");
    let bob_socket = bob_home.path().join("private").join("daemon.sock");
    let relay = start_relay()
        .await
        .expect("start self-hosted signaling relay");
    let relay_url = format!("ws://{}", relay.local_addr());
    save_config(
        alice_home.path(),
        &daemon_config(alice_home.path(), alice_socket.clone(), &relay_url),
    );
    save_config(
        bob_home.path(),
        &daemon_config(bob_home.path(), bob_socket.clone(), &relay_url),
    );
    let mut alice_daemon = spawn_daemon(alice_home.path());
    let mut bob_daemon = spawn_daemon(bob_home.path());

    let stage_deadline = Instant::now() + Duration::from_secs(60);
    let result: Result<(), String> = async {
        let alice_id = identity(&alice_socket, stage_deadline).await?;
        let bob_id = identity(&bob_socket, stage_deadline).await?;
        wait_for_peer(&alice_socket, &bob_id, stage_deadline).await?;
        wait_for_peer(&bob_socket, &alice_id, stage_deadline).await?;

        let (alice_events, alice_client, alice_capability) =
            subscribe_client(&alice_socket, stage_deadline).await?;
        let (bob_events, bob_client, bob_capability) =
            subscribe_client(&bob_socket, stage_deadline).await?;
        let label = vec![0, 0xff, b'a', b'p', b'p'];
        let inbound_opened = request(
            &bob_socket,
            json!({
                "op":"opaque_flow_open",
                "network":NETWORK_CONFIG_ID,
                "peer":alice_id,
                "label":label,
                "client_id":bob_client,
                "client_capability":bob_capability,
                "direction":"inbound",
                "mode":"reliable_ordered",
                "max_unit_bytes":1024
            }),
            stage_deadline,
        )
        .await?;
        let inbound_flow_capability = inbound_opened
            .pointer("/data/flow_capability")
            .and_then(Value::as_str)
            .ok_or_else(|| "inbound-first opaque open returned no flow capability".to_owned())?
            .to_owned();
        let opened = request(
            &alice_socket,
            json!({
                "op":"opaque_flow_open",
                "network":NETWORK_CONFIG_ID,
                "peer":bob_id,
                "label":label,
                "client_id":alice_client,
                "client_capability":alice_capability,
                "direction":"outbound",
                "mode":"reliable_ordered",
                "max_unit_bytes":1024
            }),
            stage_deadline,
        )
        .await?;
        let flow_capability = opened
            .pointer("/data/flow_capability")
            .and_then(Value::as_str)
            .ok_or_else(|| "opaque open returned no flow capability".to_owned())?
            .to_owned();
        let mut inbound = open_pipe(
            &bob_socket,
            json!({
                "op":"opaque_pipe",
                "direction":"inbound",
                "network":NETWORK_CONFIG_ID,
                "peer":alice_id,
                "client_id":bob_client,
                "client_capability":bob_capability
            }),
            stage_deadline,
        )
        .await?;
        let mut outbound = open_pipe(
            &alice_socket,
            json!({
                "op":"opaque_pipe",
                "direction":"outbound",
                "network":NETWORK_CONFIG_ID,
                "client_id":alice_client,
                "client_capability":alice_capability,
                "flow_capability":flow_capability
            }),
            stage_deadline,
        )
        .await?;

        let body = vec![0, 0xff, 0x80, b'{', b'\n', 0, 1, 2, 3];
        bounded(stage_deadline, async {
            let body_len = u32::try_from(body.len())
                .map_err(|_| "opaque fixture body length is not representable".to_owned())?;
            outbound
                .write_all(&body_len.to_le_bytes())
                .await
                .map_err(|error| format!("write opaque body length: {error}"))?;
            outbound
                .write_all(&body)
                .await
                .map_err(|error| format!("write opaque body: {error}"))?;
            outbound
                .flush()
                .await
                .map_err(|error| format!("flush opaque body: {error}"))
        })
        .await?;
        let (received_label, received_body) = bounded(stage_deadline, async {
            let payload_len = inbound
                .read_u32_le()
                .await
                .map_err(|error| format!("read opaque payload length: {error}"))?
                as usize;
            let label_len = inbound
                .read_u8()
                .await
                .map_err(|error| format!("read opaque label length: {error}"))?
                as usize;
            require(
                payload_len >= 1 + label_len,
                "opaque inbound payload length is shorter than its label",
            )?;
            let mut received_label = vec![0; label_len];
            inbound
                .read_exact(&mut received_label)
                .await
                .map_err(|error| format!("read opaque label: {error}"))?;
            let mut received_body = vec![0; payload_len - 1 - label_len];
            inbound
                .read_exact(&mut received_body)
                .await
                .map_err(|error| format!("read opaque body: {error}"))?;
            Ok((received_label, received_body))
        })
        .await?;
        require(
            received_label == label,
            "daemon changed the non-UTF8 flow label",
        )?;
        require(
            received_body == body,
            "daemon changed or decoded the opaque body",
        )?;

        // Every refusal below is before Change publication.  They exercise
        // authenticated client, network, exact flow capability, DTO identity,
        // representable bounds and reciprocal local-Inbound checks through the
        // shipped JSON operation, then one predecessor send proves that the
        // live flow was not replaced or retired.
        let max_plus_one =
            u32::try_from(myownmesh_core::realtime::MAX_APPLICATION_FLOW_BODY_BYTES + 1)
                .map_err(|_| "opaque max+1 is not representable".to_owned())?;
        let refused_changes = [
            (
                "change-wrong-client",
                opaque_change_request(
                    NETWORK_CONFIG_ID,
                    &label,
                    &alice_client,
                    "wrong-client-capability",
                    &flow_capability,
                    "outbound",
                    json!("reliable_ordered"),
                    32,
                ),
                None,
            ),
            (
                "change-wrong-flow",
                opaque_change_request(
                    NETWORK_CONFIG_ID,
                    &label,
                    &alice_client,
                    &alice_capability,
                    "wrong-flow-capability",
                    "outbound",
                    json!("reliable_ordered"),
                    32,
                ),
                None,
            ),
            (
                "change-wrong-network",
                opaque_change_request(
                    "wrong-network",
                    &label,
                    &alice_client,
                    &alice_capability,
                    &flow_capability,
                    "outbound",
                    json!("reliable_ordered"),
                    32,
                ),
                None,
            ),
            (
                "change-wrong-label",
                opaque_change_request(
                    NETWORK_CONFIG_ID,
                    b"other-label",
                    &alice_client,
                    &alice_capability,
                    &flow_capability,
                    "outbound",
                    json!("reliable_ordered"),
                    32,
                ),
                Some("flow_refused"),
            ),
            (
                "change-wrong-direction",
                opaque_change_request(
                    NETWORK_CONFIG_ID,
                    &label,
                    &alice_client,
                    &alice_capability,
                    &flow_capability,
                    "inbound",
                    json!("reliable_ordered"),
                    32,
                ),
                Some("flow_refused"),
            ),
            (
                "change-wrong-mode",
                opaque_change_request(
                    NETWORK_CONFIG_ID,
                    &label,
                    &alice_client,
                    &alice_capability,
                    &flow_capability,
                    "outbound",
                    json!({"partial_unordered":{"max_retransmits":0}}),
                    32,
                ),
                Some("flow_refused"),
            ),
            (
                "change-zero-ceiling",
                opaque_change_request(
                    NETWORK_CONFIG_ID,
                    &label,
                    &alice_client,
                    &alice_capability,
                    &flow_capability,
                    "outbound",
                    json!("reliable_ordered"),
                    0,
                ),
                Some("provider_configuration_invalid"),
            ),
            (
                "change-max-plus-one",
                opaque_change_request(
                    NETWORK_CONFIG_ID,
                    &label,
                    &alice_client,
                    &alice_capability,
                    &flow_capability,
                    "outbound",
                    json!("reliable_ordered"),
                    max_plus_one,
                ),
                Some("provider_configuration_invalid"),
            ),
        ];
        for (operation, change, expected_code) in refused_changes {
            let response = request_unchecked(&alice_socket, change, stage_deadline).await?;
            require_refusal(&response, expected_code, operation)?;
        }
        let local_inbound_change = request_unchecked(
            &bob_socket,
            opaque_change_request(
                NETWORK_CONFIG_ID,
                &label,
                &bob_client,
                &bob_capability,
                &inbound_flow_capability,
                "outbound",
                json!("reliable_ordered"),
                32,
            ),
            stage_deadline,
        )
        .await?;
        require_refusal(
            &local_inbound_change,
            Some("flow_refused"),
            "change-local-inbound",
        )?;
        let predecessor_body = b"predecessor-still-usable";
        write_opaque_body(&mut outbound, predecessor_body, stage_deadline).await?;
        let (predecessor_label, predecessor_received) =
            read_opaque_body(&mut inbound, stage_deadline).await?;
        require(
            predecessor_label == label && predecessor_received.as_slice() == predecessor_body,
            "a refused daemon Change mutated the predecessor flow",
        )?;

        let changed = request(
            &alice_socket,
            opaque_change_request(
                NETWORK_CONFIG_ID,
                &label,
                &alice_client,
                &alice_capability,
                &flow_capability,
                "outbound",
                json!("reliable_ordered"),
                32,
            ),
            stage_deadline,
        )
        .await?;
        require(
            changed
                .pointer("/data/flow_capability")
                .and_then(Value::as_str)
                == Some(flow_capability.as_str())
                && changed
                    .pointer("/data/max_unit_bytes")
                    .and_then(Value::as_u64)
                    == Some(32),
            "daemon Change acknowledgement replaced the capability or ceiling",
        )?;
        let changed_body = vec![0xc3; 32];
        write_opaque_body(&mut outbound, &changed_body, stage_deadline).await?;
        let (changed_label, changed_received) =
            read_opaque_body(&mut inbound, stage_deadline).await?;
        require(
            changed_label == label && changed_received == changed_body,
            "committed daemon Change did not deliver the exact new-limit body",
        )?;

        let above_changed_ceiling = vec![0xc4; 33];
        write_opaque_body(&mut outbound, &above_changed_ceiling, stage_deadline).await?;
        require_pipe_eof(
            &mut outbound,
            stage_deadline,
            "changed-ceiling-admission-refusal",
        )
        .await?;
        let mut fresh_outbound = open_pipe(
            &alice_socket,
            json!({
                "op":"opaque_pipe",
                "direction":"outbound",
                "network":NETWORK_CONFIG_ID,
                "client_id":alice_client,
                "client_capability":alice_capability,
                "flow_capability":flow_capability
            }),
            stage_deadline,
        )
        .await?;
        let fresh_body = b"fresh-after-limit-refusal";
        write_opaque_body(&mut fresh_outbound, fresh_body, stage_deadline).await?;
        let (fresh_label, fresh_received) = read_opaque_body(&mut inbound, stage_deadline).await?;
        require(
            fresh_label == label && fresh_received.as_slice() == fresh_body,
            "same capability did not remain usable after the refused oversized unit",
        )?;

        drop((outbound, fresh_outbound, inbound));
        let closed = request(
            &alice_socket,
            json!({
                "op":"opaque_flow_close",
                "client_id":alice_client,
                "client_capability":alice_capability,
                "flow_capability":flow_capability
            }),
            stage_deadline,
        )
        .await?;
        require(
            closed.pointer("/data/closed").and_then(Value::as_bool) == Some(true),
            "opaque close was not acknowledged after retirement",
        )?;
        let closed_change = request_unchecked(
            &alice_socket,
            opaque_change_request(
                NETWORK_CONFIG_ID,
                &label,
                &alice_client,
                &alice_capability,
                &flow_capability,
                "outbound",
                json!("reliable_ordered"),
                16,
            ),
            stage_deadline,
        )
        .await?;
        require_refusal(&closed_change, None, "change-closed-capability")?;
        drop((alice_events, bob_events));
        Ok(())
    }
    .await;

    let cleanup_deadline = Instant::now() + Duration::from_secs(20);
    let alice_reap = reap(&mut alice_daemon, cleanup_deadline).await;
    let bob_reap = reap(&mut bob_daemon, cleanup_deadline).await;
    let relay_stop = bounded(cleanup_deadline, async {
        relay
            .stop_and_wait()
            .await
            .map_err(|error| format!("stop signaling relay: {error}"))
    })
    .await;
    assert!(
        alice_reap.is_ok() && bob_reap.is_ok() && relay_stop.is_ok(),
        "daemon cleanup failed: alice={alice_reap:?} bob={bob_reap:?} relay={relay_stop:?}; result={result:?}"
    );
    assert!(
        result.is_ok(),
        "opaque daemon acceptance failed: {result:?}"
    );
}
