#!/usr/bin/env python3
"""Exercise the shipped daemon's public service and transport controls.

This runner starts three real ``myownmesh serve`` processes: two mesh nodes and
one infrastructure-only service host.  It enables the host's STUN/TURN
listeners through the public control socket, waits for authenticated peers,
exchanges typed channel payloads in both directions, reconnects the network,
and stops/restarts both listeners on their exact configured ports.

The ICE pair reported by ``peers_list`` is the only transport classification
accepted here.  A TURN URL in configuration is not evidence that TURN was
selected.  Use ``--expect-pair turn`` only on a deployment whose public
signaling/NAT topology can actually force a relay; otherwise the manifest
records that TURN selection was not available from this local direct run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import select
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO


RESOURCE_GRANT = "MYOWNMESH_RESOURCE_GRANT"
REALTIME_POLICY = "MYOWNMESH_CONNECTOR_REALTIME_POLICY"
CHANNEL = "service-transport-e2e"
CONTROL_LINE_LIMIT = 8 * 1024 * 1024
GRANT_DIMENSIONS = (
    "accounted_memory_bytes",
    "queued_bytes",
    "socket_or_handle",
    "native_transport_object",
    "worker_or_task",
    "callback_or_scheduled_work",
    "storage_bytes",
    "storage_object",
    "relay_or_provider_allocation",
    "parsing_or_cpu_work",
    "opaque_dependency_residual",
)


class ContractError(RuntimeError):
    """A bounded harness contract was refused or could not be observed."""


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def finite_grant_dimensions(raw: str) -> dict[str, int]:
    """Parse the exact finite grant grammar consumed by ``serve``.

    The runner never invents a grant or replaces a zero with a default.  This
    check catches an incomplete harness environment before any process starts;
    the daemon remains the authority for the actual resource admission.
    """

    values: dict[str, int] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item or "=" not in item:
            raise ContractError(f"{RESOURCE_GRANT} contains malformed entry {item!r}")
        name, amount = (part.strip() for part in item.split("=", 1))
        if name not in GRANT_DIMENSIONS:
            raise ContractError(f"{RESOURCE_GRANT} names unknown dimension {name!r}")
        if name in values:
            raise ContractError(f"{RESOURCE_GRANT} names dimension {name!r} twice")
        try:
            parsed = int(amount, 10)
        except ValueError as error:
            raise ContractError(f"{RESOURCE_GRANT} dimension {name!r} is not an integer") from error
        if not 0 <= parsed <= 2**64 - 1:
            raise ContractError(f"{RESOURCE_GRANT} dimension {name!r} is outside the daemon's u64 range")
        values[name] = parsed
    missing = [name for name in GRANT_DIMENSIONS if name not in values]
    if missing:
        raise ContractError(f"{RESOURCE_GRANT} omits dimensions: {', '.join(missing)}")
    return values


def read_json_line(reader: BinaryIO, limit: int = CONTROL_LINE_LIMIT) -> Any:
    line = reader.readline(limit + 1)
    if not line:
        raise ContractError("control socket closed before a complete JSON line")
    if len(line) > limit or not line.endswith(b"\n"):
        raise ContractError("control response exceeded harness line ceiling")
    try:
        return json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"control response was not valid JSON: {error}") from error


def request(control_socket: Path, body: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(str(control_socket))
        stream.sendall(encoded)
        with stream.makefile("rb") as reader:
            response = read_json_line(reader)
    if not isinstance(response, dict):
        raise ContractError(f"control response is not an object for {body.get('op')}")
    if response.get("ok") is not True:
        raise ContractError(f"control {body.get('op')} refused: {response.get('error')}")
    return response


def open_event_subscription(control_socket: Path) -> tuple[socket.socket, BinaryIO, str, str]:
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(5.0)
    try:
        stream.connect(str(control_socket))
        stream.sendall(b'{"op":"events_subscribe"}\n')
        reader = stream.makefile("rb")
        ack = read_json_line(reader)
        if not isinstance(ack, dict) or ack.get("ok") is not True:
            raise ContractError(f"events_subscribe refused: {ack!r}")
        data = ack.get("data") or {}
        client_id = data.get("client_id")
        capability = data.get("client_capability")
        canonical = (
            isinstance(client_id, str)
            and client_id.startswith("c")
            and client_id[1:].isdigit()
            and str(int(client_id[1:])) == client_id[1:]
        )
        if not canonical or not isinstance(capability, str) or not capability:
            raise ContractError("events_subscribe returned no canonical client authority")
        stream.setblocking(False)
        return stream, reader, client_id, capability
    except BaseException:
        stream.close()
        raise


def next_event(
    stream: socket.socket, reader: BinaryIO, deadline: float
) -> dict[str, Any] | None:
    """Read one event without an unbounded socket wait."""

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    # A quiet subscription must not starve the other direction.  The overall
    # deadline remains owner-selected; this is only a bounded interleave slice.
    ready, _, _ = select.select([stream], [], [], min(remaining, 0.25))
    if not ready:
        return None
    value = read_json_line(reader)
    if not isinstance(value, dict):
        raise ContractError("event stream emitted a non-object frame")
    return value


def wait_until(label: str, timeout: float, probe: Any) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        try:
            value = probe()
            if value:
                return value
            last = value
        except (OSError, ValueError, ContractError) as error:
            last = repr(error)
        time.sleep(0.25)
    raise ContractError(f"timed out waiting for {label}; last observation: {last!r}")


def peers(control_socket: Path, network: str) -> list[dict[str, Any]]:
    data = request(control_socket, {"op": "peers_list", "network": network}).get("data") or {}
    value = data.get("peers") or []
    if not isinstance(value, list):
        raise ContractError("peers_list returned a non-list peers field")
    return [peer for peer in value if isinstance(peer, dict)]


def active_peer(control_socket: Path, network: str) -> dict[str, Any] | None:
    for peer in peers(control_socket, network):
        if peer.get("status") == "active" and peer.get("authenticated") is True:
            return peer
    return None


def endpoint_status(status_response: dict[str, Any], service: str) -> dict[str, Any]:
    data = status_response.get("data") or {}
    status = data.get("status") or {}
    endpoint = status.get(service)
    if not isinstance(endpoint, dict):
        raise ContractError(f"services_status omitted status.{service}")
    return endpoint


def endpoint_port(endpoint: dict[str, Any]) -> int:
    listen = endpoint.get("listen")
    if not isinstance(listen, str) or ":" not in listen:
        raise ContractError(f"service status has no parseable listener address: {endpoint!r}")
    try:
        return int(listen.rsplit(":", 1)[1])
    except ValueError as error:
        raise ContractError(f"service status has an invalid listener port: {listen!r}") from error


def set_hosted_services(control_socket: Path, stun: bool, turn: bool) -> dict[str, Any]:
    current = request(control_socket, {"op": "services_status"})
    config = (current.get("data") or {}).get("config")
    if not isinstance(config, dict):
        raise ContractError("services_status omitted the persisted config")
    services = json.loads(json.dumps(config))
    for name, enabled in (("node", False), ("signaling", False), ("stun", stun), ("turn", turn)):
        section = services.get(name)
        if not isinstance(section, dict):
            raise ContractError(f"services config omitted {name}")
        section["enabled"] = enabled
    return request(control_socket, {"op": "services_set", "services": services})


def udp_port_is_free(bind_host: str, port: int) -> None:
    """Prove the awaited service stop released the exact configured port."""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind((bind_host, port))
        except OSError as error:
            raise ContractError(f"UDP listener {bind_host}:{port} remained owned: {error}") from error


def pair_class(peer: dict[str, Any]) -> str | None:
    pair = peer.get("selected_pair")
    if not isinstance(pair, dict):
        return None
    local = pair.get("local")
    remote = pair.get("remote")
    if local == "relay" or remote == "relay":
        return "turn"
    if local in {"server_reflexive", "peer_reflexive"} or remote in {
        "server_reflexive",
        "peer_reflexive",
    }:
        return "stun"
    if local == "host" and remote == "host":
        return "direct"
    return "unknown"


def semantic_policy() -> dict[str, int]:
    return {
        "max_fact_encoded_bytes": 65_535,
        "max_dependencies_per_fact": 64,
        "max_authority_uses_per_fact": 32,
        "max_authority_predecessors_per_use": 64,
        "max_admitted_facts": 100_000,
        "max_admitted_bytes": 128 * 1024 * 1024,
        "max_quarantined_facts": 4_096,
        "max_quarantined_bytes": 16 * 1024 * 1024,
        "max_quarantined_facts_per_author": 256,
        "max_quarantined_bytes_per_author": 4 * 1024 * 1024,
        "max_retained_facts_per_author": 10_000,
        "max_retained_bytes_per_author": 16 * 1024 * 1024,
        "max_dependency_edges": 1_000_000,
        "max_ready_batch": 256,
        "max_pending_proofs": 10_000,
        "max_pending_proof_bytes": 16 * 1024 * 1024,
        "max_proof_records": 100_000,
        "max_proof_bytes": 64 * 1024 * 1024,
        "max_proof_links": 100_000,
        "max_author_usage_rows": 100_000,
        "max_provisional_rows": 100_000,
        "max_transaction_dirty_main_pages": 1_024,
        "max_uncheckpointed_wal_frames": 1_018,
        "max_freelist_pages": 1_024,
        "max_fragmented_pages": 1_024,
        "max_main_journal_bytes": 8 * 1024 * 1024,
        "max_database_bytes": 2 * 1024 * 1024 * 1024,
        "max_wal_bytes": 8_413_072,
        "wal_checkpoint_threshold_bytes": 32 + 1_018 * (4_096 + 24),
        "emergency_reserve_bytes": 8 * 1024 * 1024,
    }


def daemon_config(
    network: str,
    service_host: str,
    stun_port: int,
    turn_port: int,
    signaling_url: str | None,
    service_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if signaling_url:
        signaling = {
            "strategy": "nostr",
            "mdns": False,
            "servers": [signaling_url],
            "redundancy": 1,
            "denylist": [],
            "public_fallback": False,
        }
    else:
        signaling = {
            "strategy": "none",
            "mdns": True,
            "servers": [],
            "redundancy": 1,
            "denylist": [],
            "public_fallback": False,
        }
    return {
        "version": 2,
        "event_capacity": 128,
        "services": service_config or {"node": {"enabled": True}},
        "networks": [
            {
                "id": network,
                "network_id": network,
                "label": "service-transport-e2e",
                "event_capacity": 128,
                "connection_trace_capacity": 128,
                "kind": "open",
                "semantic_policy": semantic_policy(),
                "signaling": signaling,
                "stun_servers": [{"urls": [f"stun:{service_host}:{stun_port}"]}],
                "turn_servers": [
                    {
                        "urls": [f"turn:{service_host}:{turn_port}?transport=udp"],
                        "username": "e2e",
                        "credential": "e2e-password",
                    }
                ],
                "pinned_peers": [],
                "auto_approve": True,
            }
        ],
    }


def hosted_service_config(bind: str, stun_port: int, turn_port: int, relay_min: int, relay_max: int, max_bps: int) -> dict[str, Any]:
    return {
        "node": {"enabled": False},
        "signaling": {"enabled": False, "bind": bind, "port": 0},
        "stun": {"enabled": False, "bind": bind, "port": stun_port},
        "turn": {
            "enabled": False,
            "bind": bind,
            "port": turn_port,
            "public_ip": bind,
            "realm": "myownmesh-service-e2e",
            "credentials": [{"username": "e2e", "password": "e2e-password"}],
            "max_bps_per_connection": max_bps,
            "relay_port_min": relay_min,
            "relay_port_max": relay_max,
        },
    }


def spawn_daemon(
    binary: Path,
    name: str,
    home: Path,
    stdout_path: Path,
    stderr_path: Path,
    grant: str,
    realtime: str,
) -> tuple[subprocess.Popen[bytes], BinaryIO, BinaryIO]:
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    env = os.environ.copy()
    env.update(
        {
            "MYOWNMESH_HOME": str(home),
            "MYOWNMESH_LOG_FORMAT": "json",
            "MYOWNMESH_CONN_TRACE": "1",
            RESOURCE_GRANT: grant,
            REALTIME_POLICY: realtime,
        }
    )
    process = subprocess.Popen(
        [str(binary), "serve"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    return process, stdout, stderr


def terminate_process(process: subprocess.Popen[bytes], grace: float = 10.0) -> dict[str, Any]:
    forced = False
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            forced = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5.0)
    return {"pid": process.pid, "returncode": process.returncode, "forced": forced}


def public_shutdown(control_socket: Path, process: subprocess.Popen[bytes], timeout: float) -> dict[str, Any]:
    """Request the production supervisor drain before the signal fallback."""

    requested = False
    try:
        request(control_socket, {"op": "forget_all_networks"}, timeout=min(timeout, 5.0))
        requested = True
    except (ContractError, OSError):
        # A process may have already begun its terminal drain.  The signal is
        # still a public operator shutdown path, and terminate_process records
        # whether it needed to be used.
        pass
    terminal = terminate_process(process, grace=min(timeout, 10.0))
    terminal["public_shutdown_requested"] = requested
    return terminal


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="existing myownmesh executable")
    parser.add_argument("--artifact-dir", required=True, type=Path, help="new or empty preserved output directory")
    parser.add_argument("--timeout", type=float, default=90.0, help="bounded discovery/reconnect timeout")
    parser.add_argument("--service-bind", default="127.0.0.1", help="host bind address for STUN/TURN")
    parser.add_argument("--service-host", default="127.0.0.1", help="address peers use for STUN/TURN")
    parser.add_argument("--stun-port", type=int, default=3478)
    parser.add_argument("--turn-port", type=int, default=3479)
    parser.add_argument("--relay-port-min", type=int, default=0, help="owner-selected TURN relay range, 0 means OS-selected")
    parser.add_argument("--relay-port-max", type=int, default=0)
    parser.add_argument("--turn-max-bps", type=int, default=0, help="owner-selected per-connection cap, 0 means service policy unlimited")
    parser.add_argument("--signaling-url", help="optional public signaling URL; absent uses production mDNS")
    parser.add_argument(
        "--expect-pair",
        choices=("direct", "turn", "any"),
        default="direct",
        help="authoritative selected_pair class required after authentication",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
        raise ContractError("this shipped-process control runner currently requires Unix control sockets")
    if args.timeout <= 0:
        raise ContractError("--timeout must be positive")
    for label, value in (("--stun-port", args.stun_port), ("--turn-port", args.turn_port)):
        if not 1 <= value <= 65535:
            raise ContractError(f"{label} must be a valid TCP/UDP port")
    if args.stun_port == args.turn_port:
        raise ContractError("STUN and TURN control ports must differ")
    if (args.relay_port_min == 0) != (args.relay_port_max == 0):
        raise ContractError("--relay-port-min and --relay-port-max must be supplied together")
    if args.relay_port_min and not (1 <= args.relay_port_min <= args.relay_port_max <= 65535):
        raise ContractError("TURN relay port range is invalid")
    if args.turn_max_bps < 0:
        raise ContractError("--turn-max-bps must be nonnegative")
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ContractError(f"--binary is not an executable file: {binary}")
    grant = os.environ.get(RESOURCE_GRANT)
    if not grant:
        raise ContractError(f"owner must set the complete finite {RESOURCE_GRANT}")
    dimensions = finite_grant_dimensions(grant)
    realtime = os.environ.get(REALTIME_POLICY)
    if realtime not in {"disabled", "enabled"}:
        raise ContractError(f"owner must set {REALTIME_POLICY}=disabled or enabled")
    if args.expect_pair == "turn" and not args.signaling_url:
        raise ContractError("--expect-pair turn requires --signaling-url; local mDNS is direct evidence")

    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if any(artifact_dir.iterdir()):
        raise ContractError(f"artifact directory must be empty: {artifact_dir}")
    network = "e2e" + secrets.token_hex(8)
    service_config = hosted_service_config(
        args.service_bind,
        args.stun_port,
        args.turn_port,
        args.relay_port_min,
        args.relay_port_max,
        args.turn_max_bps,
    )
    homes = {name: artifact_dir / f"home-{name}" for name in ("host", "a", "b")}
    sockets = {name: home / "daemon.sock" for name, home in homes.items()}
    for control_socket in sockets.values():
        if len(os.fsencode(control_socket)) > 100:
            raise ContractError(f"control socket path is too long: {control_socket}")
    for name, home in homes.items():
        home.mkdir()
        if name == "host":
            config = daemon_config(network, args.service_host, args.stun_port, args.turn_port, None, service_config)
        else:
            config = daemon_config(network, args.service_host, args.stun_port, args.turn_port, args.signaling_url)
        write_json(home / "config.json", config)

    manifest: dict[str, Any] = {
        "schema": "myownmesh-service-transport-e2e/v1",
        "started_at": utc_now(),
        "binary": str(binary),
        "binary_sha256": file_sha256(binary),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "network": network,
        "channel": CHANNEL,
        "resource_policy": {
            "grant_supplied": True,
            "grant_sha256": hashlib.sha256(grant.encode("utf-8")).hexdigest(),
            "dimensions": dimensions,
            "connector_realtime_policy": realtime,
        },
        "service_plan": {
            "bind": args.service_bind,
            "host": args.service_host,
            "stun_port": args.stun_port,
            "turn_port": args.turn_port,
            "relay_port_min": args.relay_port_min,
            "relay_port_max": args.relay_port_max,
            "turn_max_bps": args.turn_max_bps,
        },
        "transport_expectation": args.expect_pair,
        "artifacts": {},
        "observations": [],
        "prerequisites": [
            "TURN selection is accepted only from peers_list.selected_pair; the public daemon API has no force-relay selector.",
            "A TURN-selected run requires a signaling/NAT deployment that prevents a host-host pair; configured TURN URLs alone are not evidence.",
        ],
    }
    processes: dict[str, subprocess.Popen[bytes]] = {}
    logs: dict[str, tuple[BinaryIO, BinaryIO]] = {}
    streams: dict[str, tuple[socket.socket, BinaryIO]] = {}
    terminal_error: str | None = None
    cleanup_error: str | None = None
    try:
        for name in ("host", "a", "b"):
            stdout_path = artifact_dir / f"daemon-{name}.stdout.log"
            stderr_path = artifact_dir / f"daemon-{name}.stderr.log"
            process, stdout, stderr = spawn_daemon(binary, name, homes[name], stdout_path, stderr_path, grant, realtime)
            processes[name] = process
            logs[name] = (stdout, stderr)
            manifest["artifacts"][f"daemon_{name}_stdout"] = str(stdout_path)
            manifest["artifacts"][f"daemon_{name}_stderr"] = str(stderr_path)
            manifest["observations"].append({"step": f"daemon_{name}_started", "pid": process.pid, "at": utc_now()})

        for name in ("host", "a", "b"):
            wait_until(f"daemon {name} control readiness", args.timeout, lambda name=name: request(sockets[name], {"op": "status"}))
            manifest["observations"].append({"step": f"daemon_{name}_control_ready", "at": utc_now()})

        # STUN and TURN deliberately use separate lifecycle transitions.  The
        # production manager folds STUN into TURN when both are enabled on one
        # device, so asserting two simultaneous sockets would be false.  Each
        # leg nevertheless proves its own public start, exact stop, port
        # release, and same-address restart.
        stun_started = set_hosted_services(sockets["host"], True, False)
        stun_endpoint = endpoint_status(stun_started, "stun")
        if not stun_endpoint.get("running") or endpoint_port(stun_endpoint) != args.stun_port:
            raise ContractError(f"public services_set did not start standalone STUN: {stun_started!r}")
        manifest["observations"].append(
            {
                "step": "hosted_stun_running",
                "stun_listen": stun_endpoint.get("listen"),
                "at": utc_now(),
            }
        )
        stun_stopped = set_hosted_services(sockets["host"], False, False)
        if endpoint_status(stun_stopped, "stun").get("running"):
            raise ContractError(f"public services_set did not stop STUN: {stun_stopped!r}")
        udp_port_is_free(args.service_bind, args.stun_port)
        stun_restarted = set_hosted_services(sockets["host"], True, False)
        restarted_stun = endpoint_status(stun_restarted, "stun")
        if not restarted_stun.get("running") or endpoint_port(restarted_stun) != args.stun_port:
            raise ContractError(f"public services_set did not restart STUN: {stun_restarted!r}")

        turn_started = set_hosted_services(sockets["host"], False, True)
        turn_endpoint = endpoint_status(turn_started, "turn")
        if not turn_endpoint.get("running") or endpoint_port(turn_endpoint) != args.turn_port:
            raise ContractError(f"public services_set did not start TURN: {turn_started!r}")
        manifest["observations"].append(
            {
                "step": "hosted_turn_running",
                "turn_listen": turn_endpoint.get("listen"),
                "at": utc_now(),
            }
        )
        turn_stopped = set_hosted_services(sockets["host"], False, False)
        if endpoint_status(turn_stopped, "turn").get("running"):
            raise ContractError(f"public services_set did not stop TURN: {turn_stopped!r}")
        udp_port_is_free(args.service_bind, args.turn_port)
        restarted = set_hosted_services(sockets["host"], False, True)
        restarted_turn = endpoint_status(restarted, "turn")
        if not restarted_turn.get("running") or endpoint_port(restarted_turn) != args.turn_port:
            raise ContractError(f"public services_set did not restart TURN: {restarted!r}")
        manifest["observations"].append(
            {
                "step": "exact_stun_turn_ports_restarted",
                "stun_listen": restarted_stun.get("listen"),
                "turn_listen": restarted_turn.get("listen"),
                "at": utc_now(),
            }
        )

        peer_a = wait_until("A authenticated active peer", args.timeout, lambda: active_peer(sockets["a"], network))
        peer_b = wait_until("B authenticated active peer", args.timeout, lambda: active_peer(sockets["b"], network))
        classes = {"a": pair_class(peer_a), "b": pair_class(peer_b)}
        if any(value not in {"direct", "stun", "turn"} for value in classes.values()):
            raise ContractError(f"authenticated peers did not expose a known selected pair: {classes!r}")
        if args.expect_pair != "any" and any(value != args.expect_pair for value in classes.values()):
            raise ContractError(f"authenticated peers did not expose expected {args.expect_pair} selected pair: {classes!r}")
        write_json(artifact_dir / "peer-a.json", peer_a)
        write_json(artifact_dir / "peer-b.json", peer_b)
        manifest["artifacts"].update({"peer_a": str(artifact_dir / "peer-a.json"), "peer_b": str(artifact_dir / "peer-b.json")})
        manifest["observations"].append(
            {
                "step": "bilateral_authenticated_promotion_observed",
                "a_sees": peer_a.get("device_id"),
                "b_sees": peer_b.get("device_id"),
                "selected_pair_class": classes,
                "selected_pair": {"a": peer_a.get("selected_pair"), "b": peer_b.get("selected_pair")},
                "at": utc_now(),
            }
        )

        for name in ("a", "b"):
            stream, reader, client_id, capability = open_event_subscription(sockets[name])
            streams[name] = (stream, reader)
            request(
                sockets[name],
                {
                    "op": "channel_subscribe",
                    "client_id": client_id,
                    "client_capability": capability,
                    "network": network,
                    "channel": CHANNEL,
                },
            )
        manifest["observations"].append({"step": "both_channel_subscriptions_admitted", "at": utc_now()})

        payloads = {"a_to_b": {"direction": "a-to-b", "nonce": secrets.token_hex(16)}, "b_to_a": {"direction": "b-to-a", "nonce": secrets.token_hex(16)}}
        request(sockets["a"], {"op": "channel_send_reliable", "network": network, "channel": CHANNEL, "peer": peer_a["device_id"], "payload": payloads["a_to_b"]}, timeout=args.timeout)
        request(sockets["b"], {"op": "channel_send_reliable", "network": network, "channel": CHANNEL, "peer": peer_b["device_id"], "payload": payloads["b_to_a"]}, timeout=args.timeout)
        received: dict[str, dict[str, Any]] = {}
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline and len(received) < 2:
            for name, expected in (("a", payloads["b_to_a"]), ("b", payloads["a_to_b"])):
                if name not in streams:
                    continue
                frame = next_event(streams[name][0], streams[name][1], deadline)
                if frame is None:
                    continue
                if frame.get("kind") == "channel_inbound" and frame.get("network") == network and frame.get("channel") == CHANNEL and frame.get("payload") == expected:
                    received[name] = frame
        if set(received) != {"a", "b"}:
            raise ContractError(f"bidirectional typed payload was incomplete: {received!r}")
        write_json(artifact_dir / "bidirectional-payloads.json", received)
        manifest["artifacts"]["bidirectional_payloads"] = str(artifact_dir / "bidirectional-payloads.json")
        manifest["observations"].append({"step": "authenticated_bidirectional_payload_observed", "directions": sorted(received), "at": utc_now()})

        reconnect_response = request(sockets["a"], {"op": "network_reconnect", "network": network})
        manifest["observations"].append({"step": "network_reconnect_requested", "response": reconnect_response.get("data"), "at": utc_now()})
        post_reconnect = wait_until("A active after reconnect", args.timeout, lambda: active_peer(sockets["a"], network))
        post_classes = {"a": pair_class(post_reconnect)}
        false_leave: list[dict[str, Any]] = []
        event_deadline = time.monotonic() + min(args.timeout, 10.0)
        while time.monotonic() < event_deadline:
            for name, (stream, reader) in streams.items():
                frame = next_event(stream, reader, event_deadline)
                if frame is None:
                    continue
                if frame.get("event_kind") == "peer" and frame.get("kind") == "dropped":
                    reason = frame.get("reason")
                    if isinstance(reason, dict) and reason.get("kind") == "user_left":
                        false_leave.append(frame)
        if false_leave:
            raise ContractError(f"network reconnect emitted a false UserLeft: {false_leave!r}")
        manifest["observations"].append({"step": "reconnect_without_false_leave_observed", "selected_pair_class": post_classes, "at": utc_now()})

    except BaseException as error:
        terminal_error = f"{type(error).__name__}: {error}"
        raise
    finally:
        for stream, reader in streams.values():
            reader.close()
            stream.close()
        process_terminals = {name: public_shutdown(sockets[name], process, args.timeout) for name, process in reversed(tuple(processes.items()))}
        manifest["process_terminals"] = process_terminals
        bad_terminals = {name: terminal for name, terminal in process_terminals.items() if terminal["forced"] or terminal["returncode"] != 0}
        if bad_terminals:
            cleanup_error = f"daemons did not terminate gracefully: {bad_terminals!r}"
            if terminal_error is None:
                terminal_error = f"ContractError: {cleanup_error}"
        for stdout, stderr in logs.values():
            stdout.close()
            stderr.close()
        manifest["finished_at"] = utc_now()
        manifest["terminal_error"] = terminal_error
        manifest["cleanup_error"] = cleanup_error
        write_json(artifact_dir / "manifest.json", manifest)
    if cleanup_error is not None:
        raise ContractError(cleanup_error)
    print(f"service transport E2E contract completed; artifacts: {artifact_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        print(f"contract error: {error}", file=sys.stderr)
        raise SystemExit(2)
