#!/usr/bin/env python3
"""Qualify the shipped application gateway across two real daemons.

The harness starts two existing ``myownmesh serve`` executables with isolated
homes and a finite owner grant.  It uses only the public control socket after
production discovery and promotion: typed channels, acknowledged delivery,
unary and streaming RPC, capability replacement/revocation, event delivery,
and (when explicitly enabled) the binary realtime pipe.  It uses no test-only
API and performs no build step.

The JSON artifact is raw invocation evidence, not a release qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO, Callable


RESOURCE_GRANT = "MYOWNMESH_RESOURCE_GRANT"
REALTIME_POLICY = "MYOWNMESH_CONNECTOR_REALTIME_POLICY"
LINE_LIMIT = 8 * 1024 * 1024
CHANNEL = "application-gateway-production-e2e"
UNARY_METHOD = "application_gateway_e2e.unary"
STREAM_METHOD = "application_gateway_e2e.stream"
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
U64_MAX = (1 << 64) - 1

# These names are also used by the companion static controls.  A missing name
# is a missing shipped surface, not a reason to silently omit a phase.
REQUIRED_SURFACE = (
    "events_subscribe",
    "channel_send_to",
    "channel_send_reliable",
    "rpc_unary",
    "rpc_stream",
    "capabilities_replace",
    "capabilities_revoke",
    "realtime_flow_pipe",
    "admission_refusal",
    "graceful_terminal",
)


class ContractError(RuntimeError):
    """A failed process contract, rather than a product qualification."""


def missing_surface(observations: list[dict[str, Any]]) -> tuple[str, ...]:
    completed = {
        item.get("surface")
        for item in observations
        if item.get("ok") is True and item.get("skipped") is not True
    }
    return tuple(name for name in REQUIRED_SURFACE if name not in completed)


def require_surface(observations: list[dict[str, Any]]) -> None:
    missing = missing_surface(observations)
    if missing:
        raise ContractError("shipped application-gateway surface missing: " + ", ".join(missing))


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


def read_json_line(reader: BinaryIO) -> Any:
    line = reader.readline(LINE_LIMIT + 1)
    if not line:
        raise ContractError("control stream closed before a complete JSON line")
    if len(line) > LINE_LIMIT or not line.endswith(b"\n"):
        raise ContractError("control response exceeded the harness line ceiling")
    try:
        return json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"invalid JSON control response: {error}") from error


def request(control_socket: Path, body: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(str(control_socket))
        stream.sendall(encoded)
        with stream.makefile("rb") as reader:
            response = read_json_line(reader)
    if not isinstance(response, dict):
        raise ContractError(f"{body.get('op')} returned a non-object response")
    return response


def require_ok(control_socket: Path, body: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    response = request(control_socket, body, timeout)
    if response.get("ok") is not True:
        raise ContractError(f"control {body.get('op')} refused: {response.get('error')}")
    return response


class EventClient:
    """One authenticated EventsSubscribe server-push connection."""

    def __init__(self, stream: socket.socket, reader: BinaryIO, client_id: str, capability: str) -> None:
        self.stream = stream
        self.reader = reader
        self.client_id = client_id
        self.capability = capability

    @classmethod
    def open(cls, control_socket: Path, timeout: float) -> "EventClient":
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stream.settimeout(timeout)
        reader: BinaryIO | None = None
        try:
            stream.connect(str(control_socket))
            stream.sendall(b'{"op":"events_subscribe"}\n')
            reader = stream.makefile("rb")
            response = read_json_line(reader)
            data = response.get("data") if isinstance(response, dict) else None
            client_id = data.get("client_id") if isinstance(data, dict) else None
            capability = data.get("client_capability") if isinstance(data, dict) else None
            if (
                response.get("ok") is not True
                or not isinstance(client_id, str)
                or not client_id
                or not isinstance(capability, str)
                or not capability
            ):
                raise ContractError(f"events_subscribe refused: {response!r}")
            return cls(stream, reader, client_id, capability)
        except BaseException:
            if reader is not None:
                reader.close()
            stream.close()
            raise

    def close(self) -> None:
        self.reader.close()
        self.stream.close()

    def next(self, timeout: float) -> dict[str, Any]:
        # Read through the buffered file object directly.  select(2) can report
        # no kernel bytes while BufferedReader already holds the next complete
        # frame, which would turn a valid burst into a false timeout.
        self.stream.settimeout(timeout)
        try:
            frame = read_json_line(self.reader)
        except socket.timeout as error:
            raise ContractError("timed out waiting for an EventsSubscribe frame") from error
        if not isinstance(frame, dict):
            raise ContractError("EventsSubscribe produced a non-object frame")
        return frame

    def until(self, label: str, timeout: float, predicate: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            frame = self.next(max(0.05, deadline - time.monotonic()))
            if predicate(frame):
                return frame
        raise ContractError(f"timed out waiting for {label}")


def wait_until(label: str, timeout: float, probe: Callable[[], Any]) -> Any:
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


def active_peer(control_socket: Path, network: str) -> dict[str, Any] | None:
    response = require_ok(control_socket, {"op": "peers_list", "network": network})
    peers = (response.get("data") or {}).get("peers") or []
    for peer in peers:
        if peer.get("status") == "active" and peer.get("authenticated") is True:
            return peer
    return None


def terminate_process(process: subprocess.Popen[bytes], grace: float) -> dict[str, Any]:
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
            process.wait(timeout=grace)
    return {"pid": process.pid, "returncode": process.returncode, "forced": forced}


def close_best_effort(resource: Any, label: str) -> str | None:
    """Close one owned resource while preserving the rest of cleanup."""

    try:
        resource.close()
    except BaseException as error:
        return f"{label}: {type(error).__name__}: {error}"
    return None


def close_event_client(client: EventClient) -> list[str]:
    """Close both halves of an event client independently."""

    failures: list[str] = []
    if hasattr(client, "reader") and hasattr(client, "stream"):
        for label, resource in (("event reader", client.reader), ("event stream", client.stream)):
            failure = close_best_effort(resource, label)
            if failure is not None:
                failures.append(failure)
    else:
        failure = close_best_effort(client, "event client")
        if failure is not None:
            failures.append(failure)
    return failures


def terminate_all(
    processes: dict[str, subprocess.Popen[bytes]], grace: float
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Terminate every daemon independently and retain failures as evidence."""

    terminals: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for name, process in reversed(tuple(processes.items())):
        try:
            terminals[name] = terminate_process(process, grace)
        except BaseException as error:
            failure = f"daemon {name} termination: {type(error).__name__}: {error}"
            failures.append(failure)
            terminals[name] = {
                "pid": getattr(process, "pid", None),
                "returncode": getattr(process, "returncode", None),
                "forced": True,
                "error": failure,
            }
    return terminals, failures


def require_manifest(path: Path, written: bool) -> None:
    """Refuse a successful run when its terminal evidence is absent."""

    if not written or not path.is_file():
        raise ContractError(f"application gateway manifest was not written: {path}")


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


def daemon_config(network: str) -> dict[str, Any]:
    return {
        "version": 2,
        "networks": [
            {
                "id": network,
                "network_id": network,
                "label": "application-gateway-production-e2e",
                "kind": "open",
                "semantic_policy": semantic_policy(),
                "signaling": {
                    "strategy": "none",
                    "mdns": True,
                    "servers": [],
                    "redundancy": 1,
                    "denylist": [],
                    "public_fallback": False,
                },
                "stun_servers": [],
                "turn_servers": [],
                "auto_approve": True,
            }
        ],
    }


def capability_event(frame: dict[str, Any], network: str, peer: str, tags: list[str]) -> bool:
    event = frame.get("event") if frame.get("kind") == "event" else None
    return (
        isinstance(event, dict)
        and event.get("event_kind") == "peer"
        and event.get("kind") == "capabilities_changed"
        and event.get("network_id") == network
        and event.get("device_id") == peer
        and (event.get("capabilities") or {}).get("tags") == tags
    )


def encode_realtime_send(label: bytes, payload: bytes, duration_us: int = 1_000) -> bytes:
    if not label or len(label) > 255:
        raise ContractError("realtime test label must fit the shipped one-byte label length")
    body = (
        bytes((len(label), 0))
        + duration_us.to_bytes(4, "little")
        + len(payload).to_bytes(4, "little")
        + label
        + payload
    )
    return len(body).to_bytes(4, "little") + body


def decode_realtime_recv(frame: bytes) -> tuple[bytes, int, bytes]:
    if len(frame) < 10:
        raise ContractError("realtime inbound frame is truncated")
    label_len = frame[0]
    marker = frame[1]
    timestamp = int.from_bytes(frame[2:6], "little")
    payload_len = int.from_bytes(frame[6:10], "little")
    if marker not in (0, 1) or len(frame) != 10 + label_len + payload_len:
        raise ContractError("realtime inbound frame failed exact length validation")
    label = frame[10 : 10 + label_len]
    payload = frame[10 + label_len :]
    return label, timestamp, payload


def open_realtime_pipe(control_socket: Path, request_body: dict[str, Any], timeout: float) -> tuple[socket.socket, BinaryIO]:
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(timeout)
    reader: BinaryIO | None = None
    try:
        stream.connect(str(control_socket))
        stream.sendall(json.dumps(request_body, separators=(",", ":")).encode("utf-8") + b"\n")
        reader = stream.makefile("rb")
        response = read_json_line(reader)
        if response.get("ok") is not True:
            raise ContractError(f"realtime_pipe refused: {response.get('error')}")
        return stream, reader
    except BaseException:
        if reader is not None:
            reader.close()
        stream.close()
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="existing myownmesh executable")
    parser.add_argument("--artifact-dir", required=True, type=Path, help="new or empty evidence directory")
    parser.add_argument("--resource-grant", help="finite grant; defaults to MYOWNMESH_RESOURCE_GRANT")
    parser.add_argument("--connector-realtime-policy", choices=("disabled", "enabled"), help="defaults to environment")
    parser.add_argument("--timeout", type=float, default=90.0, help="seconds allowed for each finite phase")
    return parser.parse_args()


def validate_grant(raw: str) -> dict[str, int]:
    """Validate syntax for the daemon's complete finite u64 owner grant.

    This is a fail-closed input check only; the daemon remains the final
    authority for whether the supplied amounts fund its process scope.
    """

    if not isinstance(raw, str) or not raw.strip():
        raise ContractError(f"{RESOURCE_GRANT} must be a nonempty finite owner grant")
    amounts: dict[str, int] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            raise ContractError(f"{RESOURCE_GRANT} contains an empty entry")
        if entry.count("=") != 1:
            raise ContractError(f"{RESOURCE_GRANT} entries must be dimension=value")
        name, value = (part.strip() for part in entry.split("=", 1))
        if name not in GRANT_DIMENSIONS:
            raise ContractError(f"{RESOURCE_GRANT} names unknown dimension {name!r}")
        if name in amounts:
            raise ContractError(f"{RESOURCE_GRANT} repeats dimension {name!r}")
        if not value or any(character not in "0123456789" for character in value):
            raise ContractError(f"{RESOURCE_GRANT} dimension {name!r} must be a finite u64")
        canonical_value = value.lstrip("0") or "0"
        if len(canonical_value) > len(str(U64_MAX)) or (
            len(canonical_value) == len(str(U64_MAX)) and canonical_value > str(U64_MAX)
        ):
            raise ContractError(f"{RESOURCE_GRANT} dimension {name!r} exceeds u64")
        amount = int(canonical_value, 10)
        amounts[name] = amount
    missing = [name for name in GRANT_DIMENSIONS if name not in amounts]
    if missing:
        raise ContractError(f"{RESOURCE_GRANT} omits dimensions: {', '.join(missing)}")
    return amounts


def validate_args(args: argparse.Namespace, grant: str, realtime: str) -> dict[str, int]:
    if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
        raise ContractError("this shipped mDNS/control-socket runner requires a Unix host")
    if args.timeout <= 0:
        raise ContractError("--timeout must be positive")
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ContractError(f"--binary is not an executable file: {binary}")
    amounts = validate_grant(grant)
    if realtime not in {"disabled", "enabled"}:
        raise ContractError(f"{REALTIME_POLICY} must be disabled or enabled")
    return amounts


def run(args: argparse.Namespace) -> dict[str, Any]:
    grant = args.resource_grant or os.environ.get(RESOURCE_GRANT, "")
    realtime = args.connector_realtime_policy or os.environ.get(REALTIME_POLICY, "")
    grant_dimensions = validate_args(args, grant, realtime)
    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if any(artifact_dir.iterdir()):
        raise ContractError(f"artifact directory must be empty: {artifact_dir}")

    network = "appgw" + secrets.token_hex(8)
    homes = {name: artifact_dir / f"home-{name}" for name in ("a", "b")}
    sockets = {name: home / "daemon.sock" for name, home in homes.items()}
    for control_socket in sockets.values():
        if len(os.fsencode(control_socket)) > 100:
            raise ContractError(f"control socket path is too long: {control_socket}")
    for home in homes.values():
        home.mkdir()
        write_json(home / "config.json", daemon_config(network))

    manifest: dict[str, Any] = {
        "schema": "myownmesh-application-gateway-e2e/v1",
        "started_at": utc_now(),
        "binary": str(args.binary.resolve()),
        "binary_sha256": file_sha256(args.binary.resolve()),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "network": network,
        "resource_policy": {
            "grant_supplied": True,
            "grant_dimensions": grant_dimensions,
            "connector_realtime_policy": realtime,
        },
        "observations": [],
        "artifacts": {},
    }
    processes: dict[str, subprocess.Popen[bytes]] = {}
    logs: dict[str, tuple[BinaryIO | None, BinaryIO | None]] = {}
    process_home_envs: dict[str, str] = {}
    events: dict[str, EventClient] = {}
    pipes: list[tuple[socket.socket, BinaryIO]] = []
    rpc_call: socket.socket | None = None
    terminal_error: str | None = None
    cleanup_error: str | None = None
    manifest_written = False

    def observe(surface: str, detail: dict[str, Any] | None = None) -> None:
        item: dict[str, Any] = {"surface": surface, "ok": True, "at": utc_now()}
        if detail:
            item.update(detail)
        manifest["observations"].append(item)

    try:
        for name in ("a", "b"):
            stdout_path = artifact_dir / f"daemon-{name}.stdout.log"
            stderr_path = artifact_dir / f"daemon-{name}.stderr.log"
            stdout = stdout_path.open("wb")
            logs[name] = (stdout, None)
            stderr = stderr_path.open("wb")
            logs[name] = (stdout, stderr)
            environment = os.environ.copy()
            environment.update(
                {
                    "MYOWNMESH_HOME": str(homes[name]),
                    "MYOWNMESH_LOG_FORMAT": "json",
                    "MYOWNMESH_CONN_TRACE": "1",
                    RESOURCE_GRANT: grant,
                    REALTIME_POLICY: realtime,
                }
            )
            process_home_envs[name] = environment["MYOWNMESH_HOME"]
            processes[name] = subprocess.Popen(
                [str(args.binary.resolve()), "serve"],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            manifest["artifacts"][f"daemon_{name}_stdout"] = str(stdout_path)
            manifest["artifacts"][f"daemon_{name}_stderr"] = str(stderr_path)

        pids = [getattr(process, "pid", None) for process in processes.values()]
        if len(pids) != 2 or any(not isinstance(pid, int) or pid <= 0 for pid in pids) or len(set(pids)) != 2:
            raise ContractError(f"daemon launch did not produce two distinct process ids: {pids!r}")
        manifest["process_pids"] = dict(zip(processes, pids))
        if len(set(process_home_envs.values())) != 2:
            raise ContractError("daemon launch did not receive two distinct MYOWNMESH_HOME values")
        manifest["process_homes"] = process_home_envs

        for name in ("a", "b"):
            wait_until(f"daemon {name} control readiness", args.timeout, lambda name=name: request(sockets[name], {"op": "status"}))

        peer_a = wait_until("A promoted peer", args.timeout, lambda: active_peer(sockets["a"], network))
        peer_b = wait_until("B promoted peer", args.timeout, lambda: active_peer(sockets["b"], network))
        destination_id = peer_a.get("device_id")
        expected_sender_id = peer_b.get("device_id")
        if (
            not isinstance(destination_id, str)
            or not destination_id
            or not isinstance(expected_sender_id, str)
            or not expected_sender_id
        ):
            raise ContractError("active peers did not expose canonical device ids")
        if destination_id == expected_sender_id:
            raise ContractError("active peers exposed the same destination and sender id")
        write_json(artifact_dir / "peer-a-view.json", peer_a)
        write_json(artifact_dir / "peer-b-view.json", peer_b)
        manifest["artifacts"].update(
            {"peer_a_view": str(artifact_dir / "peer-a-view.json"), "peer_b_view": str(artifact_dir / "peer-b-view.json")}
        )
        manifest["peer_ids"] = {
            "a": destination_id,
            "b": expected_sender_id,
            "destination_id": destination_id,
            "expected_sender_id": expected_sender_id,
        }

        events["a"] = EventClient.open(sockets["a"], args.timeout)
        events["b"] = EventClient.open(sockets["b"], args.timeout)
        client_ids = [client.client_id for client in events.values()]
        if len(client_ids) != 2 or len(set(client_ids)) != 2:
            raise ContractError(f"event subscriptions did not produce two distinct client ids: {client_ids!r}")
        observe("events_subscribe", {"clients": {name: client.client_id for name, client in events.items()}})

        b_event = events["b"]
        require_ok(
            sockets["b"],
            {"op": "channel_subscribe", "client_id": b_event.client_id, "client_capability": b_event.capability, "network": network, "channel": CHANNEL},
            args.timeout,
        )
        first_payload = {"surface": "typed-channel", "nonce": secrets.token_hex(8)}
        require_ok(sockets["a"], {"op": "channel_send_to", "network": network, "channel": CHANNEL, "peer": destination_id, "payload": first_payload}, args.timeout)
        b_event.until("typed channel inbound", args.timeout, lambda frame: frame.get("kind") == "channel_inbound" and frame.get("network") == network and frame.get("channel") == CHANNEL and frame.get("from") == expected_sender_id and frame.get("payload") == first_payload)
        observe("channel_send_to")

        reliable_payload = {"surface": "reliable-channel", "nonce": secrets.token_hex(8)}
        require_ok(sockets["a"], {"op": "channel_send_reliable", "network": network, "channel": CHANNEL, "peer": destination_id, "payload": reliable_payload}, args.timeout)
        b_event.until("reliable typed channel inbound", args.timeout, lambda frame: frame.get("kind") == "channel_inbound" and frame.get("network") == network and frame.get("channel") == CHANNEL and frame.get("from") == expected_sender_id and frame.get("payload") == reliable_payload)
        observe("channel_send_reliable")

        require_ok(sockets["b"], {"op": "rpc_register", "client_id": b_event.client_id, "client_capability": b_event.capability, "network": network, "method": UNARY_METHOD, "streaming": False}, args.timeout)
        unary_payload = {"request": "unary", "nonce": secrets.token_hex(8)}
        unary_socket = sockets["a"]
        unary_result: dict[str, Any] | None = None

        # The command request blocks while B's event client handles the inbound
        # request.  A worker thread is unnecessary: the request is sent only
        # after the inbound event has been observed, using a short-lived socket.
        # The daemon itself performs the blocking wait; this harness uses a
        # subprocess so no local broker or test seam is involved.
        rpc_call = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        rpc_call.settimeout(args.timeout)
        rpc_call.connect(str(unary_socket))
        rpc_call.sendall(json.dumps({"op": "rpc_call", "network": network, "peer": destination_id, "method": UNARY_METHOD, "payload": unary_payload}, separators=(",", ":")).encode("utf-8") + b"\n")
        inbound = b_event.until("unary RPC inbound", args.timeout, lambda frame: frame.get("kind") == "rpc_inbound" and frame.get("network") == network and frame.get("from") == expected_sender_id and frame.get("method") == UNARY_METHOD and frame.get("payload") == unary_payload)
        require_ok(sockets["b"], {"op": "rpc_respond", "client_id": b_event.client_id, "client_capability": b_event.capability, "network": network, "peer": expected_sender_id, "method": UNARY_METHOD, "request_id": inbound["request_id"], "operation_id": inbound["operation_id"], "ok": {"echo": unary_payload}}, args.timeout)
        with rpc_call.makefile("rb") as reader:
            unary_result = read_json_line(reader)
        rpc_call.close()
        rpc_call = None
        if unary_result.get("ok") is not True or (unary_result.get("data") or {}).get("response", {}).get("echo") != unary_payload:
            raise ContractError(f"unary RPC response did not preserve the exact payload: {unary_result!r}")
        observe("rpc_unary")

        require_ok(sockets["b"], {"op": "rpc_register", "client_id": b_event.client_id, "client_capability": b_event.capability, "network": network, "method": STREAM_METHOD, "streaming": True}, args.timeout)
        stream_payload = {"request": "stream", "nonce": secrets.token_hex(8)}
        require_ok(sockets["a"], {"op": "rpc_call_stream", "client_id": events["a"].client_id, "client_capability": events["a"].capability, "network": network, "peer": destination_id, "method": STREAM_METHOD, "payload": stream_payload}, args.timeout)
        stream_inbound = b_event.until("streaming RPC inbound", args.timeout, lambda frame: frame.get("kind") == "rpc_inbound" and frame.get("network") == network and frame.get("from") == expected_sender_id and frame.get("method") == STREAM_METHOD and frame.get("streaming") is True and frame.get("payload") == stream_payload)
        request_id = stream_inbound["request_id"]
        for sequence in (0, 1):
            require_ok(sockets["b"], {"op": "rpc_stream_chunk", "client_id": b_event.client_id, "client_capability": b_event.capability, "network": network, "peer": expected_sender_id, "method": STREAM_METHOD, "request_id": request_id, "operation_id": stream_inbound["operation_id"], "payload": {"sequence": sequence, "nonce": stream_payload["nonce"]}}, args.timeout)
        require_ok(sockets["b"], {"op": "rpc_stream_end", "client_id": b_event.client_id, "client_capability": b_event.capability, "network": network, "peer": expected_sender_id, "method": STREAM_METHOD, "request_id": request_id, "operation_id": stream_inbound["operation_id"]}, args.timeout)
        chunks = []
        for _ in range(2):
            frame = events["a"].until("streaming RPC chunk", args.timeout, lambda frame: frame.get("kind") == "rpc_call_stream_chunk" and frame.get("request_id") == request_id)
            chunks.append((frame.get("payload") or {}).get("sequence"))
        events["a"].until("streaming RPC terminal", args.timeout, lambda frame: frame.get("kind") == "rpc_call_stream_end" and frame.get("request_id") == request_id and frame.get("error") is None)
        if chunks != [0, 1]:
            raise ContractError(f"stream chunks were not ordered: {chunks!r}")
        observe("rpc_stream")

        tags_one = ["application-gateway-e2e-v1"]
        require_ok(sockets["a"], {"op": "capabilities_set", "network": network, "capabilities": {"tags": tags_one, "app_version": "e2e", "extra": {"nonce": 1}}}, args.timeout)
        b_event.until("capability replacement", args.timeout, lambda frame: capability_event(frame, network, expected_sender_id, tags_one))
        observe("capabilities_replace")
        require_ok(sockets["a"], {"op": "capabilities_set", "network": network, "capabilities": {"tags": [], "app_version": None, "extra": {}}}, args.timeout)
        b_event.until("capability revocation", args.timeout, lambda frame: capability_event(frame, network, expected_sender_id, []))
        observe("capabilities_revoke")

        refused = request(sockets["b"], {"op": "channel_subscribe", "client_id": b_event.client_id, "client_capability": "wrong-capability", "network": network, "channel": CHANNEL}, args.timeout)
        if refused.get("ok") is True:
            raise ContractError("invalid client capability was accepted instead of refused")
        observe("admission_refusal", {"error": refused.get("error")})

        if realtime == "enabled":
            flow = require_ok(sockets["a"], {"op": "realtime_flow_open", "network": network, "peer": destination_id, "flow_label": "e2e-audio", "client_id": events["a"].client_id, "client_capability": events["a"].capability, "direction": "outbound", "rtp_kind": "audio", "mime": "audio/opus", "clock_rate": 48_000, "channels": 2}, args.timeout)
            flow_data = flow.get("data") or {}
            flow_capability = flow_data.get("flow_capability") or flow_data.get("capability")
            if not isinstance(flow_capability, str) or not flow_capability:
                raise ContractError(f"realtime_flow_open did not return a flow capability: {flow!r}")
            inbound_pipe, inbound_reader = open_realtime_pipe(sockets["b"], {"op": "realtime_pipe", "direction": "inbound", "network": network, "peer": expected_sender_id, "client_id": b_event.client_id, "client_capability": b_event.capability}, args.timeout)
            pipes.append((inbound_pipe, inbound_reader))
            outbound_pipe, outbound_reader = open_realtime_pipe(sockets["a"], {"op": "realtime_pipe", "direction": "outbound", "network": network, "client_id": events["a"].client_id, "client_capability": events["a"].capability, "flow_capability": flow_capability}, args.timeout)
            pipes.append((outbound_pipe, outbound_reader))
            label = b"e2e-audio"
            payload = b"opaque-realtime-payload"
            outbound_pipe.sendall(encode_realtime_send(label, payload))
            outbound_pipe.shutdown(socket.SHUT_WR)
            prefix = inbound_reader.read(4)
            if len(prefix) != 4:
                raise ContractError("realtime inbound pipe ended before its frame prefix")
            length = int.from_bytes(prefix, "little")
            received = inbound_reader.read(length)
            if len(received) != length:
                raise ContractError("realtime inbound pipe ended before its frame body")
            received_label, _, received_payload = decode_realtime_recv(received)
            if received_label != label or received_payload != payload:
                raise ContractError("realtime pipe changed the opaque payload or label")
            require_ok(sockets["a"], {"op": "realtime_flow_close", "client_id": events["a"].client_id, "client_capability": events["a"].capability, "flow_capability": flow_capability}, args.timeout)
            observe("realtime_flow_pipe")
        else:
            manifest["observations"].append({"surface": "realtime_flow_pipe", "ok": True, "skipped": True, "reason": f"{REALTIME_POLICY}=disabled", "at": utc_now()})

        for client in events.values():
            failures = close_event_client(client)
            if failures:
                raise ContractError("event cleanup failed: " + "; ".join(failures))
        events.clear()
        for stream, reader in pipes:
            failures = [
                failure
                for failure in (
                    close_best_effort(reader, "realtime reader"),
                    close_best_effort(stream, "realtime stream"),
                )
                if failure is not None
            ]
            if failures:
                raise ContractError("realtime cleanup failed: " + "; ".join(failures))
        pipes.clear()
    except BaseException as error:
        terminal_error = f"{type(error).__name__}: {error}"
        raise
    finally:
        cleanup_failures: list[str] = []
        if rpc_call is not None:
            failure = close_best_effort(rpc_call, "rpc call socket")
            if failure is not None:
                cleanup_failures.append(failure)
        for client in tuple(events.values()):
            cleanup_failures.extend(close_event_client(client))
        events.clear()
        for stream, reader in pipes:
            for label, resource in (("realtime reader", reader), ("realtime stream", stream)):
                failure = close_best_effort(resource, label)
                if failure is not None:
                    cleanup_failures.append(failure)
        pipes.clear()
        terminals, termination_failures = terminate_all(processes, args.timeout)
        cleanup_failures.extend(termination_failures)
        manifest["process_terminals"] = terminals
        bad = {name: terminal for name, terminal in terminals.items() if terminal["forced"] or terminal["returncode"] != 0}
        if not bad:
            observe("graceful_terminal")
        cleanup_reasons: list[str] = []
        if bad:
            cleanup_reasons.append(f"daemons did not terminate gracefully: {bad!r}")
        for name, (stdout, stderr) in logs.items():
            for label, stream in ((f"daemon {name} stdout", stdout), (f"daemon {name} stderr", stderr)):
                if stream is not None:
                    failure = close_best_effort(stream, label)
                    if failure is not None:
                        cleanup_failures.append(failure)
        if cleanup_failures:
            cleanup_reasons.extend(cleanup_failures)
        if cleanup_reasons:
            cleanup_error = "; ".join(cleanup_reasons)
            if terminal_error is None:
                terminal_error = f"ContractError: {cleanup_error}"
        manifest["finished_at"] = utc_now()
        manifest["terminal_error"] = terminal_error
        manifest["cleanup_error"] = cleanup_error
        try:
            write_json(artifact_dir / "manifest.json", manifest)
            manifest_written = True
        except BaseException as error:
            manifest["manifest_write_error"] = f"{type(error).__name__}: {error}"
    require_manifest(artifact_dir / "manifest.json", manifest_written)
    if cleanup_error is not None:
        raise ContractError(cleanup_error)
    require_surface(manifest["observations"])
    return manifest


def main() -> int:
    args = parse_args()
    manifest = run(args)
    print(f"application gateway E2E contract completed; artifacts: {args.artifact_dir.resolve()}")
    print(json.dumps({"observed_surfaces": [item["surface"] for item in manifest["observations"] if item.get("ok")], "terminals": manifest.get("process_terminals")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        print(f"contract error: {error}", file=sys.stderr)
        raise SystemExit(2)
