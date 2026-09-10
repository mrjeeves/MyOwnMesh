#!/usr/bin/env python3
"""Run one real two-daemon MyOwnMesh production path on a Unix LAN host.

This harness does not build the product and does not use LocalBroker or a test
transport.  It starts two shipped ``myownmesh serve`` processes with isolated
homes, lets the production mDNS adapter discover the common Open network,
waits for the production WebRTC/endpoint-auth/promotion path, then sends one
acknowledged typed-channel payload through the daemon control API.

A zero exit means only that the executable contract reached its declared
terminal during this invocation.  The preserved artifacts are inputs to a
separate qualification decision; this script makes no release-evidence claim.
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
from typing import Any, BinaryIO


RESOURCE_GRANT = "MYOWNMESH_RESOURCE_GRANT"
REALTIME_POLICY = "MYOWNMESH_CONNECTOR_REALTIME_POLICY"
CHANNEL = "architecture-production-e2e"


class ContractError(RuntimeError):
    pass


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


def read_json_line(reader: BinaryIO, limit: int = 8 * 1024 * 1024) -> Any:
    line = reader.readline(limit + 1)
    if not line:
        raise ContractError("control socket closed before a complete JSON line")
    if len(line) > limit or not line.endswith(b"\n"):
        raise ContractError("control response exceeded harness line ceiling")
    return json.loads(line.decode("utf-8"))


def open_event_subscription(control_socket: Path) -> tuple[socket.socket, BinaryIO, str, str]:
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(5.0)
    stream.connect(str(control_socket))
    stream.sendall(b'{"op":"events_subscribe"}\n')
    reader = stream.makefile("rb")
    ack = read_json_line(reader)
    if not isinstance(ack, dict) or ack.get("ok") is not True:
        reader.close()
        stream.close()
        raise ContractError(f"events_subscribe refused: {ack!r}")
    data = ack.get("data") or {}
    client_id = data.get("client_id")
    capability = data.get("client_capability")
    canonical_client_id = (
        isinstance(client_id, str)
        and client_id.startswith("c")
        and client_id[1:].isdigit()
        and str(int(client_id[1:])) == client_id[1:]
    )
    if not canonical_client_id or not isinstance(capability, str) or not capability:
        reader.close()
        stream.close()
        raise ContractError("events_subscribe did not return its routing id and capability")
    return stream, reader, client_id, capability


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


def active_peer(control_socket: Path, network: str) -> dict[str, Any] | None:
    response = request(control_socket, {"op": "peers_list", "network": network})
    peers = (response.get("data") or {}).get("peers") or []
    for peer in peers:
        if peer.get("status") == "active" and peer.get("authenticated") is True:
            return peer
    return None


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
                "label": "production-e2e",
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="existing myownmesh executable")
    parser.add_argument("--artifact-dir", required=True, type=Path, help="new or empty preserved output directory")
    parser.add_argument("--timeout", type=float, default=90.0, help="seconds allowed for discovery and promotion")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
        raise ContractError("this production mDNS runner currently requires a Unix host")
    if args.timeout <= 0:
        raise ContractError("--timeout must be positive")
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ContractError(f"--binary is not an executable file: {binary}")
    grant = os.environ.get(RESOURCE_GRANT)
    if not grant:
        raise ContractError(f"owner must set the complete finite {RESOURCE_GRANT}")
    realtime = os.environ.get(REALTIME_POLICY)
    if realtime not in {"disabled", "enabled"}:
        raise ContractError(f"owner must set {REALTIME_POLICY}=disabled or enabled")

    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if any(artifact_dir.iterdir()):
        raise ContractError(f"artifact directory must be empty: {artifact_dir}")

    network = "e2e" + secrets.token_hex(8)
    token = secrets.token_hex(16)
    payload = {"contract": "production-e2e", "token": token}
    homes = {name: artifact_dir / f"home-{name}" for name in ("a", "b")}
    sockets = {name: home / "daemon.sock" for name, home in homes.items()}
    for control_socket in sockets.values():
        if len(os.fsencode(control_socket)) > 100:
            raise ContractError(
                f"control socket path is too long for a portable Unix-domain socket: {control_socket}"
            )
    for home in homes.values():
        home.mkdir()
        write_json(home / "config.json", daemon_config(network))

    manifest: dict[str, Any] = {
        "schema": "myownmesh-production-e2e-run/v1",
        "started_at": utc_now(),
        "binary": str(binary),
        "binary_sha256": file_sha256(binary),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "network": network,
        "channel": CHANNEL,
        "resource_policy": {
            "grant_supplied": True,
            "connector_realtime_policy": realtime,
        },
        "artifacts": {},
        "observations": [],
    }
    processes: dict[str, subprocess.Popen[bytes]] = {}
    logs: dict[str, tuple[BinaryIO, BinaryIO]] = {}
    event_stream: socket.socket | None = None
    event_reader: BinaryIO | None = None
    terminal_error: str | None = None
    cleanup_error: str | None = None

    try:
        for name in ("a", "b"):
            stdout_path = artifact_dir / f"daemon-{name}.stdout.log"
            stderr_path = artifact_dir / f"daemon-{name}.stderr.log"
            stdout = stdout_path.open("wb")
            stderr = stderr_path.open("wb")
            logs[name] = (stdout, stderr)
            env = os.environ.copy()
            env.update(
                {
                    "MYOWNMESH_HOME": str(homes[name]),
                    "MYOWNMESH_LOG_FORMAT": "json",
                    "MYOWNMESH_CONN_TRACE": "1",
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
            processes[name] = process
            manifest["artifacts"][f"daemon_{name}_stdout"] = str(stdout_path)
            manifest["artifacts"][f"daemon_{name}_stderr"] = str(stderr_path)
            manifest["observations"].append({"step": f"daemon_{name}_started", "pid": process.pid, "at": utc_now()})

        for name in ("a", "b"):
            wait_until(
                f"daemon {name} control readiness",
                args.timeout,
                lambda name=name: request(sockets[name], {"op": "status"}),
            )
            manifest["observations"].append({"step": f"daemon_{name}_control_ready", "at": utc_now()})

        peer_a = wait_until("A authenticated active peer", args.timeout, lambda: active_peer(sockets["a"], network))
        peer_b = wait_until("B authenticated active peer", args.timeout, lambda: active_peer(sockets["b"], network))
        write_json(artifact_dir / "peer-a.json", peer_a)
        write_json(artifact_dir / "peer-b.json", peer_b)
        manifest["artifacts"].update(
            {"peer_a": str(artifact_dir / "peer-a.json"), "peer_b": str(artifact_dir / "peer-b.json")}
        )
        manifest["observations"].append(
            {
                "step": "bilateral_authenticated_promotion_observed",
                "a_sees": peer_a["device_id"],
                "b_sees": peer_b["device_id"],
                "a_selected_pair": peer_a.get("selected_pair"),
                "b_selected_pair": peer_b.get("selected_pair"),
                "at": utc_now(),
            }
        )

        event_stream, event_reader, client_id, capability = open_event_subscription(sockets["b"])
        request(
            sockets["b"],
            {
                "op": "channel_subscribe",
                "client_id": client_id,
                "client_capability": capability,
                "network": network,
                "channel": CHANNEL,
            },
        )
        manifest["observations"].append({"step": "b_channel_subscribed", "at": utc_now()})

        send_response = request(
            sockets["a"],
            {
                "op": "channel_send_reliable",
                "network": network,
                "channel": CHANNEL,
                "peer": peer_a["device_id"],
                "payload": payload,
            },
            timeout=args.timeout,
        )
        write_json(artifact_dir / "reliable-send-response.json", send_response)
        manifest["artifacts"]["reliable_send_response"] = str(artifact_dir / "reliable-send-response.json")

        event_path = artifact_dir / "daemon-b.events.jsonl"
        manifest["artifacts"]["daemon_b_events"] = str(event_path)
        deadline = time.monotonic() + args.timeout
        delivered: dict[str, Any] | None = None
        with event_path.open("w", encoding="utf-8", newline="\n") as event_log:
            while time.monotonic() < deadline:
                event_stream.settimeout(max(0.1, deadline - time.monotonic()))
                frame = read_json_line(event_reader)
                event_log.write(json.dumps(frame, sort_keys=True) + "\n")
                event_log.flush()
                if (
                    isinstance(frame, dict)
                    and frame.get("kind") == "channel_inbound"
                    and frame.get("network") == network
                    and frame.get("channel") == CHANNEL
                    and frame.get("payload") == payload
                    and frame.get("from") == peer_b["device_id"]
                ):
                    delivered = frame
                    break
        if delivered is None:
            raise ContractError("B did not expose the exact inbound typed-channel payload")
        manifest["observations"].append(
            {"step": "exact_typed_channel_payload_observed", "from": delivered["from"], "at": utc_now()}
        )
    except BaseException as error:
        terminal_error = f"{type(error).__name__}: {error}"
        raise
    finally:
        if event_reader is not None:
            event_reader.close()
        if event_stream is not None:
            event_stream.close()
        process_terminals = {
            name: terminate_process(process) for name, process in reversed(tuple(processes.items()))
        }
        manifest["process_terminals"] = process_terminals
        bad_terminals = {
            name: terminal
            for name, terminal in process_terminals.items()
            if terminal["forced"] or terminal["returncode"] != 0
        }
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
    print(f"production E2E contract completed; artifacts: {artifact_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        print(f"contract error: {error}", file=sys.stderr)
        raise SystemExit(2)
