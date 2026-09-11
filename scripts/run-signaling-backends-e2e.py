#!/usr/bin/env python3
"""Qualify both shipped signaling backends through real daemon processes.

The runner starts two isolated client daemons for each scenario.  The first
uses embedded mDNS.  The second starts a third shipped daemon as a loopback
NIP-01/Nostr relay and points both clients at that process.  There is no test
transport or in-process shortcut: authentication,
promotion, channel delivery, peer withdrawal, and shutdown all cross the
shipped process/control boundaries.

The owner supplies the complete finite resource vector through
``MYOWNMESH_RESOURCE_GRANT``.  A missing or malformed shipped control is a
failure, and the raw manifest is written even when a stage fails.
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
CHANNEL = "shipped-signaling-backends-e2e"
LINE_LIMIT = 8 * 1024 * 1024


class ContractError(RuntimeError):
    """The shipped process did not satisfy this harness contract."""


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


def read_json_line(reader: BinaryIO, limit: int = LINE_LIMIT) -> Any:
    line = reader.readline(limit + 1)
    if not line:
        raise ContractError("control/event socket closed before a complete JSON line")
    if len(line) > limit or not line.endswith(b"\n"):
        raise ContractError("control/event response exceeded harness line ceiling")
    try:
        return json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"invalid JSON line from shipped daemon: {error}") from error


def request(control_socket: Path, body: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """Make one real control request and require its typed success response."""

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
    """Open the shipped event stream and return its capability-bound route."""

    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(5.0)
    try:
        stream.connect(str(control_socket))
        stream.sendall(b'{"op":"events_subscribe"}\n')
        reader = stream.makefile("rb")
        ack = read_json_line(reader)
    except BaseException:
        stream.close()
        raise
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


def signaling_service_running(control_socket: Path) -> bool:
    """Require the service-status control to expose the live relay."""

    response = request(control_socket, {"op": "services_status"})
    data = response.get("data") or {}
    status = data.get("status") or {}
    signaling = status.get("signaling") or {}
    return signaling.get("enabled") is True and signaling.get("running") is True


def peer_withdrawn(control_socket: Path, network: str, device_id: str) -> bool:
    response = request(control_socket, {"op": "peers_list", "network": network})
    peers = (response.get("data") or {}).get("peers") or []
    return not any(
        peer.get("device_id") == device_id
        and peer.get("status") == "active"
        and peer.get("authenticated") is True
        for peer in peers
    )


def dropped_event(frame: Any, network: str, device_id: str) -> bool:
    """Match the canonical nested ``MeshEvent::Peer::Dropped`` wire shape."""

    if not isinstance(frame, dict) or frame.get("kind") != "event":
        return False
    event = frame.get("event")
    return (
        isinstance(event, dict)
        and event.get("event_kind") == "peer"
        and event.get("kind") == "dropped"
        and event.get("network_id") == network
        and event.get("device_id") == device_id
    )


def terminate_process(process: subprocess.Popen[bytes], grace: float = 20.0) -> dict[str, Any]:
    """Request the shipped graceful terminal, recording any forced kill."""

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


def daemon_config(network: str, *, mode: str, relay_url: str | None = None) -> dict[str, Any]:
    if mode == "mdns":
        signaling = {
            "strategy": "none",
            "mdns": True,
            "servers": [],
            "redundancy": 1,
            "denylist": [],
            "public_fallback": False,
        }
    elif mode == "nostr":
        if not relay_url:
            raise ValueError("nostr client config requires a relay URL")
        signaling = {
            "strategy": "nostr",
            "mdns": False,
            "servers": [relay_url],
            "redundancy": 1,
            "denylist": [],
            "public_fallback": False,
        }
    else:
        raise ValueError(f"unknown client mode: {mode}")
    return {
        "version": 2,
        "networks": [
            {
                "id": network,
                "network_id": network,
                "label": f"shipped-{mode}-e2e",
                "kind": "open",
                "semantic_policy": semantic_policy(),
                "signaling": signaling,
                "stun_servers": [],
                "turn_servers": [],
                "auto_approve": True,
            }
        ],
    }


def relay_config(port: int) -> dict[str, Any]:
    """Run the shipped signaling service as a pure infrastructure daemon."""

    if not 1 <= port <= 65535:
        raise ValueError(f"relay port is outside TCP's finite range: {port}")
    return {
        "version": 2,
        "services": {
            "node": {"enabled": False},
            "signaling": {
                "enabled": True,
                "bind": "127.0.0.1",
                "port": port,
            },
        },
        "networks": [],
    }


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="existing shipped myownmesh executable")
    parser.add_argument("--artifact-dir", required=True, type=Path, help="new or empty preserved output directory")
    parser.add_argument("--timeout", type=float, default=90.0, help="seconds allowed for each discovery/control stage")
    return parser.parse_args()


def start_daemon(
    name: str,
    binary: Path,
    home: Path,
    config: dict[str, Any],
    artifact_dir: Path,
    inherited_env: dict[str, str],
    *,
    connector: bool,
) -> tuple[subprocess.Popen[bytes], Path, tuple[BinaryIO, BinaryIO]]:
    home.mkdir()
    write_json(home / "config.json", config)
    control_socket = home / "private" / "daemon.sock"
    if len(os.fsencode(control_socket)) > 100:
        raise ContractError(f"control socket path is too long: {control_socket}")
    stdout_path = artifact_dir / f"{name}.stdout.log"
    stderr_path = artifact_dir / f"{name}.stderr.log"
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    env = dict(inherited_env)
    env.update(
        {
            "MYOWNMESH_HOME": str(home),
            "MYOWNMESH_LOG_FORMAT": "json",
            "MYOWNMESH_CONN_TRACE": "1",
        }
    )
    if not connector:
        env.pop(REALTIME_POLICY, None)
    process = subprocess.Popen(
        [str(binary), "serve"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    return process, control_socket, (stdout, stderr)


def run_pair(
    *,
    mode: str,
    binary: Path,
    root: Path,
    timeout: float,
    inherited_env: dict[str, str],
    manifest: dict[str, Any],
) -> None:
    scenario_dir = root / mode
    scenario_dir.mkdir()
    network = f"e2e{secrets.token_hex(8)}"
    payload = {
        "contract": "shipped-signaling-backends-e2e",
        "backend": mode,
        "token": secrets.token_hex(16),
    }
    processes: dict[str, subprocess.Popen[bytes]] = {}
    sockets: dict[str, Path] = {}
    logs: dict[str, tuple[BinaryIO, BinaryIO]] = {}
    event_stream: socket.socket | None = None
    event_reader: BinaryIO | None = None
    scenario: dict[str, Any] = {"mode": mode, "network": network, "observations": {}, "artifacts": {}}
    relay_port: int | None = None
    try:
        if mode == "nostr":
            relay_port = free_tcp_port()
            relay_config_path = scenario_dir / "relay-config.json"
            write_json(relay_config_path, relay_config(relay_port))
            scenario["artifacts"]["relay_config"] = str(relay_config_path)
            process, control, log_handles = start_daemon(
                "relay", binary, scenario_dir / "home-relay", relay_config(relay_port), scenario_dir, inherited_env, connector=False
            )
            processes["relay"] = process
            sockets["relay"] = control
            logs["relay"] = log_handles
            wait_until("self-hosted relay control readiness", timeout, lambda: request(control, {"op": "status"}))
            wait_until("self-hosted relay service status", timeout, lambda: signaling_service_running(control))
            wait_until(
                "self-hosted relay TCP readiness",
                timeout,
                lambda: _tcp_ready("127.0.0.1", relay_port),
            )
            scenario["observations"]["relay_ready"] = {"port": relay_port, "control": True}

        relay_url = f"ws://127.0.0.1:{relay_port}" if relay_port is not None else None
        for name in ("a", "b"):
            process, control, log_handles = start_daemon(
                name,
                binary,
                scenario_dir / f"home-{name}",
                daemon_config(network, mode=mode, relay_url=relay_url),
                scenario_dir,
                inherited_env,
                connector=True,
            )
            processes[name] = process
            sockets[name] = control
            logs[name] = log_handles
            scenario["artifacts"][f"{name}_stdout"] = str(scenario_dir / f"{name}.stdout.log")
            scenario["artifacts"][f"{name}_stderr"] = str(scenario_dir / f"{name}.stderr.log")
            wait_until(f"{mode} daemon {name} control readiness", timeout, lambda control=control: request(control, {"op": "status"}))

        peer_a = wait_until("A authenticated and promoted peer", timeout, lambda: active_peer(sockets["a"], network))
        peer_b = wait_until("B authenticated and promoted peer", timeout, lambda: active_peer(sockets["b"], network))
        if peer_a.get("device_id") == peer_b.get("device_id"):
            raise ContractError("the two shipped daemons unexpectedly share one device identity")
        scenario["observations"]["authenticated_promoted"] = {
            "a_sees": peer_a,
            "b_sees": peer_b,
        }

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
        request(
            sockets["a"],
            {
                "op": "channel_send_reliable",
                "network": network,
                "channel": CHANNEL,
                "peer": peer_a["device_id"],
                "payload": payload,
            },
            timeout=timeout,
        )
        delivered: dict[str, Any] | None = None
        event_path = scenario_dir / "b.events.jsonl"
        with event_path.open("w", encoding="utf-8", newline="\n") as event_log:
            deadline = time.monotonic() + timeout
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
            raise ContractError("B did not expose the exact typed-channel payload")
        scenario["artifacts"]["b_events"] = str(event_path)
        scenario["observations"]["typed_payload"] = {
            "from": delivered["from"],
            "channel": delivered["channel"],
            "payload_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
        }

        # A real graceful process terminal is the withdrawal trigger.  B's
        # event stream must expose the canonical peer Dropped event, and its
        # peers query must no longer report A active.
        terminal_a = terminate_process(processes["a"])
        scenario["observations"]["a_terminal"] = terminal_a
        if terminal_a["forced"] or terminal_a["returncode"] != 0:
            raise ContractError(f"A did not reach a graceful terminal: {terminal_a}")
        withdrawal: dict[str, Any] | None = None
        deadline = time.monotonic() + timeout
        with event_path.open("a", encoding="utf-8", newline="\n") as event_log:
            while time.monotonic() < deadline:
                event_stream.settimeout(max(0.1, deadline - time.monotonic()))
                frame = read_json_line(event_reader)
                event_log.write(json.dumps(frame, sort_keys=True) + "\n")
                event_log.flush()
                if dropped_event(frame, network, peer_b["device_id"]):
                    withdrawal = frame
                    break
        if withdrawal is None:
            raise ContractError("B did not expose a canonical peer Dropped withdrawal for A")
        wait_until(
            "B peer withdrawal state",
            timeout,
            lambda: peer_withdrawn(sockets["b"], network, peer_b["device_id"]),
        )
        scenario["observations"]["withdrawal"] = withdrawal
    finally:
        if event_reader is not None:
            event_reader.close()
        if event_stream is not None:
            event_stream.close()
        terminals: dict[str, Any] = {}
        for name, process in reversed(tuple(processes.items())):
            terminals[name] = terminate_process(process)
        scenario["terminals"] = terminals
        for stdout, stderr in logs.values():
            stdout.close()
            stderr.close()
        bad_terminals = {
            name: terminal
            for name, terminal in terminals.items()
            if terminal["forced"] or terminal["returncode"] != 0
        }
        scenario["observations"]["all_graceful_terminals"] = not bad_terminals
        manifest["scenarios"].append(scenario)
        write_json(root / "manifest.json", manifest)
        if bad_terminals and sys.exc_info()[0] is None:
            raise ContractError(f"shipped process terminals were not graceful: {bad_terminals}")


def _tcp_ready(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def main() -> int:
    args = parse_args()
    if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
        raise ContractError("shipped daemon control and embedded mDNS require a Unix host")
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
    manifest: dict[str, Any] = {
        "schema": "myownmesh-shipped-signaling-backends-e2e/v1",
        "started_at": utc_now(),
        "binary": str(binary),
        "binary_sha256": file_sha256(binary),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "resource_policy": {"grant_supplied": True, "connector_realtime_policy": realtime},
        "scenarios": [],
    }
    inherited_env = os.environ.copy()
    error: BaseException | None = None
    try:
        run_pair(mode="mdns", binary=binary, root=artifact_dir, timeout=args.timeout, inherited_env=inherited_env, manifest=manifest)
        run_pair(mode="nostr", binary=binary, root=artifact_dir, timeout=args.timeout, inherited_env=inherited_env, manifest=manifest)
        manifest["finished_at"] = utc_now()
        write_json(artifact_dir / "manifest.json", manifest)
        return 0
    except BaseException as caught:
        error = caught
        manifest["error"] = f"{type(caught).__name__}: {caught}"
        manifest["finished_at"] = utc_now()
        write_json(artifact_dir / "manifest.json", manifest)
        raise
    finally:
        if error is not None:
            # `run_pair` writes after each scenario; this preserves the raw
            # top-level manifest if validation failed before either scenario.
            write_json(artifact_dir / "manifest.json", manifest)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        print(f"contract failure: {error}", file=sys.stderr)
        raise SystemExit(2)
