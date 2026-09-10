#!/usr/bin/env python3
"""Qualify one shipped daemon through a finite, real process lifecycle.

The runner starts two real ``myownmesh serve`` processes with isolated homes,
uses production mDNS/endpoint-auth/promotion, sends one acknowledged channel
payload over the shipped control protocol, shuts both processes down, and
repeats with the same homes.  It never builds the product, uses LocalBroker,
or invents resource values: the finite grant is supplied by the owner and the
daemon's status response is preserved verbatim.

Linux records exact process-tree RSS, CPU, thread, file-descriptor, child-PID,
and exit observations from ``/proc``.  Windows keeps exact PID/exit/forced
termination observations and marks tree metrics unavailable because the
standard library has no stable child/fd/thread query; this is intentional
best-effort evidence, not a fabricated zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
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
U64_MAX = (1 << 64) - 1
LINE_LIMIT = 8 * 1024 * 1024
CHANNEL = "process-resource-e2e"
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
    """The owner-selected process contract could not be established."""


class LifecycleError(ContractError):
    """A cycle failed after producing a result that must remain in the manifest."""

    def __init__(self, message: str, result: dict[str, Any]) -> None:
        super().__init__(message)
        self.result = result


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_grant(raw: str) -> dict[str, int]:
    """Validate the owner grant shape without assigning any resource amount."""

    if not raw.strip() or any(word in raw.lower() for word in ("unbounded", "infinite")):
        raise ContractError("--resource-grant must be a finite owner-selected grant")
    values: dict[str, int] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item or "=" not in item:
            raise ContractError("--resource-grant entries must be dimension=value")
        name, value = (part.strip() for part in item.split("=", 1))
        if name not in GRANT_DIMENSIONS:
            raise ContractError(f"--resource-grant names unknown dimension {name!r}")
        if name in values:
            raise ContractError(f"--resource-grant repeats dimension {name!r}")
        try:
            amount = int(value, 10)
        except ValueError as error:
            raise ContractError(f"--resource-grant dimension {name!r} is not an integer") from error
        if amount < 0:
            raise ContractError(f"--resource-grant dimension {name!r} is negative")
        if amount > U64_MAX:
            raise ContractError(f"--resource-grant dimension {name!r} exceeds the u64 maximum")
        values[name] = amount
    missing = [name for name in GRANT_DIMENSIONS if name not in values]
    if missing:
        raise ContractError("--resource-grant omits dimensions: " + ", ".join(missing))
    return values


def read_json_line(reader: BinaryIO) -> Any:
    line = reader.readline(LINE_LIMIT + 1)
    if not line:
        raise ContractError("control endpoint closed before a JSON line")
    if len(line) > LINE_LIMIT or not line.endswith(b"\n"):
        raise ContractError("control response exceeded the fixed line ceiling")
    try:
        return json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"control response was not JSON: {error}") from error


def request(control_socket: Path, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Send one real line-protocol request on Unix."""

    if not hasattr(socket, "AF_UNIX"):
        raise ContractError("direct channel control requires a Unix-domain socket")
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(str(control_socket))
        stream.sendall(encoded)
        with stream.makefile("rb") as reader:
            response = read_json_line(reader)
    if not isinstance(response, dict):
        raise ContractError(f"{body.get('op')} returned a non-object response")
    if response.get("ok") is not True:
        raise ContractError(f"{body.get('op')} refused: {response.get('error')}")
    return response


def cli_status(binary: Path, home: Path, timeout: float) -> dict[str, Any]:
    """Use the shipped CLI status surface where named pipes replace Unix sockets."""

    environment = os.environ.copy()
    environment["MYOWNMESH_HOME"] = str(home)
    completed = subprocess.run(
        [str(binary), "ctl", "status"],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise ContractError(f"ctl status failed ({completed.returncode}): {completed.stderr.strip()}")
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ContractError(f"ctl status was not JSON: {error}") from error
    if not isinstance(data, dict):
        raise ContractError("ctl status returned a non-object")
    return {"ok": True, "data": data}


def status_request(binary: Path, home: Path, control_socket: Path, timeout: float) -> dict[str, Any]:
    if os.name == "posix" and hasattr(socket, "AF_UNIX"):
        return request(control_socket, {"op": "status"}, timeout)
    return cli_status(binary, home, timeout)


def validate_status(response: dict[str, Any], name: str) -> dict[str, Any]:
    """Require only fields present in the shipped Status reply."""

    data = response.get("data")
    if not isinstance(data, dict):
        raise ContractError(f"{name} status has no object data payload")
    required = ("version", "device_id", "joined_networks", "realtime")
    missing = [field for field in required if field not in data]
    if missing:
        raise ContractError(f"{name} status omitted shipped fields: {', '.join(missing)}")
    if not isinstance(data["device_id"], str) or not data["device_id"]:
        raise ContractError(f"{name} status has no device_id")
    if not isinstance(data["joined_networks"], list) or not isinstance(data["realtime"], dict):
        raise ContractError(f"{name} status has malformed joined_networks/realtime fields")
    return data


def open_events(control_socket: Path, timeout: float) -> tuple[socket.socket, BinaryIO, str, str]:
    if not hasattr(socket, "AF_UNIX"):
        raise ContractError("the full channel workload requires Unix control sockets")
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
        if response.get("ok") is not True or not isinstance(client_id, str) or not isinstance(capability, str):
            raise ContractError(f"events_subscribe refused: {response!r}")
        return stream, reader, client_id, capability
    except BaseException:
        if reader is not None:
            try:
                reader.close()
            except OSError:
                pass
        try:
            stream.close()
        except OSError:
            pass
        raise


def peer_snapshot(control_socket: Path, network: str, timeout: float) -> list[dict[str, Any]]:
    response = request(control_socket, {"op": "peers_list", "network": network}, timeout)
    peers = (response.get("data") or {}).get("peers") or []
    return [peer for peer in peers if isinstance(peer, dict)]


def active_peer(peers: list[dict[str, Any]]) -> dict[str, Any] | None:
    for peer in peers:
        if peer.get("status") == "active" and peer.get("authenticated") is True:
            return peer
    return None


def record_phase(
    result: dict[str, Any],
    daemon: str,
    phase: str,
    epoch: float,
    started: float,
    finished: float,
) -> None:
    """Record phase timing against one common monotonic run epoch."""

    result.setdefault("phase_timings", {}).setdefault(daemon, {})[phase] = {
        "start_seconds": started - epoch,
        "end_seconds": finished - epoch,
        "duration_seconds": finished - started,
    }


def wait_for(label: str, timeout: float, poll_interval: float, probe: Callable[[], Any], sampler: "ProcessSampler") -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        sampler.sample(label)
        try:
            value = probe()
            if value:
                return value
            last = value
        except (OSError, ValueError, ContractError) as error:
            last = repr(error)
        time.sleep(poll_interval)
    raise ContractError(f"timed out waiting for {label}; last observation: {last!r}")


def parse_proc_stat(raw: str) -> tuple[int, int, int]:
    """Return ppid, user ticks, system ticks from Linux proc stat text."""

    remainder = raw.rsplit(")", 1)[1].split()
    return int(remainder[1]), int(remainder[11]), int(remainder[12])


def linux_process_snapshot(pid: int, page_size: int, clock_ticks: int) -> dict[str, Any] | None:
    root = Path(f"/proc/{pid}")
    try:
        status = (root / "status").read_text(encoding="utf-8")
        stat = (root / "stat").read_text(encoding="utf-8")
        values: dict[str, int] = {}
        for line in status.splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                values[line.split(":", 1)[0]] = int(line.split()[1]) * 1024
        ppid, user_ticks, system_ticks = parse_proc_stat(stat)
        threads = len(list((root / "task").iterdir()))
        fds = len(list((root / "fd").iterdir()))
        return {
            "pid": pid,
            "ppid": ppid,
            "rss_bytes": values.get("VmRSS"),
            "peak_rss_bytes": values.get("VmHWM"),
            "cumulative_cpu_seconds": (user_ticks + system_ticks) / clock_ticks,
            "thread_count": threads,
            "fd_count": fds,
            "page_size": page_size,
            "clock_ticks": clock_ticks,
        }
    except (FileNotFoundError, NotADirectoryError, OSError, ValueError, IndexError, ZeroDivisionError):
        return None


class ProcessSampler:
    """Sample process trees without turning unavailable metrics into zeros."""

    def __init__(self, processes: dict[str, subprocess.Popen[bytes]]) -> None:
        self.processes = processes
        self.linux = sys.platform.startswith("linux")
        self.samples: list[dict[str, Any]] = []
        self.peak_rss: dict[str, int | None] = {name: None for name in processes}
        self.cumulative_cpu: dict[str, float | None] = {name: None for name in processes}
        self.seen_descendants: dict[str, set[int]] = {name: set() for name in processes}
        self._page_size = os.sysconf("SC_PAGE_SIZE") if self.linux else None
        self._clock_ticks = os.sysconf("SC_CLK_TCK") if self.linux else None

    def _linux_descendants(self, root_pid: int) -> list[int]:
        parents: dict[int, int] = {}
        for entry in Path("/proc").glob("[0-9]*"):
            try:
                ppid, _, _ = parse_proc_stat((entry / "stat").read_text(encoding="utf-8"))
                parents[int(entry.name)] = ppid
            except (FileNotFoundError, OSError, ValueError, IndexError):
                continue
        found = {root_pid}
        changed = True
        while changed:
            changed = False
            for pid, ppid in parents.items():
                if ppid in found and pid not in found:
                    found.add(pid)
                    changed = True
        return sorted(found)

    def sample(self, phase: str) -> None:
        observation: dict[str, Any] = {
            "monotonic": time.monotonic(),
            "phase": phase,
            "metric_method": "linux_proc" if self.linux else "pid_exit_only",
            "processes": {},
        }
        for name, process in self.processes.items():
            if self.linux and self._page_size is not None and self._clock_ticks:
                records = [
                    record
                    for pid in self._linux_descendants(process.pid)
                    if (record := linux_process_snapshot(pid, self._page_size, self._clock_ticks)) is not None
                ]
                self.seen_descendants[name].update(
                    record["pid"] for record in records if record["pid"] != process.pid
                )
                root = next((record for record in records if record["pid"] == process.pid), None)
                def sum_metric(key: str) -> int | float | None:
                    if not records or any(record.get(key) is None for record in records):
                        return None
                    return sum(record[key] for record in records)

                tree_rss = sum_metric("rss_bytes")
                tree_peak = sum_metric("peak_rss_bytes")
                tree_cumulative_cpu = sum_metric("cumulative_cpu_seconds")
                tree_threads = sum_metric("thread_count")
                tree_fds = sum_metric("fd_count")
                if tree_peak is not None and (self.peak_rss[name] is None or tree_peak > self.peak_rss[name]):
                    self.peak_rss[name] = tree_peak
                if tree_cumulative_cpu is not None and (
                    self.cumulative_cpu[name] is None or tree_cumulative_cpu > self.cumulative_cpu[name]
                ):
                    self.cumulative_cpu[name] = tree_cumulative_cpu
                observation["processes"][name] = {
                    "pid": process.pid,
                    "returncode": process.poll(),
                    "tree_pids": [record["pid"] for record in records],
                    "rss_bytes": tree_rss,
                    "peak_rss_bytes": tree_peak,
                    "cumulative_cpu_seconds": tree_cumulative_cpu,
                    "thread_count": tree_threads,
                    "fd_count": tree_fds,
                    "root": root,
                }
            else:
                observation["processes"][name] = {
                    "pid": process.pid,
                    "returncode": process.poll(),
                    "tree_pids": None,
                    "rss_bytes": None,
                    "peak_rss_bytes": None,
                    "cumulative_cpu_seconds": None,
                    "thread_count": None,
                    "fd_count": None,
                    "root": None,
                }
        self.samples.append(observation)

    def orphan_pids(self) -> dict[str, list[int] | None]:
        if not self.linux:
            return {name: None for name in self.processes}
        return {
            name: [
                pid
                for pid in sorted(seen)
                if linux_process_snapshot(pid, self._page_size or 0, self._clock_ticks or 1) is not None
            ]
            for name, seen in self.seen_descendants.items()
        }

    def result(self) -> dict[str, Any]:
        return {
            "metric_method": "linux_proc" if self.linux else "pid_exit_only",
            "tree_metrics_available": self.linux,
            "peak_rss_bytes": self.peak_rss,
            "cumulative_cpu_seconds": self.cumulative_cpu,
            "samples": self.samples,
        }


def terminate(process: subprocess.Popen[bytes], grace: float) -> dict[str, Any]:
    forced = False
    if process.poll() is None:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
        elif hasattr(signal, "CTRL_BREAK_EVENT"):
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT)
            except (OSError, ValueError):
                process.terminate()
        else:
            process.terminate()
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            forced = True
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait(timeout=grace)
    return {"pid": process.pid, "returncode": process.returncode, "forced": forced}


def terminate_processes(
    processes: dict[str, subprocess.Popen[bytes]], grace: float
) -> dict[str, dict[str, Any]]:
    """Attempt every daemon independently and retain each terminal outcome."""

    terminals: dict[str, dict[str, Any]] = {}
    for name, process in reversed(tuple(processes.items())):
        try:
            terminals[name] = terminate(process, grace)
        except Exception as error:
            terminals[name] = {
                "pid": process.pid,
                "returncode": process.poll(),
                "forced": None,
                "error": repr(error),
            }
    return terminals


def close_logs(logs: dict[str, tuple[BinaryIO, BinaryIO]]) -> list[str]:
    """Close both stdout and stderr handles even when one close fails."""

    errors: list[str] = []
    for name, (stdout, stderr) in logs.items():
        for stream_name, stream in (("stdout", stdout), ("stderr", stderr)):
            try:
                stream.close()
            except Exception as error:
                errors.append(f"{name} {stream_name}: {error!r}")
    return errors


def terminal_is_clean(
    terminals: dict[str, dict[str, Any]], cleanup_errors: list[str], process_count: int
) -> bool:
    """Require every process and every cleanup operation to have a clean result."""

    return bool(process_count) and not cleanup_errors and all(
        value.get("forced") is False
        and value.get("returncode") == 0
        and "error" not in value
        for value in terminals.values()
    )


def workload_payload(
    network: str,
    cycle: int,
    run_epoch_id: str,
    sender_identity: str,
    recipient_identity: str,
    payload_bytes: int,
) -> tuple[dict[str, Any], str, str]:
    if sender_identity == recipient_identity:
        raise ContractError("channel workload requires distinct sender and recipient identities")
    direction = "a-to-b"
    repeat_discriminator = f"{run_epoch_id}:{network}:{cycle}:{direction}"
    payload = {
        "contract": "process-resource-e2e",
        "cycle": cycle,
        "sender_identity": sender_identity,
        "recipient_identity": recipient_identity,
        "direction": direction,
        "repeat_discriminator": repeat_discriminator,
        "body": "x" * payload_bytes,
    }
    return payload, direction, repeat_discriminator


def daemon_config(network: str) -> dict[str, Any]:
    return {
        "version": 2,
        "networks": [
            {
                "id": network,
                "network_id": network,
                "label": "process-resource-e2e",
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
    parser.add_argument("--binary", required=True, type=Path, help="existing shipped myownmesh executable")
    parser.add_argument("--artifact-dir", required=True, type=Path, help="new or empty evidence directory")
    parser.add_argument("--resource-grant", required=True, help="complete finite owner grant")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument("--payload-bytes", type=int, default=32)
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> dict[str, int]:
    if not math.isfinite(args.timeout) or not math.isfinite(args.poll_interval):
        raise ContractError("--timeout and --poll-interval must be finite")
    if args.timeout <= 0 or args.poll_interval <= 0:
        raise ContractError("--timeout and --poll-interval must be positive")
    if args.payload_bytes <= 0:
        raise ContractError("--payload-bytes must be positive")
    if args.payload_bytes > U64_MAX:
        raise ContractError("--payload-bytes exceeds the u64 maximum")
    if not args.binary.is_file() or (os.name == "posix" and not os.access(args.binary, os.X_OK)):
        raise ContractError(f"--binary is not an executable file: {args.binary}")
    return validate_grant(args.resource_grant)


def run_lifecycle(
    args: argparse.Namespace,
    binary: Path,
    run_dir: Path,
    homes: dict[str, Path],
    network: str,
    cycle: int,
    create_homes: bool,
    run_epoch_id: str | None = None,
    monotonic_epoch: float | None = None,
) -> dict[str, Any]:
    if create_homes:
        for home in homes.values():
            home.mkdir(parents=True)
            write_json(home / "config.json", daemon_config(network))
    sockets = {name: home / "daemon.sock" for name, home in homes.items()}
    if os.name == "posix":
        for control_socket in sockets.values():
            if len(os.fsencode(control_socket)) > 100:
                raise ContractError(f"control socket path is too long: {control_socket}")

    processes: dict[str, subprocess.Popen[bytes]] = {}
    logs: dict[str, tuple[BinaryIO, BinaryIO]] = {}
    sampler: ProcessSampler | None = None
    events: socket.socket | None = None
    event_reader: BinaryIO | None = None
    monotonic_epoch = time.monotonic() if monotonic_epoch is None else monotonic_epoch
    result: dict[str, Any] = {
        "run_epoch": run_epoch_id or f"cycle-{cycle}",
        "monotonic_epoch_seconds": monotonic_epoch,
        "cycle": cycle,
        "network": network,
        "status": {},
        "workload": {},
        "phase_timings": {},
    }
    pending_cleanup_errors: list[str] = []
    try:
        for name in ("a", "b"):
            spawn_started = time.monotonic()
            stdout = (run_dir / f"daemon-{name}.stdout.log").open("wb")
            try:
                stderr = (run_dir / f"daemon-{name}.stderr.log").open("wb")
            except Exception:
                try:
                    stdout.close()
                except Exception as error:
                    pending_cleanup_errors.append(f"{name} stdout: {error!r}")
                raise
            logs[name] = (stdout, stderr)
            environment = os.environ.copy()
            environment.update(
                {
                    "MYOWNMESH_HOME": str(homes[name]),
                    "MYOWNMESH_LOG_FORMAT": "json",
                    "MYOWNMESH_CONN_TRACE": "1",
                    RESOURCE_GRANT: args.resource_grant,
                    REALTIME_POLICY: "disabled",
                }
            )
            kwargs: dict[str, Any] = {
                "env": environment,
                "stdin": subprocess.DEVNULL,
                "stdout": stdout,
                "stderr": stderr,
            }
            if os.name == "posix":
                kwargs["start_new_session"] = True
            elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            processes[name] = subprocess.Popen([str(binary), "serve"], **kwargs)
            record_phase(result, name, "spawn", monotonic_epoch, spawn_started, time.monotonic())
        sampler = ProcessSampler(processes)
        sampler.sample("spawned")

        for name in ("a", "b"):
            ready_started = time.monotonic()
            status = wait_for(
                f"{name} status readiness",
                args.timeout,
                args.poll_interval,
                lambda name=name: status_request(binary, homes[name], sockets[name], args.timeout),
                sampler,
            )
            validate_status(status, name)
            result["status"].setdefault(name, []).append({"phase": "ready", "response": status})
            record_phase(result, name, "ready", monotonic_epoch, ready_started, time.monotonic())
        sampler.sample("ready")
        sampler.sample("loaded")

        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            result["workload"] = {
                "channel_supported": False,
                "reason": "Windows/non-Unix named-pipe channel client is unavailable in Python stdlib",
            }
        else:
            auth_started = time.monotonic()
            peer_a = wait_for(
                "A authenticated peer",
                args.timeout,
                args.poll_interval,
                lambda: active_peer(peer_snapshot(sockets["a"], network, args.timeout)),
                sampler,
            )
            record_phase(result, "a", "authenticated", monotonic_epoch, auth_started, time.monotonic())
            auth_started = time.monotonic()
            peer_b = wait_for(
                "B authenticated peer",
                args.timeout,
                args.poll_interval,
                lambda: active_peer(peer_snapshot(sockets["b"], network, args.timeout)),
                sampler,
            )
            record_phase(result, "b", "authenticated", monotonic_epoch, auth_started, time.monotonic())
            target_b = peer_a.get("device_id")
            sender_a = peer_b.get("device_id")
            if not isinstance(target_b, str) or not isinstance(sender_a, str):
                raise ContractError("active peer status lacks canonical device_id")
            events, event_reader, client_id, capability = open_events(sockets["b"], args.timeout)
            request(
                sockets["b"],
                {
                    "op": "channel_subscribe",
                    "client_id": client_id,
                    "client_capability": capability,
                    "network": network,
                    "channel": CHANNEL,
                },
                args.timeout,
            )
            payload, direction, repeat_discriminator = workload_payload(
                network,
                cycle,
                run_epoch_id or "local",
                sender_a,
                target_b,
                args.payload_bytes,
            )
            channel_started = time.monotonic()
            request(
                sockets["a"],
                {
                    "op": "channel_send_reliable",
                    "network": network,
                    "channel": CHANNEL,
                    "peer": target_b,
                    "payload": payload,
                },
                args.timeout,
            )
            record_phase(result, "a", "channel", monotonic_epoch, channel_started, time.monotonic())
            receive_started = time.monotonic()
            deadline = time.monotonic() + args.timeout
            delivered = None
            while time.monotonic() < deadline:
                sampler.sample("quiescent")
                events.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    frame = read_json_line(event_reader)
                except (TimeoutError, socket.timeout):
                    continue
                if (
                    isinstance(frame, dict)
                    and frame.get("kind") == "channel_inbound"
                    and frame.get("network") == network
                    and frame.get("channel") == CHANNEL
                    and frame.get("from") == sender_a
                    and frame.get("payload") == payload
                ):
                    delivered = frame
                    break
            if delivered is None:
                raise ContractError("timed out waiting for the acknowledged channel payload")
            receive_finished = time.monotonic()
            record_phase(result, "b", "channel", monotonic_epoch, receive_started, receive_finished)
            payload_bytes = len(payload["body"].encode("utf-8"))
            result["workload"] = {
                "channel_supported": True,
                "channel": CHANNEL,
                "payload": payload,
                "from": sender_a,
                "to": target_b,
                "sender_identity": sender_a,
                "recipient_identity": target_b,
                "direction": direction,
                "repeat_discriminator": repeat_discriminator,
                "payload_bytes": payload_bytes,
                "throughput_bytes_per_second": (
                    payload_bytes / (receive_finished - receive_started)
                    if receive_finished > receive_started
                    else None
                ),
                "delivered": delivered,
            }
        for name in ("a", "b"):
            quiescent_started = time.monotonic()
            status = status_request(binary, homes[name], sockets[name], args.timeout)
            validate_status(status, name)
            result["status"].setdefault(name, []).append({"phase": "quiescent", "response": status})
            record_phase(result, name, "quiescent", monotonic_epoch, quiescent_started, time.monotonic())
        if sampler is not None:
            sampler.sample("pre_shutdown")
    except LifecycleError:
        raise
    except Exception as error:
        result["error"] = repr(error)
        raise LifecycleError(f"cycle {cycle} failed: {error}", result) from error
    finally:
        cleanup_errors = list(pending_cleanup_errors)
        if event_reader is not None:
            try:
                event_reader.close()
            except Exception as error:
                cleanup_errors.append(f"event reader: {error!r}")
        if events is not None:
            try:
                events.close()
            except Exception as error:
                cleanup_errors.append(f"event socket: {error!r}")
        shutdown_started = time.monotonic()
        try:
            terminals = terminate_processes(processes, args.timeout)
        except Exception as error:
            terminals = {}
            cleanup_errors.append(f"process termination: {error!r}")
        shutdown_finished = time.monotonic()
        for name in processes:
            record_phase(result, name, "shutdown", monotonic_epoch, shutdown_started, shutdown_finished)
        if sampler is not None:
            try:
                sampler.sample("terminal")
            except Exception as error:
                cleanup_errors.append(f"terminal sampling: {error!r}")
            try:
                result["orphan_children"] = sampler.orphan_pids()
            except Exception as error:
                result["orphan_children"] = None
                cleanup_errors.append(f"orphan sampling: {error!r}")
            try:
                result["process"] = sampler.result()
            except Exception as error:
                result["process"] = {}
                cleanup_errors.append(f"process result: {error!r}")
        else:
            result["process"] = {}
            result["orphan_children"] = None
        result["terminals"] = terminals
        log_errors = close_logs(logs)
        cleanup_errors.extend(log_errors)
        result["cleanup_errors"] = cleanup_errors
        result["clean_terminal"] = terminal_is_clean(terminals, cleanup_errors, len(processes))
        if os.name == "posix" and result["orphan_children"] is not None:
            result["no_orphan_children"] = all(not pids for pids in result["orphan_children"].values())
        else:
            result["no_orphan_children"] = None
        result["duration_seconds"] = time.monotonic() - monotonic_epoch
    if not result["clean_terminal"]:
        raise LifecycleError(f"cycle {cycle} did not terminate cleanly: {result['terminals']!r}", result)
    if result["no_orphan_children"] is False:
        raise LifecycleError(f"cycle {cycle} left orphan descendants: {result['orphan_children']!r}", result)
    return result


def run_and_record_cycle(manifest: dict[str, Any], lifecycle: Callable[[], dict[str, Any]]) -> None:
    """Record a cycle even when lifecycle cleanup raises after its evidence is complete."""

    try:
        result = lifecycle()
    except LifecycleError as error:
        manifest["cycles"].append(error.result)
        raise
    manifest["cycles"].append(result)


def aggregate_cycles(cycles: list[dict[str, Any]], run_epoch_id: str) -> dict[str, Any]:
    """Summarize repeated cycles without fabricating unavailable measurements."""

    summary: dict[str, Any] = {
        "run_epoch": run_epoch_id,
        "cycle_count": len(cycles),
        "clean_terminal_cycles": sum(1 for cycle in cycles if cycle.get("clean_terminal") is True),
        "channel_cycles": sum(
            1 for cycle in cycles if cycle.get("workload", {}).get("channel_supported") is True
        ),
        "cycle_durations_seconds": [cycle.get("duration_seconds") for cycle in cycles],
        "payload_bytes_by_cycle": [cycle.get("workload", {}).get("payload_bytes") for cycle in cycles],
        "payload_bytes_total": None,
        "throughput_bytes_per_second_average": None,
        "daemon_metrics": {},
        "phase_timings": {},
    }
    payload_values = [
        cycle.get("workload", {}).get("payload_bytes")
        for cycle in cycles
        if cycle.get("workload", {}).get("payload_bytes") is not None
    ]
    throughput_values = [
        cycle.get("workload", {}).get("throughput_bytes_per_second")
        for cycle in cycles
        if cycle.get("workload", {}).get("throughput_bytes_per_second") is not None
    ]
    if payload_values:
        summary["payload_bytes_total"] = sum(payload_values)
    if throughput_values:
        summary["throughput_bytes_per_second_average"] = sum(throughput_values) / len(throughput_values)
    for daemon in ("a", "b"):
        cycle_metrics = [cycle.get("process", {}) for cycle in cycles]
        peak_values = [metrics.get("peak_rss_bytes", {}).get(daemon) for metrics in cycle_metrics]
        cpu_values = [metrics.get("cumulative_cpu_seconds", {}).get(daemon) for metrics in cycle_metrics]
        summary["daemon_metrics"][daemon] = {
            "peak_rss_bytes_max": max((value for value in peak_values if value is not None), default=None),
            "cumulative_cpu_seconds_max": max(
                (value for value in cpu_values if value is not None), default=None
            ),
            "unavailable_peak_rss_cycles": sum(value is None for value in peak_values),
            "unavailable_cpu_cycles": sum(value is None for value in cpu_values),
        }
        phase_names = {
            phase
            for cycle in cycles
            for phase in cycle.get("phase_timings", {}).get(daemon, {})
        }
        for phase in sorted(phase_names):
            durations = [
                cycle.get("phase_timings", {}).get(daemon, {}).get(phase, {}).get("duration_seconds")
                for cycle in cycles
            ]
            available = [duration for duration in durations if duration is not None]
            summary["phase_timings"].setdefault(daemon, {})[phase] = {
                "durations_seconds": durations,
                "average_seconds": sum(available) / len(available) if available else None,
            }
    return summary


def main() -> int:
    args = parse_args()
    grant = validate_args(args)
    binary = args.binary.resolve(strict=True)
    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if any(artifact_dir.iterdir()):
        raise ContractError(f"artifact directory must be empty: {artifact_dir}")

    run_epoch_id = utc_now() + "-" + secrets.token_hex(8)
    network = "e2e" + secrets.token_hex(8)
    homes = {name: artifact_dir / f"home-{name}" for name in ("a", "b")}
    manifest: dict[str, Any] = {
        "schema": "myownmesh-process-resource-e2e/v1",
        "started_at": utc_now(),
        "run_epoch": run_epoch_id,
        "binary": str(binary),
        "binary_sha256": sha256_file(binary),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "uname": platform.uname()._asdict(),
        },
        "inputs": {
            "network": network,
            "resource_grant_sha256": hashlib.sha256(args.resource_grant.encode()).hexdigest(),
            "resource_dimensions": grant,
            "timeout_seconds": args.timeout,
            "poll_interval_seconds": args.poll_interval,
            "payload_bytes": args.payload_bytes,
            "transport": "production-mdns-and-control-channel",
            "localbroker": False,
        },
        "cycles": [],
        "claims": {"capacity_or_slo": False, "metrics_are_raw_observations": True},
    }
    monotonic_epoch = time.monotonic()
    manifest["monotonic_epoch_seconds"] = monotonic_epoch
    try:
        for cycle in (1, 2):
            run_dir = artifact_dir / f"cycle-{cycle:04d}"
            run_dir.mkdir()
            run_and_record_cycle(
                manifest,
                lambda cycle=cycle, run_dir=run_dir: run_lifecycle(
                    args,
                    binary,
                    run_dir,
                    homes,
                    network,
                    cycle,
                    create_homes=cycle == 1,
                    run_epoch_id=run_epoch_id,
                    monotonic_epoch=monotonic_epoch,
                ),
            )
    finally:
        manifest["finished_at"] = utc_now()
        manifest["summary"] = aggregate_cycles(manifest["cycles"], run_epoch_id)
        manifest["clean_terminal"] = bool(manifest["cycles"]) and all(
            cycle.get("clean_terminal") and cycle.get("no_orphan_children") is not False
            for cycle in manifest["cycles"]
        )
        write_json(artifact_dir / "manifest.json", manifest)
    if not manifest["clean_terminal"]:
        raise ContractError("process-resource E2E did not establish clean terminal evidence")
    print(f"process-resource E2E completed; artifacts: {artifact_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        print(f"process-resource E2E error: {error}", file=sys.stderr)
        raise SystemExit(2)
