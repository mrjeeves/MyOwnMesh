#!/usr/bin/env python3
"""Measure a shipped two-daemon production path.

The executable, daemon arguments, finite resource grant, run count, timeout,
poll interval, message count, and payload size are all supplied by the owner.
This harness does not build or install anything, does not use LocalBroker, and
makes no capacity or SLO claim.  Its JSON output is raw measurement evidence,
not a qualification decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO, Callable


RESOURCE_GRANT = "MYOWNMESH_RESOURCE_GRANT"
REALTIME_POLICY = "MYOWNMESH_CONNECTOR_REALTIME_POLICY"
CHANNEL = "architecture-production-benchmark"
LINE_LIMIT = 8 * 1024 * 1024
SEMANTIC_LEDGER_CASES = (
    ("semantic_ledger_scale", "semantic_ledger_scale_n_1k", 1_000, True),
    ("semantic_ledger_scale", "semantic_ledger_scale_n_10k", 10_000, True),
    ("semantic_ledger_scale", "semantic_ledger_scale_n_100k", 100_000, True),
    ("semantic_ledger_scale", "semantic_ledger_scale_n_250k", 250_000, True),
    ("semantic_ledger_scale", "semantic_ledger_scale_n_500k", 500_000, True),
    ("semantic_ledger_scale", "semantic_ledger_scale_n_1m", 1_000_000, True),
    ("semantic_ledger_scale", "semantic_ledger_scale_open_presence_zero", None, True),
    (
        "durable_proof_delivery_r3",
        "r3_many_pending_deliveries_preserve_unrelated_links_and_footprints",
        -1,
        False,
    ),
    (
        "semantic_capacity_controls",
        "production_lifecycle_funds_exact_database_envelope_and_releases_it",
        -2,
        False,
    ),
    (
        "network_purge_r2",
        "purge_socket_success_deletes_exact_semantic_store",
        -3,
        True,
    ),
    (
        "two_peer_handshake",
        "application_payload_is_refused_before_approval_then_delivered_after_approval",
        -4,
        False,
    ),
    (
        "topology_routing",
        "bounded_route_fails_over_and_preserves_exact_once_delivery",
        -5,
        False,
    ),
)
SEMANTIC_PROOF_SELECTOR = "r3_many_pending_deliveries_preserve_unrelated_links_and_footprints"
SEMANTIC_CAPACITY_SELECTOR = "production_lifecycle_funds_exact_database_envelope_and_releases_it"
SEMANTIC_CAPACITY_EVENTS = {"semantic_capacity_footprint", "semantic_capacity_terminal"}
SEMANTIC_PURGE_SELECTOR = "purge_socket_success_deletes_exact_semantic_store"
SEMANTIC_HANDSHAKE_SELECTOR = "application_payload_is_refused_before_approval_then_delivered_after_approval"
SEMANTIC_ROUTE_SELECTOR = "bounded_route_fails_over_and_preserves_exact_once_delivery"
SEMANTIC_PURGE_FILES = {"main", "wal", "shm", "journal", "neighbor"}
SEMANTIC_PREFIXES = {
    SEMANTIC_PROOF_SELECTOR: "DURABLE_PROOF_DELIVERY_R3_METRIC",
    SEMANTIC_PURGE_SELECTOR: "NETWORK_PURGE_R2_METRIC",
}
SEMANTIC_PROOF_OPERATIONS = {
    "duplicate_enqueue",
    "rebind",
    "supersede",
    "settle",
    "duplicate_ack",
}
SEMANTIC_SCALE_FIELDS = {
    "selector",
    "platform",
    "scale_n",
    "admitted_delta",
    "seeded_admissions",
    "timed_admissions",
    "seed_total_ms",
    "unresolved",
    "admission_total_ms",
    "admission_end_to_end_total_ms",
    "admissions_per_sec",
    "admission_p50_ms",
    "admission_p95_ms",
    "admission_p99_ms",
    "window_evidence",
    "cache_state",
    "compaction_ms",
    "startup_plus_restore_ms",
    "db_main_bytes_peak",
    "db_wal_bytes_peak",
    "db_shm_bytes_peak",
    "db_journal_bytes_peak",
    "db_total_bytes_peak",
    "db_main_bytes_after_compaction",
    "db_wal_bytes_after_compaction",
    "db_shm_bytes_after_compaction",
    "db_total_bytes_after",
    "provider_baseline",
    "provider_final",
}
SEMANTIC_OPTIONAL_SCALE_COUNTERS = {
    "process_scope_cpu_time_ms": "float",
    "process_scope_read_bytes_delta": "int",
    "process_lifetime_peak_vmhwm_bytes": "int",
    "process_rss_after_seed_bytes": "int",
    "process_rss_after_workload_bytes": "int",
    "process_rss_after_compaction_bytes": "int",
    "process_rss_after_restore_bytes": "int",
    "process_scope_write_bytes_delta": "int",
    "process_scope_write_bytes_per_admission": "float",
}
SEMANTIC_CACHE_STATE = "mixed_process_cache_no_flush"
SEMANTIC_FOOTPRINT_FIELDS = {"main_bytes", "wal_bytes", "shm_bytes", "journal_bytes", "temp_bytes"}
SEMANTIC_PROVIDER_FIELDS = {
    "owner_active_candidates",
    "owner_failed_cleanup_candidates",
    "owner_accounting_poisoned",
    "owner_queued_jobs",
    "owner_active_jobs",
    "owner_completed_jobs",
    "owner_failed_jobs",
    "owner_executor_failed",
    "mesh_active_candidates",
    "mesh_failed_cleanup_candidates",
    "mesh_accounting_poisoned",
}
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


class BenchmarkError(RuntimeError):
    """A failed benchmark contract, rather than a product qualification."""


class SemanticExecutableError(BenchmarkError):
    """A semantic child failed after its output streams were retained."""

    def __init__(
        self,
        message: str,
        *,
        stdout: str,
        stderr: str,
        sampler: dict[str, Any] | None,
        returncode: int | None,
        terminal: str,
    ) -> None:
        super().__init__(f"{message} (child_terminal={terminal})")
        self.stdout = stdout
        self.stderr = stderr
        self.sampler = sampler
        self.returncode = returncode
        self.terminal = terminal


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
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
        raise BenchmarkError("control stream closed before a JSON line")
    if len(line) > LINE_LIMIT or not line.endswith(b"\n"):
        raise BenchmarkError("control response exceeded the benchmark line ceiling")
    try:
        return json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"invalid JSON control response: {error}") from error


def request(control_socket: Path, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(str(control_socket))
        stream.sendall(encoded)
        with stream.makefile("rb") as reader:
            response = read_json_line(reader)
    if not isinstance(response, dict):
        raise BenchmarkError(f"{body.get('op')} returned a non-object response")
    if response.get("ok") is not True:
        raise BenchmarkError(f"{body.get('op')} refused: {response.get('error')}")
    return response


def peer_snapshot(control_socket: Path, network: str, timeout: float) -> list[dict[str, Any]]:
    response = request(control_socket, {"op": "peers_list", "network": network}, timeout)
    peers = (response.get("data") or {}).get("peers") or []
    return [peer for peer in peers if isinstance(peer, dict)]


def first_discovered(peers: list[dict[str, Any]]) -> dict[str, Any] | None:
    for peer in peers:
        if isinstance(peer.get("device_id"), str) and peer["device_id"]:
            return peer
    return None


def first_promoted(peers: list[dict[str, Any]]) -> dict[str, Any] | None:
    for peer in peers:
        if peer.get("status") == "active" and peer.get("authenticated") is True:
            return peer
    return None


class ProcSampler:
    """Best-effort Linux /proc sampler; unavailable metrics are explicit."""

    def __init__(self, processes: dict[str, subprocess.Popen[bytes]]) -> None:
        self.processes = processes
        self.available = sys.platform.startswith("linux")
        self.peak_rss: dict[str, int | None] = {name: None for name in processes}
        self.cumulative_cpu: dict[str, float | None] = {name: None for name in processes}
        self.samples: list[dict[str, Any]] = []
        self._clock_ticks = os.sysconf("SC_CLK_TCK") if self.available else 0
        self._page_size = os.sysconf("SC_PAGE_SIZE") if self.available else 0

    def sample(self, phase: str) -> None:
        observation: dict[str, Any] = {"at_monotonic": time.monotonic(), "phase": phase, "processes": {}}
        for name, process in self.processes.items():
            rss: int | None = None
            cpu: float | None = None
            if self.available:
                try:
                    status = Path(f"/proc/{process.pid}/status").read_text(encoding="utf-8")
                    for line in status.splitlines():
                        if line.startswith("VmHWM:"):
                            rss = int(line.split()[1]) * 1024
                            break
                    stat = Path(f"/proc/{process.pid}/stat").read_text(encoding="utf-8")
                    remainder = stat.rsplit(")", 1)[1].split()
                    cpu = (int(remainder[11]) + int(remainder[12])) / self._clock_ticks
                except (FileNotFoundError, OSError, ValueError, IndexError, ZeroDivisionError):
                    pass
            if rss is not None and (self.peak_rss[name] is None or rss > self.peak_rss[name]):
                self.peak_rss[name] = rss
            if cpu is not None and (self.cumulative_cpu[name] is None or cpu > self.cumulative_cpu[name]):
                self.cumulative_cpu[name] = cpu
            observation["processes"][name] = {"rss_bytes": rss, "cpu_seconds": cpu}
        self.samples.append(observation)

    def result(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "method": "linux_proc_status_stat" if self.available else None,
            "cpu_metric": "cumulative_process_cpu_seconds" if self.available else None,
            "peak_rss_bytes": self.peak_rss,
            "cumulative_cpu_seconds": self.cumulative_cpu,
            "samples": self.samples,
        }


def wait_for(
    label: str,
    timeout: float,
    poll_interval: float,
    run_start: float,
    probe: Callable[[], Any],
    sampler: ProcSampler,
) -> tuple[Any, float]:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        sampler.sample(label)
        try:
            value = probe()
            if value:
                return value, time.monotonic() - run_start
            last = value
        except (OSError, ValueError, BenchmarkError) as error:
            last = repr(error)
        time.sleep(poll_interval)
    raise BenchmarkError(f"timed out waiting for {label}; last observation: {last!r}")


def open_events(control_socket: Path, timeout: float) -> tuple[socket.socket, BinaryIO, str, str]:
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(timeout)
    try:
        stream.connect(str(control_socket))
        stream.sendall(b'{"op":"events_subscribe"}\n')
        reader = stream.makefile("rb")
        response = read_json_line(reader)
        data = response.get("data") if isinstance(response, dict) else None
        client_id = data.get("client_id") if isinstance(data, dict) else None
        capability = data.get("client_capability") if isinstance(data, dict) else None
        if response.get("ok") is not True or not isinstance(client_id, str) or not isinstance(capability, str):
            raise BenchmarkError(f"events_subscribe refused: {response!r}")
        return stream, reader, client_id, capability
    except BaseException:
        stream.close()
        raise


def read_event(
    reader: BinaryIO,
    stream: socket.socket,
    timeout: float,
    sampler: ProcSampler,
    label: str,
    matcher: Callable[[Any], bool],
) -> tuple[dict[str, Any], float]:
    started = time.monotonic()
    deadline = started + timeout
    while time.monotonic() < deadline:
        sampler.sample(label)
        stream.settimeout(max(0.05, min(timeout, deadline - time.monotonic())))
        try:
            frame = read_json_line(reader)
        except (TimeoutError, socket.timeout):
            continue
        if matcher(frame):
            if not isinstance(frame, dict):
                raise BenchmarkError("matched event was not an object")
            return frame, time.monotonic() - started
    raise BenchmarkError(f"timed out waiting for {label}")


def terminate(process: subprocess.Popen[bytes], grace: float) -> dict[str, Any]:
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
                "label": "production-benchmark",
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


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * weight, 6)


def summarize(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
    }


def summarize_numeric(values: list[float]) -> dict[str, float | int | None]:
    """Summarize a non-latency metric without falsely labeling its units."""
    return {
        "count": len(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
    }


def parse_finite_grant(raw: str) -> dict[str, int]:
    """Parse the daemon's complete explicit resource-grant contract."""
    if not raw.strip():
        raise BenchmarkError("--resource-grant must be a nonempty finite owner grant")
    amounts: dict[str, int] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            raise BenchmarkError("--resource-grant contains an empty entry")
        if "=" not in entry:
            raise BenchmarkError(f"--resource-grant entry `{entry}` is not dimension=value")
        name, value = (part.strip() for part in entry.split("=", 1))
        if name not in GRANT_DIMENSIONS:
            raise BenchmarkError(f"--resource-grant names unknown dimension `{name}`")
        if name in amounts:
            raise BenchmarkError(f"--resource-grant names dimension `{name}` more than once")
        if not value or any(character not in "0123456789" for character in value):
            raise BenchmarkError(f"--resource-grant dimension `{name}` must be finite nonnegative integer")
        amounts[name] = int(value)
    missing = [name for name in GRANT_DIMENSIONS if name not in amounts]
    if missing:
        raise BenchmarkError(f"--resource-grant does not name dimension `{missing[0]}`")
    return amounts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("transport", "semantic-ledger"), default="transport")
    parser.add_argument("--binary", type=Path, help="existing executable; never built by this harness")
    parser.add_argument("--artifact-dir", required=True, type=Path, help="new or empty output directory")
    parser.add_argument("--resource-grant", help="complete finite owner resource grant")
    parser.add_argument("--runs", type=int)
    parser.add_argument("--messages", type=int)
    parser.add_argument("--payload-bytes", type=int)
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--poll-interval", type=float)
    parser.add_argument("--connector-realtime-policy", choices=("disabled", "enabled"))
    parser.add_argument("--daemon-arg", action="append", help="one argument after the executable; repeat as needed")
    parser.add_argument(
        "--repo-root",
        type=Path,
        help="repository root for semantic-ledger Cargo tests (defaults to this script's repository)",
    )
    parser.add_argument(
        "--semantic-timeout",
        type=float,
        default=3_600.0,
        help="per-case timeout for semantic-ledger Cargo tests",
    )
    parser.add_argument(
        "--semantic-max-wall-ms",
        type=float,
        help="required per-case wall-time budget for semantic scale tests",
    )
    parser.add_argument(
        "--semantic-max-rss-bytes",
        type=int,
        help="required peak-RSS budget for semantic scale tests",
    )
    parser.add_argument(
        "--semantic-max-disk-bytes",
        type=int,
        help="required SQLite footprint budget for semantic scale tests",
    )
    parser.add_argument(
        "--semantic-max-marginal-slope-ms-per-fact",
        type=float,
        help="deprecated legacy slope budget; rejected in favor of matched-tail-total budget",
    )
    parser.add_argument(
        "--semantic-max-matched-tail-total-ms-per-ledger-fact",
        type=float,
        help="required matched-tail-total wall-time slope budget",
    )
    return parser.parse_args()


def validate(args: argparse.Namespace) -> None:
    if getattr(args, "mode", "transport") == "semantic-ledger":
        if args.semantic_timeout <= 0:
            raise BenchmarkError("--semantic-timeout must be positive")
        _validate_semantic_budgets(args)
        return
    required = {
        "resource_grant": getattr(args, "resource_grant", None),
        "runs": getattr(args, "runs", None),
        "messages": getattr(args, "messages", None),
        "payload_bytes": getattr(args, "payload_bytes", None),
        "timeout": getattr(args, "timeout", None),
        "poll_interval": getattr(args, "poll_interval", None),
        "daemon_arg": getattr(args, "daemon_arg", None),
    }
    if hasattr(args, "binary"):
        required["binary"] = args.binary
    if hasattr(args, "connector_realtime_policy"):
        required["connector_realtime_policy"] = args.connector_realtime_policy
    missing = next((name for name, value in required.items() if value in (None, [])), None)
    if missing is not None:
        raise BenchmarkError(f"--{missing.replace('_', '-')} is required in transport mode")
    for name in ("runs", "messages", "payload_bytes"):
        if getattr(args, name) <= 0:
            raise BenchmarkError(f"--{name.replace('_', '-')} must be positive")
    if args.timeout <= 0 or args.poll_interval <= 0:
        raise BenchmarkError("--timeout and --poll-interval must be positive")
    parse_finite_grant(args.resource_grant)
    if any("localbroker" in arg.lower() or "local_broker" in arg.lower() for arg in args.daemon_arg):
        raise BenchmarkError("LocalBroker is not a production benchmark transport")


def _validate_semantic_budgets(args: argparse.Namespace) -> None:
    for name in (
        "semantic_max_wall_ms",
        "semantic_max_matched_tail_total_ms_per_ledger_fact",
    ):
        value = getattr(args, name, None)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise BenchmarkError(f"--{name.replace('_', '-')} must be a finite positive number")
    legacy = getattr(args, "semantic_max_marginal_slope_ms_per_fact", None)
    if legacy is not None:
        raise BenchmarkError(
            "--semantic-max-marginal-slope-ms-per-fact is deprecated; provide "
            "--semantic-max-matched-tail-total-ms-per-ledger-fact"
        )
    for name in ("semantic_max_rss_bytes", "semantic_max_disk_bytes"):
        value = getattr(args, name, None)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise BenchmarkError(f"--{name.replace('_', '-')} must be a positive integer")


def _require_test_success(output: str, selector: str) -> None:
    witness = f"test {selector} ... ok"
    if sum(line.strip() == witness for line in output.splitlines()) != 1:
        raise BenchmarkError(f"semantic case {selector} did not execute exactly one passing test")
    summaries = [
        line.strip()
        for line in output.splitlines()
        if line.strip().startswith("test result:")
    ]
    if len(summaries) != 1 or not re.match(r"^test result: ok\. 1 passed; 0 failed;", summaries[0]):
        raise BenchmarkError(f"semantic case {selector} did not report exactly 1 passed/0 failed")


def _discover_semantic_executable(build_output: str) -> Path:
    artifacts: list[Path] = []
    for line in build_output.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(message, dict)
            and message.get("reason") == "compiler-artifact"
            and isinstance(message.get("executable"), str)
            and isinstance(message.get("target"), dict)
            and message["target"].get("name") == "semantic_ledger_scale"
            and "test" in message["target"].get("kind", [])
            and isinstance(message.get("profile"), dict)
            and message["profile"].get("test") is True
        ):
            artifacts.append(Path(message["executable"]).resolve())
    unique = list(dict.fromkeys(artifacts))
    if len(unique) != 1 or not unique[0].is_file():
        raise BenchmarkError(
            "release build did not produce exactly one semantic_ledger_scale test executable"
        )
    return unique[0]


def _read_semantic_output(stdout_file: BinaryIO, stderr_file: BinaryIO) -> tuple[str, str]:
    stdout_file.seek(0)
    stderr_file.seek(0)
    stdout = stdout_file.read().decode("utf-8", errors="replace")
    stderr = stderr_file.read().decode("utf-8", errors="replace")
    return stdout, stderr


def _reap_semantic_process(process: subprocess.Popen[bytes]) -> str:
    """Kill if needed and observe a child without leaving an ambiguous task."""
    try:
        running = process.poll() is None
    except BaseException:
        running = True
    if running:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return "unresolved"
    return "reaped"


def _run_semantic_executable(
    executable: Path,
    selector: str,
    timeout: float,
    cwd: Path,
) -> tuple[str, str, float, dict[str, Any], int]:
    command = [str(executable), "--ignored", "--exact", selector, "--nocapture", "--test-threads=1"]
    started = time.perf_counter()
    # Regular files keep a verbose ignored test from filling either pipe while
    # the parent is sampling. They also give the timeout path an explicit,
    # bounded lifecycle: kill, wait, read, and close before reporting failure.
    process: subprocess.Popen[bytes] | None = None
    sampler: ProcSampler | None = None
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd=cwd,
                start_new_session=os.name == "posix",
            )
            sampler = ProcSampler({"semantic_ledger_scale": process})
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                sampler.sample("semantic-scale")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BenchmarkError(f"semantic case {selector} exceeded --semantic-timeout")
                time.sleep(min(0.05, remaining))
            sampler.sample("semantic-scale-final")
            process.wait()
            stdout, stderr = _read_semantic_output(stdout_file, stderr_file)
            if process.returncode != 0:
                detail = (stderr or stdout).strip()[-4_096:]
                raise SemanticExecutableError(
                    f"semantic case {selector} exited {process.returncode}: {detail}",
                    stdout=stdout,
                    stderr=stderr,
                    sampler=sampler.result(),
                    returncode=process.returncode,
                    terminal="reaped",
                )
            elapsed_ms = (time.perf_counter() - started) * 1_000.0
            return stdout, stderr, elapsed_ms, sampler.result(), process.returncode
        except SemanticExecutableError:
            raise
        except BaseException as error:
            if process is None:
                terminal = "not_started"
            else:
                try:
                    terminal = _reap_semantic_process(process)
                except BaseException:
                    terminal = "unresolved"
            try:
                stdout, stderr = _read_semantic_output(stdout_file, stderr_file)
            except BaseException as output_error:
                stdout = f"<semantic stdout unavailable: {output_error!r}>"
                stderr = "<semantic stderr unavailable>"
            try:
                sampler_result = sampler.result() if sampler is not None else None
            except BaseException:
                sampler_result = None
            raise SemanticExecutableError(
                str(error),
                stdout=stdout,
                stderr=stderr,
                sampler=sampler_result,
                returncode=process.returncode if process is not None else None,
                terminal=terminal,
            ) from error
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        _reap_semantic_process(process)
                except BaseException:
                    pass


def _validate_semantic_scale_budgets(
    cases: list[dict[str, Any]], args: argparse.Namespace
) -> None:
    scale_case_list = [
        case
        for case in cases
        if isinstance(case.get("metric"), dict) and "scale_n" in case["metric"]
    ]
    scale_cases = {case["metric"]["scale_n"]: case for case in scale_case_list}
    expected = {1_000, 10_000, 100_000, 250_000, 500_000, 1_000_000}
    if len(scale_case_list) != len(scale_cases) or set(scale_cases) != expected:
        raise BenchmarkError("semantic scale evidence is missing or duplicating a required scale case")
    for scale, case in scale_cases.items():
        if case["elapsed_ms"] > args.semantic_max_wall_ms:
            raise BenchmarkError(f"semantic scale {scale} exceeded the wall-time budget")
        peak_rss = case.get("process", {}).get("peak_rss_bytes", {}).get("semantic_ledger_scale")
        if peak_rss is None:
            raise BenchmarkError(f"semantic scale {scale} has no measurable peak RSS")
        if peak_rss > args.semantic_max_rss_bytes:
            raise BenchmarkError(f"semantic scale {scale} exceeded the peak-RSS budget")
        metric = case["metric"]
        disk_peak = max(
            metric[field]
            for field in (
                "db_main_bytes_peak",
                "db_wal_bytes_peak",
                "db_shm_bytes_peak",
                "db_journal_bytes_peak",
                "db_total_bytes_peak",
            )
        )
        if disk_peak > args.semantic_max_disk_bytes:
            raise BenchmarkError(f"semantic scale {scale} exceeded the SQLite footprint budget")
        case["budget_observations"] = {
            "wall_ms": case["elapsed_ms"],
            "peak_rss_bytes": peak_rss,
            "sqlite_peak_bytes": disk_peak,
            "matched_tail_work_ms": None,
            "marginal_slope_estimator": "matched_tail_total_ms_per_ledger_fact/v1",
            "marginal_slope_units": "ms_per_ledger_fact",
        }
    # The scale suite intentionally seeds a large prefix for 250k/500k/1m and
    # then times the same 2,000-admission tail. Top-level elapsed time mixes
    # that seed cost with the measured workload, so adjacent total-time slopes
    # are not a complexity metric. Compare only equal tail shapes, using the
    # emitted admission_total_ms for that common tail. Unmatched transitions
    # remain explicitly unavailable.
    def matched_tail(metric: dict[str, Any]) -> tuple[tuple[Any, ...], float]:
        timed = metric.get("timed_admissions")
        window_target = metric.get("window_admission_target")
        window_limit = metric.get("window_sample_limit")
        total_ms = metric.get("admission_total_ms")
        platform_name = metric.get("platform")
        cache_state = metric.get("cache_state")
        if (
            isinstance(timed, bool)
            or not isinstance(timed, int)
            or timed <= 0
            or isinstance(window_target, bool)
            or not isinstance(window_target, int)
            or window_target <= 0
            or isinstance(window_limit, bool)
            or not isinstance(window_limit, int)
            or window_limit <= 0
            or not isinstance(platform_name, str)
            or not platform_name
            or cache_state != SEMANTIC_CACHE_STATE
        ):
            raise BenchmarkError("semantic marginal slope is unavailable: matching metadata is not positive")
        _finite_positive(total_ms, "admission_total_ms")
        key = (
            platform_name,
            timed,
            window_target,
            window_limit,
            cache_state,
        )
        return key, float(total_ms)

    matched_transitions = 0
    ordered = sorted(scale_cases.items())
    for (_, previous), (scale, current) in zip(ordered, ordered[1:]):
        current["budget_observations"]["marginal_slope_ms_per_fact"] = None
        current["budget_observations"]["marginal_slope_status"] = "unavailable_unmatched_workload"
        previous_tail = matched_tail(previous["metric"])
        current_tail = matched_tail(current["metric"])
        if previous_tail[0] != current_tail[0]:
            continue
        previous_scale = previous["metric"]["scale_n"]
        slope = (current_tail[1] - previous_tail[1]) / (scale - previous_scale)
        previous["budget_observations"]["matched_tail_work_ms"] = previous_tail[1]
        current["budget_observations"]["matched_tail_work_ms"] = current_tail[1]
        current["budget_observations"]["marginal_slope_ms_per_fact"] = slope
        current["budget_observations"]["marginal_slope_status"] = "matched_tail_window"
        matched_transitions += 1
        if slope > args.semantic_max_matched_tail_total_ms_per_ledger_fact:
            raise BenchmarkError(
                f"semantic matched-tail transition {previous_scale}->{scale} exceeded the marginal-slope budget"
            )
    if matched_transitions == 0:
        raise BenchmarkError(
            "semantic marginal slope is unavailable: no adjacent scale cases share a comparable timed tail workload"
        )


def _finite_nonnegative(value: Any, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
        or value < 0
    ):
        raise BenchmarkError(f"semantic metric {label} must be a finite nonnegative number")


def _finite_positive(value: Any, label: str) -> None:
    _finite_nonnegative(value, label)
    if value <= 0:
        raise BenchmarkError(f"semantic metric {label} must be a finite positive number")


def _validate_scale_optional_counters(metric: dict[str, Any], selector: str) -> None:
    platform_name = metric.get("platform")
    if not isinstance(platform_name, str) or not platform_name:
        raise BenchmarkError(f"semantic metric {selector}.platform must be a nonempty string")
    for field, value_kind in SEMANTIC_OPTIONAL_SCALE_COUNTERS.items():
        if field not in metric:
            raise BenchmarkError(f"semantic metric {selector}.{field} must explicitly be null when unsupported")
        value = metric[field]
        if value is None:
            if platform_name == "linux":
                raise BenchmarkError(f"semantic metric {selector}.{field} is unavailable on Linux")
            continue
        if value_kind == "float":
            _finite_nonnegative(value, f"{selector}.{field}")
        elif isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BenchmarkError(f"semantic metric {selector}.{field} must be a nonnegative integer")


def _validate_scale_windows(metric: dict[str, Any], selector: str) -> None:
    windows = metric.get("window_evidence")
    if not isinstance(windows, list) or not windows:
        raise BenchmarkError(f"semantic metric {selector}.window_evidence must be nonempty")
    scale = metric.get("scale_n")
    seeded = metric.get("seeded_admissions")
    timed = metric.get("timed_admissions")
    if (
        isinstance(scale, bool)
        or not isinstance(scale, int)
        or scale <= 0
        or isinstance(seeded, bool)
        or not isinstance(seeded, int)
        or seeded < 0
        or isinstance(timed, bool)
        or not isinstance(timed, int)
        or timed <= 0
    ):
        raise BenchmarkError(f"semantic metric {selector} has invalid positive window metadata")
    expected_start = seeded + 1
    total_count = 0
    total_admission_ms = 0.0
    required = {
        "start_admitted",
        "end_admitted",
        "admission_count",
        "admission_total_ms",
        "elapsed_ms",
        "average_admission_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
    }
    for index, window in enumerate(windows):
        if not isinstance(window, dict) or not required.issubset(window):
            raise BenchmarkError(f"semantic metric {selector}.window_evidence[{index}] is incomplete")
        for field in ("start_admitted", "end_admitted"):
            value = window[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise BenchmarkError(f"semantic metric {selector}.window_evidence[{index}].{field} is invalid")
        if window["end_admitted"] < window["start_admitted"]:
            raise BenchmarkError(f"semantic metric {selector}.window_evidence[{index}] is reversed")
        count = window["admission_count"]
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise BenchmarkError(f"semantic metric {selector}.window_evidence[{index}].admission_count is invalid")
        if window["end_admitted"] - window["start_admitted"] + 1 != count:
            raise BenchmarkError(f"semantic metric {selector}.window_evidence[{index}] has an inconsistent admission count")
        if window["start_admitted"] != expected_start:
            raise BenchmarkError(f"semantic metric {selector}.window_evidence does not provide contiguous admitted coverage")
        expected_start = window["end_admitted"] + 1
        total_count += count
        _finite_nonnegative(window["admission_total_ms"], f"{selector}.window_evidence[{index}].admission_total_ms")
        _finite_nonnegative(window["elapsed_ms"], f"{selector}.window_evidence[{index}].elapsed_ms")
        _finite_nonnegative(window["average_admission_ms"], f"{selector}.window_evidence[{index}].average_admission_ms")
        if not math.isclose(
            window["average_admission_ms"],
            window["admission_total_ms"] / count,
            rel_tol=1e-9,
            abs_tol=1e-9,
        ):
            raise BenchmarkError(f"semantic metric {selector}.window_evidence[{index}] has an inconsistent average")
        _finite_nonnegative(window["p50_ms"], f"{selector}.window_evidence[{index}].p50_ms")
        _finite_nonnegative(window["p95_ms"], f"{selector}.window_evidence[{index}].p95_ms")
        _finite_positive(window["p99_ms"], f"{selector}.window_evidence[{index}].p99_ms")
        total_admission_ms += window["admission_total_ms"]
    if expected_start != scale + 1 or total_count != timed:
        raise BenchmarkError(f"semantic metric {selector}.window_evidence does not cover exactly the timed admissions")
    _finite_nonnegative(metric.get("admission_total_ms"), f"{selector}.admission_total_ms")
    if not math.isclose(total_admission_ms, metric["admission_total_ms"], rel_tol=1e-9, abs_tol=1e-9):
        raise BenchmarkError(f"semantic metric {selector}.window_evidence total does not match admission_total_ms")


def _validate_provider(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != SEMANTIC_PROVIDER_FIELDS:
        raise BenchmarkError(f"semantic metric {label} must contain the exact provider fields")
    for field, current in value.items():
        if field in {"owner_accounting_poisoned", "owner_executor_failed", "mesh_accounting_poisoned"}:
            if not isinstance(current, bool):
                raise BenchmarkError(f"semantic metric {label}.{field} must be boolean")
        elif isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise BenchmarkError(f"semantic metric {label}.{field} must be a nonnegative integer")
    return dict(value)


def _validate_footprint(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != SEMANTIC_FOOTPRINT_FIELDS:
        raise BenchmarkError(f"semantic metric {label} must contain the exact database footprint fields")
    result: dict[str, int] = {}
    for field in sorted(SEMANTIC_FOOTPRINT_FIELDS):
        current = value[field]
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise BenchmarkError(f"semantic metric {label}.{field} must be a nonnegative integer")
        result[field] = current
    return result


def _validate_db_totals(value: Any, label: str) -> dict[str, int]:
    fields = {"main_bytes", "wal_bytes", "shm_bytes", "journal_bytes"}
    if not isinstance(value, dict) or set(value) != fields:
        raise BenchmarkError(f"semantic metric {label} must contain exact main/WAL/SHM/journal totals")
    result: dict[str, int] = {}
    for field in sorted(fields):
        current = value[field]
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise BenchmarkError(f"semantic metric {label}.{field} must be a nonnegative integer")
        result[field] = current
    return result


def _validate_optional_bytes(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BenchmarkError(f"semantic metric {label} must be null or a nonnegative integer")
    return value


def _validate_capacity_metric(metric: dict[str, Any]) -> None:
    footprint = metric.get("footprint")
    terminal = metric.get("terminal")
    footprint_fields = {
        "event",
        "M",
        "W",
        "S",
        "R",
        "B",
        "provider_baseline_storage",
        "provider_live_storage",
        "provider_baseline_opaque_dependency_residual",
        "provider_live_opaque_dependency_residual",
    }
    terminal_fields = {
        "event",
        "provider_storage",
        "provider_opaque_dependency_residual",
        "provider_retained_after_failed_cleanup",
    }
    if not isinstance(footprint, dict) or set(footprint) != footprint_fields:
        raise BenchmarkError(f"semantic case {SEMANTIC_CAPACITY_SELECTOR} has malformed footprint event")
    if not isinstance(terminal, dict) or set(terminal) != terminal_fields:
        raise BenchmarkError(f"semantic case {SEMANTIC_CAPACITY_SELECTOR} has malformed terminal event")
    numeric_footprint = footprint_fields - {"event"}
    numeric_terminal = terminal_fields - {"event"}
    for field in numeric_footprint:
        current = footprint[field]
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise BenchmarkError(f"semantic metric {SEMANTIC_CAPACITY_SELECTOR}.{field} must be a nonnegative integer")
    for field in numeric_terminal:
        current = terminal[field]
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise BenchmarkError(f"semantic metric {SEMANTIC_CAPACITY_SELECTOR}.{field} must be a nonnegative integer")
    if footprint["B"] != footprint["M"] + footprint["W"] + footprint["S"] + footprint["R"]:
        raise BenchmarkError(f"semantic case {SEMANTIC_CAPACITY_SELECTOR} violated B=M+W+S+R")
    if footprint["provider_live_storage"] - footprint["provider_baseline_storage"] != footprint["B"]:
        raise BenchmarkError(f"semantic case {SEMANTIC_CAPACITY_SELECTOR} has an incorrect live storage delta")
    if footprint["provider_live_opaque_dependency_residual"] <= footprint["provider_baseline_opaque_dependency_residual"]:
        raise BenchmarkError(f"semantic case {SEMANTIC_CAPACITY_SELECTOR} has no live bookkeeping claim")
    if any(terminal[field] != 0 for field in numeric_terminal):
        raise BenchmarkError(f"semantic case {SEMANTIC_CAPACITY_SELECTOR} did not return to its terminal baseline")


def _validate_purge_metric(metric: dict[str, Any]) -> None:
    required = {
        "selector",
        "purge_elapsed_ms",
        "recreate_elapsed_ms",
        "files",
        "neighbor_survived",
        "competing_writer_busy",
        "terminal_baseline",
    }
    missing = sorted(required.difference(metric))
    if missing:
        raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR} is missing fields: {', '.join(missing)}")
    for field in ("purge_elapsed_ms", "recreate_elapsed_ms"):
        _finite_nonnegative(metric[field], f"{SEMANTIC_PURGE_SELECTOR}.{field}")
    if metric["neighbor_survived"] is not True or metric["competing_writer_busy"] is not True:
        raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR} violated purge isolation controls")
    files = metric["files"]
    if not isinstance(files, dict) or set(files) != SEMANTIC_PURGE_FILES:
        raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR} has an incomplete file set")
    for name in sorted(SEMANTIC_PURGE_FILES):
        entry = files[name]
        if not isinstance(entry, dict) or set(entry) != {"before_bytes", "after_bytes", "recreated_bytes"}:
            raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR}.{name} is malformed")
        for field in ("before_bytes", "after_bytes", "recreated_bytes"):
            _validate_optional_bytes(entry[field], f"{SEMANTIC_PURGE_SELECTOR}.{name}.{field}")
    if files["main"]["before_bytes"] is None or files["main"]["after_bytes"] is not None:
        raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR} did not remove the main store")
    if files["main"]["recreated_bytes"] is None:
        raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR} did not recreate the main store")
    if files["journal"]["before_bytes"] is None or files["journal"]["after_bytes"] is not None:
        raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR} did not remove the journal")
    terminal = metric["terminal_baseline"]
    if not isinstance(terminal, dict) or set(terminal) != {
        "primary_shutdown_ok", "restarted_shutdown_ok", "primary_shutdown_elapsed_ms"
    }:
        raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR} has a malformed terminal baseline")
    if terminal["primary_shutdown_ok"] is not True or terminal["restarted_shutdown_ok"] is not True:
        raise BenchmarkError(f"semantic case {SEMANTIC_PURGE_SELECTOR} did not reach terminal baseline")
    _finite_nonnegative(terminal["primary_shutdown_elapsed_ms"], f"{SEMANTIC_PURGE_SELECTOR}.primary_shutdown_elapsed_ms")


def _validate_handshake_evidence(metric: dict[str, Any]) -> None:
    if metric.get("evidence") != f"test {SEMANTIC_HANDSHAKE_SELECTOR} ... ok":
        raise BenchmarkError(f"semantic case {SEMANTIC_HANDSHAKE_SELECTOR} did not expose an exact passing test witness")


def _validate_route_evidence(metric: dict[str, Any]) -> None:
    if metric.get("evidence") != f"test {SEMANTIC_ROUTE_SELECTOR} ... ok":
        raise BenchmarkError(f"semantic case {SEMANTIC_ROUTE_SELECTOR} did not expose an exact passing test witness")


def _validate_proof_metric(metric: dict[str, Any]) -> None:
    required = {
        "selector",
        "seeded_proof_count",
        "linked_fact_count",
        "configured_max_database_bytes",
        "operations",
        "unrelated_rows_preserved",
        "no_op_footprints_equal",
        "reopened_exact_equality",
        "reopened_pending_count",
        "reopened_terminal_count",
    }
    missing = sorted(required.difference(metric))
    if missing:
        raise BenchmarkError(f"semantic case {SEMANTIC_PROOF_SELECTOR} is missing fields: {', '.join(missing)}")
    for field in (
        "seeded_proof_count",
        "linked_fact_count",
        "configured_max_database_bytes",
        "reopened_pending_count",
        "reopened_terminal_count",
    ):
        current = metric[field]
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise BenchmarkError(f"semantic metric {SEMANTIC_PROOF_SELECTOR}.{field} must be a nonnegative integer")
    if metric["seeded_proof_count"] != 15 or metric["linked_fact_count"] != 5:
        raise BenchmarkError(f"semantic case {SEMANTIC_PROOF_SELECTOR} did not seed its exact proof/link counts")
    if metric["configured_max_database_bytes"] <= 0:
        raise BenchmarkError(f"semantic case {SEMANTIC_PROOF_SELECTOR} has no positive database budget")
    if (
        metric["unrelated_rows_preserved"] is not True
        or metric["no_op_footprints_equal"] is not True
        or metric["reopened_exact_equality"] is not True
    ):
        raise BenchmarkError(f"semantic case {SEMANTIC_PROOF_SELECTOR} violated preservation/no-op controls")
    operations = metric["operations"]
    if not isinstance(operations, dict) or set(operations) != SEMANTIC_PROOF_OPERATIONS:
        raise BenchmarkError(f"semantic case {SEMANTIC_PROOF_SELECTOR} has an incomplete operation set")
    for operation in sorted(SEMANTIC_PROOF_OPERATIONS):
        entry = operations[operation]
        if not isinstance(entry, dict) or set(entry) != {"before", "after"}:
            raise BenchmarkError(f"semantic case {SEMANTIC_PROOF_SELECTOR}.{operation} is malformed")
        for phase in ("before", "after"):
            totals = _validate_db_totals(
                entry[phase], f"{SEMANTIC_PROOF_SELECTOR}.{operation}.{phase}"
            )
            if sum(totals.values()) > metric["configured_max_database_bytes"]:
                raise BenchmarkError(
                    f"semantic case {SEMANTIC_PROOF_SELECTOR}.{operation}.{phase} exceeds configured database budget"
                )
    expected_terminal = sum(operation in {"supersede", "settle"} for operation in SEMANTIC_PROOF_OPERATIONS)
    if metric["reopened_terminal_count"] != expected_terminal:
        raise BenchmarkError(f"semantic case {SEMANTIC_PROOF_SELECTOR} has an inconsistent reopened terminal count")
    if metric["reopened_pending_count"] != metric["seeded_proof_count"] - expected_terminal:
        raise BenchmarkError(f"semantic case {SEMANTIC_PROOF_SELECTOR} has an inconsistent reopened pending count")


def validate_semantic_metric(metric: Any, selector: str, scale_n: int | None) -> dict[str, Any]:
    if not isinstance(metric, dict) or metric.get("selector") != selector:
        raise BenchmarkError(f"semantic case {selector} did not emit its exact selector")
    if selector == SEMANTIC_PROOF_SELECTOR:
        _validate_proof_metric(metric)
        return metric
    if selector == SEMANTIC_CAPACITY_SELECTOR:
        _validate_capacity_metric(metric)
        return metric
    if selector == SEMANTIC_PURGE_SELECTOR:
        _validate_purge_metric(metric)
        return metric
    if selector == SEMANTIC_HANDSHAKE_SELECTOR:
        _validate_handshake_evidence(metric)
        return metric
    if selector == SEMANTIC_ROUTE_SELECTOR:
        _validate_route_evidence(metric)
        return metric
    if scale_n is not None:
        missing = sorted(SEMANTIC_SCALE_FIELDS.difference(metric))
        if missing:
            raise BenchmarkError(f"semantic case {selector} is missing fields: {', '.join(missing)}")
        if metric.get("scale_n") != scale_n or metric.get("admitted_delta") != scale_n:
            raise BenchmarkError(f"semantic case {selector} did not admit exactly scale_n facts")
        seeded_admissions = metric.get("seeded_admissions")
        timed_admissions = metric.get("timed_admissions")
        if (
            isinstance(seeded_admissions, bool)
            or not isinstance(seeded_admissions, int)
            or seeded_admissions < 0
            or isinstance(timed_admissions, bool)
            or not isinstance(timed_admissions, int)
            or timed_admissions <= 0
            or seeded_admissions + timed_admissions != scale_n
        ):
            raise BenchmarkError(
                f"semantic case {selector} has an inconsistent seeded/timed admission split"
            )
        if metric.get("unresolved") != 0:
            raise BenchmarkError(f"semantic case {selector} left unresolved facts")
        if metric.get("cache_state") != SEMANTIC_CACHE_STATE:
            raise BenchmarkError(f"semantic case {selector} did not declare the exact cache state")
        for field in (
            "admission_total_ms",
            "admission_end_to_end_total_ms",
            "admission_p50_ms",
            "admission_p95_ms",
            "seed_total_ms",
            "compaction_ms",
            "startup_plus_restore_ms",
        ):
            _finite_nonnegative(metric.get(field), f"{selector}.{field}")
        _finite_positive(metric.get("admission_p99_ms"), f"{selector}.admission_p99_ms")
        _finite_positive(metric.get("admissions_per_sec"), f"{selector}.admissions_per_sec")
        _validate_scale_optional_counters(metric, selector)
        _validate_scale_windows(metric, selector)
        for field in (
            "db_main_bytes_peak",
            "db_wal_bytes_peak",
            "db_shm_bytes_peak",
            "db_journal_bytes_peak",
            "db_total_bytes_peak",
            "db_main_bytes_after_compaction",
            "db_wal_bytes_after_compaction",
            "db_shm_bytes_after_compaction",
            "db_total_bytes_after",
        ):
            current = metric.get(field)
            if isinstance(current, bool) or not isinstance(current, int) or current < 0:
                raise BenchmarkError(f"semantic metric {selector}.{field} must be a nonnegative integer")
        component_peak = sum(metric[field] for field in (
            "db_main_bytes_peak",
            "db_wal_bytes_peak",
            "db_shm_bytes_peak",
            "db_journal_bytes_peak",
        ))
        if metric["db_total_bytes_peak"] < component_peak:
            raise BenchmarkError(f"semantic case {selector} has an inconsistent peak database total")
    else:
        required = {"selector", "cycles", "db_baseline", "db_final", "provider_baseline", "provider_final"}
        missing = sorted(required.difference(metric))
        if missing:
            raise BenchmarkError(f"semantic case {selector} is missing fields: {', '.join(missing)}")
        if metric.get("cycles") != 5:
            raise BenchmarkError(f"semantic case {selector} must run its exact five-cycle control")
        baseline = _validate_footprint(metric["db_baseline"], f"{selector}.db_baseline")
        final = _validate_footprint(metric["db_final"], f"{selector}.db_final")
        if baseline != final:
            raise BenchmarkError(f"semantic case {selector} violated its exact no-churn footprint assertion")
    _validate_provider(metric.get("provider_baseline"), f"{selector}.provider_baseline")
    _validate_provider(metric.get("provider_final"), f"{selector}.provider_final")
    if metric.get("provider_baseline") != metric.get("provider_final"):
        raise BenchmarkError(f"semantic case {selector} did not return the provider to its baseline")
    return metric


def _semantic_metric_from_output(output: str, selector: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for line in output.splitlines():
        candidate = line.strip()
        if selector in SEMANTIC_PREFIXES:
            prefix = SEMANTIC_PREFIXES[selector]
            if not candidate.startswith(prefix):
                continue
            candidate = candidate[len(prefix) :].strip()
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("selector") == selector:
            matches.append(value)
    if len(matches) != 1:
        raise BenchmarkError(f"semantic case {selector} emitted {len(matches)} matching JSON metrics")
    return matches[0]


def _semantic_capacity_metric_from_output(output: str) -> dict[str, Any]:
    events: dict[str, dict[str, Any]] = {}
    for line in output.splitlines():
        try:
            value = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("event") in SEMANTIC_CAPACITY_EVENTS:
            event = value["event"]
            if event in events:
                raise BenchmarkError(f"semantic capacity emitted duplicate {event} events")
            events[event] = value
    missing = sorted(SEMANTIC_CAPACITY_EVENTS.difference(events))
    if missing:
        raise BenchmarkError(f"semantic capacity is missing events: {', '.join(missing)}")
    return {
        "selector": SEMANTIC_CAPACITY_SELECTOR,
        "footprint": events["semantic_capacity_footprint"],
        "terminal": events["semantic_capacity_terminal"],
    }


def _semantic_handshake_evidence_from_output(output: str) -> dict[str, Any]:
    witness = f"test {SEMANTIC_HANDSHAKE_SELECTOR} ... ok"
    if not any(line.strip() == witness for line in output.splitlines()):
        raise BenchmarkError(f"semantic case {SEMANTIC_HANDSHAKE_SELECTOR} did not emit its exact passing test witness")
    return {"selector": SEMANTIC_HANDSHAKE_SELECTOR, "evidence": witness}


def _semantic_route_evidence_from_output(output: str) -> dict[str, Any]:
    witness = f"test {SEMANTIC_ROUTE_SELECTOR} ... ok"
    if not any(line.strip() == witness for line in output.splitlines()):
        raise BenchmarkError(f"semantic case {SEMANTIC_ROUTE_SELECTOR} did not emit its exact passing test witness")
    return {"selector": SEMANTIC_ROUTE_SELECTOR, "evidence": witness}


def run_semantic_ledger(args: argparse.Namespace, artifact_dir: Path) -> dict[str, Any]:
    repo_root = (args.repo_root or Path(__file__).resolve().parents[1]).resolve()
    if not repo_root.is_dir():
        raise BenchmarkError(f"--repo-root is not a directory: {repo_root}")
    source_paths = [
        repo_root / "crates/myownmesh-core/tests/semantic_ledger_scale.rs",
        repo_root / "crates/myownmesh-core/tests/semantic_projection_compaction_differential.rs",
        repo_root / "crates/myownmesh-core/tests/durable_proof_delivery_r3.rs",
        repo_root / "crates/myownmesh-core/tests/semantic_capacity_controls.rs",
        repo_root / "crates/myownmesh/tests/network_purge_r2.rs",
        repo_root / "crates/myownmesh-core/tests/two_peer_handshake.rs",
        repo_root / "crates/myownmesh-core/tests/topology_routing.rs",
    ]
    source_identity = []
    for source in source_paths:
        if not source.is_file():
            raise BenchmarkError(f"semantic source file is missing: {source}")
        source_identity.append({"path": str(source), "sha256": sha256(source)})
    build_command = [
        "cargo",
        "test",
        "--locked",
        "--release",
        "--no-run",
        "--message-format=json-render-diagnostics",
        "-p",
        "myownmesh-core",
        "--features",
        "transport-lab",
        "--test",
        "semantic_ledger_scale",
    ]
    build_started_at = utc_now()
    build_start = time.perf_counter()
    try:
        build = subprocess.run(
            build_command,
            cwd=repo_root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=args.semantic_timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BenchmarkError(f"semantic release build could not complete: {error}") from error
    build_stdout_path = artifact_dir / "semantic_ledger_scale.build.stdout.log"
    build_stderr_path = artifact_dir / "semantic_ledger_scale.build.stderr.log"
    build_stdout_path.write_text(build.stdout, encoding="utf-8")
    build_stderr_path.write_text(build.stderr, encoding="utf-8")
    if build.returncode != 0:
        detail = (build.stderr or build.stdout).strip()[-4_096:]
        raise BenchmarkError(f"semantic release build exited {build.returncode}: {detail}")
    executable = _discover_semantic_executable(build.stdout)
    build_info = {
        "command": build_command,
        "started_at": build_started_at,
        "finished_at": utc_now(),
        "elapsed_ms": (time.perf_counter() - build_start) * 1_000.0,
        "returncode": build.returncode,
        "executable": str(executable),
        "executable_sha256": sha256(executable),
        "stdout_path": build_stdout_path.name,
        "stderr_path": build_stderr_path.name,
        "stdout_sha256": hashlib.sha256(build.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(build.stderr.encode()).hexdigest(),
    }
    cases: list[dict[str, Any]] = []
    for case_index, (test_target, selector, scale_n, ignored) in enumerate(SEMANTIC_LEDGER_CASES, 1):
        case_started_at = utc_now()
        case_start = time.perf_counter()
        package = "myownmesh" if selector == SEMANTIC_PURGE_SELECTOR else "myownmesh-core"
        if test_target == "semantic_ledger_scale":
            command = [
                str(executable),
                "--ignored",
                "--exact",
                selector,
                "--nocapture",
                "--test-threads=1",
            ]
            try:
                stdout, stderr, measured_elapsed_ms, process, returncode = _run_semantic_executable(
                    executable, selector, args.semantic_timeout, repo_root
                )
            except SemanticExecutableError as error:
                stdout_path = artifact_dir / f"case-{case_index:02d}-{selector}.stdout.log"
                stderr_path = artifact_dir / f"case-{case_index:02d}-{selector}.stderr.log"
                stdout_path.write_text(error.stdout, encoding="utf-8")
                stderr_path.write_text(error.stderr, encoding="utf-8")
                raise BenchmarkError(
                    f"{error}; stdout_path={stdout_path.name}; stderr_path={stderr_path.name}"
                ) from error
        else:
            command = [
                "cargo",
                "test",
                "--locked",
                "--release",
                "-p",
                package,
                "--features",
                "transport-lab",
                "--test",
                test_target,
                "--",
            ]
            if ignored:
                command.append("--ignored")
            command.extend(("--exact", selector, "--nocapture", "--test-threads=1"))
            try:
                completed = subprocess.run(
                    command,
                    cwd=repo_root,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=args.semantic_timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise BenchmarkError(f"semantic case {selector} could not complete: {error}") from error
            stdout, stderr, process = completed.stdout, completed.stderr, None
            returncode = completed.returncode
            measured_elapsed_ms = (time.perf_counter() - case_start) * 1_000.0
        stdout_path = artifact_dir / f"case-{case_index:02d}-{selector}.stdout.log"
        stderr_path = artifact_dir / f"case-{case_index:02d}-{selector}.stderr.log"
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        if returncode != 0:
            detail = (stderr or stdout or "").strip()[-4_096:]
            raise BenchmarkError(f"semantic case {selector} exited {returncode}: {detail}")
        combined_output = f"{stdout}\n{stderr}"
        _require_test_success(combined_output, selector)
        metric_output = (
            _semantic_capacity_metric_from_output(combined_output)
            if selector == SEMANTIC_CAPACITY_SELECTOR
            else _semantic_handshake_evidence_from_output(combined_output)
            if selector == SEMANTIC_HANDSHAKE_SELECTOR
            else _semantic_route_evidence_from_output(combined_output)
            if selector == SEMANTIC_ROUTE_SELECTOR
            else _semantic_metric_from_output(combined_output, selector)
        )
        metric = validate_semantic_metric(metric_output, selector, scale_n)
        cases.append(
            {
                "selector": selector,
                "command": command,
                "returncode": returncode,
                "started_at": case_started_at,
                "finished_at": utc_now(),
                "elapsed_ms": measured_elapsed_ms,
                "metric": metric,
                "stdout_path": stdout_path.name,
                "stderr_path": stderr_path.name,
                "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                "output_sha256": hashlib.sha256(combined_output.encode()).hexdigest(),
                "process": process,
            }
        )
    _validate_semantic_scale_budgets(cases, args)
    manifest = {
        "schema": "myownmesh-production-semantic-ledger/v1",
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "mode": "semantic-ledger",
        "repo_root": str(repo_root),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "uname": platform.uname()._asdict(),
        },
        "source_identity": source_identity,
        "build": build_info,
        "budgets": {
            "max_wall_ms": args.semantic_max_wall_ms,
            "max_rss_bytes": args.semantic_max_rss_bytes,
            "max_disk_bytes": args.semantic_max_disk_bytes,
            "max_matched_tail_total_ms_per_ledger_fact": args.semantic_max_matched_tail_total_ms_per_ledger_fact,
        },
        "cases": cases,
        "claims": {
            "capacity_or_slo": False,
            "budget_gates_enforced": True,
            "reported_curves_only": False,
            "exact_no_churn_assertions": True,
        },
    }
    write_json(artifact_dir / "semantic-ledger.json", manifest)
    return manifest


def run_once(args: argparse.Namespace, run_dir: Path, binary: Path, run_number: int) -> dict[str, Any]:
    run_start = time.monotonic()
    network = "benchmark" + secrets.token_hex(8)
    homes = {name: run_dir / f"home-{name}" for name in ("a", "b")}
    sockets = {name: home / "daemon.sock" for name, home in homes.items()}
    for control_socket in sockets.values():
        if len(os.fsencode(control_socket)) > 100:
            raise BenchmarkError(f"control socket path is too long: {control_socket}")
    for home in homes.values():
        home.mkdir(parents=True)
        write_json(home / "config.json", daemon_config(network))

    processes: dict[str, subprocess.Popen[bytes]] = {}
    logs: dict[str, tuple[BinaryIO, BinaryIO]] = {}
    sampler: ProcSampler | None = None
    events: socket.socket | None = None
    event_reader: BinaryIO | None = None
    result: dict[str, Any] = {
        "run": run_number,
        "network": network,
        "run_start_monotonic": run_start,
        "messages": [],
    }
    try:
        for name in ("a", "b"):
            stdout = (run_dir / f"daemon-{name}.stdout.log").open("wb")
            stderr = (run_dir / f"daemon-{name}.stderr.log").open("wb")
            logs[name] = (stdout, stderr)
            environment = os.environ.copy()
            environment.update(
                {
                    "MYOWNMESH_HOME": str(homes[name]),
                    "MYOWNMESH_LOG_FORMAT": "json",
                    "MYOWNMESH_CONN_TRACE": "1",
                    RESOURCE_GRANT: args.resource_grant,
                    REALTIME_POLICY: args.connector_realtime_policy,
                }
            )
            processes[name] = subprocess.Popen(
                [str(binary), *args.daemon_arg],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        sampler = ProcSampler(processes)
        ready: dict[str, float] = {}
        discovered: dict[str, float] = {}
        promoted: dict[str, float] = {}
        peers: dict[str, dict[str, Any]] = {}
        for name in ("a", "b"):
            _, elapsed = wait_for(
                f"{name} control readiness",
                args.timeout,
                args.poll_interval,
                run_start,
                lambda name=name: request(sockets[name], {"op": "status"}, args.timeout),
                sampler,
            )
            ready[name] = elapsed
        for name in ("a", "b"):
            peer, elapsed = wait_for(
                f"{name} discovery",
                args.timeout,
                args.poll_interval,
                run_start,
                lambda name=name: first_discovered(peer_snapshot(sockets[name], network, args.timeout)),
                sampler,
            )
            discovered[name] = elapsed
            peers[name] = peer
            promoted_peer, promotion_elapsed = wait_for(
                f"{name} promotion",
                args.timeout,
                args.poll_interval,
                run_start,
                lambda name=name: first_promoted(peer_snapshot(sockets[name], network, args.timeout)),
                sampler,
            )
            promoted[name] = promotion_elapsed
            peers[name] = promoted_peer
        events, event_reader, client_id, capability = open_events(sockets["b"], args.timeout)
        request(
            sockets["b"],
            {"op": "channel_subscribe", "client_id": client_id, "client_capability": capability, "network": network, "channel": CHANNEL},
            args.timeout,
        )
        destination_id = peers["a"]["device_id"]
        expected_sender_id = peers["b"]["device_id"]
        if not isinstance(destination_id, str) or not isinstance(expected_sender_id, str):
            raise BenchmarkError("production peers did not expose canonical device ids")
        if destination_id == expected_sender_id:
            raise BenchmarkError("production peers exposed the same destination and sender id")
        payload_body = "x" * args.payload_bytes
        send_started = time.monotonic()
        for sequence in range(args.messages):
            payload = {"contract": "production-benchmark", "run": run_number, "sequence": sequence, "body": payload_body}
            encoded_payload = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            sent_at = time.monotonic()
            request(
                sockets["a"],
                {"op": "channel_send_reliable", "network": network, "channel": CHANNEL, "peer": destination_id, "payload": payload},
                args.timeout,
            )
            frame, _ = read_event(
                event_reader,
                events,
                args.timeout,
                sampler,
                "typed-message delivery",
                lambda frame, sequence=sequence, payload=payload: isinstance(frame, dict)
                and frame.get("kind") == "channel_inbound"
                and frame.get("network") == network
                and frame.get("channel") == CHANNEL
                and frame.get("from") == expected_sender_id
                and frame.get("payload") == payload
                and isinstance(frame.get("payload"), dict)
                and frame["payload"].get("sequence") == sequence,
            )
            delivered_at = time.monotonic()
            result["messages"].append(
                {
                    "sequence": sequence,
                    "payload_bytes": len(encoded_payload),
                    "sent_at_monotonic": sent_at,
                    "delivered_at_monotonic": delivered_at,
                    "latency_ms": (delivered_at - sent_at) * 1000,
                    "event": frame,
                }
            )
        elapsed = time.monotonic() - send_started
        total_bytes = sum(message["payload_bytes"] for message in result["messages"])
        result.update(
            {
                "elapsed_seconds": elapsed,
                "throughput_messages_per_second": args.messages / elapsed if elapsed > 0 else None,
                "throughput_payload_bytes_per_second": total_bytes / elapsed if elapsed > 0 else None,
                "timings_ms": {
                    "control_ready": max(ready.values()) * 1000,
                    "discovery": max(discovered.values()) * 1000,
                    "promotion": max(promoted.values()) * 1000,
                },
                "timings_ms_by_daemon": {
                    name: {
                        "control_ready": ready[name] * 1000,
                        "discovery": discovered[name] * 1000,
                        "promotion": promoted[name] * 1000,
                    }
                    for name in ("a", "b")
                },
                "peer_observations": peers,
            }
        )
    finally:
        if event_reader is not None:
            try:
                event_reader.close()
            except OSError:
                pass
        if events is not None:
            try:
                events.close()
            except OSError:
                pass
        if sampler is not None:
            sampler.sample("pre-terminate")
        terminals: dict[str, dict[str, Any]] = {}
        for name, process in reversed(tuple(processes.items())):
            try:
                terminals[name] = terminate(process, args.timeout)
            except BaseException as error:
                terminals[name] = {
                    "pid": process.pid,
                    "returncode": process.poll(),
                    "forced": True,
                    "error": f"{type(error).__name__}: {error}",
                }
        if sampler is not None:
            result["process"] = sampler.result()
        result["terminals"] = terminals
        result["clean_terminal"] = set(terminals) == {"a", "b"} and all(
            not value["forced"] and value["returncode"] == 0 for value in terminals.values()
        )
        for stdout, stderr in logs.values():
            try:
                stdout.close()
            except OSError:
                pass
            try:
                stderr.close()
            except OSError:
                pass
    return result


def main_transport(args: argparse.Namespace) -> int:
    if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
        raise BenchmarkError("this production mDNS benchmark requires a Unix host")
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise BenchmarkError(f"--binary is not an executable file: {binary}")
    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if any(artifact_dir.iterdir()):
        raise BenchmarkError(f"artifact directory must be empty: {artifact_dir}")
    manifest: dict[str, Any] = {
        "schema": "myownmesh-production-benchmark/v1",
        "started_at": utc_now(),
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "uname": platform.uname()._asdict(),
        },
        "inputs": {
            "runs": args.runs,
            "messages": args.messages,
            "payload_bytes_requested": args.payload_bytes,
            "timeout_seconds": args.timeout,
            "poll_interval_seconds": args.poll_interval,
            "daemon_args": args.daemon_arg,
            "connector_realtime_policy": args.connector_realtime_policy,
            "resource_grant_supplied": True,
            "resource_grant_sha256": hashlib.sha256(args.resource_grant.encode()).hexdigest(),
        },
        "runs": [],
        "raw_samples": "raw-samples.json",
        "claims": {"capacity_or_slo": False},
    }
    try:
        for run_number in range(1, args.runs + 1):
            run_dir = artifact_dir / f"run-{run_number:04d}"
            run_dir.mkdir()
            manifest["runs"].append(run_once(args, run_dir, binary, run_number))
    finally:
        write_json(artifact_dir / "raw-samples.json", manifest["runs"])
        manifest["finished_at"] = utc_now()
        manifest["clean_terminal"] = bool(manifest["runs"]) and all(run.get("clean_terminal") for run in manifest["runs"])
        timing_values = {
            name: [run["timings_ms"][name] for run in manifest["runs"] if name in run.get("timings_ms", {})]
            for name in ("control_ready", "discovery", "promotion")
        }
        message_values = [message["latency_ms"] for run in manifest["runs"] for message in run.get("messages", [])]
        manifest["summary"] = {name: summarize(values) for name, values in timing_values.items()}
        manifest["summary"]["typed_message"] = summarize(message_values)
        manifest["summary"]["throughput_messages_per_second"] = summarize_numeric(
            [
                run["throughput_messages_per_second"]
                for run in manifest["runs"]
                if "throughput_messages_per_second" in run
            ]
        )
        manifest["summary"]["throughput_payload_bytes_per_second"] = summarize_numeric(
            [
                run["throughput_payload_bytes_per_second"]
                for run in manifest["runs"]
                if "throughput_payload_bytes_per_second" in run
            ]
        )
        manifest["summary"]["peak_rss_bytes"] = {
            name: summarize_numeric(
                [
                    run["process"]["peak_rss_bytes"][name]
                    for run in manifest["runs"]
                    if run.get("process", {}).get("peak_rss_bytes", {}).get(name) is not None
                ]
            )
            for name in ("a", "b")
        }
        manifest["summary"]["cumulative_cpu_seconds"] = {
            name: summarize_numeric(
                [
                    run["process"]["cumulative_cpu_seconds"][name]
                    for run in manifest["runs"]
                    if run.get("process", {}).get("cumulative_cpu_seconds", {}).get(name) is not None
                ]
            )
            for name in ("a", "b")
        }
        write_json(artifact_dir / "manifest.json", manifest)
    if not manifest["clean_terminal"]:
        raise BenchmarkError("one or more daemons did not terminate cleanly")
    print(f"production benchmark completed; artifacts: {artifact_dir}")
    return 0


def main_semantic_ledger(args: argparse.Namespace) -> int:
    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if any(artifact_dir.iterdir()):
        raise BenchmarkError(f"artifact directory must be empty: {artifact_dir}")
    run_semantic_ledger(args, artifact_dir)
    print(f"semantic-ledger benchmark completed; artifacts: {artifact_dir}")
    return 0


def main() -> int:
    args = parse_args()
    validate(args)
    if args.mode == "semantic-ledger":
        return main_semantic_ledger(args)
    return main_transport(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        raise SystemExit(2)
