#!/usr/bin/env python3
"""Measure real MyOwnMesh daemon-to-daemon connection establishment.

This is deliberately not an in-process transport benchmark.  It drives the
installed/compiled ``myownmesh`` CLI against a running daemon, waits for a
remote device to be discovered, performs the public waited-dial operation, and
then verifies the daemon's public peer snapshot.  Each input network must be a
fresh room for that sample; otherwise ``connect`` is idempotent and the result
would measure an already-live session.

The peer daemon must already be running on a different machine with the same
network(s), ``auto_approve`` enabled for unattended measurement, and compatible
signaling/STUN/TURN configuration.  Capture ``myownmesh ctl trace`` on both
machines alongside this command when a phase-by-phase timeline is required.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def run_json(binary: str, arguments: list[str], timeout_s: float) -> Any:
    completed = subprocess.run(
        [binary, *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(
            f"{' '.join(arguments)} failed with exit {completed.returncode}: {detail}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"{' '.join(arguments)} returned non-JSON output: {completed.stdout!r}"
        ) from error


def peer_snapshot(
    binary: str, network: str, peer: str, timeout_s: float
) -> dict[str, Any] | None:
    payload = run_json(binary, ["ctl", "peers", network], timeout_s)
    if not isinstance(payload, dict) or not isinstance(payload.get("peers"), list):
        raise RuntimeError(
            f"peer snapshot for {network!r} is not an object containing a peers list"
        )
    peers = payload["peers"]
    for candidate in peers:
        if (
            isinstance(candidate, dict)
            and peer_record_canonical_id(candidate).casefold() == peer.casefold()
        ):
            return candidate
    return None


def peer_record_canonical_id(candidate: dict[str, Any]) -> str:
    """Reassemble the canonical id exposed by the public peer projection.

    ``ctl status`` and dial arguments use ``<device-id>-<suffix>`` while
    ``ctl peers`` deliberately presents those as separate fields.  Accept an
    already-combined id too so this stays compatible with older projections.
    """
    device_id = str(candidate.get("device_id", ""))
    suffix = str(candidate.get("device_suffix", ""))
    if not device_id or not suffix or device_id.casefold().endswith(
        f"-{suffix}".casefold()
    ):
        return device_id
    return f"{device_id}-{suffix}"


def wait_for_peer(
    binary: str,
    network: str,
    peer: str,
    timeout_s: float,
    poll_s: float,
    predicate,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = peer_snapshot(binary, network, peer, timeout_s=min(10.0, timeout_s))
        if last is not None and predicate(last):
            return last, (time.perf_counter_ns() - started) / 1_000_000.0
        time.sleep(poll_s)
    raise RuntimeError(
        f"peer {peer} did not reach the required state on {network!r} within "
        f"{timeout_s:.1f}s; last snapshot={last!r}"
    )


def admitted(peer: dict[str, Any]) -> bool:
    return bool(peer.get("authenticated")) and str(peer.get("status", "")).lower() in {
        "active",
        "shelved",
    }


def approved_bilaterally(peer: dict[str, Any]) -> bool:
    return admitted(peer) and bool(peer.get("local_approve_sent")) and bool(
        peer.get("remote_approve_seen")
    )


def is_fresh_discovery(peer: dict[str, Any]) -> bool:
    """Reject an idempotent reconnect disguised as a fresh measurement."""
    return (
        not admitted(peer)
        and not bool(peer.get("local_approve_sent"))
        and not bool(peer.get("remote_approve_seen"))
        and peer.get("selected_pair") is None
    )


def pair_class(pair: Any) -> str | None:
    if not isinstance(pair, dict):
        return None
    local = str(pair.get("local", "")).lower()
    remote = str(pair.get("remote", "")).lower()
    if not local or not remote:
        return None
    if "relay" in {local, remote}:
        return "turn"
    reflexive = {"server_reflexive", "peer_reflexive", "srflx", "prflx"}
    if local in reflexive or remote in reflexive:
        return "stun"
    if local == "host" and remote == "host":
        return "lan"
    return None


def enforce_required_route(route: str, required: str | None) -> None:
    if required is not None and route != required:
        raise RuntimeError(
            f"selected route {route!r} did not satisfy required route {required!r}"
        )


def percentile(sorted_values: list[float], percentile_value: float) -> float:
    if not sorted_values:
        return 0.0
    # Nearest-rank percentile: with 20 observations p95 is the 19th value,
    # leaving one observation in the upper 5% instead of rounding ad hoc.
    rank = max(1, math.ceil(percentile_value * len(sorted_values)))
    return sorted_values[min(rank - 1, len(sorted_values) - 1)]


def measure_one(args: argparse.Namespace, network: str) -> dict[str, Any]:
    discovered, discovery_ms = wait_for_peer(
        args.binary,
        network,
        args.peer,
        args.discovery_timeout_ms / 1000.0,
        args.poll_ms / 1000.0,
        lambda _peer: True,
    )
    if not is_fresh_discovery(discovered):
        raise RuntimeError(
            "peer was already admitted, approved, or had a selected ICE pair before dial; "
            "the network is not a fresh connection sample"
        )

    started_wall = dt.datetime.now(dt.timezone.utc).isoformat()
    started_ns = time.perf_counter_ns()
    reply = run_json(
        args.binary,
        [
            "ctl",
            "networks",
            "connect",
            network,
            args.peer,
            "--wait-ms",
            str(args.connect_timeout_ms),
        ],
        args.connect_timeout_ms / 1000.0 + 10.0,
    )
    connected_ns = time.perf_counter_ns()
    connect_ms = (connected_ns - started_ns) / 1_000_000.0
    if not isinstance(reply, dict) or reply.get("active") is not True:
        raise RuntimeError(f"waited dial did not report active: {reply!r}")

    peer, approval_observation_ms = wait_for_peer(
        args.binary,
        network,
        args.peer,
        args.pair_timeout_ms / 1000.0,
        args.poll_ms / 1000.0,
        lambda snapshot: approved_bilaterally(snapshot)
        and pair_class(snapshot.get("selected_pair")) is not None,
    )
    route = pair_class(peer.get("selected_pair"))
    if route is None:
        raise RuntimeError("authenticated session has no classifiable selected ICE pair")
    enforce_required_route(route, args.require_route)

    return {
        "schema": "myownmesh-real-connection-benchmark-v1",
        "measured_at_utc": started_wall,
        "local_host": socket.gethostname(),
        "peer_host": args.peer_host,
        "scenario": args.scenario,
        "network": network,
        "peer": args.peer,
        "discovery_wait_ms": round(discovery_ms, 3),
        "connect_to_authenticated_active_ms": round(connect_ms, 3),
        "post_connect_pair_observation_ms": round(approval_observation_ms, 3),
        "route": route,
        "selected_pair": peer.get("selected_pair"),
        "rtt_ms": peer.get("rtt_ms"),
        "local_candidates": peer.get("local_candidates"),
        "remote_candidates": peer.get("remote_candidates"),
        "authenticated": peer.get("authenticated"),
        "status": peer.get("status"),
        "local_approve_sent": peer.get("local_approve_sent"),
        "remote_approve_seen": peer.get("remote_approve_seen"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure production-daemon connection establishment over fresh real networks."
        )
    )
    parser.add_argument("--binary", default="myownmesh", help="myownmesh executable")
    parser.add_argument("--peer", required=True, help="remote device id")
    parser.add_argument(
        "--peer-host",
        required=True,
        help="remote machine hostname; must differ from the local hostname",
    )
    parser.add_argument(
        "--peer-binary-sha256",
        required=True,
        help="recorded SHA-256 of the native myownmesh executable running on the peer",
    )
    parser.add_argument(
        "--local-source-revision",
        required=True,
        help="Git revision from which the local executable was built",
    )
    parser.add_argument(
        "--peer-source-revision",
        required=True,
        help="Git revision from which the peer executable was built",
    )
    parser.add_argument(
        "--network",
        action="append",
        required=True,
        help="fresh joined network/config id for one sample; repeat for more samples",
    )
    parser.add_argument("--discovery-timeout-ms", type=int, default=60_000)
    parser.add_argument("--connect-timeout-ms", type=int, default=60_000)
    parser.add_argument("--pair-timeout-ms", type=int, default=10_000)
    parser.add_argument("--poll-ms", type=int, default=25)
    parser.add_argument(
        "--scenario",
        default="baseline",
        help="recorded workload label, for example baseline or semantic-admission-load",
    )
    parser.add_argument(
        "--require-route",
        choices=("lan", "stun", "turn"),
        help="fail a sample unless its nominated ICE pair has this route class",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    local = socket.gethostname().casefold()
    if args.peer_host.casefold() == local:
        parser.error(
            "peer-host equals the local hostname; this harness refuses same-host results"
        )
    if len(set(args.network)) != len(args.network):
        parser.error("each --network must be unique and fresh")
    for name in (
        "discovery_timeout_ms",
        "connect_timeout_ms",
        "pair_timeout_ms",
        "poll_ms",
    ):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    resolved_binary = (
        str(Path(args.binary).resolve())
        if os.path.isfile(args.binary)
        else shutil.which(args.binary)
    )
    if resolved_binary is None:
        parser.error(f"myownmesh executable not found: {args.binary}")
    args.binary = resolved_binary
    if not args.scenario.strip():
        parser.error("--scenario must not be empty")
    if args.local_source_revision.casefold() != args.peer_source_revision.casefold():
        parser.error(
            "peer source revision differs from the local source revision; "
            "mixed-source timing is not a comparable benchmark"
        )
    args.peer_binary_sha256 = args.peer_binary_sha256.casefold()
    args.binary_sha256 = file_sha256(args.binary)
    args.local_source_revision = args.local_source_revision.casefold()
    args.peer_source_revision = args.peer_source_revision.casefold()
    return args


def file_sha256(path: str) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    records: list[dict[str, Any]] = []
    benchmark_started_ns = time.perf_counter_ns()
    for network in args.network:
        try:
            record = measure_one(args, network)
            records.append(record)
            print(json.dumps(record, sort_keys=True), flush=True)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            record = {
                "schema": "myownmesh-real-connection-benchmark-v1",
                "measured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "local_host": socket.gethostname(),
                "peer_host": args.peer_host,
                "network": network,
                "peer": args.peer,
                "scenario": args.scenario,
                "failure": str(error),
            }
            records.append(record)
            print(json.dumps(record, sort_keys=True), flush=True)

    latencies = sorted(
        float(record["connect_to_authenticated_active_ms"])
        for record in records
        if "connect_to_authenticated_active_ms" in record
    )
    failures = [record for record in records if "failure" in record]
    total_wall_ms = (time.perf_counter_ns() - benchmark_started_ns) / 1_000_000.0
    # Twenty is the minimum sample count at which a nearest-rank p95 has one
    # complete observation in the upper 5% tail. Smaller runs remain useful
    # smoke evidence but are labelled unqualified rather than overclaimed.
    minimum_qualified_samples = math.ceil(1.0 / (1.0 - 0.95))
    qualified = not failures and len(latencies) >= minimum_qualified_samples
    mean_ms = statistics.fmean(latencies) if latencies else None
    summary = {
        "schema": "myownmesh-real-connection-benchmark-summary-v1",
        "scenario": args.scenario,
        "attempts": len(records),
        "successful_samples": len(latencies),
        "failed_samples": len(failures),
        "success_rate": round(len(latencies) / len(records), 6),
        "statistically_qualified": qualified,
        "minimum_qualified_samples": minimum_qualified_samples,
        "qualification_failures": [
            reason
            for reason, failed in (
                ("one or more connection attempts failed", bool(failures)),
                (
                    "fewer than 20 successful samples; p95 tail is under-resolved",
                    len(latencies) < minimum_qualified_samples,
                ),
            )
            if failed
        ],
        "p50_ms": round(percentile(latencies, 0.50), 3) if latencies else None,
        "p95_ms": round(percentile(latencies, 0.95), 3) if latencies else None,
        "max_ms": round(max(latencies), 3) if latencies else None,
        "mean_ms": round(mean_ms, 3) if mean_ms is not None else None,
        "connection_phase_serial_capacity_per_second": round(1000.0 / mean_ms, 3)
        if mean_ms is not None
        else None,
        "observed_serial_attempts_per_second": round(
            len(records) * 1000.0 / total_wall_ms, 3
        ),
        "binary": args.binary,
        "binary_sha256": args.binary_sha256,
        "peer_binary_sha256": args.peer_binary_sha256,
        "local_source_revision": args.local_source_revision,
        "peer_source_revision": args.peer_source_revision,
        "local_host": socket.gethostname(),
        "peer_host": args.peer_host,
        "platform": platform.platform(),
        "logical_cpu_count": os.cpu_count(),
        "routes": {
            route: sum(record["route"] == route for record in records)
            for route in sorted(
                {str(record["route"]) for record in records if "route" in record}
            )
        },
    }
    print(json.dumps(summary, sort_keys=True), flush=True)
    if args.output:
        args.output.write_text(
            "\n".join(json.dumps(item, sort_keys=True) for item in [*records, summary])
            + "\n",
            encoding="utf-8",
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
