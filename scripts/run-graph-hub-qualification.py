#!/usr/bin/env python3
"""Run one frozen Graph/Hub qualification matrix without rebuilding between cells.

The outer durable runner owns checkout and resource serialization.  This harness
does not lock, retry, clean, install, or modify source files.  It performs one
locked workspace/all-target test build, resolves test executables exclusively
from that Cargo JSON stream, and then invokes a finite caller-supplied selector
matrix against those immutable binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable


SCHEMA_VERSION = 1
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MIN_CAPTURE_BYTES = 64 * 1024
GIT_TIMEOUT_SECONDS = 10
MAX_CELLS = 256
MAX_SELECTORS = 4096
TARGET_KINDS = {"lib", "bin", "integration"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]+$")
SELECTOR = re.compile(r"^[A-Za-z0-9_.:-]+$")
HEAD = re.compile(r"^[0-9a-fA-F]{40}$")
TEST_SUMMARY = re.compile(
    r"^test result: (?P<status>ok|FAILED)\. "
    r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
    r"(?P<filtered_out>\d+) filtered out(?:; finished in [^\r\n]+)?\r?$",
    re.MULTILINE,
)
RUNNING_TESTS = re.compile(r"^running (?P<count>\d+) tests?\r?$", re.MULTILINE)


class QualificationError(RuntimeError):
    pass


def selector_key(value: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        value.get("package", ""),
        value.get("target_kind", ""),
        value.get("target_name", ""),
        value.get("selector", ""),
    )


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise QualificationError(f"file changed while hashing: {path}")
    return digest.hexdigest()


def _git(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        return subprocess.check_output(
            ["git", "-c", "core.quotePath=false", "-C", str(repo), *args],
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise QualificationError(f"read-only git {' '.join(args)} failed: {error}") from error


def _nul_paths(raw: bytes) -> list[str]:
    return [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]


def source_manifest(repo: Path) -> dict[str, Any]:
    repo = repo.resolve()
    head = _git(repo, "rev-parse", "HEAD").decode().strip()
    ref_raw = subprocess.run(
        ["git", "-C", str(repo), "symbolic-ref", "--quiet", "--short", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=GIT_TIMEOUT_SECONDS,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        check=False,
    )
    ref = ref_raw.stdout.decode("utf-8", "replace").strip() or None
    tracked = set(_nul_paths(_git(repo, "ls-files", "--cached", "-z")))
    untracked = set(
        _nul_paths(_git(repo, "ls-files", "--others", "--exclude-standard", "-z"))
    )
    entries: list[dict[str, Any]] = []
    for relative in sorted(tracked | untracked):
        candidate = Path(os.path.abspath(repo / relative))
        if os.path.commonpath([str(repo), str(candidate)]) != str(repo):
            raise QualificationError(f"git returned a path outside the repository: {relative}")
        custody = "tracked" if relative in tracked else "untracked"
        if candidate.is_symlink():
            payload = os.readlink(candidate).encode("utf-8", "surrogateescape")
            entries.append(
                {
                    "path": relative,
                    "custody": custody,
                    "kind": "symlink",
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        elif candidate.is_file():
            entries.append(
                {
                    "path": relative,
                    "custody": custody,
                    "kind": "file",
                    "bytes": candidate.stat().st_size,
                    "sha256": sha256_file(candidate),
                }
            )
        elif custody == "tracked" and not candidate.exists():
            entries.append(
                {
                    "path": relative,
                    "custody": custody,
                    "kind": "deleted",
                    "bytes": None,
                    "sha256": None,
                }
            )
        else:
            raise QualificationError(f"unsupported source entry: {relative}")
    status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all").decode(
        "utf-8", "replace"
    ).splitlines()
    body = {"head": head, "ref": ref, "status": status, "files": entries}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    lock = next((entry for entry in entries if entry["path"] == "Cargo.lock"), None)
    if lock is None or lock["kind"] != "file" or lock["custody"] != "tracked":
        raise QualificationError("tracked root Cargo.lock is required for a locked qualification")
    return {
        **body,
        "file_count": len(entries),
        "tracked_count": len(tracked),
        "untracked_count": len(untracked),
        "cargo_lock": lock,
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def build_command(cargo: str) -> list[str]:
    return [
        cargo,
        "build",
        "--locked",
        "--workspace",
        "--all-targets",
        "--tests",
        "--features",
        "transport-lab",
        "--keep-going",
        "--message-format=json-render-diagnostics",
    ]


def package_name(package_id: str) -> str:
    old = re.match(r"^([A-Za-z0-9_.-]+)\s+\d", package_id)
    if old:
        return old.group(1)
    fragment = package_id.rsplit("#", 1)[-1]
    if "@" in fragment:
        return fragment.split("@", 1)[0]
    if fragment and not re.match(r"^\d+(?:\.\d+)+", fragment):
        return fragment
    base = package_id.split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    return base


def cargo_target_kind(kinds: Iterable[str]) -> str | None:
    values = set(kinds)
    if "test" in values:
        return "integration"
    if "lib" in values:
        return "lib"
    if "bin" in values:
        return "bin"
    return None


class CargoArtifactCollector:
    def __init__(self) -> None:
        self.executables: dict[tuple[str, str, str], Path] = {}
        self.errors: list[str] = []

    def feed(self, line: str) -> None:
        if not line.strip():
            return
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            self.errors.append(f"non-JSON Cargo stdout: {error}")
            return
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            return
        if not message.get("profile", {}).get("test"):
            return
        target = message.get("target", {})
        kind = cargo_target_kind(target.get("kind", []))
        if kind is None:
            return
        key = (package_name(str(message.get("package_id", ""))), kind, target.get("name", ""))
        path = Path(message["executable"])
        previous = self.executables.get(key)
        if previous is not None and previous != path:
            self.errors.append(f"ambiguous Cargo executable for {key}: {previous} vs {path}")
        self.executables[key] = path


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=GIT_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _pump(
    stream: Any,
    sink: bytearray,
    limit: int,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
    line_callback: Callable[[str], None] | None,
    callback_errors: list[str],
) -> None:
    pending = bytearray()
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            remaining = limit - len(sink)
            if len(chunk) > remaining:
                if remaining > 0:
                    sink.extend(chunk[:remaining])
                overflow.set()
                _kill_process_tree(process)
                break
            sink.extend(chunk)
            if line_callback is not None:
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    try:
                        line_callback((line + b"\n").decode("utf-8", "replace"))
                    except Exception as error:  # retained as harness evidence
                        callback_errors.append(repr(error))
        if line_callback is not None and pending and not overflow.is_set():
            try:
                line_callback(pending.decode("utf-8", "replace"))
            except Exception as error:
                callback_errors.append(repr(error))
    except Exception as error:
        callback_errors.append(f"capture stream failed: {error!r}")
        _kill_process_tree(process)
    finally:
        stream.close()


def run_captured(
    command: list[str],
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    stdout_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    started = utc_now()
    monotonic_start = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
    except OSError as error:
        return {
            "command": command,
            "started_at": started,
            "completed_at": utc_now(),
            "elapsed_seconds": time.monotonic() - monotonic_start,
            "exit_code": None,
            "terminal": "spawn_error",
            "error": repr(error),
            "stdout": "",
            "stderr": "",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    stdout_overflow = threading.Event()
    stderr_overflow = threading.Event()
    callback_errors: list[str] = []
    threads = [
        threading.Thread(
            target=_pump,
            args=(
                process.stdout,
                stdout,
                max_output_bytes,
                stdout_overflow,
                process,
                stdout_callback,
                callback_errors,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_pump,
            args=(
                process.stderr,
                stderr,
                max_output_bytes,
                stderr_overflow,
                process,
                None,
                callback_errors,
            ),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_tree(process)
        try:
            exit_code = process.wait(timeout=GIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            exit_code = None
    for thread in threads:
        thread.join(timeout=GIT_TIMEOUT_SECONDS)
    readers_stuck = any(thread.is_alive() for thread in threads)
    if readers_stuck or (timed_out and exit_code is None):
        terminal = "outcome_unknown"
    elif timed_out:
        terminal = "timeout"
    elif stdout_overflow.is_set() or stderr_overflow.is_set():
        terminal = "output_limit"
    elif callback_errors:
        terminal = "capture_error"
    else:
        terminal = "exited"
    return {
        "command": command,
        "started_at": started,
        "completed_at": utc_now(),
        "elapsed_seconds": time.monotonic() - monotonic_start,
        "exit_code": exit_code,
        "terminal": terminal,
        "callback_errors": callback_errors,
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_truncated": stdout_overflow.is_set(),
        "stderr_truncated": stderr_overflow.is_set(),
    }


def parse_test_result(stdout: str) -> dict[str, Any]:
    summaries = list(TEST_SUMMARY.finditer(stdout))
    running = [int(match.group("count")) for match in RUNNING_TESTS.finditer(stdout)]
    if len(summaries) != 1 or len(running) != 1:
        raise QualificationError(
            f"expected one native test summary and running count, found {len(summaries)}/{len(running)}"
        )
    summary = summaries[0]
    return {
        "status": summary.group("status"),
        "running": running[0],
        "passed": int(summary.group("passed")),
        "failed": int(summary.group("failed")),
        "ignored": int(summary.group("ignored")),
        "measured": int(summary.group("measured")),
        "filtered_out": int(summary.group("filtered_out")),
    }


def validate_spec(spec: dict[str, Any]) -> list[dict[str, Any]]:
    if spec.get("schema_version") != SCHEMA_VERSION:
        raise QualificationError(f"schema_version must be {SCHEMA_VERSION}")
    if not HEAD.fullmatch(str(spec.get("expected_head", ""))):
        raise QualificationError("expected_head must be one exact 40-hex revision")
    build_timeout = spec.get("build_timeout_seconds")
    if type(build_timeout) is not int or build_timeout <= 0:
        raise QualificationError("build_timeout_seconds must be a positive integer")
    capture = spec.get("max_output_bytes")
    if type(capture) is not int or not MIN_CAPTURE_BYTES <= capture <= MAX_CAPTURE_BYTES:
        raise QualificationError(
            f"max_output_bytes must be between {MIN_CAPTURE_BYTES} and {MAX_CAPTURE_BYTES}"
        )
    contract = spec.get("acceptance_contract")
    if not isinstance(contract, dict):
        raise QualificationError("acceptance_contract must bind the manager-owned contract")
    contract_path = contract.get("path")
    contract_hash = contract.get("sha256")
    if (
        not isinstance(contract_path, str)
        or not contract_path
        or Path(contract_path).is_absolute()
        or ".." in Path(contract_path).parts
        or not isinstance(contract_hash, str)
        or not re.fullmatch(r"[0-9a-fA-F]{64}", contract_hash)
    ):
        raise QualificationError("acceptance_contract path/hash is invalid")
    required_raw = spec.get("required_selectors")
    if (
        not isinstance(required_raw, list)
        or not required_raw
        or len(required_raw) > MAX_SELECTORS
    ):
        raise QualificationError("required_selectors must be a nonempty manager-owned list")
    required: set[tuple[str, str, str, str]] = set()
    for entry in required_raw:
        if not isinstance(entry, dict):
            raise QualificationError("each required selector must be an object")
        key = selector_key(entry)
        if (
            not all(isinstance(value, str) and value for value in key)
            or key[1] not in TARGET_KINDS
            or key in required
        ):
            raise QualificationError(f"invalid or duplicate required selector: {entry!r}")
        required.add(key)
    cells = spec.get("cells")
    if not isinstance(cells, list) or not cells or len(cells) > MAX_CELLS:
        raise QualificationError("cells must be a nonempty finite list")
    normalized: list[dict[str, Any]] = []
    ids: set[str] = set()
    coverage: set[tuple[str, str, str, str]] = set()
    for raw in cells:
        if not isinstance(raw, dict):
            raise QualificationError("each cell must be an object")
        cell = dict(raw)
        cell_id = cell.get("id")
        if not isinstance(cell_id, str) or not IDENTIFIER.fullmatch(cell_id) or cell_id in ids:
            raise QualificationError(f"invalid or duplicate cell id: {cell_id!r}")
        package = cell.get("package")
        kind = cell.get("target_kind")
        target = cell.get("target_name")
        if not all(isinstance(value, str) and value for value in (package, kind, target)):
            raise QualificationError(f"{cell_id}: package/target fields must be nonempty strings")
        if kind not in TARGET_KINDS:
            raise QualificationError(f"{cell_id}: unsupported target_kind {kind!r}")
        selectors = cell.get("selectors")
        if not isinstance(selectors, list) or not selectors or not all(
            isinstance(selector, str) and SELECTOR.fullmatch(selector) for selector in selectors
        ):
            raise QualificationError(f"{cell_id}: selectors must be an explicit nonempty list")
        if len(selectors) != 1:
            raise QualificationError(
                f"{cell_id}: qualification cells require exactly one exact selector"
            )
        expected_running = cell.get("expected_running")
        if type(expected_running) is not int or expected_running <= 0:
            raise QualificationError(f"{cell_id}: expected_running must be positive")
        if expected_running != 1:
            raise QualificationError(
                f"{cell_id}: the exact selector must account for one running test"
            )
        expected = cell.get("expected_summary")
        required_counts = {"passed", "failed", "ignored", "measured"}
        if not isinstance(expected, dict) or not required_counts.issubset(expected):
            raise QualificationError(f"{cell_id}: expected_summary lacks exact counts")
        if not set(expected).issubset(required_counts | {"filtered_out"}):
            raise QualificationError(f"{cell_id}: expected_summary has unknown counts")
        for name in required_counts | ({"filtered_out"} if "filtered_out" in expected else set()):
            if type(expected[name]) is not int or expected[name] < 0:
                raise QualificationError(f"{cell_id}: invalid expected {name}")
        if expected["failed"] != 0 or expected["passed"] != expected_running:
            raise QualificationError(
                f"{cell_id}: qualification cells must expect every running test to pass"
            )
        timeout = cell.get("timeout_seconds")
        if type(timeout) is not int or timeout <= 0:
            raise QualificationError(f"{cell_id}: timeout_seconds must be positive")
        if not isinstance(cell.get("ignored", False), bool):
            raise QualificationError(f"{cell_id}: ignored must be boolean")
        dependencies = cell.get("depends_on", [])
        if (
            not isinstance(dependencies, list)
            or len(dependencies) != len(set(dependencies))
            or any(dep not in ids for dep in dependencies)
        ):
            raise QualificationError(f"{cell_id}: dependencies must name earlier cells")
        if cell.get("ignored", False) and not selectors:
            raise QualificationError(f"{cell_id}: ignored whole-target sweeps are forbidden")
        ids.add(cell_id)
        for selector in selectors:
            key = (package, kind, target, selector)
            if key in coverage:
                raise QualificationError(f"{cell_id}: selector repeats an earlier cell: {selector}")
            coverage.add(key)
        normalized.append(cell)
        if len(coverage) > MAX_SELECTORS:
            raise QualificationError("selector manifest exceeds the finite selector ceiling")
    missing = sorted(required - coverage)
    if missing:
        preview = "; ".join("/".join(item) for item in missing[:8])
        raise QualificationError(
            f"selector manifest omits {len(missing)} manager-required controls: {preview}"
        )
    return normalized


def evaluate_capture(capture: dict[str, Any], cell: dict[str, Any]) -> tuple[bool, Any]:
    try:
        actual = parse_test_result(capture["stdout"])
    except QualificationError as error:
        return False, {"parse_error": str(error)}
    expected = cell["expected_summary"]
    matches = (
        capture["terminal"] == "exited"
        and capture["exit_code"] == 0
        and actual["status"] == "ok"
        and actual["running"] == cell["expected_running"]
    )
    for name, value in expected.items():
        matches = matches and actual.get(name) == value
    return matches, actual


def _checkpoint_matches(actual: dict[str, Any], baseline: dict[str, Any]) -> bool:
    return actual["sha256"] == baseline["sha256"] and actual["head"] == baseline["head"]


def run_qualification(repo: Path, spec: dict[str, Any], cargo: str) -> tuple[dict[str, Any], int]:
    cells = validate_spec(spec)
    baseline = source_manifest(repo)
    contract = spec["acceptance_contract"]
    contract_entry = next(
        (entry for entry in baseline["files"] if entry["path"] == contract["path"]), None
    )
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "started_at": utc_now(),
        "status": "running",
        "environment": {
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "python": sys.version,
            "repository": str(repo),
            "cargo": cargo,
        },
        "selector_manifest_sha256": hashlib.sha256(
            json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "selector_manifest": spec,
        "acceptance_contract": contract,
        "source": {"start": baseline, "checkpoints": []},
        "build": None,
        "binaries": [],
        "cells": [],
    }
    if (
        contract_entry is None
        or contract_entry["kind"] != "file"
        or contract_entry["sha256"].lower() != contract["sha256"].lower()
    ):
        report["status"] = "stale_source"
        report["fatal"] = "acceptance contract does not match its manager-supplied hash"
        report["completed_at"] = utc_now()
        return report, 2
    if baseline["head"].lower() != spec["expected_head"].lower():
        report["status"] = "stale_source"
        report["fatal"] = "HEAD does not match expected_head"
        report["completed_at"] = utc_now()
        return report, 2
    expected_ref = spec.get("expected_ref")
    if expected_ref is not None and baseline["ref"] != expected_ref:
        report["status"] = "stale_source"
        report["fatal"] = "ref does not match expected_ref"
        report["completed_at"] = utc_now()
        return report, 2
    expected_manifest = spec.get("expected_source_manifest_sha256")
    if expected_manifest is not None and baseline["sha256"] != expected_manifest:
        report["status"] = "stale_source"
        report["fatal"] = "source manifest does not match expected_source_manifest_sha256"
        report["completed_at"] = utc_now()
        return report, 2

    collector = CargoArtifactCollector()
    build = run_captured(
        build_command(cargo),
        repo,
        spec["build_timeout_seconds"],
        spec["max_output_bytes"],
        collector.feed,
    )
    report["build"] = build
    if build["terminal"] == "outcome_unknown":
        report["status"] = "outcome_unknown"
        report["fatal"] = "build process outcome or liveness is unknown; no later process was started"
        report["completed_at"] = utc_now()
        return report, 2
    try:
        after_build = source_manifest(repo)
    except (OSError, QualificationError) as error:
        report["status"] = "source_custody_error"
        report["fatal"] = f"could not rehash source after build: {error}"
        report["completed_at"] = utc_now()
        return report, 2
    report["source"]["checkpoints"].append(
        {"phase": "after_build", "sha256": after_build["sha256"], "head": after_build["head"]}
    )
    if not _checkpoint_matches(after_build, baseline):
        report["status"] = "stale_source"
        report["fatal"] = "source changed during build"
        report["completed_at"] = utc_now()
        return report, 2
    if build["terminal"] != "exited" or build["exit_code"] != 0 or collector.errors:
        report["status"] = "build_failed"
        report["cargo_json_errors"] = collector.errors
        report["completed_at"] = utc_now()
        return report, 1

    binaries: dict[tuple[str, str, str], dict[str, Any]] = {}
    for key, raw_path in sorted(collector.executables.items()):
        path = raw_path if raw_path.is_absolute() else repo / raw_path
        if not path.is_file():
            report["status"] = "build_failed"
            report["fatal"] = f"Cargo-reported executable is missing: {path}"
            report["completed_at"] = utc_now()
            return report, 1
        try:
            binary_hash = sha256_file(path)
        except (OSError, QualificationError) as error:
            report["status"] = "binary_custody_error"
            report["fatal"] = f"could not hash Cargo-reported executable {path}: {error}"
            report["completed_at"] = utc_now()
            return report, 2
        identity = {
            "package": key[0],
            "target_kind": key[1],
            "target_name": key[2],
            "path": str(path),
            "sha256": binary_hash,
        }
        binaries[key] = identity
        report["binaries"].append(identity)

    missing_targets = sorted(
        {
            (cell["package"], cell["target_kind"], cell["target_name"])
            for cell in cells
        }
        - set(binaries)
    )
    if missing_targets:
        report["status"] = "manifest_target_error"
        report["fatal"] = "manager manifest names targets absent from this exact build"
        report["missing_targets"] = missing_targets
        report["completed_at"] = utc_now()
        return report, 1

    statuses: dict[str, str] = {}
    runtime_failed = False
    for cell in cells:
        cell_id = cell["id"]
        if any(statuses.get(dep) != "passed" for dep in cell.get("depends_on", [])):
            result = {"id": cell_id, "status": "skipped_dependency", "depends_on": cell.get("depends_on", [])}
            report["cells"].append(result)
            statuses[cell_id] = result["status"]
            runtime_failed = True
            continue
        try:
            checkpoint = source_manifest(repo)
        except (OSError, QualificationError) as error:
            report["status"] = "source_custody_error"
            report["fatal"] = f"could not hash source before cell {cell_id}: {error}"
            break
        report["source"]["checkpoints"].append(
            {"phase": f"before:{cell_id}", "sha256": checkpoint["sha256"], "head": checkpoint["head"]}
        )
        if not _checkpoint_matches(checkpoint, baseline):
            report["status"] = "stale_source"
            report["fatal"] = f"source changed before cell {cell_id}"
            break
        key = (cell["package"], cell["target_kind"], cell["target_name"])
        binary = binaries.get(key)
        if binary is None:
            result = {"id": cell_id, "status": "missing_binary", "target": key}
            report["cells"].append(result)
            statuses[cell_id] = result["status"]
            runtime_failed = True
            continue
        path = Path(binary["path"])
        try:
            before_binary = sha256_file(path)
        except (OSError, QualificationError) as error:
            report["status"] = "binary_custody_error"
            report["fatal"] = f"could not hash binary before cell {cell_id}: {error}"
            break
        if before_binary != binary["sha256"]:
            report["status"] = "stale_binary"
            report["fatal"] = f"binary changed before cell {cell_id}"
            break
        command = [str(path), "--exact", *cell["selectors"]]
        if cell.get("ignored", False):
            command.append("--ignored")
        command.extend(["--nocapture", "--test-threads=1"])
        capture = run_captured(
            command,
            repo,
            cell["timeout_seconds"],
            spec["max_output_bytes"],
        )
        passed, parsed = evaluate_capture(capture, cell)
        if capture["terminal"] == "outcome_unknown":
            result = {
                "id": cell_id,
                "status": "outcome_unknown",
                "target": {"package": key[0], "kind": key[1], "name": key[2]},
                "selectors": cell["selectors"],
                "expected_running": cell["expected_running"],
                "expected_summary": cell["expected_summary"],
                "actual_summary": parsed,
                "binary_sha256_before": before_binary,
                "binary_sha256_after": None,
                "capture": capture,
            }
            report["cells"].append(result)
            statuses[cell_id] = result["status"]
            report["status"] = "outcome_unknown"
            report["fatal"] = (
                f"cell {cell_id} process outcome or liveness is unknown; "
                "no later process was started"
            )
            break
        try:
            after_binary = sha256_file(path)
            after_source = source_manifest(repo)
        except (OSError, QualificationError) as error:
            report["cells"].append(
                {
                    "id": cell_id,
                    "status": "custody_error",
                    "capture": capture,
                    "actual_summary": parsed,
                    "error": str(error),
                }
            )
            statuses[cell_id] = "custody_error"
            report["status"] = "source_custody_error"
            report["fatal"] = f"could not rehash source/binary after cell {cell_id}: {error}"
            break
        report["source"]["checkpoints"].append(
            {"phase": f"after:{cell_id}", "sha256": after_source["sha256"], "head": after_source["head"]}
        )
        result = {
            "id": cell_id,
            "status": "passed" if passed else "failed",
            "target": {"package": key[0], "kind": key[1], "name": key[2]},
            "selectors": cell["selectors"],
            "expected_running": cell["expected_running"],
            "expected_summary": cell["expected_summary"],
            "actual_summary": parsed,
            "binary_sha256_before": before_binary,
            "binary_sha256_after": after_binary,
            "capture": capture,
        }
        report["cells"].append(result)
        statuses[cell_id] = result["status"]
        runtime_failed = runtime_failed or not passed
        if after_binary != binary["sha256"]:
            report["status"] = "stale_binary"
            report["fatal"] = f"binary changed during cell {cell_id}"
            break
        if not _checkpoint_matches(after_source, baseline):
            report["status"] = "stale_source"
            report["fatal"] = f"source changed during cell {cell_id}"
            break
    if report["status"] == "running":
        report["status"] = "failed" if runtime_failed else "passed"
    report["completed_at"] = utc_now()
    if report["status"] == "passed":
        return report, 0
    if report["status"] in {
        "stale_source",
        "stale_binary",
        "source_custody_error",
        "binary_custody_error",
        "outcome_unknown",
    }:
        return report, 2
    return report, 1


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error(f"refusing to overwrite existing output: {args.output}")
    try:
        spec = json.loads(args.manifest.read_text(encoding="utf-8"))
        repo = args.repo.resolve(strict=True)
        cargo = shutil.which(args.cargo) or args.cargo
        report, exit_code = run_qualification(repo, spec, cargo)
    except (OSError, json.JSONDecodeError, QualificationError) as error:
        report = {
            "schema_version": SCHEMA_VERSION,
            "status": "harness_error",
            "started_at": utc_now(),
            "completed_at": utc_now(),
            "error": str(error),
        }
        exit_code = 2
    try:
        write_report(args.output, report)
    except OSError as error:
        print(f"could not write qualification report: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": str(args.output)}))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
