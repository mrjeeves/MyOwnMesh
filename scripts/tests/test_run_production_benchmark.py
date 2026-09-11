from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import sys
import tempfile
import time
from argparse import Namespace
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "run-production-benchmark.py"
SPEC = importlib.util.spec_from_file_location("production_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


COMPLETE_GRANT = ",".join(f"{name}=1" for name in benchmark.GRANT_DIMENSIONS)


def _provider_snapshot() -> dict[str, object]:
    return {
        "owner_active_candidates": 0,
        "owner_failed_cleanup_candidates": 0,
        "owner_accounting_poisoned": False,
        "owner_queued_jobs": 0,
        "owner_active_jobs": 0,
        "owner_completed_jobs": 0,
        "owner_failed_jobs": 0,
        "owner_executor_failed": False,
        "mesh_active_candidates": 0,
        "mesh_failed_cleanup_candidates": 0,
        "mesh_accounting_poisoned": False,
    }


def _scale_metric(selector: str, scale_n: int) -> dict[str, object]:
    timed_admissions = min(scale_n, 2_000) if scale_n >= 250_000 else scale_n
    seeded_admissions = scale_n - timed_admissions
    window_target = (timed_admissions + 127) // 128
    window_evidence = []
    window_start = seeded_admissions
    remaining = timed_admissions
    while remaining:
        count = min(window_target, remaining)
        window_total_ms = float(count) / timed_admissions
        window_evidence.append(
            {
                "start_admitted": window_start + 1,
                "end_admitted": window_start + count,
                "admission_count": count,
                "admission_total_ms": window_total_ms,
                "elapsed_ms": window_total_ms,
                "average_admission_ms": window_total_ms / count,
                "p50_ms": 0.001,
                "p95_ms": 0.002,
                "p99_ms": 0.003,
            }
        )
        window_start += count
        remaining -= count
    return {
        "selector": selector,
        "platform": "windows",
        "scale_n": scale_n,
        "admitted_delta": scale_n,
        "seeded_admissions": seeded_admissions,
        "timed_admissions": timed_admissions,
        "seed_total_ms": 0.0,
        "unresolved": 0,
        "admission_total_ms": 1.0,
        "admission_end_to_end_total_ms": 1.0,
        "admissions_per_sec": 1_000.0 * timed_admissions,
        "delta_write_total_ms": 0.5,
        "admission_p50_ms": 0.001,
        "admission_p95_ms": 0.002,
        "admission_p99_ms": 0.003,
        "window_evidence": window_evidence,
        "window_admission_target": window_target,
        "window_sample_limit": 64,
        "cache_state": benchmark.SEMANTIC_CACHE_STATE,
        **{field: None for field in benchmark.SEMANTIC_OPTIONAL_SCALE_COUNTERS},
        "compaction_ms": 0.25,
        "startup_plus_restore_ms": 2.0,
        "db_main_bytes_peak": 10,
        "db_wal_bytes_peak": 2,
        "db_shm_bytes_peak": 3,
        "db_journal_bytes_peak": 4,
        "db_total_bytes_peak": 19,
        "db_main_bytes_after_compaction": 10,
        "db_wal_bytes_after_compaction": 0,
        "db_shm_bytes_after_compaction": 0,
        "db_total_bytes_after": 10,
        "provider_baseline": _provider_snapshot(),
        "provider_final": _provider_snapshot(),
    }


def _open_metric() -> dict[str, object]:
    footprint = {field: 0 for field in benchmark.SEMANTIC_FOOTPRINT_FIELDS}
    return {
        "selector": "semantic_ledger_scale_open_presence_zero",
        "cycles": 5,
        "db_baseline": footprint,
        "db_final": dict(footprint),
        "provider_baseline": _provider_snapshot(),
        "provider_final": _provider_snapshot(),
    }


def _proof_metric() -> dict[str, object]:
    footprint = {field: 4 for field in ("main_bytes", "wal_bytes", "shm_bytes", "journal_bytes")}
    operations = {
        operation: {"before": dict(footprint), "after": dict(footprint)}
        for operation in benchmark.SEMANTIC_PROOF_OPERATIONS
    }
    return {
        "selector": benchmark.SEMANTIC_PROOF_SELECTOR,
        "seeded_proof_count": 15,
        "linked_fact_count": 5,
        "configured_max_database_bytes": 256 * 1024 * 1024,
        "operations": operations,
        "unrelated_rows_preserved": True,
        "no_op_footprints_equal": True,
        "reopened_exact_equality": True,
        "reopened_pending_count": 13,
        "reopened_terminal_count": 2,
    }


def _capacity_metric() -> dict[str, object]:
    return {
        "selector": benchmark.SEMANTIC_CAPACITY_SELECTOR,
        "footprint": {
            "event": "semantic_capacity_footprint",
            "M": 100,
            "W": 20,
            "S": 30,
            "R": 50,
            "B": 200,
            "provider_baseline_storage": 0,
            "provider_live_storage": 200,
            "provider_baseline_opaque_dependency_residual": 1,
            "provider_live_opaque_dependency_residual": 2,
        },
        "terminal": {
            "event": "semantic_capacity_terminal",
            "provider_storage": 0,
            "provider_opaque_dependency_residual": 0,
            "provider_retained_after_failed_cleanup": 0,
        },
    }


def _purge_metric() -> dict[str, object]:
    absent = {"before_bytes": None, "after_bytes": None, "recreated_bytes": None}
    return {
        "selector": benchmark.SEMANTIC_PURGE_SELECTOR,
        "purge_elapsed_ms": 3,
        "recreate_elapsed_ms": 4,
        "files": {
            "main": {"before_bytes": 100, "after_bytes": None, "recreated_bytes": 100},
            "wal": dict(absent),
            "shm": dict(absent),
            "journal": {"before_bytes": 20, "after_bytes": None, "recreated_bytes": None},
            "neighbor": {"before_bytes": 7, "after_bytes": 7, "recreated_bytes": 7},
        },
        "neighbor_survived": True,
        "competing_writer_busy": True,
        "terminal_baseline": {
            "primary_shutdown_ok": True,
            "restarted_shutdown_ok": True,
            "primary_shutdown_elapsed_ms": 5,
        },
    }


def _budget_scale_cases(timed_by_scale: dict[int, int]) -> list[dict[str, object]]:
    cases = []
    for scale in (1_000, 10_000, 100_000, 250_000, 500_000, 1_000_000):
        timed = timed_by_scale[scale]
        cases.append(
            {
                "elapsed_ms": 1.0,
                "process": {"peak_rss_bytes": {"semantic_ledger_scale": 1}},
                "metric": {
                    "scale_n": scale,
                    "timed_admissions": timed,
                    "admission_total_ms": 1.0,
                    "platform": "linux",
                    "window_admission_target": 128,
                    "window_sample_limit": 64,
                    "cache_state": benchmark.SEMANTIC_CACHE_STATE,
                    "db_main_bytes_peak": 1,
                    "db_wal_bytes_peak": 1,
                    "db_shm_bytes_peak": 1,
                    "db_journal_bytes_peak": 1,
                    "db_total_bytes_peak": 4,
                },
            }
        )
    return cases


def test_scale_budget_rejects_unmatched_seeded_workloads() -> None:
    args = Namespace(semantic_max_wall_ms=10.0, semantic_max_rss_bytes=10, semantic_max_disk_bytes=10,
                     semantic_max_matched_tail_total_ms_per_ledger_fact=1.0)
    cases = _budget_scale_cases({scale: scale for scale in (1_000, 10_000, 100_000, 250_000, 500_000, 1_000_000)})
    try:
        benchmark._validate_semantic_scale_budgets(cases, args)
    except benchmark.BenchmarkError as error:
        assert "unavailable" in str(error)
    else:
        raise AssertionError("mixed seeded/unseeded scales must not silently pass a slope gate")


def test_scale_budget_uses_only_matched_tail_workload() -> None:
    args = Namespace(semantic_max_wall_ms=10.0, semantic_max_rss_bytes=10, semantic_max_disk_bytes=10,
                     semantic_max_matched_tail_total_ms_per_ledger_fact=0.001)
    cases = _budget_scale_cases({
        1_000: 1_000,
        10_000: 10_000,
        100_000: 100_000,
        250_000: 2_000,
        500_000: 2_000,
        1_000_000: 2_000,
    })
    cases[3]["metric"]["admission_total_ms"] = 1.0
    cases[4]["metric"]["admission_total_ms"] = 1.1
    cases[5]["metric"]["admission_total_ms"] = 1.2
    benchmark._validate_semantic_scale_budgets(cases, args)
    assert cases[1]["budget_observations"]["marginal_slope_status"] == "unavailable_unmatched_workload"
    assert cases[4]["budget_observations"]["marginal_slope_status"] == "matched_tail_window"
    assert math.isclose(cases[4]["budget_observations"]["marginal_slope_ms_per_fact"], 0.0000004)


def test_semantic_executable_output_files_are_read_after_sampling_model() -> None:
    class FakeProcess:
        pid = 2_000_000_000
        returncode = 0

        def poll(self) -> int:
            return self.returncode

        def wait(self) -> int:
            return self.returncode

    class FakeSampler:
        def __init__(self, processes: dict[str, object]) -> None:
            self.processes = processes

        def sample(self, phase: str) -> None:
            del phase

        def result(self) -> dict[str, object]:
            return {"available": False, "samples": []}

    def fake_popen(command: list[str], **kwargs: object) -> FakeProcess:
        del command
        stdout = kwargs["stdout"]
        stderr = kwargs["stderr"]
        assert hasattr(stdout, "write") and hasattr(stderr, "write")
        stdout.write(b"out" * (256 * 1024))
        stderr.write(b"err" * (256 * 1024))
        return FakeProcess()

    with patch.object(benchmark.subprocess, "Popen", fake_popen), patch.object(benchmark, "ProcSampler", FakeSampler):
        stdout, stderr, _, _, returncode = benchmark._run_semantic_executable(
            Path("fixture"), "selector", 1.0, Path(".")
        )
    assert returncode == 0
    assert len(stdout) == 3 * 256 * 1024
    assert len(stderr) == 3 * 256 * 1024


def test_scale_window_coverage_and_totals_are_strict() -> None:
    metric = _scale_metric("semantic_ledger_scale_n_10k", 10_000)
    assert benchmark.validate_semantic_metric(metric, metric["selector"], 10_000) == metric
    assert len(metric["window_evidence"]) > 1
    assert metric["window_evidence"][-1]["admission_count"] < metric["window_admission_target"]
    broken_coverage = dict(metric)
    broken_coverage["window_evidence"] = [dict(window) for window in metric["window_evidence"]]
    broken_coverage["window_evidence"][1]["start_admitted"] += 1
    broken_coverage["window_evidence"][1]["end_admitted"] += 1
    try:
        benchmark.validate_semantic_metric(broken_coverage, metric["selector"], 10_000)
    except benchmark.BenchmarkError as error:
        assert "contiguous" in str(error)
    else:
        raise AssertionError("non-contiguous scale windows must be rejected")
    broken_total = dict(metric)
    # Every individual window remains valid; only the aggregate sum disagrees.
    broken_total["admission_total_ms"] = 2.0
    try:
        benchmark.validate_semantic_metric(broken_total, metric["selector"], 10_000)
    except benchmark.BenchmarkError as error:
        assert "total does not match" in str(error)
    else:
        raise AssertionError("inconsistent scale window totals must be rejected")
    broken_mean = dict(metric)
    broken_mean["window_evidence"] = [dict(window) for window in metric["window_evidence"]]
    broken_mean["window_evidence"][0]["average_admission_ms"] += 1.0
    try:
        benchmark.validate_semantic_metric(broken_mean, metric["selector"], 10_000)
    except benchmark.BenchmarkError as error:
        assert "inconsistent average" in str(error)
    else:
        raise AssertionError("inconsistent window means must be rejected")


def test_scale_budget_preserves_signed_matched_tail_delta_and_threshold() -> None:
    args = Namespace(semantic_max_wall_ms=10.0, semantic_max_rss_bytes=10, semantic_max_disk_bytes=10,
                     semantic_max_matched_tail_total_ms_per_ledger_fact=0.001)
    cases = _budget_scale_cases({
        1_000: 1_000,
        10_000: 10_000,
        100_000: 100_000,
        250_000: 2_000,
        500_000: 2_000,
        1_000_000: 2_000,
    })
    cases[3]["metric"]["admission_total_ms"] = 2.0
    cases[4]["metric"]["admission_total_ms"] = 1.0
    cases[5]["metric"]["admission_total_ms"] = 501.00025
    try:
        benchmark._validate_semantic_scale_budgets(cases, args)
    except benchmark.BenchmarkError as error:
        assert "500000->1000000" in str(error)
    else:
        raise AssertionError("positive threshold overflow must fail after preserving signed deltas")
    assert cases[4]["budget_observations"]["marginal_slope_ms_per_fact"] == -0.000004


def _finish_fixture_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    process.wait(timeout=2.0)


@contextmanager
def _real_child_popen(script: str, ready: Path, before_ready=None):
    """Keep fixture custody even before the runner receives its Popen result."""
    real_popen = benchmark.subprocess.Popen
    children = []

    def popen(command: list[str], **kwargs: object):
        del command
        process = real_popen([sys.executable, "-u", "-c", script], **kwargs)
        children.append(process)
        try:
            if before_ready is not None:
                before_ready()
            deadline = time.monotonic() + 2.0
            while not ready.exists():
                if process.poll() is not None:
                    raise AssertionError(f"child exited before readiness: {process.returncode}")
                if time.monotonic() >= deadline:
                    raise AssertionError("child did not publish readiness")
                time.sleep(0.001)
            return process
        except BaseException:
            _finish_fixture_child(process)
            raise

    try:
        yield popen, children
    finally:
        for process in children:
            _finish_fixture_child(process)


CHILD_OUTPUT_BYTES = 524_289


def _flood_child_script(ready: Path, release: Path, returncode: int = 0) -> str:
    return (
        "import pathlib, sys, time\n"
        f"sys.stdout.buffer.write(b'o' * {CHILD_OUTPUT_BYTES}); sys.stdout.flush()\n"
        f"sys.stderr.buffer.write(b'e' * {CHILD_OUTPUT_BYTES}); sys.stderr.flush()\n"
        f"pathlib.Path({str(ready)!r}).write_text('ready')\n"
        "watchdog = time.monotonic() + 30.0\n"
        f"while not pathlib.Path({str(release)!r}).exists():\n"
        "    if time.monotonic() >= watchdog: raise SystemExit(99)\n"
        "    time.sleep(0.001)\n"
        f"raise SystemExit({returncode})\n"
    )


def _real_child_released_after_sample(returncode: int) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        ready = Path(temporary) / "child.ready"
        release = Path(temporary) / "child.release"
        real_sampler = benchmark.ProcSampler

        class ObservingSampler:
            instances = []

            def __init__(self, processes: dict[str, object]) -> None:
                self.process = processes["semantic_ledger_scale"]
                self.inner = real_sampler(processes)
                self.saw_running = False
                self.instances.append(self)

            def sample(self, phase: str) -> None:
                if self.process.poll() is None:
                    self.saw_running = True
                self.inner.sample(phase)
                # The child cannot exit before this exact alive observation.
                release.touch()

            def result(self) -> dict[str, object]:
                return self.inner.result()

        with _real_child_popen(_flood_child_script(ready, release, returncode), ready) as (popen, children):
            with patch.object(benchmark.subprocess, "Popen", popen), patch.object(
                benchmark, "ProcSampler", ObservingSampler
            ):
                if returncode == 0:
                    stdout, stderr, _, _, actual_returncode = benchmark._run_semantic_executable(
                        Path("fixture"), "ignored", 2.0, Path(temporary)
                    )
                    assert actual_returncode == 0
                else:
                    try:
                        benchmark._run_semantic_executable(Path("fixture"), "ignored", 2.0, Path(temporary))
                    except benchmark.SemanticExecutableError as error:
                        assert error.terminal == "reaped"
                        assert error.returncode == returncode
                        stdout, stderr = error.stdout, error.stderr
                    else:
                        raise AssertionError("nonzero semantic child must fail with retained output")
            assert stdout == "o" * CHILD_OUTPUT_BYTES
            assert stderr == "e" * CHILD_OUTPUT_BYTES
            assert ObservingSampler.instances[0].saw_running
            # Assert before the fixture's fallback cleanup can mask a runner defect.
            assert len(children) == 1 and children[0].returncode == returncode


def test_semantic_real_child_success_floods_both_streams_and_reaps() -> None:
    _real_child_released_after_sample(0)


def test_semantic_real_child_failure_retains_output_and_reaps() -> None:
    _real_child_released_after_sample(17)


def test_semantic_child_deadline_retains_output_and_reaps() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        ready = Path(temporary) / "deadline.ready"
        release = Path(temporary) / "never.release"
        with _real_child_popen(_flood_child_script(ready, release), ready) as (popen, children):
            try:
                with patch.object(benchmark.subprocess, "Popen", popen):
                    benchmark._run_semantic_executable(Path("fixture"), "ignored", 0.1, Path(temporary))
            except benchmark.SemanticExecutableError as error:
                assert error.terminal == "reaped"
                assert "exceeded --semantic-timeout" in str(error)
                assert error.stdout == "o" * CHILD_OUTPUT_BYTES
                assert error.stderr == "e" * CHILD_OUTPUT_BYTES
                assert error.returncode is not None
            else:
                raise AssertionError("deadline must fail with retained output")
            assert len(children) == 1 and children[0].returncode is not None


def test_semantic_sampler_failures_reap_child_and_retain_output() -> None:
    for sampler_error in ("constructor", "sample", "keyboard_interrupt"):
        with tempfile.TemporaryDirectory() as temporary:
            ready = Path(temporary) / f"{sampler_error}.ready"
            release = Path(temporary) / "never.release"

            class FailingSampler:
                def __init__(self, processes: dict[str, object]) -> None:
                    del processes
                    self.samples = 0
                    if sampler_error == "constructor":
                        raise RuntimeError("sampler constructor failure")

                def sample(self, phase: str) -> None:
                    del phase
                    self.samples += 1
                    if self.samples == 1:
                        return
                    if sampler_error == "keyboard_interrupt":
                        raise KeyboardInterrupt()
                    raise RuntimeError("sampler sample failure")

                def result(self) -> dict[str, object]:
                    return {}

            with _real_child_popen(_flood_child_script(ready, release), ready) as (popen, children):
                with patch.object(benchmark.subprocess, "Popen", popen), patch.object(
                    benchmark, "ProcSampler", FailingSampler
                ):
                    try:
                        benchmark._run_semantic_executable(Path("fixture"), "selector", 2.0, Path(temporary))
                    except benchmark.SemanticExecutableError as error:
                        assert error.terminal == "reaped"
                        assert error.stdout == "o" * CHILD_OUTPUT_BYTES
                        assert error.stderr == "e" * CHILD_OUTPUT_BYTES
                        assert error.returncode is not None
                        expected_cause = KeyboardInterrupt if sampler_error == "keyboard_interrupt" else RuntimeError
                        assert isinstance(error.__cause__, expected_cause)
                    else:
                        raise AssertionError("sampler failures must fail closed")
                assert len(children) == 1 and children[0].returncode is not None


def test_fixture_readiness_failure_reaps_before_handoff() -> None:
    for error_type in (RuntimeError, KeyboardInterrupt):
        with tempfile.TemporaryDirectory() as temporary:
            ready = Path(temporary) / "ready"
            release = Path(temporary) / "never.release"

            def fail_before_ready():
                raise error_type("fixture readiness failure")

            with _real_child_popen(_flood_child_script(ready, release), ready, fail_before_ready) as (popen, children):
                with patch.object(benchmark.subprocess, "Popen", popen):
                    try:
                        benchmark._run_semantic_executable(Path("fixture"), "selector", 2.0, Path(temporary))
                    except benchmark.SemanticExecutableError as error:
                        # The fixture, not the runner, still owned the unreturned handle.
                        assert error.terminal == "not_started"
                        assert isinstance(error.__cause__, error_type)
                    else:
                        raise AssertionError("readiness failure must not become a successful launch")
                assert len(children) == 1 and children[0].returncode is not None


def test_semantic_unresolved_reap_never_reports_success() -> None:
    class UnreapableProcess:
        pid = 2_000_000_000
        returncode = None

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> None:
            del timeout
            raise subprocess.TimeoutExpired("fixture", 1.0)

        def kill(self) -> None:
            raise OSError("fixture process cannot be killed")

    def fake_popen(command, **kwargs):
        kwargs["stdout"].write(b"unresolved stdout")
        kwargs["stderr"].write(b"unresolved stderr")
        return UnreapableProcess()

    # A full-wrapper model, never an OS signal against an arbitrary fake PID.
    with tempfile.TemporaryDirectory() as temporary:
        with (
            patch.object(benchmark.subprocess, "Popen", fake_popen),
            patch.object(benchmark, "ProcSampler", side_effect=RuntimeError("injected sampler failure")),
            patch.object(benchmark.os, "killpg", side_effect=PermissionError("model signal refused"), create=True),
        ):
            try:
                benchmark._run_semantic_executable(Path("fixture"), "selector", 2.0, Path(temporary))
            except benchmark.SemanticExecutableError as error:
                assert error.terminal == "unresolved"
                assert error.returncode is None
                assert error.stdout == "unresolved stdout"
                assert error.stderr == "unresolved stderr"
            else:
                raise AssertionError("unknown child terminal state must never return success")


def test_percentiles_are_deterministic_and_interpolated() -> None:
    assert benchmark.percentile([10.0, 20.0, 30.0, 40.0], 0.50) == 25.0
    assert benchmark.percentile([10.0, 20.0, 30.0, 40.0], 0.95) == 38.5
    assert benchmark.summarize([10.0, 20.0, 30.0, 40.0]) == {
        "count": 4,
        "p50_ms": 25.0,
        "p95_ms": 38.5,
        "p99_ms": 39.7,
    }


def test_empty_percentile_is_explicitly_unavailable() -> None:
    assert benchmark.percentile([], 0.99) is None
    assert benchmark.summarize([]) == {"count": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None}


def test_finite_grant_and_localbroker_controls() -> None:
    class Args:
        runs = messages = payload_bytes = 1
        timeout = poll_interval = 1.0
        resource_grant = COMPLETE_GRANT
        daemon_arg = ["serve"]

    benchmark.validate(Args())
    Args.resource_grant = "unbounded"
    try:
        benchmark.validate(Args())
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("unbounded grants must be rejected")
    Args.resource_grant = COMPLETE_GRANT
    Args.daemon_arg = ["LocalBroker"]
    try:
        benchmark.validate(Args())
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("LocalBroker must be rejected")


def test_finite_grant_parser_requires_every_canonical_dimension() -> None:
    assert benchmark.parse_finite_grant(COMPLETE_GRANT) == {
        name: 1 for name in benchmark.GRANT_DIMENSIONS
    }
    for invalid in (
        COMPLETE_GRANT.replace("queued_bytes=1,", ""),
        COMPLETE_GRANT.replace("queued_bytes=1", "queued_bytes=-1"),
        f"{COMPLETE_GRANT},queued_bytes=2",
        f"{COMPLETE_GRANT},unknown=1",
    ):
        try:
            benchmark.parse_finite_grant(invalid)
        except benchmark.BenchmarkError:
            pass
        else:
            raise AssertionError(f"invalid finite grant accepted: {invalid}")


def test_semantic_metric_validation_requires_exact_provider_and_storage_shapes() -> None:
    metric = _scale_metric("semantic_ledger_scale_n_1k", 1_000)
    assert benchmark.validate_semantic_metric(metric, metric["selector"], 1_000) == metric
    malformed = dict(metric)
    malformed["provider_final"] = {"owner_active_candidates": 0}
    try:
        benchmark.validate_semantic_metric(malformed, metric["selector"], 1_000)
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("malformed provider metrics must be rejected")


def test_proof_metric_validation_requires_capacity_and_reopen_controls() -> None:
    metric = _proof_metric()
    assert benchmark.validate_semantic_metric(metric, metric["selector"], -1) == metric
    for field, value in (
        ("configured_max_database_bytes", False),
        ("reopened_exact_equality", False),
        ("reopened_pending_count", 12),
        ("reopened_terminal_count", True),
    ):
        malformed = dict(metric)
        malformed[field] = value
        try:
            benchmark.validate_semantic_metric(malformed, metric["selector"], -1)
        except benchmark.BenchmarkError:
            pass
        else:
            raise AssertionError(f"invalid proof field accepted: {field}={value!r}")
    missing = dict(metric)
    del missing["reopened_exact_equality"]
    try:
        benchmark.validate_semantic_metric(missing, metric["selector"], -1)
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("missing proof reopen field must be rejected")


def test_capacity_and_purge_metric_validation_is_fail_closed() -> None:
    capacity = _capacity_metric()
    bad_capacity = dict(capacity)
    bad_capacity["footprint"] = dict(capacity["footprint"])
    bad_capacity["footprint"]["B"] = 201
    try:
        benchmark.validate_semantic_metric(
            bad_capacity, benchmark.SEMANTIC_CAPACITY_SELECTOR, -2
        )
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("inconsistent capacity envelope must be rejected")

    purge = _purge_metric()
    bad_purge = dict(purge)
    bad_purge["terminal_baseline"] = dict(purge["terminal_baseline"])
    bad_purge["terminal_baseline"]["restarted_shutdown_ok"] = False
    try:
        benchmark.validate_semantic_metric(bad_purge, benchmark.SEMANTIC_PURGE_SELECTOR, -3)
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("unclean purge terminal baseline must be rejected")


def test_semantic_ledger_runs_exact_ignored_cases_and_records_identity() -> None:
    scale_metrics = {
        selector: _scale_metric(selector, scale)
        for _, selector, scale, _ in benchmark.SEMANTIC_LEDGER_CASES
        if scale is not None and scale > 0
    }
    metrics = {
        **scale_metrics,
        "semantic_ledger_scale_open_presence_zero": _open_metric(),
        benchmark.SEMANTIC_PROOF_SELECTOR: _proof_metric(),
        benchmark.SEMANTIC_CAPACITY_SELECTOR: _capacity_metric(),
        benchmark.SEMANTIC_PURGE_SELECTOR: _purge_metric(),
        benchmark.SEMANTIC_HANDSHAKE_SELECTOR: {
            "selector": benchmark.SEMANTIC_HANDSHAKE_SELECTOR,
            "evidence": f"test {benchmark.SEMANTIC_HANDSHAKE_SELECTOR} ... ok",
        },
        benchmark.SEMANTIC_ROUTE_SELECTOR: {
            "selector": benchmark.SEMANTIC_ROUTE_SELECTOR,
            "evidence": f"test {benchmark.SEMANTIC_ROUTE_SELECTOR} ... ok",
        },
    }
    calls: list[list[str]] = []
    scale_calls: list[str] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["capture_output"] is True
        if "--no-run" in command:
            artifact = {
                "reason": "compiler-artifact",
                "target": {"name": "semantic_ledger_scale", "kind": ["test"]},
                "profile": {"test": True},
                "executable": str(Path(__file__)),
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(artifact), "")
        selector = command[command.index("--exact") + 1]
        if selector in (benchmark.SEMANTIC_HANDSHAKE_SELECTOR, benchmark.SEMANTIC_ROUTE_SELECTOR):
            metric_line = f"test {selector} ... ok\n"
            metric_line += "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        elif selector == benchmark.SEMANTIC_CAPACITY_SELECTOR:
            metric_line = (
                f"test {selector} ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
                + json.dumps(metrics[selector]["footprint"])
                + "\n"
                + json.dumps(metrics[selector]["terminal"])
            )
        else:
            metric_line = (
                f"test {selector} ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
                + (
                    benchmark.SEMANTIC_PREFIXES[selector] + " "
                    if selector in benchmark.SEMANTIC_PREFIXES
                    else ""
                )
                + json.dumps(metrics[selector])
            )
        return subprocess.CompletedProcess(command, 0, metric_line + "\n", "")

    args = Namespace(
        mode="semantic-ledger",
        semantic_timeout=10.0,
        semantic_max_wall_ms=10.0,
        semantic_max_rss_bytes=10,
        semantic_max_disk_bytes=19,
        semantic_max_matched_tail_total_ms_per_ledger_fact=1.0,
        repo_root=Path(__file__).parents[2],
    )
    with tempfile.TemporaryDirectory() as temporary:
        artifact_dir = Path(temporary)
        def fake_scale(*args: object, **kwargs: object) -> tuple[str, str, float, dict[str, object], int]:
            del kwargs
            selector = args[1]
            scale_calls.append(selector)
            output = (
                f"test {selector} ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
                + json.dumps(metrics[selector])
            )
            return output, "", 1.0, {"peak_rss_bytes": {"semantic_ledger_scale": 1}}, 0

        with (
            patch.object(benchmark.subprocess, "run", fake_run),
            patch.object(benchmark, "_run_semantic_executable", fake_scale),
        ):
            manifest = benchmark.run_semantic_ledger(args, artifact_dir)
        assert (artifact_dir / "semantic-ledger.json").is_file()

    case_calls = [command for command in calls if "--no-run" not in command]
    assert [command[command.index("--exact") + 1] for command in case_calls] == [
        benchmark.SEMANTIC_PROOF_SELECTOR,
        benchmark.SEMANTIC_CAPACITY_SELECTOR,
        benchmark.SEMANTIC_PURGE_SELECTOR,
        benchmark.SEMANTIC_HANDSHAKE_SELECTOR,
        benchmark.SEMANTIC_ROUTE_SELECTOR,
    ]
    assert any("--no-run" in command for command in calls)
    assert any(command[command.index("-p") + 1] == "myownmesh-core" for command in calls)
    assert any(command[command.index("-p") + 1] == "myownmesh" for command in calls)
    expected_executable_calls = [
        selector for target, selector, _, _ in benchmark.SEMANTIC_LEDGER_CASES
        if target == "semantic_ledger_scale"
    ]
    assert scale_calls == expected_executable_calls
    ignored_selectors = {
        "semantic_ledger_scale_n_1k",
        "semantic_ledger_scale_n_10k",
        "semantic_ledger_scale_n_100k",
        "semantic_ledger_scale_open_presence_zero",
        benchmark.SEMANTIC_PURGE_SELECTOR,
    }
    assert all(
        ("--ignored" in command) == (command[command.index("--exact") + 1] in ignored_selectors)
        and "--exact" in command
        for command in calls
        if "--no-run" not in command
    )
    assert manifest["claims"] == {
        "capacity_or_slo": False,
        "budget_gates_enforced": True,
        "reported_curves_only": False,
        "exact_no_churn_assertions": True,
    }
    assert {entry["selector"] for entry in manifest["cases"]} == set(metrics)
    assert len(manifest["source_identity"]) == 7
    assert all(len(entry["sha256"]) == 64 for entry in manifest["source_identity"])
    assert all(entry["returncode"] == 0 and entry["elapsed_ms"] >= 0 for entry in manifest["cases"])
    assert all(len(entry["output_sha256"]) == 64 for entry in manifest["cases"])


def test_semantic_ledger_fails_closed_on_nonzero_case() -> None:
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(command, 17, "", "fixture failure")

    args = Namespace(mode="semantic-ledger", semantic_timeout=1.0, repo_root=Path(__file__).parents[2])
    with tempfile.TemporaryDirectory() as temporary:
        artifact_dir = Path(temporary)
        with patch.object(benchmark.subprocess, "run", fake_run):
            try:
                benchmark.run_semantic_ledger(args, artifact_dir)
            except benchmark.BenchmarkError as error:
                assert "semantic release build exited 17" in str(error)
            else:
                raise AssertionError("nonzero semantic case must fail closed")
        assert not (artifact_dir / "semantic-ledger.json").exists()


def test_run_once_uses_public_control_direction_repeats_and_cleans_up() -> None:
    class FakeProcess:
        next_pid = 50000

        def __init__(self) -> None:
            self.pid = FakeProcess.next_pid
            FakeProcess.next_pid += 1
            self.returncode = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float) -> int:
            del timeout
            self.returncode = 0
            return self.returncode

    class FakeSampler:
        instances: list["FakeSampler"] = []

        def __init__(self, processes: dict[str, FakeProcess]) -> None:
            self.processes = processes
            self.phases: list[str] = []
            FakeSampler.instances.append(self)

        def sample(self, phase: str) -> None:
            self.phases.append(phase)

        def result(self) -> dict[str, object]:
            return {
                "available": False,
                "method": None,
                "cpu_metric": None,
                "peak_rss_bytes": {name: None for name in self.processes},
                "cumulative_cpu_seconds": {name: None for name in self.processes},
                "samples": self.phases,
            }

    class Closable:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    processes: list[FakeProcess] = []
    requests: list[tuple[str, dict[str, object]]] = []
    sent_payloads: list[dict[str, object]] = []
    active_network = ""
    event_stream = Closable()
    event_reader = Closable()

    def fake_popen(*args: object, **kwargs: object) -> FakeProcess:
        del args, kwargs
        process = FakeProcess()
        processes.append(process)
        return process

    def fake_request(control_socket: Path, body: dict[str, object], timeout: float) -> dict[str, object]:
        nonlocal active_network
        del timeout
        requests.append((str(control_socket), body))
        if body["op"] == "peers_list":
            is_a = "home-a" in str(control_socket)
            remote = "device-b" if is_a else "device-a"
            return {"ok": True, "data": {"peers": [{"device_id": remote, "status": "active", "authenticated": True}]}}
        if body["op"] == "channel_send_reliable":
            active_network = str(body["network"])
            sent_payloads.append(body["payload"])
        return {"ok": True, "data": {}}

    def fake_read_event(*args: object, **kwargs: object) -> tuple[dict[str, object], float]:
        del args, kwargs
        payload = sent_payloads[-1]
        return {
            "kind": "channel_inbound",
            "network": active_network,
            "channel": benchmark.CHANNEL,
            "from": "device-a",
            "payload": payload,
        }, 0.001

    class Args(Namespace):
        runs = 1
        messages = 3
        payload_bytes = 8
        timeout = 1.0
        poll_interval = 0.001
        resource_grant = COMPLETE_GRANT
        connector_realtime_policy = "disabled"
        daemon_arg = ["serve"]

    with tempfile.TemporaryDirectory() as temporary:
        run_dir = Path(temporary)
        with (
            patch.object(benchmark.subprocess, "Popen", fake_popen),
            patch.object(benchmark, "ProcSampler", FakeSampler),
            patch.object(benchmark, "request", fake_request),
            patch.object(benchmark, "open_events", lambda *args: (event_stream, event_reader, "c1", "cap")),
            patch.object(benchmark, "read_event", fake_read_event),
            patch.object(benchmark.os, "killpg", create=True),
        ):
            result = benchmark.run_once(Args(), run_dir, Path("shipped"), 1)

    assert len(processes) == 2
    assert len(sent_payloads) == 3
    send_requests = [body for _, body in requests if body["op"] == "channel_send_reliable"]
    assert all(body["peer"] == "device-b" for body in send_requests)
    assert all(message["event"]["from"] == "device-a" for message in result["messages"])
    assert set(result["terminals"]) == {"a", "b"}
    assert result["clean_terminal"] is True
    assert set(result["timings_ms_by_daemon"]) == {"a", "b"}
    assert all(
        set(timings) == {"control_ready", "discovery", "promotion"}
        for timings in result["timings_ms_by_daemon"].values()
    )
    assert "pre-terminate" in FakeSampler.instances[0].phases
    assert event_stream.closed and event_reader.closed
