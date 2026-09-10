from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import sys
from types import SimpleNamespace
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "run-process-resource-e2e.py"
SPEC = importlib.util.spec_from_file_location("run_process_resource_e2e", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def complete_grant() -> str:
    return ",".join(f"{name}=100" for name in runner.GRANT_DIMENSIONS)


class ProcessResourceE2EControls(unittest.TestCase):
    def test_grant_requires_every_finite_owner_dimension(self) -> None:
        values = runner.validate_grant(complete_grant())
        self.assertEqual(set(values), set(runner.GRANT_DIMENSIONS))
        self.assertEqual(values["worker_or_task"], 100)

    def test_grant_rejects_unbounded_duplicate_missing_and_negative(self) -> None:
        with self.assertRaises(runner.ContractError):
            runner.validate_grant("unbounded")
        with self.assertRaises(runner.ContractError):
            runner.validate_grant(complete_grant() + ",worker_or_task=101")
        with self.assertRaises(runner.ContractError):
            runner.validate_grant("accounted_memory_bytes=1")
        with self.assertRaises(runner.ContractError):
            runner.validate_grant(complete_grant().replace("worker_or_task=100", "worker_or_task=-1"))

    def test_grant_accepts_u64_maximum_and_rejects_overflow(self) -> None:
        maximum = str(runner.U64_MAX)
        values = runner.validate_grant(complete_grant().replace("worker_or_task=100", f"worker_or_task={maximum}"))
        self.assertEqual(values["worker_or_task"], runner.U64_MAX)
        with self.assertRaises(runner.ContractError):
            runner.validate_grant(
                complete_grant().replace("worker_or_task=100", f"worker_or_task={runner.U64_MAX + 1}")
            )

    def test_args_reject_nonfinite_floats_and_payload_u64_overflow(self) -> None:
        base = SimpleNamespace(
            timeout=1.0,
            poll_interval=0.1,
            payload_bytes=1,
            binary=pathlib.Path(sys.executable),
            resource_grant=complete_grant(),
        )
        self.assertEqual(runner.validate_args(base)["worker_or_task"], 100)
        for field in ("timeout", "poll_interval"):
            for value in (float("nan"), float("inf"), float("-inf")):
                invalid = SimpleNamespace(**vars(base))
                setattr(invalid, field, value)
                with self.assertRaises(runner.ContractError):
                    runner.validate_args(invalid)
        maximum = SimpleNamespace(**vars(base))
        maximum.payload_bytes = runner.U64_MAX
        self.assertEqual(runner.validate_args(maximum)["worker_or_task"], 100)
        overflow = SimpleNamespace(**vars(base))
        overflow.payload_bytes = runner.U64_MAX + 1
        with self.assertRaises(runner.ContractError):
            runner.validate_args(overflow)

    def test_linux_proc_parser_handles_parenthesis_in_command_name(self) -> None:
        raw = "123 (name with ) paren) S 77 0 0 0 0 0 0 0 0 0 11 13"
        self.assertEqual(runner.parse_proc_stat(raw), (77, 11, 13))

    @unittest.skipUnless(os.name == "posix", "the exact /proc probe is Unix-only")
    def test_linux_proc_snapshot_is_real_and_nonzero_for_this_process(self) -> None:
        if not runner.ProcessSampler({}).linux:
            self.skipTest("Linux /proc metrics are unavailable")
        page_size = os.sysconf("SC_PAGE_SIZE")
        clock_ticks = os.sysconf("SC_CLK_TCK")
        snapshot = runner.linux_process_snapshot(os.getpid(), page_size, clock_ticks)
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot["pid"], os.getpid())
        self.assertGreaterEqual(snapshot["thread_count"], 1)
        self.assertGreaterEqual(snapshot["fd_count"], 1)
        self.assertGreaterEqual(snapshot["rss_bytes"], 1)

    def test_process_sampler_does_not_turn_unavailable_metrics_into_zero(self) -> None:
        class FinishedProcess:
            pid = 2**31 - 1

            @staticmethod
            def poll() -> int:
                return 0

        sampler = runner.ProcessSampler({"fake": FinishedProcess()})
        sampler.sample("terminal")
        record = sampler.samples[0]["processes"]["fake"]
        if sampler.linux:
            self.assertIsNone(record["rss_bytes"])
            self.assertIsNone(record["thread_count"])
            self.assertIsNone(record["fd_count"])
        else:
            self.assertIsNone(record["tree_pids"])
            self.assertIsNone(record["rss_bytes"])
            self.assertIsNone(record["thread_count"])
            self.assertIsNone(record["fd_count"])

    def test_process_sampler_labels_cpu_as_cumulative(self) -> None:
        class FinishedProcess:
            pid = 2**31 - 1

            @staticmethod
            def poll() -> int:
                return 0

        sampler = runner.ProcessSampler({"fake": FinishedProcess()})
        sampler.sample("terminal")
        record = sampler.samples[0]["processes"]["fake"]
        self.assertIn("cumulative_cpu_seconds", record)
        self.assertNotIn("peak_cpu_seconds", record)
        self.assertIn("cumulative_cpu_seconds", sampler.result())
        self.assertNotIn("peak_cpu_seconds", sampler.result())

    def test_aggregate_summary_preserves_null_metrics_and_phase_epoch(self) -> None:
        cycles = [
            {
                "clean_terminal": True,
                "workload": {"channel_supported": False},
                "duration_seconds": 1.5,
                "phase_timings": {
                    "a": {"ready": {"duration_seconds": 0.25}},
                    "b": {"ready": {"duration_seconds": None}},
                },
                "process": {
                    "peak_rss_bytes": {"a": None, "b": 10},
                    "cumulative_cpu_seconds": {"a": None, "b": 0.5},
                },
            }
        ]
        summary = runner.aggregate_cycles(cycles, "epoch-1")
        self.assertEqual(summary["run_epoch"], "epoch-1")
        self.assertIsNone(summary["daemon_metrics"]["a"]["peak_rss_bytes_max"])
        self.assertIsNone(summary["daemon_metrics"]["a"]["cumulative_cpu_seconds_max"])
        self.assertEqual(summary["daemon_metrics"]["b"]["peak_rss_bytes_max"], 10)
        self.assertIsNone(summary["phase_timings"]["b"]["ready"]["average_seconds"])

    def test_aggregate_summary_reports_payload_and_throughput_without_fabrication(self) -> None:
        summary = runner.aggregate_cycles(
            [
                {
                    "workload": {
                        "payload_bytes": 12,
                        "throughput_bytes_per_second": 6.0,
                    },
                    "process": {},
                },
                {"workload": {}, "process": {}},
            ],
            "epoch-2",
        )
        self.assertEqual(summary["payload_bytes_by_cycle"], [12, None])
        self.assertEqual(summary["payload_bytes_total"], 12)
        self.assertEqual(summary["throughput_bytes_per_second_average"], 6.0)

    def test_failed_cycle_result_is_recorded_before_error_reaches_caller(self) -> None:
        manifest: dict[str, object] = {"cycles": []}
        result = {
            "cycle": 1,
            "terminals": {"a": {"returncode": 1, "forced": False}},
            "clean_terminal": False,
            "cleanup_errors": [],
        }

        def failed_lifecycle() -> dict[str, object]:
            raise runner.LifecycleError("injected terminal failure", result)

        with self.assertRaises(runner.LifecycleError):
            runner.run_and_record_cycle(manifest, failed_lifecycle)
        self.assertEqual(manifest["cycles"], [result])

    def test_cleanup_error_cannot_be_reported_as_clean_terminal(self) -> None:
        terminals = {"a": {"returncode": 0, "forced": False}}
        self.assertTrue(runner.terminal_is_clean(terminals, [], 1))
        self.assertFalse(runner.terminal_is_clean(terminals, ["stderr: injected close failure"], 1))

    def test_termination_attempts_each_daemon_after_one_failure(self) -> None:
        class FakeProcess:
            def __init__(self, pid: int, fail: bool = False) -> None:
                self.pid = pid
                self.fail = fail
                self.returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float) -> int:
                if self.fail:
                    raise RuntimeError("injected wait failure")
                self.returncode = 0
                return 0

            def terminate(self) -> None:
                self.returncode = 0

            def send_signal(self, _signal: int) -> None:
                return None

        first = FakeProcess(2**31 - 2, fail=True)
        second = FakeProcess(2**31 - 3)
        terminals = runner.terminate_processes({"a": first, "b": second}, 0.01)
        self.assertIn("a", terminals)
        self.assertIn("b", terminals)
        self.assertIn("error", terminals["a"])
        self.assertEqual(terminals["b"]["returncode"], 0)

    def test_log_cleanup_closes_stdout_and_stderr(self) -> None:
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        self.assertEqual(runner.close_logs({"a": (stdout, stderr)}), [])
        self.assertTrue(stdout.closed)
        self.assertTrue(stderr.closed)

    def test_log_cleanup_records_close_failure_and_continues(self) -> None:
        class FailingStream:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True
                raise OSError("injected close failure")

        stdout = FailingStream()
        stderr = io.BytesIO()
        errors = runner.close_logs({"a": (stdout, stderr)})
        self.assertEqual(len(errors), 1)
        self.assertTrue(stdout.closed)
        self.assertTrue(stderr.closed)

    def test_workload_has_distinct_direction_and_repeat_identity(self) -> None:
        payload, direction, repeat = runner.workload_payload(
            "net", 2, "epoch-1", "sender", "recipient", 4
        )
        self.assertEqual(direction, "a-to-b")
        self.assertEqual(repeat, "epoch-1:net:2:a-to-b")
        self.assertEqual(payload["sender_identity"], "sender")
        self.assertEqual(payload["recipient_identity"], "recipient")
        self.assertEqual(payload["direction"], direction)
        with self.assertRaises(runner.ContractError):
            runner.workload_payload("net", 2, "epoch-1", "same", "same", 4)

    def test_config_is_production_mdns_and_not_localbroker(self) -> None:
        config = runner.daemon_config("e2e123")
        network = config["networks"][0]
        self.assertTrue(network["signaling"]["mdns"])
        self.assertEqual(network["signaling"]["strategy"], "none")
        self.assertNotIn("LocalBroker", jsonish(config))

    def test_status_contract_preserves_shipped_resource_liveness_fields(self) -> None:
        response = {
            "ok": True,
            "data": {
                "version": "4.0.0",
                "device_id": "device-a",
                "joined_networks": ["e2e123"],
                "realtime": {},
            },
        }
        self.assertEqual(runner.validate_status(response, "a"), response["data"])
        with self.assertRaises(runner.ContractError):
            runner.validate_status({"ok": True, "data": {"device_id": "device-a"}}, "a")


def jsonish(value: object) -> str:
    return repr(value).lower()


if __name__ == "__main__":
    unittest.main()
