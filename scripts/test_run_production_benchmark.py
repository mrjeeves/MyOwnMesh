import json
import json
import tempfile
import unittest
from argparse import Namespace
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


SCRIPT = Path(__file__).with_name("run-production-benchmark.py")
SPEC = spec_from_file_location("run_production_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class BenchmarkRunnerTests(unittest.TestCase):
    def test_scale_cases_include_required_high_water_marks(self) -> None:
        scales = {
            scale
            for target, selector, scale, ignored in BENCHMARK.SEMANTIC_LEDGER_CASES
            if target == "semantic_ledger_scale"
        }
        self.assertTrue({1_000, 10_000, 100_000, 250_000, 500_000, 1_000_000} <= scales)

    def test_test_success_rejects_zero_and_duplicate_evidence(self) -> None:
        good = "test semantic_ledger_scale_n_250k ... ok\n" "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out\n"
        BENCHMARK._require_test_success(good, "semantic_ledger_scale_n_250k")
        with self.assertRaises(BENCHMARK.BenchmarkError):
            BENCHMARK._require_test_success(
                "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out\n",
                "semantic_ledger_scale_n_250k",
            )
        with self.assertRaises(BENCHMARK.BenchmarkError):
            BENCHMARK._require_test_success(
                good + "test semantic_ledger_scale_n_250k ... ok\n",
                "semantic_ledger_scale_n_250k",
            )

    def test_release_artifact_discovery_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "semantic_ledger_scale"
            executable.write_bytes(b"test executable")
            message = {
                "reason": "compiler-artifact",
                "target": {"name": "semantic_ledger_scale", "kind": ["test"]},
                "profile": {"test": True},
                "executable": str(executable),
            }
            self.assertEqual(BENCHMARK._discover_semantic_executable(json.dumps(message)), executable.resolve())

    def test_semantic_budgets_are_required_and_strict(self) -> None:
        valid = Namespace(
            semantic_max_wall_ms=1.0,
            semantic_max_rss_bytes=1,
            semantic_max_disk_bytes=1,
            semantic_max_matched_tail_total_ms_per_ledger_fact=1.0,
        )
        BENCHMARK._validate_semantic_budgets(valid)
        invalid = Namespace(
            semantic_max_wall_ms=None,
            semantic_max_rss_bytes=1,
            semantic_max_disk_bytes=1,
            semantic_max_matched_tail_total_ms_per_ledger_fact=1.0,
        )
        with self.assertRaises(BENCHMARK.BenchmarkError):
            BENCHMARK._validate_semantic_budgets(invalid)

    def test_legacy_slope_budget_is_rejected_before_launch(self) -> None:
        legacy = Namespace(
            semantic_max_wall_ms=1.0,
            semantic_max_rss_bytes=1,
            semantic_max_disk_bytes=1,
            semantic_max_marginal_slope_ms_per_fact=1.0,
            semantic_max_matched_tail_total_ms_per_ledger_fact=1.0,
        )
        with self.assertRaises(BENCHMARK.BenchmarkError):
            BENCHMARK._validate_semantic_budgets(legacy)

    def test_scale_schema_requires_frozen_latency_and_cache_fields(self) -> None:
        self.assertIn("admission_end_to_end_total_ms", BENCHMARK.SEMANTIC_SCALE_FIELDS)
        self.assertIn("admission_p99_ms", BENCHMARK.SEMANTIC_SCALE_FIELDS)
        self.assertIn("admissions_per_sec", BENCHMARK.SEMANTIC_SCALE_FIELDS)
        self.assertIn("seeded_admissions", BENCHMARK.SEMANTIC_SCALE_FIELDS)
        self.assertIn("timed_admissions", BENCHMARK.SEMANTIC_SCALE_FIELDS)
        self.assertIn("seed_total_ms", BENCHMARK.SEMANTIC_SCALE_FIELDS)
        self.assertIn("window_evidence", BENCHMARK.SEMANTIC_SCALE_FIELDS)
        self.assertNotIn("delta_write_total_ms", BENCHMARK.SEMANTIC_SCALE_FIELDS)
        self.assertEqual(BENCHMARK.SEMANTIC_CACHE_STATE, "mixed_process_cache_no_flush")
        with self.assertRaises(BENCHMARK.BenchmarkError):
            BENCHMARK._finite_positive(0.0, "p99")

    def test_optional_platform_counters_are_explicitly_supported_or_unsupported(self) -> None:
        unsupported = {"platform": "windows"}
        unsupported.update({field: None for field in BENCHMARK.SEMANTIC_OPTIONAL_SCALE_COUNTERS})
        BENCHMARK._validate_scale_optional_counters(unsupported, "windows-scale")
        linux = {"platform": "linux"}
        linux.update({field: None for field in BENCHMARK.SEMANTIC_OPTIONAL_SCALE_COUNTERS})
        with self.assertRaises(BENCHMARK.BenchmarkError):
            BENCHMARK._validate_scale_optional_counters(linux, "linux-scale")
        linux.update(
            {
                "process_scope_cpu_time_ms": 1.0,
                "process_scope_read_bytes_delta": 2,
                "process_lifetime_peak_vmhwm_bytes": 3,
                "process_rss_after_seed_bytes": 4,
                "process_rss_after_workload_bytes": 5,
                "process_rss_after_compaction_bytes": 6,
                "process_rss_after_restore_bytes": 7,
                "process_scope_write_bytes_delta": 8,
                "process_scope_write_bytes_per_admission": 9.0,
            }
        )
        BENCHMARK._validate_scale_optional_counters(linux, "linux-scale")


if __name__ == "__main__":
    unittest.main()
