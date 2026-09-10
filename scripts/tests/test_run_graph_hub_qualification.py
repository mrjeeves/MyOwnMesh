import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "run-graph-hub-qualification.py"
SPEC = importlib.util.spec_from_file_location("run_graph_hub_qualification", MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(runner)


def complete_spec():
    groups = {
        ("myownmesh-core", "lib", "myownmesh_core"): [
            "semantic::causal::tests::one",
            "engine::parenting::tests::two",
        ],
        ("myownmesh", "bin", "myownmesh"): ["registry::tests::three"],
        ("myownmesh-core", "integration", "hub_tree_routing"): ["four"],
    }
    cells = []
    ordinal = 0
    for (package, kind, target), selectors in sorted(groups.items()):
        for selector in selectors:
            cells.append(
                {
                    "id": f"cell-{ordinal}",
                    "package": package,
                    "target_kind": kind,
                    "target_name": target,
                    "selectors": [selector],
                    "expected_running": 1,
                    "expected_summary": {
                        "passed": 1,
                        "failed": 0,
                        "ignored": 0,
                        "measured": 0,
                    },
                    "timeout_seconds": 30,
                }
            )
            ordinal += 1
    return {
        "schema_version": 1,
        "expected_head": "a" * 40,
        "expected_ref": "candidate",
        "build_timeout_seconds": 60,
        "max_output_bytes": runner.MIN_CAPTURE_BYTES,
        "acceptance_contract": {
            "path": "docs/qualification/graph-hub-acceptance-contract.md",
            "sha256": "b" * 64,
        },
        "required_selectors": [
            {
                "package": package,
                "target_kind": kind,
                "target_name": target,
                "selector": selector,
            }
            for (package, kind, target), selectors in groups.items()
            for selector in selectors
        ],
        "cells": cells,
    }


class ManifestControls(unittest.TestCase):
    def test_manager_owned_required_manifest_is_accepted(self):
        cells = runner.validate_spec(complete_spec())
        self.assertGreater(len(cells), 1)
        self.assertTrue(all(cell["selectors"] for cell in cells))

    def test_missing_recipe_selector_is_rejected(self):
        spec = complete_spec()
        spec["cells"].pop()
        with self.assertRaisesRegex(runner.QualificationError, "omits 1 manager-required"):
            runner.validate_spec(spec)

    def test_required_selector_list_cannot_be_empty_or_duplicate(self):
        spec = complete_spec()
        spec["required_selectors"] = []
        with self.assertRaisesRegex(runner.QualificationError, "nonempty manager-owned"):
            runner.validate_spec(spec)
        spec = complete_spec()
        spec["required_selectors"].append(dict(spec["required_selectors"][0]))
        with self.assertRaisesRegex(runner.QualificationError, "duplicate required"):
            runner.validate_spec(spec)

    def test_zero_expected_tests_and_implicit_target_sweep_are_rejected(self):
        spec = complete_spec()
        spec["cells"][0]["expected_running"] = 0
        with self.assertRaisesRegex(runner.QualificationError, "expected_running"):
            runner.validate_spec(spec)
        spec = complete_spec()
        spec["cells"][0]["selectors"] = []
        with self.assertRaisesRegex(runner.QualificationError, "explicit nonempty"):
            runner.validate_spec(spec)

    def test_each_cell_has_one_exact_selector_and_one_expected_test(self):
        spec = complete_spec()
        spec["cells"][0]["selectors"].append("another::exact::selector")
        with self.assertRaisesRegex(runner.QualificationError, "exactly one exact selector"):
            runner.validate_spec(spec)
        spec = complete_spec()
        spec["cells"][0]["expected_running"] = 2
        spec["cells"][0]["expected_summary"]["passed"] = 2
        with self.assertRaisesRegex(runner.QualificationError, "one running test"):
            runner.validate_spec(spec)

    def test_dependencies_must_be_unique_earlier_cells(self):
        spec = complete_spec()
        spec["cells"][0]["depends_on"] = [spec["cells"][1]["id"]]
        with self.assertRaisesRegex(runner.QualificationError, "earlier cells"):
            runner.validate_spec(spec)
        spec = complete_spec()
        first = spec["cells"][0]["id"]
        spec["cells"][1]["depends_on"] = [first, first]
        with self.assertRaisesRegex(runner.QualificationError, "earlier cells"):
            runner.validate_spec(spec)

    def test_selector_cannot_repeat_in_another_cell(self):
        spec = complete_spec()
        clone = dict(spec["cells"][0])
        clone["id"] = "duplicate-cell"
        spec["cells"].append(clone)
        with self.assertRaisesRegex(runner.QualificationError, "repeats an earlier cell"):
            runner.validate_spec(spec)


class CargoArtifactControls(unittest.TestCase):
    def test_build_command_is_one_locked_workspace_transport_lab_build(self):
        self.assertEqual(
            runner.build_command("cargo"),
            [
                "cargo",
                "build",
                "--locked",
                "--workspace",
                "--all-targets",
                "--tests",
                "--features",
                "transport-lab",
                "--keep-going",
                "--message-format=json-render-diagnostics",
            ],
        )

    def test_collector_distinguishes_lib_bin_and_integration_targets(self):
        collector = runner.CargoArtifactCollector()
        fixtures = [
            ("myownmesh-core", ["lib"], "myownmesh_core", "core-test"),
            ("myownmesh", ["bin"], "myownmesh", "daemon-test"),
            ("myownmesh-core", ["test"], "hub_tree_routing", "hub-test"),
        ]
        for package, kinds, name, executable in fixtures:
            collector.feed(
                json.dumps(
                    {
                        "reason": "compiler-artifact",
                        "package_id": f"path+file:///repo/{package}#{package}@0.3.2",
                        "target": {"kind": kinds, "name": name},
                        "profile": {"test": True},
                        "executable": executable,
                    }
                )
            )
        self.assertEqual(
            set(collector.executables),
            {
                ("myownmesh-core", "lib", "myownmesh_core"),
                ("myownmesh", "bin", "myownmesh"),
                ("myownmesh-core", "integration", "hub_tree_routing"),
            },
        )
        self.assertEqual(collector.errors, [])

    def test_non_json_cargo_stdout_is_not_silently_accepted(self):
        collector = runner.CargoArtifactCollector()
        collector.feed("not Cargo JSON\n")
        self.assertEqual(len(collector.errors), 1)


class NativeSummaryControls(unittest.TestCase):
    def test_crlf_summary_and_exact_count_are_parsed(self):
        parsed = runner.parse_test_result(
            "running 2 tests\r\n"
            "test a ... ok\r\ntest b ... ok\r\n"
            "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.01s\r\n"
        )
        self.assertEqual(parsed["running"], 2)
        self.assertEqual(parsed["passed"], 2)
        self.assertEqual(parsed["filtered_out"], 7)

    def test_zero_match_exit_zero_is_not_a_pass(self):
        cell = {
            "expected_running": 1,
            "expected_summary": {"passed": 1, "failed": 0, "ignored": 0, "measured": 0},
        }
        capture = {
            "terminal": "exited",
            "exit_code": 0,
            "stdout": (
                "running 0 tests\n"
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out\n"
            ),
            "stderr": "",
        }
        passed, actual = runner.evaluate_capture(capture, cell)
        self.assertFalse(passed)
        self.assertEqual(actual["running"], 0)

    def test_nonzero_exit_retains_complete_native_failure_summary(self):
        cell = {
            "expected_running": 1,
            "expected_summary": {"passed": 1, "failed": 0, "ignored": 0, "measured": 0},
        }
        capture = {
            "terminal": "exited",
            "exit_code": 101,
            "stdout": (
                "running 1 test\n"
                "test failed_control ... FAILED\n"
                "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out\n"
            ),
            "stderr": "failure detail\n",
        }
        passed, actual = runner.evaluate_capture(capture, cell)
        self.assertFalse(passed)
        self.assertEqual(actual["status"], "FAILED")
        self.assertEqual(actual["failed"], 1)

    def test_expected_negative_stderr_does_not_override_native_pass(self):
        cell = {
            "expected_running": 1,
            "expected_summary": {"passed": 1, "failed": 0, "ignored": 0, "measured": 0},
        }
        capture = {
            "terminal": "exited",
            "exit_code": 0,
            "stdout": (
                "running 1 test\n"
                "test expected_panic ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
            ),
            "stderr": "thread panicked at expected negative control\n",
        }
        passed, actual = runner.evaluate_capture(capture, cell)
        self.assertTrue(passed)
        self.assertEqual(actual["status"], "ok")

    def test_missing_or_multiple_native_summaries_are_rejected(self):
        with self.assertRaises(runner.QualificationError):
            runner.parse_test_result("running 1 test\n")
        duplicated = (
            "running 1 test\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        ) * 2
        with self.assertRaises(runner.QualificationError):
            runner.parse_test_result(duplicated)


class MatrixExecutionControls(unittest.TestCase):
    @staticmethod
    def _capture(exit_code, stdout=""):
        return {
            "command": [],
            "started_at": "start",
            "completed_at": "end",
            "elapsed_seconds": 0.01,
            "exit_code": exit_code,
            "terminal": "exited",
            "callback_errors": [],
            "stdout": stdout,
            "stderr": "expected negative marker\n",
            "stdout_bytes": len(stdout),
            "stderr_bytes": 25,
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    def test_one_build_then_all_independent_cells_run_after_failure(self):
        spec = complete_spec()
        source = {
            "head": "a" * 40,
            "ref": "candidate",
            "sha256": "c" * 64,
            "files": [
                {
                    "path": spec["acceptance_contract"]["path"],
                    "kind": "file",
                    "sha256": spec["acceptance_contract"]["sha256"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = {}
            for cell in spec["cells"]:
                path = root / f"{cell['id']}.test"
                path.write_bytes(cell["id"].encode())
                binaries[(cell["package"], cell["target_kind"], cell["target_name"])] = path
            runtime_commands = []

            def fake_run(command, cwd, timeout, limit, stdout_callback=None):
                if stdout_callback is not None:
                    for (package, kind, target), path in binaries.items():
                        cargo_kind = "test" if kind == "integration" else kind
                        stdout_callback(
                            json.dumps(
                                {
                                    "reason": "compiler-artifact",
                                    "package_id": f"path+file:///repo/{package}#{package}@0.3.2",
                                    "target": {"kind": [cargo_kind], "name": target},
                                    "profile": {"test": True},
                                    "executable": str(path),
                                }
                            )
                        )
                    return self._capture(0)
                runtime_commands.append(command)
                cell = next(cell for cell in spec["cells"] if command[0].endswith(f"{cell['id']}.test"))
                if len(runtime_commands) == 1:
                    return self._capture(
                        101,
                        f"running {cell['expected_running']} tests\n"
                        f"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n",
                    )
                count = cell["expected_running"]
                return self._capture(
                    0,
                    f"running {count} tests\n"
                    f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
                )

            with mock.patch.object(runner, "source_manifest", return_value=source), mock.patch.object(
                runner, "run_captured", side_effect=fake_run
            ):
                report, exit_code = runner.run_qualification(root, spec, "cargo")
            self.assertEqual(exit_code, 1)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(len(runtime_commands), len(spec["cells"]))
            self.assertEqual(report["cells"][0]["status"], "failed")
            self.assertTrue(all(cell["status"] == "passed" for cell in report["cells"][1:]))

    def test_unknown_build_starts_no_later_process_or_custody_probe(self):
        spec = complete_spec()
        source = {
            "head": "a" * 40,
            "ref": "candidate",
            "sha256": "c" * 64,
            "files": [
                {
                    "path": spec["acceptance_contract"]["path"],
                    "kind": "file",
                    "sha256": spec["acceptance_contract"]["sha256"],
                }
            ],
        }
        unknown = self._capture(None)
        unknown["terminal"] = "outcome_unknown"
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            runner, "source_manifest", return_value=source
        ) as manifest_probe, mock.patch.object(
            runner, "run_captured", return_value=unknown
        ) as spawn:
            report, exit_code = runner.run_qualification(Path(directory), spec, "cargo")
        self.assertEqual(exit_code, 2)
        self.assertEqual(report["status"], "outcome_unknown")
        self.assertEqual(spawn.call_count, 1)
        self.assertEqual(manifest_probe.call_count, 1)

    def test_unknown_runtime_starts_no_later_cell_or_custody_probe(self):
        spec = complete_spec()
        source = {
            "head": "a" * 40,
            "ref": "candidate",
            "sha256": "c" * 64,
            "files": [
                {
                    "path": spec["acceptance_contract"]["path"],
                    "kind": "file",
                    "sha256": spec["acceptance_contract"]["sha256"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = {}
            for cell in spec["cells"]:
                key = (cell["package"], cell["target_kind"], cell["target_name"])
                if key not in binaries:
                    path = root / f"target-{len(binaries)}.test"
                    path.write_bytes(str(key).encode())
                    binaries[key] = path
            calls = []

            def fake_run(command, cwd, timeout, limit, stdout_callback=None):
                calls.append(command)
                if stdout_callback is not None:
                    for (package, kind, target), path in binaries.items():
                        cargo_kind = "test" if kind == "integration" else kind
                        stdout_callback(
                            json.dumps(
                                {
                                    "reason": "compiler-artifact",
                                    "package_id": f"path+file:///repo/{package}#{package}@0.3.2",
                                    "target": {"kind": [cargo_kind], "name": target},
                                    "profile": {"test": True},
                                    "executable": str(path),
                                }
                            )
                        )
                    return self._capture(0)
                unknown = self._capture(
                    None,
                    "running 1 test\n"
                    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n",
                )
                unknown["terminal"] = "outcome_unknown"
                return unknown

            with mock.patch.object(
                runner, "source_manifest", return_value=source
            ) as manifest_probe, mock.patch.object(
                runner, "run_captured", side_effect=fake_run
            ):
                report, exit_code = runner.run_qualification(root, spec, "cargo")
        self.assertEqual(exit_code, 2)
        self.assertEqual(report["status"], "outcome_unknown")
        self.assertEqual(report["cells"][0]["status"], "outcome_unknown")
        self.assertEqual(report["cells"][0]["actual_summary"]["failed"], 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(manifest_probe.call_count, 3)


class ArtifactWriteControls(unittest.TestCase):
    def test_report_writer_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            runner.write_report(output, {"status": "first"})
            with self.assertRaises(FileExistsError):
                runner.write_report(output, {"status": "second"})


if __name__ == "__main__":
    unittest.main()
