#!/usr/bin/env python3
"""Contract controls for the production-daemon connection benchmark."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("benchmark-connections.py")
SPEC = importlib.util.spec_from_file_location("benchmark_connections", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class BenchmarkConnectionContractTests(unittest.TestCase):
    def test_peer_snapshot_consumes_public_cli_shape(self) -> None:
        expected = {"device_id": "peer-a", "status": "pending"}
        with mock.patch.object(
            BENCHMARK,
            "run_json",
            return_value={"peers": [expected, {"device_id": "peer-b"}]},
        ):
            self.assertEqual(
                BENCHMARK.peer_snapshot("myownmesh", "fresh-network", "peer-a", 1.0),
                expected,
            )

    def test_peer_snapshot_reassembles_public_suffix_for_dial_identity(self) -> None:
        expected = {
            "device_id": "vebjwc6ii4wg3vvhiud4wlsrnyh3iqlanmqhkdmrtixcua5fym4a",
            "device_suffix": "70CD6",
            "status": "sighted",
        }
        with mock.patch.object(
            BENCHMARK,
            "run_json",
            return_value={"peers": [expected]},
        ):
            self.assertEqual(
                BENCHMARK.peer_snapshot(
                    "myownmesh",
                    "fresh-network",
                    "vebjwc6ii4wg3vvhiud4wlsrnyh3iqlanmqhkdmrtixcua5fym4a-70CD6",
                    1.0,
                ),
                expected,
            )

    def test_peer_snapshot_rejects_old_bare_list_assumption(self) -> None:
        with mock.patch.object(BENCHMARK, "run_json", return_value=[]):
            with self.assertRaisesRegex(RuntimeError, "object containing a peers list"):
                BENCHMARK.peer_snapshot(
                    "myownmesh", "fresh-network", "peer-a", 1.0
                )

    def test_freshness_gate_rejects_idempotent_live_connection(self) -> None:
        pending = {
            "authenticated": False,
            "status": "pending",
            "local_approve_sent": False,
            "remote_approve_seen": False,
            "selected_pair": None,
        }
        self.assertTrue(BENCHMARK.is_fresh_discovery(pending))
        for changed in (
            {"authenticated": True, "status": "active"},
            {"local_approve_sent": True},
            {"remote_approve_seen": True},
            {"selected_pair": {"local": "host", "remote": "host"}},
        ):
            with self.subTest(changed=changed):
                self.assertFalse(
                    BENCHMARK.is_fresh_discovery({**pending, **changed})
                )

    def test_selected_pair_classification_uses_nominated_pair(self) -> None:
        cases = (
            ({"local": "host", "remote": "host"}, "lan"),
            ({"local": "server_reflexive", "remote": "host"}, "stun"),
            ({"local": "host", "remote": "peer_reflexive"}, "stun"),
            ({"local": "relay", "remote": "host"}, "turn"),
            ({"local": "unknown", "remote": "unknown"}, None),
        )
        for pair, expected in cases:
            with self.subTest(pair=pair):
                self.assertEqual(BENCHMARK.pair_class(pair), expected)

    def test_required_turn_route_rejects_non_turn_pairs(self) -> None:
        BENCHMARK.enforce_required_route("turn", "turn")
        BENCHMARK.enforce_required_route("stun", None)
        with self.assertRaisesRegex(RuntimeError, "required route 'turn'"):
            BENCHMARK.enforce_required_route("stun", "turn")

    def test_percentile_uses_nearest_rank_without_understating_p95(self) -> None:
        values = [float(value) for value in range(1, 21)]
        self.assertEqual(BENCHMARK.percentile(values, 0.50), 10.0)
        self.assertEqual(BENCHMARK.percentile(values, 0.95), 19.0)
        self.assertEqual(BENCHMARK.percentile(values, 1.00), 20.0)


if __name__ == "__main__":
    unittest.main()
