from __future__ import annotations

import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "run-signaling-backends-e2e.py"
SPEC = importlib.util.spec_from_file_location("run_signaling_backends_e2e", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ShippedSignalingBackendControls(unittest.TestCase):
    def test_mdns_config_is_the_real_embedded_backend(self) -> None:
        network = runner.daemon_config("e2e123", mode="mdns")["networks"][0]
        signaling = network["signaling"]
        self.assertEqual(signaling["strategy"], "none")
        self.assertTrue(signaling["mdns"])
        self.assertEqual(signaling["servers"], [])
        self.assertFalse(signaling["public_fallback"])

    def test_nostr_config_names_only_the_shipped_loopback_relay(self) -> None:
        network = runner.daemon_config(
            "e2e123", mode="nostr", relay_url="ws://127.0.0.1:41234"
        )["networks"][0]
        signaling = network["signaling"]
        self.assertEqual(signaling["strategy"], "nostr")
        self.assertFalse(signaling["mdns"])
        self.assertEqual(signaling["servers"], ["ws://127.0.0.1:41234"])
        self.assertFalse(signaling["public_fallback"])

    def test_relay_is_a_pure_infrastructure_shipped_daemon(self) -> None:
        services = runner.relay_config(41234)["services"]
        self.assertFalse(services["node"]["enabled"])
        self.assertTrue(services["signaling"]["enabled"])
        self.assertEqual(services["signaling"]["bind"], "127.0.0.1")
        self.assertEqual(services["signaling"]["port"], 41234)

    def test_drop_event_requires_canonical_network_and_peer_identity(self) -> None:
        frame = {
            "kind": "event",
            "event": {
                "event_kind": "peer",
                "kind": "dropped",
                "network_id": "e2e123",
                "device_id": "dev-a",
            },
        }
        self.assertTrue(runner.dropped_event(frame, "e2e123", "dev-a"))
        self.assertFalse(runner.dropped_event(frame, "other", "dev-a"))
        self.assertFalse(runner.dropped_event(frame, "e2e123", "dev-b"))
        frame["event"]["kind"] = "sighted"
        self.assertFalse(runner.dropped_event(frame, "e2e123", "dev-a"))

    def test_invalid_client_mode_and_missing_nostr_relay_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            runner.daemon_config("e2e123", mode="unknown")
        with self.assertRaises(ValueError):
            runner.daemon_config("e2e123", mode="nostr")
        with self.assertRaises(ValueError):
            runner.relay_config(0)

    def test_source_uses_shipped_serve_and_required_typed_controls(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('[str(binary), "serve"]', source)
        for operation in (
            '"status"',
            '"services_status"',
            '"peers_list"',
            '"events_subscribe"',
            '"channel_subscribe"',
            '"channel_send_reliable"',
        ):
            self.assertIn(operation, source)
        self.assertNotIn("LocalBroker", source)
        self.assertIn("all_graceful_terminals", source)

    def test_manifest_has_both_process_scenarios_and_finite_grant_marker(self) -> None:
        self.assertEqual(
            runner.main.__name__,
            "main",
            "the script must retain a process entry point rather than only fixture helpers",
        )
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("MYOWNMESH_RESOURCE_GRANT", source)
        self.assertIn('mode="mdns"', source)
        self.assertIn('mode="nostr"', source)


if __name__ == "__main__":
    unittest.main()
