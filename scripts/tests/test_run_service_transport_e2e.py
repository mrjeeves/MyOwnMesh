import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "run-service-transport-e2e.py"
SPEC = importlib.util.spec_from_file_location("run_service_transport_e2e", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class GrantControls(unittest.TestCase):
    def test_finite_grant_requires_every_daemon_dimension(self) -> None:
        raw = ",".join(f"{name}=0" for name in harness.GRANT_DIMENSIONS)
        parsed = harness.finite_grant_dimensions(raw)
        self.assertEqual(set(parsed), set(harness.GRANT_DIMENSIONS))

    def test_finite_grant_rejects_unknown_and_duplicate_dimensions(self) -> None:
        base = ",".join(f"{name}=0" for name in harness.GRANT_DIMENSIONS)
        with self.assertRaises(harness.ContractError):
            harness.finite_grant_dimensions(base + ",not_a_dimension=1")
        with self.assertRaises(harness.ContractError):
            harness.finite_grant_dimensions(base + ",queued_bytes=1")


class TransportControls(unittest.TestCase):
    def test_selected_pair_is_authoritative(self) -> None:
        self.assertEqual(
            harness.pair_class({"selected_pair": {"local": "host", "remote": "host"}}),
            "direct",
        )
        self.assertEqual(
            harness.pair_class({"selected_pair": {"local": "relay", "remote": "host"}}),
            "turn",
        )
        self.assertIsNone(harness.pair_class({"turn_servers": [{"urls": ["turn:configured"]}]}))

    def test_config_has_no_implicit_peer_turn_or_service_selection(self) -> None:
        config = harness.daemon_config("n", "127.0.0.1", 3478, 3479, None)
        network = config["networks"][0]
        self.assertTrue(network["signaling"]["mdns"])
        self.assertEqual(network["turn_servers"][0]["username"], "e2e")
        services = harness.hosted_service_config("127.0.0.1", 3478, 3479, 0, 0, 0)
        self.assertFalse(services["stun"]["enabled"])
        self.assertFalse(services["turn"]["enabled"])

    def test_manifest_contract_names_public_lifecycle_prerequisites(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        for marker in (
            '"services_status"',
            '"services_set"',
            '"peers_list"',
            '"network_reconnect"',
            '"channel_send_reliable"',
            '"forget_all_networks"',
            "selected_pair",
            "MYOWNMESH_RESOURCE_GRANT",
            "public_shutdown_requested",
        ):
            self.assertIn(marker, source)
        self.assertIn("public daemon api has no force-relay selector", source.lower())


if __name__ == "__main__":
    unittest.main()
