import importlib.util
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "verify-v4-cutover.py"
SPEC = importlib.util.spec_from_file_location("verify_v4_cutover", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


CURRENT_SOURCE = """
pub const PROTOCOL_VERSION: u32 = 3;
enum MeshMessage { HubIntroduction }
struct TurnServer;
struct FactInventory; struct FactRequest; struct FactPageMessage;
enum FactBody { AuthorityLineageResolution }
const FEATURE: &str = "endpoint_auth_v1";
"""


class SourceControls(unittest.TestCase):
    def test_current_source_passes(self) -> None:
        checker.scan_source_text("current", CURRENT_SOURCE)

    def test_current_noncanonical_device_error_is_allowed(self) -> None:
        checker.scan_source_text(
            "current introduction error",
            "enum HubIntroductionError { NonCanonicalDeviceId }\n"
            "let error = HubIntroductionError::NonCanonicalDeviceId;",
        )

    def test_exact_removed_identifier_markers_are_rejected(self) -> None:
        for marker in checker.LEGACY_MARKERS + checker.CUSTOM_APPLICATION_RELAY_MARKERS:
            if not marker.isidentifier():
                if marker == "route-flow-diagnostics":
                    with self.assertRaises(SystemExit) as error:
                        checker.scan_source_text("removed.rs", f'#[cfg(feature = "{marker}")] fn old() {{}}')
                    self.assertIn(marker, str(error.exception))
                continue
            for source in (
                marker,
                f"struct {marker};",
                f"type Removed = old::{marker};",
                f'const KIND: &str = "{marker}";',
            ):
                with self.subTest(marker=marker, source=source):
                    with self.assertRaises(SystemExit) as error:
                        checker.scan_source_text("removed", source)
                    self.assertIn(marker, str(error.exception))

    def test_longer_identifiers_are_not_removed_identifier_tokens(self) -> None:
        for marker in checker.LEGACY_MARKERS + checker.CUSTOM_APPLICATION_RELAY_MARKERS:
            if not marker.isidentifier():
                continue
            for current in (f"Current{marker}", f"{marker}_detail", f"{marker}\u00e9"):
                with self.subTest(marker=marker, current=current):
                    checker.scan_source_text("distinct current identifier", f"struct {current};")

    def test_removed_namespace_is_still_rejected(self) -> None:
        with self.assertRaises(SystemExit) as error:
            checker.scan_source_text("namespace", "use network_state::Current;")
        self.assertIn("network_state::", str(error.exception))

    def test_removed_wire_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as error:
            checker.scan_source_text("fixture", CURRENT_SOURCE + " NetworkStateBroadcast")
        self.assertIn("NetworkStateBroadcast", str(error.exception))

    def test_removed_alias_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as error:
            checker.scan_source_text("fixture", "pub use semantic::{ FactBody };")
        self.assertIn("pub use semantic", str(error.exception))

    def test_removed_wire_spelling_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as error:
            checker.scan_source_text("fixture", 'const KIND: &str = "roster_summary";')
        self.assertIn("roster_summary", str(error.exception))

    def test_serde_alias_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as error:
            checker.scan_source_text(
                "fixture",
                '#[serde(rename_all = "snake_case", alias = "roster_summary")]\n'
                "struct Removed;",
            )
        self.assertIn("serde alias", str(error.exception))

    def test_turn_nostr_and_introduction_shared_hop_are_not_custom_relay(self) -> None:
        checker.scan_source_text(
            "current.rs",
            'struct TurnServer; struct TurnServiceConfig; struct RoutedHop;\n'
            'struct HubIntroductionPolicyConfig; let turn_servers = [];\n'
            'let nostr_relay = "wss://relay.example";',
        )

    def test_test_only_rejections_and_comments_are_not_production_surfaces(self) -> None:
        checker.scan_source_text(
            "current.rs",
            '// ClosedRelayControl is retired.\n'
            '/* outer /* ClosedRelayData */ comment */\n'
            '#[cfg(test)] mod controls {\n'
            'let data = r###" } #[cfg(test)] ClosedRelayData "###;\n'
            'fn rejects() { let old = "closed_relay_send"; }\n'
            '}\n'
            '#[cfg(all(unix, test))] fn negative() { let old = "endpoint_cipher"; }\n'
            'struct TurnServer;',
        )

    def test_test_only_mask_cannot_hide_following_production_or_any_feature(self) -> None:
        for prefix in (
            '#[cfg(test)] mod tests { let text = r#"}"#; }\n',
            '#[cfg(test)] const OLD: &str = "ClosedRelayData";\n',
            '#[cfg(any(test, feature = "transport-lab"))]\n',
            '#[cfg(all(not(test), unix))]\n',
            'const QUOTED: &str = "#[cfg(test)]";\n',
        ):
            with self.subTest(prefix=prefix), self.assertRaises(SystemExit):
                checker.scan_source_text("bad.rs", prefix + "struct RoutedApplicationEnvelope;")

    def test_cfg_test_comma_fields_and_arguments_preserve_following_production(self) -> None:
        # Actual control.rs DispatchHooks shape: the old scanner consumed
        # past these commas and failed at the enclosing struct's closing }.
        fields = (
            '    #[cfg(test)]\n'
            '    before_events_subscribe_commit: Option<Arc<DispatchBarrier>>,\n'
            '    #[cfg(test)]\n'
            '    registry: Option<tokio::sync::oneshot::Sender<crate::ipc::ClientRegistry>>,\n'
        )
        source = 'struct DispatchHooks {\n' + fields + '}\n'
        checker.scan_source_text("control.rs", source)
        checker.scan_source_text(
            "turn.rs",
            'fn start(#[cfg(test)] probe: Option<CleanupProbe>, live: bool) {}\n'
            'fn call() { start(#[cfg(test)] None, true); }\n'
            'fn build() { let value = State { #[cfg(test)] probe: None, live: true }; }',
        )
        for declaration in (
            'struct DispatchHooks {\n' + fields + '    live: ClosedRelayControl,\n}',
            source + 'struct ClosedRelayControl;',
            'struct S { #[cfg(test)] field: Pair<u8, ClosedRelayControl>, live: bool }',
        ):
            # Even ambiguous angle-bracket commas leave the suffix checked;
            # they cannot extend a test mask across production declarations.
            with self.subTest(source=declaration), self.assertRaises(SystemExit) as error:
                checker.scan_source_text("bad.rs", declaration)
            self.assertIn("ClosedRelayControl", str(error.exception))

    def test_rust_masking_failure_names_source_and_exact_character_offset(self) -> None:
        source = '#[cfg(test)]\nfn bad() { (] }\n'
        offset = source.index("]", source.index("fn bad"))
        with self.assertRaises(SystemExit) as error:
            checker.scan_source_text("broken.rs", source)
        self.assertIn("broken.rs:2:13", str(error.exception))
        self.assertIn(f"character offset {offset}", str(error.exception))
        self.assertIn("unbalanced test-only Rust item", str(error.exception))

    def test_last_cfg_parameter_without_comma_keeps_enclosing_body_checked(self) -> None:
        # Exact clients.rs RouteJoinCustodian::start parameter shape.
        signature = 'fn start(&self, #[cfg(test)] fail_at: Option<usize>)'
        source = signature + ' -> Result<(), IpcAdmissionError> { Ok(()) }'
        masked = checker.production_rust_text(source, "clients.rs")
        self.assertEqual(masked[source.index(") ->"):], source[source.index(") ->"):])
        checker.scan_source_text("clients.rs", source)
        for source in (
            signature + ' { let old = ClosedRelayControl; }',
            'fn call() { start(#[cfg(test)] None); let old = ClosedRelayControl; }',
            'struct S { #[cfg(test)] probe: Option<Probe> } struct ClosedRelayControl;',
        ):
            with self.subTest(source=source), self.assertRaises(SystemExit) as error:
                checker.scan_source_text("bad.rs", source)
            self.assertIn("ClosedRelayControl", str(error.exception))
        for source in (
            'fn bad(#[cfg(test)] probe: Option<Probe> }',
            '#[cfg(test)] probe: Option<Probe>)',
        ):
            with self.subTest(source=source), self.assertRaises(SystemExit) as error:
                checker.scan_source_text("bad.rs", source)
            self.assertIn("unbalanced test-only Rust item", str(error.exception))


class GraphControls(unittest.TestCase):
    def _write_current_graph(self, directory: str) -> pathlib.Path:
        root = pathlib.Path(directory)
        (root / "crates" / "demo" / "src").mkdir(parents=True)
        (root / "gui" / "src").mkdir(parents=True)
        (root / "gui" / "src-tauri" / "src").mkdir(parents=True)
        (root / "crates" / "demo" / "src" / "lib.rs").write_text(
            CURRENT_SOURCE, encoding="utf-8"
        )
        (root / "gui" / "src" / "app.ts").write_text(
            "export const current = 'HubIntroduction';", encoding="utf-8"
        )
        (root / "gui" / "src-tauri" / "src" / "main.rs").write_text(
            "fn main() {}", encoding="utf-8"
        )
        return root

    def test_current_introduction_error_and_fact_page_graph_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._write_current_graph(directory)
            (root / "crates" / "demo" / "src" / "routing.rs").write_text(
                "enum HubIntroductionError { NonCanonicalDeviceId }\n"
                "let error = HubIntroductionError::NonCanonicalDeviceId;",
                encoding="utf-8",
            )
            checker.scan_source_tree(root)

    def test_missing_current_fact_page_message_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._write_current_graph(directory)
            source = root / "crates" / "demo" / "src" / "lib.rs"
            source.write_text(
                CURRENT_SOURCE.replace("struct FactPageMessage;", "struct FactBundle;"),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit) as error:
                checker.scan_source_tree(root)
            self.assertIn("lacks current form(s): FactPageMessage", str(error.exception))

    def test_gui_and_tauri_legacy_wires_are_rejected(self) -> None:
        for relative in (
            pathlib.Path("gui/src/bad.ts"),
            pathlib.Path("gui/src/bad.svelte"),
            pathlib.Path("gui/src-tauri/src/bad.rs"),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = self._write_current_graph(directory)
                path = root / relative
                path.write_text("const removed = 'governance_snapshot';", encoding="utf-8")
                with self.assertRaises(SystemExit) as error:
                    checker.scan_source_tree(root)
                self.assertIn("governance_snapshot", str(error.exception))

    def test_tests_fixtures_and_marker_inventories_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._write_current_graph(directory)
            (root / "crates" / "demo" / "tests").mkdir()
            (root / "crates" / "demo" / "tests" / "legacy.rs").write_text(
                "NetworkStateBroadcast", encoding="utf-8"
            )
            (root / "gui" / "src" / "test_fixture.ts").write_text(
                "RosterRequest", encoding="utf-8"
            )
            (root / "scripts").mkdir()
            (root / "scripts" / "marker_inventory.py").write_text(
                "GovernanceSnapshot", encoding="utf-8"
            )
            checker.scan_source_tree(root)


class InventoryControls(unittest.TestCase):
    def test_marker_inventory_requires_current_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "markers.py"
            path.write_text(
                "MYOWNMESH_TRANSPORT_LAB_MFA_BARRIER transport-lab",
                encoding="utf-8",
            )
            checker.scan_release_marker_inventory(path)

    def test_marker_inventory_retains_removed_rejection_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "markers.py"
            path.write_text(
                "MYOWNMESH_TRANSPORT_LAB_MFA_BARRIER transport-lab\n"
                "NetworkStateBroadcast",
                encoding="utf-8",
            )
            checker.scan_release_marker_inventory(path)

    def test_marker_inventory_requires_transport_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "markers.py"
            path.write_text("transport-lab", encoding="utf-8")
            with self.assertRaises(SystemExit) as error:
                checker.scan_release_marker_inventory(path)
            self.assertIn("MFA_BARRIER", str(error.exception))


class ManifestControls(unittest.TestCase):
    def test_explicit_lab_manifest_wiring_is_allowed(self) -> None:
        checker.scan_manifest_text(
            "good",
            "[features]\ntransport-lab = []\n"
            "[[example]]\nrequired-features = [\"transport-lab\"]\n"
            "[dev-dependencies]\nmyownmesh-core = { features = [\"transport-lab\"] }\n",
        )

    def test_production_transport_feature_leak_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as error:
            checker.scan_manifest_text(
                "bad",
                "[dependencies]\nmyownmesh-core = { features = [\"transport-lab\"] }\n",
            )
        self.assertIn("transport-lab", str(error.exception))

    def test_default_lab_feature_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as error:
            checker.scan_manifest_text(
                "bad",
                "[features]\ndefault = [\"transport-lab\"]\n",
            )
        self.assertIn("by default", str(error.exception))

    def test_removed_compatibility_feature_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as error:
            checker.scan_manifest_text(
                "bad",
                "[features]\nlegacy-v1 = []\n",
            )
        self.assertIn("legacy-v1", str(error.exception))


if __name__ == "__main__":
    unittest.main()
