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
pub const PROTOCOL_VERSION: u32 = 2;
enum MeshMessage { ClosedRelayControl, ClosedRelayData }
struct FactInventory; struct FactRequest; struct FactPageMessage;
enum FactBody { AuthorityLineageResolution }
const FEATURE: &str = "endpoint_auth_v1";
"""


class SourceControls(unittest.TestCase):
    def test_current_source_passes(self) -> None:
        checker.scan_source_text("current", CURRENT_SOURCE)

    def test_current_noncanonical_device_error_is_allowed(self) -> None:
        checker.scan_source_text(
            "current routed error",
            "enum RoutedApplicationError { NonCanonicalDeviceId }\n"
            "let error = RoutedApplicationError::NonCanonicalDeviceId;",
        )

    def test_exact_removed_identifier_markers_are_rejected(self) -> None:
        for marker in checker.LEGACY_MARKERS:
            if not marker.isidentifier():
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
        for marker in checker.LEGACY_MARKERS:
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
            "export const current = 'ClosedRelayData';", encoding="utf-8"
        )
        (root / "gui" / "src-tauri" / "src" / "main.rs").write_text(
            "fn main() {}", encoding="utf-8"
        )
        return root

    def test_current_routed_error_and_fact_page_graph_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._write_current_graph(directory)
            (root / "crates" / "demo" / "src" / "routing.rs").write_text(
                "enum RoutedApplicationError { NonCanonicalDeviceId }\n"
                "let error = RoutedApplicationError::NonCanonicalDeviceId;",
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
