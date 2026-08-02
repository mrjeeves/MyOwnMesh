#!/usr/bin/env python3
"""Compile external Arc 03 probes and verify the exact rejection causes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
CORE = REPO / "crates" / "myownmesh-core"


@dataclass(frozen=True)
class RejectedProbe:
    name: str
    source: str
    code: str
    fragments: tuple[str, ...]


REJECTED = (
    RejectedProbe(
        "raw_candidate_application_is_private",
        """use myownmesh_core::transport::{LocalIceCandidate, PeerSession};
async fn bypass(session: &PeerSession, candidate: LocalIceCandidate) {
    session.add_ice_candidate(candidate).await.unwrap(); // expected-error
}
fn main() {}
""",
        "E0624",
        ("add_ice_candidate", "private"),
    ),
    RejectedProbe(
        "connector_worker_is_not_public",
        """use myownmesh_core::transport::webrtc::WebRtcConnectorWorker; // expected-error
fn main() { let _ = std::mem::size_of::<WebRtcConnectorWorker>(); }
""",
        "E0603",
        ("WebRtcConnectorWorker", "private"),
    ),
)


POSITIVE_SOURCE = """use myownmesh_core::transport::{LocalIceCandidate, PeerSession};
fn public_compatibility_surface(_: &PeerSession, _: LocalIceCandidate) {}
fn main() { let _ = public_compatibility_surface; }
"""


def cargo_toml() -> str:
    core_path = CORE.as_posix().replace('"', '\\"')
    bins = [
        "[[bin]]\n" f'name = "{probe.name}"\n' f'path = "src/{probe.name}.rs"\n'
        for probe in REJECTED
    ]
    bins.append(
        "[[bin]]\n"
        'name = "positive_public_types"\n'
        'path = "src/positive_public_types.rs"\n'
    )
    return (
        "[package]\n"
        'name = "myownmesh-v4-arc03-compiler-boundaries"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n\n'
        "[dependencies]\n"
        f'myownmesh-core = {{ path = "{core_path}" }}\n\n'
        + "\n".join(bins)
    )


def run_check(project: Path, binary: str) -> tuple[int, list[dict], str]:
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    result = subprocess.run(
        [
            "cargo",
            "check",
            "--offline",
            "--message-format=json",
            "--bin",
            binary,
        ],
        cwd=project,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    diagnostics: list[dict] = []
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-message":
            continue
        if record.get("target", {}).get("name") == binary:
            diagnostics.append(record.get("message", {}))
    return result.returncode, diagnostics, result.stderr


def matches(probe: RejectedProbe, diagnostics: list[dict]) -> bool:
    marker_lines = [
        line_number
        for line_number, line in enumerate(probe.source.splitlines(), start=1)
        if "expected-error" in line
    ]
    if len(marker_lines) != 1:
        return False
    expected_line = marker_lines[0]
    expected_file = f"{probe.name}.rs"
    for diagnostic in diagnostics:
        code = (diagnostic.get("code") or {}).get("code")
        rendered = diagnostic.get("rendered") or diagnostic.get("message") or ""
        primary_span_matches = any(
            span.get("is_primary")
            and Path(span.get("file_name", "")).name == expected_file
            and span.get("line_start", 0) <= expected_line <= span.get("line_end", 0)
            for span in diagnostic.get("spans", [])
        )
        if (
            code == probe.code
            and all(fragment in rendered for fragment in probe.fragments)
            and primary_span_matches
        ):
            return True
    return False


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="myownmesh-v4-arc03-compiler-") as temporary:
        project = Path(temporary)
        source_dir = project / "src"
        source_dir.mkdir()
        (project / "Cargo.toml").write_text(cargo_toml(), encoding="utf-8", newline="\n")
        for probe in REJECTED:
            (source_dir / f"{probe.name}.rs").write_text(
                probe.source, encoding="utf-8", newline="\n"
            )
        (source_dir / "positive_public_types.rs").write_text(
            POSITIVE_SOURCE, encoding="utf-8", newline="\n"
        )

        positive_code, positive_diagnostics, positive_stderr = run_check(
            project, "positive_public_types"
        )
        if positive_code != 0:
            failures.append(
                "positive public-type control failed: "
                + (positive_stderr.strip() or str(positive_diagnostics))
            )

        for probe in REJECTED:
            return_code, diagnostics, stderr = run_check(project, probe.name)
            if return_code == 0:
                failures.append(f"{probe.name} compiled but rejection was required")
                continue
            if not matches(probe, diagnostics):
                summary = [
                    {
                        "code": (diagnostic.get("code") or {}).get("code"),
                        "message": diagnostic.get("message"),
                    }
                    for diagnostic in diagnostics
                ]
                failures.append(
                    f"{probe.name} failed for the wrong cause: expected {probe.code} "
                    f"and {probe.fragments}, got {summary}; cargo stderr={stderr.strip()!r}"
                )

    if failures:
        print("V4 Arc 03 compiler-boundary checks failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "V4 Arc 03 compiler-boundary checks passed: one positive public-type "
        "control and two cause-matched rejection controls."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
