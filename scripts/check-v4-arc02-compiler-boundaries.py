#!/usr/bin/env python3
"""Compile Arc 02 boundary probes and verify their exact diagnostic causes."""

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
        "candidate_from_public_label",
        """use myownmesh_core::runtime::attempt::CandidateCapability;
fn main() {
    let public_peer_id = String::new();
    let _candidate = CandidateCapability::from(public_peer_id); // expected-error
}
""",
        "E0308",
        ("CandidateCapability", "String"),
    ),
    RejectedProbe(
        "connected_is_not_session",
        """use myownmesh_core::connector::ConnectedChannelCapability;
use myownmesh_core::runtime::session_broker::SessionCapability;
fn connected() -> ConnectedChannelCapability { unimplemented!() }
fn application_operation(_: &SessionCapability) {}
fn main() { application_operation(&connected()); } // expected-error
""",
        "E0308",
        ("ConnectedChannelCapability", "SessionCapability"),
    ),
    RejectedProbe(
        "connected_is_not_authenticated",
        """use myownmesh_core::connector::ConnectedChannelCapability;
use myownmesh_core::endpoint_auth::AuthenticatedChannelCapability;
fn connected() -> ConnectedChannelCapability { unimplemented!() }
fn requires_authentication(_: AuthenticatedChannelCapability) {}
fn main() { requires_authentication(connected()); } // expected-error
""",
        "E0308",
        ("ConnectedChannelCapability", "AuthenticatedChannelCapability"),
    ),
    RejectedProbe(
        "principal_from_public_label",
        """use myownmesh_core::application_gateway::LocalPrincipalCapability;
fn main() {
    let public_client_label = String::new();
    let _principal = LocalPrincipalCapability::from(public_client_label); // expected-error
}
""",
        "E0308",
        ("LocalPrincipalCapability", "String"),
    ),
    RejectedProbe(
        "session_has_no_public_constructor",
        """use myownmesh_core::runtime::session_broker::SessionCapability;
fn main() { let _session = SessionCapability::new("public-session-label"); } // expected-error
""",
        "E0599",
        ("SessionCapability", "new"),
    ),
    RejectedProbe(
        "session_is_not_serializable",
        """use myownmesh_core::runtime::session_broker::SessionCapability;
fn session() -> SessionCapability { unimplemented!() }
fn main() { let _ = serde_json::to_string(&session()); } // expected-error
""",
        "E0277",
        ("SessionCapability", "Serialize"),
    ),
    RejectedProbe(
        "session_is_not_deserializable",
        """use myownmesh_core::runtime::session_broker::SessionCapability;
fn main() { let _: SessionCapability = serde_json::from_str("{}").unwrap(); } // expected-error
""",
        "E0277",
        ("SessionCapability", "Deserialize"),
    ),
    RejectedProbe(
        "session_is_not_clone",
        """use myownmesh_core::runtime::session_broker::SessionCapability;
fn requires_clone<T: Clone>() {}
fn main() { requires_clone::<SessionCapability>(); } // expected-error
""",
        "E0277",
        ("SessionCapability", "Clone"),
    ),
    RejectedProbe(
        "pre_auth_permit_is_not_session_permit",
        """use myownmesh_core::runtime::attempt::PreAuthAttemptPermit;
use myownmesh_core::runtime::session_broker::SessionPermit;
fn pre_authentication_permit() -> PreAuthAttemptPermit { unimplemented!() }
fn requires_session_permit(_: SessionPermit) {}
fn main() { requires_session_permit(pre_authentication_permit()); } // expected-error
""",
        "E0308",
        ("PreAuthAttemptPermit", "SessionPermit"),
    ),
    RejectedProbe(
        "runtime_witness_is_not_public",
        """use myownmesh_core::runtime::RuntimeIncarnation; // expected-error
fn main() { let _ = std::mem::size_of::<RuntimeIncarnation>(); }
""",
        "E0603",
        ("RuntimeIncarnation", "private"),
    ),
)

POSITIVE_SOURCE = """use myownmesh_core::runtime::session_broker::SessionCapability;
fn requires_promoted_session(_: &SessionCapability) {}
fn main() { let _boundary = requires_promoted_session; }
"""


def cargo_toml() -> str:
    core_path = CORE.as_posix().replace('"', '\\"')
    bins = [
        "[[bin]]\n"
        f'name = "{probe.name}"\n'
        f'path = "src/{probe.name}.rs"\n'
        for probe in REJECTED
    ]
    bins.append(
        "[[bin]]\n"
        'name = "positive_type_path"\n'
        'path = "src/positive_type_path.rs"\n'
    )
    return (
        "[package]\n"
        'name = "myownmesh-v4-arc02-compiler-boundaries"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n\n'
        "[dependencies]\n"
        f'myownmesh-core = {{ path = "{core_path}" }}\n'
        'serde_json = "1"\n\n'
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
        target = record.get("target", {})
        if target.get("name") == binary:
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
    with tempfile.TemporaryDirectory(prefix="myownmesh-v4-arc02-compiler-") as temporary:
        project = Path(temporary)
        source_dir = project / "src"
        source_dir.mkdir()
        (project / "Cargo.toml").write_text(cargo_toml(), encoding="utf-8", newline="\n")
        for probe in REJECTED:
            (source_dir / f"{probe.name}.rs").write_text(
                probe.source, encoding="utf-8", newline="\n"
            )
        (source_dir / "positive_type_path.rs").write_text(
            POSITIVE_SOURCE, encoding="utf-8", newline="\n"
        )

        positive_code, positive_diagnostics, positive_stderr = run_check(
            project, "positive_type_path"
        )
        if positive_code != 0:
            failures.append(
                "positive type-path control failed: "
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
                    f"{probe.name} failed for the wrong cause: "
                    f"expected {probe.code} and {probe.fragments}, got {summary}; "
                    f"cargo stderr={stderr.strip()!r}"
                )
                continue

            wrong_code = RejectedProbe(
                probe.name,
                probe.source,
                "E9999",
                probe.fragments,
            )
            wrong_fragment = RejectedProbe(
                probe.name,
                probe.source,
                probe.code,
                ("intentionally-absent-diagnostic-fragment",),
            )
            wrong_line = RejectedProbe(
                probe.name,
                "\n" + probe.source,
                probe.code,
                probe.fragments,
            )
            if (
                matches(wrong_code, diagnostics)
                or matches(wrong_fragment, diagnostics)
                or matches(wrong_line, diagnostics)
            ):
                failures.append(f"{probe.name} cause-matcher accepted a false expectation")

    if failures:
        print("V4 Arc 02 compiler-boundary checks failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "V4 Arc 02 compiler-boundary checks passed: 1 positive type-path control "
        f"and {len(REJECTED)} cause-matched rejection controls."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
