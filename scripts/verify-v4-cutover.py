#!/usr/bin/env python3
"""Verify that the V4 source and release marker inventory are hard-cut over.

The checker names obsolete protocol/authority surfaces explicitly.  It does
not reject historical words in comments or stable domain-version tags: those
are not executable compatibility surfaces.  The graph scan covers first-party
Rust, GUI, Tauri, and Cargo manifests while excluding deliberate tests,
fixtures, and diagnostic marker inventories.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re


# These are removed modules, wire variants, aliases, or authority shims.  Do
# not broaden this list to generic words such as "legacy" or "fallback": the
# repository retains legitimate negative controls and on-disk recovery.
LEGACY_MARKERS = (
    "NetworkStateBroadcast",
    "RosterSummary",
    "RosterRequest",
    "RosterEntries",
    "GovernanceSnapshot",
    "GovernanceMfaEnroll",
    "SelfStandDownReference",
    "CanonicalDeviceId",
    "LegacyAuthority",
    "network_state::",
    "governance_state",
    "pub use semantic::{",
    # Serialized spellings are checked as well as Rust identifiers.  These
    # are deliberately exact: broad words such as ``legacy`` and ``v3`` also
    # occur in negative controls and stable domain labels.
    "roster_summary",
    "roster_request",
    "roster_entries",
    "governance_snapshot",
    "governance_mfa_enroll",
    "self_stand_down_reference",
    "canonical_device_id",
    "legacy_authority",
)

REMOVED_COMPATIBILITY_FEATURE_MARKERS = (
    "legacy-v1",
    "legacy-media",
    "transport-v3",
    "protocol-v3",
    "route-flow-diagnostics",
)

# Custom member/application relay surfaces, not standard TURN or Nostr relay
# servers. RoutedHop remains a bounded introduction-control helper.
CUSTOM_APPLICATION_RELAY_MARKERS = (
    "ClosedRelayControl", "ClosedRelayData", "ClosedRelayPolicyConfig",
    "ClosedRelayChannel", "ClosedRelayError", "open_closed_relay", "accept_closed_relay",
    "ClosedRelayOpen", "ClosedRelayAccept", "ClosedRelaySend",
    "ClosedRelayRecv", "ClosedRelayClose", "ClosedRelayState",
    "ClosedRoutedPayload", "RoutedApplicationEnvelope", "RoutedApplicationError",
    "RoutingPolicyConfig", "ApplicationTransportPolicyConfig",
    "EndpointCipherControl", "EndpointCiphertext", "EndpointCipherPolicyConfig", "CiphertextPacket",
    "closed_relay", "application_transport", "endpoint_cipher", "routing_policy",
    "closed_relay_control", "closed_relay_data", "routed_application", "endpoint_ciphertext",
    "closed_relay_open", "closed_relay_accept", "closed_relay_send",
    "closed_relay_recv", "closed_relay_state", "closed_relay_close",
    "send_routed_channel_frame", "queue_routed_channel_frame",
    "route_flow", "route_trace_listen", "route-flow-diagnostics",
)

SERDE_ALIAS_RE = re.compile(
    r"#\s*\[\s*serde\s*\([^\]]*\balias\s*=",
    re.IGNORECASE | re.DOTALL,
)

GRAPH_SOURCE_SUFFIXES = {".rs", ".ts", ".svelte"}
GRAPH_EXCLUDED_PARTS = {
    ".git",
    "node_modules",
    "target",
    "vendor",
    "tests",
    "test",
    "fixtures",
    "fixture",
    "snapshots",
    "snapshot",
    "__tests__",
}

CURRENT_MARKERS = (
    "PROTOCOL_VERSION: u32 = 3",
    "HubIntroduction",
    "TurnServer",
    "FactInventory",
    "FactRequest",
    "FactPageMessage",
    "AuthorityLineageResolution",
    "endpoint_auth_v1",
)

# Keep the release checker from silently losing its existing transport-lab
# artifact boundary while this independent hard-cutover gate checks it.
RELEASE_MARKER_POSITIVES = (
    "MYOWNMESH_TRANSPORT_LAB_MFA_BARRIER",
    "transport-lab",
)


def fail(message: str) -> None:
    raise SystemExit(f"V4 hard-cutover check: {message}")


def find_markers(label: str, text: str, markers: tuple[str, ...]) -> list[str]:
    found = []
    for marker in markers:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", marker):
            # A removed identifier or serialized key must be a complete token.
            # NonCanonicalDeviceId is a current error, not CanonicalDeviceId.
            # Unicode-aware boundaries also avoid splitting longer identifiers.
            present = re.search(rf"(?<!\w){re.escape(marker)}(?!\w)", text) is not None
        else:
            # Preserve explicit namespace and banned-expression matching,
            # including network_state::Type and pub use semantic::{ ... }.
            present = marker in text
        if present:
            found.append(marker)
    return found


def scan_source_text(label: str, text: str) -> None:
    found = find_markers(label, text, LEGACY_MARKERS)
    production = production_rust_text(text, label) if label.endswith(".rs") else text
    found.extend(find_markers(label, production, CUSTOM_APPLICATION_RELAY_MARKERS))
    if SERDE_ALIAS_RE.search(text):
        found.append("serde alias")
    if found:
        fail(f"{label} contains removed surface(s): {', '.join(found)}")


def production_rust_text(text: str, label: str = "<Rust source>") -> str:
    """Mask comments and unconditionally test-only items, not lab production.

    Tokenize strings/raw strings atomically so quoted cfg/braces cannot hide
    a following production item. Only cfg(test) or a direct test conjunct in
    cfg(all(...)) is excluded; cfg(any(test, feature=...)) remains production.
    This is a source absence guard, not a Rust compiler or runtime proof.
    """
    atom = re.compile(
        r'//[^\n]*|/\*|(?:br|cr|r)(?P<hashes>\#{0,255})"'
        r'|(?:b|c)?"(?:\\.|[^"\\])*"'
        r"|b?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\])'"
        r"|\s+|[A-Za-z_][A-Za-z_0-9]*|.", re.DOTALL,
    )
    tokens = []
    masked = list(text)
    cursor = 0

    def syntax_fail(message: str, offset: int) -> None:
        line = text.count("\n", 0, offset) + 1
        column = offset - text.rfind("\n", 0, offset)
        fail(f"{label}:{line}:{column} (character offset {offset}): {message}")

    def mask(start: int, end: int) -> None:
        for index in range(start, end):
            if masked[index] != "\n":
                masked[index] = " "

    while cursor < len(text):
        match = atom.match(text, cursor)
        assert match is not None
        value = match.group()
        end = match.end()
        if value == "/*":
            depth = 1
            while depth and end < len(text):
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                syntax_fail("unterminated Rust comment in source guard", cursor)
            mask(cursor, end)
        elif value.startswith("//"):
            mask(cursor, end)
        elif match.group("hashes") is not None:
            terminator = '"' + match.group("hashes")
            closing = text.find(terminator, end)
            if closing < 0:
                syntax_fail("unterminated Rust raw string in source guard", cursor)
            end = closing + len(terminator)
            tokens.append((cursor, end, text[cursor:end]))
        elif not value.isspace():
            tokens.append((cursor, end, value))
        cursor = end

    values = [token[2] for token in tokens]
    index = 0
    while index < len(tokens):
        if values[index:index + 4] != ["#", "[", "cfg", "("]:
            index += 1
            continue
        closing = index + 4
        depth = 1
        while closing < len(tokens) and depth:
            depth += (values[closing] == "(") - (values[closing] == ")")
            closing += 1
        if depth or values[closing:closing + 1] != ["]"]:
            syntax_fail("unbalanced Rust cfg in source guard", tokens[index][0])
        condition = values[index + 4:closing - 1]
        test_only = condition == ["test"]
        if condition[:2] == ["all", "("] and condition[-1:] == [")"]:
            argument, nesting = [], 0
            for token in condition[2:-1] + [","]:
                if token == "," and nesting == 0:
                    test_only |= argument == ["test"]
                    argument = []
                else:
                    argument.append(token)
                    nesting += (token == "(") - (token == ")")
        if not test_only:
            index = closing + 1
            continue
        # Attributes also guard comma-terminated fields and arguments, not
        # only items/statements. Stop at a top-level comma rather than eating
        # the next production field or the enclosing body's closing token.
        # Angle brackets are deliberately not guessed as type vs comparison:
        # a generic comma can stop masking early, leaving the suffix checked.
        end_index = closing + 1
        stack = []
        saw_body = False
        pairs = {")": "(", "]": "[", "}": "{"}
        enclosing_boundary = False
        while end_index < len(tokens):
            token = values[end_index]
            if token in ("(", "[", "{"):
                if token == "{" and not stack:
                    saw_body = True
                stack.append(token)
            elif token in pairs:
                if not stack and not saw_body:
                    # The last cfg-gated parameter/field/argument need not
                    # have a trailing comma. Match its actual enclosing
                    # delimiter, which predates the attribute, and leave
                    # that delimiter outside the mask. Do not treat an
                    # arbitrary unmatched closer as a valid boundary.
                    preceding = []
                    for prior in reversed(values[:index]):
                        if prior in pairs:
                            preceding.append(pairs[prior])
                        elif prior in ("(", "[", "{"):
                            if not preceding:
                                enclosing_boundary = prior == pairs[token]
                                break
                            if preceding.pop() != prior:
                                break
                    if enclosing_boundary:
                        break
                if not stack or stack.pop() != pairs[token]:
                    syntax_fail("unbalanced test-only Rust item in source guard",
                                tokens[end_index][0])
                if saw_body and not stack:
                    break
            elif token in (";", ",") and not stack:
                break
            end_index += 1
        if end_index == len(tokens):
            syntax_fail("unterminated test-only Rust item in source guard",
                        tokens[index][0])
        mask(tokens[index][0], tokens[end_index][0 if enclosing_boundary else 1])
        index = end_index if enclosing_boundary else end_index + 1
    return "".join(masked)


def _excluded_graph_path(source_root: pathlib.Path, path: pathlib.Path) -> bool:
    relative_parts = path.relative_to(source_root).parts
    lowered_parts = tuple(part.lower() for part in relative_parts)
    if any(part in GRAPH_EXCLUDED_PARTS for part in lowered_parts):
        return True
    # Keep source-side test helpers and marker snapshots out even when they
    # are placed directly below a first-party source directory.
    filename = path.name.lower()
    return bool(
        re.search(
            r"(?:^|[._-])(test|tests|fixture|fixtures|snapshot|snapshots)(?:[._-]|$)",
            filename,
        )
    )


def iter_graph_files(source_root: pathlib.Path):
    """Yield first-party V4 source and manifest files.

    The graph intentionally excludes tests/fixtures and diagnostic marker
    inventories.  Production Rust is under crate ``src`` trees; the GUI
    consists of first-party ``gui/src`` TS/Svelte plus Tauri Rust; manifests
    are limited to the workspace and those first-party package trees.
    """

    for directory, directories, filenames in os.walk(source_root):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory.lower() not in GRAPH_EXCLUDED_PARTS
        )
        for filename in sorted(filenames):
            path = pathlib.Path(directory) / filename
            if _excluded_graph_path(source_root, path):
                continue
            relative = path.relative_to(source_root).parts
            suffix = path.suffix.lower()
            if path.name == "Cargo.toml":
                if relative == ("Cargo.toml",) or relative[0] == "crates" or relative[:2] == (
                    "gui",
                    "src-tauri",
                ):
                    yield path
                continue
            if suffix not in GRAPH_SOURCE_SUFFIXES:
                continue
            if relative[:1] == ("crates",) and "src" in relative:
                yield path
            elif relative[:3] == ("gui", "src-tauri", "src"):
                yield path
            elif relative[:2] == ("gui", "src") and suffix in {".ts", ".svelte"}:
                yield path


def scan_manifest_text(label: str, text: str) -> None:
    """Reject removed feature wiring while allowing explicit lab controls."""

    found = find_markers(label, text, LEGACY_MARKERS + CUSTOM_APPLICATION_RELAY_MARKERS)
    if found:
        fail(f"{label} contains removed surface(s): {', '.join(found)}")

    section = ""
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        header = re.match(r"\[([^]]+)\]", line)
        if header:
            section = header.group(1).strip().lower()
            continue

        lowered = line.lower()
        for marker in REMOVED_COMPATIBILITY_FEATURE_MARKERS:
            if re.search(
                rf"(?<![a-z0-9_-]){re.escape(marker)}(?![a-z0-9_-])", lowered
            ):
                fail(f"{label} contains removed compatibility feature: {marker}")

        if (
            section == "features"
            and re.match(r"default\s*=", lowered)
            and "transport-lab" in lowered
        ):
            fail(f"{label} enables transport-lab by default")

        if "transport-lab" in lowered:
            allowed = (
                section == "features"
                or "dev-dependencies" in section
                or "required-features" in lowered
            )
            if not allowed:
                fail(f"{label} leaks transport-lab through {section or 'package'}")

        if section == "features":
            feature = re.match(r"([a-zA-Z0-9_-]+)\s*=", line)
            if feature and re.search(
                r"(?:legacy|compat|v3)", feature.group(1), re.IGNORECASE
            ):
                fail(
                    f"{label} declares removed compatibility feature: {feature.group(1)}"
                )


def scan_source_tree(source_root: pathlib.Path) -> None:
    graph_files = list(iter_graph_files(source_root))
    source_files = [
        path for path in graph_files if path.suffix.lower() in GRAPH_SOURCE_SUFFIXES
    ]
    if not source_files:
        fail(f"source graph has no first-party source files: {source_root}")

    seen_current = {marker: False for marker in CURRENT_MARKERS}
    for path in graph_files:
        text = path.read_text(encoding="utf-8")
        if path.name == "Cargo.toml":
            scan_manifest_text(str(path), text)
        else:
            scan_source_text(str(path), text)
            for marker in CURRENT_MARKERS:
                seen_current[marker] |= marker in text

    missing = [marker for marker, present in seen_current.items() if not present]
    if missing:
        fail(f"source tree lacks current form(s): {', '.join(missing)}")


def scan_release_marker_inventory(path: pathlib.Path) -> None:
    if not path.is_file():
        fail(f"release marker inventory does not exist: {path}")
    text = path.read_text(encoding="utf-8")
    # This file is a deliberate diagnostic inventory: it must name the
    # forbidden bytes so the release-artifact scanner can reject them.  Do
    # not feed it back through the production-source absence gate.
    missing = [marker for marker in RELEASE_MARKER_POSITIVES if marker not in text]
    if missing:
        fail(f"release marker inventory lost required marker(s): {', '.join(missing)}")


def verify_tree(source_root: pathlib.Path, marker_inventory: pathlib.Path) -> None:
    scan_source_tree(source_root)
    scan_release_marker_inventory(marker_inventory)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--marker-inventory",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().with_name("verify-release-artifact.py"),
    )
    args = parser.parse_args()
    verify_tree(args.source_root, args.marker_inventory)
    print("V4 hard-cutover boundary: PASS")


if __name__ == "__main__":
    main()
