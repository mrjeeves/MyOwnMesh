#!/usr/bin/env python3
"""Prove the source-level boundaries of the V4 Arc 02 authority spine."""

from __future__ import annotations

import argparse
import copy
import functools
import hashlib
import re
import sys
import tomllib
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
CORE_SRC = REPO / "crates" / "myownmesh-core" / "src"
CORE_MANIFEST = REPO / "crates" / "myownmesh-core" / "Cargo.toml"

TYPE_OWNERS = {
    "CandidateCapability": "runtime/attempt/mod.rs",
    "ConnectedChannelCapability": "connector/mod.rs",
    "AuthenticatedChannelCapability": "endpoint_auth/mod.rs",
    "SessionCapability": "runtime/session_broker/mod.rs",
    "LocalPrincipalCapability": "application_gateway/mod.rs",
    "PreAuthAttemptPermit": "runtime/attempt/mod.rs",
    "EndpointAuthPermit": "endpoint_auth/mod.rs",
    "SessionPermit": "runtime/session_broker/mod.rs",
    "RelayAllocationPermit": "runtime/relay/mod.rs",
    "ApplicationQueuePermit": "application_gateway/mod.rs",
}

EXPECTED_FIELDS = {
    "PreAuthAttemptPermit": {
        "attempt": "Arc<AttemptOwnership>",
        "aggregate": "Arc<AggregateReservation>",
    },
    "CandidateCapability": {
        "attempt": "Arc<AttemptOwnership>",
        "reservation": "CandidateReservation",
    },
    "ConnectedChannelCapability": {"candidate": "CandidateCapability"},
    "EndpointAuthPermit": {"runtime": "RuntimeIncarnation"},
    "AuthenticatedChannelCapability": {
        "connected": "ConnectedChannelCapability",
        "permit": "EndpointAuthPermit",
    },
    "SessionPermit": {"runtime": "RuntimeIncarnation"},
    "LocalPrincipalCapability": {"runtime": "RuntimeIncarnation"},
    "SessionCapability": {
        "authenticated_channel": "AuthenticatedChannelCapability",
        "local_principal": "LocalPrincipalCapability",
        "permit": "SessionPermit",
    },
    "RelayAllocationPermit": {"runtime": "RuntimeIncarnation"},
    "ApplicationQueuePermit": {"runtime": "RuntimeIncarnation"},
}

MODULE_EXPORTS = {
    "application_gateway",
    "connector",
    "endpoint_auth",
    "resource",
    "runtime",
}

BOUNDARIES = {
    "application_gateway/BOUNDARY.md",
    "connector/BOUNDARY.md",
    "endpoint_auth/BOUNDARY.md",
    "resource/BOUNDARY.md",
    "runtime/attempt/BOUNDARY.md",
    "runtime/relay/BOUNDARY.md",
    "runtime/session_broker/BOUNDARY.md",
}

COMPILE_FAIL_FENCES = {
    "runtime/attempt/mod.rs": 1,
    "connector/mod.rs": 1,
    "endpoint_auth/mod.rs": 1,
    "application_gateway/mod.rs": 1,
    "runtime/session_broker/mod.rs": 4,
}

LEGACY_WRAPPERS = {
    "LegacyCandidate": ("runtime/attempt/mod.rs", "CandidateCapability"),
    "LegacyConnectedChannel": ("connector/mod.rs", "ConnectedChannelCapability"),
    "LegacyAuthenticatedChannel": (
        "endpoint_auth/mod.rs",
        "AuthenticatedChannelCapability",
    ),
    "LegacySession": ("runtime/session_broker/mod.rs", "SessionCapability"),
    "LegacyPrincipal": ("application_gateway/mod.rs", "LocalPrincipalCapability"),
}

PROTECTED_TYPES = set(TYPE_OWNERS) | set(LEGACY_WRAPPERS) | {"RuntimeIncarnation"}
AUTHORITY_OWNER_MODULES = set(TYPE_OWNERS.values()) | {"runtime/mod.rs"}
LEAF_AUTHORITY_OWNER_MODULES = set(TYPE_OWNERS.values())
PILOT_SOURCES = {
    "engine/connection.rs",
    "engine/mod.rs",
    "engine/state.rs",
    "handle.rs",
}

PROTECTED_PRODUCTION_FINGERPRINTS = {
    "lib.rs": "a959b670159fb39b083daa969bc852a36c70e2ed05b9ae6a98a06f8eb0fb4ecc",
    "application_gateway/mod.rs": "fdeb6156d7a02f96992e2eff4200c4058b213892f2109c28d619330e3d82d3c2",
    "connector/mod.rs": "3a3a23a98208be249a874ed3217c303ffada45a8fcbb64bca0e10c14f381c85b",
    "endpoint_auth/mod.rs": "d7de05bbb7d4b95c8db451474c99ea723e74a6a38783356dc732ae40749d34a5",
    "runtime/attempt/mod.rs": "3b95ace7c758f722ecb7214dc9640e028524d683be99b7463d3c34b6000e33f1",
    "runtime/mod.rs": "aeb6a2bf2fd12df877eb4e02c7c924ce164b07e7db31db457b16f6a4303988d1",
    "runtime/relay/mod.rs": "4652f8fb1a327152c32532f2ef86e26d05b2056321c053684779dbfa438475e6",
    "runtime/session_broker/mod.rs": "31d52ee33c76214123316783e33c3f0003e16f66ab3f2a3200aa81d19ddc9686",
}

FORBIDDEN_TRAITS = {"Clone", "Copy", "Default", "Deserialize", "Serialize"}

PRE_AUTH_FAMILIES = {
    "AcceptedConnection",
    "HalfOpenHandshake",
    "FrameBytes",
    "ParserBytes",
    "DurableFactHashWork",
    "DurableFactSignatureWork",
    "EphemeralSignalingParseWork",
    "CandidateObject",
    "Socket",
    "TransportObject",
    "DnsWork",
    "StunWork",
    "IceWork",
    "RelayWork",
    "ConnectorSpecificWork",
    "MediaQuarantine",
    "PacketQuarantine",
    "Timer",
    "Task",
    "Callback",
    "DiagnosticQueue",
    "Cleanup",
}

POST_AUTH_FAMILIES = {
    "AuthenticatedSession",
    "ApplicationQueue",
    "MediaDecode",
    "MediaEncode",
    "RelayBandwidth",
    "RelayBuffer",
    "SessionRecovery",
    "ApplicationCallback",
    "LocalHandle",
    "SubscriptionState",
}


def mask_rust(text: str) -> str:
    """Mask comments and literals while preserving offsets and newlines."""

    out = list(text)
    cursor = 0
    while cursor < len(text):
        if text.startswith("//", cursor):
            end = text.find("\n", cursor)
            end = len(text) if end < 0 else end
            for pos in range(cursor, end):
                out[pos] = " "
            cursor = end
            continue
        if text.startswith("/*", cursor):
            depth = 1
            end = cursor + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            for pos in range(cursor, end):
                if out[pos] != "\n":
                    out[pos] = " "
            cursor = end
            continue

        raw = (
            re.match(r'(?:br|r)(?P<hashes>#{0,16})"', text[cursor:])
            if text[cursor] in {"b", "r"}
            else None
        )
        if raw:
            close = '"' + raw.group("hashes")
            end = text.find(close, cursor + raw.end())
            end = len(text) if end < 0 else end + len(close)
            for pos in range(cursor, end):
                if out[pos] != "\n":
                    out[pos] = " "
            cursor = end
            continue

        quote = cursor + 1 if text.startswith('b"', cursor) else cursor
        if quote < len(text) and text[quote] == '"':
            end = quote + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == '"':
                    end += 1
                    break
                end += 1
            for pos in range(cursor, end):
                if out[pos] != "\n":
                    out[pos] = " "
            cursor = end
            continue

        if text[cursor] == "'":
            character = re.match(r"'(?:\\.|[^\\'\n])'", text[cursor:])
            if character:
                end = cursor + character.end()
                for pos in range(cursor, end):
                    out[pos] = " "
                cursor = end
                continue
        cursor += 1
    masked = "".join(out)
    return re.sub(r"\br#(?=[A-Za-z_]\w*)", "  ", masked)


def matching_brace(masked: str, opening: int) -> int:
    depth = 0
    for pos in range(opening, len(masked)):
        if masked[pos] == "{":
            depth += 1
        elif masked[pos] == "}":
            depth -= 1
            if depth == 0:
                return pos
    raise ValueError(f"unclosed brace at byte {opening}")


def blank_range(chars: list[str], start: int, end: int) -> None:
    for pos in range(start, end):
        if chars[pos] != "\n":
            chars[pos] = " "


def production_text(text: str) -> str:
    """Remove items guarded by cfg(test) before checking production authority."""

    masked = mask_rust(text)
    chars = list(text)
    cfg_test = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    for match in cfg_test.finditer(masked):
        cursor = match.end()
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        brace = masked.find("{", cursor)
        semi = masked.find(";", cursor)
        if semi >= 0 and (brace < 0 or semi < brace):
            blank_range(chars, match.start(), semi + 1)
        elif brace >= 0:
            blank_range(chars, match.start(), matching_brace(masked, brace) + 1)
    return "".join(chars)


def production_fingerprint(text: str) -> str:
    tokens = re.sub(r"\s+", "", mask_rust(production_text(text)))
    return hashlib.sha256(tokens.encode("utf-8")).hexdigest()


def struct_scope(text: str, name: str, masked: str | None = None) -> tuple[str, str]:
    """Return adjacent attributes and the body of one named struct."""

    masked = mask_rust(text) if masked is None else masked
    declaration = re.compile(
        rf"(?m)^(?P<attrs>(?:[ \t]*#\s*\[[^\]\n]*\][ \t]*\r?\n)*)"
        rf"[ \t]*(?P<vis>pub(?:\s*\([^)]*\))?\s+)?"
        rf"struct\s+{re.escape(name)}\b[^{{;]*\{{"
    )
    matches = list(declaration.finditer(masked))
    if len(matches) != 1:
        raise ValueError(f"expected one struct {name}, found {len(matches)}")
    opening = masked.find("{", matches[0].start())
    closing = matching_brace(masked, opening)
    return text[matches[0].start() : opening], text[opening + 1 : closing]


def struct_fields(body: str) -> dict[str, tuple[str, str]]:
    """Read the simple named fields used by the Arc 02 authority structs."""

    fields: dict[str, tuple[str, str]] = {}
    for match in re.finditer(
        r"(?m)^\s*(?P<vis>pub(?:\s*\([^)]*\))?\s+)?"
        r"(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<type>[^,\n]+)\s*,?",
        mask_rust(body),
    ):
        fields[match.group("name")] = (
            (match.group("vis") or "").strip(),
            re.sub(r"\s+", "", match.group("type")),
        )
    return fields


def enum_variants(text: str, name: str) -> set[str]:
    masked = mask_rust(text)
    declaration = re.search(rf"\benum\s+{re.escape(name)}\b[^{{;]*\{{", masked)
    if declaration is None:
        raise ValueError(f"missing enum {name}")
    opening = masked.find("{", declaration.start())
    closing = matching_brace(masked, opening)
    body = masked[opening + 1 : closing]
    return set(re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s*(?:,|\(|\{)", body))


def struct_literal_count(masked: str, type_name: str) -> int:
    """Count named struct expressions without counting declarations or returns."""

    count = 0
    for match in re.finditer(rf"\b{re.escape(type_name)}\s*\{{", masked):
        boundary = max(
            masked.rfind(";", 0, match.start()),
            masked.rfind("{", 0, match.start()),
            masked.rfind("}", 0, match.start()),
        )
        prefix = masked[boundary + 1 : match.start()]
        if not re.search(r"\b(?:struct|impl|fn)\b", prefix):
            count += 1
    return count


def inherent_impl_bodies(masked: str, type_name: str) -> list[str]:
    declarations = list(
        re.finditer(
            rf"\bimpl(?:\s*<[^{{}};]*>)?\s+"
            rf"(?:\s*\(\s*)*(?:::)?(?:[A-Za-z_]\w*\s*::\s*)*"
            rf"{re.escape(type_name)}(?:\s*<[^{{}};]*>)?"
            rf"(?:\s*\)\s*)*(?:\s+where\s+[^{{}};]*)?\s*\{{",
            masked,
        )
    )
    bodies = []
    for declaration in declarations:
        opening = masked.find("{", declaration.start())
        bodies.append(masked[opening + 1 : matching_brace(masked, opening)])
    return bodies


def function_signatures(masked: str) -> list[tuple[str, str, str]]:
    """Return visibility, name, and return type for functions with bodies."""

    signatures: list[tuple[str, str, str]] = []
    pattern = re.compile(
        r"\b(?P<vis>pub(?:\s*\([^)]*\))?\s+)?"
        r"(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
        r"fn\s+(?P<name>[A-Za-z_]\w*)\b(?P<signature>[^;{}]*)\{"
    )
    for match in pattern.finditer(masked):
        signature = match.group("signature")
        return_match = re.search(r"->\s*(?P<return>.*?)(?:\bwhere\b|$)", signature)
        returns = return_match.group("return").strip() if return_match else ""
        signatures.append(((match.group("vis") or "").strip(), match.group("name"), returns))
    return signatures


def returns_owned_type(return_type: str, type_name: str) -> bool:
    without_references = re.sub(
        rf"&\s*(?:'[A-Za-z_]\w*\s*)?(?:mut\s+)?"
        rf"(?:[A-Za-z_]\w*\s*::\s*)*{re.escape(type_name)}\b",
        "",
        return_type,
    )
    return bool(re.search(rf"\b{re.escape(type_name)}\b", without_references))


def trait_impl_headers(masked: str) -> list[str]:
    return [
        match.group("header")
        for match in re.finditer(r"\bimpl\b(?P<header>[^;{}]*)\{", masked)
        if re.search(r"\bfor\b", match.group("header"))
    ]


def load_sources() -> dict[str, str]:
    paths = (
        set(TYPE_OWNERS.values())
        | {"runtime/mod.rs", "resource/mod.rs", "lib.rs"}
        | PILOT_SOURCES
    )
    return {
        path: (CORE_SRC / path).read_text(encoding="utf-8")
        for path in sorted(paths)
    }


def validate_core_manifest(text: str) -> list[str]:
    try:
        manifest = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [f"core manifest is not valid TOML: {error}"]

    errors = []
    if manifest.get("package", {}).get("name") != "myownmesh-core":
        errors.append("core manifest package name changed")
    expected_library = {"name": "myownmesh_core", "path": "src/lib.rs"}
    if manifest.get("lib") != expected_library:
        errors.append(
            "core manifest library target must remain exactly "
            "name=myownmesh_core and path=src/lib.rs"
        )
    return errors


@functools.lru_cache(maxsize=1)
def workspace_production_sources() -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted((REPO / "crates").glob("*/src/**/*.rs")):
        key = path.relative_to(REPO).as_posix()
        result[key] = production_text(path.read_text(encoding="utf-8"))
    return result


@functools.lru_cache(maxsize=1)
def workspace_production_masked_sources() -> dict[str, str]:
    return {
        path: mask_rust(text)
        for path, text in workspace_production_sources().items()
    }


def validate(sources: dict[str, str], boundaries: set[str]) -> list[str]:
    errors: list[str] = []
    production = {path: production_text(text) for path, text in sources.items()}
    production_masked = {path: mask_rust(text) for path, text in production.items()}
    workspace_masked = dict(workspace_production_masked_sources())
    for path, text in production_masked.items():
        workspace_path = f"crates/myownmesh-core/src/{path}"
        workspace_masked[workspace_path] = text

    for owner, expected in PROTECTED_PRODUCTION_FINGERPRINTS.items():
        actual = production_fingerprint(sources[owner])
        if actual != expected:
            errors.append(
                f"{owner}: production source fingerprint changed, expected {expected}, "
                f"found {actual}"
            )

    protected_pattern = "|".join(re.escape(name) for name in sorted(PROTECTED_TYPES))
    protected_reference = re.compile(rf"\b(?:{protected_pattern})\b")
    protected_workspace_masked = {
        path: text
        for path, text in workspace_masked.items()
        if protected_reference.search(text)
    }
    type_alias = re.compile(
        r"\btype\s+(?P<alias>[A-Za-z_]\w*)"
        r"(?:\s*<[^;{}]*>)?(?:\s+where\s+[^;{}=]*)?\s*=\s*"
        r"(?P<target>[^;]+);"
    )
    renamed_import = re.compile(
        rf"\b(?P<target>{protected_pattern})\s+as\s+(?P<alias>[A-Za-z_]\w*)\b"
    )
    for path, text in protected_workspace_masked.items():
        for declaration in type_alias.finditer(text):
            target = declaration.group("target")
            protected = re.search(rf"\b(?:{protected_pattern})\b", target)
            if protected:
                errors.append(
                    f"{path}: type alias {declaration.group('alias')} aliases protected "
                    f"authority or wrapper type {protected.group(0)}"
                )
        for alias in renamed_import.finditer(text):
            errors.append(
                f"{path}: renamed import {alias.group('alias')} aliases protected "
                f"authority or wrapper type {alias.group('target')}"
            )

    macro_definition = re.compile(r"\bmacro_rules\s*!\s*[A-Za-z_]\w*")
    macro_invocation = re.compile(
        r"\b(?:[A-Za-z_]\w*\s*::\s*)*[A-Za-z_]\w*\s*!\s*[({\[]"
    )
    attribute = re.compile(r"#\s*\[\s*(?P<name>[A-Za-z_]\w*)")
    child_module = re.compile(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_]\w*\s*(?:;|\{)"
    )
    for owner in sorted(AUTHORITY_OWNER_MODULES):
        owner_source = production_masked[owner]
        if macro_definition.search(owner_source) or macro_invocation.search(owner_source):
            errors.append(
                f"{owner}: production code-generating macros are forbidden in an "
                "authority-owner module"
            )
        attributes = [match.group("name") for match in attribute.finditer(owner_source)]
        unexpected_attributes = sorted(set(attributes) - {"allow", "derive"})
        if unexpected_attributes:
            errors.append(
                f"{owner}: production code-generating attributes are forbidden in an "
                f"authority-owner module: {unexpected_attributes}"
            )
        derive_count = attributes.count("derive")
        expected_derive_count = 1 if owner == "runtime/mod.rs" else 0
        if derive_count != expected_derive_count:
            errors.append(
                f"{owner}: expected {expected_derive_count} reviewed derive attribute(s), "
                f"found {derive_count}"
            )
        if owner in LEAF_AUTHORITY_OWNER_MODULES and child_module.search(owner_source):
            errors.append(
                f"{owner}: authority owner must remain a leaf module so descendants "
                "cannot mint or expose private authority"
            )

    lib = production["lib.rs"]
    lib_masked = mask_rust(lib)
    if re.search(r"#\s*\[[^\]]*\bpath\b[^\]]*\]", lib_masked):
        errors.append("core library uses a forbidden path redirection attribute")
    for module in sorted(MODULE_EXPORTS):
        declarations = re.findall(
            rf"(?m)^pub\s+mod\s+{re.escape(module)}\s*;\s*$", lib_masked
        )
        if len(declarations) != 1:
            errors.append(f"core library does not export Arc 02 module {module}")

    for boundary in sorted(BOUNDARIES):
        if boundary not in boundaries:
            errors.append(f"target module lacks BOUNDARY.md: {boundary}")

    for owner, expected_count in COMPILE_FAIL_FENCES.items():
        actual_count = len(re.findall(r"```compile_fail(?:,[A-Z]\d+)?", sources[owner]))
        if actual_count != expected_count:
            errors.append(
                f"{owner}: expected {expected_count} compile-fail controls, "
                f"found {actual_count}"
            )

    for type_name, owner in TYPE_OWNERS.items():
        source = production[owner]
        try:
            heading, body = struct_scope(source, type_name, production_masked[owner])
        except ValueError as error:
            errors.append(f"{owner}: {error}")
            continue

        derives = set()
        for derive in re.findall(r"derive\s*\(([^)]*)\)", heading):
            derives.update(part.strip().split("::")[-1] for part in derive.split(","))
        forbidden_derives = sorted(derives & FORBIDDEN_TRAITS)
        if forbidden_derives:
            errors.append(
                f"{owner}: {type_name} derives forbidden authority traits "
                f"{', '.join(forbidden_derives)}"
            )

        fields = struct_fields(body)
        expected = EXPECTED_FIELDS[type_name]
        actual_names = set(fields)
        if actual_names != set(expected):
            errors.append(
                f"{owner}: {type_name} fields changed, expected "
                f"{sorted(expected)}, found {sorted(actual_names)}"
            )
        for field_name, expected_type in expected.items():
            if field_name not in fields:
                continue
            visibility, actual_type = fields[field_name]
            if visibility:
                errors.append(
                    f"{owner}: {type_name}.{field_name} exposes authority as {visibility}"
                )
            if actual_type != expected_type:
                errors.append(
                    f"{owner}: {type_name}.{field_name} expected {expected_type}, "
                    f"found {actual_type}"
                )

        trait_impl = re.compile(
            rf"\bimpl(?:\s*<[^>{{}}]*>)?\s+"
            rf"(?P<trait>Clone|Copy|Default|Serialize|Deserialize|From\s*<|TryFrom\s*<)"
            rf"[^{{;]*\bfor\s+{re.escape(type_name)}\b"
        )
        match = trait_impl.search(production_masked[owner])
        if match:
            errors.append(
                f"{owner}: {type_name} has forbidden authority conversion or trait "
                f"{match.group('trait')}"
            )

        if re.search(
            rf"\bunsafe\b[^;{{}}]*\b{re.escape(type_name)}\b",
            production_masked[owner],
        ):
            errors.append(f"{owner}: unsafe authority construction mentions {type_name}")

    for type_name in TYPE_OWNERS:
        conversion = re.compile(
            rf"\bimpl(?:\s*<[^>{{}}]*>)?\s+"
            rf"(?:From|TryFrom)\s*<[^>]+>\s+for\s+"
            rf"(?:[A-Za-z_]\w*\s*::\s*)*{re.escape(type_name)}\b"
        )
        if any(conversion.search(text) for text in protected_workspace_masked.values()):
            errors.append(f"{type_name} has a production From or TryFrom conversion")

        forbidden_impl = re.compile(
            rf"\bimpl(?:\s*<[^>{{}}]*>)?\s+[^;{{}}]*"
            rf"\b(?:Clone|Copy|Default|Deserialize|Serialize)\b"
            rf"(?:\s*<[^>{{}}]*>)?\s+for\s+"
            rf"(?:[A-Za-z_]\w*\s*::\s*)*{re.escape(type_name)}\b"
        )
        if any(forbidden_impl.search(text) for text in protected_workspace_masked.values()):
            errors.append(f"{type_name} has a forbidden production trait implementation")

        trait_owners = [
            path
            for path, text in protected_workspace_masked.items()
            for header in trait_impl_headers(text)
            if re.search(rf"\b{re.escape(type_name)}\b", header)
        ]
        if trait_owners:
            errors.append(
                f"{type_name} appears in a production trait implementation: "
                f"{sorted(set(trait_owners))}"
            )

        inherent_impl_owners = []
        inherent_impl = re.compile(
            rf"\bimpl(?:\s*<[^{{}};]*>)?\s+"
            rf"(?:\s*\(\s*)*(?:::)?(?:[A-Za-z_]\w*\s*::\s*)*"
            rf"{re.escape(type_name)}(?:\s*<[^{{}};]*>)?"
            rf"(?:\s*\)\s*)*(?:\s+where\s+[^{{}};]*)?\s*\{{"
        )
        for path, text in protected_workspace_masked.items():
            if inherent_impl.search(text):
                inherent_impl_owners.append(path)
        expected_owner = f"crates/myownmesh-core/src/{TYPE_OWNERS[type_name]}"
        if any(path != expected_owner for path in inherent_impl_owners):
            errors.append(
                f"{type_name} has an inherent implementation outside its owner: "
                f"{sorted(inherent_impl_owners)}"
            )

        unsafe_forge = re.compile(
            rf"\b(?:transmute|MaybeUninit|assume_init|zeroed)\b[^;{{}}]*"
            rf"\b{re.escape(type_name)}\b|"
            rf"\b{re.escape(type_name)}\b[^;{{}}]*"
            rf"\b(?:transmute|MaybeUninit|assume_init|zeroed)\b"
        )
        if any(unsafe_forge.search(text) for text in protected_workspace_masked.values()):
            errors.append(f"{type_name} appears in an unsafe construction pattern")

    session_source = production_masked[TYPE_OWNERS["SessionCapability"]]
    session_literals = struct_literal_count(session_source, "SessionCapability")
    if session_literals:
        errors.append(
            "Session Broker production source contains "
            f"{session_literals} SessionCapability struct literal(s)"
        )
    visible_session_mint = re.compile(
        r"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+)?fn\s+[A-Za-z_]\w*"
        r"[^;{]*->\s*(?:[A-Za-z_:<>]+\s*)?SessionCapability\b"
    )
    if visible_session_mint.search(session_source):
        errors.append("SessionCapability has a public or crate-visible production mint")
    session_impls = inherent_impl_bodies(session_source, "SessionCapability")
    if not session_impls:
        errors.append("runtime/session_broker/mod.rs: missing SessionCapability impl")
    for session_impl in session_impls:
        if struct_literal_count(session_impl, "Self"):
            errors.append("SessionCapability inherent impl contains a production Self mint")
        for visibility, function, return_type in function_signatures(session_impl):
            if visibility and re.search(r"\bSelf\b", return_type):
                errors.append(
                    "SessionCapability has a visible Self-returning production method: "
                    f"{function}"
                )
    for visibility, function, return_type in function_signatures(session_source):
        if visibility and returns_owned_type(return_type, "SessionCapability"):
            errors.append(
                "SessionCapability has a visible value-returning production function: "
                f"{function}"
            )

    runtime_source = production_masked["runtime/mod.rs"]
    if not re.search(r"pub\s*\(\s*crate\s*\)\s+struct\s+RuntimeIncarnation", runtime_source):
        errors.append("RuntimeIncarnation must remain crate-private")
    if re.search(
        r"\bpub(?:\s*\([^)]*\))?\s+fn\s+new\s*\([^)]*\)\s*->\s*Self",
        runtime_source,
    ):
        errors.append("RuntimeIncarnation has a visible production constructor")
    try:
        runtime_heading, runtime_fields_body = struct_scope(
            production["runtime/mod.rs"],
            "RuntimeIncarnation",
            production_masked["runtime/mod.rs"],
        )
    except ValueError as error:
        errors.append(f"runtime/mod.rs: {error}")
    else:
        runtime_derives = set()
        for derive in re.findall(r"derive\s*\(([^)]*)\)", runtime_heading):
            runtime_derives.update(part.strip().split("::")[-1] for part in derive.split(","))
        unexpected_runtime_derives = sorted(runtime_derives - {"Clone"})
        if unexpected_runtime_derives:
            errors.append(
                "RuntimeIncarnation derives constructor or wire traits: "
                f"{unexpected_runtime_derives}"
            )
        runtime_fields = struct_fields(runtime_fields_body)
        if runtime_fields != {"marker": ("", "Arc<RuntimeMarker>")}:
            errors.append(
                "RuntimeIncarnation field boundary changed: "
                f"{runtime_fields}"
            )
    if not re.search(r"(?m)^\s*struct\s+RuntimeMarker\s*;", runtime_source):
        errors.append("RuntimeMarker must remain private")
    runtime_trait_owners = [
        path
        for path, text in protected_workspace_masked.items()
        for header in trait_impl_headers(text)
        if re.search(r"\bRuntimeIncarnation\b", header)
    ]
    if runtime_trait_owners:
        errors.append(
            "RuntimeIncarnation appears in a production trait implementation: "
            f"{sorted(set(runtime_trait_owners))}"
        )
    for visibility, function, return_type in function_signatures(runtime_source):
        if visibility and returns_owned_type(return_type, "RuntimeIncarnation"):
            errors.append(
                "RuntimeIncarnation has a visible value-returning production function: "
                f"{function}"
            )
    runtime_impls = inherent_impl_bodies(runtime_source, "RuntimeIncarnation")
    if len(runtime_impls) != 1:
        errors.append(
            "RuntimeIncarnation must have exactly one owner-local inherent impl, "
            f"found {len(runtime_impls)}"
        )
    elif struct_literal_count(runtime_impls[0], "Self") != 1:
        errors.append(
            "RuntimeIncarnation inherent impl must contain exactly one private Self mint"
        )
    runtime_constructor_call = re.compile(r"\bRuntimeIncarnation\s*::\s*new\s*\(")
    constructor_callers = [
        path
        for path, text in protected_workspace_masked.items()
        if runtime_constructor_call.search(text)
    ]
    if constructor_callers:
        errors.append(
            "RuntimeIncarnation is constructed outside test scaffolding: "
            f"{sorted(constructor_callers)}"
        )
    runtime_owner = "crates/myownmesh-core/src/runtime/mod.rs"
    literal_callers = [
        path
        for path, text in protected_workspace_masked.items()
        if path != runtime_owner and struct_literal_count(text, "RuntimeIncarnation")
    ]
    if literal_callers:
        errors.append(
            "RuntimeIncarnation has an off-owner struct literal: "
            f"{sorted(literal_callers)}"
        )
    if struct_literal_count(runtime_source, "RuntimeIncarnation"):
        errors.append("RuntimeIncarnation has a named production struct literal")

    resource_source = production["resource/mod.rs"]
    resource_masked = mask_rust(resource_source)
    for enum_name, expected in (
        ("PreAuthResourceFamily", PRE_AUTH_FAMILIES),
        ("PostAuthResourceFamily", POST_AUTH_FAMILIES),
    ):
        try:
            actual = enum_variants(resource_source, enum_name)
        except ValueError as error:
            errors.append(f"resource/mod.rs: {error}")
            continue
        if actual != expected:
            errors.append(
                f"resource/mod.rs: {enum_name} closed family changed, expected "
                f"{sorted(expected)}, found {sorted(actual)}"
            )

    process_root = re.compile(
        r"(?m)^\s*static\s+PROCESS_RESOURCE_ROOT\s*:\s*"
        r"OnceLock\s*<\s*ResourceAccountant\s*>\s*=\s*OnceLock\s*::\s*new\s*\(\s*\)\s*;"
    )
    all_statics = list(re.finditer(r"(?m)^\s*(?:pub\s+)?static\s+[^;]+;", resource_masked))
    if len(process_root.findall(resource_masked)) != 1 or len(all_statics) != 1:
        errors.append(
            "resource/mod.rs: exactly one typed process observation root is required"
        )
    if re.search(r"\b(?:LazyLock|thread_local)\b", resource_masked):
        errors.append("resource/mod.rs: unexpected process-global accounting state")
    if re.search(
        r"\b(?:admit|allow|authorize|deny|limit|permit|reject|reserve)\w*\b",
        resource_masked,
        re.IGNORECASE,
    ):
        errors.append("resource/mod.rs: observation code contains resource-policy vocabulary")
    if re.search(
        r"\b(?:std::net|tokio|TcpStream|TcpListener|UdpSocket|Command::new|fs::)",
        resource_masked,
    ):
        errors.append("resource/mod.rs: observation code performs an external operation")

    for struct_name, expected_names in (
        (
            "ResourceUse",
            {"items", "logical_bytes", "retained_bytes", "tasks"},
        ),
        (
            "ResourceFamilyReport",
            {
                "family",
                "active",
                "peak_active",
                "active_lease_count",
                "peak_active_lease_count",
                "oldest_active_lifetime",
                "oldest_active_lifetime_inexact",
                "completed_lease_count",
                "completed_total_use",
                "completed_total_lifetime",
                "measurement_inexact",
            },
        ),
        ("ResourceReport", {"pre_authentication", "post_authentication"}),
    ):
        try:
            _, body = struct_scope(
                resource_source,
                struct_name,
                production_masked["resource/mod.rs"],
            )
        except ValueError as error:
            errors.append(f"resource/mod.rs: {error}")
            continue
        actual_names = set(struct_fields(body))
        if actual_names != expected_names:
            errors.append(
                f"resource/mod.rs: {struct_name} report shape changed, expected "
                f"{sorted(expected_names)}, found {sorted(actual_names)}"
            )

    for method in ("observe_pre_authentication", "observe_post_authentication"):
        if not re.search(
            rf"\bpub\s+fn\s+{method}\s*\([^{{;]*\)\s*->\s*ObservationLease\b",
            resource_masked,
        ):
            errors.append(f"resource/mod.rs: {method} must return ObservationLease")

    for scope_name in (
        "ProcessResourceRoot",
        "MeshRuntimeResourceScope",
        "NetworkInstanceResourceScope",
        "PeerConnectionResourceScope",
    ):
        try:
            _, body = struct_scope(resource_source, scope_name, resource_masked)
        except ValueError as error:
            errors.append(f"resource/mod.rs: {error}")
            continue
        if struct_fields(body) != {"accountant": ("", "ResourceAccountant")}:
            errors.append(
                f"resource/mod.rs: {scope_name} must contain only one private accountant"
            )

    hierarchy_links = (
        ("ProcessResourceRoot", "mesh_runtime_scope", "MeshRuntimeResourceScope"),
        (
            "MeshRuntimeResourceScope",
            "network_instance_scope",
            "NetworkInstanceResourceScope",
        ),
        (
            "NetworkInstanceResourceScope",
            "peer_connection_scope",
            "PeerConnectionResourceScope",
        ),
    )
    for owner, method, child in hierarchy_links:
        if not re.search(
            rf"impl\s+{owner}\s*\{{[\s\S]*?fn\s+{method}\s*\([^)]*\)\s*->\s*{child}\b",
            resource_masked,
        ):
            errors.append(
                f"resource/mod.rs: missing fixed hierarchy link {owner}::{method} -> {child}"
            )
    ancestor_walk = re.compile(
        r"fn\s+for_each_scope\s*\([^{}]*\)\s*\{\s*"
        r"for\s+scope\s+in\s+self\s*\.\s*ancestors\s*\.\s*iter\s*\(\s*\)\s*\{\s*"
        r"update\s*\(\s*scope\s*\)\s*;\s*\}\s*"
        r"update\s*\(\s*&\s*self\s*\.\s*leaf\s*\)\s*;\s*\}"
    )
    if not ancestor_walk.search(resource_masked) or len(
        re.findall(r"self\s*\.\s*for_each_scope\s*\(", resource_masked)
    ) != 3:
        errors.append("resource/mod.rs: leaf observations do not update their ancestor path")

    if re.search(r"\b(?:BTreeMap|Hierarchy|active_starts|lock_transaction)\b", resource_masked):
        errors.append("resource/mod.rs: observer metadata or hierarchy lock is not bounded")
    try:
        _, accountant_body = struct_scope(resource_source, "ResourceAccountant", resource_masked)
        _, state_body = struct_scope(resource_source, "State", resource_masked)
        _, family_body = struct_scope(resource_source, "FamilyState", resource_masked)
    except ValueError as error:
        errors.append(f"resource/mod.rs: {error}")
    else:
        if struct_fields(accountant_body) != {
            "ancestors": ("", "Arc<[Arc<Inner>]>"),
            "leaf": ("", "Arc<Inner>"),
        }:
            errors.append("resource/mod.rs: observer path metadata must remain fixed and lock-free")
        state_fields = struct_fields(state_body)
        if state_fields.get("pre_authentication") != (
            "",
            "[FamilyState;PRE_AUTH_RESOURCE_FAMILY_COUNT]",
        ) or state_fields.get("post_authentication") != (
            "",
            "[FamilyState;POST_AUTH_RESOURCE_FAMILY_COUNT]",
        ):
            errors.append("resource/mod.rs: observer families must use fixed-size storage")
        if re.search(r"\b(?:Vec|HashMap|BTreeMap|DashMap|LinkedList|VecDeque)\b", family_body):
            errors.append("resource/mod.rs: active-lease metadata must remain constant-space")

    for owner in ("resource/mod.rs", "engine/connection.rs"):
        if re.search(r"\b(?:expect|unwrap)\s*\(|\bpanic\s*!", production_masked[owner]):
            errors.append(f"{owner}: production resource measurement contains a panic path")

    connection_source = production["engine/connection.rs"]
    connection_masked = production_masked["engine/connection.rs"]
    engine_masked = production_masked["engine/mod.rs"]
    state_masked = production_masked["engine/state.rs"]
    try:
        peer_heading, peer_body = struct_scope(
            connection_source, "PeerStateData", connection_masked
        )
    except ValueError as error:
        errors.append(f"engine/connection.rs: {error}")
    else:
        peer_derives = {
            part.strip().split("::")[-1]
            for derive in re.findall(r"derive\s*\(([^)]*)\)", peer_heading)
            for part in derive.split(",")
        }
        if "Clone" in peer_derives:
            errors.append("engine/connection.rs: PeerStateData must not derive Clone")
        pending_field = struct_fields(peer_body).get("pending_remote_candidates")
        if pending_field != ("", "PendingRemoteCandidateQueue"):
            errors.append(
                "engine/connection.rs: pending_remote_candidates must be a private observed queue"
            )
    peer_clone_impl = re.compile(
        r"\bimpl(?:\s*<[^>{}]*>)?\s+Clone\s+for\s+"
        r"(?:[A-Za-z_]\w*\s*::\s*)*PeerStateData\b"
    )
    if any(peer_clone_impl.search(text) for text in workspace_masked.values()):
        errors.append("engine/connection.rs: PeerStateData must not implement Clone")

    try:
        snapshot_heading, snapshot_body = struct_scope(
            connection_source, "PeerStateSnapshot", connection_masked
        )
    except ValueError as error:
        errors.append(f"engine/connection.rs: {error}")
    else:
        snapshot_derives = {
            part.strip().split("::")[-1]
            for derive in re.findall(r"derive\s*\(([^)]*)\)", snapshot_heading)
            for part in derive.split(",")
        }
        if "Clone" not in snapshot_derives:
            errors.append("engine/connection.rs: read-only peer snapshot must be clonable")
        if not re.search(r"\bpub\s+struct\s+PeerStateSnapshot\b", mask_rust(snapshot_heading)):
            errors.append("engine/connection.rs: read-only peer snapshot must be public")
        snapshot_fields = struct_fields(snapshot_body)
        if any(visibility != "pub" for visibility, _ in snapshot_fields.values()):
            errors.append("engine/connection.rs: read-only peer snapshot fields must be readable")
        if "pending_remote_candidates" in snapshot_fields:
            errors.append("engine/connection.rs: read-only peer snapshot copied mutable ownership")
    if not re.search(
        r"e\s*\.\s*value\s*\(\s*\)\s*\.\s*snapshot\s*\(\s*\)", state_masked
    ) or not re.search(r"peer\s*\.\s*snapshot\s*\(\s*\)", state_masked):
        errors.append("engine/state.rs: compatibility reads must use the read-only peer snapshot")

    for struct_name, expected in (
        (
            "PendingRemoteCandidate",
            {
                "candidate": ("", "LocalIceCandidate"),
                "observation": ("", "CandidateObservationLease"),
            },
        ),
        (
            "PendingRemoteCandidateQueue",
            {
                "entries": ("", "Vec<PendingRemoteCandidate>"),
                "container_observation": ("", "Option<ObservationLease>"),
            },
        ),
    ):
        try:
            heading, body = struct_scope(connection_source, struct_name, connection_masked)
        except ValueError as error:
            errors.append(f"engine/connection.rs: {error}")
            continue
        if struct_name == "PendingRemoteCandidateQueue" and re.search(
            r"\bpub(?:\s*\([^)]*\))?\s+struct\b", heading
        ):
            errors.append(
                "engine/connection.rs: PendingRemoteCandidateQueue must remain private"
            )
        if struct_fields(body) != expected:
            errors.append(
                f"engine/connection.rs: {struct_name} ownership fields changed"
            )

    if re.search(r"\bcandidate\s*\.\s*clone\s*\(", engine_masked):
        errors.append("engine/mod.rs: inbound remote candidate must be moved, not cloned")
    if len(re.findall(r"connection\s*::\s*apply_pending_remote_candidate\s*\(", engine_masked)) != 2:
        errors.append(
            "engine/mod.rs: queued and immediate candidate application must both be observed"
        )
    state_source = production["engine/state.rs"]
    state_masked = production_masked["engine/state.rs"]
    try:
        registry_heading, registry_body = struct_scope(
            state_source, "PeerRegistry", state_masked
        )
    except ValueError as error:
        errors.append(f"engine/state.rs: {error}")
    else:
        if not re.search(r"pub\s*\(\s*super\s*\)\s+struct", mask_rust(registry_heading)):
            errors.append("engine/state.rs: PeerRegistry must remain private to the engine")
        registry_fields = struct_fields(registry_body)
        registry_body_masked = mask_rust(registry_body)
        if set(registry_fields) != {"peers", "mutation"} or not re.search(
            r"peers\s*:\s*DashMap\s*<\s*String\s*,\s*Arc\s*<\s*PeerConnection\s*>\s*>",
            registry_body_masked,
        ) or registry_fields.get("mutation") != ("", "Mutex<()>"):
            errors.append("engine/state.rs: PeerRegistry must narrowly own the peer map")

    replacement_cleanup = re.compile(
        r"if\s+let\s+Some\s*\(\s*replaced\s*\)\s*=\s*"
        r"self\s*\.\s*peers\s*\.\s*insert\s*\([^)]*\)\s*\{\s*"
        r"replaced\s*\.\s*discard_pending_remote_candidates\s*\(\s*\)\s*;"
    )
    removal_cleanup = re.compile(
        r"let\s*\(\s*_\s*,\s*peer\s*\)\s*=\s*"
        r"self\s*\.\s*peers\s*\.\s*remove\s*\([^;]+;\s*"
        r"peer\s*\.\s*discard_pending_remote_candidates\s*\(\s*\)\s*;"
    )
    retirement_cleanup = re.compile(
        r"for\s+peer\s+in\s+&\s*retired\s*\{\s*"
        r"peer\s*\.\s*discard_pending_remote_candidates\s*\(\s*\)\s*;\s*\}\s*"
        r"self\s*\.\s*peers\s*\.\s*clear\s*\(\s*\)\s*;"
    )
    if not replacement_cleanup.search(state_masked):
        errors.append(
            "engine/state.rs: peer replacement must explicitly retire queued candidate observations"
        )
    if not removal_cleanup.search(state_masked):
        errors.append(
            "engine/state.rs: peer removal must explicitly retire queued candidate observations"
        )
    if not retirement_cleanup.search(state_masked):
        errors.append(
            "engine/state.rs: peer clear and shutdown must retire every queued candidate observation"
        )
    peer_map_mutations = sum(
        len(re.findall(r"\.\s*peers\s*\.\s*(?:insert|remove|clear)\s*\(", text))
        for path, text in protected_workspace_masked.items()
        if path != "crates/myownmesh-core/src/engine/state.rs"
    )
    if peer_map_mutations != 0:
        errors.append(
            "engine/state.rs: raw peer-map mutation escaped the private registry"
        )
    try:
        _, network_state_body = struct_scope(state_source, "NetworkState", state_masked)
    except ValueError as error:
        errors.append(f"engine/state.rs: {error}")
    else:
        if network_state_body and struct_fields(network_state_body).get("peers") != (
            "pub(super)",
            "PeerRegistry",
        ):
            errors.append("engine/state.rs: NetworkState must expose only the narrow peer registry")
    if not re.search(
        r"pub\s+async\s+fn\s+shutdown\s*\([^)]*\)\s*\{\s*"
        r"let\s+retired\s*=\s*self\s*\.\s*peers\s*\.\s*retire_all\s*\(",
        state_masked,
    ):
        errors.append("engine/state.rs: shutdown must retire registry ownership first")
    if not re.search(
        r"fn\s+v4_arc02_shutdown_retires_queue_while_external_peer_arc_survives\s*\(",
        mask_rust(sources["engine/mod.rs"]),
    ):
        errors.append("engine/mod.rs: missing external-Arc shutdown cleanup control")
    if not re.search(
        r"let\s+result\s*=\s*apply\s*\(\s*candidate\s*\)\s*\.\s*await\s*;"
        r"\s*drop\s*\(\s*observation\s*\)\s*;",
        connection_masked,
    ):
        errors.append(
            "engine/connection.rs: candidate observation must outlive asynchronous application"
        )
    if not all(
        token in connection_masked
        for token in (
            "candidate.candidate.capacity()",
            "size_of::<PendingRemoteCandidate>()",
            "container_observation",
        )
    ):
        errors.append(
            "engine/connection.rs: candidate strings and queue container need separate retained-byte observations"
        )

    scoped_owner_fields = (
        (
            "handle.rs",
            "MeshInner",
            "resource_scope",
            "MeshRuntimeResourceScope",
        ),
        (
            "engine/state.rs",
            "NetworkState",
            "resource_scope",
            "NetworkInstanceResourceScope",
        ),
        (
            "engine/connection.rs",
            "PeerConnection",
            "resource_scope",
            "PeerConnectionResourceScope",
        ),
    )
    for owner, struct_name, field_name, field_type in scoped_owner_fields:
        try:
            _, body = struct_scope(production[owner], struct_name, production_masked[owner])
        except ValueError as error:
            errors.append(f"{owner}: {error}")
            continue
        if struct_fields(body).get(field_name) != ("", field_type):
            errors.append(
                f"{owner}: {struct_name} must privately own {field_type}"
            )
    handle_masked = production_masked["handle.rs"]
    state_masked = production_masked["engine/state.rs"]
    process_scope_pattern = re.compile(
        r"ProcessResourceRoot\s*::\s*global\s*\(\s*\)\s*\.\s*mesh_runtime_scope\s*\(\s*\)"
    )
    if len(process_scope_pattern.findall(handle_masked)) != 1:
        errors.append("handle.rs: Mesh runtime must descend from the process resource root")
    if len(process_scope_pattern.findall(state_masked)) != 1:
        errors.append(
            "engine/state.rs: direct NetworkState construction must descend from the process resource root"
        )
    if len(process_scope_pattern.findall(engine_masked)) != 1:
        errors.append(
            "engine/mod.rs: direct spawn_network construction must descend from the process resource root"
        )
    if not re.search(r"spawn_network_in_mesh_scope\s*\(", handle_masked):
        errors.append("handle.rs: joined network instances must reuse their Mesh runtime scope")

    owner_private_transitions = {
        "runtime/attempt/mod.rs": {"admitted", "allocate_candidate"},
        "connector/mod.rs": {"mark_connected"},
    }
    for owner, functions in owner_private_transitions.items():
        source = production_masked[owner]
        for function in functions:
            if not re.search(
                rf"(?m)^\s*fn\s+{function}(?:\s*<[^>]+>)?\s*\(", source
            ):
                errors.append(f"{owner}: owner transition {function} is not private")

    attempt_masked = production_masked["runtime/attempt/mod.rs"]
    for struct_name, expected in (
        (
            "AttemptOwnership",
            {"runtime": ("", "RuntimeIncarnation")},
        ),
        (
            "AggregateReservation",
            {
                "capacity": ("", "ResourceUse"),
                "state": ("", "Mutex<AggregateReservationState>"),
            },
        ),
        (
            "CandidateReservation",
            {
                "aggregate": ("", "Arc<AggregateReservation>"),
                "claim": ("", "ResourceUse"),
            },
        ),
    ):
        try:
            heading, body = struct_scope(
                production["runtime/attempt/mod.rs"], struct_name, attempt_masked
            )
        except ValueError as error:
            errors.append(f"runtime/attempt/mod.rs: {error}")
            continue
        if re.search(r"\bpub\b", mask_rust(heading)) or struct_fields(body) != expected:
            errors.append(
                f"runtime/attempt/mod.rs: {struct_name} must remain the private reviewed reservation owner"
            )
    allocation_order = re.compile(
        r"let\s+reservation\s*=\s*self\s*\.\s*aggregate\s*\.\s*reserve\s*\(\s*claim\s*\)\s*\?\s*;"
        r"[\s\S]*?let\s+capability\s*=\s*CandidateCapability\s*\{"
        r"[\s\S]*?let\s+candidate\s*=\s*allocate\s*\(\s*\)\s*;"
    )
    if not allocation_order.search(attempt_masked):
        errors.append("runtime/attempt/mod.rs: candidate allocation must follow its child reservation")
    if re.search(r"CandidateCapability\s*\{\s*permit\s*:", attempt_masked):
        errors.append("runtime/attempt/mod.rs: a candidate must not consume the attempt permit")

    for wrapper, (owner, capability_type) in LEGACY_WRAPPERS.items():
        source = production[owner]
        try:
            heading, body = struct_scope(
                source,
                wrapper,
                production_masked[owner],
            )
        except ValueError as error:
            errors.append(f"{owner}: {error}")
            continue
        if not re.search(r"pub\s*\(\s*crate\s*\)\s+struct", mask_rust(heading)):
            errors.append(f"{owner}: {wrapper} must remain crate-private")
        fields = struct_fields(body)
        if fields.get("capability", (None, None))[1] != capability_type:
            errors.append(f"{owner}: {wrapper} must require {capability_type}")
        if fields.get("legacy", (None, None))[1] != "T":
            errors.append(f"{owner}: {wrapper} must hold its legacy value privately")
        if any(visibility for visibility, _ in fields.values()):
            errors.append(f"{owner}: {wrapper} exposes a public field")

        wrapper_source = production_masked[owner]
        wrapper_impls = inherent_impl_bodies(wrapper_source, wrapper)
        if len(wrapper_impls) != 1:
            errors.append(
                f"{owner}: {wrapper} must have exactly one inherent implementation, "
                f"found {len(wrapper_impls)}"
            )
            continue
        impl_body = wrapper_impls[0]
        if re.search(r"\bpub(?:\s*\([^)]*\))?\s+fn\s+into_parts\b", impl_body):
            errors.append(f"{owner}: {wrapper} exposes raw legacy extraction")
        if re.search(
            r"\bpub(?:\s*\([^)]*\))?\s+fn\s+[A-Za-z_]\w*"
            r"[^;{]*->\s*[^;{]*\bT\b",
            impl_body,
        ):
            errors.append(f"{owner}: {wrapper} exposes its raw legacy value")
        wrapper_trait_owners = [
            path
            for path, text in protected_workspace_masked.items()
            for header in trait_impl_headers(text)
            if re.search(rf"\b{re.escape(wrapper)}\b", header)
        ]
        if wrapper_trait_owners:
            errors.append(
                f"{owner}: {wrapper} appears in a production trait implementation: "
                f"{sorted(set(wrapper_trait_owners))}"
            )

    return errors


def existing_boundaries() -> set[str]:
    return {path for path in BOUNDARIES if (CORE_SRC / path).is_file()}


def negative_controls(sources: dict[str, str], boundaries: set[str]) -> list[str]:
    cases: list[tuple[str, dict[str, str], set[str], str]] = []

    source_change = copy.deepcopy(sources)
    source_change["runtime/session_broker/mod.rs"] += "\nfn unreviewed_owner_change() {}\n"
    cases.append(
        (
            "unreviewed authority-owner source change",
            source_change,
            boundaries,
            "production source fingerprint changed",
        )
    )

    cloned = copy.deepcopy(sources)
    cloned["runtime/session_broker/mod.rs"] = cloned[
        "runtime/session_broker/mod.rs"
    ].replace(
        "pub struct SessionCapability {",
        "#[derive(Clone)]\npub struct SessionCapability {",
        1,
    )
    cases.append(("clonable session", cloned, boundaries, "derives forbidden"))

    public_field = copy.deepcopy(sources)
    public_field["runtime/session_broker/mod.rs"] = public_field[
        "runtime/session_broker/mod.rs"
    ].replace("    runtime: RuntimeIncarnation,", "    pub runtime: RuntimeIncarnation,", 1)
    cases.append(("public permit field", public_field, boundaries, "exposes authority"))

    visible_mint = copy.deepcopy(sources)
    visible_mint["runtime/session_broker/mod.rs"] += (
        "\npub(crate) fn forged_session() -> SessionCapability { unimplemented!() }\n"
    )
    cases.append(("visible session mint", visible_mint, boundaries, "visible production mint"))

    result_self_mint = copy.deepcopy(sources)
    result_self_mint["runtime/session_broker/mod.rs"] = result_self_mint[
        "runtime/session_broker/mod.rs"
    ].replace(
        "impl SessionCapability {",
        "impl SessionCapability {\n"
        "    pub(crate) fn forged_result() -> Result<Self, ()> { unimplemented!() }",
        1,
    )
    cases.append(
        (
            "wrapped Self session mint",
            result_self_mint,
            boundaries,
            "visible Self-returning",
        )
    )

    second_session_impl = copy.deepcopy(sources)
    second_session_impl["runtime/session_broker/mod.rs"] += (
        "\nimpl SessionCapability {"
        " pub(crate) fn forged_result() -> Result<Self, ()> { unimplemented!() } }\n"
    )

    session_type_alias = copy.deepcopy(sources)
    session_type_alias["runtime/session_broker/mod.rs"] += (
        "\ntype SessionAlias = SessionCapability;"
        " impl SessionAlias { pub(crate) fn forged_result() -> Result<Self, ()> {"
        " unimplemented!() } }\n"
    )
    cases.append(
        (
            "session type-alias mint",
            session_type_alias,
            boundaries,
            "type alias SessionAlias aliases protected",
        )
    )

    session_import_alias = copy.deepcopy(sources)
    session_import_alias["runtime/session_broker/mod.rs"] += (
        "\nuse self::SessionCapability as SessionAlias;"
        " impl SessionAlias { pub(crate) fn forged_result() -> Result<Self, ()> {"
        " unimplemented!() } }\n"
    )
    cases.append(
        (
            "session renamed-import mint",
            session_import_alias,
            boundaries,
            "renamed import SessionAlias aliases protected",
        )
    )

    raw_session_impl = copy.deepcopy(sources)
    raw_session_impl["runtime/session_broker/mod.rs"] += (
        "\nimpl r#SessionCapability {"
        " pub(crate) fn forged_result() -> Result<Self, ()> { unimplemented!() } }\n"
    )
    cases.append(
        (
            "raw-identifier session mint",
            raw_session_impl,
            boundaries,
            "visible Self-returning",
        )
    )

    macro_session_impl = copy.deepcopy(sources)
    macro_session_impl["runtime/session_broker/mod.rs"] += (
        "\nmacro_rules! emit_session_mint { ($name:ident) => {"
        " impl $name { pub(crate) fn forged_result() -> Result<Self, ()> {"
        " unimplemented!() } } } }"
        " emit_session_mint!(SessionCapability);\n"
    )

    parenthesized_session_impl = copy.deepcopy(sources)
    parenthesized_session_impl["runtime/session_broker/mod.rs"] += (
        "\nimpl ((SessionCapability)) {"
        " pub(crate) fn forged_result() -> Result<Self, ()> { unimplemented!() } }\n"
    )
    cases.append(
        (
            "parenthesized session mint",
            parenthesized_session_impl,
            boundaries,
            "visible Self-returning",
        )
    )

    where_session_impl = copy.deepcopy(sources)
    where_session_impl["runtime/session_broker/mod.rs"] += (
        "\nimpl SessionCapability where SessionCapability: Sized {"
        " pub(crate) fn forged_result() -> Result<Self, ()> { unimplemented!() } }\n"
    )
    cases.append(
        (
            "where-clause session mint",
            where_session_impl,
            boundaries,
            "visible Self-returning",
        )
    )

    attributed_session_impl = copy.deepcopy(sources)
    attributed_session_impl["runtime/session_broker/mod.rs"] += (
        "\n#[authority_codegen] struct MacroInput;\n"
    )

    descendant_session_mint = copy.deepcopy(sources)
    descendant_session_mint["runtime/session_broker/mod.rs"] += "\nmod redteam_escape;\n"
    descendant_session_mint["runtime/session_broker/redteam_escape.rs"] = (
        "use super::*;\n"
        "pub(crate) fn forged_session("
        "authenticated_channel: AuthenticatedChannelCapability, "
        "local_principal: LocalPrincipalCapability, permit: SessionPermit"
        ") -> SessionCapability { SessionCapability { authenticated_channel, "
        "local_principal, permit } }\n"
    )
    cases.append(
        (
            "descendant-module session mint",
            descendant_session_mint,
            boundaries,
            "authority owner must remain a leaf module",
        )
    )
    cases.append(
        (
            "attribute-generated authority code",
            attributed_session_impl,
            boundaries,
            "code-generating attributes are forbidden",
        )
    )
    cases.append(
        (
            "macro-generated session mint",
            macro_session_impl,
            boundaries,
            "code-generating macros are forbidden",
        )
    )
    cases.append(
        (
            "second-impl wrapped Self session mint",
            second_session_impl,
            boundaries,
            "visible Self-returning",
        )
    )

    forged_runtime = copy.deepcopy(sources)
    forged_runtime["runtime/attempt/mod.rs"] += (
        "\nfn forged_runtime() { let _ = RuntimeIncarnation::new(); }\n"
    )
    cases.append(
        (
            "off-owner runtime construction",
            forged_runtime,
            boundaries,
            "constructed outside test scaffolding",
        )
    )

    runtime_type_alias = copy.deepcopy(sources)
    runtime_type_alias["runtime/mod.rs"] += (
        "\ntype RuntimeAlias = RuntimeIncarnation;"
        " impl Default for RuntimeAlias { fn default() -> Self { unimplemented!() } }\n"
    )
    cases.append(
        (
            "runtime type-alias mint",
            runtime_type_alias,
            boundaries,
            "type alias RuntimeAlias aliases protected",
        )
    )

    raw_runtime_impl = copy.deepcopy(sources)
    raw_runtime_impl["runtime/mod.rs"] += (
        "\nimpl r#RuntimeIncarnation {"
        " pub(crate) fn forged_runtime() -> Self { unimplemented!() } }\n"
    )

    parenthesized_runtime_impl = copy.deepcopy(sources)
    parenthesized_runtime_impl["runtime/mod.rs"] += (
        "\nimpl (RuntimeIncarnation) {"
        " pub(crate) fn forged_runtime() -> Self { unimplemented!() } }\n"
    )
    cases.append(
        (
            "parenthesized runtime mint",
            parenthesized_runtime_impl,
            boundaries,
            "exactly one owner-local inherent impl",
        )
    )

    where_runtime_impl = copy.deepcopy(sources)
    where_runtime_impl["runtime/mod.rs"] += (
        "\nimpl RuntimeIncarnation where RuntimeIncarnation: Sized {"
        " pub(crate) fn forged_runtime() -> Self { unimplemented!() } }\n"
    )
    cases.append(
        (
            "where-clause runtime mint",
            where_runtime_impl,
            boundaries,
            "exactly one owner-local inherent impl",
        )
    )
    cases.append(
        (
            "raw-identifier runtime mint",
            raw_runtime_impl,
            boundaries,
            "exactly one owner-local inherent impl",
        )
    )

    conversion = copy.deepcopy(sources)
    conversion["runtime/attempt/mod.rs"] += (
        "\nimpl From<String> for CandidateCapability {"
        " fn from(_: String) -> Self { unimplemented!() } }\n"
    )
    cases.append(("public ID conversion", conversion, boundaries, "From or TryFrom"))

    into_conversion = copy.deepcopy(sources)
    into_conversion["runtime/attempt/mod.rs"] += (
        "\nimpl Into<CandidateCapability> for String {"
        " fn into(self) -> CandidateCapability { unimplemented!() } }\n"
    )
    cases.append(
        (
            "public ID Into conversion",
            into_conversion,
            boundaries,
            "production trait implementation",
        )
    )

    candidate_type_alias = copy.deepcopy(sources)
    candidate_type_alias["runtime/attempt/mod.rs"] += (
        "\ntype CandidateAlias = CandidateCapability;"
        " impl Into<CandidateAlias> for String {"
        " fn into(self) -> CandidateAlias { unimplemented!() } }\n"
    )
    cases.append(
        (
            "candidate type-alias conversion",
            candidate_type_alias,
            boundaries,
            "type alias CandidateAlias aliases protected",
        )
    )

    session_factory = copy.deepcopy(sources)
    session_factory["runtime/session_broker/mod.rs"] += (
        "\npub(crate) trait SessionFactory { fn forge() -> Self; }\n"
        "impl SessionFactory for SessionCapability {"
        " fn forge() -> Self { unimplemented!() } }\n"
    )
    cases.append(
        (
            "session factory trait",
            session_factory,
            boundaries,
            "production trait implementation",
        )
    )

    runtime_default = copy.deepcopy(sources)
    runtime_default["runtime/mod.rs"] += (
        "\nimpl Default for RuntimeIncarnation {"
        " fn default() -> Self { unimplemented!() } }\n"
    )
    cases.append(
        (
            "runtime Default mint",
            runtime_default,
            boundaries,
            "RuntimeIncarnation appears in a production trait implementation",
        )
    )

    runtime_factory = copy.deepcopy(sources)
    runtime_factory["runtime/mod.rs"] += (
        "\npub(crate) fn forged_runtime_factory() -> RuntimeIncarnation {"
        " RuntimeIncarnation { marker: Arc::new(RuntimeMarker) } }\n"
    )
    cases.append(
        (
            "runtime named factory",
            runtime_factory,
            boundaries,
            "visible value-returning production function",
        )
    )

    missing_export = copy.deepcopy(sources)
    missing_export["lib.rs"] = missing_export["lib.rs"].replace("pub mod connector;", "", 1)
    cases.append(("missing module export", missing_export, boundaries, "does not export"))

    redirected_export = copy.deepcopy(sources)
    redirected_export["lib.rs"] = redirected_export["lib.rs"].replace(
        "pub mod application_gateway;",
        '#[path = "redteam_application_gateway.rs"]\npub mod application_gateway;',
        1,
    )
    redirected_export["redteam_application_gateway.rs"] = (
        "pub struct LocalPrincipalCapability;\n"
        "pub struct ApplicationQueuePermit;\n"
    )
    cases.append(
        (
            "redirected authority module",
            redirected_export,
            boundaries,
            "forbidden path redirection attribute",
        )
    )

    conditional_export = copy.deepcopy(sources)
    conditional_export["lib.rs"] = conditional_export["lib.rs"].replace(
        "pub mod application_gateway;",
        "#[cfg(any())]\npub mod application_gateway;\n"
        "#[cfg(not(any()))]\npub mod application_gateway {"
        " pub struct LocalPrincipalCapability;"
        " pub struct ApplicationQueuePermit; }",
        1,
    )
    cases.append(
        (
            "conditional authority module replacement",
            conditional_export,
            boundaries,
            "production source fingerprint changed",
        )
    )

    raw_wrapper = copy.deepcopy(sources)
    raw_wrapper["connector/mod.rs"] = raw_wrapper["connector/mod.rs"].replace(
        "    fn into_parts(self)", "    pub(crate) fn into_parts(self)", 1
    )
    cases.append(("raw legacy bypass", raw_wrapper, boundaries, "raw legacy extraction"))

    renamed_raw_wrapper = copy.deepcopy(sources)
    renamed_raw_wrapper["connector/mod.rs"] = renamed_raw_wrapper[
        "connector/mod.rs"
    ].replace(
        "    fn into_parts(self)",
        "    pub(crate) fn expose_parts(self)",
        1,
    )
    cases.append(
        (
            "renamed raw legacy bypass",
            renamed_raw_wrapper,
            boundaries,
            "exposes its raw legacy value",
        )
    )

    second_wrapper_impl = copy.deepcopy(sources)
    second_wrapper_impl["connector/mod.rs"] += (
        "\nimpl<T> LegacyConnectedChannel<T> {"
        " pub(crate) fn expose_parts(self) -> (ConnectedChannelCapability, T) {"
        " (self.capability, self.legacy) } }\n"
    )

    wrapper_type_alias = copy.deepcopy(sources)
    wrapper_type_alias["connector/mod.rs"] += (
        "\ntype LegacyConnectedAlias<T> = LegacyConnectedChannel<T>;"
        " impl<T> LegacyConnectedAlias<T> {"
        " pub(crate) fn expose_parts(self) -> (ConnectedChannelCapability, T) {"
        " (self.capability, self.legacy) } }\n"
    )
    cases.append(
        (
            "legacy wrapper type-alias bypass",
            wrapper_type_alias,
            boundaries,
            "type alias LegacyConnectedAlias aliases protected",
        )
    )

    raw_wrapper_impl = copy.deepcopy(sources)
    raw_wrapper_impl["connector/mod.rs"] += (
        "\nimpl<T> r#LegacyConnectedChannel<T> {"
        " pub(crate) fn expose_parts(self) -> (ConnectedChannelCapability, T) {"
        " (self.capability, self.legacy) } }\n"
    )

    parenthesized_wrapper_impl = copy.deepcopy(sources)
    parenthesized_wrapper_impl["connector/mod.rs"] += (
        "\nimpl<T> (LegacyConnectedChannel<T>) {"
        " pub(crate) fn expose_parts(self) -> (ConnectedChannelCapability, T) {"
        " (self.capability, self.legacy) } }\n"
    )
    cases.append(
        (
            "parenthesized legacy wrapper bypass",
            parenthesized_wrapper_impl,
            boundaries,
            "exactly one inherent implementation",
        )
    )

    where_wrapper_impl = copy.deepcopy(sources)
    where_wrapper_impl["connector/mod.rs"] += (
        "\nimpl<T> LegacyConnectedChannel<T> where T: 'static {"
        " pub(crate) fn expose_parts(self) -> (ConnectedChannelCapability, T) {"
        " (self.capability, self.legacy) } }\n"
    )
    cases.append(
        (
            "where-clause legacy wrapper bypass",
            where_wrapper_impl,
            boundaries,
            "exactly one inherent implementation",
        )
    )
    cases.append(
        (
            "raw-identifier legacy wrapper bypass",
            raw_wrapper_impl,
            boundaries,
            "exactly one inherent implementation",
        )
    )
    cases.append(
        (
            "second-impl raw legacy bypass",
            second_wrapper_impl,
            boundaries,
            "exactly one inherent implementation",
        )
    )

    wrapper_deref = copy.deepcopy(sources)
    wrapper_deref["connector/mod.rs"] += (
        "\nimpl<T> std::ops::Deref for LegacyConnectedChannel<T> {"
        " type Target = T; fn deref(&self) -> &T { &self.legacy } }\n"
    )
    cases.append(
        (
            "legacy wrapper Deref bypass",
            wrapper_deref,
            boundaries,
            "appears in a production trait implementation",
        )
    )

    missing_binding = copy.deepcopy(sources)
    missing_binding["runtime/relay/mod.rs"] = missing_binding[
        "runtime/relay/mod.rs"
    ].replace("    runtime: RuntimeIncarnation,", "    marker: String,", 1)
    cases.append(("missing runtime binding", missing_binding, boundaries, "fields changed"))

    missing_boundary = set(boundaries)
    missing_boundary.remove("connector/BOUNDARY.md")
    cases.append(("missing boundary", sources, missing_boundary, "lacks BOUNDARY.md"))

    missing_compile_fail = copy.deepcopy(sources)
    for owner in COMPILE_FAIL_FENCES:
        missing_compile_fail[owner] = re.sub(
            r"```compile_fail(?:,[A-Z]\d+)?",
            "```text",
            missing_compile_fail[owner],
        )
    cases.append(
        (
            "removed compile-fail controls",
            missing_compile_fail,
            boundaries,
            "compile-fail controls",
        )
    )

    clone_peer_state = copy.deepcopy(sources)
    clone_peer_state["engine/connection.rs"] = clone_peer_state[
        "engine/connection.rs"
    ].replace(
        "#[derive(Debug)]\npub struct PeerStateData",
        "#[derive(Debug, Clone)]\npub struct PeerStateData",
        1,
    )
    cases.append(
        (
            "cloneable peer state",
            clone_peer_state,
            boundaries,
            "PeerStateData must not derive Clone",
        )
    )

    manual_peer_clone = copy.deepcopy(sources)
    manual_peer_clone["engine/connection.rs"] += (
        "\nimpl Clone for PeerStateData {"
        " fn clone(&self) -> Self { PeerStateData::default() } }\n"
    )
    cases.append(
        (
            "manual peer-state clone",
            manual_peer_clone,
            boundaries,
            "PeerStateData must not implement Clone",
        )
    )

    public_candidate_queue = copy.deepcopy(sources)
    public_candidate_queue["engine/connection.rs"] = public_candidate_queue[
        "engine/connection.rs"
    ].replace(
        "    pending_remote_candidates: PendingRemoteCandidateQueue,",
        "    pub pending_remote_candidates: PendingRemoteCandidateQueue,",
        1,
    )
    cases.append(
        (
            "public candidate queue",
            public_candidate_queue,
            boundaries,
            "pending_remote_candidates must be a private observed queue",
        )
    )

    cloned_remote_candidate = copy.deepcopy(sources)
    cloned_remote_candidate["engine/mod.rs"] = cloned_remote_candidate[
        "engine/mod.rs"
    ].replace(
        "peer.queue_remote_candidate(&mut data, candidate);",
        "peer.queue_remote_candidate(&mut data, candidate.clone());",
        1,
    )
    cases.append(
        (
            "cloned remote candidate",
            cloned_remote_candidate,
            boundaries,
            "inbound remote candidate must be moved, not cloned",
        )
    )

    unobserved_application = copy.deepcopy(sources)
    unobserved_application["engine/mod.rs"] = unobserved_application[
        "engine/mod.rs"
    ].replace(
        "connection::apply_pending_remote_candidate(",
        "connection::apply_remote_candidate_without_observation(",
        1,
    )
    cases.append(
        (
            "unobserved candidate application",
            unobserved_application,
            boundaries,
            "queued and immediate candidate application must both be observed",
        )
    )

    retained_replaced_queue = copy.deepcopy(sources)
    retained_replaced_queue["engine/state.rs"] = retained_replaced_queue[
        "engine/state.rs"
    ].replace(
        "        replaced.discard_pending_remote_candidates();",
        "        drop(replaced);",
        1,
    )
    cases.append(
        (
            "retained queue after peer replacement",
            retained_replaced_queue,
            boundaries,
            "peer replacement must explicitly retire queued candidate observations",
        )
    )

    retained_removed_queue = copy.deepcopy(sources)
    retained_removed_queue["engine/state.rs"] = retained_removed_queue[
        "engine/state.rs"
    ].replace(
        "        peer.discard_pending_remote_candidates();",
        "        let _retired_peer = &peer;",
        1,
    )
    cases.append(
        (
            "retained queue after peer removal",
            retained_removed_queue,
            boundaries,
            "peer removal must explicitly retire queued candidate observations",
        )
    )

    broken_resource_hierarchy = copy.deepcopy(sources)
    broken_resource_hierarchy["resource/mod.rs"] = broken_resource_hierarchy[
        "resource/mod.rs"
    ].replace(
        "for scope in self.ancestors.iter() {",
        "for scope in self.ancestors.iter().skip(1) {",
        1,
    )
    cases.append(
        (
            "resource observation skips process root",
            broken_resource_hierarchy,
            boundaries,
            "leaf observations do not update their ancestor path",
        )
    )

    unbounded_active_metadata = copy.deepcopy(sources)
    unbounded_active_metadata["resource/mod.rs"] = unbounded_active_metadata[
        "resource/mod.rs"
    ].replace(
        "    oldest_active_started_at: Option<Instant>,",
        "    active_starts: std::collections::BTreeMap<Instant, u64>,",
        1,
    )
    cases.append(
        (
            "unbounded active-lease metadata",
            unbounded_active_metadata,
            boundaries,
            "observer metadata or hierarchy lock is not bounded",
        )
    )

    hierarchy_hot_path_lock = copy.deepcopy(sources)
    hierarchy_hot_path_lock["resource/mod.rs"] = hierarchy_hot_path_lock[
        "resource/mod.rs"
    ].replace(
        "    leaf: Arc<Inner>,",
        "    leaf: Arc<Inner>,\n    transaction: Mutex<()>,",
        1,
    )
    cases.append(
        (
            "hierarchy hot-path mutex",
            hierarchy_hot_path_lock,
            boundaries,
            "observer path metadata must remain fixed and lock-free",
        )
    )

    panicking_measurement = copy.deepcopy(sources)
    panicking_measurement["engine/connection.rs"] += (
        "\nfn redteam_measurement_panic() { panic!(\"measurement overflow\"); }\n"
    )
    cases.append(
        (
            "panicking resource measurement",
            panicking_measurement,
            boundaries,
            "production resource measurement contains a panic path",
        )
    )

    unretired_clear = copy.deepcopy(sources)
    unretired_clear["engine/state.rs"] = unretired_clear["engine/state.rs"].replace(
        "        for peer in &retired {\n            peer.discard_pending_remote_candidates();\n        }",
        "        let _ = &retired;",
        1,
    )
    cases.append(
        (
            "peer clear without queue retirement",
            unretired_clear,
            boundaries,
            "peer clear and shutdown must retire every queued candidate observation",
        )
    )

    public_raw_peer_map = copy.deepcopy(sources)
    public_raw_peer_map["engine/state.rs"] = public_raw_peer_map["engine/state.rs"].replace(
        "    pub(super) peers: PeerRegistry,",
        "    pub peers: DashMap<String, Arc<PeerConnection>>,",
        1,
    )
    cases.append(
        (
            "public raw peer map",
            public_raw_peer_map,
            boundaries,
            "NetworkState must expose only the narrow peer registry",
        )
    )

    snapshot_copies_queue = copy.deepcopy(sources)
    snapshot_copies_queue["engine/connection.rs"] = snapshot_copies_queue[
        "engine/connection.rs"
    ].replace(
        "pub struct PeerStateSnapshot {",
        "pub struct PeerStateSnapshot {\n    pub pending_remote_candidates: PendingRemoteCandidateQueue,",
        1,
    )
    cases.append(
        (
            "read-only snapshot copies mutable queue ownership",
            snapshot_copies_queue,
            boundaries,
            "read-only peer snapshot copied mutable ownership",
        )
    )

    detached_mesh_scope = copy.deepcopy(sources)
    detached_mesh_scope["handle.rs"] = detached_mesh_scope["handle.rs"].replace(
        "ProcessResourceRoot::global().mesh_runtime_scope()",
        "ResourceAccountant::observation_only()",
        1,
    )
    cases.append(
        (
            "Mesh runtime detached from process root",
            detached_mesh_scope,
            boundaries,
            "Mesh runtime must descend from the process resource root",
        )
    )

    detached_direct_spawn = copy.deepcopy(sources)
    detached_direct_spawn["engine/mod.rs"] = detached_direct_spawn[
        "engine/mod.rs"
    ].replace(
        "ProcessResourceRoot::global().mesh_runtime_scope()",
        "ResourceAccountant::observation_only()",
        1,
    )
    cases.append(
        (
            "direct spawn detached from process root",
            detached_direct_spawn,
            boundaries,
            "direct spawn_network construction must descend from the process resource root",
        )
    )

    global_accountant = copy.deepcopy(sources)
    global_accountant["resource/mod.rs"] += "\nstatic GLOBAL_COUNT: u64 = 0;\n"
    cases.append(
        (
            "global accountant",
            global_accountant,
            boundaries,
            "exactly one typed process observation root",
        )
    )

    policy_observer = copy.deepcopy(sources)
    policy_observer["resource/mod.rs"] += "\nfn reserve_resource() {}\n"
    cases.append(
        (
            "resource policy in observer",
            policy_observer,
            boundaries,
            "resource-policy vocabulary",
        )
    )

    failures: list[str] = []
    for name, candidate_sources, candidate_boundaries, expected in cases:
        if candidate_sources == sources and candidate_boundaries == boundaries:
            failures.append(f"negative control did not mutate its input: {name}")
            continue
        errors = validate(candidate_sources, candidate_boundaries)
        if not any(expected in error for error in errors):
            failures.append(f"negative control was not rejected: {name}")

    redirected_manifest = CORE_MANIFEST.read_text(encoding="utf-8").replace(
        'path = "src/lib.rs"',
        'path = "src/redteam_lib.rs"',
        1,
    )
    if redirected_manifest == CORE_MANIFEST.read_text(encoding="utf-8"):
        failures.append("negative control did not mutate its input: redirected library target")
    if not any(
        "library target must remain exactly" in error
        for error in validate_core_manifest(redirected_manifest)
    ):
        failures.append("negative control was not rejected: redirected library target")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--negative-controls",
        action="store_true",
        help="prove that independent authority-boundary faults are rejected",
    )
    args = parser.parse_args()

    sources = load_sources()
    boundaries = existing_boundaries()
    errors = (
        negative_controls(sources, boundaries)
        if args.negative_controls
        else validate(sources, boundaries)
    ) + validate_core_manifest(CORE_MANIFEST.read_text(encoding="utf-8"))
    if errors:
        label = "negative controls" if args.negative_controls else "foundation source gate"
        print(f"V4 Arc 02 {label} failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    if args.negative_controls:
        print(
            "V4 Arc 02 negative controls passed: source-fingerprint, clone, public-field, visible-mint, "
            "wrapped-mint, second-impl mint, alias-mint, raw-identifier mint, "
            "parenthesized-mint, where-clause mint, macro-mint, attribute-mint, "
            "descendant-module mint, factory-trait, runtime-factory, public-ID conversion, "
            "module-export, module-redirection, library-target redirection, "
            "conditional-module replacement, "
            "legacy-bypass, second-impl "
            "legacy-bypass, alias-bypass, "
            "raw-identifier bypass, parenthesized bypass, where-clause bypass, "
            "wrapper-trait, runtime-binding, "
            "compile-control, boundary, candidate-ownership, registry-retirement, "
            "bounded-metadata, lock-free-rollup, measurement-panic, hierarchy, "
            "global-accountant, and resource-policy faults "
            "were rejected."
        )
    else:
        print(
            "V4 Arc 02A through 02C source gate passed: 10 target-owned authority types, "
            "reviewed production fingerprints, private fields, runtime binding, "
            "owner-private transitions, no production SessionCapability mint, "
            "confined legacy adapters, a retiring peer registry, bounded observation metadata, "
            "panic-free measurement, aggregate attempt reservations, and observed remote candidates."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
