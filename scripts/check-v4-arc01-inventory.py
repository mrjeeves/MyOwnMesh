#!/usr/bin/env python3
"""Verify the V4 Arc 01 state and effect inventory against Rust source.

The checker deliberately uses only the Python standard library. It reads the
input declarations and effect sites from production Rust source, then compares
them with the reviewed inventory. A newly added field, message variant, queue,
task, parser, write, listener, connection, or public send-style API fails until
an owner is recorded.
"""

from __future__ import annotations

import argparse
import copy
import functools
import fnmatch
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO = Path(__file__).resolve().parents[1]
INVENTORY_PATH = REPO / "docs" / "v4-transition" / "arc-01-inventory.json"

ALLOWED_FLAGS = {
    "authority_mutation",
    "external_code_replacement",
    "ordinary_forwarding",
    "payload_bypass",
    "public_authority_bypass",
    "unbounded_queue",
    "unbounded_resource",
}
REQUIRED_RESOURCE_METRICS = {"items", "bytes", "tasks", "lifetime"}
OBSERVED_CANDIDATE_RESOURCE_METRICS = {
    "items",
    "logical_bytes",
    "retained_bytes",
    "tasks",
    "lifetime",
}


@dataclass(frozen=True)
class Surface:
    category: str
    path: str
    symbol: str
    token: str
    ordinal: int

    def key(self) -> str:
        return f"{self.category}|{self.path}|{self.symbol}|{self.token}|{self.ordinal}"


@dataclass(frozen=True)
class DeclarationMember:
    path: str
    kind: str
    name: str
    ordinal: int
    member: str
    shape_sha256: str

    def key(self) -> str:
        return (
            f"{self.path}|{self.kind}|{self.name}@{self.ordinal}|{self.member}|"
            f"{self.shape_sha256}"
        )


def relative(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def mask_rust(text: str) -> str:
    """Mask comments and literals while retaining newlines and byte offsets."""

    out = list(text)
    i = 0
    size = len(text)
    while i < size:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end < 0:
                end = size
            for pos in range(i, end):
                out[pos] = " "
            i = end
            continue
        if text.startswith("/*", i):
            depth = 1
            end = i + 2
            while end < size and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            for pos in range(i, end):
                if out[pos] != "\n":
                    out[pos] = " "
            i = end
            continue

        raw = re.match(r"(?:br|r)(?P<hashes>#{0,16})\"", text[i:])
        if raw:
            hashes = raw.group("hashes")
            close = '"' + hashes
            end = text.find(close, i + raw.end())
            end = size if end < 0 else end + len(close)
            for pos in range(i, end):
                if out[pos] != "\n":
                    out[pos] = " "
            i = end
            continue

        quote_at = i + 1 if text.startswith('b"', i) else i
        if quote_at < size and text[quote_at] == '"':
            end = quote_at + 1
            while end < size:
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == '"':
                    end += 1
                    break
                end += 1
            for pos in range(i, end):
                if out[pos] != "\n":
                    out[pos] = " "
            i = end
            continue

        # Mask a Rust character literal, but leave lifetimes such as 'a intact.
        if text[i] == "'":
            char_match = re.match(r"'(?:\\.|[^\\'\n])'", text[i:])
            if char_match:
                end = i + char_match.end()
                for pos in range(i, end):
                    out[pos] = " "
                i = end
                continue
        i += 1
    return "".join(out)


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


@functools.lru_cache(maxsize=None)
def production_text(text: str) -> str:
    """Blank items guarded by cfg(test), including in-file test modules."""

    masked = mask_rust(text)
    chars = list(text)
    attr_re = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    block_item_re = re.compile(
        r"(?:(?:pub(?:\s*\([^)]*\))?)\s+)?"
        r"(?:(?:async|unsafe|const)\s+)*"
        r"(?:extern(?:\s+\"[^\"]*\")?\s+)?"
        r"(?:fn|mod|impl|trait|struct|enum|union|if|match|while|for|loop)\b"
    )
    for match in attr_re.finditer(masked):
        cursor = match.end()
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        while cursor < len(masked) and masked[cursor] == "#":
            opening = masked.find("[", cursor)
            if opening < 0:
                break
            depth = 0
            attribute_end = None
            for pos in range(opening, len(masked)):
                if masked[pos] == "[":
                    depth += 1
                elif masked[pos] == "]":
                    depth -= 1
                    if depth == 0:
                        attribute_end = pos + 1
                        break
            if attribute_end is None:
                raise ValueError(f"unclosed attribute at byte {cursor}")
            cursor = attribute_end
            while cursor < len(masked) and masked[cursor].isspace():
                cursor += 1
        if block_item_re.match(masked, cursor):
            brace = masked.find("{", cursor)
            if brace < 0:
                raise ValueError(f"cfg(test) block item has no body at byte {cursor}")
            end = matching_brace(masked, brace)
            blank_range(chars, match.start(), end + 1)
            continue

        # A cfg-gated struct field or enum variant ends at its top-level
        # comma. A use, type, const, or statement ends at its top-level
        # semicolon. Do not search for the next brace: for a field, that brace
        # can be the enclosing struct close or the next production item.
        depths = {"(": 0, "[": 0, "<": 0, "{": 0}
        closes = {")": "(", "]": "[", ">": "<", "}": "{"}
        end = None
        for pos in range(cursor, len(masked)):
            char = masked[pos]
            if char in depths:
                depths[char] += 1
            elif char in closes:
                opener = closes[char]
                if depths[opener] > 0:
                    depths[opener] -= 1
                elif char == "}":
                    break
            elif char in ",;" and not any(depths.values()):
                end = pos + 1
                break
        if end is None:
            raise ValueError(f"cfg(test) member has no terminator at byte {cursor}")
        blank_range(chars, match.start(), end)
    return "".join(chars)


def split_top_level(body: str) -> list[str]:
    pieces: list[str] = []
    start = 0
    depth = {"(": 0, "[": 0, "{": 0, "<": 0}
    closing = {")": "(", "]": "[", "}": "{", ">": "<"}
    for pos, char in enumerate(body):
        if char in depth:
            depth[char] += 1
        elif char in closing:
            opener = closing[char]
            if depth[opener] > 0:
                depth[opener] -= 1
        elif char == "," and not any(depth.values()):
            pieces.append(body[start:pos])
            start = pos + 1
    pieces.append(body[start:])
    return pieces


def remove_leading_attributes(piece: str) -> str:
    value = piece.lstrip()
    while value.startswith("#"):
        opening = value.find("[")
        if opening < 0:
            break
        depth = 0
        end = None
        for pos in range(opening, len(value)):
            if value[pos] == "[":
                depth += 1
            elif value[pos] == "]":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        if end is None:
            break
        value = value[end:].lstrip()
    return value


def extract_declaration(text: str, kind: str, name: str) -> list[str]:
    masked = mask_rust(text)
    pattern = re.compile(rf"\b{re.escape(kind)}\s+{re.escape(name)}\b[^;{{]*\{{")
    matches = list(pattern.finditer(masked))
    if len(matches) != 1:
        raise ValueError(f"expected one {kind} {name}, found {len(matches)}")
    opening = masked.find("{", matches[0].start())
    end = matching_brace(masked, opening)
    body = masked[opening + 1 : end]
    members: list[str] = []
    for raw_piece in split_top_level(body):
        piece = remove_leading_attributes(raw_piece)
        if not piece:
            continue
        if kind == "struct":
            found = re.match(
                r"(?:pub(?:\([^)]*\))?\s+)?(?P<name>[A-Za-z_]\w*)\s*:", piece
            )
        else:
            found = re.match(r"(?P<name>[A-Za-z_]\w*)", piece)
        if found:
            members.append(found.group("name"))
    return members


def rust_sources() -> list[Path]:
    files: list[Path] = []
    for crate in sorted((REPO / "crates").iterdir()):
        source = crate / "src"
        if source.is_dir():
            files.extend(sorted(source.rglob("*.rs")))
        build_script = crate / "build.rs"
        if build_script.is_file():
            files.append(build_script)
    gui_tauri = REPO / "gui" / "src-tauri"
    if (gui_tauri / "src").is_dir():
        files.extend(sorted((gui_tauri / "src").rglob("*.rs")))
    if (gui_tauri / "build.rs").is_file():
        files.append(gui_tauri / "build.rs")
    return files


@functools.lru_cache(maxsize=1)
def scan_declaration_members() -> list[DeclarationMember]:
    result: list[DeclarationMember] = []
    for path in rust_sources():
        text = production_text(path.read_text(encoding="utf-8"))
        masked = mask_rust(text)
        rel = relative(path)
        counts: dict[tuple[str, str], int] = {}

        named = re.compile(
            r"\b(?P<kind>struct|enum)\s+(?P<name>[A-Za-z_]\w*)\b[^;{]*\{"
        )
        for match in named.finditer(masked):
            kind = match.group("kind")
            name = match.group("name")
            opening = masked.find("{", match.start())
            end = matching_brace(masked, opening)
            body = masked[opening + 1 : end]
            shape_sha256 = hashlib.sha256(
                re.sub(r"\s+", " ", text[match.start() : end + 1]).strip().encode("utf-8")
            ).hexdigest()
            key = (kind, name)
            ordinal = counts.get(key, 0) + 1
            counts[key] = ordinal
            result.append(
                DeclarationMember(rel, kind, name, ordinal, "$type", shape_sha256)
            )
            for raw_piece in split_top_level(body):
                piece = remove_leading_attributes(raw_piece)
                if not piece:
                    continue
                if kind == "struct":
                    found = re.match(
                        r"(?:pub(?:\([^)]*\))?\s+)?(?P<name>[A-Za-z_]\w*)\s*:",
                        piece,
                    )
                else:
                    found = re.match(r"(?P<name>[A-Za-z_]\w*)", piece)
                if found:
                    result.append(
                        DeclarationMember(
                            rel,
                            kind,
                            name,
                            ordinal,
                            found.group("name"),
                            shape_sha256,
                        )
                    )

        # The production tree currently has only simple one-line tuple structs.
        tuple_struct = re.compile(
            r"\bstruct\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<body>[^;{}]*)\)\s*;"
        )
        for match in tuple_struct.finditer(masked):
            name = match.group("name")
            key = ("struct", name)
            ordinal = counts.get(key, 0) + 1
            counts[key] = ordinal
            shape_sha256 = hashlib.sha256(
                re.sub(r"\s+", " ", text[match.start() : match.end()]).strip().encode("utf-8")
            ).hexdigest()
            result.append(
                DeclarationMember(rel, "struct", name, ordinal, "$type", shape_sha256)
            )
            pieces = [piece for piece in split_top_level(match.group("body")) if piece.strip()]
            for index, _ in enumerate(pieces):
                result.append(
                    DeclarationMember(rel, "struct", name, ordinal, f"${index}", shape_sha256)
                )

        unit_struct = re.compile(r"\bstruct\s+(?P<name>[A-Za-z_]\w*)\s*;")
        for match in unit_struct.finditer(masked):
            name = match.group("name")
            key = ("struct", name)
            ordinal = counts.get(key, 0) + 1
            counts[key] = ordinal
            shape_sha256 = hashlib.sha256(
                re.sub(r"\s+", " ", text[match.start() : match.end()]).strip().encode("utf-8")
            ).hexdigest()
            result.append(
                DeclarationMember(rel, "struct", name, ordinal, "$type", shape_sha256)
            )

    return sorted(result, key=DeclarationMember.key)


CALL_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "queue_unbounded",
        "mpsc::unbounded_channel",
        re.compile(r"(?:tokio::sync::)?mpsc::unbounded_channel\s*(?:::\s*<[^;\n=]+>)?\s*\("),
    ),
    (
        "queue_bounded",
        "mpsc::channel",
        re.compile(r"(?:tokio::sync::)?mpsc::channel\s*(?:::\s*<[^;\n=]+>)?\s*\("),
    ),
    (
        "queue_broadcast",
        "broadcast::channel",
        re.compile(r"(?:tokio::sync::)?broadcast::channel\s*(?:::\s*<[^;\n=]+>)?\s*\("),
    ),
    (
        "queue_watch",
        "watch::channel",
        re.compile(r"(?:tokio::sync::)?watch::channel\s*(?:::\s*<[^;\n=]+>)?\s*\("),
    ),
    (
        "queue_oneshot",
        "oneshot::channel",
        re.compile(r"(?:tokio::sync::)?oneshot::channel\s*(?:::\s*<[^;\n=]+>)?\s*\("),
    ),
    ("task", "tokio::spawn", re.compile(r"\btokio::spawn\s*\(")),
    ("task", "tokio::task::spawn", re.compile(r"\btokio::task::spawn\s*\(")),
    ("task", "spawn_blocking", re.compile(r"\b(?:tokio::task::)?spawn_blocking\s*\(")),
    ("task", "thread::spawn", re.compile(r"\b(?:std::)?thread::spawn\s*\(")),
    ("task", "builder.spawn", re.compile(r"\.spawn\s*\(")),
    ("network_bind", "TcpListener::bind", re.compile(r"\b(?:std::net::|tokio::net::)?TcpListener::bind\s*\(")),
    ("network_bind", "UdpSocket::bind", re.compile(r"\b(?:std::net::|tokio::net::)?UdpSocket::bind\s*\(")),
    ("network_connect", "TcpStream::connect", re.compile(r"\b(?:std::net::|tokio::net::)?TcpStream::connect\s*\(")),
    ("network_connect", "connect_async", re.compile(r"\b(?:tokio_tungstenite::)?connect_async\s*\(")),
    ("network_connect", "LocalSocketStream::connect", re.compile(r"\bLocalSocketStream::connect\s*\(")),
    ("network_connect", "turn.inner.connect", re.compile(r"\bself\s*\.\s*inner\s*\.\s*connect\s*\(")),
    ("network_accept", "accept", re.compile(r"\.accept\s*\(\s*\)")),
    ("network_accept", "accept_async", re.compile(r"\baccept_async\s*\(")),
    ("network_receive", "recv_from", re.compile(r"\.recv_from\s*\(")),
    ("network_receive", "turn.inner.recv", re.compile(r"\bself\s*\.\s*inner\s*\.\s*recv\s*\(")),
    ("stream_receive", "next_line", re.compile(r"\.next_line\s*\(")),
    ("stream_receive", "read_line", re.compile(r"\.read_line\s*\(")),
    ("stream_receive", "read_exact", re.compile(r"\.read_exact\s*\(")),
    ("stream_receive", "fill_buf", re.compile(r"\.fill_buf\s*\(")),
    ("network_send", "send_to", re.compile(r"\.send_to\s*\(")),
    ("network_send", "turn.inner.send", re.compile(r"\bself\s*\.\s*inner\s*\.\s*send\s*\(")),
    ("network_receive", "websocket.read.next", re.compile(r"\bread\s*\.\s*next\s*\(")),
    ("network_send", "websocket.write.send", re.compile(r"\bwrite\s*\.\s*send\s*\(")),
    ("external_carrier", "ServiceDaemon::new", re.compile(r"\bServiceDaemon::new\s*\(")),
    ("external_carrier", "turn.inner.close", re.compile(r"\bself\s*\.\s*inner\s*\.\s*close\s*\(")),
    (
        "external_carrier",
        "turn.inner.allocate_conn",
        re.compile(r"\bself\s*\.\s*inner\s*\.\s*allocate_conn\s*\("),
    ),
    ("external_carrier", "turn.Server::new", re.compile(r"\bServer::new\s*\(")),
    (
        "external_carrier",
        "turn.server.close",
        re.compile(r"\bself\s*\.\s*server\s*\.\s*close\s*\("),
    ),
    ("external_carrier", "ServiceDaemon.browse", re.compile(r"\bdaemon\s*\.\s*browse\s*\(")),
    (
        "external_carrier",
        "ServiceDaemon.register",
        re.compile(r"\bself\s*\.\s*daemon\s*\.\s*register\s*\("),
    ),
    (
        "external_carrier",
        "ServiceDaemon.unregister",
        re.compile(r"\bself\s*\.\s*daemon\s*\.\s*unregister\s*\("),
    ),
    (
        "external_carrier",
        "ServiceDaemon.shutdown",
        re.compile(r"\bself\s*\.\s*daemon\s*\.\s*shutdown\s*\("),
    ),
    (
        "external_carrier",
        "mdns.Receiver.recv_async",
        re.compile(r"\bbrowse_rx\s*\.\s*recv_async\s*\("),
    ),
    ("external_carrier", "DNSServiceBrowse", re.compile(r"\bDNSServiceBrowse\s*\(")),
    ("external_carrier", "DNSServiceRegister", re.compile(r"\bDNSServiceRegister\s*\(")),
    ("external_carrier", "DNSServiceResolve", re.compile(r"\bDNSServiceResolve\s*\(")),
    ("external_carrier", "DNSServiceGetAddrInfo", re.compile(r"\bDNSServiceGetAddrInfo\s*\(")),
    ("external_carrier", "DNSServiceProcessResult", re.compile(r"\bDNSServiceProcessResult\s*\(")),
    ("external_carrier", "DNSServiceRefSockFD", re.compile(r"\bDNSServiceRefSockFD\s*\(")),
    ("external_carrier", "DNSServiceQueryRecord", re.compile(r"\bDNSServiceQueryRecord\s*\(")),
    ("external_carrier", "DNSServiceRefDeallocate", re.compile(r"\bDNSServiceRefDeallocate\s*\(")),
    ("external_http", "reqwest::Client::builder", re.compile(r"\breqwest::Client::builder\s*\(")),
    (
        "external_http_request",
        "http.get.send",
        re.compile(r"\.\s*get\s*\([^)]*\)\s*\.\s*send\s*\("),
    ),
    (
        "external_http_body",
        "http.response.body",
        re.compile(r"\.\s*(?:json|bytes|text)\s*\(\s*\)\s*\.await\b"),
    ),
    ("network_bind", "ListenerOptions::new", re.compile(r"\bListenerOptions::new\s*\(")),
    ("parser", "serde_json::from_str", re.compile(r"\bserde_json::from_str\s*(?:::\s*<[^;\n=]+>)?\s*\(")),
    ("parser", "serde_json::from_slice", re.compile(r"\bserde_json::from_slice\s*(?:::\s*<[^;\n=]+>)?\s*\(")),
    ("parser", "serde_json::from_value", re.compile(r"\bserde_json::from_value\s*(?:::\s*<[^;\n=]+>)?\s*\(")),
    ("parser_binary", "unmarshal_binary", re.compile(r"\.unmarshal_binary\s*\(")),
    ("callback_registration", "on_ice_candidate", re.compile(r"\.on_ice_candidate\s*\(")),
    (
        "callback_registration",
        "on_ice_connection_state_change",
        re.compile(r"\.on_ice_connection_state_change\s*\("),
    ),
    (
        "callback_registration",
        "on_peer_connection_state_change",
        re.compile(r"\.on_peer_connection_state_change\s*\("),
    ),
    ("callback_registration", "on_data_channel", re.compile(r"\.on_data_channel\s*\(")),
    ("callback_registration", "on_track", re.compile(r"\.on_track\s*\(")),
    ("callback_registration", "on_open", re.compile(r"\.on_open\s*\(")),
    ("callback_registration", "on_close", re.compile(r"\.on_close\s*\(")),
    ("callback_registration", "on_message", re.compile(r"\.on_message\s*\(")),
    ("callback_registration", "on_error", re.compile(r"\.on_error\s*\(")),
    (
        "write",
        "write_atomic",
        re.compile(r"\b(?:crate::persist::|myownmesh_core::persist::)write_atomic\s*\("),
    ),
    ("write", "fs::write", re.compile(r"\b(?:std::|tokio::)?fs::write\s*\(")),
    ("write", "fs::create_dir_all", re.compile(r"\b(?:std::|tokio::)?fs::create_dir_all\s*\(")),
    ("write", "fs::remove_file", re.compile(r"\b(?:std::|tokio::)?fs::remove_file\s*\(")),
    ("write", "fs::remove_dir_all", re.compile(r"\b(?:std::|tokio::)?fs::remove_dir_all\s*\(")),
    ("write", "fs::rename", re.compile(r"\b(?:std::|tokio::)?fs::rename\s*\(")),
    ("write", "fs::set_permissions", re.compile(r"\b(?:std::|tokio::)?fs::set_permissions\s*\(")),
    ("write", "fs::copy", re.compile(r"\b(?:std::|tokio::)?fs::copy\s*\(")),
    ("write", "File::create", re.compile(r"\b(?:std::fs::|tokio::fs::)?File::create\s*\(")),
    ("write", "OpenOptions::new", re.compile(r"\b(?:std::fs::|tokio::fs::)?OpenOptions::new\s*\(")),
    ("write", "write_all", re.compile(r"\.write_all\s*\(")),
    ("write", "sync_all", re.compile(r"\.sync_all\s*\(")),
    ("write", "set_len", re.compile(r"\.set_len\s*\(")),
    ("process", "Command::new", re.compile(r"\b(?:std::process::|tokio::process::)?Command::new\s*\(")),
    ("process", "process::exit", re.compile(r"\b(?:std::)?process::exit\s*\(")),
]


PUBLIC_ACTION_PREFIXES = (
    "advertise",
    "announce",
    "approve",
    "broadcast",
    "call",
    "close",
    "close_media",
    "connect",
    "deny",
    "dispatch",
    "join",
    "leave",
    "open_media",
    "propose",
    "push",
    "reconnect",
    "reject",
    "remove_roster",
    "register",
    "request_departure",
    "resolve",
    "respond",
    "send",
    "shutdown",
    "sign_proposal",
    "spawn_split",
    "start",
    "stop",
    "subscribe",
    "unregister",
    "withdraw",
)

CONSTRUCTOR_PREFIXES = (
    "attach",
    "create",
    "from_",
    "join",
    "load_or_create",
    "new",
    "open",
    "spawn",
    "start",
)

PARSER_PREFIXES = (
    "decode",
    "from_extra",
    "load",
    "parse",
    "read",
)


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    ordinal: int
    start: int
    end: int
    visibility: str

    def symbol(self) -> str:
        return f"{self.name}@{self.ordinal}"


def function_spans(masked: str) -> list[FunctionSpan]:
    pattern = re.compile(
        r"(?m)^\s*(?P<vis>pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
        r"(?:extern\s+)?fn\s+"
        r"(?P<name>[A-Za-z_]\w*)\b[^;{]*\{"
    )
    provisional: list[tuple[str, int, int, str]] = []
    for match in pattern.finditer(masked):
        opening = masked.find("{", match.start())
        end = matching_brace(masked, opening)
        provisional.append(
            (match.group("name"), match.start(), end + 1, (match.group("vis") or "").strip())
        )
    counts: dict[str, int] = {}
    result: list[FunctionSpan] = []
    for name, start, end, visibility in provisional:
        ordinal = counts.get(name, 0) + 1
        counts[name] = ordinal
        result.append(FunctionSpan(name, ordinal, start, end, visibility))
    return result


def containing_symbol(spans: list[FunctionSpan], offset: int) -> str:
    inside = [span for span in spans if span.start <= offset < span.end]
    if not inside:
        return "<module>"
    return min(inside, key=lambda item: item.end - item.start).symbol()


@functools.lru_cache(maxsize=1)
def scan_surfaces() -> list[Surface]:
    surfaces: list[Surface] = []
    for path in rust_sources():
        text = production_text(path.read_text(encoding="utf-8"))
        masked = mask_rust(text)
        spans = function_spans(masked)
        rel = relative(path)

        occurrence: dict[tuple[str, str, str], int] = {}
        for category, token, pattern in CALL_PATTERNS:
            for match in pattern.finditer(masked):
                symbol = containing_symbol(spans, match.start())
                base = (category, symbol, token)
                ordinal = occurrence.get(base, 0) + 1
                occurrence[base] = ordinal
                surfaces.append(Surface(category, rel, symbol, token, ordinal))

        for span in spans:
            surfaces.append(
                Surface("callable", rel, span.symbol(), span.visibility or "private", 1)
            )
            if span.visibility and span.name.startswith(PUBLIC_ACTION_PREFIXES):
                surfaces.append(
                    Surface("public_action", rel, span.symbol(), span.visibility or "pub", 1)
                )
            if span.name.startswith(CONSTRUCTOR_PREFIXES):
                surfaces.append(
                    Surface("constructor_entry", rel, span.symbol(), span.visibility or "private", 1)
                )
            if span.name.startswith(PARSER_PREFIXES):
                surfaces.append(
                    Surface("parser_entry", rel, span.symbol(), span.visibility or "private", 1)
                )

        trait_signature = re.compile(
            r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?"
            r"(?:unsafe\s+)?(?:extern\s+)?fn\s+"
            r"(?P<name>[A-Za-z_]\w*)\b[^;{]*;"
        )
        trait_counts: dict[str, int] = {}
        for match in trait_signature.finditer(masked):
            name = match.group("name")
            ordinal = trait_counts.get(name, 0) + 1
            trait_counts[name] = ordinal
            surfaces.append(
                Surface("trait_callable", rel, f"{name}@{ordinal}", "signature", 1)
            )
            if name.startswith(PUBLIC_ACTION_PREFIXES):
                surfaces.append(
                    Surface(
                        "public_trait_action",
                        rel,
                        f"{name}@{ordinal}",
                        "trait_method",
                        1,
                    )
                )

        static_pattern = re.compile(
            r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+(?:mut\s+)?"
            r"(?P<name>[A-Za-z_]\w*)\s*:"
        )
        static_counts: dict[str, int] = {}
        for match in static_pattern.finditer(masked):
            name = match.group("name")
            ordinal = static_counts.get(name, 0) + 1
            static_counts[name] = ordinal
            surfaces.append(
                Surface("static_state", rel, f"{name}@{ordinal}", "static", 1)
            )
    return sorted(surfaces, key=Surface.key)


def assigned_members(entry: dict) -> tuple[dict[str, str], list[str]]:
    members = entry["members"]
    assigned: dict[str, str] = {}
    errors: list[str] = []
    for group in entry["ownership"]:
        target = group.get("target")
        decision = group.get("decision")
        if bool(target) == bool(decision):
            errors.append(
                f"{entry['path']}::{entry['name']}: ownership group needs exactly one target or decision"
            )
            continue
        label = target or f"OWNER_DECISION_REQUIRED:{decision}"
        for member in group["members"]:
            if member not in members:
                errors.append(
                    f"{entry['path']}::{entry['name']}: ownership names unknown member {member}"
                )
            if member in assigned:
                errors.append(
                    f"{entry['path']}::{entry['name']}: {member} has two assignments"
                )
            assigned[member] = label
    missing = [member for member in members if member not in assigned]
    if missing:
        errors.append(
            f"{entry['path']}::{entry['name']}: unassigned members {', '.join(missing)}"
        )
    return assigned, errors


def value_matches(value: str | int, patterns: str | int | list[str] | list[int]) -> bool:
    candidates = patterns if isinstance(patterns, list) else [patterns]
    return any(
        value == candidate
        if isinstance(candidate, int)
        else fnmatch.fnmatchcase(str(value), candidate)
        for candidate in candidates
    )


def surface_matches(spec: dict, surface: Surface) -> bool:
    values: dict[str, str | int] = {
        "category": surface.category,
        "path": surface.path,
        "symbol": surface.symbol,
        "token": surface.token,
        "ordinal": surface.ordinal,
        "key": surface.key(),
    }
    if not all(value_matches(values[field], pattern) for field, pattern in spec["match"].items()):
        return False
    return not any(
        all(value_matches(values[field], pattern) for field, pattern in exclusion.items())
        for exclusion in spec.get("exclude", [])
    )


def declaration_matches(spec: dict, member: DeclarationMember) -> bool:
    values: dict[str, str | int] = {
        "path": member.path,
        "kind": member.kind,
        "name": member.name,
        "ordinal": member.ordinal,
        "member": member.member,
        "shape_sha256": member.shape_sha256,
        "key": member.key(),
    }
    if not all(value_matches(values[field], pattern) for field, pattern in spec["match"].items()):
        return False
    return not any(
        all(value_matches(values[field], pattern) for field, pattern in exclusion.items())
        for exclusion in spec.get("exclude", [])
    )


def marker_source(marker: dict) -> str:
    source = production_text((REPO / marker["path"]).read_text(encoding="utf-8"))
    symbol = marker.get("symbol")
    if not symbol:
        return source
    spans = [span for span in function_spans(mask_rust(source)) if span.symbol() == symbol]
    if len(spans) != 1:
        raise ValueError(
            f"expected one marker scope {marker['path']}::{symbol}, found {len(spans)}"
        )
    return source[spans[0].start : spans[0].end]


def snapshot_record(keys: list[str]) -> dict[str, int | str]:
    return {
        "count": len(keys),
        "sha256": hashlib.sha256(("\n".join(keys) + "\n").encode("utf-8")).hexdigest(),
    }


def source_snapshot_keys() -> list[str]:
    keys = []
    for path in rust_sources():
        normalized = production_text(path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        keys.append(f"{relative(path)}|{digest}")
    return sorted(keys)


def assignment_label(
    group: dict,
    node_targets: set[str],
    domains: set[str],
    dispositions: set[str],
    decisions: set[str],
    context: str,
) -> tuple[str | None, list[str]]:
    selected = [
        ("target", group.get("target")),
        ("domain", group.get("domain")),
        ("disposition", group.get("disposition")),
        ("decision", group.get("decision")),
    ]
    selected = [(kind, value) for kind, value in selected if value]
    if len(selected) != 1:
        return None, [f"{context} needs exactly one target, domain, disposition, or decision"]
    kind, value = selected[0]
    allowed = {
        "target": node_targets,
        "domain": domains,
        "disposition": dispositions,
        "decision": decisions,
    }[kind]
    if value not in allowed:
        return None, [f"{context} has unknown {kind} {value}"]
    prefixes = {
        "target": "NODE",
        "domain": "DOMAIN",
        "disposition": "DISPOSITION",
        "decision": "OWNER_DECISION_REQUIRED",
    }
    return f"{prefixes[kind]}:{value}", []


def validate_inventory(inventory: dict) -> list[str]:
    errors: list[str] = []
    node_targets = set(inventory["node_targets"])
    domains = set(inventory["non_node_domains"])
    dispositions = set(inventory["dispositions"])
    decisions = {item["id"] for item in inventory["owner_decisions"]}

    all_groups = (
        inventory["declaration_rules"]
        + inventory["surface_rules"]
        + inventory["semantic_markers"]
        + inventory.get("resource_records", [])
    )
    used_decisions = {group.get("decision") for group in all_groups if group.get("decision")}
    for decision in sorted(decisions - used_decisions):
        errors.append(f"owner decision is not referenced by evidence: {decision}")
    for group in all_groups:
        flags = group.get("flags", [])
        if not isinstance(flags, list) or any(flag not in ALLOWED_FLAGS for flag in flags):
            errors.append(f"group {group.get('id', '<unnamed>')} has invalid flags {flags!r}")
    for group in inventory["semantic_markers"]:
        if not group.get("flags"):
            errors.append(
                f"semantic marker group {group.get('id', '<unnamed>')} needs a risk flag"
            )

    source_keys = source_snapshot_keys()
    source_fingerprint = snapshot_record(source_keys)["sha256"]
    source_snapshot = inventory["source_snapshot"]
    if source_snapshot["count"] != len(source_keys):
        errors.append(
            f"production source count changed: recorded {source_snapshot['count']}, "
            f"source {len(source_keys)}"
        )
    if source_snapshot["sha256"] != source_fingerprint:
        errors.append(
            "production source fingerprint changed: "
            f"recorded {source_snapshot['sha256']}, source {source_fingerprint}"
        )

    declaration_members = scan_declaration_members()
    declaration_keys = [member.key() for member in declaration_members]
    declaration_fingerprint = hashlib.sha256(
        ("\n".join(declaration_keys) + "\n").encode("utf-8")
    ).hexdigest()
    declaration_snapshot = inventory["declaration_snapshot"]
    if declaration_snapshot["count"] != len(declaration_keys):
        errors.append(
            "declaration member count changed: "
            f"recorded {declaration_snapshot['count']}, source {len(declaration_keys)}"
        )
    if declaration_snapshot["sha256"] != declaration_fingerprint:
        errors.append(
            "declaration member fingerprint changed: "
            f"recorded {declaration_snapshot['sha256']}, source {declaration_fingerprint}"
        )

    declaration_assignments: dict[str, list[str]] = {
        key: [] for key in declaration_keys
    }
    for group in inventory["declaration_rules"]:
        context = f"declaration rule {group.get('id', '<unnamed>')}"
        label, assignment_errors = assignment_label(
            group, node_targets, domains, dispositions, decisions, context
        )
        errors.extend(assignment_errors)
        if label is None:
            continue
        matched = [
            member for member in declaration_members if declaration_matches(group, member)
        ]
        if not matched:
            errors.append(
                f"declaration rule {group.get('id', '<unnamed>')} matches nothing"
            )
        for member in matched:
            declaration_assignments[member.key()].append(label)

    for key, labels in declaration_assignments.items():
        if not labels:
            errors.append(f"unassigned declaration member: {key}")
        elif len(labels) > 1:
            errors.append(
                f"declaration member has {len(labels)} assignments "
                f"({', '.join(labels)}): {key}"
            )

    surfaces = scan_surfaces()
    keys = [surface.key() for surface in surfaces]
    fingerprint = hashlib.sha256(("\n".join(keys) + "\n").encode("utf-8")).hexdigest()
    snapshot = inventory["surface_snapshot"]
    if snapshot["count"] != len(keys):
        errors.append(
            f"source surface count changed: recorded {snapshot['count']}, source {len(keys)}"
        )
    if snapshot["sha256"] != fingerprint:
        errors.append(
            f"source surface fingerprint changed: recorded {snapshot['sha256']}, source {fingerprint}"
        )

    assignments: dict[str, list[str]] = {key: [] for key in keys}
    for group in inventory["surface_rules"]:
        context = f"surface rule {group.get('id', '<unnamed>')}"
        label, assignment_errors = assignment_label(
            group, node_targets, domains, dispositions, decisions, context
        )
        errors.extend(assignment_errors)
        if label is None:
            continue
        matched = [surface for surface in surfaces if surface_matches(group, surface)]
        if not matched:
            errors.append(f"surface rule {group.get('id', '<unnamed>')} matches nothing")
        for surface in matched:
            assignments[surface.key()].append(label)
            if surface.category == "queue_unbounded" and "unbounded_queue" not in group.get("flags", []):
                errors.append(
                    f"unbounded queue rule lacks unbounded_queue flag: {group.get('id', '<unnamed>')}"
                )
            if surface.category != "queue_unbounded" and "unbounded_queue" in group.get("flags", []):
                errors.append(
                    f"unbounded_queue flag covers a non-queue surface: "
                    f"{group.get('id', '<unnamed>')} -> {surface.key()}"
                )

    for key, labels in assignments.items():
        if not labels:
            errors.append(f"unassigned source surface: {key}")
        elif len(labels) > 1:
            errors.append(f"surface has {len(labels)} assignments ({', '.join(labels)}): {key}")

    for marker_group in inventory["semantic_markers"]:
        _, assignment_errors = assignment_label(
            marker_group,
            node_targets,
            domains,
            dispositions,
            decisions,
            f"semantic marker group {marker_group.get('id', '<unnamed>')}",
        )
        errors.extend(assignment_errors)
        for marker in marker_group["items"]:
            try:
                source = marker_source(marker)
            except (OSError, ValueError) as error:
                errors.append(f"semantic marker scope failed: {error}")
                continue
            if "file_sha256" in marker:
                actual_sha256 = hashlib.sha256((REPO / marker["path"]).read_bytes()).hexdigest()
                if actual_sha256 != marker["file_sha256"]:
                    errors.append(
                        f"semantic marker file changed: {marker['path']}; "
                        f"recorded {marker['file_sha256']}, source {actual_sha256}"
                    )
            if "anchor" in marker:
                count = source.count(marker["anchor"])
                if count != marker["count"]:
                    errors.append(
                        f"semantic marker changed: {marker['path']} anchor {marker['anchor']!r}; "
                        f"recorded {marker['count']}, source {count}"
                    )
            if "before" in marker:
                before = source.find(marker["before"])
                after = source.find(marker["after"])
                if before < 0 or after < 0 or before >= after:
                    errors.append(
                        f"semantic marker ordering changed: {marker['path']} "
                        f"{marker['before']!r} before {marker['after']!r}"
                    )

    resource_surface_coverage: Counter[str] = Counter()
    surface_by_key = {surface.key(): surface for surface in surfaces}
    for resource_group in inventory.get("resource_records", []):
        _, assignment_errors = assignment_label(
            resource_group,
            node_targets,
            domains,
            dispositions,
            decisions,
            f"resource record group {resource_group.get('id', '<unnamed>')}",
        )
        errors.extend(assignment_errors)
        metrics = resource_group.get("required_metrics", [])
        expected_metrics = (
            OBSERVED_CANDIDATE_RESOURCE_METRICS
            if resource_group.get("id") == "resource-attempt-candidates"
            else REQUIRED_RESOURCE_METRICS
        )
        if set(metrics) != expected_metrics or len(metrics) != len(expected_metrics):
            required = (
                "items, logical_bytes, retained_bytes, tasks, and lifetime"
                if expected_metrics == OBSERVED_CANDIDATE_RESOURCE_METRICS
                else "items, bytes, tasks, and lifetime"
            )
            errors.append(
                f"resource record group {resource_group.get('id', '<unnamed>')} must require "
                f"exactly {required}"
            )
        for record in resource_group["items"]:
            if "surface_key" in record:
                surface_key = record["surface_key"]
                surface = surface_by_key.get(surface_key)
                if surface is None:
                    errors.append(
                        f"resource record {record['name']} names an unknown surface {surface_key}"
                    )
                elif surface.category != "queue_unbounded":
                    errors.append(
                        f"resource record {record['name']} covers non-unbounded surface {surface_key}"
                    )
                else:
                    resource_surface_coverage[surface_key] += 1
            try:
                source = marker_source(record)
            except (OSError, ValueError) as error:
                errors.append(f"resource record scope failed: {error}")
                continue
            count = source.count(record["anchor"])
            if count != record["count"]:
                errors.append(
                    f"resource record changed: {record['name']} in {record['path']}; "
                    f"recorded {record['count']}, source {count}"
                )

    for surface in surfaces:
        if surface.category != "queue_unbounded":
            continue
        coverage = resource_surface_coverage[surface.key()]
        if coverage != 1:
            errors.append(
                f"unbounded queue surface needs exactly one structured resource record, "
                f"found {coverage}: {surface.key()}"
            )

    expected = inventory.get("expected_aggregates")
    if expected is None:
        errors.append("inventory lacks expected_aggregates")
    else:
        actual_aggregates = {
            "declaration_assignments": dict(
                sorted(
                    Counter(
                        labels[0]
                        for labels in declaration_assignments.values()
                        if len(labels) == 1
                    ).items()
                )
            ),
            "surface_assignments": dict(
                sorted(
                    Counter(
                        labels[0] for labels in assignments.values() if len(labels) == 1
                    ).items()
                )
            ),
            "surface_categories": dict(
                sorted(Counter(surface.category for surface in surfaces).items())
            ),
            "semantic_marker_items": sum(
                len(group["items"]) for group in inventory["semantic_markers"]
            ),
            "resource_record_items": sum(
                len(group["items"]) for group in inventory.get("resource_records", [])
            ),
        }
        if expected != actual_aggregates:
            errors.append(
                "expected aggregate summary changed: recorded "
                f"{json.dumps(expected, sort_keys=True)}, source "
                f"{json.dumps(actual_aggregates, sort_keys=True)}"
            )

    report_path = inventory.get("report_path")
    if report_path:
        try:
            report = (REPO / report_path).read_text(encoding="utf-8")
        except OSError as error:
            errors.append(f"inventory report cannot be read: {error}")
        else:
            for anchor in inventory.get("report_anchors", []):
                count = report.count(anchor)
                if count != 1:
                    errors.append(
                        f"inventory report anchor changed: {anchor!r}; expected 1, source {count}"
                    )
            declaration_rows = expected.get("declaration_assignments", {}) if expected else {}
            surface_rows = expected.get("surface_assignments", {}) if expected else {}
            for label in sorted(set(declaration_rows) | set(surface_rows)):
                kind, name = label.split(":", 1)
                display = {
                    "NODE": name,
                    "DOMAIN": f"{name} domain",
                    "DISPOSITION": name,
                    "OWNER_DECISION_REQUIRED": f"Decision: {name}",
                }[kind]
                row = (
                    f"| {display} | {declaration_rows.get(label, 0):,} | "
                    f"{surface_rows.get(label, 0):,} |"
                )
                if report.count(row) != 1:
                    errors.append(f"inventory report assignment row changed: {row!r}")

    for module in inventory.get("target_modules", []):
        boundary = REPO / module / "BOUNDARY.md"
        if not boundary.is_file():
            errors.append(f"target module lacks BOUNDARY.md: {module}")

    return errors


def run_negative_controls(inventory: dict) -> list[str]:
    bad = copy.deepcopy(inventory)
    bad["source_snapshot"]["sha256"] = "0" * 64
    bad["declaration_rules"] = [
        rule for rule in bad["declaration_rules"] if rule["id"] != "decl-gui-client"
    ]
    bad["surface_rules"].append(
        copy.deepcopy(
            next(rule for rule in bad["surface_rules"] if rule["id"] == "surface-gui-client")
        )
    )
    bad["semantic_markers"][0]["items"][0]["count"] += 1
    bad["semantic_markers"][0]["flags"] = []
    bad["semantic_markers"] = [
        group for group in bad["semantic_markers"] if group["id"] != "marker-raw-signaling-api"
    ]
    workflow_marker = next(
        marker
        for group in bad["semantic_markers"]
        for marker in group["items"]
        if marker.get("file_sha256")
    )
    workflow_marker["file_sha256"] = "0" * 64
    bad["resource_records"][0]["items"] = bad["resource_records"][0]["items"][1:]
    bad["resource_records"][0]["required_metrics"] = ["items", "bytes", "tasks"]
    next(
        group
        for group in bad["resource_records"]
        if group["id"] == "resource-attempt-candidates"
    )["required_metrics"] = ["items", "logical_bytes", "tasks", "lifetime"]
    next(
        rule for rule in bad["surface_rules"] if rule["id"] == "surface-gui-client"
    )["flags"] = ["unbounded_queue"]
    bad["expected_aggregates"]["resource_record_items"] += 1

    errors = validate_inventory(bad)
    expected = {
        "source fingerprint": "production source fingerprint changed",
        "removed owner": "unassigned declaration member",
        "duplicate owner": "surface has 2 assignments",
        "semantic drift": "semantic marker changed",
        "semantic risk flag": "needs a risk flag",
        "unused decision": "owner decision is not referenced by evidence: OD-RAW-SIGNALING-API",
        "workflow fingerprint": "semantic marker file changed",
        "resource coverage": "unbounded queue surface needs exactly one structured resource record",
        "resource metrics": "must require exactly items, bytes, tasks, and lifetime",
        "candidate byte metrics": (
            "must require exactly items, logical_bytes, retained_bytes, tasks, and lifetime"
        ),
        "precise queue flag": "unbounded_queue flag covers a non-queue surface",
        "aggregate drift": "expected aggregate summary changed",
    }
    failures = [
        name
        for name, needle in expected.items()
        if not any(needle in error for error in errors)
    ]
    if failures:
        return [f"negative control was not rejected: {name}" for name in failures]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dump-surfaces",
        action="store_true",
        help="print the mechanically discovered production surfaces as JSON",
    )
    parser.add_argument(
        "--dump-declarations",
        action="store_true",
        help="print the mechanically discovered production declaration members as JSON",
    )
    parser.add_argument(
        "--dump-snapshots",
        action="store_true",
        help="print exact source, declaration, and effect snapshot records",
    )
    parser.add_argument(
        "--negative-controls",
        action="store_true",
        help="prove that independent source, owner, marker, and aggregate faults are rejected",
    )
    args = parser.parse_args()
    if args.dump_surfaces:
        print(json.dumps([surface.key() for surface in scan_surfaces()], indent=2))
        return 0
    if args.dump_declarations:
        print(json.dumps([member.key() for member in scan_declaration_members()], indent=2))
        return 0
    if args.dump_snapshots:
        print(
            json.dumps(
                {
                    "source_snapshot": snapshot_record(source_snapshot_keys()),
                    "declaration_snapshot": snapshot_record(
                        [member.key() for member in scan_declaration_members()]
                    ),
                    "surface_snapshot": snapshot_record(
                        [surface.key() for surface in scan_surfaces()]
                    ),
                },
                indent=2,
            )
        )
        return 0
    if not INVENTORY_PATH.is_file():
        print(f"missing inventory: {INVENTORY_PATH}", file=sys.stderr)
        return 2
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    if args.negative_controls:
        failures = run_negative_controls(inventory)
        if failures:
            print("V4 Arc 01 negative controls failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        print(
            "V4 Arc 01 negative controls passed: source fingerprint, ownership, semantic, "
            "workflow, resource, queue-flag, and aggregate faults were rejected."
        )
        return 0
    errors = validate_inventory(inventory)
    if errors:
        print("V4 Arc 01 inventory check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        "V4 Arc 01 inventory check passed: "
        f"{len(source_snapshot_keys())} production Rust source units, "
        f"{len(scan_declaration_members())} declaration members, "
        f"{len(scan_surfaces())} source surfaces, "
        f"{sum(len(group['items']) for group in inventory['semantic_markers'])} semantic markers, "
        f"{sum(len(group['items']) for group in inventory.get('resource_records', []))} resource records."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
