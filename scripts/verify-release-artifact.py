#!/usr/bin/env python3
"""Verify that shipped artifacts do not contain the transport-lab seam."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import tarfile
import zipfile


REMOVED_V3_MARKERS = (
    b"NetworkStateBroadcast",
    b"RosterSummary",
    b"RosterRequest",
    b"RosterEntries",
    b"GovernanceSnapshot",
    b"GovernanceMfaEnroll",
    b"SelfStandDownReference",
    b"CanonicalDeviceId",
    b"LegacyAuthority",
    b"network_state::",
    b"governance_state",
)

FORBIDDEN_MARKERS = (
    b"MYOWNMESH_TRANSPORT_LAB_MFA_BARRIER",
    b"TransportLab",
    b"transport_lab",
    b"transport-lab",
    *REMOVED_V3_MARKERS,
)
SCAN_CHUNK_SIZE = 64 * 1024
DESKTOP_RELEASE_TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "linux-aarch64": "aarch64-unknown-linux-gnu",
    "macos-aarch64": "aarch64-apple-darwin",
    "macos-x86_64": "x86_64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
}
APPLIANCE_RELEASE_JOBS = {
    "daemon-riscv64": ("linux-riscv64", "riscv64gc-unknown-linux-musl"),
    "daemon-aarch64-musl": ("linux-aarch64-musl", "aarch64-unknown-linux-musl"),
}
MINISIGN_ARCHIVE_NAME = "minisign-0.11-linux.tar.gz"
MINISIGN_ARCHIVE_SHA256 = (
    "F0A0954413DF8531BEFED169E447A66DA6868D79052ED7E892E50A4291AF7AE0"
)


def fail(message: str) -> None:
    raise SystemExit(f"release artifact check: {message}")


def scan_bytes(label: str, payload: bytes) -> None:
    scan_stream(label, io.BytesIO(payload))


def scan_stream(label: str, stream: object) -> None:
    """Scan a binary stream in bounded chunks, retaining marker overlap."""
    overlap = b""
    overlap_size = max(len(marker) for marker in FORBIDDEN_MARKERS) - 1
    while True:
        chunk = stream.read(SCAN_CHUNK_SIZE)
        if not chunk:
            return
        window = overlap + chunk
        found = [marker.decode("ascii") for marker in FORBIDDEN_MARKERS if marker in window]
        if found:
            fail(
                f"{label} contains transport-lab marker(s) or removed V3 marker(s): "
                f"{', '.join(found)}"
            )
        overlap = window[-overlap_size:]


def scan_file(path: pathlib.Path) -> None:
    if not path.is_file():
        fail(f"artifact does not exist: {path}")
    with path.open("rb") as stream:
        scan_stream(str(path), stream)


def verify_release_public_key(path: pathlib.Path, public_key: str) -> None:
    """Require a compiled daemon to carry the publication trust anchor."""
    if not public_key.strip():
        fail("release trust-anchor verification requires a non-empty public key")
    if not path.is_file():
        fail(f"artifact does not exist: {path}")
    marker = public_key.strip().encode("ascii", errors="strict")
    try:
        payload = path.read_bytes()
    except OSError as error:
        fail(f"cannot read release trust-anchor artifact {path}: {error}")
    if marker not in payload:
        fail(f"{path} does not embed the configured release public key")


def iter_regular_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Return every regular file below *root*, refusing ambiguous entries."""
    if root.is_symlink():
        fail(f"artifact tree root is an unsupported symlink: {root}")
    if not root.is_dir():
        fail(f"artifact tree does not exist or is not a directory: {root}")
    files: list[pathlib.Path] = []
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as error:
            fail(f"cannot enumerate artifact tree {current}: {error}")
        for entry in entries:
            path = pathlib.Path(entry.path)
            if entry.is_symlink():
                fail(f"artifact tree contains an unsupported symlink: {path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                files.append(path)
            else:
                fail(f"artifact tree contains a non-regular entry: {path}")
    if not files:
        fail(f"artifact tree contains no regular files: {root}")
    return sorted(files)


def scan_tree(root: pathlib.Path) -> None:
    """Scan every regular file in an installer/bundle tree."""
    files = iter_regular_files(root)
    empty = [str(path) for path in files if path.stat().st_size == 0]
    if empty:
        fail("installer tree contains empty regular file(s): " + ", ".join(empty))
    for path in files:
        scan_file(path)


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(SCAN_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot read checksum payload {path}: {error}")
    return digest.hexdigest()


def verify_checksum_sidecars(root: pathlib.Path) -> None:
    """Validate every checksum sidecar against its sibling payload."""
    files = iter_regular_files(root)
    by_name: dict[str, pathlib.Path] = {}
    for path in files:
        if path.name in by_name:
            fail(f"checksum tree has duplicate basename: {path.name}")
        by_name[path.name] = path

    for sidecar in files:
        if not sidecar.name.endswith(".sha256"):
            continue
        payload_name = sidecar.name[: -len(".sha256")]
        payload = by_name.get(payload_name)
        if payload is None:
            fail(
                f"checksum sidecar {sidecar.name} has no matching payload "
                f"{payload_name}"
            )
        try:
            lines = sidecar.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            fail(f"cannot read checksum sidecar {sidecar}: {error}")
        if len(lines) != 1 or not lines[0].strip():
            fail(f"checksum sidecar {sidecar.name} must contain exactly one record")
        match = re.fullmatch(r"\s*([0-9a-fA-F]{64})\s+(\*?)(.+?)\s*", lines[0])
        if match is None or match.group(3) != payload_name:
            fail(f"checksum sidecar {sidecar.name} names the wrong payload")
        actual = _sha256_file(payload)
        if match.group(1).lower() != actual:
            fail(
                f"checksum mismatch for {payload_name}: "
                f"declared {match.group(1).lower()}, actual {actual}"
            )


def required_signature_targets(root: pathlib.Path) -> list[pathlib.Path]:
    """Return release files that must carry detached signature provenance."""
    files = iter_regular_files(root)
    targets = [
        path
        for path in files
        if not path.name.endswith((".minisig", ".sha256"))
    ]
    if not targets:
        fail(f"signature tree contains no release payloads: {root}")
    expected_signatures = {
        path.with_name(path.name + ".minisig") for path in targets
    }
    orphaned = sorted(
        path.name
        for path in files
        if path.name.endswith(".minisig") and path not in expected_signatures
    )
    if orphaned:
        fail(
            "orphan signature sidecar(s) have no release payload: "
            + ", ".join(orphaned)
        )
    missing = [
        path.name
        for path in targets
        if not path.with_name(path.name + ".minisig").is_file()
    ]
    if missing:
        fail(
            "signature provenance missing for release payload(s): "
            + ", ".join(sorted(missing))
        )
    return targets


def write_asset_manifest(roots: list[pathlib.Path], output: pathlib.Path) -> None:
    """Write the build-owned exact release basename/digest allowlist."""
    assets: dict[str, str] = {}
    for root in roots:
        for path in iter_regular_files(root):
            name = path.name
            if name.endswith(".minisig"):
                continue
            if name in assets:
                fail(f"asset manifest has duplicate release basename: {name}")
            assets[name] = _sha256_file(path)
    if not assets:
        fail("asset manifest contains no release payloads")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"assets": dict(sorted(assets.items()))}, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_asset_allowlist(root: pathlib.Path) -> dict[str, str]:
    """Load and validate all source/build-owned JSON allowlists below *root*."""
    if not root.is_dir() or root.is_symlink():
        fail(f"asset allowlist directory does not exist: {root}")
    paths = sorted(root.glob("*.json"))
    if not paths:
        fail(f"asset allowlist directory contains no manifests: {root}")
    assets: dict[str, str] = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            fail(f"asset allowlist contains a non-regular manifest: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            fail(f"invalid asset allowlist {path}: {error}")
        entries = document.get("assets") if isinstance(document, dict) else None
        if not isinstance(entries, dict) or not entries:
            fail(f"asset allowlist {path} has no assets object")
        for name, digest in entries.items():
            if (
                not isinstance(name, str)
                or pathlib.PurePath(name).name != name
                or name in ("", ".", "..")
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None
            ):
                fail(f"asset allowlist {path} contains an invalid asset record")
            old = assets.get(name)
            if old is not None and old.lower() != digest.lower():
                fail(f"asset allowlist has conflicting digest for {name}")
            assets[name] = digest.lower()
    return assets


def verify_asset_allowlist(root: pathlib.Path, allowlist: pathlib.Path) -> dict[str, str]:
    expected = load_asset_allowlist(allowlist)
    actual = {
        path.name: _sha256_file(path)
        for path in iter_regular_files(root)
        if not path.name.endswith(".minisig")
    }
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    mismatched = sorted(
        name for name in set(expected) & set(actual) if expected[name] != actual[name]
    )
    if missing or unexpected or mismatched:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        if mismatched:
            details.append("digest mismatch " + ", ".join(mismatched))
        fail("release asset allowlist mismatch: " + "; ".join(details))
    return expected


def _gh_json(repository: str, endpoint: str) -> dict | None:
    """Read one GitHub API object, distinguishing a missing object from failure."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/{endpoint}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        if "404" in detail or "Not Found" in detail:
            return None
        fail(f"GitHub preflight query failed for {endpoint}: {detail}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"GitHub preflight returned invalid JSON for {endpoint}: {error}")
    if not isinstance(value, dict):
        fail(f"GitHub preflight returned a non-object for {endpoint}")
    return value


def _gh_release_create(repository: str, tag: str, commit: str) -> None:
    result = subprocess.run(
        [
            "gh",
            "release",
            "create",
            tag,
            "--repo",
            repository,
            "--target",
            commit,
            "--draft",
            "--title",
            tag,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        fail(f"could not create the exact draft release {tag}: {detail}")


def _resolve_tag_commit(repository: str, tag: str, tag_ref: dict) -> str:
    """Resolve a lightweight or annotated tag to its exact commit SHA."""
    tag_object = tag_ref.get("object")
    seen: set[str] = set()
    while isinstance(tag_object, dict) and tag_object.get("type") == "tag":
        tag_sha = tag_object.get("sha")
        if not isinstance(tag_sha, str) or not tag_sha or tag_sha in seen:
            fail(f"release tag {tag} has an invalid or cyclic annotated target")
        seen.add(tag_sha)
        annotated = _gh_json(repository, f"git/tags/{tag_sha}")
        if annotated is None:
            fail(f"release tag {tag} has an unreadable annotated target {tag_sha}")
        tag_object = annotated.get("object")
    if not isinstance(tag_object, dict) or tag_object.get("type") != "commit":
        fail(f"release tag {tag} does not resolve to a commit")
    sha = tag_object.get("sha")
    if not isinstance(sha, str) or not sha:
        fail(f"release tag {tag} has no commit SHA")
    return sha


def preflight_release(tag: str, commit: str, repository: str) -> None:
    """Refuse public/repointed tags and establish one exact draft release."""
    if not tag or not commit or not repository:
        fail("release preflight requires non-empty tag, commit, and repository")

    tag_ref = _gh_json(repository, f"git/ref/tags/{tag}")
    if tag_ref is not None:
        resolved_commit = _resolve_tag_commit(repository, tag, tag_ref)
        if resolved_commit != commit:
            fail(
                f"release tag {tag} targets {resolved_commit}, "
                f"not the requested commit {commit}"
            )

    release = _gh_json(repository, f"releases/tags/{tag}")
    if release is not None:
        if release.get("draft") is not True:
            fail(f"release tag {tag} is already public; refusing to overwrite it")
        if release.get("target_commitish") != commit:
            fail(
                f"draft release {tag} targets {release.get('target_commitish')}, "
                f"not the requested commit {commit}"
            )
        return

    _gh_release_create(repository, tag, commit)
    created = _gh_json(repository, f"releases/tags/{tag}")
    if created is None or created.get("draft") is not True:
        fail(f"release preflight did not establish a draft for {tag}")
    if created.get("target_commitish") != commit:
        fail(
            f"new draft release {tag} targets {created.get('target_commitish')}, "
            f"not the requested commit {commit}"
        )


def verify_signature_tree(
    root: pathlib.Path,
    public_key: str,
    minisign_binary: str = "minisign",
    asset_allowlist: pathlib.Path | None = None,
) -> None:
    """Verify every release payload has a valid detached minisign signature."""
    if not public_key.strip():
        fail("signature provenance requires a non-empty minisign public key")
    verify_checksum_sidecars(root)
    if asset_allowlist is not None:
        verify_asset_allowlist(root, asset_allowlist)
    for path in required_signature_targets(root):
        signature = path.with_name(path.name + ".minisig")
        try:
            result = subprocess.run(
                [
                    minisign_binary,
                    "-Vm",
                    str(path),
                    "-P",
                    public_key,
                    "-x",
                    str(signature),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as error:
            fail(f"cannot verify release signature for {path}: {error}")
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            fail(f"invalid release signature for {path}: {detail}")


def verify_remote_release_assets(
    root: pathlib.Path,
    repository: str,
    tag: str,
    public_key: str,
    asset_allowlist: pathlib.Path | None = None,
    remote_tree: pathlib.Path | None = None,
) -> None:
    """Recheck the draft's complete payload/signature set after upload.

    When *remote_tree* is supplied, it must be a fresh download of the
    release.  Its payload bytes are checked against the build-owned digest
    allowlist and its detached signatures are verified independently, so
    release metadata cannot stand in for the bytes that will be published.
    """
    if not repository or not tag:
        fail("remote asset verification requires a repository and tag")
    expected_payloads = verify_asset_allowlist(root, asset_allowlist) if asset_allowlist else None
    verify_signature_tree(root, public_key, asset_allowlist=asset_allowlist)
    release = _gh_json(repository, f"releases/tags/{tag}?per_page=100")
    if release is None:
        fail(f"release {tag} disappeared before publication")
    if release.get("draft") is not True:
        fail(f"release {tag} is no longer a draft before publication")
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail(f"release {tag} returned no typed asset list")
    remote_names: list[str] = []
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            fail(f"release {tag} returned an invalid asset record")
        if asset.get("state") != "uploaded":
            fail(f"release {tag} asset {asset['name']} is not uploaded")
        remote_names.append(asset["name"])
    if len(remote_names) != len(set(remote_names)):
        fail(f"release {tag} returned duplicate asset names")
    expected_names = (
        list(expected_payloads)
        + [f"{name}.minisig" for name in expected_payloads if not name.endswith(".sha256")]
        if expected_payloads is not None
        else [path.name for path in iter_regular_files(root)]
    )
    if set(remote_names) != set(expected_names):
        missing = sorted(set(expected_names) - set(remote_names))
        unexpected = sorted(set(remote_names) - set(expected_names))
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        fail(f"release {tag} asset/signature set mismatch: {'; '.join(details)}")
    if remote_tree is not None:
        if expected_payloads is None:
            fail("remote asset verification requires a build-owned asset allowlist")
        remote_files = {path.name for path in iter_regular_files(remote_tree)}
        if remote_files != set(expected_names):
            missing = sorted(set(expected_names) - remote_files)
            unexpected = sorted(remote_files - set(expected_names))
            details = []
            if missing:
                details.append("download missing " + ", ".join(missing))
            if unexpected:
                details.append("download unexpected " + ", ".join(unexpected))
            fail("downloaded release asset set mismatch: " + "; ".join(details))
        verify_asset_allowlist(remote_tree, asset_allowlist)
        verify_signature_tree(
            remote_tree,
            public_key,
            asset_allowlist=asset_allowlist,
        )


def verify_minisign_installation(path: pathlib.Path, sign_job: str) -> None:
    """Require an immutable, verified signer before any signing key is exposed."""
    archive_declaration = f'minisign_archive="{MINISIGN_ARCHIVE_NAME}"'
    if archive_declaration not in sign_job:
        fail(f"sign job does not pin the minisign archive name: {path}")
    if (
        "https://github.com/jedisct1/minisign/releases/download/0.11/"
        "$minisign_archive"
    ) not in sign_job:
        fail(f"sign job does not pin the minisign 0.11 download URL: {path}")
    if MINISIGN_ARCHIVE_SHA256 not in sign_job:
        fail(f"sign job does not pin the minisign archive digest: {path}")
    digest_check = (
        'printf \'%s  %s\\n\' "$minisign_archive_sha256" "$minisign_archive" '
        "| sha256sum --check"
    )
    if digest_check not in sign_job:
        fail(f"sign job does not verify the minisign archive digest: {path}")

    install_start = sign_job.find("      - name: Install minisign\n")
    gate_start = sign_job.find("      - name: Gate on signing key\n")
    digest_start = sign_job.find(digest_check, install_start)
    extract_start = sign_job.find('          tar -xzf "$minisign_archive"', install_start)
    binary_check = sign_job.find("          test -x minisign-linux/x86_64/minisign", install_start)
    install_command = sign_job.find(
        "          sudo install -m 0755 minisign-linux/x86_64/minisign /usr/local/bin/minisign",
        install_start,
    )
    if install_start < 0 or digest_start < 0 or extract_start < 0:
        fail(f"sign job has no complete minisign installation verification: {path}")
    if digest_start >= extract_start:
        fail(f"sign job verifies the minisign archive after extraction: {path}")
    if binary_check < 0 or install_command < 0 or binary_check >= install_command:
        fail(f"sign job does not verify the minisign executable before install: {path}")
    if gate_start < 0 or gate_start <= install_command:
        fail(f"signing keys are exposed before signer verification: {path}")
    pre_gate = sign_job[:gate_start]
    for key_name in ("MINISIGN_SECRET_KEY", "MINISIGN_PUBLIC_KEY", "MYOWNMESH_RELEASE_PUBKEY"):
        if key_name in pre_gate:
            fail(f"signing key {key_name} is exposed before signer verification: {path}")


def zip_member_is_regular_file(member: zipfile.ZipInfo) -> bool:
    if member.is_dir():
        return False
    if member.create_system == 3:
        mode = (member.external_attr >> 16) & 0xFFFF
        if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            return False
    return True


def scan_archive(path: pathlib.Path, expected_members: list[str]) -> None:
    if not path.is_file():
        fail(f"archive does not exist: {path}")
    if not expected_members:
        fail(f"archive scan requires at least one expected member: {path}")
    if len(set(expected_members)) != len(expected_members):
        fail(f"{path} has duplicate expected member arguments")
    expected = set(expected_members)
    entry_counts = {name: 0 for name in expected}
    regular_counts = {name: 0 for name in expected}
    empty_members: set[str] = set()
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.filename in expected:
                    entry_counts[member.filename] += 1
                    if zip_member_is_regular_file(member):
                        regular_counts[member.filename] += 1
                        if member.file_size == 0:
                            empty_members.add(member.filename)
                if not zip_member_is_regular_file(member):
                    continue
                with archive.open(member) as stream:
                    scan_stream(f"{path}!{member.filename}", stream)
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                if member.name in expected:
                    entry_counts[member.name] += 1
                if member.isfile():
                    if member.name in expected:
                        regular_counts[member.name] += 1
                        if member.size == 0:
                            empty_members.add(member.name)
                    stream = archive.extractfile(member)
                    if stream is not None:
                        with stream:
                            scan_stream(f"{path}!{member.name}", stream)
    else:
        fail(f"unsupported archive type: {path}")
    duplicates = sorted(name for name, count in entry_counts.items() if count > 1)
    if duplicates:
        fail(f"{path} has duplicate expected member entr{'y' if len(duplicates) == 1 else 'ies'}: {', '.join(duplicates)}")
    nonregular = sorted(name for name in expected if regular_counts[name] != 1)
    if nonregular:
        fail(f"{path} expected member(s) are not exactly one regular file: {', '.join(nonregular)}")
    if empty_members:
        fail(f"{path} expected member(s) are empty: {', '.join(sorted(empty_members))}")
    missing = sorted(name for name in expected if entry_counts[name] == 0)
    if missing:
        fail(f"{path} is missing expected member(s): {', '.join(missing)}")


def verify_workflow(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    if not re.search(r"(?ms)^concurrency:\s*\n\s+group:\s*release-", text):
        fail(f"release workflow lacks per-tag concurrency fencing: {path}")
    lines = text.splitlines()
    jobs: dict[str, str] = {}
    current_job: str | None = None
    for line in lines:
        match = re.match(r"^  ([A-Za-z0-9_-]+):$", line)
        if match:
            current_job = match.group(1)
            jobs[current_job] = ""
        elif current_job is not None:
            jobs[current_job] += line + "\n"

    def job_needs(body: str) -> set[str]:
        lines = body.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"^    needs:\s*(.*)$", line)
            if match is None:
                continue
            value = match.group(1).strip()
            if value:
                if value.startswith("[") and value.endswith("]"):
                    return {
                        item.strip().strip("'\"")
                        for item in value[1:-1].split(",")
                        if item.strip()
                    }
                return {value.strip("'\"")}
            dependencies: set[str] = set()
            for dependency_line in lines[index + 1 :]:
                item = re.match(r"^      -\s*[\"']?([A-Za-z0-9_-]+)[\"']?\s*$", dependency_line)
                if item is not None:
                    dependencies.add(item.group(1))
                    continue
                if dependency_line.strip() and not dependency_line.startswith("      "):
                    break
            return dependencies
        return set()

    dependencies = {job_name: job_needs(body) for job_name, body in jobs.items()}
    unknown_dependencies = sorted(
        f"{job_name}->{dependency}"
        for job_name, needs in dependencies.items()
        for dependency in needs
        if dependency not in jobs
    )
    if unknown_dependencies:
        fail(
            "release workflow has unknown job dependency(ies): "
            + ", ".join(unknown_dependencies)
        )

    visit_state: dict[str, int] = {}

    def visit(job_name: str) -> None:
        state = visit_state.get(job_name, 0)
        if state == 1:
            fail(f"release workflow has a dependency cycle at {job_name}")
        if state == 2:
            return
        visit_state[job_name] = 1
        for dependency in dependencies.get(job_name, ()):
            visit(dependency)
        visit_state[job_name] = 2

    for job_name in jobs:
        visit(job_name)

    sign_job = jobs.get("sign", "")
    if not sign_job:
        fail(f"release workflow has no signer job: {path}")
    verify_minisign_installation(path, sign_job)

    def depends_on(job_name: str, prerequisite: str) -> bool:
        pending = list(dependencies.get(job_name, ()))
        visited: set[str] = set()
        while pending:
            dependency = pending.pop()
            if dependency == prerequisite:
                return True
            if dependency in visited:
                continue
            visited.add(dependency)
            pending.extend(dependencies.get(dependency, ()))
        return False

    preflight = jobs.get("prepare-release", "")
    if not preflight:
        fail(f"release workflow has no source-owned prepare-release job: {path}")
    for required in (
        "--preflight-release",
        "--tag",
        "--commit",
        "$GITHUB_SHA",
        "--repository",
        "$GITHUB_REPOSITORY",
    ):
        if required not in preflight:
            fail(f"prepare-release does not verify {required}: {path}")
    for platform, target in DESKTOP_RELEASE_TARGETS.items():
        row = re.search(
            rf"-\s*\{{\s*name:\s*{re.escape(platform)},"
            rf"\s*os:\s*[^,]+,\s*target:\s*{re.escape(target)}\s*\}}",
            text,
        )
        if row is None:
            fail(
                f"release workflow is missing required release target "
                f"{platform} ({target})"
            )
    for job_name, (platform, target) in APPLIANCE_RELEASE_JOBS.items():
        body = jobs.get(job_name, "")
        if f"({platform})" not in body or target not in body:
            fail(
                f"release workflow is missing required release target "
                f"{platform} ({target})"
            )
    if "--tree" not in text or "release/bundle" not in text:
        fail(f"release workflow does not scan every Tauri installer tree: {path}")
    if "--archive" not in text or "--member" not in text:
        fail(f"release workflow does not verify packaged archive members: {path}")
    if text.count("--preflight-release") < 2:
        fail(f"release workflow does not re-resolve the exact tag before publish: {path}")
    if "--asset-allowlist" not in text or "--write-asset-manifest" not in text:
        fail(f"release workflow lacks source-owned release asset allowlists: {path}")
    if "actions/download-artifact@v4" not in text:
        fail(f"release workflow does not retrieve build-owned asset allowlists: {path}")
    if "actions/upload-artifact@v4" not in text:
        fail(f"release workflow does not publish build-owned asset allowlists: {path}")
    if "MYOWNMESH_RELEASE_PUBKEY" not in text or "MINISIGN_PUBLIC_KEY" not in text:
        fail(f"release workflow does not bind artifacts to the publication key: {path}")
    for job_name, body in jobs.items():
        script_lines = [
            index
            for index, line in enumerate(body.splitlines())
            if re.search(r"\bpython(?:3)?\s+[^#]*(?:scripts/|\$GITHUB_WORKSPACE/scripts/)", line)
        ]
        checkout_lines = [
            index for index, line in enumerate(body.splitlines()) if "actions/checkout@" in line
        ]
        if script_lines and (not checkout_lines or min(checkout_lines) > min(script_lines)):
            fail(f"release job {job_name} uses a script before checkout")
        if checkout_lines:
            for required in (
                "ref: ${{ github.sha }}",
                "fetch-depth: 0",
                "git rev-parse HEAD",
                "git merge-base --is-ancestor",
                "git remote get-url origin",
                "$GITHUB_REPOSITORY",
            ):
                if required not in body:
                    fail(f"release job {job_name} lacks exact checkout/origin proof: {required}")
        action_publisher = "action-gh-release@" in body or "tauri-apps/tauri-action@" in body
        command_writer = re.search(r"\bgh\s+release\s+(?:upload|edit)\b", body) is not None
        if not (action_publisher or command_writer):
            continue
        if not depends_on(job_name, "prepare-release"):
            fail(f"release writer job {job_name} does not depend on prepare-release")
        if not depends_on(job_name, "release-gates"):
            fail(f"release writer job {job_name} does not depend on release-gates")
        if "action-gh-release@" in body and not re.search(r"(?m)^\s+draft:\s*true\s*$", body):
            fail(f"publisher job {job_name} can publish a non-draft release")
        if "tauri-apps/tauri-action@" in body and not re.search(
            r"(?m)^\s+releaseDraft:\s*true\s*$", body
        ):
            fail(f"publisher job {job_name} can publish a non-draft Tauri release")

        if "tauri-apps/tauri-action@" in body:
            if "MYOWNMESH_RELEASE_PUBKEY" not in body or "MINISIGN_PUBLIC_KEY" not in body:
                fail(f"Tauri publisher job {job_name} lacks publication-key binding")
            if not re.search(
                r"[\"']?\$MYOWNMESH_RELEASE_PUBKEY[\"']?\s*=\s*[\"']?\$MINISIGN_PUBLIC_KEY|[\"']?\$MINISIGN_PUBLIC_KEY[\"']?\s*=\s*[\"']?\$MYOWNMESH_RELEASE_PUBKEY",
                body,
            ):
                fail(f"Tauri publisher job {job_name} lacks key equality proof")

        if job_name == "sign":
            signature_step = re.search(
                r"(?ms)^      - name: Sign and upload signatures\n(?P<body>.*?)(?=^      - name:|\Z)",
                body,
            )
            remote_step = re.search(
                r"(?ms)^      - name: Recheck uploaded payload/signature set while draft\n(?P<body>.*?)(?=^      - name:|\Z)",
                body,
            )
            if signature_step is None or "MINISIGN_PUBLIC_KEY" not in signature_step.group("body"):
                fail("sign step does not receive MINISIGN_PUBLIC_KEY")
            if remote_step is None or "MINISIGN_PUBLIC_KEY" not in remote_step.group("body"):
                fail("release asset verification step does not receive MINISIGN_PUBLIC_KEY")
            sign_start = body.find("Sign and upload signatures")
            first_allowlist = body.find("--asset-allowlist")
            if first_allowlist < 0 or first_allowlist > sign_start:
                fail("sign job does not reject stale assets before signing")

    for job_name, body in jobs.items():
        for line_number, line in enumerate(body.splitlines(), 1):
            release_build = re.search(
                r"cargo\s+(?:zigbuild|build)\s+[^\n]*--release[^\n]*--bin\s+myownmesh",
                line,
            )
            if release_build and "--no-default-features" not in line:
                fail(f"release daemon build at {path}:{line_number} lacks --no-default-features")
            if release_build and (
                "MYOWNMESH_RELEASE_PUBKEY" not in body
                or "--release-public-key" not in body
            ):
                fail(f"release daemon build in {job_name} lacks publication-key binding")
            if re.search(r"cargo\s+(?:zigbuild|build)\s+[^\n]*--release[^\n]*--features[^\n]*transport-lab", line):
                fail(f"release workflow enables transport-lab at {path}:{line_number}")
    if "--signature-tree" not in text or "--public-key" not in text:
        fail(f"release workflow does not verify detached signatures before publish: {path}")
    if "--verify-release-assets" not in text:
        fail(f"release workflow does not recheck uploaded release assets: {path}")
    if "gh release edit \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --draft=false" in text:
        if text.index("--signature-tree") > text.index("--draft=false"):
            fail(f"release workflow publishes before signature verification: {path}")
        if text.index("--verify-release-assets") > text.index("--draft=false"):
            fail(f"release workflow publishes before asset-set verification: {path}")
        publish_index = text.index('gh release edit "$TAG" --repo "$GITHUB_REPOSITORY" --draft=false')
        preflight_positions = [
            match.start() for match in re.finditer(r"--preflight-release", text)
        ]
        if len(preflight_positions) < 2 or preflight_positions[-1] >= publish_index:
            fail(f"release workflow lacks an immediate late exact-tag preflight: {path}")
        late_preflight = text[preflight_positions[-1] : publish_index]
        for required in ("--tag", "--commit", "$GITHUB_SHA", "--repository"):
            if required not in late_preflight:
                fail(f"late exact-tag preflight does not verify {required}: {path}")
        publish_marker = "      - name: Publish signed release\n"
        publish_start = text.rfind(publish_marker)
        if publish_start < 0:
            fail(f"release workflow has no named final publish step: {path}")
        publish_body = text[publish_start:]
        for required in (
            "--preflight-release",
            "--verify-release-assets",
            "--remote-tree",
            "gh release download",
            "gh release edit \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --draft=false",
        ):
            if required not in publish_body:
                fail(f"final publish step lacks immediate verification: {required}")
    if "signing/minisign.key" in text:
        fail(f"release workflow places the minisign secret in the payload tree: {path}")


def verify_manifest(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    features = re.search(r"(?ms)^\[features\]\s*(.*?)(?=^\[|\Z)", text)
    if features is None:
        fail(f"manifest has no [features] section: {path}")
    body = features.group(1)
    if not re.search(r"(?m)^default\s*=\s*\[\s*\]\s*$", body):
        fail(f"shipped CLI defaults are not empty: {path}")
    if not re.search(r'(?m)^transport-lab\s*=\s*\[\s*"myownmesh-core/transport-lab"\s*\]\s*$', body):
        fail(f"transport-lab test feature forwarding changed unexpectedly: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=pathlib.Path)
    parser.add_argument("--archive", type=pathlib.Path)
    parser.add_argument(
        "--tree",
        action="append",
        default=[],
        type=pathlib.Path,
        help="scan every regular file below an installer/bundle tree",
    )
    parser.add_argument(
        "--member",
        action="append",
        default=[],
        help="exact regular-file member required in --archive (repeatable)",
    )
    parser.add_argument("--workflow", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--signature-tree", type=pathlib.Path)
    parser.add_argument("--public-key")
    parser.add_argument("--release-public-key")
    parser.add_argument("--asset-allowlist", type=pathlib.Path)
    parser.add_argument("--write-asset-manifest", type=pathlib.Path)
    parser.add_argument(
        "--remote-tree",
        type=pathlib.Path,
        help="freshly downloaded release tree to verify against the build allowlist",
    )
    parser.add_argument("--verify-release-assets", action="store_true")
    parser.add_argument("--preflight-release", action="store_true")
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--repository")
    args = parser.parse_args()
    if args.preflight_release:
        preflight_release(
            args.tag or "",
            args.commit or "",
            args.repository or os.environ.get("GITHUB_REPOSITORY", ""),
        )
        print("release draft preflight: PASS")
        return
    if not any(
        (
            args.binary,
            args.archive,
            args.tree,
            args.workflow,
            args.manifest,
            args.signature_tree,
            args.verify_release_assets,
            args.write_asset_manifest,
            args.remote_tree,
        )
    ):
        parser.error("at least one scan target is required")
    if args.binary:
        scan_file(args.binary)
        if args.release_public_key:
            verify_release_public_key(args.binary, args.release_public_key)
    if args.archive:
        scan_archive(args.archive, args.member)
    for tree in args.tree:
        scan_tree(tree)
    if args.asset_allowlist and not args.signature_tree:
        if not args.tree:
            parser.error("--asset-allowlist requires --tree or --signature-tree")
        verify_asset_allowlist(args.tree[0], args.asset_allowlist)
    if args.write_asset_manifest:
        if not args.tree:
            parser.error("--write-asset-manifest requires at least one --tree")
        write_asset_manifest(args.tree, args.write_asset_manifest)
    if args.workflow:
        verify_workflow(args.workflow)
    if args.manifest:
        verify_manifest(args.manifest)
    if args.verify_release_assets:
        if args.signature_tree is None or args.public_key is None:
            parser.error("--verify-release-assets requires --signature-tree and --public-key")
        if args.remote_tree is not None and args.asset_allowlist is None:
            parser.error("--remote-tree requires --asset-allowlist")
        verify_remote_release_assets(
            args.signature_tree,
            args.repository or os.environ.get("GITHUB_REPOSITORY", ""),
            args.tag or os.environ.get("TAG", ""),
            args.public_key,
            args.asset_allowlist,
            args.remote_tree,
        )
    elif args.signature_tree:
        if args.public_key is None:
            parser.error("--signature-tree requires --public-key")
        verify_signature_tree(
            args.signature_tree,
            args.public_key,
            asset_allowlist=args.asset_allowlist,
        )
    elif args.remote_tree:
        parser.error("--remote-tree requires --verify-release-assets")
    print("release artifact boundary: PASS")


if __name__ == "__main__":
    main()
