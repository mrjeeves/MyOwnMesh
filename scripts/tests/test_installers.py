"""Production-shaped checksum controls for the release installers."""

import json
from pathlib import Path
import hashlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class InstallerChecksumControls(unittest.TestCase):
    @staticmethod
    def _extract_sh_function(source: str, name: str) -> str:
        start = source.index(f"{name}() {{")
        end = source.index("\n}\n", start) + 3
        return source[start:end]

    def test_posix_release_paths_verify_exact_asset_before_extract(self) -> None:
        source = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
        self.assertIn("verify_sha256_sidecar", source)
        self.assertIn("Malformed or orphaned SHA256 sidecar", source)
        self.assertIn("length(hash) != 64", source)
        self.assertIn("No SHA-256 implementation is available", source)
        self.assertNotIn("skipping integrity check", source)

        for function, cleanup in (
            ("try_release", "_cleanup_try_release"),
            ("try_release_gui", "_cleanup_try_gui"),
        ):
            start = source.index(f"\n{function}() {{") + 1
            end = source.find("\n}\n", start) + 3
            self.assertGreater(end, start)
            body = source[start:end]
            self.assertRegex(body, rf"(?m)^  trap {cleanup} 0 2 15$")
            self.assertRegex(body, r"(?m)^  trap - 0 2 15$")
            self.assertNotRegex(body, r"(?m)^  trap .*\bEXIT\b")

        for archive, extractor, installer in (
            ("$ASSET", "tar -xzf", "install_binary"),
            ("$GUI_ASSET", "tar -xzf", "install_gui_binary"),
        ):
            start = source.index(
                f'verify_sha256_sidecar "$_TRY_', source.index(archive)
            )
            self.assertLess(start, source.index(extractor, start))
            self.assertLess(start, source.index(installer, start))

        self.assertIn('if ! tar -xzf', source)
        self.assertIn('if ! install_binary', source)
        self.assertIn('if ! install_gui_binary', source)

    def test_bash_production_helpers_refuse_failed_extract_and_install(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is unavailable")
        probe = subprocess.run(
            [bash, "-c", "exit 0"], check=False, capture_output=True, text=True
        )
        if probe.returncode != 0:
            self.skipTest("bash is present but not executable in this environment")

        source = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
        functions = "\n".join(
            self._extract_sh_function(source, name)
            for name in (
                "log",
                "warn",
                "err",
                "install_binary",
                "install_gui_binary",
                "_cleanup_try_release",
                "verify_sha256_sidecar",
                "try_release",
                "_cleanup_try_gui",
                "try_release_gui",
            )
        )
        payload = "fixture payload"
        digest = hashlib.sha256(payload.encode()).hexdigest()
        fixture = f'''#!/usr/bin/env bash
set -eu
ROOT="$1"
MODE="$2"
PREFIX_DIR="$ROOT/prefix"
TMPDIR="$ROOT/tmp"
REPO=fixture/repo
DRY_RUN=false
ASSET=myownmesh-linux-x86_64.tar.gz
GUI_ASSET=myownmesh-gui-linux-x86_64.tar.gz
PAYLOAD={payload!r}
DIGEST={digest!r}
mkdir -p "$TMPDIR"

curl() {{
  if [[ "$*" == *api.github.com* ]]; then
    printf '%s\\n' '{{"assets":[{{"browser_download_url":"https://fixture/myownmesh-linux-x86_64.tar.gz"}},{{"browser_download_url":"https://fixture/myownmesh-gui-linux-x86_64.tar.gz"}}]}}'
    return 0
  fi
  out=""
  previous=""
  for arg in "$@"; do
    if [ "$previous" = "-o" ]; then out="$arg"; fi
    previous="$arg"
  done
  [ -n "$out" ] || return 1
  case "$out" in
    *.sha256) printf '%s  %s\\n' "$DIGEST" "${{out##*/}}" | sed 's/\\.sha256$//' > "$out" ;;
    *) printf '%s' "$PAYLOAD" > "$out" ;;
  esac
}}

tar() {{
  [ "$MODE" != "tar-fail" ] || return 1
  destination=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "-C" ]; then destination="$2"; shift 2; else shift; fi
  done
  [ -n "$destination" ] || return 1
  case "$destination" in
    *tmp.*) printf '%s' "daemon extracted" > "$destination/myownmesh"; printf '%s' "gui extracted" > "$destination/myownmesh-gui" ;;
    *) return 1 ;;
  esac
}}

install() {{
  [ "$MODE" != "install-fail" ] || return 1
  previous=""
  last=""
  for arg in "$@"; do previous="$last"; last="$arg"; done
  [ -n "$previous" ] && [ -n "$last" ] || return 1
  cp "$previous" "$last"
}}

{functions}

if try_release; then daemon_status=0; else daemon_status=$?; fi
if try_release_gui; then gui_status=0; else gui_status=$?; fi
daemon_installed=false
gui_installed=false
[ -f "$PREFIX_DIR/myownmesh" ] && daemon_installed=true
[ -f "$PREFIX_DIR/myownmesh-gui" ] && gui_installed=true
remaining="$(find "$TMPDIR" -mindepth 1 -maxdepth 1 -type d -print | wc -l)"
printf '__RESULT__%s|%s|%s|%s|%s\\n' "$daemon_status" "$gui_status" "$daemon_installed" "$gui_installed" "$remaining"
'''

        for mode, expected_status, expected_installed in (
            ("success", (0, 0), (True, True)),
            ("tar-fail", (1, 1), (False, False)),
            ("install-fail", (1, 1), (False, False)),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                fixture_script = Path(temporary) / "posix-helper-fixture.sh"
                fixture_script.write_text(fixture, encoding="utf-8")
                completed = subprocess.run(
                    [bash, str(fixture_script), temporary, mode],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            self.assertEqual(
                completed.returncode,
                0,
                f"{mode}: {completed.stdout}{completed.stderr}",
            )
            result_lines = [
                line
                for line in completed.stdout.splitlines()
                if line.startswith("__RESULT__")
            ]
            self.assertEqual(len(result_lines), 1, completed.stdout + completed.stderr)
            fields = result_lines[0][len("__RESULT__") :].split("|")
            self.assertEqual(tuple(map(int, fields[:2])), expected_status)
            self.assertEqual((fields[2] == "true", fields[3] == "true"), expected_installed)
            self.assertEqual(int(fields[4]), 0, f"{mode}: temporary release dirs remain")

    def test_powershell_production_release_paths_gate_extract_and_install(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")

        script = r'''
param([string]$SourcePath)
$ErrorActionPreference = "Stop"
function Log($msg)  { Write-Host "fixture: $msg" }
function Warn($msg) { Write-Host "fixture-warning: $msg" }
function Err($msg)  { Write-Host "fixture-error: $msg" }
$source = Get-Content -Raw -LiteralPath $SourcePath
$start = $source.IndexOf("function Install-FromZip")
$end = $source.IndexOf("function Build-FromSource", $start)
if ($start -lt 0 -or $end -le $start) { throw "installer function boundaries not found" }
Invoke-Expression $source.Substring($start, $end - $start)

$script:fixtureRoot = Join-Path $env:TEMP ("myownmesh-installer-fixture-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $script:fixtureRoot | Out-Null
$Prefix = Join-Path $script:fixtureRoot "prefix"
$Repo = "fixture/repo"
$DryRun = $false
$asset = "myownmesh-windows-x86_64.zip"
$guiAsset = "myownmesh-gui-windows-x86_64.zip"
$script:payloadPath = Join-Path $script:fixtureRoot "payload.bin"
$script:payloadBytes = [byte[]](1, 2, 3, 5, 8, 13)

$script:events = @()
function Log($msg) {
    Write-Host "fixture: $msg"
    if ($msg -eq "SHA256 OK") { $script:events += "$script:phase-verified" }
}

function Install-FromZip([string]$zipPath) {
    $script:events += "daemon-extract"
    $script:events += "daemon-install"
}
function Install-GuiFromZip([string]$zipPath) {
    $script:events += "gui-extract"
    $script:events += "gui-install"
}
function Invoke-RestMethod {
    param([string]$Uri, $Headers)
    [pscustomobject]@{ assets = @(
        [pscustomobject]@{ name = $asset; browser_download_url = "https://fixture/$asset" },
        [pscustomobject]@{ name = $guiAsset; browser_download_url = "https://fixture/$guiAsset" }
    ) }
}
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing)
    if ($Uri.EndsWith(".sha256")) {
        $name = [IO.Path]::GetFileName($OutFile)
        $name = $name.Substring(0, $name.Length - 7)
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $script:payloadPath).Hash.ToLowerInvariant()
        switch ($script:fixture) {
            "missing" { throw "fixture missing sidecar" }
            "empty" { [IO.File]::WriteAllText($OutFile, "") }
            "malformed" { [IO.File]::WriteAllText($OutFile, "not-a-hash  $name") }
            "multiple" { [IO.File]::WriteAllText($OutFile, "$hash  $name`n$hash  $name") }
            "orphan" { [IO.File]::WriteAllText($OutFile, "$hash  orphan.zip") }
            "wrong-name" { [IO.File]::WriteAllText($OutFile, "$hash  OTHER.zip") }
            "mismatch" { [IO.File]::WriteAllText($OutFile, ("0" * 64) + "  " + $name) }
            "double-marker" { [IO.File]::WriteAllText($OutFile, "$hash  **$name") }
            "valid-text" { [IO.File]::WriteAllText($OutFile, "$hash  $name") }
            "valid-binary" { [IO.File]::WriteAllText($OutFile, "$hash  *$name") }
            default { throw "unknown fixture" }
        }
    } else {
        if ($script:fixture -ne "missing-payload") {
            [IO.File]::WriteAllBytes($OutFile, $script:payloadBytes)
            [IO.File]::WriteAllBytes($script:payloadPath, $script:payloadBytes)
        }
    }
}

$fixtures = @("missing", "missing-payload", "empty", "malformed", "multiple", "orphan", "wrong-name", "mismatch", "double-marker", "valid-text", "valid-binary")
$results = @()
try {
    foreach ($fixture in $fixtures) {
        $script:fixture = $fixture
        if ($fixture -eq "valid-binary") {
            $script:payloadBytes = [byte[]](0..255)
        } else {
            $script:payloadBytes = [Text.Encoding]::UTF8.GetBytes("fixture text payload")
        }
        Remove-Item -LiteralPath $script:payloadPath -Force -ErrorAction SilentlyContinue
        $script:phase = "daemon"
        $script:events = @()
        $daemon = Try-Release
        $daemonEvents = @($script:events)
        Remove-Item -LiteralPath $script:payloadPath -Force -ErrorAction SilentlyContinue
        $script:phase = "gui"
        $script:events = @()
        $gui = Try-ReleaseGui
        $guiEvents = @($script:events)
        $results += [pscustomobject]@{
            fixture = $fixture
            daemon = [bool]$daemon
            daemonEvents = $daemonEvents
            gui = [bool]$gui
            guiEvents = $guiEvents
        }
    }
    Write-Output ("__RESULT__" + ($results | ConvertTo-Json -Compress))
} finally {
    Remove-Item -LiteralPath $script:fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            fixture_script = Path(temporary) / "installer-fixture.ps1"
            fixture_script.write_text(script, encoding="utf-8")
            completed = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(fixture_script),
                    "-SourcePath",
                    str(ROOT / "scripts" / "install.ps1"),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        result_lines = [
            line for line in completed.stdout.splitlines() if line.startswith("__RESULT__")
        ]
        self.assertEqual(len(result_lines), 1, completed.stdout + completed.stderr)
        results = json.loads(result_lines[0][len("__RESULT__") :])
        invalid = {
            "missing",
            "missing-payload",
            "empty",
            "malformed",
            "multiple",
            "orphan",
            "wrong-name",
            "mismatch",
            "double-marker",
        }
        for result in results:
            if result["fixture"] in invalid:
                self.assertFalse(result["daemon"])
                self.assertFalse(result["gui"])
                self.assertEqual(result["daemonEvents"], [])
                self.assertEqual(result["guiEvents"], [])
            else:
                self.assertTrue(result["daemon"])
                self.assertTrue(result["gui"])
                self.assertEqual(
                    result["daemonEvents"],
                    ["daemon-verified", "daemon-extract", "daemon-install"],
                )
                self.assertEqual(
                    result["guiEvents"],
                    ["gui-verified", "gui-extract", "gui-install"],
                )


if __name__ == "__main__":
    unittest.main()
