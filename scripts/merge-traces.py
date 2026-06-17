#!/usr/bin/env python3
"""Merge per-machine connection traces into one wall-clock timeline.

Phase-0 debugging tool for MyOwnMesh connection-state reliability. Each
machine in a test captures its own connection trace:

    myownmesh ctl trace <network> > trace-<host>.jsonl

This script interleaves several such JSONL files into a single
time-ordered view so a distributed sequence — peer A's ICE goes
Disconnected, peer B re-handshakes, the relay redials — reads top to
bottom as one story instead of three logs you mentally diff.

Records are ordered by `ts_wall_ms` (wall clock). Wall clocks across
machines drift; the `--skew` summary prints each host's observed time
span so gross offsets are visible. For ordering *within* one machine,
`t_mono_ms` (monotonic, in each record) is authoritative and immune to
NTP steps.

Input lines that aren't ConnTrace records — the subscribe ack, the
`{"lagged":N}` gap markers, or full JSON daemon logs mixed in — are
skipped (and counted). Stdlib only; runs anywhere Python 3 does.

Usage:
    scripts/merge-traces.py trace-mac.jsonl trace-win.jsonl trace-linux.jsonl
    scripts/merge-traces.py --peer 3f9a2c1b trace-*.jsonl
    scripts/merge-traces.py --since 2026-06-16T20:00:00Z trace-*.jsonl
"""

import argparse
import datetime as dt
import json
import os
import sys


def host_label(path):
    """Derive a short host tag from a filename (trace-<host>.jsonl -> host)."""
    stem = os.path.basename(path)
    for suffix in (".jsonl", ".json", ".log", ".txt"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    for prefix in ("trace-", "conn-trace-", "conntrace-"):
        if stem.startswith(prefix):
            stem = stem[len(prefix):]
            break
    return stem or os.path.basename(path)


def fmt_time(ts_ms):
    """UTC HH:MM:SS.mmm from epoch milliseconds."""
    t = dt.datetime.fromtimestamp(ts_ms / 1000.0, tz=dt.timezone.utc)
    return t.strftime("%H:%M:%S.") + f"{ts_ms % 1000:03d}"


def parse_since(value):
    """Accept an ISO-8601 instant or a bare epoch-ms integer."""
    try:
        return int(value)
    except ValueError:
        pass
    iso = value.replace("Z", "+00:00")
    return int(dt.datetime.fromisoformat(iso).timestamp() * 1000)


def load(paths):
    """Yield (host, record) for every ConnTrace line; report skips."""
    rows = []
    skipped = 0
    for path in paths:
        host = host_label(path)
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"warning: cannot open {path}: {e}", file=sys.stderr)
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                # A ConnTrace always carries these two keys; anything
                # else (ack, {"lagged":N}, stray log line) is skipped.
                if not isinstance(rec, dict) or "ts_wall_ms" not in rec or "device_id" not in rec:
                    skipped += 1
                    continue
                rows.append((host, rec))
    return rows, skipped


def main():
    ap = argparse.ArgumentParser(
        description="Merge per-machine MyOwnMesh connection traces into one timeline.",
    )
    ap.add_argument("files", nargs="+", help="ConnTrace JSONL files (one per machine).")
    ap.add_argument("--peer", help="Only show this device id (prefix match).")
    ap.add_argument("--network", help="Only show this network id.")
    ap.add_argument("--since", help="Drop records before this time (ISO-8601 or epoch ms).")
    ap.add_argument("--skew", action="store_true", help="Print a per-host time-span summary.")
    args = ap.parse_args()

    rows, skipped = load(args.files)
    if args.peer:
        rows = [r for r in rows if r[1].get("device_id", "").startswith(args.peer)]
    if args.network:
        rows = [r for r in rows if r[1].get("network_id") == args.network]
    if args.since:
        cutoff = parse_since(args.since)
        rows = [r for r in rows if r[1].get("ts_wall_ms", 0) >= cutoff]

    if not rows:
        print("no ConnTrace records matched.", file=sys.stderr)
        return 1

    rows.sort(key=lambda r: (r[1].get("ts_wall_ms", 0), r[0]))
    t0 = rows[0][1]["ts_wall_ms"]

    def cell(rec, key, dash="-"):
        v = rec.get(key)
        return dash if v is None else str(v)

    table = []
    for host, rec in rows:
        ts = rec.get("ts_wall_ms", 0)
        table.append([
            fmt_time(ts),
            f"+{ts - t0}",
            host,
            rec.get("device_id", "")[:8],
            cell(rec, "epoch"),
            ",".join(rec.get("changed", [])) or "-",
            cell(rec, "status"),
            cell(rec, "tier"),
            cell(rec, "ice_state"),
            cell(rec, "pc_state"),
            cell(rec, "pair_class"),
            cell(rec, "rtt_ms"),
            cell(rec, "last_recv_age_ms"),
        ])

    headers = ["TIME", "+ms", "HOST", "PEER", "EPOCH", "CHANGED",
               "STATUS", "TIER", "ICE", "PC", "PAIR", "RTT", "AGE"]
    widths = [len(h) for h in headers]
    for row in table:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(val))

    def render(row):
        return "  ".join(val.ljust(widths[i]) for i, val in enumerate(row))

    print(render(headers))
    print("  ".join("-" * w for w in widths))
    for row in table:
        print(render(row))

    if skipped:
        print(f"\n({skipped} non-trace line(s) skipped)", file=sys.stderr)

    if args.skew:
        print("\nper-host wall-clock span (gross skew check):", file=sys.stderr)
        spans = {}
        for host, rec in rows:
            ts = rec.get("ts_wall_ms", 0)
            lo, hi = spans.get(host, (ts, ts))
            spans[host] = (min(lo, ts), max(hi, ts))
        for host, (lo, hi) in sorted(spans.items()):
            print(f"  {host:12} {fmt_time(lo)} .. {fmt_time(hi)}  "
                  f"first=+{lo - t0}ms", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
