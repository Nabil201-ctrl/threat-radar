#!/usr/bin/env python3
"""threat-radar CLI — load IOCs, scan logs, print hits."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from loader import load_csv
from matcher import scan_log


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    default_db = root / "db" / "radar.db"

    ap = argparse.ArgumentParser(description="IOC load + log match")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_load = sub.add_parser("load", help="load IOC csv into sqlite")
    p_load.add_argument("-i", "--input", default=str(root / "sample_data" / "iocs.csv"))
    p_load.add_argument("--db", default=str(default_db))

    p_scan = sub.add_parser("scan", help="scan a log against loaded IOCs")
    p_scan.add_argument("-l", "--log", default=str(root / "sample_data" / "traffic_log.txt"))
    p_scan.add_argument("--db", default=str(default_db))
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--no-persist", action="store_true")

    p_run = sub.add_parser("run", help="load then scan (the happy path)")
    p_run.add_argument("-i", "--input", default=str(root / "sample_data" / "iocs.csv"))
    p_run.add_argument("-l", "--log", default=str(root / "sample_data" / "traffic_log.txt"))
    p_run.add_argument("--db", default=str(default_db))
    p_run.add_argument("--json", action="store_true")

    args = ap.parse_args()

    if args.cmd == "load":
        n = load_csv(args.input, args.db)
        print(f"loaded {n} IOCs into {args.db}")
        return 0

    if args.cmd == "scan":
        hits = scan_log(args.log, args.db, persist=not args.no_persist)
        return _print_hits(hits, args.json)

    if args.cmd == "run":
        n = load_csv(args.input, args.db)
        hits = scan_log(args.log, args.db, persist=True)
        if not args.json:
            print(f"loaded {n} IOCs")
        return _print_hits(hits, args.json)

    return 1


def _print_hits(hits, as_json: bool) -> int:
    if as_json:
        print(
            json.dumps(
                [
                    {
                        "type": h.ioc_type,
                        "value": h.ioc_value,
                        "severity": h.severity,
                        "tags": h.tags,
                        "line": h.line,
                    }
                    for h in hits
                ],
                indent=2,
            )
        )
        return 0

    if not hits:
        print("no IOC hits — either clean traffic or empty DB (did you load?)")
        return 0

    print(f"{len(hits)} hit(s)\n")
    for h in hits:
        print(f"  [{h.severity.upper():6}] {h.ioc_type:7} {h.ioc_value}")
        if h.tags:
            print(f"           tags: {h.tags}")
        print(f"           log: {h.line[:120]}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
