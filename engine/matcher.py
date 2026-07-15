"""Scan a log file for IOC hits.

I'm not building Zeek. Just substring / token checks that work on demo logs
and teach the pipeline idea.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from store import connect, record_hit


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
URL_RE = re.compile(r"https?://\S+", re.I)


@dataclass
class Match:
    ioc_type: str
    ioc_value: str
    severity: str
    tags: str
    line: str


def _load_iocs(db_path: str | Path) -> list[dict]:
    conn = connect(db_path)
    rows = conn.execute("SELECT type, value, severity, tags FROM iocs").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def scan_log(log_path: str | Path, db_path: str | Path, persist: bool = True) -> list[Match]:
    iocs = _load_iocs(db_path)
    by_type: dict[str, list[dict]] = {}
    for ioc in iocs:
        by_type.setdefault(ioc["type"], []).append(ioc)

    matches: list[Match] = []
    lines = Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines()

    for line in lines:
        lower = line.lower()
        # check each type with the cheapest approach that still works
        for ioc in by_type.get("ip", []):
            if ioc["value"] in lower:
                matches.append(
                    Match("ip", ioc["value"], ioc["severity"], ioc["tags"] or "", line)
                )

        for ioc in by_type.get("domain", []):
            if ioc["value"] in lower:
                matches.append(
                    Match("domain", ioc["value"], ioc["severity"], ioc["tags"] or "", line)
                )

        for ioc in by_type.get("url", []):
            if ioc["value"] in lower:
                matches.append(
                    Match("url", ioc["value"], ioc["severity"], ioc["tags"] or "", line)
                )

        for ioc in by_type.get("hash", []):
            if ioc["value"] in lower:
                matches.append(
                    Match("hash", ioc["value"], ioc["severity"], ioc["tags"] or "", line)
                )

    if persist and matches:
        conn = connect(db_path)
        now = datetime.now(timezone.utc).isoformat()
        for m in matches:
            record_hit(conn, now, m.ioc_type, m.ioc_value, m.line, m.severity)
        conn.commit()
        conn.close()

    return matches
