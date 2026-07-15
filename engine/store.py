"""SQLite is enough. Don't invent a data platform for a lab project."""

from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT,
    tags TEXT,
    UNIQUE(type, value)
);

CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seen_at TEXT,
    ioc_type TEXT,
    ioc_value TEXT,
    log_line TEXT,
    severity TEXT
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def upsert_ioc(
    conn: sqlite3.Connection,
    type_: str,
    value: str,
    severity: str,
    source: str,
    tags: str,
) -> None:
    conn.execute(
        """
        INSERT INTO iocs(type, value, severity, source, tags)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(type, value) DO UPDATE SET
            severity=excluded.severity,
            source=excluded.source,
            tags=excluded.tags
        """,
        (type_, value.lower().strip(), severity, source, tags),
    )


def record_hit(
    conn: sqlite3.Connection,
    seen_at: str,
    ioc_type: str,
    ioc_value: str,
    log_line: str,
    severity: str,
) -> None:
    conn.execute(
        """
        INSERT INTO hits(seen_at, ioc_type, ioc_value, log_line, severity)
        VALUES (?, ?, ?, ?, ?)
        """,
        (seen_at, ioc_type, ioc_value, log_line, severity),
    )
