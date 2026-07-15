"""Load IOCs from CSV into sqlite."""

from __future__ import annotations

import csv
from pathlib import Path

from store import connect, upsert_ioc


def load_csv(csv_path: str | Path, db_path: str | Path) -> int:
    conn = connect(db_path)
    count = 0
    with Path(csv_path).open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            upsert_ioc(
                conn,
                row["type"].strip().lower(),
                row["value"].strip(),
                row.get("severity", "medium").strip().lower(),
                row.get("source", "").strip(),
                row.get("tags", "").strip(),
            )
            count += 1
    conn.commit()
    conn.close()
    return count
