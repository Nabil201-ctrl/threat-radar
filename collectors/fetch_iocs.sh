#!/usr/bin/env bash
# In real life you'd curl threat feeds here.
# For the portfolio we normalize whatever CSV we already have + stamp a run id.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-$ROOT/sample_data/iocs.csv}"
OUT_DIR="$ROOT/sample_data/runs"
mkdir -p "$OUT_DIR"

STAMP=$(date +%Y%m%d_%H%M%S)
OUT="$OUT_DIR/iocs_$STAMP.csv"

if [[ ! -f "$SRC" ]]; then
  echo "missing IOC source: $SRC" >&2
  exit 1
fi

# strip blank lines / comments, keep header
{
  head -n 1 "$SRC"
  tail -n +2 "$SRC" | grep -v '^#' | grep -v '^[[:space:]]*$' || true
} > "$OUT"

# also refresh the "latest" pointer the python engine likes
cp "$OUT" "$ROOT/sample_data/iocs_latest.csv"

echo "[collect] $(wc -l < "$OUT") lines -> $OUT"
echo "[collect] also updated sample_data/iocs_latest.csv"
