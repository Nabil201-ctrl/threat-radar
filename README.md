# threat-radar

**Threat intelligence pipeline — IOC load, store, match**

Bash collects/normalizes IOC feeds; Python loads them into SQLite and scans traffic-style logs for hits. The “capstone” of this project set.

| | |
|---|---|
| **Repo name** | `threat-radar` |
| **One-liner** | Local threat-intel mini-pipeline: CSV IOCs → SQLite → log matches |
| **Languages** | Python + Bash (+ SQLite) |
| **Keywords** | `threat-intelligence`, `ioc`, `cybersecurity`, `detection-engineering`, `sqlite`, `log-analysis` |
| **Level** | Intermediate / portfolio capstone |

---

## Why this exists

Threat work is a pipeline, not a single script:

1. get indicators  
2. store them  
3. match against telemetry  
4. keep an audit trail of hits  

This project is small enough to finish alone, big enough to talk about seriously.

---

## Logic

**IOC types:** `ip`, `domain`, `url`, `hash`

**Load path**

- CSV rows → upsert into `iocs` table (`UNIQUE(type, value)` so re-loads don’t duplicate)

**Match path**

- read log line by line  
- for each IOC type, look for the value in the line (demo-friendly substring match)  
- on hit: print + insert into `hits` table with timestamp  

**Why SQLite?**  
You can open the DB, show tables in an interview, and query history without Docker.

---

## Flowchart

```text
 ┌────────────────────┐
 │ IOC feed / CSV     │
 └─────────┬──────────┘
           │
           v
 ┌────────────────────┐
 │ fetch_iocs.sh      │  normalize + stamp run
 └─────────┬──────────┘
           │
           v
 ┌────────────────────┐
 │ loader.py          │  upsert → sqlite iocs
 └─────────┬──────────┘
           │
           v
 ┌────────────────────┐     ┌──────────────┐
 │ matcher.py         │◄────│ traffic log  │
 └─────────┬──────────┘     └──────────────┘
           │
           v
    hits table + CLI report
```

---

## Project layout

```text
threat-radar/
├── collectors/fetch_iocs.sh
├── engine/
│   ├── store.py      # schema
│   ├── loader.py     # csv → db
│   ├── matcher.py    # log scan
│   └── cli.py
├── sample_data/
│   ├── iocs.csv
│   └── traffic_log.txt
├── db/               # created on first run
└── tests/
```

---

## Build & run

### 1. Collect / normalize IOCs

```bash
cd Documents/Github/threat-radar
chmod +x collectors/fetch_iocs.sh
./collectors/fetch_iocs.sh
```

### 2. Load + scan (one shot)

```bash
python3 engine/cli.py run
```

### 3. Or step by step

```bash
python3 engine/cli.py load -i sample_data/iocs.csv
python3 engine/cli.py scan -l sample_data/traffic_log.txt
python3 engine/cli.py scan --json
```

### 4. Inspect the DB

```bash
sqlite3 db/radar.db "SELECT type, value, severity FROM iocs;"
sqlite3 db/radar.db "SELECT ioc_value, severity, substr(log_line,1,80) FROM hits;"
```

### 5. Test

```bash
python3 -c "
import sys; sys.path.insert(0,'engine')
from tests.test_matcher import test_finds_bad_ip_and_domain
test_finds_bad_ip_and_domain(); print('ok')
"
```

---

## How the five projects connect (story for resume)

```text
log-pulse      → find noisy IPs in auth logs
       ↓ export IPs
threat-radar   → check those IPs against IOC DB
       ↓
phish-snare    → score shady URLs seen in HTTP logs
       ↓
session-watch  → ATO / impossible travel on accounts
       ↓
fraud-pulse    → block money movement when risk is high
```

You can mention this chain even if each repo stays independent.

---

## Resume bullets

- Designed a mini threat-intel pipeline (collect → store → match → audit)
- Modeled IOCs in SQLite with upsert semantics and hit history
- Combined Bash collection with Python detection engineering

## Interview line

> “I treated threat intel like a data product: normalize indicators, store them once, match many logs, keep hits queryable.”

## Extend it

- STIX/TAXII or public abuse.ch feed in `fetch_iocs.sh`
- CIDR matching for IP ranges
- Map tags to ATT&CK techniques
- Alert webhook on `severity=high`
