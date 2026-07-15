import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

from loader import load_csv
from matcher import scan_log


def test_finds_bad_ip_and_domain():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "t.db"
        load_csv(root / "sample_data" / "iocs.csv", db)
        hits = scan_log(root / "sample_data" / "traffic_log.txt", db, persist=False)
        values = {h.ioc_value for h in hits}
        assert "203.0.113.44" in values
        assert "evil-update-paypal.tk" in values
