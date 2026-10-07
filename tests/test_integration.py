import json
from pathlib import Path
from src.main import collect_events
from src.detector import Detector

ROOT = Path(__file__).resolve().parents[1]

def test_sample_logs_load():
    events = collect_events(ROOT / "sample_logs")
    assert len(events) == 3
    alerts = Detector().detect(events)
    assert {a["rule_id"] for a in alerts} >= {"IAM-001", "S3-001", "CT-001"}

def test_alerts_are_json_serializable():
    events = collect_events(ROOT / "sample_logs")
    alerts = Detector().detect(events)
    payload = json.dumps(alerts)
    assert payload.startswith("[")
