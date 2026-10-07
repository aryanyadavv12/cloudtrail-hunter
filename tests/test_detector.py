from src.detector import Detector
from tests.test_data import SAMPLE_EVENTS

def test_detector_builds_alerts():
    alerts = Detector().detect(SAMPLE_EVENTS.values())
    assert len(alerts) >= 11
    assert all("alert_id" in a and a["alert_id"].startswith("ALR-") for a in alerts)

def test_alert_contains_context():
    alert = Detector().detect_event(SAMPLE_EVENTS["iam_high_priv"])[0]
    assert alert["rule_id"] == "IAM-001"
    assert alert["severity"] == "HIGH"
    assert alert["mitre_attack"] == "T1078.001"
    assert alert["principal"].endswith("/test")

def test_empty_events():
    assert Detector().detect([]) == []

def test_selected_rules():
    alerts = Detector(["CT-001"]).detect(SAMPLE_EVENTS.values())
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "CT-001"
