from src.alerts import build_alert, format_console
from tests.test_data import SAMPLE_EVENTS
from src.rules import evaluate_rules

def test_console_format_contains_core_fields():
    rule = evaluate_rules(SAMPLE_EVENTS["ct_stop"])[0]
    alert = build_alert(SAMPLE_EVENTS["ct_stop"], rule)
    output = format_console(alert)
    assert "CT-001" in output
    assert "CRITICAL" in output
    assert "StopLogging" in output
    assert "203.0.113.45" in output

def test_alert_uses_fallback_principal():
    event = dict(SAMPLE_EVENTS["ct_stop"])
    event["userIdentity"] = {"principalId": "ABC"}
    rule = evaluate_rules(event)[0]
    alert = build_alert(event, rule)
    assert alert["principal"] == "ABC"

def test_alert_id_is_stable():
    rule = evaluate_rules(SAMPLE_EVENTS["ct_stop"])[0]
    a = build_alert(SAMPLE_EVENTS["ct_stop"], rule)
    b = build_alert(SAMPLE_EVENTS["ct_stop"], rule)
    assert a["alert_id"] == b["alert_id"]
