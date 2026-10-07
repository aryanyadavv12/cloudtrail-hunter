import json
from src.utils import event_id, alert_id, iter_events, principal
from tests.test_data import SAMPLE_EVENTS

def test_event_id_prefers_eventid():
    assert event_id(SAMPLE_EVENTS["ct_stop"]) == "test-event"

def test_event_id_fallback_is_stable():
    e = {"eventName": "X", "foo": 1}
    assert event_id(e) == event_id(e)

def test_principal_fallback_unknown():
    assert principal({}) == "unknown"

def test_iter_events_list(tmp_path):
    p = tmp_path / "events.json"
    p.write_text(json.dumps([{"eventName": "A"}, {"eventName": "B"}]))
    assert len(list(iter_events(p))) == 2

def test_iter_events_records_wrapper(tmp_path):
    p = tmp_path / "records.json"
    p.write_text(json.dumps({"Records": [{"eventName": "A"}]}))
    assert len(list(iter_events(p))) == 1
