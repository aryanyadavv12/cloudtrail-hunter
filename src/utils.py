import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable


def load_json_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def iter_events(path):
    data = load_json_file(path)
    if isinstance(data, dict) and isinstance(data.get("Records"), list):
        yield from data["Records"]
    elif isinstance(data, list):
        yield from data
    elif isinstance(data, dict):
        yield data
    else:
        raise ValueError("Expected a CloudTrail event object, list, or Records wrapper")


def event_id(event: Dict[str, Any]) -> str:
    return str(event.get("eventID") or event.get("eventId") or hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()[:16])


def alert_id(event: Dict[str, Any], rule_id: str) -> str:
    raw = f"{event.get('eventTime','')}|{event_id(event)}|{rule_id}"
    return "ALR-" + hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def principal(event: Dict[str, Any]) -> str:
    identity = event.get("userIdentity") or {}
    return str(identity.get("arn") or identity.get("userName") or identity.get("principalId") or "unknown")


def utc_now():
    return datetime.now(timezone.utc).isoformat()
