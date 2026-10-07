import json
from typing import Any, Dict
from .utils import alert_id, principal


def build_alert(event: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "alert_id": alert_id(event, rule["id"]),
        "timestamp": event.get("eventTime"),
        "severity": rule["severity"],
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "rule_description": rule["description"],
        "mitre_attack": rule["mitre_attack"],
        "event": {
            "event_name": event.get("eventName"),
            "event_source": event.get("eventSource"),
            "region": event.get("awsRegion"),
            "event_id": event.get("eventID") or event.get("eventId"),
        },
        "principal": principal(event),
        "source": {
            "ip": event.get("sourceIPAddress"),
            "user_agent": event.get("userAgent"),
        },
        "request_parameters": event.get("requestParameters"),
        "response_elements": event.get("responseElements"),
    }


def format_console(alert: Dict[str, Any]) -> str:
    lines = [
        f"[{alert['severity']}] {alert['rule_id']} – {alert['rule_name']}",
        "=" * 62,
        f"Timestamp: {alert.get('timestamp')}",
        f"Principal: {alert.get('principal')}",
        f"Source IP: {alert['source'].get('ip')}",
        f"Event: {alert['event'].get('event_name')}",
        f"Region: {alert['event'].get('region')}",
        f"Alert ID: {alert['alert_id']}",
        "",
        "Details: " + json.dumps(alert.get("request_parameters"), sort_keys=True),
        f"Severity: {alert['severity']}",
        f"Rule: {alert['rule_id']}",
        f"Description: {alert['rule_description']}",
        f"MITRE ATT&CK: {alert['mitre_attack']}",
    ]
    return "\n".join(lines)
