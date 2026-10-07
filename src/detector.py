from typing import Dict, Iterable, List
from .alerts import build_alert
from .rules import evaluate_rules


class Detector:
    def __init__(self, selected_rules=None):
        self.selected_rules = selected_rules

    def detect_event(self, event: Dict) -> List[Dict]:
        return [build_alert(event, rule) for rule in evaluate_rules(event, self.selected_rules)]

    def detect(self, events: Iterable[Dict]) -> List[Dict]:
        alerts = []
        for event in events:
            alerts.extend(self.detect_event(event))
        return alerts
