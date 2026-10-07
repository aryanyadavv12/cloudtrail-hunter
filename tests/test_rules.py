from tests.test_data import SAMPLE_EVENTS
from src.rules import evaluate_rules, RULES

EXPECTED = {
    "iam_high_priv": "IAM-001",
    "iam_inline": "IAM-002",
    "iam_change": "IAM-003",
    "iam_delete": "IAM-004",
    "s3_policy": "S3-001",
    "s3_acl": "S3-002",
    "s3_get": "S3-005",
    "ct_stop": "CT-001",
    "ct_delete": "CT-002",
    "ct_update": "CT-003",
    "auth_fail": "AUTH-001",
}

def test_all_eleven_rules_exist():
    assert len(RULES) == 11
    assert {r["id"] for r in RULES} == set(EXPECTED.values())

def test_each_rule_matches_its_fixture():
    for fixture, rule_id in EXPECTED.items():
        assert rule_id in {r["id"] for r in evaluate_rules(SAMPLE_EVENTS[fixture])}

def test_auth_success_does_not_alert():
    e = dict(SAMPLE_EVENTS["auth_fail"])
    e["responseElements"] = {"ConsoleLogin": "Success"}
    assert evaluate_rules(e) == []

def test_normal_event_does_not_alert():
    e = dict(SAMPLE_EVENTS["auth_fail"])
    e["eventName"] = "ListBuckets"
    e["eventSource"] = "s3.amazonaws.com"
    assert evaluate_rules(e) == []

def test_rule_selection():
    alerts = evaluate_rules(SAMPLE_EVENTS["iam_high_priv"], ["CT-001", "IAM-001"])
    assert [r["id"] for r in alerts] == ["IAM-001"]

import pytest

@pytest.mark.parametrize("event_name", [
    "ListBuckets", "DescribeInstances", "GetCallerIdentity", "ListUsers", "ListRoles",
    "GetTrailStatus", "LookupEvents", "GetBucketLocation", "HeadObject", "ConsoleLoginSuccess",
    "CreateLogStream", "DescribeLogGroups", "GetObjectAcl", "ListObjectsV2", "GetPolicy",
    "GetRole", "GetUser", "SimulatePrincipalPolicy", "TagUser", "UntagUser",
])
def test_benign_events_do_not_match(event_name):
    event = dict(SAMPLE_EVENTS["auth_fail"])
    event["eventName"] = event_name
    event["eventSource"] = "example.amazonaws.com"
    event["responseElements"] = None
    assert evaluate_rules(event) == []
