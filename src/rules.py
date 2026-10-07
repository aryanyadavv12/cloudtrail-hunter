"""CloudTrail Hunter detection rules.

Each rule is intentionally deterministic and works on a single CloudTrail event.
"""
from typing import Any, Dict, List


HIGH_PRIV_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/SecurityAudit",
}


def _name(event: Dict[str, Any]) -> str:
    return str(event.get("eventName", ""))


def _req(event: Dict[str, Any]) -> Dict[str, Any]:
    return event.get("requestParameters") or {}


def _response(event: Dict[str, Any]) -> Dict[str, Any]:
    return event.get("responseElements") or {}


def _policy_arn(event: Dict[str, Any]) -> str:
    req = _req(event)
    return str(req.get("policyArn", ""))


def rule_iam_001(e):
    return _name(e) in {"AttachUserPolicy", "AttachRolePolicy"} and _policy_arn(e) in HIGH_PRIV_POLICIES


def rule_iam_002(e):
    return _name(e) in {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"}


def rule_iam_003(e):
    return _name(e) in {
        "CreateUser", "DeleteUser", "CreateRole", "DeleteRole", "CreatePolicy",
        "DeletePolicy", "AttachUserPolicy", "AttachRolePolicy", "DetachUserPolicy",
        "DetachRolePolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
        "UpdateAssumeRolePolicy", "AddUserToGroup", "RemoveUserFromGroup",
    }


def rule_iam_004(e):
    return _name(e) == "DeleteUser"


def rule_s3_001(e):
    return _name(e) == "PutBucketPolicy"


def rule_s3_002(e):
    return _name(e) == "PutBucketAcl"


def rule_s3_005(e):
    return _name(e) == "GetObject"


def rule_ct_001(e):
    return _name(e) == "StopLogging"


def rule_ct_002(e):
    return _name(e) == "DeleteTrail"


def rule_ct_003(e):
    return _name(e) in {"PutEventSelectors", "UpdateTrail"}


def rule_auth_001(e):
    return _name(e) == "ConsoleLogin" and str(_response(e).get("ConsoleLogin", "")).lower() == "failure"

RULES = [
    {"id": "IAM-001", "severity": "HIGH", "name": "Suspicious IAM Policy Attachment", "description": "Direct admin/high-privilege policy attached to user/role", "mitre_attack": "T1078.001", "check": rule_iam_001},
    {"id": "IAM-002", "severity": "MEDIUM", "name": "Inline IAM Policy Change", "description": "Inline user, role, or group policy was added", "mitre_attack": "T1078.001", "check": rule_iam_002},
    {"id": "IAM-003", "severity": "MEDIUM", "name": "IAM Configuration Change", "description": "An IAM identity or policy change event was observed", "mitre_attack": "T1078.001", "check": rule_iam_003},
    {"id": "IAM-004", "severity": "MEDIUM", "name": "IAM User Deleted", "description": "An IAM user was deleted", "mitre_attack": "T1531", "check": rule_iam_004},
    {"id": "S3-001", "severity": "HIGH", "name": "S3 Bucket Policy Changed", "description": "An S3 bucket policy was changed", "mitre_attack": "T1537", "check": rule_s3_001},
    {"id": "S3-002", "severity": "HIGH", "name": "S3 Bucket ACL Changed", "description": "An S3 bucket ACL was changed", "mitre_attack": "T1537", "check": rule_s3_002},
    {"id": "S3-005", "severity": "MEDIUM", "name": "S3 Object Access", "description": "An S3 GetObject event was observed for investigation", "mitre_attack": "T1537", "check": rule_s3_005},
    {"id": "CT-001", "severity": "CRITICAL", "name": "CloudTrail Logging Stopped", "description": "CloudTrail logging was stopped", "mitre_attack": "T1070", "check": rule_ct_001},
    {"id": "CT-002", "severity": "CRITICAL", "name": "CloudTrail Trail Deleted", "description": "A CloudTrail trail was deleted", "mitre_attack": "T1070", "check": rule_ct_002},
    {"id": "CT-003", "severity": "HIGH", "name": "CloudTrail Configuration Changed", "description": "CloudTrail event selectors or trail configuration changed", "mitre_attack": "T1562", "check": rule_ct_003},
    {"id": "AUTH-001", "severity": "LOW", "name": "Failed Console Login", "description": "A failed AWS console login was observed", "mitre_attack": "T1110", "check": rule_auth_001},
]


def evaluate_rules(event: Dict[str, Any], selected: List[str] = None) -> List[Dict[str, Any]]:
    selected_set = set(selected or [r["id"] for r in RULES])
    return [rule for rule in RULES if rule["id"] in selected_set and rule["check"](event)]
