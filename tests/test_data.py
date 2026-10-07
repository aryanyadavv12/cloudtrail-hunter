from copy import deepcopy

BASE = {
    "eventTime": "2024-11-05T15:05:30Z",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.45",
    "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test"},
    "requestParameters": {},
    "responseElements": None,
    "eventID": "test-event"
}

def event(name, source="iam.amazonaws.com", request=None, response=None):
    e = deepcopy(BASE)
    e.update(eventName=name, eventSource=source)
    e["requestParameters"] = request or {}
    e["responseElements"] = response
    return e

SAMPLE_EVENTS = {
    "iam_high_priv": event("AttachUserPolicy", request={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
    "iam_inline": event("PutUserPolicy"),
    "iam_change": event("CreateUser"),
    "iam_delete": event("DeleteUser"),
    "s3_policy": event("PutBucketPolicy", source="s3.amazonaws.com"),
    "s3_acl": event("PutBucketAcl", source="s3.amazonaws.com"),
    "s3_get": event("GetObject", source="s3.amazonaws.com"),
    "ct_stop": event("StopLogging", source="cloudtrail.amazonaws.com"),
    "ct_delete": event("DeleteTrail", source="cloudtrail.amazonaws.com"),
    "ct_update": event("UpdateTrail", source="cloudtrail.amazonaws.com"),
    "auth_fail": event("ConsoleLogin", source="signin.amazonaws.com", response={"ConsoleLogin": "Failure"}),
}
