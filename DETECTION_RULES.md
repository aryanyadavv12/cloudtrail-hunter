# Detection Rules

## IAM
- **IAM-001 / HIGH:** `AttachUserPolicy` or `AttachRolePolicy` with `AdministratorAccess`, `IAMFullAccess`, or `SecurityAudit`.
- **IAM-002 / MEDIUM:** `PutUserPolicy`, `PutRolePolicy`, or `PutGroupPolicy`.
- **IAM-003 / MEDIUM:** common IAM identity/policy configuration changes.
- **IAM-004 / MEDIUM:** `DeleteUser`.

## S3
- **S3-001 / HIGH:** `PutBucketPolicy`.
- **S3-002 / HIGH:** `PutBucketAcl`.
- **S3-005 / MEDIUM:** `GetObject` pattern for investigation.

## CloudTrail
- **CT-001 / CRITICAL:** `StopLogging`.
- **CT-002 / CRITICAL:** `DeleteTrail`.
- **CT-003 / HIGH:** `PutEventSelectors` or `UpdateTrail`.

## Authentication
- **AUTH-001 / LOW:** `ConsoleLogin` where `responseElements.ConsoleLogin == Failure`.

The rule names and mappings follow the supplied project specification. In a production environment, tune severity and ATT&CK mappings against the organization's threat model and current ATT&CK version.
