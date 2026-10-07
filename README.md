# Cloud SOC – AWS CloudTrail Hunter

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-45-success)
![Coverage](https://img.shields.io/badge/coverage-97%25-success)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

A Python-based AWS CloudTrail detection engine built as a **SOC Analyst portfolio project**.

CloudTrail Hunter processes CloudTrail-style JSON events, evaluates deterministic security rules, and produces structured SOC-style alerts. The project can be demonstrated completely offline with the included synthetic CloudTrail events and can optionally retrieve recent CloudTrail events through `boto3`.

> **Portfolio focus:** AWS security monitoring, log analysis, detection engineering, Python automation, MITRE ATT&CK mapping, testing, and CI/CD.

---

## What it does

CloudTrail Hunter looks for suspicious AWS activity across:

- **IAM** — privilege-related policy changes and account changes
- **S3** — bucket policy, ACL, and object-access patterns
- **CloudTrail** — attempts to stop, delete, or modify logging
- **Authentication** — failed AWS Console logins

Each matching event is converted into a SOC-style alert containing severity, rule ID, timestamp, principal, source IP, event information, request context, and MITRE ATT&CK mapping.

---

## Detection Rules

| Rule | Severity | Detection | MITRE ATT&CK |
|---|---|---|---|
| IAM-001 | HIGH | High-privilege managed policy attachment | T1078.001 |
| IAM-002 | MEDIUM | Inline IAM policy change | T1078.001 |
| IAM-003 | MEDIUM | Multiple IAM change events | T1078.001 |
| IAM-004 | MEDIUM | IAM user deletion | T1531 |
| S3-001 | HIGH | `PutBucketPolicy` | T1537 |
| S3-002 | HIGH | `PutBucketAcl` | T1537 |
| S3-005 | MEDIUM | `GetObject` pattern | T1537 |
| CT-001 | CRITICAL | `StopLogging` | T1070 |
| CT-002 | CRITICAL | `DeleteTrail` | T1070 |
| CT-003 | HIGH | CloudTrail configuration change | T1562 |
| AUTH-001 | LOW | Failed `ConsoleLogin` | T1110 |

See [DETECTION_RULES.md](DETECTION_RULES.md) for rule details and examples.

---

## Architecture

```text
                 CloudTrail JSON Events
                          │
                          ▼
                  ┌─────────────────┐
                  │  Event Loader   │
                  │   src/main.py   │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Detection Engine│
                  │ src/detector.py │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Detection Rules │
                  │   src/rules.py  │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Alert Formatter│
                  │   src/alerts.py │
                  └────────┬────────┘
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
          Console Alerts        JSON Report
```

The optional `src/cloudtrail.py` module provides AWS CloudTrail lookup through `boto3`; the bundled demo does **not** require AWS credentials.

---

## Quick Start

### 1. Create a virtual environment

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Run the tests

```bash
python -m pytest tests/ --cov=src --cov-report=term-missing
```

Current validation: **45 tests passed with 97% coverage**.

### 4. Run the offline SOC demo

```bash
python -m src.main --logs sample_logs --console --output reports/analysis.json --verbose
```

You can also run selected rules:

```bash
python -m src.main --logs sample_logs --rules IAM-001 S3-001 CT-001 --console
```

The sample data is synthetic and is included only for safe demonstration and testing.

---

## Example Alert

```text
[HIGH] IAM-001 – Suspicious IAM Policy Attachment
Timestamp: 2024-11-05T15:05:30Z
Principal: arn:aws:iam::123456789012:user/admin
Source IP: 203.0.113.45
Event: AttachUserPolicy
Region: us-east-1
Rule: IAM-001
Severity: HIGH
MITRE ATT&CK: T1078.001
```

Alerts can also be written as structured JSON for further analysis or integration into other workflows.

---

## Project Structure

```text
cloudtrail-hunter/
├── .github/workflows/tests.yml   # GitHub Actions CI
├── config/config.yaml            # Example configuration
├── sample_logs/                  # Synthetic CloudTrail events
├── src/
│   ├── main.py                   # CLI entry point
│   ├── detector.py               # Detection engine
│   ├── rules.py                  # 11 detection rules
│   ├── alerts.py                 # Alert formatting
│   ├── cloudtrail.py             # Optional AWS integration
│   └── utils.py                  # Helper functions
├── tests/                        # Unit and integration tests
├── ARCHITECTURE.md
├── DETECTION_RULES.md
├── INSTALLATION.md
├── INVESTIGATION.md
├── MITRE_MAPPING.md
├── QUICK_START.md
├── TESTING.md
├── CHANGELOG.md
├── LICENSE
├── requirements.txt
└── .gitignore
```

---

## Testing & CI/CD

The project includes unit and integration tests for the detection rules, detector, alert formatting, CLI, utilities, and CloudTrail integration.

- **45 automated tests**
- **97% coverage** in the current validation run
- `pytest` + `pytest-cov`
- GitHub Actions workflow for Python **3.9, 3.10, and 3.11**
- CI runs on pushes and pull requests

---

## Security & AWS Notes

The default demonstration is offline and does not require AWS credentials.

If you use the optional AWS CloudTrail integration:

1. Configure your AWS profile/region securely.
2. Never commit access keys or `~/.aws/credentials`.
3. Do not commit production CloudTrail logs containing sensitive information.
4. Review IAM permissions before connecting the tool to a real AWS account.

The included sample events use dummy account identifiers and documentation IP space.

---

## Documentation

- [Quick Start](QUICK_START.md)
- [Installation](INSTALLATION.md)
- [Architecture](ARCHITECTURE.md)
- [Detection Rules](DETECTION_RULES.md)
- [Investigation Guide](INVESTIGATION.md)
- [MITRE ATT&CK Mapping](MITRE_MAPPING.md)
- [Testing](TESTING.md)
- [Changelog](CHANGELOG.md)

---

## Skills Demonstrated

**Cybersecurity:** SOC monitoring, cloud security, log analysis, detection engineering, alert triage, MITRE ATT&CK

**AWS:** CloudTrail, IAM, S3

**Development:** Python, JSON processing, CLI development, automated testing

**DevOps:** Git, GitHub Actions, CI/CD

---

## License

This project is licensed under the [MIT License](LICENSE).
