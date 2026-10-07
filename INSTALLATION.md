# Installation

## Requirements
- Python 3.9–3.11 for the CI matrix
- pip
- Git (for GitHub publishing)
- AWS credentials are **not required** for offline analysis

## Windows
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
If PowerShell blocks activation, run the commands from Command Prompt instead or use `python -m pip ...` without activating the environment.

## Linux/macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Optional AWS access
Configure AWS CLI credentials outside this repository. Never commit credentials. The `src/cloudtrail.py` helper uses boto3 and can be adapted for authorized accounts.
