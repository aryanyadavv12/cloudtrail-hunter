# Quick Start

## 1. Create environment
```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate
```

## 2. Install
```bash
python -m pip install -r requirements.txt
```

## 3. Test
```bash
python -m pytest tests/ --cov=src --cov-report=term-missing
```

## 4. Run the demo
```bash
python -m src.main --logs sample_logs --console --output reports/analysis.json --verbose
```

## 5. Run selected rules
```bash
python -m src.main --logs sample_logs --rules IAM-001 S3-001 CT-001 --console
```
