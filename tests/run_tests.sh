#!/usr/bin/env bash
set -euo pipefail
python -m pytest tests/ --cov=src --cov-report=term-missing --cov-report=html
