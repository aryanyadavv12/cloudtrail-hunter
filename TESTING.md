# Testing

Run:
```bash
python -m pytest tests/ --cov=src --cov-report=term-missing
```

The test suite covers:
- Presence of all 11 rules
- Positive fixture for every rule
- Negative authentication and normal-event cases
- Rule selection
- Alert structure and deterministic IDs
- Loading all bundled sample logs
- JSON serialization

CI runs the same test suite across Python 3.9, 3.10 and 3.11.
