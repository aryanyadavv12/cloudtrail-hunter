import json
from pathlib import Path
from src.main import build_parser, collect_events, main

ROOT = Path(__file__).resolve().parents[1]

def test_parser_defaults():
    args = build_parser().parse_args([])
    assert args.logs is None
    assert args.console is False

def test_collect_single_file():
    events = collect_events(ROOT / "sample_logs" / "iam_privilege_escalation.json")
    assert len(events) == 1

def test_main_missing_logs_returns_two(capsys):
    assert main([]) == 2
    assert "Use --logs" in capsys.readouterr().out

def test_main_console_and_output(tmp_path, capsys):
    out = tmp_path / "alerts.json"
    assert main(["--logs", str(ROOT / "sample_logs"), "--console", "--output", str(out), "--verbose"]) == 0
    captured = capsys.readouterr().out
    assert "Processed 3 event(s)" in captured
    data = json.loads(out.read_text())
    assert len(data) == 4
    assert "IAM-001" in captured

def test_main_no_alerts(tmp_path, capsys):
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"}))
    assert main(["--logs", str(clean), "--console"]) == 0
    assert "No detections." in capsys.readouterr().out
