import argparse
import json
from pathlib import Path
from .alerts import format_console
from .detector import Detector
from .utils import iter_events


def build_parser():
    p = argparse.ArgumentParser(description="Cloud SOC – AWS CloudTrail Hunter")
    p.add_argument("--logs", help="Directory or JSON file containing CloudTrail events")
    p.add_argument("--rules", nargs="*", help="Only run selected rule IDs")
    p.add_argument("--console", action="store_true", help="Print SOC-style alerts")
    p.add_argument("--output", help="Write alerts to a JSON file")
    p.add_argument("--verbose", action="store_true", help="Print processing details")
    return p


def collect_events(logs_path):
    path = Path(logs_path)
    if path.is_file():
        return list(iter_events(path))
    if path.is_dir():
        events = []
        for f in sorted(path.glob("*.json")):
            events.extend(iter_events(f))
        return events
    raise FileNotFoundError(f"Logs path not found: {logs_path}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.logs:
        print("Use --logs PATH to analyze CloudTrail JSON events. Example: python -m src.main --logs sample_logs --console")
        return 2
    events = collect_events(args.logs)
    alerts = Detector(args.rules).detect(events)
    if args.verbose:
        print(f"Processed {len(events)} event(s); generated {len(alerts)} alert(s).")
    if args.console:
        if alerts:
            print("\n\n".join(format_console(a) for a in alerts))
        else:
            print("No detections.")
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
        if args.verbose:
            print(f"Wrote {len(alerts)} alert(s) to {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
