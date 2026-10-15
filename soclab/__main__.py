import argparse
import json
from pathlib import Path
from .core import detect, load_events, run_demo, validate


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic SOC lab; no commands in logs are executed.")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Generate deterministic telemetry and reference-rule results")
    demo.add_argument("--out", type=Path, default=Path("."))
    for command in ("validate", "detect"):
        p = sub.add_parser(command)
        p.add_argument("file", type=Path)
    p = sub.add_parser("evidence", help="Print events selected by exact lab event IDs")
    p.add_argument("file", type=Path)
    p.add_argument("ids", nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "demo":
            manifest, alerts = run_demo(args.out)
            print(f"Generated {manifest['event_count']} events and {len(alerts)} reference alerts in {args.out.resolve()}")
            print("Offline Python validation only. No live Splunk query execution.")
        else:
            rows = load_events(args.file)
            count = validate(rows)
            if args.command == "validate":
                print(f"Valid lab schema: {count} events")
            elif args.command == "detect":
                print(json.dumps(detect(rows), indent=2))
            else:
                missing = set(args.ids) - {e['event_uid'] for e in rows}
                if missing:
                    raise ValueError(f"Unknown evidence IDs: {sorted(missing)}")
                print(json.dumps([e for e in rows if e['event_uid'] in args.ids], indent=2))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
