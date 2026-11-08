"""Generate and evaluate synthetic authentication scenarios, no real logs needed."""
import argparse
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from workbench import Policy, investigate


def scenario_events(name):
    start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    events = []

    def record(second, user, address, event):
        events.append({"timestamp": start + timedelta(seconds=second),
                       "username": user, "source_ip": address, "event": event})

    if name == "credential_guessing":
        for second in (0, 20, 40, 60, 80, 100):
            record(second, "demo.alex", "192.0.2.44", "failure")
        record(120, "demo.alex", "192.0.2.44", "success")
    elif name == "password_spray":
        for i, user in enumerate(("demo.a", "demo.b", "demo.c", "demo.d")):
            record(i * 50, user, "198.51.100.17", "failure")
    elif name == "routine_errors":
        for i in range(3):
            record(i * 700, "demo.employee", "203.0.113.7", "failure")
        record(3000, "demo.employee", "203.0.113.7", "success")
    elif name == "window_boundary":
        for second in (0, 700, 1400, 2100, 2800):
            record(second, "demo.user", "192.0.2.50", "failure")
    else:
        raise ValueError("Unknown scenario")
    return events


def scenario_report(name):
    return investigate(scenario_events(name), Policy())


def export_csv(name, path):
    with Path(path).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp", "username", "source_ip", "event"])
        writer.writeheader()
        for row in scenario_events(name):
            writer.writerow({**row, "timestamp": row["timestamp"].isoformat()})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["credential_guessing", "password_spray", "routine_errors", "window_boundary"])
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    if args.csv:
        export_csv(args.scenario, args.csv)
    print(json.dumps(scenario_report(args.scenario), indent=2))
