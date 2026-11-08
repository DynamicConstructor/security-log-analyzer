"""Analyze sanitized authentication events; standard library only."""

import argparse
import csv
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

FIELDS = {"timestamp", "username", "source_ip", "event"}


def read_events(path):
    events = []
    with Path(path).open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or not FIELDS.issubset(reader.fieldnames):
            raise ValueError(f"CSV must contain: {', '.join(sorted(FIELDS))}")
        for line, row in enumerate(reader, start=2):
            try:
                time = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                if time.tzinfo is None:
                    raise ValueError("timezone required")
                ipaddress.ip_address(row["source_ip"])
                if not row["username"].strip() or row["event"] not in ("success", "failure"):
                    raise ValueError("invalid username or event")
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise ValueError(f"Invalid event on CSV line {line}: {exc}") from exc
            events.append({"timestamp": time, "username": row["username"],
                           "source_ip": row["source_ip"], "event": row["event"]})
    return sorted(events, key=lambda row: row["timestamp"])


def analyze(events, threshold=5, minutes=10, account_threshold=3):
    if threshold < 1 or minutes < 1 or account_threshold < 1:
        raise ValueError("Thresholds and minutes must be positive")
    failures = defaultdict(list)
    source_failures = defaultdict(list)
    success_after_failures = []
    for row in events:
        key = (row["username"], row["source_ip"])
        if row["event"] == "failure":
            failures[key].append(row["timestamp"])
            source_failures[row["source_ip"]].append(row)
        else:
            recent = [t for t in failures[key]
                      if timedelta(0) <= row["timestamp"] - t <= timedelta(minutes=minutes)]
            if len(recent) >= threshold:
                success_after_failures.append({"username": key[0], "source_ip": key[1],
                                               "failed_attempts": len(recent)})

    bursts = []
    for (username, source_ip), times in sorted(failures.items()):
        left = 0
        maximum = 0
        for right, timestamp in enumerate(times):
            while timestamp - times[left] > timedelta(minutes=minutes):
                left += 1
            maximum = max(maximum, right - left + 1)
        if maximum >= threshold:
            bursts.append({"username": username, "source_ip": source_ip,
                           "max_failures_in_window": maximum})

    cross_account = []
    for ip, attempts in sorted(source_failures.items()):
        left = 0
        best = set()
        for right, attempt in enumerate(attempts):
            while attempt["timestamp"] - attempts[left]["timestamp"] > timedelta(minutes=minutes):
                left += 1
            accounts = {r["username"] for r in attempts[left:right+1]}
            if len(accounts) > len(best):
                best = accounts
        if len(best) >= account_threshold:
            cross_account.append({"source_ip": ip, "distinct_accounts_in_window": len(best)})

    return {
        "total_events": len(events),
        "total_failures": sum(len(times) for times in failures.values()),
        "failure_bursts": bursts,
        "multi_account_sources": cross_account,
        "success_after_failures": success_after_failures,
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze authorized authentication CSV logs")
    parser.add_argument("csv_file")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logins to alert on")
    parser.add_argument("--window", type=int, default=10, help="Sliding window, minutes")
    parser.add_argument("--account-threshold", type=int, default=3, help="Distinct accounts to alert on")
    args = parser.parse_args()
    try:
        report = analyze(read_events(args.csv_file), args.threshold, args.window,
                         args.account_threshold)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Events: {report['total_events']} | Failures: {report['total_failures']}")
        for label in ("failure_bursts", "multi_account_sources", "success_after_failures"):
            print(f"\n{label.replace('_', ' ').title()}:")
            for finding in report[label]:
                print("  " + json.dumps(finding))
            if not report[label]:
                print("  None detected")


if __name__ == "__main__":
    main()
