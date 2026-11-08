"""Offline security-event triage: parse, detect, explain, and export.

All inputs must be authorized and sanitized. Alerts are heuristics and must be
reviewed by a human; this is not an incident-response or SIEM replacement.
"""

import argparse
import hashlib
import html
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from analyzer import analyze, read_events


@dataclass(frozen=True)
class Policy:
    failure_threshold: int = 5
    account_threshold: int = 3
    window_minutes: int = 10

    def validate(self):
        if min(self.failure_threshold, self.account_threshold, self.window_minutes) < 1:
            raise ValueError("All policy values must be positive")


def normalize_event(value, line):
    if not isinstance(value, dict):
        raise ValueError(f"Line {line}: expected a JSON object")
    try:
        timestamp = datetime.fromisoformat(str(value["timestamp"]).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        username = value["username"]
        source_ip = value["source_ip"]
        event = value["event"]
        if not isinstance(username, str) or not username.strip():
            raise ValueError("username must be a nonempty string")
        if not isinstance(source_ip, str):
            raise ValueError("source_ip must be a string")
        ipaddress.ip_address(source_ip)
        if event not in ("success", "failure"):
            raise ValueError("event must be success or failure")
        return {"timestamp": timestamp.astimezone(timezone.utc),
                "username": username, "source_ip": source_ip, "event": event}
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Line {line}: invalid event: {exc}") from exc


def load_events(path):
    """Read validated CSV or JSONL; return UTC-sorted events."""
    source = Path(path)
    if source.suffix.lower() == ".csv":
        # Revalidate via a common schema and normalize timezone offsets to UTC.
        rows = read_events(source)
        return sorted((normalize_event(r, i) for i, r in enumerate(rows, 2)),
                      key=lambda r: r["timestamp"])
    if source.suffix.lower() != ".jsonl":
        raise ValueError("Supported input formats: .csv and .jsonl")
    rows = []
    with source.open(encoding="utf-8") as stream:
        for line, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {line}: invalid JSON: {exc.msg}") from exc
            rows.append(normalize_event(value, line))
    return sorted(rows, key=lambda r: r["timestamp"])


def stable_id(kind, parts):
    payload = json.dumps([kind, *parts], separators=(",", ":"), ensure_ascii=False)
    return kind.upper()[:3] + "-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:10]


def investigate(events, policy=Policy()):
    policy.validate()
    basic = analyze(events, policy.failure_threshold, policy.window_minutes,
                    policy.account_threshold)
    findings = []
    for row in basic["failure_bursts"]:
        findings.append({"id": stable_id("burst", [row["username"], row["source_ip"]]),
                         "category": "Repeated login failures", "severity": "medium",
                         "entity": f"{row['username']} @ {row['source_ip']}",
                         "evidence": f"Maximum {row['max_failures_in_window']} failures within {policy.window_minutes} minutes",
                         "recommendation": "Correlate with expected user behavior, account lockouts, MFA, and source reputation."})
    for row in basic["multi_account_sources"]:
        findings.append({"id": stable_id("spray", [row["source_ip"]]),
                         "category": "Multi-account source activity", "severity": "medium",
                         "entity": row["source_ip"],
                         "evidence": f"{row['distinct_accounts_in_window']} distinct accounts failed within {policy.window_minutes} minutes",
                         "recommendation": "Check whether source is a shared gateway, SSO relay, or unexpected authentication origin."})
    for row in basic["success_after_failures"]:
        findings.append({"id": stable_id("success", [row["username"], row["source_ip"], row["failed_attempts"]]),
                         "category": "Success following repeated failures", "severity": "high",
                         "entity": f"{row['username']} @ {row['source_ip']}",
                         "evidence": f"Successful login after {row['failed_attempts']} failures in the window",
                         "recommendation": "Verify with account owner and investigate session/device context; don't assume compromise."})
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (order[x["severity"]], x["category"], x["entity"]))
    return {"schema_version": "1.0", "source_event_count": basic["total_events"],
            "failed_event_count": basic["total_failures"],
            "policy": {"failure_threshold": policy.failure_threshold,
                       "account_threshold": policy.account_threshold,
                       "window_minutes": policy.window_minutes},
            "findings": findings,
            "disclaimer": "Synthetic/authorized logs only. Heuristic alerts require human validation."}


def render_markdown(report):
    def plain(value):
        """Keep untrusted event text from introducing Markdown structure."""
        return re.sub(r"\s+", " ", str(value)).replace("\\", "\\\\").replace("`", "\\`").replace("[", "\\[").replace("]", "\\]").replace("*", "\\*").replace("_", "\\_")
    lines = ["# Authentication Security Triage", "",
             f"**Events:** {report['source_event_count']} | **Failures:** {report['failed_event_count']} | **Findings:** {len(report['findings'])}",
             "", report["disclaimer"], ""]
    for finding in report["findings"]:
        lines.extend([f"## {finding['id']} — {finding['category']}", "",
                      f"- Severity (heuristic): **{finding['severity']}**",
                      f"- Subject: {plain(finding['entity'])}",
                      f"- Evidence: {plain(finding['evidence'])}",
                      f"- Recommended triage: {finding['recommendation']}", ""])
    if not report["findings"]:
        lines.append("No heuristic findings at the current thresholds.")
    return "\n".join(lines) + "\n"


def render_html(report):
    """Escape every data-derived field, including input usernames."""
    esc = lambda item: html.escape(str(item), quote=True)
    cards = "".join(
        '<article class="finding"><h2>' + esc(f["id"]) + ' — ' + esc(f["category"]) +
        '</h2><p><strong>Severity:</strong> ' + esc(f["severity"]) +
        '</p><p><strong>Subject:</strong> ' + esc(f["entity"]) +
        '</p><p><strong>Evidence:</strong> ' + esc(f["evidence"]) +
        '</p><p><strong>Next step:</strong> ' + esc(f["recommendation"]) + '</p></article>'
        for f in report["findings"]
    ) or "<p>No heuristic findings at the current thresholds.</p>"
    return ('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Authentication Security Triage</title>'
            '<style>body{font:16px system-ui;background:#0b1322;color:#e7edf7;max-width:920px;'
            'margin:auto;padding:2rem;line-height:1.5}.finding{border:1px solid #52647f;'
            'border-radius:12px;padding:1.1rem;margin:1rem 0;background:#17233a}'
            'small{color:#becadc}h1{color:#8ee9d6}</style>'
            '<h1>Authentication Security Triage</h1>'
            f'<p>{report["source_event_count"]} events · {len(report["findings"])} findings</p>'
            f'<small>{esc(report["disclaimer"])}</small>' + cards + '</html>')


def main():
    parser = argparse.ArgumentParser(description="Offline authentication triage and reporting")
    parser.add_argument("source", type=Path, help="Sanitized .csv or .jsonl auth events")
    parser.add_argument("--format", choices=["json", "markdown", "html"], default="json")
    parser.add_argument("--output", type=Path, help="Write report to file instead of stdout")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--accounts", type=int, default=3)
    parser.add_argument("--window", type=int, default=10)
    args = parser.parse_args()
    try:
        policy = Policy(args.threshold, args.accounts, args.window)
        report = investigate(load_events(args.source), policy)
        content = ({"json": lambda: json.dumps(report, indent=2),
                    "markdown": lambda: render_markdown(report),
                    "html": lambda: render_html(report)}[args.format])()
        if args.output:
            args.output.write_text(content, encoding="utf-8")
            print(f"Saved {args.format} report to {args.output}")
        else:
            print(content)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
