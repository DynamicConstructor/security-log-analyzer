# Security Log Analyzer

> **Flagship expansion:** Offline authentication triage with CSV/JSONL ingestion, configurable rules, structured findings, and shareable reports. AI-assisted starter/expansion; Alex's independent contributions must be recorded separately.

An entry-level defensive security project for Alexander's new public portfolio.

**Status:** Functional educational implementation with automated checks. Alexander must personally reproduce and extend the results before claiming personal authorship.

## What it does

Reads a CSV of fictional authentication events and reports:

- Failed login counts by account and source IP
- Accounts with at least five failures in a ten-minute window
- Sources with failed logins against at least three distinct accounts **within a sliding time window**
- Successful logins that follow a series of failures from the same account and IP

These are **heuristics**, not proof of an attack. Real security analysts investigate context and false positives.

## Run

Requires Python 3.10+ and no third-party packages.

```bash
python analyzer.py sample_auth.csv
python analyzer.py sample_auth.csv --json --window 15 --threshold 5
python workbench.py sample_auth.jsonl --format json
python workbench.py sample_auth.csv --format markdown --output triage.md
python workbench.py sample_auth.csv --format html --output triage.html
python -m unittest discover -s tests -v
```

To use another authorized, sanitized dataset:

```bash
python analyzer.py path/to/events.csv --json
```

CSV columns: `timestamp` (ISO 8601 with timezone), `username`, `source_ip`, `event` (`success` or `failure`). Do not upload real credentials, private client data, or identifiable production logs to a public repository.

## Architecture

```mermaid
flowchart LR
  A[Sanitized CSV or JSONL] --> B[Validate, normalize and sort]
  B --> C[Sliding-window rules]
  C --> D[Findings and triage guidance]
  D --> E[JSON, Markdown or HTML]
```

## Sample result (synthetic data)

| Signal | Result | Interpretation |
|---|---:|---|
| Failure burst | 5 attempts, one account | Investigate potential password guessing |
| Cross-account source | 3 accounts | Investigate possible password spraying |
| Success after failures | 1 occurrence | Check whether expected user activity |

No signal independently establishes malicious activity. All sample IPs use documentation-only address ranges.

## Flagship workbench (new)

`workbench.py` builds on the original `analyzer.py` for investigation-ready output:

- **Two input formats:** CSV and newline-delimited JSON (`.jsonl`)
- **Common UTC normalization:** timezone-aware timestamps required
- **Configurable policy:** failure threshold, distinct-account threshold, sliding-window duration
- **Structured finding IDs:** stable identifiers, categories, heuristic severities, evidence and recommended next steps
- **Three output formats:** machine-readable JSON, Markdown case notes, and self-contained HTML
- **Safe HTML rendering:** input-derived strings are escaped to prevent report injection
- **15 automated tests:** original detection tests plus nine additional workbench tests

This is a demonstrator for investigation support, **not** a full SIEM, production incident-response system, or claim that an alert proves a breach. Details: [architecture and limits](docs/FLAGSHIP-DESIGN.md) and [cloud validation](docs/VALIDATION.md).

### Reproducible workbench example

```bash
python workbench.py sample_auth.jsonl --format markdown
```

The synthetic ten-event sample produces three findings: one high-priority success-after-failures heuristic and two medium-priority login-pattern heuristics. Severity labels are **demonstration policy choices**, not CVSS scores.

See the [generated sample triage report](docs/SAMPLE-REPORT.md), produced from the supplied fictional JSONL data.

### Alex's personal ownership review

Use [the personal ownership checklist](docs/ALEX-OWNERSHIP.md) to reproduce the results, explain design decisions, add an original feature and test, and record authentic evidence of his own work.

## Interview talking points

1. Why sliding time windows help detect bursts of failed authentication.
2. Why a shared office IP or password reset can create false positives.
3. Why input validation and timezone-aware timestamps matter.
4. How to improve the project with event correlation, baselines, and a dashboard.

## Next steps for Alexander

- Run the commands and save screenshots of actual output and passing tests.
- Review each detection rule and explain it in his own words.
- Add a new test case, document what changed, and commit it.
- Create a separate **public** GitHub repository; do not change or copy private business repositories.
- Replace this starter README with a case study describing his personal implementation and verified results.

## Resume claim (only after personally running, testing, and understanding it)

> Developed a Python authentication-log analyzer using sliding-window detection to flag repeated login failures, multi-account source activity, and success-after-failure patterns; validated detection rules with automated tests.
