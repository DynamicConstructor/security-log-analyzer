# Case Study: Detecting Authentication Anomalies

## Problem

Raw sign-in logs are hard to triage manually. Repeated failures and attempts across several accounts may be useful signals, but simple totals can confuse activity spread over hours with a sudden burst.

## Approach

The Python tool validates timezone-aware CSV and JSONL events, normalizes timestamps to UTC, sorts chronologically, and applies sliding time windows. It reports repeated failed logins, multi-account sources, and successful logins following a failure burst. JSON, Markdown, and escaped HTML output support follow-on review.

## Architecture

`CSV → validation → chronological events → detection windows → console/JSON findings`

## Engineering decisions

- Standard-library implementation avoids a runtime dependency chain.
- Time-bound rules reduce one class of false positives compared with unbounded counters. Sliding distinct-account counts use a Counter to avoid repeatedly rebuilding sets.
- Input validation produces explicit failures for malformed records.
- Unit tests cover both expected detections and negative cases.

## Expanded synthetic scenarios

`scenario_lab.py` exercises credential guessing followed by a success, a multi-account source, routine isolated errors, and events outside the configured time window. The last two are deliberate negative controls, not proofs that real users are safe.

## Performance method and result

Run `python benchmark.py --sizes 1000 5000 10000 --repetitions 3`. The script measures only Python in-memory analysis over deterministic fake events, reporting median wall-clock milliseconds. On the November 8, 2026 cloud run: **1,000: 3.019 ms; 5,000: 11.301 ms; 10,000: 26.607 ms**. The workload creates no alerts and excludes file loading, disk output, and production ingestion; timings are host-dependent and must not be generalized into SIEM throughput.

## Demonstrated outcome

The bundled synthetic sample produces three categories of findings. **22 Python tests passed** in the latest cloud run, including six scenario/benchmark checks. No malicious activity or professional investigation is claimed.

## Next personal contribution

Alexander can add deduplication of repeat success alerts, severity configuration, or a CLI export option, document the design tradeoff, and commit the change himself.
