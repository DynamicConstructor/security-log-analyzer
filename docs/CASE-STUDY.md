# Case Study: Detecting Authentication Anomalies

## Problem

Raw sign-in logs are hard to triage manually. Repeated failures and attempts across several accounts may be useful signals, but simple totals can confuse activity spread over hours with a sudden burst.

## Approach

The Python tool validates timezone-aware CSV events and IP addresses, sorts chronologically, and applies sliding time windows. It reports repeated failed logins, multi-account sources, and successful logins following a failure burst. A JSON mode supports follow-on processing.

## Architecture

`CSV → validation → chronological events → detection windows → console/JSON findings`

## Engineering decisions

- Standard-library implementation avoids a runtime dependency chain.
- Time-bound rules reduce one class of false positives compared with unbounded counters.
- Input validation produces explicit failures for malformed records.
- Unit tests cover both expected detections and negative cases.

## Demonstrated outcome

The synthetic sample produces three categories of findings and all six unit tests pass in the recorded cloud run. No malicious activity or professional investigation is claimed.

## Next personal contribution

Alexander can add deduplication of repeat success alerts, severity configuration, or a CLI export option, document the design tradeoff, and commit the change himself.
