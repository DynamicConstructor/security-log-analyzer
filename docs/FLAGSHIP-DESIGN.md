# Flagship Engineering Design and Limitations

## Objective

Help a junior analyst turn authorized, sanitized authentication logs into structured triage notes rather than isolated failure counts. It is an offline educational project, not a production SIEM.

## Components

| Component | Responsibility |
|---|---|
| `analyzer.py` | Validated CSV parsing and sliding-window detection engine |
| `workbench.py` | JSONL ingestion, UTC normalization, policy configuration, finding construction, output rendering |
| `sample_auth.csv` / `.jsonl` | Equivalent synthetic input fixtures |
| `tests/` | Unit checks for detection, failure handling, configuration and safe HTML output |

## Data contract

Each input event has `timestamp` (timezone-aware ISO 8601), `username`, `source_ip` (valid IPv4/IPv6), and `event` (`success` or `failure`). JSONL stores one object per line. Events are normalized to UTC and sorted for analysis. Unsupported input extensions and malformed records fail explicitly.

## Three detections

1. **Failure burst:** a username/IP pair reaches a failure count within the configured window.
2. **Cross-account source:** one IP fails authentication against multiple distinct usernames in the window.
3. **Success after failures:** a login succeeds after a specified number of recent failures on the same username/IP pair.

The finding renderer assigns heuristic severities and remediation-oriented triage suggestions. These are not claims of compromise. Shared NAT gateways, SSO services, user typos, and legitimate password resets can generate false positives.

## Security and privacy boundaries

- Use only synthetic or explicitly authorized sanitized logs.
- The HTML reporter escapes untrusted strings and contains no external scripts or requests.
- Do not upload production logins, personal identifiers, access tokens, or internal IP information to a public repo.
- No active scanning, exploitation, password testing, or external-network requests occur.

## Known engineering limits

- Entire input is loaded into memory; it is not a streaming or distributed processor.
- JSONL and CSV parsing are strict; upstream log transformation is outside scope.
- Stable IDs represent finding subjects, not necessarily a unique temporal incident.
- Severity is fixed heuristic metadata, not a validated risk model.
- No automatic alert delivery, SIEM integrations, geolocation, device context, or measurement of false-positive rates.

## Next independent contribution for Alex

The backlog issue requests an original CLI feature with a detection and non-detection test. Alex should implement and explain it himself, using a separate commit and dated personal review notes.
