# Cloud Validation — November 8, 2026

**Execution:** ChatGPT-managed Linux environment, Python 3.12.14. This is AI-assisted cloud testing, not a claim that Alexander personally ran the project.

## Reproduce

```bash
python -m unittest discover -s tests -v
python analyzer.py sample_auth.csv --json
```

**Result:** 6/6 automated tests passed; sample CLI demonstration passed.

From the bundled fictional dataset: 10 events, 8 failures, one five-failure burst, one three-account source within a time window, and one success following five failures. Sample IPs belong to documentation-only ranges. These alerts are indicators requiring investigation, **not confirmed attacks**.

## Coverage and limitations

Tests cover sample patterns, stale attempts outside the window, invalid thresholds, missing columns, and chronological sorting. The tool has no production log connectors, baseline modeling, or detection-quality measurement on real traffic. False positives and false negatives are possible.

## Personal verification still required

- [ ] Alexander runs the commands independently
- [ ] Records his actual environment and dated results
- [ ] Explains the sliding-window logic and its limitations
- [ ] Makes and tests his own improvement
