# Demonstration Evidence — Security Log Analyzer

**Source:** Synthetic fixtures; cloud-executed checks. Not Alexander's personal run.

```bash
python scenario_lab.py credential_guessing
python scenario_lab.py password_spray
python scenario_lab.py routine_errors
python scenario_lab.py window_boundary
python workbench.py sample_auth.jsonl --format html --output triage.html
python benchmark.py --sizes 1000 5000 10000 --repetitions 3
python -m unittest discover -s tests -v
```

Expected: guessing produces repeated failures plus success-after-failures; spray produces multi-account activity; routine errors and time-window boundary do not trip default thresholds. The bundled ten-event sample yields three heuristic findings.

Cloud benchmark, November 8, 2026 (median of three runs): 1k events **3.019 ms**, 5k **11.301 ms**, 10k **26.607 ms**. Includes neither ingestion nor reporting, uses an alert-free deterministic workload, and is machine-dependent. **22 unit tests passed.**

For an authentic personal walkthrough, Alexander should rerun these commands and save a screenshot of the HTML report, benchmark output, and his own test result, then document an independently implemented improvement.
