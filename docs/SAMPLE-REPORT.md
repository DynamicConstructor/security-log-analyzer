# Authentication Security Triage

**Events:** 10 | **Failures:** 8 | **Findings:** 3

Synthetic/authorized logs only. Heuristic alerts require human validation.

## SUC-d77d4d2608 — Success following repeated failures

- Severity (heuristic): **high**
- Subject: `alex @ 192.0.2.10`
- Evidence: Successful login after 5 failures in the window
- Recommended triage: Verify with account owner and investigate session/device context; don't assume compromise.

## SPR-330fc3f86d — Multi-account source activity

- Severity (heuristic): **medium**
- Subject: `198.51.100.20`
- Evidence: 3 distinct accounts failed within 10 minutes
- Recommended triage: Check whether source is a shared gateway, SSO relay, or unexpected authentication origin.

## BUR-ffc5976ee9 — Repeated login failures

- Severity (heuristic): **medium**
- Subject: `alex @ 192.0.2.10`
- Evidence: Maximum 5 failures within 10 minutes
- Recommended triage: Correlate with expected user behavior, account lockouts, MFA, and source reputation.

