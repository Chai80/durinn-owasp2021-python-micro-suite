# durinn-owasp2021-python-micro-suite (INTENTIONALLY VULNERABLE)

This repository is a tiny Python/Flask app specifically for SAST benchmarking and convergence experiments.

⚠️ **DO NOT DEPLOY THIS APP.**
⚠️ Keep this repo **private**.
⚠️ The code intentionally contains insecure patterns on OWASP branches.

## Branches
- `main` / `baseline-clean`: minimal app with `/health` only.
- OWASP Top 10:2021 category branches (each has ~10 insecure patterns):
  - `owasp2021-a01-broken-access-control`
  - `owasp2021-a02-cryptographic-failures`
  - `owasp2021-a03-injection`
  - `owasp2021-a04-insecure-design`
  - `owasp2021-a05-security-misconfiguration`
  - `owasp2021-a06-vulnerable-outdated-components` (SCA-oriented)
  - `owasp2021-a07-identification-authentication-failures`
  - `owasp2021-a08-software-data-integrity-failures`
  - `owasp2021-a09-security-logging-monitoring-failures`
  - `owasp2021-a10-ssrf`

## Ground truth markers
Each intentionally vulnerable region is bracketed by anchor comments like:

- `# GT:OWASP2021_A03_01_START`
- `# GT:OWASP2021_A03_01_END`

These anchors are designed to be machine-resolved to exact line ranges for benchmarking.
