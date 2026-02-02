# Suite scoring guide (TP/FP/FN) — Durinn OWASP 2021 Python Micro Suite

This document explains how **true positives**, **false positives**, and related metrics are defined for this test suite, and how to structure test cases so the suite produces **interpretable** benchmark results.

---

## 1) Why the suite needed changes

When the suite mixes meta branches + out-of-scope cases + only-positive examples, the HTML report tends to be dominated by artifacts:

- **GT contamination on meta branches** (baseline/hygiene branches look like they “missed 97 vulns”).
- **Out-of-scope tests** mixed into SAST scoring (e.g., access-control / insecure-design logic that default rule-based SAST won’t catch).
- **No designed negatives**, so precision isn’t stressed (tools have few chances to be wrong).

The redesign addresses these with:

1) **Track/set split** (SAST core vs out-of-scope vs SCA/IaC)  
2) **Paired negative controls** (“safe twins”)  
3) **Rule-coverage gate** for in-scope GT items

---

## 2) Definitions: TP / FP / FN in this suite

### Ground truth (GT)
GT items are defined primarily by **in-code markers** (recommended for branch-per-case suites):

- `# GT:<ID>_START ...`
- `# GT:<ID>_END`

Markers are materialized into a per-branch `benchmark/gt_catalog.yaml`.

> **Recommended for benchmarking runs:** use **GT source = markers** (not YAML fallback).  
> This ensures only vulnerabilities present in the branch are counted.

### True Positive (TP)
A tool finding/cluster is a **TP** if it matches a GT item (file + line overlap, often with a small tolerance window).

### False Positive (FP)
A tool finding/cluster is an **FP** if it **does not match any GT item**.

This includes:
- findings on baseline/meta branches (which should have **zero GT**),
- findings on **safe twin** endpoints (intentionally unmarked),
- findings outside GT-marked regions.

> Sometimes a tool flags a real issue that isn’t labeled. In this benchmark it’s still counted as FP until GT is expanded.

### False Negative (FN)
A GT item is an **FN** for a tool if **no finding matches it** (shown in Durinn as the **GT gap queue**).

### True Negative (TN)
We don’t count TNs explicitly. Instead we stress-test noise/precision using **safe twins + baseline/meta branches**.

---

## 3) Track split: what we score together (and what we don’t)

### Meta track (noise-only / integrity)
- `main` (baseline-clean)
- `benchmark-hygiene`

**Expected GT:** 0  
**Interpretation:** any findings are **noise (FPs)** or configuration/scope issues.

### SAST core track (scored)
These are intended to be detectable by default rule-based SAST:

- `owasp2021-a02-cryptographic-failures`
- `owasp2021-a03-injection`
- `owasp2021-a05-security-misconfiguration`
- `owasp2021-a07-identification-authentication-failures` *(partial; some items are “missing control”)*
- `owasp2021-a08-software-data-integrity-failures`
- `owasp2021-a09-security-logging-monitoring-failures` *(partial; some items are “missing control”)*
- `owasp2021-a10-ssrf`

### Out-of-scope for default SAST (track separately)
These often require app-specific modeling / business-logic reasoning:

- `owasp2021-a01-broken-access-control`
- `owasp2021-a04-insecure-design`

You can still run scanners, but don’t interpret misses as “SAST tool failure” in the core scorecard.

### SCA track (dependency / components)
- `owasp2021-a06-vulnerable-outdated-components`

Requires SCA tooling. Don’t include it in a SAST-only scorecard.

---

## 4) Expected TP / FP “range” (what the suite is designed to measure)

### A) SAST core track: TP budget
Each SAST core branch has **10 GT markers** (10 labeled vulnerabilities).

Across the **7** SAST core branches:

- **GT total (max TPs): 70**

So the **TP range** for any scanner on the SAST core track is:

- **0 → 70 true positives** (depends on tool + config)

### B) Designed FP pressure: safe twins + baseline/meta
Safe twin endpoints are intentionally **unmarked** (so findings on them count as FP).

Safe twin endpoint counts added in the redesign:

| Branch | GT (TP budget) | Safe twins (FP pressure) |
|---|---:|---:|
| A02 cryptographic failures | 10 | 3 |
| A03 injection | 10 | 9 |
| A05 misconfiguration | 10 | 4 |
| A07 identification/auth | 10 | 4 |
| A08 integrity/deserialization | 10 | 5 |
| A09 logging/monitoring | 10 | 7 |
| A10 SSRF | 10 | 3 |
| **Total (core track)** | **70** | **35** |

Additionally, `main` and `benchmark-hygiene` are **noise-only** baselines.

**Interpretation goal:**
- A high-precision tool should produce **few/zero** findings on safe twins + meta branches.
- A noisy tool will produce many FPs here.

---

## 5) How to run the suite so results are interpretable

Recommended benchmark run settings:

- Run/score only the **SAST core branches** for the “headline” scorecard.
- **GT source:** markers (avoid YAML fallback contamination)
- **GT tolerance:** small nonzero window (e.g., ±5 to ±10 lines)
- Confirm path filters don’t exclude the code under test.

---

## 6) How to add new test cases without breaking the benchmark

### A) Every TP should have a paired negative
For each new vulnerability pattern:

1) Add a GT-marked vulnerable endpoint (**TP**)
2) Add at least one **safe twin** endpoint that looks similar but is unambiguously safe (**FP pressure**)

### B) Put metadata on marker lines
On the `*_START` marker line, add fields to support filtering and reporting:

- `track=sast|sca|iac|out_of_scope`
- `set=core|extended|research`
- `cwe=CWE-XXX`
- `kind=sqli|ssrf|cmdi|deser|jwt|crypto|tls|logging|...`

Example:

```python
# GT:OWASP2021_A03_04_START track=sast set=core cwe=CWE-89 kind=sqli
...
# GT:OWASP2021_A03_04_END
```

### C) Rule-coverage gate
Before merging new GT items into `set=core`, confirm the pattern is plausibly covered by at least one scanner’s default ruleset.

Run:

```bash
python3 scripts/validate_rule_coverage.py
```

This prevents obvious “undetectable by design” drift.

---

## 7) Maintainer pointers (where things live)

- Track/branch guidance: `benchmark/branch_tracks.yaml`
- Canonical catalogs (reference): `benchmark/catalog/`
- Per-branch GT catalog (generated from markers): `benchmark/gt_catalog.yaml`
- Rule inventory drop folder: `benchmark/rules_inventory/`
- Rule-coverage gate: `scripts/validate_rule_coverage.py`

---

## Appendix: interpreting “false positives” on safe twins

Safe twins are intentionally unmarked. Therefore any findings on them count as FP.

If a tool flags a safe twin because it is genuinely insecure, we should:

- fix the safe twin to be unambiguously safe, or
- (if the finding is valid) add GT markers and reclassify it.
