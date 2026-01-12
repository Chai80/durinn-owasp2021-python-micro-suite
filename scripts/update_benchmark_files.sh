#!/usr/bin/env bash
set -euo pipefail
python benchmark/generate_gt_catalog.py
python benchmark/generate_suite_sets.py
python scripts/validate_branch_purity.py
