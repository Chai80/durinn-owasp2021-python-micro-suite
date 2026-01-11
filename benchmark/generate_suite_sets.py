#!/usr/bin/env python3
import argparse, os, re, subprocess
from pathlib import Path
import yaml

BRANCH_RE = re.compile(r"^owasp2021-a(?P<num>\d{2})-")

def current_branch():
    for k in ("GITHUB_HEAD_REF","GITHUB_REF_NAME","BRANCH_NAME"):
        v = os.environ.get(k)
        if v: return v
    return subprocess.check_output(["git","rev-parse","--abbrev-ref","HEAD"], text=True).strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmark/suite_sets.yaml")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    branch = current_branch()
    m = BRANCH_RE.match(branch)
    if not m:
        print(f"[suite_sets] SKIP (not OWASP branch): {branch}")
        return 0

    num = m.group("num")
    owasp = f"A{num}"
    tools = ["aikido","semgrep","snyk","sonarqube"]

    gt = Path("benchmark/gt_catalog.yaml")
    if not gt.exists():
        raise SystemExit("[suite_sets] Missing benchmark/gt_catalog.yaml. Run generate_gt_catalog first.")

    ids = [it["id"] for it in yaml.safe_load(gt.read_text(encoding="utf-8")).get("items", [])]

    # Default behavior: keep everything as extended, except A01/A04/A09 default out-of-scope
    if owasp in ("A01","A04","A06","A09"):
        extended = []
        out_scope = ids
    else:
        extended = ids
        out_scope = []

    doc = {
      "version": 1,
      "suite": "durinn-owasp2021-python-micro-suite",
      "branch": branch,
      "owasp": owasp,
      "scanners_under_test": tools,
      "tracks": {
        "sast": {
          "core_sast_intersection": {"gt_ids": []},
          "extended_sast": {"gt_ids": sorted(extended)},
          "out_of_scope_for_sast": {"gt_ids": sorted(out_scope)},
          "negative_controls": {"gt_ids": []},
          "tool_expected": {t: [] for t in tools},
        }
      }
    }

    rendered = yaml.safe_dump(doc, sort_keys=False)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    if args.check:
        if not out.exists() or out.read_text(encoding="utf-8") != rendered:
            raise SystemExit("[suite_sets] OUT OF DATE: run python benchmark/generate_suite_sets.py")
        print("[suite_sets] OK")
        return 0

    out.write_text(rendered, encoding="utf-8")
    print(f"[suite_sets] Wrote {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
