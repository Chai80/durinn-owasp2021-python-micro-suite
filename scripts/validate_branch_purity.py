#!/usr/bin/env python3
import os, re, subprocess, sys
from pathlib import Path

BRANCH_RE = re.compile(r"^owasp2021-a(?P<num>\d{2})-")
GT_RE = re.compile(r"GT:(?P<id>OWASP2021_A(?P<num>\d{2})_[A-Z0-9_]+)_(?P<tag>START|END)")

def current_branch() -> str:
    for k in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME", "BRANCH_NAME"):
        v = os.environ.get(k)
        if v: return v
    return subprocess.check_output(["git","rev-parse","--abbrev-ref","HEAD"], text=True).strip()

def scan_gt_ids():
    ids = {}
    for p in Path("app").rglob("*.py"):
        if any(part in (".venv","venv","site-packages") for part in p.parts): 
            continue
        for i,line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            m = GT_RE.search(line)
            if not m: 
                continue
            ids.setdefault(m.group("id"), []).append((p.as_posix(), i, m.group("tag")))
    return ids

def main():
    strict_10 = (os.environ.get("STRICT_10") == "1") or ("--strict-10" in sys.argv)
    strict_benchmark = (os.environ.get("STRICT_BENCHMARK") == "1") or ("--strict-benchmark" in sys.argv)

    branch = current_branch()
    m = BRANCH_RE.match(branch)
    if not m:
        print(f"[purity] SKIP (not OWASP branch): {branch}")
        return 0

    num = m.group("num")
    expected = f"A{num}"
    expected_route = f"a{num}.py"
    print(f"[purity] Branch={branch} expected={expected}")

    routes = Path("app/routes")
    if not routes.exists():
        print("[purity] FAIL: app/routes missing")
        return 2

    allowed = {"__init__.py", "health.py", expected_route}
    found = {p.name for p in routes.glob("*.py")}
    extra = sorted(found - allowed)
    missing = sorted(allowed - found)
    if missing:
        print(f"[purity] FAIL: missing route files: {missing}")
        return 2
    if extra:
        print(f"[purity] FAIL: extra route files (scanners will scan): {extra}")
        return 2

    gt = scan_gt_ids()
    if not gt:
        print("[purity] FAIL: no GT markers found under app/")
        return 2

    wrong = [i for i in gt if not i.startswith(f"OWASP2021_{expected}_")]
    if wrong:
        print("[purity] FAIL: cross-category GT IDs found:")
        for i in sorted(wrong): print(" -", i)
        return 2

    bad_pairs = []
    for i,occ in gt.items():
        tags = [t for _,_,t in occ]
        if tags.count("START") != 1 or tags.count("END") != 1:
            bad_pairs.append((i, occ))
    if bad_pairs:
        print("[purity] FAIL: bad START/END pairing:")
        for i,occ in bad_pairs: print(" -", i, occ)
        return 2

    primary = sorted([i for i in gt if re.match(rf"^OWASP2021_{expected}_\d{{2}}$", i)])
    if len(primary) != 10:
        msg = f"[purity] {'FAIL' if strict_10 else 'WARN'}: expected 10 primary numeric IDs, found {len(primary)}: {primary}"
        print(msg)
        if strict_10:
            return 2

    for rel in ("benchmark/gt_catalog.yaml", "benchmark/suite_sets.yaml"):
        p = Path(rel)
        if not p.exists():
            print(f"[purity] {'FAIL' if strict_benchmark else 'WARN'}: missing {rel}")
            if strict_benchmark: return 2
            continue
        txt = p.read_text(encoding="utf-8", errors="ignore")
        bad = [x for x in re.findall(r"OWASP2021_A(\d{2})_[A-Z0-9_]+", txt) if x != num]
        if bad:
            print(f"[purity] {'FAIL' if strict_benchmark else 'WARN'}: {rel} references other OWASP categories")
            if strict_benchmark: return 2

    print("[purity] PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
