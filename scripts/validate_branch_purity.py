#!/usr/bin/env python3
import os
import re
import subprocess
import sys
from pathlib import Path

BRANCH_RE = re.compile(r"^owasp2021-a(?P<num>\d{2})-")
GT_RE = re.compile(r"GT:(?P<id>OWASP2021_A(?P<num>\d{2})_[A-Z0-9_]+)_(?P<tag>START|END)")

def current_branch() -> str:
    for k in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME", "BRANCH_NAME", "GIT_BRANCH"):
        v = os.environ.get(k)
        if v:
            return v
    return subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()

def scan_gt_ids_in_app():
    ids = {}
    for p in Path("app").rglob("*.py"):
        if any(part in (".venv","venv","site-packages") for part in p.parts):
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            m = GT_RE.search(line)
            if m:
                ids.setdefault(m.group("id"), []).append((p.as_posix(), i, m.group("tag")))
    return ids

def main(argv):
    strict_10 = ("--strict-10" in argv) or (os.environ.get("STRICT_10") == "1")
    strict_benchmark = ("--strict-benchmark" in argv) or (os.environ.get("STRICT_BENCHMARK") == "1")

    branch = current_branch()
    m = BRANCH_RE.match(branch)
    if not m:
        print(f"[purity] SKIP (not OWASP branch): {branch}")
        return 0

    num = m.group("num")
    expected = f"A{num}"
    is_a06 = (num == "06")

    print(f"[purity] Branch={branch} expected={expected}")

    routes = Path("app/routes")
    if not routes.exists():
        print("[purity] FAIL: app/routes not found")
        return 2

    found = {p.name for p in routes.glob("*.py")}
    required = {"__init__.py", "health.py"}
    allowed = set(required)

    if not is_a06:
        required.add(f"a{num}.py")
        allowed.add(f"a{num}.py")
    else:
        allowed.add("a06.py")  # optional

    missing = sorted(required - found)
    extra = sorted(found - allowed)
    if missing:
        print(f"[purity] FAIL: missing required route files: {missing}")
        return 2
    if extra:
        print(f"[purity] FAIL: extra route files present: {extra}")
        return 2

    gt_map = scan_gt_ids_in_app()

    if not gt_map:
        if is_a06:
            print("[purity] OK: No GT markers for A06 (SCA/out-of-scope for SAST).")
        else:
            print("[purity] FAIL: No GT markers found under app/")
            return 2
    else:
        wrong_ids = [gid for gid in gt_map if not gid.startswith(f"OWASP2021_{expected}_")]
        if wrong_ids:
            print(f"[purity] FAIL: Found GT ids not matching {expected}: {sorted(wrong_ids)}")
            return 2

        for gid, occ in gt_map.items():
            tags = [t for _, _, t in occ]
            if tags.count("START") != 1 or tags.count("END") != 1:
                print(f"[purity] FAIL: Bad START/END pairing for {gid}: {occ}")
                return 2

        primary = sorted([i for i in gt_map if re.match(rf"^OWASP2021_{expected}_\d{{2}}$", i)])
        if not is_a06 and len(primary) != 10:
            msg = f"[purity] {'FAIL' if strict_10 else 'WARN'}: expected 10 numeric IDs, found {len(primary)}: {primary}"
            print(msg)
            if strict_10:
                return 2

    # branch-local benchmark files should not reference other OWASP categories
    for rel in ("benchmark/gt_catalog.yaml", "benchmark/suite_sets.yaml"):
        p = Path(rel)
        if not p.exists():
            msg = f"[purity] {'FAIL' if strict_benchmark else 'WARN'}: missing {rel}"
            print(msg)
            if strict_benchmark:
                return 2
            continue

        txt = p.read_text(encoding="utf-8", errors="ignore")
        bad = [x for x in re.findall(r"OWASP2021_A(\d{2})_[A-Z0-9_]+", txt) if x != num]
        if bad:
            msg = f"[purity] {'FAIL' if strict_benchmark else 'WARN'}: {rel} references other OWASP categories"
            print(msg)
            if strict_benchmark:
                return 2

    print("[purity] PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
