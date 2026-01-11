#!/usr/bin/env python3
import argparse, os, re, subprocess
from pathlib import Path
import yaml

BRANCH_RE = re.compile(r"^owasp2021-a(?P<num>\d{2})-")
GT_RE = re.compile(r"GT:(?P<id>OWASP2021_A(?P<num>\d{2})_[A-Z0-9_]+)_(?P<tag>START|END)")

def current_branch():
    for k in ("GITHUB_HEAD_REF","GITHUB_REF_NAME","BRANCH_NAME"):
        v = os.environ.get(k)
        if v: return v
    return subprocess.check_output(["git","rev-parse","--abbrev-ref","HEAD"], text=True).strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmark/gt_catalog.yaml")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    branch = current_branch()
    m = BRANCH_RE.match(branch)
    if not m:
        print(f"[gt_catalog] SKIP (not OWASP branch): {branch}")
        return 0

    num = m.group("num")
    owasp = f"A{num}"
    prefix = f"OWASP2021_{owasp}_"

    hits = {}
    for p in sorted(Path("app").rglob("*.py")):
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i,line in enumerate(lines, start=1):
            mm = GT_RE.search(line)
            if not mm: continue
            gid = mm.group("id")
            if not gid.startswith(prefix): 
                continue
            hits.setdefault(gid, {"file": p.as_posix()})
            hits[gid][mm.group("tag")] = i

    items = []
    for gid,d in sorted(hits.items()):
        if "START" not in d or "END" not in d:
            raise SystemExit(f"GT id {gid} missing START/END: {d}")
        items.append({"id": gid, "file": d["file"], "start_line": d["START"], "end_line": d["END"]})

    doc = {"version": 1, "suite": "durinn-owasp2021-python-micro-suite", "branch": branch, "owasp": owasp, "items": items}
    rendered = yaml.safe_dump(doc, sort_keys=False)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    if args.check:
        if not out.exists() or out.read_text(encoding="utf-8") != rendered:
            raise SystemExit(f"[gt_catalog] OUT OF DATE: run python benchmark/generate_gt_catalog.py")
        print("[gt_catalog] OK")
        return 0

    out.write_text(rendered, encoding="utf-8")
    print(f"[gt_catalog] Wrote {out} ({len(items)} items)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
