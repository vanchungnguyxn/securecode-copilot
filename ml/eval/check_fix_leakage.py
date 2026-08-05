"""Verify fix held-out / CVEFixes grouping has no train leakage.

Checks:
  1) curated_executable fingerprints ∩ sft_fix fingerprints == ∅
  2) cvefixes_holdout_next_retrain fingerprints ∩ sft_fix (after exclude merge) == ∅
  3) Near-duplicate grouping: normalized 32-char prefix / identical CWE+normalized body

Exit code 1 if hard leakage (exact fingerprint overlap on curated or reserved holdout).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
PROC = ROOT / "ml" / "datasets" / "processed"


def norm_ws(s: str) -> str:
    return re.sub(r"\s+", "", (s or "").strip())


def fingerprint(code: str) -> str:
    return hashlib.sha1(norm_ws(code).encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def train_fix_fps(sft: Path) -> Set[str]:
    fps: Set[str] = set()
    for row in load_jsonl(sft):
        if row.get("task") != "fix":
            continue
        inp = row.get("input") or ""
        m = re.search(r"Vulnerable code:\n([\s\S]+)$", inp)
        code = m.group(1) if m else inp
        fps.add(fingerprint(code))
        if row.get("output"):
            fps.add(fingerprint(row["output"]))
    return fps


def group_key(lang: str, cwe: str, code: str) -> str:
    body = norm_ws(code)[:96]
    return f"{lang}|{cwe}|{hashlib.sha1(body.encode()).hexdigest()[:16]}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sft-fix", type=Path, default=PROC / "sft_fix.jsonl")
    ap.add_argument("--heldout", type=Path, default=PROC / "fix_eval_heldout.jsonl")
    ap.add_argument("--cve-holdout", type=Path, default=PROC / "cvefixes_holdout_next_retrain.jsonl")
    ap.add_argument("--out", type=Path, default=ROOT / "ml" / "eval" / "reports" / "leakage_check.json")
    args = ap.parse_args()

    train_fps = train_fix_fps(args.sft_fix)
    heldout = load_jsonl(args.heldout)
    cve_hold = load_jsonl(args.cve_holdout)

    curated = [r for r in heldout if r.get("source") == "curated_executable"]
    cve_disjoint = [r for r in heldout if r.get("source") == "cvefixes_disjoint"]

    curated_leak = [r["id"] for r in curated if r.get("fingerprint") in train_fps]
    cve_in_heldout_leak = [r["id"] for r in cve_disjoint if r.get("fingerprint") in train_fps]
    cve_next_leak = [
        str(r.get("id") or r.get("cve_id"))
        for r in cve_hold
        if fingerprint(r.get("vulnerable_code") or "") in train_fps
        or fingerprint(r.get("secure_code") or "") in train_fps
    ]

    # Grouping: same group key across train-side CVEFixes pairs file vs heldout curated
    groups_train: Dict[str, int] = defaultdict(int)
    for row in load_jsonl(args.sft_fix):
        if row.get("task") != "fix":
            continue
        inp = row.get("input") or ""
        lang_m = re.search(r"Language:\s*(\S+)", inp)
        cwe_m = re.search(r"CWE:\s*(\S+)", inp)
        code_m = re.search(r"Vulnerable code:\n([\s\S]+)$", inp)
        if not code_m:
            continue
        g = group_key(lang_m.group(1) if lang_m else "?", cwe_m.group(1) if cwe_m else "?", code_m.group(1))
        groups_train[g] += 1

    curated_group_overlap = []
    for r in curated:
        g = group_key(r.get("language") or "?", r.get("cwe") or "?", r.get("vulnerable_code") or "")
        if groups_train.get(g, 0) > 0:
            curated_group_overlap.append({"id": r["id"], "group": g, "train_n": groups_train[g]})

    report = {
        "train_fix_fingerprints": len(train_fps),
        "curated_executable_n": len(curated),
        "cvefixes_disjoint_in_heldout_n": len(cve_disjoint),
        "cvefixes_next_retrain_n": len(cve_hold),
        "hard_leakage": {
            "curated_fingerprint_overlap_ids": curated_leak,
            "cvefixes_disjoint_fingerprint_overlap_ids": cve_in_heldout_leak,
            "cvefixes_next_retrain_still_in_sft_ids": cve_next_leak[:50],
            "cvefixes_next_retrain_still_in_sft_n": len(cve_next_leak),
        },
        "soft_grouping": {
            "curated_near_dup_group_hits": curated_group_overlap[:30],
            "n": len(curated_group_overlap),
            "note": "Hits mean same lang|cwe|normalized-body-hash as some train fix; investigate if n>0",
        },
        "pass_curated_hard": len(curated_leak) == 0,
        "pass_cve_disjoint_hard": len(cve_in_heldout_leak) == 0,
        "pass_cve_next_excluded_from_sft": len(cve_next_leak) == 0,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md = ROOT / "ml" / "eval" / "reports" / "leakage_check.md"
    lines = [
        "# Fix eval leakage check",
        "",
        f"- Train fix fingerprints: **{report['train_fix_fingerprints']}**",
        f"- Curated executable: **{report['curated_executable_n']}** (hard leak ids: {len(curated_leak)})",
        f"- CVEFixes disjoint in heldout: **{report['cvefixes_disjoint_in_heldout_n']}** (hard leak: {len(cve_in_heldout_leak)})",
        f"- CVEFixes next-retrain file: **{report['cvefixes_next_retrain_n']}** (still in sft: {len(cve_next_leak)})",
        f"- Soft group overlaps (curated): **{len(curated_group_overlap)}**",
        "",
        f"- pass_curated_hard: `{report['pass_curated_hard']}`",
        f"- pass_cve_disjoint_hard: `{report['pass_cve_disjoint_hard']}`",
        f"- pass_cve_next_excluded_from_sft: `{report['pass_cve_next_excluded_from_sft']}`",
        "",
        "JSON: `leakage_check.json`",
    ]
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in report if k.startswith("pass_") or k.endswith("_n") or k in ("curated_executable_n", "train_fix_fingerprints")}, indent=2))
    print(f"wrote {args.out}")

    hard_fail = (not report["pass_curated_hard"]) or (not report["pass_cve_disjoint_hard"])
    # next-retrain exclusion is required after rebuild; fail if still leaking reserved
    if not report["pass_cve_next_excluded_from_sft"]:
        print("WARN: reserved CVEFixes still present in sft_fix — rebuild merge with --exclude-holdout", file=sys.stderr)
        hard_fail = True
    return 1 if hard_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
