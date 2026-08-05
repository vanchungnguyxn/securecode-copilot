"""Rebuild sft_fix from curated + CVEFixes while excluding next-retrain holdout.

Excludes by reserve id AND by vulnerable/secure fingerprints so duplicate CVE text
cannot re-enter under another id.

Usage:
  python ml/datasets/rebuild_sft_exclude_holdout.py
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Set

HERE = Path(__file__).resolve().parent
OUT = HERE / "processed"
sys.path.insert(0, str(HERE))
from ingest_cvefixes import to_fix_row  # noqa: E402


def norm_ws(s: str) -> str:
    return re.sub(r"\s+", "", (s or "").strip())


def fingerprint(code: str) -> str:
    return hashlib.sha1(norm_ws(code).encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def main() -> None:
    reserve_path = OUT / "fix_eval_cve_reserve_ids.json"
    pairs_path = OUT / "cvefixes_pairs.jsonl"
    holdout_path = OUT / "cvefixes_holdout_next_retrain.jsonl"
    if not pairs_path.exists():
        raise SystemExit(f"missing {pairs_path}")

    exclude_ids: Set[str] = set()
    if reserve_path.exists():
        exclude_ids = set(json.loads(reserve_path.read_text(encoding="utf-8")).get("ids") or [])

    if holdout_path.exists():
        holdout_pairs = load_jsonl(holdout_path)
    else:
        holdout_pairs = [p for p in load_jsonl(pairs_path) if str(p.get("id") or p.get("cve_id") or "") in exclude_ids]

    exclude_fps: Set[str] = set()
    for p in holdout_pairs:
        exclude_ids.add(str(p.get("id") or p.get("cve_id") or ""))
        exclude_fps.add(fingerprint(p.get("vulnerable_code") or ""))
        exclude_fps.add(fingerprint(p.get("secure_code") or ""))

    subprocess.check_call(
        [sys.executable, "-u", str(HERE / "build_fix_sft.py"), "--n-per-template", "12", "--fix-repeat", "2"]
    )
    sft_path = OUT / "sft_fix.jsonl"
    rows = load_jsonl(sft_path)
    pairs = load_jsonl(pairs_path)

    kept = []
    skipped_id = 0
    skipped_fp = 0
    for p in pairs:
        pid = str(p.get("id") or p.get("cve_id") or "")
        fp_v = fingerprint(p.get("vulnerable_code") or "")
        fp_s = fingerprint(p.get("secure_code") or "")
        if pid in exclude_ids:
            skipped_id += 1
            continue
        if fp_v in exclude_fps or fp_s in exclude_fps:
            skipped_fp += 1
            continue
        kept.append(p)

    cleaned_rows = []
    stripped_curated = 0
    for r in rows:
        if r.get("task") != "fix":
            cleaned_rows.append(r)
            continue
        inp = r.get("input") or ""
        m = re.search(r"Vulnerable code:\n([\s\S]+)$", inp)
        code = m.group(1) if m else inp
        if fingerprint(code) in exclude_fps or fingerprint(r.get("output") or "") in exclude_fps:
            stripped_curated += 1
            continue
        cleaned_rows.append(r)

    extra = [to_fix_row(p["language"], p["cwe"], p["vulnerable_code"], p["secure_code"]) for p in kept]
    extra = extra + extra
    random.seed(42)
    merged = cleaned_rows + extra
    random.shuffle(merged)
    with sft_path.open("w", encoding="utf-8") as f:
        for r in merged:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    meta = {
        "sft_fix_n": len(merged),
        "by_task": dict(Counter(r.get("task") for r in merged)),
        "by_source": dict(Counter(r.get("source", "curated") for r in merged)),
        "cvefixes_merged": len(kept),
        "cvefixes_holdout_excluded_ids": skipped_id,
        "cvefixes_holdout_excluded_fp_dupes": skipped_fp,
        "curated_rows_stripped_holdout_fp": stripped_curated,
        "holdout_pairs_n": len(holdout_pairs),
        "note": "Holdout excluded by id+fingerprint for next CodeT5 retrain; current checkpoint may still have seen old merge",
    }
    (OUT / "sft_fix_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
