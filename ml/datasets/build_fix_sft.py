"""Build fix-heavy SFT for CodeT5 (oversample fix, clear prompt format).

Output: ml/datasets/processed/sft_fix.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
import sys

sys.path.insert(0, str(HERE))
from expand_sft import build_bulk, rich_explain  # noqa: E402
from prepare_datasets import expand_curated  # noqa: E402
from vibe_patterns import VIBE_HARD_NEGATIVES  # noqa: E402

FIX_INSTR = (
    "fix: Rewrite the vulnerable code into a secure version. "
    "Return only the fixed code, no markdown, no explanation."
)
EXPLAIN_INSTR = (
    "explain: Explain the vulnerability, impact, and a short fix hint in plain text."
)


def norm_code(s: str) -> str:
    return "\n".join(ln.rstrip() for ln in s.strip().splitlines())


def make_fix_row(p: Dict[str, Any]) -> Dict[str, str]:
    return {
        "task": "fix",
        "instruction": FIX_INSTR,
        "input": (
            f"Language: {p['language']}\n"
            f"CWE: {p.get('cwe', 'CWE-000')}\n"
            f"Vulnerable code:\n{norm_code(p['vulnerable_code'])}"
        ),
        "output": norm_code(p["secure_code"]),
    }


def make_explain_row(p: Dict[str, Any]) -> Dict[str, str]:
    return {
        "task": "explain",
        "instruction": EXPLAIN_INSTR,
        "input": (
            f"Language: {p['language']}\n"
            f"CWE: {p.get('cwe', 'CWE-000')}\n"
            f"Code:\n{norm_code(p['vulnerable_code'])}"
        ),
        "output": rich_explain(p),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=HERE / "processed" / "sft_fix.jsonl")
    ap.add_argument("--n-per-template", type=int, default=14)
    ap.add_argument("--fix-repeat", type=int, default=3, help="Oversample each fix example")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    pairs = expand_curated(args.seed) + build_bulk(args.n_per_template)
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for p in pairs:
        key = (p["language"], norm_code(p["vulnerable_code"]))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)

    rows: List[Dict[str, str]] = []
    for p in uniq:
        fix = make_fix_row(p)
        for _ in range(args.fix_repeat):
            rows.append(fix)
        rows.append(make_explain_row(p))

    # a little SAFE detect keeps model from always inventing vulns when asked
    for hn in VIBE_HARD_NEGATIVES[:8]:
        rows.append(
            {
                "task": "detect",
                "instruction": "detect: Reply SAFE or VULNERABLE.",
                "input": f"Language: {hn['language']}\nCode:\n{norm_code(hn['code'])}",
                "output": "SAFE",
            }
        )

    random.shuffle(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    by = {}
    for r in rows:
        by[r["task"]] = by.get(r["task"], 0) + 1
    meta = {"n": len(rows), "pairs": len(uniq), "by_task": by, "path": str(args.out)}
    (args.out.parent / "sft_fix_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
