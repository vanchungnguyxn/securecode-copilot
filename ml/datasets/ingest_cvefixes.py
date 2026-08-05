"""Download hitoshura25/cvefixes → fix pairs for CodeT5 SFT.

Writes:
  ml/datasets/processed/cvefixes_pairs.jsonl
  merges into ml/datasets/processed/sft_fix.jsonl (optional --merge)
"""

from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "processed"

LANG_MAP = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
    "ts": "typescript",
    "typescript": "typescript",
    "java": "java",
    "c": "c",
    "c++": "cpp",
    "cpp": "cpp",
    "cc": "cpp",
    "cxx": "cpp",
    "c#": "csharp",
    "csharp": "csharp",
    "cs": "csharp",
    "php": "php",
    "go": "go",
    "ruby": "ruby",
}

FIX_INSTR = (
    "fix: Rewrite the vulnerable code into a secure version. "
    "Return only the fixed code, no markdown, no explanation."
)


def norm_lang(x: Any) -> Optional[str]:
    if x is None:
        return None
    s = str(x).strip().lower()
    if not s or s in {"nan", "none", "null"}:
        return None
    # sometimes list or multi
    if "," in s:
        s = s.split(",")[0].strip()
    return LANG_MAP.get(s, s if s in LANG_MAP.values() else None)


def norm_cwe(x: Any) -> str:
    if x is None:
        return "CWE-000"
    s = str(x).strip()
    m = re.search(r"(CWE-?\d+)", s, re.I)
    if not m:
        return "CWE-000"
    t = m.group(1).upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")
    if t.startswith("CWE") and not t.startswith("CWE-"):
        t = "CWE-" + t[3:]
    return t


def clean_code(s: Any, max_chars: int = 2500) -> str:
    if s is None:
        return ""
    text = str(s).replace("\r\n", "\n").strip()
    # drop pure diff markers noise
    lines = []
    for ln in text.splitlines():
        if ln.startswith("+++") or ln.startswith("---") or ln.startswith("@@"):
            continue
        if ln.startswith("+") or ln.startswith("-"):
            ln = ln[1:]
        lines.append(ln.rstrip())
    text = "\n".join(lines).strip()
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def to_fix_row(lang: str, cwe: str, vuln: str, secure: str) -> Dict[str, str]:
    return {
        "task": "fix",
        "instruction": FIX_INSTR,
        "input": f"Language: {lang}\nCWE: {cwe}\nVulnerable code:\n{vuln}",
        "output": secure,
        "source": "cvefixes",
    }


def iter_cvefixes(max_rows: int, langs: Optional[List[str]], seed: int = 42) -> Iterable[Dict[str, Any]]:
    from datasets import load_dataset

    random.seed(seed)
    want = {LANG_MAP.get(x, x) for x in (langs or [])} if langs else None
    per_lang_cap = max(50, max_rows // max(1, len(want or ["x"])))
    print(
        f"[1/3] load hitoshura25/cvefixes (download+cache) max_rows={max_rows} "
        f"per_lang_cap={per_lang_cap} langs={want or 'all'}",
        flush=True,
    )
    # Non-streaming: HF resume download is more reliable than streaming shard hops on flaky nets.
    ds = load_dataset("hitoshura25/cvefixes", split="train")
    print(f"[1/3] dataset ready n={len(ds)} — filtering pairs...", flush=True)
    # shuffle indices for diversity
    idxs = list(range(len(ds)))
    random.shuffle(idxs)

    counts: Counter = Counter()
    kept = 0
    scanned = 0
    last_print_kept = -1
    for i in idxs:
        ex = ds[i]
        scanned += 1
        if scanned % 500 == 0 or (kept != last_print_kept and kept > 0 and kept % 50 == 0):
            last_print_kept = kept
            print(f"  ... scanned={scanned} kept={kept}/{max_rows} by_lang={dict(counts)}", flush=True)
        lang = norm_lang(ex.get("language"))
        if not lang:
            continue
        if want and lang not in want:
            continue
        if counts[lang] >= per_lang_cap:
            continue
        vuln = clean_code(ex.get("vulnerable_code"))
        fixed = clean_code(ex.get("fixed_code"))
        if len(vuln) < 40 or len(fixed) < 40:
            continue
        if vuln == fixed:
            continue
        cwe = norm_cwe(ex.get("cwe_id"))
        yield {
            "id": f"cvefix-{ex.get('cve_id', i)}-{i}",
            "language": lang,
            "cwe": cwe,
            "vulnerable_code": vuln,
            "secure_code": fixed,
            "cve_id": ex.get("cve_id"),
            "severity": "high",
            "explanation": f"CVEFixes patch for {ex.get('cve_id')} ({cwe}).",
        }
        counts[lang] += 1
        kept += 1
        if kept >= max_rows:
            break
        # soft stop: filled every wanted lang to cap
        if want and all(counts.get(l, 0) >= per_lang_cap for l in want):
            break
    print(f"[1/3] done scanned={scanned} kept={kept} by_lang={dict(counts)}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-rows", type=int, default=800)
    ap.add_argument(
        "--langs",
        default="python,javascript,java,c,cpp,php,csharp",
        help="comma languages or empty for all mapped",
    )
    ap.add_argument("--merge-sft-fix", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    langs = [x.strip() for x in args.langs.split(",") if x.strip()] or None
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pairs_path = OUT_DIR / "cvefixes_pairs.jsonl"
    pairs: List[Dict[str, Any]] = list(iter_cvefixes(args.max_rows, langs, args.seed))
    print(f"[2/3] write {pairs_path} ({len(pairs)} pairs)", flush=True)
    with pairs_path.open("w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")
    meta = {
        "n_pairs": len(pairs),
        "by_lang": dict(Counter(p["language"] for p in pairs)),
        "by_cwe_top": Counter(p["cwe"] for p in pairs).most_common(15),
        "path": str(pairs_path),
    }
    (OUT_DIR / "cvefixes_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2), flush=True)

    if args.merge_sft_fix:
        import subprocess
        import sys

        print("[3/3] rebuild curated sft_fix + merge CVEFixes...", flush=True)
        subprocess.check_call(
            [
                sys.executable,
                "-u",
                str(HERE / "build_fix_sft.py"),
                "--n-per-template",
                "12",
                "--fix-repeat",
                "2",
            ]
        )
        sft_path = OUT_DIR / "sft_fix.jsonl"
        rows = []
        if sft_path.exists():
            rows = [json.loads(l) for l in sft_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        extra = [to_fix_row(p["language"], p["cwe"], p["vulnerable_code"], p["secure_code"]) for p in pairs]
        # repeat CVEFixes once more for weight
        extra = extra + extra
        random.seed(args.seed)
        merged = rows + extra
        random.shuffle(merged)
        with sft_path.open("w", encoding="utf-8") as f:
            for r in merged:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        by_task = Counter(r.get("task") for r in merged)
        by_src = Counter(r.get("source", "curated") for r in merged)
        print(
            json.dumps(
                {"sft_fix_n": len(merged), "by_task": dict(by_task), "by_source": dict(by_src)},
                indent=2,
            ),
            flush=True,
        )
        print(f"[done] {sft_path}", flush=True)


if __name__ == "__main__":
    main()
