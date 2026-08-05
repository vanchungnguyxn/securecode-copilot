"""
Held-out vulnerability-fix evaluation for CodeT5 / heuristic / OpenAI.

Primary metrics (thesis-grade):
  - Exact match
  - CodeBLEU (or codebleu_approx)
  - Compile success rate
  - Unit-test pass rate
  - Security-test pass rate (+ pattern / scanner regression)
  - Functional preservation rate

Legacy soft-match is reported but NOT recommended as a primary claim.

Usage:
  # build held-out set
  python ml/datasets/build_heldout_fix_eval.py

  # evaluate CodeT5 LoRA
  .\\.venv-ml\\Scripts\\python.exe ml\\eval\\eval_fix_heldout.py --provider local --limit 0

  # evaluate secure_reference as oracle (sanity upper bound)
  python ml/eval/eval_fix_heldout.py --provider oracle

  # heuristic rewrite baseline
  python ml/eval/eval_fix_heldout.py --provider heuristic --executable-only
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "eval"))
sys.path.insert(0, str(ROOT / "backend"))

from fix_metrics import (  # noqa: E402
    evaluate_case_dynamic,
    evaluate_case_static,
    normalize_code,
)


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def mean(xs: List[Optional[float]]) -> Optional[float]:
    vals = [float(x) for x in xs if x is not None]
    return sum(vals) / len(vals) if vals else None


def rate(flags: List[Optional[bool]]) -> Optional[float]:
    vals = [1.0 if x else 0.0 for x in flags if x is not None]
    return sum(vals) / len(vals) if vals else None


def gen_oracle(case: Dict[str, Any]) -> str:
    return case.get("secure_reference") or ""


def gen_identity(case: Dict[str, Any]) -> str:
    return case.get("vulnerable_code") or ""


def load_local_generator(ckpt: Path):
    import torch
    from peft import PeftModel
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

    extra = ckpt / "adapter_config_extra.json"
    base = "Salesforce/codet5-base"
    if extra.exists():
        base = json.loads(extra.read_text(encoding="utf-8")).get("base_model_name_or_path", base)
    tok = AutoTokenizer.from_pretrained(str(ckpt))
    model = AutoModelForSeq2SeqLM.from_pretrained(base)
    model = PeftModel.from_pretrained(model, str(ckpt))
    model.eval()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    def generate(case: Dict[str, Any]) -> str:
        instr = (
            "fix: Rewrite the vulnerable code into a secure version. "
            "Return only the fixed code, no markdown, no explanation."
        )
        inp = (
            f"Language: {case.get('language')}\n"
            f"CWE: {case.get('cwe', '')}\n"
            f"Vulnerable code:\n{normalize_code(case['vulnerable_code'])}"
        )
        src = f"{instr}\n{inp}"
        enc = tok(src, return_tensors="pt", truncation=True, max_length=400).to(device)
        with torch.no_grad():
            out = model.generate(
                **enc,
                max_new_tokens=220,
                num_beams=2,
                repetition_penalty=1.15,
                no_repeat_ngram_size=4,
            )
        return normalize_code(tok.decode(out[0], skip_special_tokens=True))

    return generate


def load_heuristic_generator():
    from app.models.schemas import Severity, Vulnerability
    from app.services.llm import HeuristicLLM
    import asyncio

    llm = HeuristicLLM()

    def generate(case: Dict[str, Any]) -> str:
        lang = case.get("language") or "python"
        code = case["vulnerable_code"]
        vuln = Vulnerability(
            id="v1",
            rule_id=str(case.get("cwe") or "GENERIC"),
            title=case.get("title") or "vuln",
            message="",
            severity=Severity.HIGH,
            cwe=case.get("cwe") or "CWE-000",
            owasp="",
            language=lang,
            file="heldout.py",
            start_line=1,
            end_line=max(1, code.count("\n") + 1),
            snippet=code[:500],
            confidence=0.9,
        )

        async def _run():
            fix = await llm.fix(code, vuln)
            return fix.fixed_code

        return normalize_code(asyncio.run(_run()))

    return generate


def aggregate(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    def col(key: str):
        return [r.get(key) for r in rows]

    exec_rows = [r for r in rows if r.get("source") == "curated_executable"]
    cve_rows = [r for r in rows if r.get("source") == "cvefixes_disjoint"]

    def block(subset: List[Dict[str, Any]], name: str) -> Dict[str, Any]:
        if not subset:
            return {"n": 0}
        return {
            "n": len(subset),
            "exact_match": rate(col_s(subset, "exact_match")),
            "soft_match_legacy": rate(col_s(subset, "soft_match_legacy")),
            "codebleu_mean": mean(col_s(subset, "codebleu")),
            "compile_success": rate(col_s(subset, "compile_ok")),
            "unit_pass": rate(col_s(subset, "unit_pass")),
            "security_pass": rate(col_s(subset, "security_pass")),
            "security_combined": rate(col_s(subset, "security_combined")),
            "functional_pass": rate(col_s(subset, "functional_pass")),
            "scanner_clean": rate(col_s(subset, "scanner_clean")),
            "note": name,
        }

    def col_s(subset, key):
        return [r.get(key) for r in subset]

    return {
        "all": block(rows, "all held-out"),
        "curated_executable": block(exec_rows, "primary for unit/security/functional"),
        "cvefixes_disjoint": block(cve_rows, "static metrics / exact / codebleu"),
        "codebleu_backend": next((r.get("codebleu_backend") for r in rows if r.get("codebleu_backend")), None),
    }


def to_markdown(provider: str, agg: Dict[str, Any], meta: Dict[str, Any]) -> str:
    def pct(x):
        return "—" if x is None else f"{100 * x:.1f}%"

    def num(x):
        return "—" if x is None else f"{x:.3f}"

    lines = [
        "# Held-out Fix Evaluation",
        "",
        f"- Provider: `{provider}`",
        f"- Generated: {meta.get('timestamp')}",
        f"- Dataset: `{meta.get('dataset')}` (n={meta.get('n')})",
        "",
        "## Caveat",
        "",
        "Do **not** report `soft_match_legacy` as primary evidence of fix quality. "
        "Prefer **unit_pass**, **security_pass**, **functional_pass**, **exact_match**, **CodeBLEU**, "
        "and human evaluation on this held-out set.",
        "",
    ]
    for key in ("curated_executable", "cvefixes_disjoint", "all"):
        b = agg.get(key) or {}
        if not b.get("n"):
            continue
        lines += [
            f"## {key} (n={b['n']})",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Exact match | {pct(b.get('exact_match'))} |",
            f"| CodeBLEU (mean) | {num(b.get('codebleu_mean'))} |",
            f"| Compile success | {pct(b.get('compile_success'))} |",
            f"| Unit-test pass | {pct(b.get('unit_pass'))} |",
            f"| Security-test pass | {pct(b.get('security_pass'))} |",
            f"| Security combined | {pct(b.get('security_combined'))} |",
            f"| Functional pass | {pct(b.get('functional_pass'))} |",
            f"| Scanner clean | {pct(b.get('scanner_clean'))} |",
            f"| Soft-match legacy (weak) | {pct(b.get('soft_match_legacy'))} |",
            "",
        ]
    lines += [
        "## Human evaluation",
        "",
        "Use `ml/eval/human_eval_rubric.md` + `ml/eval/reports/human_eval_template.csv`.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=ROOT / "ml/datasets/processed/fix_eval_heldout.jsonl")
    ap.add_argument("--ckpt", type=Path, default=ROOT / "ml/inference/checkpoints/codet5-lora")
    ap.add_argument(
        "--provider",
        choices=["local", "oracle", "identity", "heuristic"],
        default="local",
    )
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    ap.add_argument("--executable-only", action="store_true")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "ml/eval/reports")
    args = ap.parse_args()

    if not args.data.exists():
        raise SystemExit(f"Missing {args.data}. Run: python ml/datasets/build_heldout_fix_eval.py")

    cases = load_jsonl(args.data)
    if args.executable_only:
        cases = [c for c in cases if c.get("source") == "curated_executable"]
    if args.limit and args.limit > 0:
        cases = cases[: args.limit]

    if args.provider == "oracle":
        generate = gen_oracle
    elif args.provider == "identity":
        generate = gen_identity
    elif args.provider == "heuristic":
        generate = load_heuristic_generator()
    else:
        if not args.ckpt.exists():
            raise SystemExit(f"Missing checkpoint {args.ckpt}")
        generate = load_local_generator(args.ckpt)

    results: List[Dict[str, Any]] = []
    t0 = time.time()
    for i, case in enumerate(cases, 1):
        pred = generate(case)
        static = evaluate_case_static(pred, case)
        dyn = evaluate_case_dynamic(pred, case)
        row = {
            "id": case["id"],
            "language": case.get("language"),
            "cwe": case.get("cwe"),
            "source": case.get("source"),
            "pred": pred,
            "gold": case.get("secure_reference"),
            **static,
            **dyn,
        }
        results.append(row)
        print(
            f"[{i}/{len(cases)}] {case['id']} exact={static['exact_match']} "
            f"cb={static['codebleu']:.3f} unit={dyn.get('unit_pass')} sec={dyn.get('security_pass')}"
        )

    agg = aggregate(results)
    meta = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "provider": args.provider,
        "dataset": str(args.data),
        "n": len(results),
        "seconds": round(time.time() - t0, 2),
        "ckpt": str(args.ckpt) if args.provider == "local" else None,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    tag = args.provider
    json_path = args.out_dir / f"fix_heldout_{tag}.json"
    md_path = args.out_dir / f"fix_heldout_{tag}.md"
    payload = {"meta": meta, "aggregate": agg, "results": results}
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(to_markdown(args.provider, agg, meta), encoding="utf-8")
    print(json.dumps({"meta": meta, "aggregate": agg}, indent=2))
    print(f"[done] {md_path}")


if __name__ == "__main__":
    main()
