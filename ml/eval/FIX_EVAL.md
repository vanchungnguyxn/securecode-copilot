# Fix Evaluation Protocol (Held-out)

## Problem with the old number

`bench_compare.py` reported ~60% **soft-match** on samples from `sft_pairs.jsonl`.
That criterion is easy to hit (prefix / token overlap) and the file family overlaps training SFT,
so it **does not** prove generalization on unseen vulnerable code.

## What to report instead

| Tier | Metric | Role |
|------|--------|------|
| Primary (executable) | Unit-test pass | Behavior preserved + API usable |
| Primary (executable) | Security-test pass | Targeted CWE mitigated |
| Primary (executable) | Functional pass | Non-security behavior ok |
| Primary (static) | Exact match | Strict equality to reference patch |
| Primary (static) | CodeBLEU | Structural similarity to reference |
| Primary (static) | Compile success | Syntactic validity |
| Secondary | Scanner clean | Rule engine finds 0 hits after patch |
| Legacy only | Soft-match | Continuity with old plots — **not** thesis claim |
| Qualitative | Human rubric | Correctness / safety / readability |

## Commands

```powershell
# 1) Build held-out set (disjoint fingerprints from sft_fix.jsonl)
.\.venv-ml\Scripts\python.exe ml\datasets\build_heldout_fix_eval.py

# 2) Upper bound sanity (gold patches)
.\.venv-ml\Scripts\python.exe ml\eval\eval_fix_heldout.py --provider oracle

# 3) Identity baseline (unpatched vulnerable code)
.\.venv-ml\Scripts\python.exe ml\eval\eval_fix_heldout.py --provider identity --executable-only

# 4) CodeT5 LoRA held-out eval
.\.venv-ml\Scripts\python.exe ml\eval\eval_fix_heldout.py --provider local

# 5) Heuristic baseline (executable subset)
.\.venv\Scripts\python.exe ml\eval\eval_fix_heldout.py --provider heuristic --executable-only
```

Reports: `ml/eval/reports/fix_heldout_<provider>.{json,md}`

Human protocol: [`human_eval_rubric.md`](human_eval_rubric.md)

## Dataset composition

- `curated_executable` — Python vignettes with unit + security + functional tests (primary).
- `cvefixes_disjoint` — CVEFixes pairs absent from training fingerprints (Exact / CodeBLEU / compile).

Metadata: `ml/datasets/processed/fix_eval_heldout_meta.json`
