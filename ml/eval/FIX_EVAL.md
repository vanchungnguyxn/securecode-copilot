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

- `curated_executable` — Python vignettes with unit + security + functional tests (**primary**; target n≥40).
- `cvefixes_disjoint` — CVEFixes pairs absent from **current** `sft_fix` fingerprints (Exact / CodeBLEU).
- `cvefixes_holdout_next_retrain.jsonl` — ~20% deterministic reserve; **exclude before next retrain** via `rebuild_sft_exclude_holdout.py` / `ingest_cvefixes --exclude-holdout`.

Leakage check:

```powershell
.\.venv-ml\Scripts\python.exe ml\eval\check_fix_leakage.py
# → ml/eval/reports/leakage_check.md
```

## Next retrain (CVEFixes holdout)

1. Tracked reserve ids: `ml/datasets/cvefixes_holdout_reserve_ids.json`
2. `python ml/datasets/rebuild_sft_exclude_holdout.py` — rebuild `sft_fix.jsonl` without reserved pairs (id + fingerprint)
3. Train CodeT5 on the new `sft_fix.jsonl`
4. `build_heldout_fix_eval.py` + `check_fix_leakage.py` (must pass `pass_cve_next_excluded_from_sft`)
