# Held-out Fix Evaluation

- Provider: `oracle`
- Generated: 2026-08-05T21:58:20
- Dataset: `D:\securecode-copilot\ml\datasets\processed\fix_eval_heldout.jsonl` (n=16)

## Caveat

Do **not** report `soft_match_legacy` as primary evidence of fix quality. Prefer **unit_pass**, **security_pass**, **functional_pass**, **exact_match**, **CodeBLEU**, and human evaluation on this held-out set.

## curated_executable (n=16)

| Metric | Value |
|--------|-------|
| Exact match | 100.0% |
| CodeBLEU (mean) | 1.000 |
| Compile success | 100.0% |
| Unit-test pass | 100.0% |
| Security-test pass | 100.0% |
| Security combined | 100.0% |
| Functional pass | 100.0% |
| Scanner clean | 93.8% |
| Soft-match legacy (weak) | 100.0% |

## all (n=16)

| Metric | Value |
|--------|-------|
| Exact match | 100.0% |
| CodeBLEU (mean) | 1.000 |
| Compile success | 100.0% |
| Unit-test pass | 100.0% |
| Security-test pass | 100.0% |
| Security combined | 100.0% |
| Functional pass | 100.0% |
| Scanner clean | 93.8% |
| Soft-match legacy (weak) | 100.0% |

## Human evaluation

Use `ml/eval/human_eval_rubric.md` + `ml/eval/reports/human_eval_template.csv`.
