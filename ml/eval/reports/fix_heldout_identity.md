# Held-out Fix Evaluation

- Provider: `identity`
- Generated: 2026-08-05T21:55:57
- Dataset: `D:\securecode-copilot\ml\datasets\processed\fix_eval_heldout.jsonl` (n=12)

## Caveat

Do **not** report `soft_match_legacy` as primary evidence of fix quality. Prefer **unit_pass**, **security_pass**, **functional_pass**, **exact_match**, **CodeBLEU**, and human evaluation on this held-out set.

## curated_executable (n=12)

| Metric | Value |
|--------|-------|
| Exact match | 0.0% |
| CodeBLEU (mean) | 0.646 |
| Compile success | 100.0% |
| Unit-test pass | 16.7% |
| Security-test pass | 8.3% |
| Security combined | 8.3% |
| Functional pass | 25.0% |
| Scanner clean | 41.7% |
| Soft-match legacy (weak) | 75.0% |

## all (n=12)

| Metric | Value |
|--------|-------|
| Exact match | 0.0% |
| CodeBLEU (mean) | 0.646 |
| Compile success | 100.0% |
| Unit-test pass | 16.7% |
| Security-test pass | 8.3% |
| Security combined | 8.3% |
| Functional pass | 25.0% |
| Scanner clean | 41.7% |
| Soft-match legacy (weak) | 75.0% |

## Human evaluation

Use `ml/eval/human_eval_rubric.md` + `ml/eval/reports/human_eval_template.csv`.
