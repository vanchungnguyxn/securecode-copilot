# Held-out Fix Evaluation

- Provider: `local`
- Generated: 2026-08-05T21:59:02
- Dataset: `D:\securecode-copilot\ml\datasets\processed\fix_eval_heldout.jsonl` (n=16)

## Caveat

Do **not** report `soft_match_legacy` as primary evidence of fix quality. Prefer **unit_pass**, **security_pass**, **functional_pass**, **exact_match**, **CodeBLEU**, and human evaluation on this held-out set.

## curated_executable (n=16)

| Metric | Value |
|--------|-------|
| Exact match | 0.0% |
| CodeBLEU (mean) | 0.490 |
| Compile success | 87.5% |
| Unit-test pass | 12.5% |
| Security-test pass | 18.8% |
| Security combined | 18.8% |
| Functional pass | 18.8% |
| Scanner clean | 75.0% |
| Soft-match legacy (weak) | 56.2% |

## all (n=16)

| Metric | Value |
|--------|-------|
| Exact match | 0.0% |
| CodeBLEU (mean) | 0.490 |
| Compile success | 87.5% |
| Unit-test pass | 12.5% |
| Security-test pass | 18.8% |
| Security combined | 18.8% |
| Functional pass | 18.8% |
| Scanner clean | 75.0% |
| Soft-match legacy (weak) | 56.2% |

## Human evaluation

Use `ml/eval/human_eval_rubric.md` + `ml/eval/reports/human_eval_template.csv`.
