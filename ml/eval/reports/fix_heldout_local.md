# Held-out Fix Evaluation

- Provider: `local`
- Generated: 2026-08-05T23:03:15
- Dataset: `D:\securecode-copilot\ml\datasets\processed\fix_eval_heldout.jsonl` (n=40)

## Caveat

Do **not** report `soft_match_legacy` as primary evidence of fix quality. Prefer **unit_pass**, **security_pass**, **functional_pass**, **exact_match**, **CodeBLEU**, and human evaluation on this held-out set.

## curated_executable (n=40)

| Metric | Value |
|--------|-------|
| Exact match | 2.5% |
| CodeBLEU (mean) | 0.508 |
| Compile success | 87.5% |
| Unit-test pass | 37.5% |
| Security-test pass | 10.0% |
| Security combined | 10.0% |
| Functional pass | 35.0% |
| Scanner clean | 77.5% |
| Soft-match legacy (weak) | 50.0% |

## all (n=40)

| Metric | Value |
|--------|-------|
| Exact match | 2.5% |
| CodeBLEU (mean) | 0.508 |
| Compile success | 87.5% |
| Unit-test pass | 37.5% |
| Security-test pass | 10.0% |
| Security combined | 10.0% |
| Functional pass | 35.0% |
| Scanner clean | 77.5% |
| Soft-match legacy (weak) | 50.0% |

## Human evaluation

Use `ml/eval/human_eval_rubric.md` + `ml/eval/reports/human_eval_template.csv`.
