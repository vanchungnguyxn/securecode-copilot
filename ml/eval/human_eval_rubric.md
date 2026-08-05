# Human Evaluation Rubric — Vulnerability Fix Quality

Protocol for SecureCode Copilot thesis / acceptance testing.

## Why this exists

Automatic metrics (exact match, CodeBLEU, compile, unit/security tests) are necessary but incomplete.
Human raters judge whether a patch is **correct**, **safe**, and **understandable** in context.

## Sampling

- Draw **≥ 30** held-out cases from `fix_eval_heldout.jsonl` (prefer `curated_executable` + stratified CVEFixes).
- Blind raters to model identity when comparing systems.
- Each item rated by **≥ 2** independent raters; report mean + Cohen’s κ / agreement %.

## Dimensions (1–5 Likert)

| Score | Correctness | Safety | Readability |
|------:|-------------|--------|-------------|
| 1 | Wrong / broken API | Keeps vulnerability or introduces worse issue | Unreadable / irrelevant |
| 2 | Mostly wrong, accidental overlap | Incomplete mitigation | Hard to follow |
| 3 | Partial fix; edge cases fail | Mitigates somehow but fragile | Understandable with effort |
| 4 | Correct for stated scenario | Vulnerability removed; minor concerns | Clear |
| 5 | Fully correct vs intent | Secure pattern; defense-in-depth OK | Idiomatic & clear |

### Optional binary checklist (mark Y/N)

- [ ] Compiles / parses
- [ ] Preserves intended behavior
- [ ] Removes targeted CWE pattern
- [ ] No obvious new sink (eval, shell=True, pickle, raw SQL…)
- [ ] Would you merge after light review?

## Procedure

1. Show: language, CWE, vulnerable snippet, **model patch only** (hide gold at first).
2. Optionally reveal gold for comparative note (do not change scores retroactively without label).
3. Fill `ml/eval/reports/human_eval_template.csv`.
4. Aggregate means per dimension; report % with score ≥ 4.

## Reporting template

```
Human eval (n=N, raters=R)
  Correctness μ=…  (%≥4=…)
  Safety      μ=…  (%≥4=…)
  Readability μ=…  (%≥4=…)
  Inter-rater agreement=…
```

Store filled CSV under `ml/eval/reports/human_eval_<date>.csv` (do not commit PII).
