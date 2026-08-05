# Multilingual detection eval

Rule coverage ≠ fine-tuned model generalization.

| Script | Output | Use for |
|--------|--------|---------|
| `bench_multilingual.py` | `reports/bench_multilingual.md` | Per-language P/R/F1/FPR for Rule / ML / Hybrid |
| `bench_compare.py` | `reports/bench_compare.md` | Aggregate tables (smoke + Devign mix) |

## Tiers inside `bench_multilingual.md`

1. **`cvefixes_pairs`** — preferred for multi-lang detector claims (external pairs).
2. **`detector_test`** — held-out, but C-heavy.
3. **`sft_hardneg_smoke`** — project SFT/HN only; do not use alone in thesis.

## Languages

Python · JavaScript · TypeScript · Java · C · C++ · C# · PHP

TypeScript currently has **no labeled rows** in these tiers (rules exist; map/eval as JS if needed).

```powershell
.\.venv-ml\Scripts\python.exe ml\eval\bench_multilingual.py
```
