# SecureCode Copilot — Benchmark (Rule vs ML vs Hybrid)

## detector_test_devign_mix (n=435)

| Method | Precision | Recall | F1 | FPR |
|--------|-----------|--------|----|-----|
| Rule-only | 0.735 | 0.165 | 0.270 | 0.060 |
| ML-only (CodeBERT) | 0.764 | 0.193 | 0.308 | 0.060 |
| Hybrid product (low-FPR) | 0.729 | 0.321 | 0.446 | 0.120 |
| Hybrid recall (legacy) | 0.729 | 0.321 | 0.446 | 0.120 |

- ML threshold (anti_fp/product): `0.8480`
- ML anti_fp thr: `0.8480`
- safe_cutoff (suppress rule FP): `0.4500`

## sft_pairs_plus_hardneg (n=971)

| Method | Precision | Recall | F1 | FPR |
|--------|-----------|--------|----|-----|
| Rule-only | 0.880 | 0.930 | 0.905 | 0.121 |
| ML-only (CodeBERT) | 0.500 | 0.008 | 0.017 | 0.008 |
| Hybrid product (low-FPR) | 0.873 | 0.930 | 0.901 | 0.129 |
| Hybrid recall (legacy) | 0.873 | 0.930 | 0.901 | 0.129 |

- ML threshold (anti_fp/product): `0.8480`
- ML anti_fp thr: `0.8480`
- safe_cutoff (suppress rule FP): `0.4500`

## CodeT5 fix soft-match
```json
{
  "available": true,
  "fix_soft_match": 0.6333333333333333,
  "fix_token_overlap_hits": 18,
  "n": 60
}
```

Interpretation for thesis:
- **Hybrid product**: rules + ML FP suppression; ML-alone only at anti_fp thr => lower FPR.
- **Hybrid recall (legacy)**: higher recall/FPR — analysis only, not product default.
- Report anti_fp / balanced thresholds separately.