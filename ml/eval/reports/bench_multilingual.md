# Multilingual Detection Benchmark (per language)

Fine-tuned CodeBERT + RuleScanner evaluated **separately for each language**.

### How to read this

- **Rule-only** proves multi-language *scanner coverage*.
- **ML-only / Hybrid** show whether the **fine-tuned detector** generalizes per language.
- Prefer **`cvefixes_pairs`** over **`sft_hardneg_smoke`** for generalization claims.
- `detector_test` is held-out but **C-heavy** (Devign) — weak for JS/Java claims alone.
- **TypeScript** has no dedicated labeled set here (engine may treat as JS).

- ML discovery thr: `0.9976`
- ML anti_fp thr: `0.9976`
- safe_cutoff: `0.5500`

## Tier: `cvefixes_pairs` (n=1522)

External CVEFixes vuln/secure pairs (stronger multi-lang evidence).

### Rule-only

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 228 | 0.615 | 0.070 | 0.126 | 0.044 |
| javascript | 228 | 0.500 | 0.096 | 0.162 | 0.096 |
| typescript | 0 | — | — | — | — |
| java | 228 | 0.615 | 0.070 | 0.126 | 0.044 |
| c | 228 | 0.500 | 0.053 | 0.095 | 0.053 |
| cpp | 228 | 0.400 | 0.018 | 0.034 | 0.026 |
| csharp | 154 | 0.500 | 0.013 | 0.025 | 0.013 |
| php | 228 | 0.524 | 0.096 | 0.163 | 0.088 |

### ML-only (CodeBERT)

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 228 | 0.544 | 0.272 | 0.363 | 0.228 |
| javascript | 228 | 0.667 | 0.088 | 0.155 | 0.044 |
| typescript | 0 | — | — | — | — |
| java | 228 | 1.000 | 0.061 | 0.116 | 0.000 |
| c | 228 | 0.594 | 0.167 | 0.260 | 0.114 |
| cpp | 228 | 0.864 | 0.167 | 0.279 | 0.026 |
| csharp | 154 | 1.000 | 0.091 | 0.167 | 0.000 |
| php | 228 | 0.938 | 0.132 | 0.231 | 0.009 |

### Hybrid product

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 228 | 0.540 | 0.298 | 0.384 | 0.254 |
| javascript | 228 | 0.615 | 0.140 | 0.229 | 0.088 |
| typescript | 0 | — | — | — | — |
| java | 228 | 0.824 | 0.123 | 0.214 | 0.026 |
| c | 228 | 0.595 | 0.219 | 0.321 | 0.149 |
| cpp | 228 | 0.875 | 0.184 | 0.304 | 0.026 |
| csharp | 154 | 1.000 | 0.104 | 0.188 | 0.000 |
| php | 228 | 0.885 | 0.202 | 0.329 | 0.026 |

**Hybrid snapshot**

- Stronger (n≥20 & F1≥0.5): —
- Weaker / small-n: python (F1=0.38, n=228), javascript (F1=0.23, n=228), java (F1=0.21, n=228), c (F1=0.32, n=228), cpp (F1=0.30, n=228), csharp (F1=0.19, n=154), php (F1=0.33, n=228)
- No labeled samples: typescript

## Tier: `detector_test` (n=534)

Held-out detector split — language balance skewed toward C.

### Rule-only

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 17 | 0.600 | 0.273 | 0.375 | 0.333 |
| javascript | 7 | 1.000 | 1.000 | 1.000 | 0.000 |
| typescript | 0 | — | — | — | — |
| java | 3 | 1.000 | 0.500 | 0.667 | 0.000 |
| c | 409 | 0.625 | 0.134 | 0.220 | 0.068 |
| cpp | 32 | 0.000 | 0.000 | 0.000 | 0.062 |
| csharp | 17 | 0.000 | 0.000 | 0.000 | 0.000 |
| php | 49 | 0.750 | 0.103 | 0.182 | 0.050 |

### ML-only (CodeBERT)

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 17 | 1.000 | 0.818 | 0.900 | 0.000 |
| javascript | 7 | 0.000 | 0.000 | 0.000 | 0.000 |
| typescript | 0 | — | — | — | — |
| java | 3 | 1.000 | 0.500 | 0.667 | 0.000 |
| c | 409 | 1.000 | 0.053 | 0.102 | 0.000 |
| cpp | 32 | 0.500 | 0.062 | 0.111 | 0.062 |
| csharp | 17 | 1.000 | 0.250 | 0.400 | 0.000 |
| php | 49 | 0.700 | 0.241 | 0.359 | 0.150 |

### Hybrid product

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 17 | 1.000 | 0.909 | 0.952 | 0.000 |
| javascript | 7 | 1.000 | 1.000 | 1.000 | 0.000 |
| typescript | 0 | — | — | — | — |
| java | 3 | 1.000 | 0.500 | 0.667 | 0.000 |
| c | 409 | 0.756 | 0.166 | 0.272 | 0.045 |
| cpp | 32 | 0.500 | 0.062 | 0.111 | 0.062 |
| csharp | 17 | 1.000 | 0.250 | 0.400 | 0.000 |
| php | 49 | 0.714 | 0.345 | 0.465 | 0.200 |

**Hybrid snapshot**

- Stronger (n≥20 & F1≥0.5): —
- Weaker / small-n: python (F1=0.95, n=17), javascript (F1=1.00, n=7), java (F1=0.67, n=3), c (F1=0.27, n=409), cpp (F1=0.11, n=32), csharp (F1=0.40, n=17), php (F1=0.47, n=49)
- No labeled samples: typescript

## Tier: `sft_hardneg_smoke` (n=977)

Project SFT + hard negatives — smoke only, overlaps training family.

### Rule-only

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 308 | 0.846 | 0.932 | 0.887 | 0.155 |
| javascript | 259 | 0.991 | 0.840 | 0.909 | 0.007 |
| typescript | 0 | — | — | — | — |
| java | 117 | 0.711 | 0.947 | 0.812 | 0.367 |
| c | 93 | 1.000 | 1.000 | 1.000 | 0.000 |
| cpp | 68 | 1.000 | 1.000 | 1.000 | 0.000 |
| csharp | 110 | 0.821 | 1.000 | 0.902 | 0.218 |
| php | 22 | 1.000 | 1.000 | 1.000 | 0.000 |

### ML-only (CodeBERT)

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 308 | 1.000 | 0.395 | 0.566 | 0.000 |
| javascript | 259 | 1.000 | 0.224 | 0.366 | 0.000 |
| typescript | 0 | — | — | — | — |
| java | 117 | 1.000 | 0.263 | 0.417 | 0.000 |
| c | 93 | 1.000 | 0.044 | 0.085 | 0.000 |
| cpp | 68 | 1.000 | 0.059 | 0.111 | 0.000 |
| csharp | 110 | 1.000 | 0.236 | 0.382 | 0.000 |
| php | 22 | 1.000 | 0.727 | 0.842 | 0.000 |

### Hybrid product

| Language | Samples | Precision | Recall | F1 | FPR |
|----------|---------|-----------|--------|----|-----|
| python | 308 | 1.000 | 0.857 | 0.923 | 0.000 |
| javascript | 259 | 1.000 | 0.776 | 0.874 | 0.000 |
| typescript | 0 | — | — | — | — |
| java | 117 | 1.000 | 0.982 | 0.991 | 0.000 |
| c | 93 | 1.000 | 0.756 | 0.861 | 0.000 |
| cpp | 68 | 1.000 | 1.000 | 1.000 | 0.000 |
| csharp | 110 | 1.000 | 0.982 | 0.991 | 0.000 |
| php | 22 | 1.000 | 1.000 | 1.000 | 0.000 |

**Hybrid snapshot**

- Stronger (n≥20 & F1≥0.5): python (F1=0.92, n=308), javascript (F1=0.87, n=259), java (F1=0.99, n=117), c (F1=0.86, n=93), cpp (F1=1.00, n=68), csharp (F1=0.99, n=110), php (F1=1.00, n=22)
- Weaker / small-n: —
- No labeled samples: typescript

## Claim guidance for thesis

| Claim | Supported by |
|-------|--------------|
| Multi-language **rule detection** | Non-empty Rule-only rows with real P/R |
| Multi-language **fine-tuned detector** | ML/Hybrid on `cvefixes_pairs` / balanced detector splits |
| Multi-language **fix generation** | Held-out fix eval (`FIX_EVAL.md`), not this table |

Do **not** cite only `sft_hardneg_smoke` as proof of multilingual generalization.
