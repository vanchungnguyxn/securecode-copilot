# Baseline compare (Python labeled pairs)

n=240  thr_anti_fp=0.848  safe_cutoff=0.450

| Method | Precision | Recall | F1 | FPR |
|--------|-----------|--------|----|-----|
| SCC Rule-only | 0.827 | 0.917 | 0.870 | 0.192 |
| SCC Hybrid (low-FPR) | 0.821 | 0.917 | 0.866 | 0.200 |
| Bandit | 0.628 | 0.758 | 0.687 | 0.450 |
| Semgrep | 0.938 | 0.125 | 0.221 | 0.008 |
