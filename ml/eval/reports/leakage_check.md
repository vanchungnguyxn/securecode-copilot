# Fix eval leakage check

- Train fix fingerprints: **2165**
- Curated executable: **40** (hard leak ids: 0)
- CVEFixes disjoint in heldout: **80** (hard leak: 0)
- CVEFixes next-retrain file: **157** (still in sft: 0)
- Soft group overlaps (curated): **0**

- pass_curated_hard: `True`
- pass_cve_disjoint_hard: `True`
- pass_cve_next_excluded_from_sft: `True`

JSON: `leakage_check.json`
