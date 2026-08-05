"""Offline evaluation: Precision/Recall/F1 of rule scanner vs labeled sample dataset."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow importing backend scanner
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.scanners.engine import RuleScanner  # noqa: E402


def main():
    data = ROOT / "ml" / "datasets" / "sample" / "securecode_sft.jsonl"
    rows = [json.loads(l) for l in data.read_text(encoding="utf-8").splitlines() if l.strip()]
    scanner = RuleScanner()

    tp = fp = fn = 0
    details = []
    for row in rows:
        lang = row["language"]
        code = row["vulnerable_code"]
        expected_cwe = row["cwe"]
        _, findings = scanner.scan(code, lang)
        found_cwes = {f.cwe for f in findings}
        if expected_cwe in found_cwes:
            tp += 1
            details.append((row["id"], "TP", expected_cwe))
        elif findings:
            fp += 1  # detected something else primarily — count as miss for target CWE
            fn += 1
            details.append((row["id"], "PARTIAL", expected_cwe, sorted(found_cwes)))
        else:
            fn += 1
            details.append((row["id"], "FN", expected_cwe))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print("=== SecureCode Copilot Eval (rule engine on sample SFT set) ===")
    print(f"samples={len(rows)}  TP={tp}  FP={fp}  FN={fn}")
    print(f"precision={precision:.3f}  recall={recall:.3f}  f1={f1:.3f}")
    for d in details:
        print(" ", d)


if __name__ == "__main__":
    main()
