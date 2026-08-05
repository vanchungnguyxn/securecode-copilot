"""Deprecated wrapper — use train_detector.py + train_codet5_lora.py instead.

See ml/FINETUNE.md and scripts/train_local.ps1 for the real fine-tune path
(CodeBERT + CodeT5 on local GPU, no API).
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main():
    print("SecureCode Copilot fine-tune (local models, no API)")
    print("  1) python ml/datasets/prepare_datasets.py --max-devign 4000")
    print("  2) python ml/training/train_detector.py --data ml/datasets/processed/detector")
    print("  3) python ml/training/train_codet5_lora.py --data ml/datasets/processed/sft.jsonl")
    print("  Or: powershell -File scripts/train_local.ps1")
    print("Docs: ml/FINETUNE.md")
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.dry_run:
        data = Path(__file__).resolve().parents[1] / "datasets" / "processed" / "sft.jsonl"
        sample = Path(__file__).resolve().parents[1] / "datasets" / "sample" / "securecode_sft.jsonl"
        print("sft processed exists:", data.exists(), "| sample exists:", sample.exists())


if __name__ == "__main__":
    main()
