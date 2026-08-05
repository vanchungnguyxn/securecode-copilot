"""Evaluate detector checkpoint: Precision/Recall/F1/FPR + hard-negative FP rate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def load_jsonl(path: Path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", type=Path, default=Path("ml/inference/checkpoints/detector-codebert"))
    ap.add_argument("--data", type=Path, default=Path("ml/datasets/processed/detector/test.jsonl"))
    ap.add_argument("--hard-negatives", type=Path, default=Path("ml/datasets/processed/hard_negatives.jsonl"))
    ap.add_argument("--threshold-file", type=Path, default=Path("ml/inference/checkpoints/thresholds.json"))
    args = ap.parse_args()

    import torch
    from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    if not args.ckpt.exists():
        raise SystemExit(f"Checkpoint missing: {args.ckpt} — train first.")

    thr = 0.5
    if args.threshold_file.exists():
        report = json.loads(args.threshold_file.read_text(encoding="utf-8"))
        thr = float(report.get("detector", {}).get("threshold", {}).get("threshold", 0.5))

    tok = AutoTokenizer.from_pretrained(args.ckpt)
    model = AutoModelForSequenceClassification.from_pretrained(args.ckpt)
    model.eval()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    def predict(codes):
        probs = []
        with torch.no_grad():
            for i in range(0, len(codes), 8):
                enc = tok(codes[i : i + 8], truncation=True, max_length=256, padding=True, return_tensors="pt")
                enc = {k: v.to(device) for k, v in enc.items()}
                p = torch.softmax(model(**enc).logits, dim=-1)[:, 1].cpu().numpy()
                probs.extend(p.tolist())
        return np.array(probs)

    rows = load_jsonl(args.data)
    probs = predict([r["code"] for r in rows])
    y = np.array([r["label"] for r in rows])
    pred = (probs >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print("=== Detector test ===")
    print(f"threshold={thr:.4f}")
    print(classification_report(y, pred, digits=4))
    print(f"Precision={precision_score(y, pred, zero_division=0):.4f} Recall={recall_score(y, pred, zero_division=0):.4f} F1={f1_score(y, pred, zero_division=0):.4f} FPR={fpr:.4f}")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")

    if args.hard_negatives.exists():
        hn = load_jsonl(args.hard_negatives)
        hp = predict([r["code"] for r in hn])
        hn_fp = int((hp >= thr).sum())
        print(f"\n=== Hard-negative FP === {hn_fp}/{len(hn)} ({hn_fp/len(hn):.2%})  (mục tiêu càng thấp càng tốt)")


if __name__ == "__main__":
    main()
