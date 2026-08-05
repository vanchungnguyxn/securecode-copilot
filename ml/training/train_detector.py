"""Weighted CodeBERT trainer + recall-aware threshold selection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import numpy as np


def load_jsonl(path: Path) -> List[Dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def pick_threshold(
    y_true,
    probs,
    min_precision: float = 0.65,
    target_recall: float = 0.55,
) -> Dict:
    """Prefer usable recall while keeping precision floor. Also report anti_fp / balanced."""
    from sklearn.metrics import (
        confusion_matrix,
        f1_score,
        precision_recall_curve,
        precision_score,
        recall_score,
    )

    precisions, recalls, thresholds = precision_recall_curve(y_true, probs)

    def metrics_at(t: float) -> Dict:
        pred = (probs >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
        return {
            "threshold": float(t),
            "precision": float(precision_score(y_true, pred, zero_division=0)),
            "recall": float(recall_score(y_true, pred, zero_division=0)),
            "f1": float(f1_score(y_true, pred, zero_division=0)),
            "fpr": fpr,
        }

    # anti-FP: max F1 at P >= min_precision+0.1 (stricter)
    anti_cands = []
    for p, r, t in zip(precisions[:-1], recalls[:-1], thresholds):
        if p >= min(0.9, min_precision + 0.15):
            f1 = 0.0 if (p + r) == 0 else 2 * p * r / (p + r)
            anti_cands.append((f1, float(t)))
    if anti_cands:
        anti_cands.sort(reverse=True)
        anti = metrics_at(anti_cands[0][1])
        anti["strategy"] = f"max_f1_at_P>={min(0.9, min_precision + 0.15):.2f}"
    else:
        anti = metrics_at(0.7)
        anti["strategy"] = "fallback_0.7_anti"

    # balanced: max F1
    best_f1, best_t = -1.0, 0.5
    for t in thresholds:
        f1 = f1_score(y_true, (probs >= t).astype(int), zero_division=0)
        if f1 > best_f1:
            best_f1, best_t = f1, float(t)
    balanced = metrics_at(best_t)
    balanced["strategy"] = "max_f1"

    # production/hybrid: among P>=min_precision, maximize recall; prefer R>=target_recall
    hy = []
    for p, r, t in zip(precisions[:-1], recalls[:-1], thresholds):
        if p >= min_precision:
            # score heavily weights recall once precision floor met
            score = float(r) * 2.0 + float(p) + (0.5 if r >= target_recall else 0.0)
            hy.append((score, float(r), float(t), float(p)))
    if hy:
        hy.sort(reverse=True)
        _, r, t, p = hy[0]
        hybrid = metrics_at(t)
        hybrid["strategy"] = f"max_recall_at_P>={min_precision:.2f}_targetR>={target_recall:.2f}"
    else:
        hybrid = balanced
        hybrid["strategy"] = "max_f1_as_hybrid_fallback"

    # safe_cutoff: below this → confident SAFE (for suppressing rule FPs)
    # Prefer higher cutoff when hybrid thr is high (lower product FPR).
    safe_cutoff = float(max(0.30, min(0.55, hybrid["threshold"] * 0.60)))

    out = dict(hybrid)
    out["anti_fp"] = anti
    out["balanced"] = balanced
    out["hybrid"] = hybrid
    out["safe_cutoff"] = safe_cutoff
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--base-model", default="microsoft/codebert-base")
    ap.add_argument("--output", type=Path, default=Path("ml/inference/checkpoints/detector-codebert"))
    ap.add_argument("--epochs", type=int, default=5)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max-length", type=int, default=320)
    ap.add_argument("--min-precision", type=float, default=0.65)
    ap.add_argument("--target-recall", type=float, default=0.55)
    ap.add_argument("--vuln-weight", type=float, default=2.0, help="Class weight for label=1 to boost recall")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    import torch
    import torch.nn as nn
    from datasets import Dataset
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        DataCollatorWithPadding,
        Trainer,
        TrainingArguments,
        set_seed,
    )

    set_seed(args.seed)
    device_info = {
        "cuda": torch.cuda.is_available(),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "vram_gb": round(torch.cuda.get_device_properties(0).total_memory / 1024**3, 2)
        if torch.cuda.is_available()
        else 0,
    }
    print("[hardware]", device_info)

    train_rows = load_jsonl(args.data / "train.jsonl")
    valid_rows = load_jsonl(args.data / "valid.jsonl")
    test_rows = load_jsonl(args.data / "test.jsonl")
    if not train_rows:
        raise SystemExit(f"No train data in {args.data}")

    # Oversample vulnerable rows once to help recall
    vulns = [r for r in train_rows if int(r["label"]) == 1]
    train_rows = train_rows + vulns
    print(f"[data] train={len(train_rows)} (after vuln oversample) valid={len(valid_rows)} test={len(test_rows)}")

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)

    def tok(batch):
        enc = tokenizer(batch["code"], truncation=True, max_length=args.max_length)
        enc["labels"] = batch["label"]
        return enc

    train_ds = Dataset.from_list(train_rows).map(tok, batched=True, remove_columns=list(train_rows[0].keys()))
    valid_ds = (
        Dataset.from_list(valid_rows).map(tok, batched=True, remove_columns=list(valid_rows[0].keys()))
        if valid_rows
        else None
    )

    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, num_labels=2)
    args.output.mkdir(parents=True, exist_ok=True)

    class_weights = torch.tensor([1.0, float(args.vuln_weight)])

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            logits = outputs.logits
            weight = class_weights.to(logits.device)
            loss_fct = nn.CrossEntropyLoss(weight=weight)
            loss = loss_fct(logits.view(-1, 2), labels.view(-1))
            return (loss, outputs) if return_outputs else loss

    use_fp16 = torch.cuda.is_available()
    ta_kwargs = dict(
        output_dir=str(args.output / "runs"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        save_strategy="epoch",
        fp16=use_fp16,
        logging_steps=20,
        report_to=[],
        dataloader_num_workers=0,
        seed=args.seed,
        greater_is_better=True,
    )
    if valid_ds:
        ta_kwargs["evaluation_strategy"] = "epoch"
        ta_kwargs["load_best_model_at_end"] = True
        ta_kwargs["metric_for_best_model"] = "f1"
    targs = TrainingArguments(**ta_kwargs)

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        return {
            "accuracy": accuracy_score(labels, preds),
            "precision": precision_score(labels, preds, zero_division=0),
            "recall": recall_score(labels, preds, zero_division=0),
            "f1": f1_score(labels, preds, zero_division=0),
        }

    trainer = WeightedTrainer(
        model=model,
        args=targs,
        train_dataset=train_ds,
        eval_dataset=valid_ds,
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics if valid_ds else None,
    )
    trainer.train()
    trainer.save_model(str(args.output))
    tokenizer.save_pretrained(str(args.output))

    tune_rows = valid_rows or test_rows
    model.eval()
    device = next(model.parameters()).device
    texts = [r["code"] for r in tune_rows]
    y_true = np.array([r["label"] for r in tune_rows])
    probs = []
    with torch.no_grad():
        for i in range(0, len(texts), args.batch_size):
            batch = texts[i : i + args.batch_size]
            enc = tokenizer(
                batch, truncation=True, max_length=args.max_length, padding=True, return_tensors="pt"
            )
            enc = {k: v.to(device) for k, v in enc.items()}
            logits = model(**enc).logits
            p = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
            probs.extend(p.tolist())
    probs = np.array(probs)
    thr = pick_threshold(y_true, probs, min_precision=args.min_precision, target_recall=args.target_recall)

    test_metrics = {}
    if test_rows:
        test_texts = [r["code"] for r in test_rows]
        y_test = np.array([r["label"] for r in test_rows])
        test_probs = []
        with torch.no_grad():
            for i in range(0, len(test_texts), args.batch_size):
                batch = test_texts[i : i + args.batch_size]
                enc = tokenizer(
                    batch, truncation=True, max_length=args.max_length, padding=True, return_tensors="pt"
                )
                enc = {k: v.to(device) for k, v in enc.items()}
                logits = model(**enc).logits
                p = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
                test_probs.extend(p.tolist())
        test_probs = np.array(test_probs)
        pred = (test_probs >= thr["threshold"]).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
        test_metrics = {
            "accuracy": float(accuracy_score(y_test, pred)),
            "precision": float(precision_score(y_test, pred, zero_division=0)),
            "recall": float(recall_score(y_test, pred, zero_division=0)),
            "f1": float(f1_score(y_test, pred, zero_division=0)),
            "fpr": float(fp / (fp + tn) if (fp + tn) else 0.0),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
        }

    report = {
        "base_model": args.base_model,
        "hardware": device_info,
        "threshold": thr,
        "safe_cutoff": thr.get("safe_cutoff", 0.30),
        "test_metrics": test_metrics,
        "train_size": len(train_rows),
        "valid_size": len(valid_rows),
        "test_size": len(test_rows),
        "vuln_weight": args.vuln_weight,
        "min_precision": args.min_precision,
        "target_recall": args.target_recall,
    }
    thr_path = args.output.parent / "thresholds.json"
    existing = {}
    if thr_path.exists():
        existing = json.loads(thr_path.read_text(encoding="utf-8"))
    thr_obj = report.get("threshold") or {}
    anti = thr_obj.get("anti_fp") if isinstance(thr_obj, dict) else None
    ml_disc = float((anti or {}).get("threshold") or thr_obj.get("threshold") or 0.8)
    sc = float(report.get("safe_cutoff", 0.45))
    report["product"] = {
        "note": "Use anti_fp thr for ML discovery; safe_cutoff for rule FP suppression; discovery off by default",
        "ml_discovery_threshold": ml_disc,
        "safe_cutoff": max(sc, 0.45),
        "use_ml_discovery_default": False,
    }
    report["safe_cutoff"] = report["product"]["safe_cutoff"]
    existing["detector"] = report
    thr_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    (args.output / "train_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"[done] saved detector -> {args.output}")


if __name__ == "__main__":
    main()
