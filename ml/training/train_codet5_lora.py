"""
Fine-tune CodeT5-base with LoRA for explain + fix (seq2seq).

Sized for RTX 3050 4GB (fp16 + LoRA, batch=1, grad accum).

Usage:
  python ml/training/train_codet5_lora.py --data ml/datasets/processed/sft.jsonl --epochs 3
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List


def load_jsonl(path: Path) -> List[Dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def to_text_pair(row: Dict) -> Dict[str, str]:
    src = f"{row['instruction']}\n{row['input']}"
    tgt = row["output"]
    return {"source": src, "target": tgt}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--base-model", default="Salesforce/codet5-base")
    ap.add_argument("--output", type=Path, default=Path("ml/inference/checkpoints/codet5-lora"))
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-source-length", type=int, default=384)
    ap.add_argument("--max-target-length", type=int, default=256)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--tasks", default="fix,explain", help="Comma list or 'all'")
    ap.add_argument("--fix-repeat", type=int, default=1, help="Extra oversample of fix rows")
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    args = ap.parse_args()

    import torch
    from datasets import Dataset
    from peft import LoraConfig, TaskType, get_peft_model
    from transformers import (
        AutoModelForSeq2SeqLM,
        AutoTokenizer,
        DataCollatorForSeq2Seq,
        Seq2SeqTrainer,
        Seq2SeqTrainingArguments,
        set_seed,
    )

    set_seed(args.seed)
    print("[hardware] cuda=", torch.cuda.is_available(), end="")
    if torch.cuda.is_available():
        print(" gpu=", torch.cuda.get_device_name(0), "vram_gb=", round(torch.cuda.get_device_properties(0).total_memory / 1024**3, 2))
    else:
        print(" (CPU — sẽ chậm)")

    rows = load_jsonl(args.data)
    # Prefer fix-heavy training when mixed SFT
    if args.tasks != "all":
        wanted = {t.strip() for t in args.tasks.split(",") if t.strip()}
        rows = [r for r in rows if r.get("task") in wanted]
    if args.fix_repeat > 1:
        extra = []
        for r in rows:
            if r.get("task") == "fix":
                for _ in range(args.fix_repeat - 1):
                    extra.append(r)
        rows = rows + extra
    rows = [to_text_pair(r) for r in rows]
    if not rows:
        raise SystemExit("empty SFT data after filters")
    print(f"[data] text pairs={len(rows)}")

    # Prefer explain+fix; keep some detect
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=False)
    model = AutoModelForSeq2SeqLM.from_pretrained(args.base_model)

    lora = LoraConfig(
        task_type=TaskType.SEQ_2_SEQ_LM,
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        target_modules=["q", "v"],
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    def preprocess(batch):
        model_inputs = tokenizer(
            batch["source"],
            max_length=args.max_source_length,
            truncation=True,
        )
        labels = tokenizer(
            text_target=batch["target"],
            max_length=args.max_target_length,
            truncation=True,
        )
        model_inputs["labels"] = labels["input_ids"]
        return model_inputs

    ds = Dataset.from_list(rows).map(preprocess, batched=True, remove_columns=["source", "target"])
    # small holdout
    split = ds.train_test_split(test_size=0.1, seed=args.seed)
    train_ds, eval_ds = split["train"], split["test"]

    args.output.mkdir(parents=True, exist_ok=True)
    targs = Seq2SeqTrainingArguments(
        output_dir=str(args.output / "runs"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        fp16=torch.cuda.is_available(),
        evaluation_strategy="epoch",
        save_strategy="epoch",
        predict_with_generate=True,
        logging_steps=5,
        report_to=[],
        seed=args.seed,
        dataloader_num_workers=0,
    )

    trainer = Seq2SeqTrainer(
        model=model,
        args=targs,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        tokenizer=tokenizer,
        data_collator=DataCollatorForSeq2Seq(tokenizer, model=model),
    )
    trainer.train()
    model.save_pretrained(str(args.output))
    tokenizer.save_pretrained(str(args.output))

    # save base model name for loading
    (args.output / "adapter_config_extra.json").write_text(
        json.dumps({"base_model_name_or_path": args.base_model}, indent=2),
        encoding="utf-8",
    )
    print(f"[done] saved CodeT5 LoRA -> {args.output}")


if __name__ == "__main__":
    main()
