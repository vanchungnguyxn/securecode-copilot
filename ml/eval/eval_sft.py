"""Smoke-eval CodeT5 LoRA on a few SFT fix/explain samples."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", type=Path, default=Path("ml/inference/checkpoints/codet5-lora"))
    ap.add_argument("--data", type=Path, default=Path("ml/datasets/processed/sft.jsonl"))
    ap.add_argument("--n", type=int, default=5)
    args = ap.parse_args()

    if not args.ckpt.exists():
        raise SystemExit(f"Missing {args.ckpt}")

    import torch
    from peft import PeftModel
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

    extra = args.ckpt / "adapter_config_extra.json"
    base = "Salesforce/codet5-base"
    if extra.exists():
        base = json.loads(extra.read_text(encoding="utf-8")).get("base_model_name_or_path", base)

    tok = AutoTokenizer.from_pretrained(args.ckpt)
    model = AutoModelForSeq2SeqLM.from_pretrained(base)
    model = PeftModel.from_pretrained(model, str(args.ckpt))
    model.eval()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    rows = [json.loads(l) for l in args.data.read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = [r for r in rows if r.get("task") in ("fix", "explain")][: args.n]

    for r in rows:
        src = f"{r['instruction']}\n{r['input']}"
        enc = tok(src, return_tensors="pt", truncation=True, max_length=320).to(device)
        with torch.no_grad():
            out = model.generate(**enc, max_new_tokens=160)
        pred = tok.decode(out[0], skip_special_tokens=True)
        print("=" * 60)
        print("TASK:", r["task"])
        print("GOLD:", r["output"][:200])
        print("PRED:", pred[:200])


if __name__ == "__main__":
    main()
