"""Simple local inference wrapper for fine-tuned LoRA (optional)."""

from __future__ import annotations

import argparse
from pathlib import Path


def generate(model_path: str, prompt: str, max_new_tokens: int = 256) -> str:
    try:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as e:
        raise SystemExit(f"Install torch/transformers/peft: {e}")

    path = Path(model_path)
    if not path.exists():
        return (
            "[model missing] Using heuristic stub response.\n"
            "CWE: CWE-89\nSeverity: critical\n"
            "Use parameterized queries instead of string concatenation."
        )

    tokenizer = AutoTokenizer.from_pretrained(model_path)
    base = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        device_map="auto" if torch.cuda.is_available() else None,
    )
    # If adapter-only dir, user should pass base+adapter; for simplicity assume merged/full
    inputs = tokenizer(prompt, return_tensors="pt")
    if torch.cuda.is_available():
        inputs = {k: v.cuda() for k, v in inputs.items()}
    out = base.generate(**inputs, max_new_tokens=max_new_tokens)
    return tokenizer.decode(out[0], skip_special_tokens=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="checkpoints/securecode-lora")
    p.add_argument("--prompt", required=True)
    args = p.parse_args()
    print(generate(args.model, args.prompt))


if __name__ == "__main__":
    main()
