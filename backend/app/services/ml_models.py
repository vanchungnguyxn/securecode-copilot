"""Local fine-tuned models: CodeBERT detector + CodeT5 explainer/fixer."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple

ROOT = Path(__file__).resolve().parents[3]  # repo root when used from backend/app/...
# backend/app/services/ml_models.py -> parents[0]=services, [1]=app, [2]=backend, [3]=repo
REPO_ROOT = Path(__file__).resolve().parents[3]
CKPT_ROOT = REPO_ROOT / "ml" / "inference" / "checkpoints"


class DetectorModel:
    def __init__(self, ckpt: Path, threshold: float = 0.5):
        self.ckpt = ckpt
        self.threshold = threshold
        self._model = None
        self._tok = None
        self.available = ckpt.exists()

    def _load(self):
        if self._model is not None:
            return
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._tok = AutoTokenizer.from_pretrained(str(self.ckpt))
        self._model = AutoModelForSequenceClassification.from_pretrained(str(self.ckpt))
        self._model.eval()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._model.to(self.device)
        self.torch = torch

    def predict(self, code: str) -> Tuple[float, bool]:
        """Returns (vuln_probability, is_vulnerable). Uses contextual windows up to 320 tokens."""
        if not self.available:
            return 0.0, False
        self._load()
        enc = self._tok(code, truncation=True, max_length=320, return_tensors="pt")
        enc = {k: v.to(self.device) for k, v in enc.items()}
        with self.torch.no_grad():
            logits = self._model(**enc).logits
            prob = float(self.torch.softmax(logits, dim=-1)[0, 1].item())
        return prob, prob >= self.threshold


class CodeT5Generator:
    def __init__(self, ckpt: Path):
        self.ckpt = ckpt
        self.available = ckpt.exists()
        self._model = None
        self._tok = None

    def _load(self):
        if self._model is not None:
            return
        import torch
        from peft import PeftModel
        from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

        extra = self.ckpt / "adapter_config_extra.json"
        base = "Salesforce/codet5-base"
        if extra.exists():
            base = json.loads(extra.read_text(encoding="utf-8")).get("base_model_name_or_path", base)
        self._tok = AutoTokenizer.from_pretrained(str(self.ckpt))
        model = AutoModelForSeq2SeqLM.from_pretrained(base)
        self._model = PeftModel.from_pretrained(model, str(self.ckpt))
        self._model.eval()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._model.to(self.device)
        self.torch = torch

    def generate(
        self,
        instruction: str,
        input_text: str,
        max_new_tokens: int = 256,
        num_beams: int = 4,
    ) -> str:
        if not self.available:
            return ""
        self._load()
        src = f"{instruction}\n{input_text}"
        enc = self._tok(src, return_tensors="pt", truncation=True, max_length=384)
        enc = {k: v.to(self.device) for k, v in enc.items()}
        with self.torch.no_grad():
            out = self._model.generate(
                **enc,
                max_new_tokens=max_new_tokens,
                num_beams=num_beams,
                do_sample=False,
                early_stopping=True,
                repetition_penalty=1.35,
                no_repeat_ngram_size=3,
            )
        text = self._tok.decode(out[0], skip_special_tokens=True).strip()
        # strip accidental markdown fences
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:])
            if text.endswith("```"):
                text = "\n".join(text.splitlines()[:-1])
        return text.strip()


def load_threshold() -> float:
    """ML discovery threshold — prefer precision-aware (anti_fp / hybrid), not max-recall balanced.

    Balanced thr (~0.7) on Devign-like data yields FPR ~0.89 — too noisy for product discovery.
    """
    path = CKPT_ROOT / "thresholds.json"
    if not path.exists():
        return 0.75
    data = json.loads(path.read_text(encoding="utf-8"))
    det = data.get("detector", {})
    thr = det.get("threshold", {})
    if isinstance(thr, dict):
        # Prefer anti_fp, then explicit hybrid thr, then top-level number fields
        for key in ("anti_fp", "hybrid", "production"):
            block = thr.get(key)
            if isinstance(block, dict) and "threshold" in block:
                return float(block["threshold"])
        if "threshold" in thr and not isinstance(thr["threshold"], dict):
            return float(thr["threshold"])
        bal = thr.get("balanced") or {}
        if isinstance(bal, dict) and "threshold" in bal:
            # Balanced only as last resort, floor at 0.75 to curb FPR
            return max(0.75, float(bal["threshold"]))
    return 0.75


def load_safe_cutoff() -> float:
    """Only suppress rule hits when ML vuln-prob is below this (confident SAFE).

    Higher cutoff → more aggressive FP suppression (may cost some recall).
    """
    path = CKPT_ROOT / "thresholds.json"
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        det = data.get("detector", {})
        if "safe_cutoff" in det:
            return float(det["safe_cutoff"])
        thr = det.get("threshold", {})
        if isinstance(thr, dict) and "safe_cutoff" in thr:
            return float(thr["safe_cutoff"])
        if isinstance(thr, dict) and "anti_fp" in thr:
            anti_t = float(thr["anti_fp"].get("threshold", 0.6))
            return max(0.35, min(0.55, anti_t * 0.55))
    return 0.45


@lru_cache(maxsize=1)
def get_detector() -> DetectorModel:
    # bust cache by including threshold file mtime in factory if present
    thr = CKPT_ROOT / "thresholds.json"
    _ = thr.stat().st_mtime if thr.exists() else 0
    return DetectorModel(CKPT_ROOT / "detector-codebert", threshold=load_threshold())


def clear_model_cache() -> None:
    get_detector.cache_clear()
    get_generator.cache_clear()


@lru_cache
def get_generator() -> CodeT5Generator:
    return CodeT5Generator(CKPT_ROOT / "codet5-lora")
