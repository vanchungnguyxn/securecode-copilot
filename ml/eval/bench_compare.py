"""
Benchmark table: Rule-only vs CodeBERT vs Hybrid on labeled sets.
Outputs JSON + Markdown for thesis.

Usage:
  python ml/eval/bench_compare.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.scanners.engine import RuleScanner  # noqa: E402
from app.services.repo_ingest import context_window  # noqa: E402


def load_jsonl(path: Path) -> List[Dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def prf(y_true, y_pred) -> Dict[str, float]:
    from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": fpr,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "support_pos": int((y_true == 1).sum()),
        "support_neg": int((y_true == 0).sum()),
    }


def rule_predict(scanner: RuleScanner, code: str, lang: str) -> int:
    _, findings = scanner.scan(code, lang or "auto")
    return 1 if findings else 0


def main():
    det_test = ROOT / "ml" / "datasets" / "processed" / "detector" / "test.jsonl"
    pairs = ROOT / "ml" / "datasets" / "processed" / "sft_pairs.jsonl"
    hn_path = ROOT / "ml" / "datasets" / "processed" / "hard_negatives.jsonl"
    ckpt = ROOT / "ml" / "inference" / "checkpoints" / "detector-codebert"
    thr_path = ROOT / "ml" / "inference" / "checkpoints" / "thresholds.json"

    scanner = RuleScanner()
    rows = load_jsonl(det_test) if det_test.exists() else []

    # Also build binary set from sft pairs + hard negatives for multilingual table
    multi = []
    if pairs.exists():
        for p in load_jsonl(pairs):
            multi.append({"code": p["vulnerable_code"], "label": 1, "language": p["language"], "id": p["id"] + "_v"})
            multi.append({"code": p["secure_code"], "label": 0, "language": p["language"], "id": p["id"] + "_s"})
    if hn_path.exists():
        for h in load_jsonl(hn_path):
            multi.append({"code": h["code"], "label": 0, "language": h["language"], "id": h["id"]})

    # Load ML
    ml_ok = ckpt.exists()
    model = tok = device = None
    thr = 0.82
    safe_cutoff = 0.45
    thr_anti = 0.85
    if thr_path.exists():
        conf = json.loads(thr_path.read_text(encoding="utf-8")).get("detector", {})
        safe_cutoff = float(conf.get("safe_cutoff", 0.45))
        t = conf.get("threshold", {})
        if isinstance(t, dict):
            if "anti_fp" in t:
                thr_anti = float(t["anti_fp"]["threshold"])
                thr = thr_anti  # product default: low FPR
            elif "hybrid" in t:
                thr = float(t["hybrid"]["threshold"])
            elif "balanced" in t:
                thr = max(0.75, float(t["balanced"]["threshold"]))
        prod = conf.get("product") or {}
        if "ml_discovery_threshold" in prod:
            thr = float(prod["ml_discovery_threshold"])
        if "safe_cutoff" in prod:
            safe_cutoff = float(prod["safe_cutoff"])

    if ml_ok:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        tok = AutoTokenizer.from_pretrained(str(ckpt))
        model = AutoModelForSequenceClassification.from_pretrained(str(ckpt))
        model.eval()
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)

    def ml_prob(code: str) -> float:
        if not ml_ok:
            return 0.0
        import torch

        enc = tok(code, truncation=True, max_length=320, return_tensors="pt")
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.no_grad():
            return float(torch.softmax(model(**enc).logits, dim=-1)[0, 1].item())

    def eval_split(name: str, data: List[Dict]) -> Dict:
        y = [int(r["label"]) for r in data]
        y_rule = [rule_predict(scanner, r["code"], r.get("language", "auto")) for r in data]
        probs = [ml_prob(r["code"]) for r in data] if ml_ok else [0.0] * len(data)
        y_ml = [1 if p >= thr else 0 for p in probs]
        # Hybrid-recall (legacy): rule OR ml@thr, suppress rule if p < safe_cutoff
        y_hyb_r = []
        for p, yr in zip(probs, y_rule):
            if yr == 1 and p < safe_cutoff:
                y_hyb_r.append(0)
            elif yr == 1 or p >= thr:
                y_hyb_r.append(1)
            else:
                y_hyb_r.append(0)
        # Hybrid-precision (product): rules + ML suppress only; ML alone needs anti_fp thr
        y_hyb_p = []
        for p, yr in zip(probs, y_rule):
            if yr == 1 and p < safe_cutoff:
                y_hyb_p.append(0)
            elif yr == 1:
                y_hyb_p.append(1)
            elif p >= thr_anti:
                y_hyb_p.append(1)
            else:
                y_hyb_p.append(0)
        return {
            "dataset": name,
            "n": len(data),
            "rule_only": prf(y, y_rule),
            "ml_only": prf(y, y_ml) if ml_ok else None,
            "hybrid": prf(y, y_hyb_p),  # product default (lower FPR)
            "hybrid_recall": prf(y, y_hyb_r),
            "ml_threshold": thr,
            "ml_threshold_anti_fp": thr_anti,
            "safe_cutoff": safe_cutoff,
        }

    report = {
        "detector_test": eval_split("detector_test_devign_mix", rows) if rows else None,
        "multilingual_pairs": eval_split("sft_pairs_plus_hardneg", multi) if multi else None,
    }

    # SFT fix/explain smoke metrics if generator exists
    codet5 = ROOT / "ml" / "inference" / "checkpoints" / "codet5-lora"
    sft_eval = {"available": codet5.exists(), "fix_exact_match": None, "n": 0}
    if codet5.exists() and pairs.exists():
        try:
            import torch
            from peft import PeftModel
            from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

            extra = codet5 / "adapter_config_extra.json"
            base = "Salesforce/codet5-base"
            if extra.exists():
                base = json.loads(extra.read_text(encoding="utf-8")).get("base_model_name_or_path", base)
            gtok = AutoTokenizer.from_pretrained(str(codet5))
            gmodel = AutoModelForSeq2SeqLM.from_pretrained(base)
            gmodel = PeftModel.from_pretrained(gmodel, str(codet5))
            gmodel.eval()
            gdev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            gmodel.to(gdev)
            sample = [p for p in load_jsonl(pairs) if p.get("vulnerable_code") and p.get("secure_code")][:60]
            em = 0
            tok_hit = 0
            for p in sample:
                src = (
                    "fix: Rewrite the vulnerable code into a secure version. "
                    "Return only the fixed code, no markdown, no explanation.\n"
                    f"Language: {p['language']}\nCWE: {p['cwe']}\nVulnerable code:\n{p['vulnerable_code']}"
                )
                enc = gtok(src, return_tensors="pt", truncation=True, max_length=384).to(gdev)
                with torch.no_grad():
                    out = gmodel.generate(
                        **enc,
                        max_new_tokens=192,
                        num_beams=4,
                        do_sample=False,
                        early_stopping=True,
                    )
                pred = gtok.decode(out[0], skip_special_tokens=True).strip()
                if pred.startswith("```"):
                    pred = "\n".join(pred.splitlines()[1:])
                    if pred.endswith("```"):
                        pred = "\n".join(pred.splitlines()[:-1])
                gold = p["secure_code"].strip()
                pn = "".join(pred.split()).lower()
                gn = "".join(gold.split()).lower()
                soft = False
                if pn and (pn == gn or gn[:48] in pn or pn[:48] in gn):
                    soft = True
                else:
                    # token overlap of significant fragments
                    gtoks = {t for t in gold.replace("(", " ").replace(")", " ").split() if len(t) > 3}
                    ptoks = set(pred.replace("(", " ").replace(")", " ").split())
                    if gtoks and len(gtoks & ptoks) / len(gtoks) >= 0.45:
                        soft = True
                        tok_hit += 1
                if soft:
                    em += 1
            sft_eval = {
                "available": True,
                "fix_soft_match": em / max(1, len(sample)),
                "fix_token_overlap_hits": tok_hit,
                "n": len(sample),
            }
        except Exception as e:
            sft_eval = {"available": True, "error": str(e)}

    report["codet5_fix"] = sft_eval

    out_dir = ROOT / "ml" / "eval" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "bench_compare.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Markdown table
    def row(title, m):
        if not m:
            return f"| {title} | - | - | - | - |"
        return (
            f"| {title} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} |"
        )

    md = ["# SecureCode Copilot — Benchmark (Rule vs ML vs Hybrid)", ""]
    for key in ("detector_test", "multilingual_pairs"):
        block = report.get(key)
        if not block:
            continue
        md.append(f"## {block['dataset']} (n={block['n']})")
        md.append("")
        md.append("| Method | Precision | Recall | F1 | FPR |")
        md.append("|--------|-----------|--------|----|-----|")
        md.append(row("Rule-only", block["rule_only"]))
        md.append(row("ML-only (CodeBERT)", block["ml_only"]))
        md.append(row("Hybrid product (low-FPR)", block["hybrid"]))
        if block.get("hybrid_recall"):
            md.append(row("Hybrid recall (legacy)", block["hybrid_recall"]))
        md.append("")
        md.append(f"- ML threshold (anti_fp/product): `{block['ml_threshold']:.4f}`")
        if "ml_threshold_anti_fp" in block:
            md.append(f"- ML anti_fp thr: `{block['ml_threshold_anti_fp']:.4f}`")
        md.append(f"- safe_cutoff (suppress rule FP): `{block['safe_cutoff']:.4f}`")
        md.append("")
    md.append("## CodeT5 fix soft-match")
    md.append(f"```json\n{json.dumps(sft_eval, indent=2)}\n```")
    md.append("")
    md.append("Interpretation for thesis:")
    md.append("- **Hybrid product**: rules + ML FP suppression; ML-alone only at anti_fp thr => lower FPR.")
    md.append("- **Hybrid recall (legacy)**: higher recall/FPR — analysis only, not product default.")
    md.append("- Report anti_fp / balanced thresholds separately.")
    (out_dir / "bench_compare.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md).encode("ascii", "replace").decode("ascii"))
    print(f"\n[done] {out_dir / 'bench_compare.md'}")


if __name__ == "__main__":
    main()
