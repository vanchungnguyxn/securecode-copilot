"""
Per-language detection benchmark (Rule / CodeBERT / Hybrid).

Unlike the aggregate `sft_pairs_plus_hardneg` smoke block in bench_compare.py, this script:

1. Reports **one table per language** (Precision / Recall / F1 / FPR).
2. Separates data **tiers** so thesis claims are not confused with training-family smoke:
   - `detector_test` — held-out detector split (mostly C/Devign-heavy; show honestly)
   - `cvefixes_pairs` — external patch pairs as binary labels (stronger multi-lang signal)
   - `sft_hardneg_smoke` — project SFT + hard negatives (smoke only)

TypeScript: reported as N/A if no labeled samples (rules may still scan TS as JS).

Usage:
  .\\.venv-ml\\Scripts\\python.exe ml\\eval\\bench_multilingual.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.scanners.engine import RuleScanner  # noqa: E402

LANG_ORDER = [
    "python",
    "javascript",
    "typescript",
    "java",
    "c",
    "cpp",
    "csharp",
    "php",
]

LANG_ALIASES = {
    "py": "python",
    "js": "javascript",
    "ts": "typescript",
    "c++": "cpp",
    "c#": "csharp",
    "cs": "csharp",
}


def norm_lang(x: Optional[str]) -> str:
    s = (x or "unknown").strip().lower()
    return LANG_ALIASES.get(s, s)


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def prf(y_true, y_pred) -> Dict[str, float]:
    from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    if len(y_true) == 0:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "fpr": 0.0,
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
            "support_pos": 0,
            "support_neg": 0,
            "n": 0,
        }
    labels_present = sorted(set(y_true.tolist()) | set(y_pred.tolist()) | {0, 1})
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
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
        "n": int(len(y_true)),
    }


def build_tiers() -> Dict[str, List[Dict[str, Any]]]:
    proc = ROOT / "ml" / "datasets" / "processed"
    tiers: Dict[str, List[Dict[str, Any]]] = {
        "detector_test": [],
        "cvefixes_pairs": [],
        "sft_hardneg_smoke": [],
    }

    for r in load_jsonl(proc / "detector" / "test.jsonl"):
        code = r.get("code") or r.get("func") or ""
        if not code.strip():
            continue
        tiers["detector_test"].append(
            {
                "id": r.get("id") or "",
                "code": code,
                "label": int(r["label"]),
                "language": norm_lang(r.get("language")),
                "source": "detector_test",
            }
        )

    for p in load_jsonl(proc / "cvefixes_pairs.jsonl"):
        vul = (p.get("vulnerable_code") or "").strip()
        sec = (p.get("secure_code") or "").strip()
        lang = norm_lang(p.get("language"))
        pid = p.get("id") or p.get("cve_id") or ""
        if vul:
            tiers["cvefixes_pairs"].append(
                {
                    "id": f"{pid}_v",
                    "code": vul,
                    "label": 1,
                    "language": lang,
                    "source": "cvefixes",
                }
            )
        if sec:
            tiers["cvefixes_pairs"].append(
                {
                    "id": f"{pid}_s",
                    "code": sec,
                    "label": 0,
                    "language": lang,
                    "source": "cvefixes",
                }
            )

    for p in load_jsonl(proc / "sft_pairs.jsonl"):
        lang = norm_lang(p.get("language"))
        pid = p.get("id") or ""
        if p.get("vulnerable_code"):
            tiers["sft_hardneg_smoke"].append(
                {
                    "id": f"{pid}_v",
                    "code": p["vulnerable_code"],
                    "label": 1,
                    "language": lang,
                    "source": "sft_pairs",
                }
            )
        if p.get("secure_code"):
            tiers["sft_hardneg_smoke"].append(
                {
                    "id": f"{pid}_s",
                    "code": p["secure_code"],
                    "label": 0,
                    "language": lang,
                    "source": "sft_pairs",
                }
            )
    for h in load_jsonl(proc / "hard_negatives.jsonl"):
        tiers["sft_hardneg_smoke"].append(
            {
                "id": h.get("id") or "",
                "code": h.get("code") or "",
                "label": 0,
                "language": norm_lang(h.get("language")),
                "source": "hard_negatives",
            }
        )

    return tiers


def load_ml(ckpt: Path, thr_path: Path):
    thr = 0.85
    thr_anti = 0.85
    safe_cutoff = 0.45
    if thr_path.exists():
        conf = json.loads(thr_path.read_text(encoding="utf-8")).get("detector", {})
        safe_cutoff = float(conf.get("safe_cutoff", safe_cutoff))
        t = conf.get("threshold", {})
        if isinstance(t, dict):
            if "anti_fp" in t:
                thr_anti = float(t["anti_fp"]["threshold"])
                thr = thr_anti
            elif "hybrid" in t:
                thr = float(t["hybrid"]["threshold"])
        prod = conf.get("product") or {}
        if "ml_discovery_threshold" in prod:
            thr = float(prod["ml_discovery_threshold"])
        if "safe_cutoff" in prod:
            safe_cutoff = float(prod["safe_cutoff"])

    if not ckpt.exists():
        return None, thr, thr_anti, safe_cutoff

    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(str(ckpt))
    model = AutoModelForSequenceClassification.from_pretrained(str(ckpt))
    model.eval()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    def ml_prob(code: str) -> float:
        enc = tok(code, truncation=True, max_length=320, return_tensors="pt")
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.no_grad():
            return float(torch.softmax(model(**enc).logits, dim=-1)[0, 1].item())

    return ml_prob, thr, thr_anti, safe_cutoff


def predict_all(
    data: List[Dict[str, Any]],
    scanner: RuleScanner,
    ml_prob,
    thr: float,
    thr_anti: float,
    safe_cutoff: float,
) -> Dict[str, List[int]]:
    y = [int(r["label"]) for r in data]
    y_rule = []
    probs = []
    for r in data:
        _, findings = scanner.scan(r["code"], r.get("language") or "auto")
        y_rule.append(1 if findings else 0)
        probs.append(float(ml_prob(r["code"])) if ml_prob else 0.0)

    y_ml = [1 if p >= thr else 0 for p in probs]
    y_hyb = []
    for p, yr in zip(probs, y_rule):
        if yr == 1 and p < safe_cutoff:
            y_hyb.append(0)
        elif yr == 1:
            y_hyb.append(1)
        elif p >= thr_anti:
            y_hyb.append(1)
        else:
            y_hyb.append(0)
    return {"y": y, "rule": y_rule, "ml": y_ml, "hybrid": y_hyb}


def eval_by_language(
    data: List[Dict[str, Any]],
    scanner: RuleScanner,
    ml_prob,
    thr: float,
    thr_anti: float,
    safe_cutoff: float,
) -> Dict[str, Any]:
    # group indices by language
    by_lang: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in data:
        by_lang[norm_lang(r.get("language"))].append(r)

    per_lang: Dict[str, Any] = {}
    for lang in LANG_ORDER:
        subset = by_lang.get(lang, [])
        if not subset:
            per_lang[lang] = {
                "n": 0,
                "support_pos": 0,
                "support_neg": 0,
                "rule_only": None,
                "ml_only": None,
                "hybrid": None,
                "status": "no_labeled_samples",
            }
            continue
        pred = predict_all(subset, scanner, ml_prob, thr, thr_anti, safe_cutoff)
        rule_m = prf(pred["y"], pred["rule"])
        ml_m = prf(pred["y"], pred["ml"]) if ml_prob else None
        hyb_m = prf(pred["y"], pred["hybrid"])
        per_lang[lang] = {
            "n": len(subset),
            "support_pos": rule_m["support_pos"],
            "support_neg": rule_m["support_neg"],
            "rule_only": rule_m,
            "ml_only": ml_m,
            "hybrid": hyb_m,
            "status": "ok" if rule_m["support_pos"] > 0 and rule_m["support_neg"] > 0 else "degenerate_labels",
        }

    # also capture unexpected langs
    extras = {k: v for k, v in by_lang.items() if k not in LANG_ORDER}
    return {
        "per_language": per_lang,
        "extra_languages": {k: len(v) for k, v in extras.items()},
        "n_total": len(data),
    }


def fmt_row(lang: str, n: int, m: Optional[Dict[str, float]]) -> str:
    if not m or n == 0:
        return f"| {lang} | {n} | — | — | — | — |"
    return (
        f"| {lang} | {n} | {m['precision']:.3f} | {m['recall']:.3f} | "
        f"{m['f1']:.3f} | {m['fpr']:.3f} |"
    )


def to_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Multilingual Detection Benchmark (per language)",
        "",
        "Fine-tuned CodeBERT + RuleScanner evaluated **separately for each language**.",
        "",
        "### How to read this",
        "",
        "- **Rule-only** proves multi-language *scanner coverage*.",
        "- **ML-only / Hybrid** show whether the **fine-tuned detector** generalizes per language.",
        "- Prefer **`cvefixes_pairs`** over **`sft_hardneg_smoke`** for generalization claims.",
        "- `detector_test` is held-out but **C-heavy** (Devign) — weak for JS/Java claims alone.",
        "- **TypeScript** has no dedicated labeled set here (engine may treat as JS).",
        "",
        f"- ML discovery thr: `{report['thresholds']['thr']:.4f}`",
        f"- ML anti_fp thr: `{report['thresholds']['thr_anti']:.4f}`",
        f"- safe_cutoff: `{report['thresholds']['safe_cutoff']:.4f}`",
        "",
    ]

    tier_notes = {
        "cvefixes_pairs": "External CVEFixes vuln/secure pairs (stronger multi-lang evidence).",
        "detector_test": "Held-out detector split — language balance skewed toward C.",
        "sft_hardneg_smoke": "Project SFT + hard negatives — smoke only, overlaps training family.",
    }

    for tier, note in tier_notes.items():
        block = report["tiers"].get(tier)
        if not block:
            continue
        lines += [
            f"## Tier: `{tier}` (n={block['n_total']})",
            "",
            note,
            "",
        ]
        for method, key in (
            ("Rule-only", "rule_only"),
            ("ML-only (CodeBERT)", "ml_only"),
            ("Hybrid product", "hybrid"),
        ):
            lines += [
                f"### {method}",
                "",
                "| Language | Samples | Precision | Recall | F1 | FPR |",
                "|----------|---------|-----------|--------|----|-----|",
            ]
            for lang in LANG_ORDER:
                info = block["per_language"].get(lang, {})
                n = int(info.get("n") or 0)
                m = info.get(key)
                lines.append(fmt_row(lang, n, m))
            lines.append("")

        # Mini summary: languages where hybrid F1 >= 0.5 and n>=20
        strong = []
        weak = []
        missing = []
        for lang in LANG_ORDER:
            info = block["per_language"].get(lang, {})
            n = int(info.get("n") or 0)
            hyb = info.get("hybrid")
            if n == 0:
                missing.append(lang)
            elif hyb and n >= 20 and hyb["f1"] >= 0.5:
                strong.append(f"{lang} (F1={hyb['f1']:.2f}, n={n})")
            elif n > 0:
                weak.append(f"{lang} (F1={hyb['f1'] if hyb else 0:.2f}, n={n})")
        lines += [
            "**Hybrid snapshot**",
            "",
            f"- Stronger (n≥20 & F1≥0.5): {', '.join(strong) or '—'}",
            f"- Weaker / small-n: {', '.join(weak) or '—'}",
            f"- No labeled samples: {', '.join(missing) or '—'}",
            "",
        ]

    lines += [
        "## Claim guidance for thesis",
        "",
        "| Claim | Supported by |",
        "|-------|--------------|",
        "| Multi-language **rule detection** | Non-empty Rule-only rows with real P/R |",
        "| Multi-language **fine-tuned detector** | ML/Hybrid on `cvefixes_pairs` / balanced detector splits |",
        "| Multi-language **fix generation** | Held-out fix eval (`FIX_EVAL.md`), not this table |",
        "",
        "Do **not** cite only `sft_hardneg_smoke` as proof of multilingual generalization.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ckpt = ROOT / "ml" / "inference" / "checkpoints" / "detector-codebert"
    thr_path = ROOT / "ml" / "inference" / "checkpoints" / "thresholds.json"
    scanner = RuleScanner()
    ml_prob, thr, thr_anti, safe_cutoff = load_ml(ckpt, thr_path)

    tiers_raw = build_tiers()
    report: Dict[str, Any] = {
        "thresholds": {"thr": thr, "thr_anti": thr_anti, "safe_cutoff": safe_cutoff},
        "ml_available": ml_prob is not None,
        "tiers": {},
    }

    for name, data in tiers_raw.items():
        print(f"[eval] {name} n={len(data)}")
        report["tiers"][name] = eval_by_language(
            data, scanner, ml_prob, thr, thr_anti, safe_cutoff
        )

    out_dir = ROOT / "ml" / "eval" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "bench_multilingual.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    md = to_markdown(report)
    (out_dir / "bench_multilingual.md").write_text(md, encoding="utf-8")
    print(md.encode("ascii", "replace").decode("ascii"))
    print(f"\n[done] {out_dir / 'bench_multilingual.md'}")


if __name__ == "__main__":
    main()
