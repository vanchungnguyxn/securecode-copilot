"""Compare SecureCode Copilot vs Bandit (and Semgrep if installed) on labeled Python samples.

Outputs:
  ml/eval/reports/baseline_compare.json
  ml/eval/reports/baseline_compare.md
  ml/eval/reports/figures/10_baseline_vs_bandit.png
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.scanners.engine import RuleScanner  # noqa: E402


def load_jsonl(path: Path) -> List[Dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def prf(y_true, y_pred) -> Dict[str, float]:
    from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
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
        "n": int(len(y_true)),
    }


def bandit_predict(codes: List[str]) -> List[int]:
    if shutil.which("bandit") is None and shutil.which("bandit.exe") is None:
        # try python -m bandit
        try:
            subprocess.run([sys.executable, "-m", "bandit", "-h"], capture_output=True, check=False)
        except Exception:
            return []
    preds = []
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        for i, code in enumerate(codes):
            fp = tdir / f"s{i}.py"
            fp.write_text(code, encoding="utf-8")
            cmd = [sys.executable, "-m", "bandit", "-q", "-f", "json", str(fp)]
            r = subprocess.run(cmd, capture_output=True, text=True)
            try:
                data = json.loads(r.stdout or "{}")
                results = data.get("results") or []
                preds.append(1 if results else 0)
            except Exception:
                preds.append(0)
    return preds


def _semgrep_bin() -> Optional[str]:
    for name in ("semgrep", "semgrep.exe"):
        found = shutil.which(name)
        if found:
            return found
    # venv Scripts next to this interpreter (Windows often omits Scripts from PATH)
    cand = Path(sys.executable).resolve().parent / ("semgrep.exe" if sys.platform == "win32" else "semgrep")
    if cand.is_file():
        return str(cand)
    return None


def semgrep_predict(codes: List[str]) -> Optional[List[int]]:
    semgrep = _semgrep_bin()
    if semgrep is None:
        return None
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        path_by_i = {}
        for i, code in enumerate(codes):
            fp = tdir / f"s{i}.py"
            fp.write_text(code, encoding="utf-8")
            path_by_i[str(fp.resolve())] = i
            path_by_i[fp.name] = i
        cmd = [
            semgrep,
            "--config",
            "p/python",
            "--json",
            "--quiet",
            "--disable-version-check",
            "--no-git-ignore",
            str(tdir),
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        preds = [0] * len(codes)
        try:
            data = json.loads(r.stdout or "{}")
            for hit in data.get("results") or []:
                p = str(hit.get("path") or "")
                idx = path_by_i.get(p) or path_by_i.get(Path(p).name)
                if idx is not None:
                    preds[idx] = 1
        except Exception:
            return [0] * len(codes)
        return preds


def hybrid_product_predict(codes: List[str], langs: List[str], thr: float, safe_cutoff: float) -> List[int]:
    """Rule + ML suppress (no aggressive ML OR) — mirrors product mode."""
    scanner = RuleScanner()
    ckpt = ROOT / "ml" / "inference" / "checkpoints" / "detector-codebert"
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(str(ckpt))
    model = AutoModelForSequenceClassification.from_pretrained(str(ckpt))
    model.eval()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    def prob(code: str) -> float:
        enc = tok(code, truncation=True, max_length=320, return_tensors="pt")
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.no_grad():
            return float(torch.softmax(model(**enc).logits, dim=-1)[0, 1].item())

    out = []
    for code, lang in zip(codes, langs):
        _, findings = scanner.scan(code, lang or "python")
        yr = 1 if findings else 0
        p = prob(code)
        if yr == 1 and p < safe_cutoff:
            out.append(0)
        elif yr == 1:
            out.append(1)
        elif p >= thr:
            out.append(1)
        else:
            out.append(0)
    return out


def main():
    pairs = ROOT / "ml" / "datasets" / "processed" / "sft_pairs.jsonl"
    hn = ROOT / "ml" / "datasets" / "processed" / "hard_negatives.jsonl"
    rows = []
    if pairs.exists():
        for p in load_jsonl(pairs):
            if p.get("language") != "python":
                continue
            rows.append({"code": p["vulnerable_code"], "label": 1, "language": "python"})
            rows.append({"code": p["secure_code"], "label": 0, "language": "python"})
    if hn.exists():
        for h in load_jsonl(hn):
            if h.get("language") == "python":
                rows.append({"code": h["code"], "label": 0, "language": "python"})

    # cap for bandit runtime
    rows = rows[:240]
    y = [r["label"] for r in rows]
    codes = [r["code"] for r in rows]
    langs = [r["language"] for r in rows]

    scanner = RuleScanner()
    y_rule = [1 if scanner.scan(c, "python")[1] else 0 for c in codes]

    thr_path = ROOT / "ml" / "inference" / "checkpoints" / "thresholds.json"
    thr = 0.848
    safe = 0.45
    if thr_path.exists():
        conf = json.loads(thr_path.read_text(encoding="utf-8"))["detector"]
        safe = float(conf.get("safe_cutoff", 0.45))
        anti = (conf.get("threshold") or {}).get("anti_fp") or {}
        if "threshold" in anti:
            thr = float(anti["threshold"])

    y_hyb = hybrid_product_predict(codes, langs, thr, safe)

    # install bandit if missing
    try:
        import bandit  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "bandit"], check=False)

    y_bandit = bandit_predict(codes)
    y_semgrep = semgrep_predict(codes)

    report = {
        "n": len(rows),
        "language": "python",
        "rule_only": prf(y, y_rule),
        "hybrid_product": prf(y, y_hyb),
        "bandit": prf(y, y_bandit) if y_bandit else {"error": "bandit unavailable"},
        "semgrep": prf(y, y_semgrep) if y_semgrep is not None else {"skipped": "semgrep not installed"},
        "thresholds": {"anti_fp": thr, "safe_cutoff": safe},
    }

    out = ROOT / "ml" / "eval" / "reports"
    out.mkdir(parents=True, exist_ok=True)
    (out / "baseline_compare.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Baseline compare (Python labeled pairs)",
        "",
        f"n={report['n']}  thr_anti_fp={thr:.3f}  safe_cutoff={safe:.3f}",
        "",
        "| Method | Precision | Recall | F1 | FPR |",
        "|--------|-----------|--------|----|-----|",
    ]
    for key, title in [
        ("rule_only", "SCC Rule-only"),
        ("hybrid_product", "SCC Hybrid (low-FPR)"),
        ("bandit", "Bandit"),
        ("semgrep", "Semgrep"),
    ]:
        m = report[key]
        if "precision" not in m:
            lines.append(f"| {title} | - | - | - | {m} |")
        else:
            lines.append(
                f"| {title} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} |"
            )
    (out / "baseline_compare.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # figure
    fig_dir = out / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    methods = []
    fprs = []
    f1s = []
    recalls = []
    for key, title in [
        ("rule_only", "SCC Rule"),
        ("hybrid_product", "SCC Hybrid"),
        ("bandit", "Bandit"),
    ]:
        m = report[key]
        if "fpr" not in m:
            continue
        methods.append(title)
        fprs.append(m["fpr"])
        f1s.append(m["f1"])
        recalls.append(m["recall"])
    if y_semgrep is not None and "fpr" in report["semgrep"]:
        methods.append("Semgrep")
        fprs.append(report["semgrep"]["fpr"])
        f1s.append(report["semgrep"]["f1"])
        recalls.append(report["semgrep"]["recall"])

    x = np.arange(len(methods))
    width = 0.25
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    ax.bar(x - width, recalls, width, label="Recall", color="#2F6B3A")
    ax.bar(x, f1s, width, label="F1", color="#B35C1E")
    ax.bar(x + width, fprs, width, label="FPR (lower better)", color="#8B1A1A")
    ax.set_xticks(x)
    ax.set_xticklabels(methods)
    ax.set_ylim(0, 1.15)
    ax.set_title(f"SecureCode Copilot vs baselines — Python labeled (n={report['n']})")
    ax.legend()
    fig.tight_layout()
    fig.savefig(fig_dir / "10_baseline_vs_bandit.png", dpi=160, bbox_inches="tight")
    plt.close(fig)

    print(json.dumps(report, indent=2))
    print("[done]", out / "baseline_compare.md")


if __name__ == "__main__":
    main()
