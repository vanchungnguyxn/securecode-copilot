"""Generate thesis-ready PNG figures — clean layout, no overlapping labels."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import List

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Patch
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "ml" / "eval" / "reports" / "figures"
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "backend"))

C = {
    "ink": "#1B2A33",
    "muted": "#5B6B73",
    "rule": "#3D5A6C",
    "ml": "#0E7C6B",
    "hybrid": "#C45C26",
    "bandit": "#7A6A4F",
    "semgrep": "#5C6B8A",
    "good": "#1F6B4A",
    "warn": "#B45309",
    "bad": "#9B2C2C",
    "soft": "#F4F1EC",
    "card": "#FFFFFF",
    "grid": "#D6D1C9",
    "med": "#C9A227",
}


def _style() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": C["soft"],
            "axes.facecolor": C["card"],
            "axes.edgecolor": C["grid"],
            "axes.labelcolor": C["ink"],
            "axes.titlecolor": C["ink"],
            "axes.grid": True,
            "grid.color": C["grid"],
            "grid.alpha": 0.45,
            "grid.linewidth": 0.7,
            "font.size": 11,
            "axes.titlesize": 12,
            "axes.labelsize": 10.5,
            "xtick.color": C["ink"],
            "ytick.color": C["ink"],
            "figure.dpi": 170,
            "savefig.facecolor": C["soft"],
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.35,
            "font.family": "DejaVu Sans",
        }
    )


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _header(fig, main: str, sub: str) -> None:
    """Figure-level title block — never overlaps axes titles."""
    fig.text(0.02, 0.98, main, fontsize=14.5, fontweight="bold", color=C["ink"], ha="left", va="top")
    fig.text(0.02, 0.925, sub, fontsize=9.2, color=C["muted"], ha="left", va="top", wrap=True)


def _footer(fig, text: str) -> None:
    fig.text(0.02, 0.015, text, fontsize=7.5, color=C["muted"], ha="left", va="bottom")


def _clean(ax) -> None:
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_axisbelow(True)


def _save(fig, name: str, footer: str) -> Path:
    _footer(fig, footer)
    path = OUT / name
    fig.savefig(path)
    plt.close(fig)
    return path


def _bar_labels(ax, bars, vals, fmt=lambda v: f"{v:.0%}", y_pad=0.03, fontsize=9.5) -> None:
    ymax = ax.get_ylim()[1]
    for b, v in zip(bars, vals):
        y = min(v + y_pad, ymax - y_pad * 0.5)
        ax.text(b.get_x() + b.get_width() / 2, y, fmt(v), ha="center", va="bottom", fontsize=fontsize, fontweight="bold", color=C["ink"])


# ---------------------------------------------------------------------------
def fig_hybrid_metrics():
    bench = load_json(ROOT / "ml" / "eval" / "reports" / "bench_compare.json")
    multi = bench["multilingual_pairs"]
    methods = ["rule_only", "hybrid", "ml_only"]
    labels = ["Rule", "Hybrid", "ML alone"]
    full = ["Rule (SAST)", "Hybrid (product)", "ML alone (CodeBERT)"]
    colors = [C["rule"], C["hybrid"], C["ml"]]
    panels = [
        ("precision", "Precision — đúng khi báo lỗi"),
        ("recall", "Recall — bắt được lỗi"),
        ("f1", "F1 — cân bằng"),
    ]

    fig, axes = plt.subplots(1, 3, figsize=(12.4, 5.4), sharey=True)
    fig.subplots_adjust(left=0.07, right=0.98, top=0.76, bottom=0.22, wspace=0.2)
    _header(
        fig,
        "SecureCode Copilot phát hiện lỗ hổng thế nào?",
        f"Bộ đa ngôn ngữ + hard-negative (n={multi['n']}). Hybrid ≈ Rule; ML đơn lẻ được chỉnh để hạn chế báo sai.",
    )

    for ax, (key, title) in zip(axes, panels):
        vals = [multi[m][key] for m in methods]
        bars = ax.bar(np.arange(3), vals, color=colors, width=0.62, zorder=3)
        ax.set_xticks(np.arange(3))
        ax.set_xticklabels(labels)
        ax.set_ylim(0, 1.28)
        _bar_labels(ax, bars, vals, y_pad=0.05)
        ax.set_title(title, fontsize=10.5, pad=12, color=C["ink"])
        _clean(ax)
        ax.axhline(0.9, color=C["muted"], ls=":", lw=0.9, alpha=0.65, zorder=1)
    axes[0].set_ylabel("Tỷ lệ (0–1)")

    handles = [Patch(facecolor=c, label=l) for c, l in zip(colors, full)]
    fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 0.07), fontsize=9.5)

    return _save(fig, "01_hybrid_vs_rule_ml_multilingual.png", "Nguồn: bench_compare.json → multilingual_pairs")


def fig_devign_metrics():
    bench = load_json(ROOT / "ml" / "eval" / "reports" / "bench_compare.json")
    d = bench["detector_test"]
    methods = ["rule_only", "ml_only", "hybrid"]
    labels = ["Rule", "ML", "Hybrid"]

    fig, axes = plt.subplots(1, 2, figsize=(11.8, 5.4), gridspec_kw={"width_ratios": [2.1, 1]})
    fig.subplots_adjust(left=0.08, right=0.97, top=0.74, bottom=0.14, wspace=0.3)
    _header(
        fig,
        "Trên mã C thật (Devign mix) — khó hơn demo",
        f"n={d['n']} · Hybrid tăng recall so với Rule/ML đơn; FPR vẫn kiểm soát (~{d['hybrid']['fpr']:.0%}).",
    )

    ax = axes[0]
    x = np.arange(3) * 1.15
    width = 0.28
    for i, (key, color, name) in enumerate(
        [("precision", C["rule"], "Precision"), ("recall", C["ml"], "Recall"), ("f1", C["hybrid"], "F1")]
    ):
        vals = [d[m][key] for m in methods]
        bars = ax.bar(x + (i - 1) * width, vals, width, label=name, color=color, zorder=3)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.03, f"{v:.2f}", ha="center", fontsize=8, color=C["ink"])
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.18)
    ax.set_ylabel("Score")
    ax.set_title("Precision / Recall / F1", fontsize=11, pad=10)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, 1.0), ncols=3, fontsize=9)
    _clean(ax)

    ax = axes[1]
    fprs = [d[m]["fpr"] for m in methods]
    bars = ax.bar(labels, fprs, color=[C["rule"], C["ml"], C["hybrid"]], width=0.55, zorder=3)
    ax.set_ylim(0, max(fprs) * 1.55 + 0.02)
    _bar_labels(ax, bars, fprs, y_pad=max(fprs) * 0.06)
    ax.set_ylabel("False Positive Rate")
    ax.set_title("Báo sai (thấp hơn = tốt)", fontsize=11, pad=8)
    _clean(ax)

    return _save(fig, "02_detector_devign_mix.png", "Nguồn: bench_compare.json → detector_test (Devign/CodeXGLUE)")


def fig_confusion_hybrid():
    bench = load_json(ROOT / "ml" / "eval" / "reports" / "bench_compare.json")
    h = bench["multilingual_pairs"]["hybrid"]
    n = bench["multilingual_pairs"]["n"]
    cells = [
        (0, 0, h["tn"], "Đúng: AN TOÀN", C["good"]),
        (0, 1, h["fp"], "Báo sai (FP)", C["warn"]),
        (1, 0, h["fn"], "Bỏ sót (FN)", C["bad"]),
        (1, 1, h["tp"], "Đúng: LỖ HỔNG", C["good"]),
    ]

    fig, ax = plt.subplots(figsize=(8.0, 6.2))
    fig.subplots_adjust(left=0.18, right=0.95, top=0.78, bottom=0.14)
    _header(
        fig,
        "Hybrid đọc kết quả thế nào?",
        f"n={n}  ·  Precision {h['precision']:.0%}  ·  Recall {h['recall']:.0%}  ·  F1 {h['f1']:.0%}  ·  FPR {h['fpr']:.0%}",
    )

    ax.set_xlim(-0.55, 1.55)
    ax.set_ylim(1.55, -0.55)
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Dự đoán: An toàn", "Dự đoán: Lỗ hổng"], fontsize=11)
    ax.set_yticklabels(["Thật:\nAn toàn", "Thật:\nLỗ hổng"], fontsize=11)
    ax.tick_params(length=0, pad=10)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.grid(False)

    for i, j, val, label, color in cells:
        ax.add_patch(
            FancyBboxPatch(
                (j - 0.40, i - 0.40),
                0.80,
                0.80,
                boxstyle="round,pad=0.02,rounding_size=0.1",
                facecolor=color,
                edgecolor="white",
                linewidth=4,
                alpha=0.9,
            )
        )
        ax.text(j, i - 0.08, f"{int(val)}", ha="center", va="center", fontsize=26, fontweight="bold", color="white")
        ax.text(j, i + 0.26, label, ha="center", va="center", fontsize=9.5, color="white")

    return _save(fig, "03_hybrid_confusion_multilingual.png", "Nguồn: multilingual_pairs.hybrid (tn/fp/fn/tp)")


def fig_codet5_fix():
    bench = load_json(ROOT / "ml" / "eval" / "reports" / "bench_compare.json")
    after = float(bench["codet5_fix"]["fix_soft_match"])
    n = int(bench["codet5_fix"]["n"])
    labels = ["Lần đầu\nmixed SFT", "Fix-heavy\n(curated)", "+ CVEFixes\nthật"]
    vals = [0.05, 0.533, after]
    colors = [C["bandit"], C["ml"], C["hybrid"]]

    fig, ax = plt.subplots(figsize=(8.6, 5.4))
    fig.subplots_adjust(left=0.12, right=0.96, top=0.78, bottom=0.16)
    _header(
        fig,
        "Gợi ý sửa mã (CodeT5) ngày càng khớp hơn",
        f"Soft-match = đoạn sửa trùng từ khóa với bản vá chuẩn (eval n={n}).",
    )

    x = np.arange(len(vals))
    bars = ax.bar(x, vals, color=colors, width=0.52, zorder=3)
    ax.plot(x, vals, color=C["ink"], lw=1.8, marker="o", markersize=8, zorder=4)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylim(0, 0.95)
    ax.set_ylabel("Tỷ lệ soft-match")
    _bar_labels(ax, bars, vals, fmt=lambda v: f"{v*100:.1f}%", y_pad=0.04, fontsize=11)
    _clean(ax)

    ax.annotate(
        f"+{(after - 0.533)*100:.0f} điểm nhờ CVEFixes",
        xy=(2, after),
        xytext=(0.55, 0.78),
        textcoords="data",
        arrowprops=dict(arrowstyle="->", color=C["ink"], lw=1.2),
        fontsize=10,
        color=C["ink"],
        bbox=dict(boxstyle="round,pad=0.4", facecolor="white", edgecolor=C["grid"], linewidth=1),
    )

    return _save(
        fig,
        "04_codet5_fix_softmatch.png",
        "Priors: 5.0% early · 53.3% trước CVEFixes · hiện tại từ bench_compare.json",
    )


def fig_dataset_composition():
    dmeta = load_json(ROOT / "ml" / "datasets" / "processed" / "meta.json")
    cvem = load_json(ROOT / "ml" / "datasets" / "processed" / "cvefixes_meta.json")
    pairs = ROOT / "ml" / "datasets" / "processed" / "sft_pairs.jsonl"
    langs = Counter()
    if pairs.exists():
        for line in pairs.open(encoding="utf-8"):
            if line.strip():
                langs[json.loads(line).get("language", "?")] += 1

    fig, axes = plt.subplots(1, 3, figsize=(13.2, 5.6))
    fig.subplots_adjust(left=0.09, right=0.98, top=0.74, bottom=0.18, wspace=0.38)
    _header(
        fig,
        "Dữ liệu huấn luyện — ba góc nhìn",
        "Detector: Defect Detection + curated · Fix: thêm patch CVEFixes đa ngôn ngữ.",
    )

    # Sources — isolate giant CodeXGLUE so small bars stay readable
    ax = axes[0]
    src = dmeta.get("source_counts", {})
    pretty = {
        "hf:google/code_x_glue_cc_defect_detection": "CodeXGLUE",
        "hf:s2e-lab/SecurityEval": "SecurityEval",
        "curated_vuln": "Curated vuln",
        "curated_secure": "Curated safe",
        "hard_negative": "Hard-neg",
        "hard_negative_aug": "Hard-neg aug",
    }
    big_key = "hf:google/code_x_glue_cc_defect_detection"
    big_n = src.get(big_key, 0)
    small = sorted(((pretty.get(k, k[:14]), v) for k, v in src.items() if k != big_key), key=lambda kv: kv[1])
    names = [n for n, _ in small]
    vals = [v for _, v in small]
    bars = ax.barh(names, vals, color=C["rule"], zorder=3, height=0.62)
    for b, v in zip(bars, vals):
        ax.text(v + max(vals) * 0.04, b.get_y() + b.get_height() / 2, f"{v}", va="center", fontsize=9, color=C["ink"])
    ax.set_xlim(0, max(vals) * 1.35 if vals else 1)
    ax.set_xlabel("# mẫu (nguồn phụ)")
    ax.set_title(f"Nguồn phụ detector  ·  Σ tổng={dmeta['detector_total']}", fontsize=11, pad=10)
    # callout under chart, not over title
    ax.text(
        0.5,
        -0.22,
        f"Nguồn chính: CodeXGLUE/Devign = {big_n:,}",
        transform=ax.transAxes,
        fontsize=9,
        color=C["hybrid"],
        fontweight="bold",
        ha="center",
        va="top",
    )
    _clean(ax)
    ax.grid(axis="y", visible=False)

    ax = axes[1]
    lc = dmeta.get("label_counts", {})
    vuln, safe = lc.get("1", 0), lc.get("0", 0)
    wedges, _ = ax.pie(
        [vuln, safe],
        colors=[C["hybrid"], C["ml"]],
        startangle=90,
        wedgeprops=dict(width=0.48, edgecolor=C["soft"], linewidth=4),
    )
    ax.legend(
        wedges,
        [f"Lỗ hổng   {vuln:,}  ({vuln/(vuln+safe):.0%})", f"An toàn   {safe:,}  ({safe/(vuln+safe):.0%})"],
        loc="upper center",
        bbox_to_anchor=(0.5, -0.02),
        frameon=False,
        fontsize=9.5,
    )
    ax.set_title("Cân bằng nhãn detector", fontsize=11, pad=10)

    ax = axes[2]
    if langs:
        items = langs.most_common()
        names = [k for k, _ in items][::-1]
        vals = [v for _, v in items][::-1]
        bars = ax.barh(names, vals, color=C["ml"], zorder=3, height=0.62)
        for b, v in zip(bars, vals):
            ax.text(v + max(vals) * 0.03, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=9)
        ax.set_xlabel("# SFT pairs")
        ax.set_xlim(0, max(vals) * 1.28)
    ax.set_title(f"Ngôn ngữ SFT pairs (n={sum(langs.values())})", fontsize=11, pad=10)
    _clean(ax)
    ax.grid(axis="y", visible=False)

    cve_langs = cvem.get("by_lang", {})
    top = ", ".join(f"{k}={v}" for k, v in sorted(cve_langs.items(), key=lambda x: -x[1])[:5])
    fig.text(
        0.5,
        0.07,
        f"CVEFixes pairs: {top} … (Σ={cvem.get('n_pairs')})",
        ha="center",
        fontsize=9,
        color=C["muted"],
    )

    return _save(fig, "05_dataset_composition.png", "Nguồn: meta.json · sft_pairs.jsonl · cvefixes_meta.json")


def fig_sft_tasks():
    sft_path = ROOT / "ml" / "datasets" / "processed" / "sft_fix.jsonl"
    rows = [json.loads(l) for l in sft_path.read_text(encoding="utf-8").splitlines() if l.strip()] if sft_path.exists() else []
    by_task = Counter(r.get("task", "?") for r in rows)
    by_src = Counter(r.get("source", "curated") for r in rows)
    n = len(rows)

    fig, axes = plt.subplots(1, 2, figsize=(11.0, 5.0))
    fig.subplots_adjust(left=0.08, right=0.97, top=0.78, bottom=0.14, wspace=0.3)
    _header(fig, "CodeT5 học gì? — ưu tiên SỬA mã", f"Tổng {n} mẫu SFT · curated + CVEFixes để sinh fix/explain.")

    ax = axes[0]
    order = [t for t in ("fix", "explain", "detect") if t in by_task]
    vals = [by_task[t] for t in order]
    pretty = {"fix": "Fix", "explain": "Explain", "detect": "Detect"}
    colors = [C["hybrid"], C["ml"], C["rule"]][: len(order)]
    bars = ax.bar([pretty[t] for t in order], vals, color=colors, width=0.55, zorder=3)
    ax.set_ylim(0, max(vals) * 1.18)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + max(vals) * 0.025, f"{v}", ha="center", fontweight="bold", fontsize=11)
    ax.set_ylabel("# examples")
    ax.set_title("Theo nhiệm vụ", fontsize=11, pad=8)
    _clean(ax)

    ax = axes[1]
    src_order = [s for s in ("curated", "cvefixes") if s in by_src]
    src_vals = [by_src[s] for s in src_order]
    src_pretty = {"curated": "Curated", "cvefixes": "CVEFixes"}
    bars = ax.bar([src_pretty[s] for s in src_order], src_vals, color=[C["rule"], C["hybrid"]], width=0.5, zorder=3)
    ax.set_ylim(0, max(src_vals) * 1.18)
    for b, v in zip(bars, src_vals):
        ax.text(b.get_x() + b.get_width() / 2, v + max(src_vals) * 0.025, f"{v}", ha="center", fontweight="bold", fontsize=11)
    ax.set_title("Theo nguồn dữ liệu", fontsize=11, pad=8)
    _clean(ax)

    meta = {"n": n, "by_task": dict(by_task), "by_source": dict(by_src)}
    (ROOT / "ml" / "datasets" / "processed" / "sft_fix_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return _save(fig, "06_sft_task_mix.png", "Nguồn: sft_fix.jsonl (đếm trực tiếp)")


def fig_repo_scan_evidence():
    from app.scanners.engine import RuleScanner
    from app.scanners.rules import detect_language

    LANG_EXT = {
        ".py": "python",
        ".js": "javascript",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".cs": "csharp",
        ".php": "php",
        ".rules": "firebase",
    }
    demos = {
        "acc-shop": ROOT / "examples" / "acc-shop",
        "vibe-auth": ROOT / "examples" / "vibe-auth",
        "naive-notes": ROOT / "examples" / "naive-notes",
        "lang-extra": ROOT / "examples" / "lang-extra",
        "simple-cms": ROOT / "examples" / "simple-cms",
    }
    hints = {
        "acc-shop": "lỗ hổng cố ý",
        "vibe-auth": "JWT / Firebase",
        "naive-notes": "pwd plaintext",
        "lang-extra": "PHP / C# / C++",
        "simple-cms": "gần an toàn",
    }
    scanner = RuleScanner()
    rows = []
    for name, folder in demos.items():
        sev = Counter()
        for f in folder.rglob("*"):
            if not f.is_file() or f.suffix.lower() not in LANG_EXT:
                continue
            if any(p in f.parts for p in ("node_modules", ".venv", "__pycache__")):
                continue
            code = f.read_text(encoding="utf-8", errors="ignore")
            lang = LANG_EXT.get(f.suffix.lower()) or detect_language(code, f.name)
            _, findings = scanner.scan(code, lang, str(f))
            for v in findings:
                sev[v.severity.value] += 1
        rows.append((name, sev))

    labels = [f"{n}\n({hints[n]})" for n, _ in rows]
    crit = [r[1].get("critical", 0) for r in rows]
    high = [r[1].get("high", 0) for r in rows]
    med = [r[1].get("medium", 0) for r in rows]
    totals = [c + h + m for c, h, m in zip(crit, high, med)]
    x = np.arange(len(labels))

    fig, ax = plt.subplots(figsize=(11.5, 5.4))
    fig.subplots_adjust(left=0.08, right=0.97, top=0.78, bottom=0.18)
    _header(
        fig,
        "Quét thật các repo demo — thấy gì?",
        "App cố ý lỗi / vibe-coding bắt nhiều finding; app gần chuẩn ít hơn (đúng kỳ vọng).",
    )

    ax.bar(x, crit, label="Critical", color=C["bad"], width=0.58, zorder=3)
    ax.bar(x, high, bottom=crit, label="High", color=C["hybrid"], width=0.58, zorder=3)
    bottom2 = [a + b for a, b in zip(crit, high)]
    ax.bar(x, med, bottom=bottom2, label="Medium", color=C["med"], width=0.58, zorder=3)
    ymax = max(totals) * 1.22 if totals else 1
    ax.set_ylim(0, ymax)
    for xi, t in zip(x, totals):
        ax.text(xi, t + ymax * 0.025, str(t), ha="center", fontweight="bold", fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9.5)
    ax.set_ylabel("Số phát hiện")
    ax.legend(frameon=False, ncols=3, loc="upper right", fontsize=9)
    _clean(ax)

    (OUT / "07_demo_repo_scan_counts.json").write_text(
        json.dumps({k: dict(v) for k, v in rows}, indent=2),
        encoding="utf-8",
    )
    return _save(fig, "07_demo_repo_scan_counts.png", "Live RuleScanner trên examples/* — không phải số giả")


def fig_threshold_strategies():
    rep = load_json(ROOT / "ml" / "inference" / "checkpoints" / "detector-codebert" / "train_report.json")
    thr = rep.get("threshold", {})
    blocks = [
        ("anti_fp", "Anti-FP", "Dùng trong product"),
        ("hybrid", "Hybrid", "Ngưỡng phụ"),
        ("balanced", "Balanced", "Tham chiếu (FPR cao)"),
    ]
    names, notes, precs, recs, f1s, fprs = [], [], [], [], [], []
    for key, title, note in blocks:
        block = thr.get(key) if key != "hybrid" else (thr.get("hybrid") or thr)
        if not isinstance(block, dict) or "precision" not in block:
            continue
        names.append(title)
        notes.append(note)
        precs.append(block["precision"])
        recs.append(block["recall"])
        f1s.append(block["f1"])
        fprs.append(block.get("fpr", 0))

    fig, axes = plt.subplots(1, 2, figsize=(11.8, 5.4), gridspec_kw={"width_ratios": [1.65, 1]})
    fig.subplots_adjust(left=0.08, right=0.97, top=0.74, bottom=0.24, wspace=0.28)
    _header(
        fig,
        "Chọn ngưỡng CodeBERT: ít báo sai hơn là bắt hết",
        f"GPU {rep['hardware'].get('gpu', '?')} · train={rep.get('train_size')} mẫu",
    )

    ax = axes[0]
    x = np.arange(len(names)) * 1.1
    width = 0.26
    ax.bar(x - width, precs, width, label="Precision", color=C["rule"], zorder=3)
    ax.bar(x, recs, width, label="Recall", color=C["ml"], zorder=3)
    ax.bar(x + width, f1s, width, label="F1", color=C["hybrid"], zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=10)
    ax.set_ylim(0, 1.2)
    ax.set_ylabel("Score")
    ax.set_title("Precision / Recall / F1", fontsize=11, pad=10)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, 1.0), ncols=3, fontsize=9)
    _clean(ax)

    ax = axes[1]
    bars = ax.bar(names, fprs, color=[C["ml"], C["rule"], C["bad"]][: len(names)], width=0.5, zorder=3)
    ax.set_ylim(0, min(1.08, max(fprs) * 1.28 + 0.05))
    _bar_labels(ax, bars, fprs, y_pad=0.045)
    ax.set_ylabel("FPR")
    ax.set_title("Báo sai theo chiến lược", fontsize=11, pad=10)
    _clean(ax)

    fig.text(
        0.5,
        0.1,
        "   ·   ".join(f"{n}: {note}" for n, note in zip(names, notes)),
        ha="center",
        fontsize=9.5,
        color=C["muted"],
    )

    return _save(fig, "08_codebert_threshold_strategies.png", "Nguồn: detector-codebert/train_report.json → threshold.*")


def fig_architecture_pipeline():
    fig, ax = plt.subplots(figsize=(12.5, 4.6))
    ax.set_xlim(0, 12.5)
    ax.set_ylim(0, 4.6)
    ax.axis("off")
    ax.set_facecolor(C["soft"])
    fig.patch.set_facecolor(C["soft"])

    ax.text(0.25, 4.2, "SecureCode Copilot hoạt động ra sao?", fontsize=15, fontweight="bold", color=C["ink"], ha="left")
    ax.text(
        0.25,
        3.75,
        "Mã nguồn → phát hiện → giải thích & đề xuất sửa → CI / SARIF",
        fontsize=10,
        color=C["muted"],
        ha="left",
    )

    boxes = [
        (0.25, "1. Mã nguồn\nPy · JS · Java\nC/C++ · C# · PHP", C["rule"]),
        (2.7, "2. Rule SAST\nOWASP / CWE\nnhanh, giải thích được", C["rule"]),
        (5.15, "3. CodeBERT\nxác suất lỗ hổng\n(lọc báo sai)", C["ml"]),
        (7.6, "4. Hybrid\nghép Rule + ML\nchế độ product", C["hybrid"]),
        (10.05, "5. CodeT5\nExplain + Fix\n(+ CVEFixes)", C["hybrid"]),
    ]
    for x, text, color in boxes:
        ax.add_patch(
            FancyBboxPatch(
                (x, 1.25),
                2.15,
                2.0,
                boxstyle="round,pad=0.03,rounding_size=0.12",
                facecolor="white",
                edgecolor=color,
                linewidth=2.2,
            )
        )
        ax.text(x + 1.075, 2.25, text, ha="center", va="center", fontsize=9.5, color=C["ink"])

    for x0 in (2.4, 4.85, 7.3, 9.75):
        ax.annotate(
            "",
            xy=(x0 + 0.3, 2.25),
            xytext=(x0, 2.25),
            arrowprops=dict(arrowstyle="-|>", color=C["ink"], lw=1.5, mutation_scale=11),
        )

    ax.add_patch(
        FancyBboxPatch(
            (0.25, 0.25),
            11.95,
            0.7,
            boxstyle="round,pad=0.02,rounding_size=0.08",
            facecolor="white",
            edgecolor=C["grid"],
            lw=1.1,
        )
    )
    ax.text(
        6.2,
        0.6,
        "CI/CD: action/scan.py → GitHub Action / SARIF    ·    UI + FastAPI apply-fix    ·    GPU: RTX 3050 4GB",
        ha="center",
        va="center",
        fontsize=9,
        color=C["muted"],
    )

    path = OUT / "09_system_pipeline.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def fig_baseline_compare():
    rep = load_json(ROOT / "ml" / "eval" / "reports" / "baseline_compare.json")
    methods = [
        ("rule_only", "SCC Rule", C["rule"]),
        ("hybrid_product", "SCC Hybrid", C["hybrid"]),
        ("bandit", "Bandit", C["bandit"]),
        ("semgrep", "Semgrep", C["semgrep"]),
    ]
    usable = []
    for key, label, color in methods:
        block = rep.get(key)
        if isinstance(block, dict) and "f1" in block:
            usable.append((label, color, block))

    fig, axes = plt.subplots(1, 2, figsize=(12.0, 5.2), gridspec_kw={"width_ratios": [1.7, 1]})
    fig.subplots_adjust(left=0.08, right=0.97, top=0.76, bottom=0.2, wspace=0.28)
    _header(
        fig,
        "So với công cụ có sẵn: Bandit & Semgrep",
        f"Python labeled pairs n={rep['n']} · cùng bộ mẫu · anti_fp={rep['thresholds']['anti_fp']:.3f}",
    )

    ax = axes[0]
    x = np.arange(len(usable))
    width = 0.22
    for i, (metric, color, name) in enumerate(
        [("precision", C["rule"], "Precision"), ("recall", C["ml"], "Recall"), ("f1", C["hybrid"], "F1")]
    ):
        vals = [u[2][metric] for u in usable]
        ax.bar(x + (i - 1) * width, vals, width, label=name, color=color, zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels([u[0] for u in usable], fontsize=10)
    ax.set_ylim(0, 1.15)
    ax.legend(frameon=False, ncols=3, loc="upper right", fontsize=9)
    ax.set_ylabel("Score")
    ax.set_title("Precision / Recall / F1", fontsize=11, pad=8)
    _clean(ax)

    ax = axes[1]
    fprs = [u[2]["fpr"] for u in usable]
    bars = ax.bar([u[0] for u in usable], fprs, color=[u[1] for u in usable], width=0.55, zorder=3)
    ax.set_ylim(0, max(fprs) * 1.4 + 0.04)
    _bar_labels(ax, bars, fprs, y_pad=max(fprs) * 0.05)
    ax.set_ylabel("FPR (báo sai)")
    ax.set_title("Ai báo sai nhiều hơn?", fontsize=11, pad=8)
    ax.tick_params(axis="x", labelsize=9.5)
    _clean(ax)

    fig.text(
        0.5,
        0.06,
        "Semgrep: precision cao nhưng recall thấp  ·  SCC Hybrid: cân bằng tốt hơn Bandit",
        ha="center",
        fontsize=9,
        color=C["muted"],
    )

    return _save(fig, "10_baseline_vs_bandit.png", "Nguồn: baseline_compare.json")


def write_caption_index(paths: List[Path]) -> None:
    lines = [
        "# Figures for thesis / report",
        "",
        "Mỗi ảnh trả lời **một câu hỏi** — layout đã chỉnh để tránh đè chữ.",
        "",
        "| File | Câu hỏi / nội dung |",
        "|------|---------------------|",
        "| `01_hybrid_vs_rule_ml_multilingual.png` | SCC Rule / Hybrid / ML phát hiện lỗ hổng ra sao? |",
        "| `02_detector_devign_mix.png` | Trên mã C thật (Devign) thì sao? |",
        "| `03_hybrid_confusion_multilingual.png` | Hybrid đúng / sai ở đâu? |",
        "| `04_codet5_fix_softmatch.png` | Gợi ý sửa mã tiến bộ thế nào (+CVEFixes)? |",
        "| `05_dataset_composition.png` | Train bằng dữ liệu gì? |",
        "| `06_sft_task_mix.png` | CodeT5 học fix / explain / từ đâu? |",
        "| `07_demo_repo_scan_counts.png` | Quét repo demo thấy gì? |",
        "| `08_codebert_threshold_strategies.png` | Vì sao chọn Anti-FP threshold? |",
        "| `09_system_pipeline.png` | Pipeline hệ thống end-to-end |",
        "| `10_baseline_vs_bandit.png` | So với Bandit & Semgrep |",
        "",
        "```powershell",
        r".\.venv-ml\Scripts\python.exe ml\eval\make_report_figures.py",
        "```",
        "",
    ]
    (OUT / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    _style()
    paths = []
    for fn in [
        fig_hybrid_metrics,
        fig_devign_metrics,
        fig_confusion_hybrid,
        fig_codet5_fix,
        fig_dataset_composition,
        fig_sft_tasks,
        fig_repo_scan_evidence,
        fig_threshold_strategies,
        fig_architecture_pipeline,
        fig_baseline_compare,
    ]:
        p = fn()
        print("[ok]", p.name)
        paths.append(p)
    write_caption_index(paths)
    print("[done]", OUT)


if __name__ == "__main__":
    main()
