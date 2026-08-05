#!/usr/bin/env python3
"""SecureCode Copilot CI scanner — rule or hybrid (fine-tuned CodeBERT).

Modes:
  rule    — RuleScanner only (fast; default on GitHub-hosted runners)
  hybrid  — Rule + CodeBERT context filter/discovery when checkpoint exists
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.scanners.engine import RuleScanner  # noqa: E402
from app.scanners.rules import detect_language  # noqa: E402

LANG_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rules": "firebase",
}

FAIL_SEV = {"critical", "high"}
CKPT = ROOT / "ml" / "inference" / "checkpoints" / "detector-codebert"


def iter_files(paths: list[str]):
    for p in paths:
        path = Path(p)
        if path.is_file():
            yield path
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.is_file() and f.suffix.lower() in LANG_EXT:
                    if any(part in {"node_modules", ".venv", ".venv-ml", "dist", "build", ".git"} for part in f.parts):
                        continue
                    yield f


def to_dump(v) -> dict:
    if hasattr(v, "model_dump"):
        return v.model_dump(mode="json")
    return dict(v)


def scan_rule(paths: list[str]) -> list[dict]:
    scanner = RuleScanner()
    all_findings = []
    for f in iter_files(paths):
        try:
            code = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lang = LANG_EXT.get(f.suffix.lower()) or detect_language(code, f.name)
        _, findings = scanner.scan(code, lang, str(f.as_posix()))
        for v in findings:
            d = to_dump(v)
            d.setdefault("detector", "rule")
            all_findings.append(d)
    return all_findings


async def scan_hybrid(paths: list[str], include_ml_discovery: bool = True) -> list[dict]:
    """Use product CopilotService (same path as API). Falls back to rules if ML unavailable."""
    os.environ.setdefault("LLM_PROVIDER", "heuristic")  # CI: detect only, skip heavy CodeT5
    os.environ["USE_ML_DETECTOR"] = "true"

    from app.core.config import get_settings
    from app.models.schemas import Language, ScanRequest
    from app.services.copilot import CopilotService
    from app.services.ml_models import clear_model_cache

    clear_model_cache()
    settings = get_settings()
    # force detector on even if .env missing in CI
    object.__setattr__(settings, "use_ml_detector", True) if hasattr(settings, "model_copy") else None
    try:
        settings.use_ml_detector = True  # type: ignore[attr-defined]
    except Exception:
        pass

    svc = CopilotService(settings)
    det = svc._get_detector()
    ml_ok = bool(det and det is not False and getattr(det, "available", False))
    if not ml_ok:
        print("[warn] Hybrid requested but detector checkpoint missing/unavailable → rule-only")
        print(f"[warn] expected: {CKPT}")
        return scan_rule(paths)

    print(f"[info] hybrid CI using CodeBERT checkpoint: {CKPT}")
    all_findings: list[dict] = []
    for f in iter_files(paths):
        try:
            code = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lang_s = LANG_EXT.get(f.suffix.lower()) or detect_language(code, f.name)
        try:
            lang = Language(lang_s)
        except Exception:
            lang = Language.AUTO
        result = await svc.scan(
            ScanRequest(
                code=code,
                language=lang,
                filename=f.as_posix(),
                include_explanations=False,
                include_fixes=False,
            )
        )
        if not include_ml_discovery:
            result.vulnerabilities = [
                v
                for v in result.vulnerabilities
                if getattr(v, "detector", None) not in ("ml", "ml-discovery")
            ]
        for v in result.vulnerabilities:
            d = to_dump(v)
            all_findings.append(d)
    return all_findings


def write_outputs(all_findings: list[dict], json_out: Path | None, sarif: Path | None) -> None:
    by_sev: dict[str, int] = {}
    for v in all_findings:
        by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
        det = v.get("detector", "rule")
        print(
            f"[{v['severity'].upper()}] detector={det} "
            f"{v.get('file')}:{v.get('start_line')} {v.get('rule_id')} — {v.get('title')}"
        )
    print(f"\nTotal: {len(all_findings)}  counts={by_sev}")

    if json_out:
        json_out.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")

    if sarif:
        payload = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecureCode Copilot",
                            "informationUri": "https://github.com/",
                            "version": "hybrid" if any(v.get("detector") == "hybrid" for v in all_findings) else "rule",
                        }
                    },
                    "results": [
                        {
                            "ruleId": v["rule_id"],
                            "level": "error" if v["severity"] in FAIL_SEV else "warning",
                            "message": {"text": f"{v['title']}: {v.get('message', '')}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": v.get("file", "")},
                                        "region": {"startLine": v.get("start_line", 1)},
                                    }
                                }
                            ],
                            "properties": {"detector": v.get("detector", "rule")},
                        }
                        for v in all_findings
                    ],
                }
            ],
        }
        sarif.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="SecureCode Copilot CI scanner")
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low"])
    ap.add_argument("--mode", default="rule", choices=["rule", "hybrid"], help="rule (default) or hybrid ML")
    ap.add_argument("--sarif", type=Path, default=None)
    ap.add_argument("--json-out", type=Path, default=None)
    ap.add_argument("--ml-discovery", action="store_true", help="Hybrid: also emit ML-only windows (noisier)")
    args = ap.parse_args()

    fail_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold = fail_rank[args.fail_on]

    if args.mode == "hybrid":
        # Default CI hybrid = score/filter rule hits with CodeBERT (low noise).
        # Pass --ml-discovery to also surface ML-only windows.
        all_findings = asyncio.run(scan_hybrid(args.paths, include_ml_discovery=args.ml_discovery))
    else:
        all_findings = scan_rule(args.paths)

    write_outputs(all_findings, args.json_out, args.sarif)

    should_fail = any(fail_rank.get(v["severity"], 99) <= threshold for v in all_findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
