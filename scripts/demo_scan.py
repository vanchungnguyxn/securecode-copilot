#!/usr/bin/env python3
"""Demo: scan all vulnerable examples and print a thesis-friendly summary."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.models.schemas import Language, ScanRequest  # noqa: E402
from app.services.copilot import CopilotService  # noqa: E402


FILES = [
    ("examples/vulnerable/demo.py", Language.PYTHON),
    ("examples/vulnerable/demo.js", Language.JAVASCRIPT),
    ("examples/vulnerable/VulnerableDemo.java", Language.JAVA),
    ("examples/vulnerable/demo.c", Language.C),
]


async def main():
    svc = CopilotService()
    print("=" * 64)
    print(" SecureCode Copilot — Demo Scan")
    print("=" * 64)
    total = 0
    for rel, lang in FILES:
        path = ROOT / rel
        code = path.read_text(encoding="utf-8")
        result = await svc.scan(
            ScanRequest(
                code=code,
                language=lang,
                filename=rel,
                include_explanations=True,
                include_fixes=True,
            )
        )
        total += result.vulnerability_count
        print(f"\n> {rel}  [{result.language}]  findings={result.vulnerability_count}  {result.severity_counts}")
        for v in result.vulnerabilities[:5]:
            print(f"   - L{v.start_line} [{v.severity}] {v.rule_id}: {v.title}")
        if result.fixes:
            first = result.fixes[0].fixed_code.splitlines()[0][:80]
            print(f"   fix example -> {first}")
    print("\n" + "=" * 64)
    print(f" TOTAL vulnerabilities across examples: {total}")
    print("=" * 64)


if __name__ == "__main__":
    asyncio.run(main())
