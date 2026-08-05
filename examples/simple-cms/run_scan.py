"""Hybrid scan for examples/simple-cms."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.models.schemas import Language, ScanRequest  # noqa: E402
from app.services.copilot import CopilotService  # noqa: E402


async def main() -> None:
    svc = CopilotService()
    f = ROOT / "examples" / "simple-cms" / "app.py"
    r = await svc.scan(
        ScanRequest(
            code=f.read_text(encoding="utf-8"),
            language=Language.PYTHON,
            filename="app.py",
            include_explanations=False,
            include_fixes=False,
        )
    )
    print(f"Hybrid Total: {r.vulnerability_count}")
    for v in r.vulnerabilities:
        d = v.model_dump(mode="json")
        print(f"[{d['severity'].upper()}] {d['rule_id']} L{d['start_line']} — {d['title']}")


if __name__ == "__main__":
    asyncio.run(main())
