"""Scan examples/naive-notes with hybrid pipeline."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.models.schemas import Language, ScanRequest  # noqa: E402
from app.services.copilot import CopilotService  # noqa: E402


async def main() -> None:
    shop = ROOT / "examples" / "naive-notes"
    svc = CopilotService()
    files = sorted(shop.rglob("*.py"))
    allv: list[dict] = []
    for f in files:
        code = f.read_text(encoding="utf-8", errors="ignore")
        rel = str(f.relative_to(shop)).replace("\\", "/")
        r = await svc.scan(
            ScanRequest(
                code=code,
                language=Language.PYTHON,
                filename=rel,
                include_explanations=False,
                include_fixes=False,
            )
        )
        for v in r.vulnerabilities:
            d = v.model_dump(mode="json")
            allv.append(d)
            print(
                f"[{d['severity'].upper()}] detector={d.get('detector')} "
                f"{d['file']}:{d['start_line']} {d['rule_id']} — {d['title']}"
            )
    by_sev: dict[str, int] = {}
    for v in allv:
        by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
    print(f"\nHybrid Total: {len(allv)}  counts={by_sev or '{}'}")
    out = shop / "scan_hybrid.json"
    out.write_text(json.dumps(allv, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    asyncio.run(main())
