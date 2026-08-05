"""Orchestrates scan → explain → fix + repo-level analysis."""

from __future__ import annotations

import hashlib
import re
import tempfile
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Optional

from app.core.config import Settings, get_settings
from app.models.schemas import (
    ApplyFixResponse,
    Explanation,
    FixSuggestion,
    Language,
    RepoScanRequest,
    RepoScanResult,
    ScanRequest,
    ScanResult,
    Severity,
    Vulnerability,
)
from app.scanners.engine import RuleScanner
from app.services.llm import BaseLLM, get_llm, _replace_lines
from app.services.repo_ingest import context_window, download_github_zip, extract_zip_bytes, iter_source_files


class CopilotService:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.scanner = RuleScanner()
        self.llm: BaseLLM = get_llm(self.settings)
        self._detector = None

    def _get_detector(self):
        if self._detector is not None:
            return self._detector
        try:
            from app.services.ml_models import get_detector

            self._detector = get_detector()
        except Exception:
            self._detector = False
        return self._detector

    def _score_context(self, code: str, vuln: Vulnerability) -> float:
        det = self._get_detector()
        if not det or det is False or not getattr(det, "available", False):
            return vuln.confidence
        ctx = context_window(code, vuln.start_line, vuln.end_line, pad=14)
        text = ctx or vuln.snippet or ""
        try:
            prob, _ = det.predict(text)
            return float(prob)
        except Exception:
            return vuln.confidence

    def _filter_false_positives(self, code: str, vulns: list[Vulnerability]) -> tuple[list[Vulnerability], dict]:
        """Suppress rule hits when contextual ML score says confident SAFE.

        High/critical: suppress if p < safe_cutoff (raised for secret/auth rules).
        Medium/low: also require p >= confirm_thr to keep (stricter → lower FPR).
        """
        det = self._get_detector()
        meta = {"ml_detector": False, "suppressed_fp": 0, "safe_cutoff": None, "confirm_thr": None, "scored": 0}
        if not det or det is False or not getattr(det, "available", False):
            return vulns, meta

        try:
            from app.services.ml_models import load_safe_cutoff, load_threshold

            safe_cutoff = load_safe_cutoff()
            confirm_thr = min(0.72, max(safe_cutoff + 0.15, load_threshold() * 0.85))
        except Exception:
            safe_cutoff = 0.45
            confirm_thr = 0.65

        # Slightly more aggressive FP suppress for product (secrets / soft auth noise)
        safe_cutoff = min(0.55, float(safe_cutoff) + 0.05)
        confirm_thr = max(confirm_thr, safe_cutoff + 0.12)

        meta["ml_detector"] = True
        meta["safe_cutoff"] = safe_cutoff
        meta["confirm_thr"] = confirm_thr
        kept = []
        # Soft auth/config noise — ML may suppress. Critical sinks should almost never be dropped.
        soft_rules = ("HARDCODE", "CORS", "DEBUG", "SECRET", "PLAINPWD")
        hard_rules = ("SQLI", "CMDI", "DESER", "EVAL", "XSS", "PATH", "XXE", "SSTI", "RCE", "TRAVERSAL")
        for v in vulns:
            try:
                prob = self._score_context(code, v)
                meta["scored"] += 1
            except Exception:
                kept.append(v)
                continue
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            rid = (v.rule_id or "").upper()
            is_soft = any(s in rid for s in soft_rules)
            is_hard = any(s in rid for s in hard_rules)

            # Context-aware: env/f-string secret construction → treat as safer
            snip = (v.snippet or "") + "\n" + context_window(code, v.start_line, v.end_line, pad=6)
            looks_env_safe = bool(
                re.search(r"os\.(?:getenv|environ)|process\.env|\{[A-Z][A-Z0-9_]*\}", snip)
            )
            # process.env.X || 'hardcoded-fallback' is NOT safe (common vibe-code anti-pattern)
            if re.search(
                r"(?:process\.env(?:\.\w+)?|os\.environ(?:\[[^\]]+\])?|os\.getenv\([^\)]*\))"
                r"[^\n]{0,100}\|\|\s*['\"][^'\"]{4,}",
                snip,
            ):
                looks_env_safe = False
            # Plain string assignment of secret (no env) stays unsafe
            if re.search(
                r"(?:secret|password|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
                snip,
                re.I,
            ) and not re.search(r"process\.env|os\.(?:getenv|environ)", snip):
                looks_env_safe = False
            local_cutoff = safe_cutoff + (0.08 if looks_env_safe and is_soft else 0.0)

            # Hard sinks (SQLi/RCE/deser/...): never let ML suppress rule hits
            if is_hard and not is_soft:
                v.confidence = max(v.confidence, float(prob))
                v.detector = "hybrid"
                kept.append(v)
                continue

            # Soft auth/config: only suppress when truly env-sourced (no literal fallback)
            if is_soft and looks_env_safe and prob < 0.62:
                meta["suppressed_fp"] += 1
                continue
            if is_soft and not looks_env_safe and any(s in rid for s in ("HARDCODE", "SECRET", "PLAINPWD")):
                # Keep hardcoded / fallback secrets regardless of weak ML score
                v.confidence = max(v.confidence, float(prob))
                v.detector = "hybrid"
                kept.append(v)
                continue
            if is_soft and prob < local_cutoff:
                meta["suppressed_fp"] += 1
                continue
            if sev in {"medium", "low", "info"} and is_soft and prob < confirm_thr:
                meta["suppressed_fp"] += 1
                continue
            if (not is_soft) and prob < max(0.25, safe_cutoff - 0.2):
                meta["suppressed_fp"] += 1
                continue
            v.confidence = max(v.confidence, float(prob))
            v.detector = "hybrid"
            kept.append(v)
        return kept, meta

    def _ml_discover(self, code: str, language: str, filename: Optional[str], existing: list[Vulnerability]) -> list[Vulnerability]:
        """Sliding-window ML discovery — optional; precision-oriented threshold."""
        det = self._get_detector()
        if not det or det is False or not getattr(det, "available", False):
            return []
        try:
            from app.services.ml_models import load_threshold

            thr = load_threshold()
        except Exception:
            thr = 0.80

        # Never discover below 0.78 — hard FPR floor for product
        thr = max(0.78, float(thr))

        lines = code.splitlines()
        if len(lines) < 3:
            return []
        occupied = {(v.start_line, v.end_line) for v in existing}
        found: list[Vulnerability] = []
        window = 20
        step = 12
        for start in range(0, len(lines), step):
            end = min(len(lines), start + window)
            chunk = "\n".join(lines[start:end])
            if len(chunk.strip()) < 40:
                continue
            try:
                prob, is_vuln = det.predict(chunk)
            except Exception:
                continue
            if (not is_vuln) or prob < thr:
                continue
            sl, el = start + 1, end
            if any(abs(sl - a) < 8 for a, _ in occupied):
                continue
            occupied.add((sl, el))
            vid = hashlib.sha1(f"ML-{filename}-{sl}-{chunk[:80]}".encode()).hexdigest()[:12]
            found.append(
                Vulnerability(
                    id=vid,
                    rule_id="ML-CONTEXT-001",
                    title="ML-detected potential vulnerability",
                    severity=Severity.HIGH if prob >= 0.85 else Severity.MEDIUM,
                    cwe="CWE-1035",
                    owasp="A06:2021-Vulnerable and Outdated Components",
                    language=language,
                    file=filename,
                    start_line=sl,
                    end_line=el,
                    snippet="\n".join(lines[start:min(end, start + 8)]),
                    message=f"CodeBERT scored this region as vulnerable (p={prob:.2f}). Review for injection/unsafe APIs.",
                    confidence=float(prob),
                    detector="ml",
                )
            )
            if len(found) >= 5:
                break
        return found

    async def scan(self, req: ScanRequest) -> ScanResult:
        t0 = time.perf_counter()
        language, vulns = self.scanner.scan(
            code=req.code,
            language=req.language.value if req.language else "auto",
            filename=req.filename,
        )

        use_ml = (self.settings.llm_provider or "").lower() == "local" or self.settings.use_ml_detector
        fp_meta: dict = {}
        if use_ml:
            vulns, fp_meta = self._filter_false_positives(req.code, vulns)
            # ML discovery OFF by default (USE_ML_DISCOVERY=true to enable)
            if getattr(self.settings, "use_ml_discovery", False):
                extra = self._ml_discover(req.code, language, req.filename, vulns)
                vulns.extend(extra)
                fp_meta["ml_discovered"] = len(extra)
            else:
                fp_meta["ml_discovered"] = 0
                fp_meta["ml_discovery_enabled"] = False

        explanations: list[Explanation] = []
        fixes: list[FixSuggestion] = []

        # Limit heavy LLM/explain on huge repos: caller controls flags
        if req.include_explanations:
            for v in vulns[:80]:
                explanations.append(await self.llm.explain(req.code, v))

        if req.include_fixes:
            for v in vulns[:80]:
                fixes.append(await self.llm.fix(req.code, v))

        counts = Counter(v.severity.value for v in vulns)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            language=language,
            filename=req.filename,
            vulnerability_count=len(vulns),
            severity_counts=dict(counts),
            vulnerabilities=vulns,
            explanations=explanations,
            fixes=fixes,
            source_code=req.code,
            meta={
                "elapsed_ms": elapsed_ms,
                "llm_provider": self.settings.llm_provider,
                "detector": "hybrid-rule-codebert-context" if fp_meta.get("ml_detector") else "rule",
                **fp_meta,
            },
        )

    async def scan_repo(self, req: RepoScanRequest, zip_bytes: Optional[bytes] = None) -> RepoScanResult:
        t0 = time.perf_counter()
        tmp = tempfile.mkdtemp(prefix="scc-repo-")
        root = Path(tmp)
        source = "unknown"
        try:
            if zip_bytes:
                work = extract_zip_bytes(zip_bytes, root)
                source = "zip-upload"
            elif req.github_url:
                work = await download_github_zip(req.github_url, root)
                source = req.github_url
            else:
                raise ValueError("Provide github_url or zip upload")

            files = iter_source_files(work, max_files=req.max_files)
            results: list[ScanResult] = []
            all_vulns: list[Vulnerability] = []
            code_by_file: dict[str, str] = {}

            # Pass 1: detect thoroughly (no explain/fix yet — faster & covers more files)
            for f in files:
                lang = Language(f["language"]) if f["language"] in Language._value2member_map_ else Language.AUTO
                one = await self.scan(
                    ScanRequest(
                        code=f["code"],
                        language=lang,
                        filename=f["path"],
                        include_explanations=False,
                        include_fixes=False,
                    )
                )
                if not req.ml_discovery:
                    one.vulnerabilities = [v for v in one.vulnerabilities if v.detector != "ml"]
                    one.vulnerability_count = len(one.vulnerabilities)
                    # recompute severity after filter
                    one.severity_counts = dict(Counter(v.severity.value for v in one.vulnerabilities))
                # ensure file path stamped
                for v in one.vulnerabilities:
                    if not v.file:
                        v.file = f["path"]
                results.append(one)
                all_vulns.extend(one.vulnerabilities)
                code_by_file[f["path"]] = f["code"]

            # Pass 2: explain + fix for top findings (by severity)
            enriched = 0
            max_enrich = int(getattr(req, "max_enrich", 80) or 80)
            sev_rank = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFO: 4,
            }
            ranked = sorted(all_vulns, key=lambda v: (sev_rank.get(v.severity, 9), v.start_line))
            by_id_result = {v.id: r for r in results for v in r.vulnerabilities}

            if req.include_explanations or req.include_fixes:
                for v in ranked[:max_enrich]:
                    code = code_by_file.get(v.file or "", "")
                    if not code:
                        # fall back: find matching result
                        host = by_id_result.get(v.id)
                        code = (host.source_code if host else "") or ""
                    if not code:
                        continue
                    host = by_id_result.get(v.id)
                    if req.include_explanations:
                        expl = await self.llm.explain(code, v)
                        if host is not None:
                            host.explanations.append(expl)
                    if req.include_fixes:
                        fx = await self.llm.fix(code, v)
                        if host is not None:
                            host.fixes.append(fx)
                    enriched += 1

            sev = Counter(v.severity.value for v in all_vulns)
            return RepoScanResult(
                scan_id=str(uuid.uuid4()),
                source=source,
                file_count=len(files),
                scanned_files=len(results),
                vulnerability_count=len(all_vulns),
                severity_counts=dict(sev),
                results=results,
                meta={
                    "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                    "llm_provider": self.settings.llm_provider,
                    "mode": "repo-context-hybrid",
                    "files_considered": len(files),
                    "enriched_findings": enriched,
                    "max_enrich": max_enrich,
                    "include_explanations": req.include_explanations,
                    "include_fixes": req.include_fixes,
                },
            )
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)

    async def explain(self, code: str, vuln: Vulnerability) -> Explanation:
        return await self.llm.explain(code, vuln)

    async def fix(self, code: str, vuln: Vulnerability) -> FixSuggestion:
        return await self.llm.fix(code, vuln)

    def apply_fix(self, code: str, fixed_snippet: str, start_line: int, end_line: int) -> ApplyFixResponse:
        return ApplyFixResponse(code=_replace_lines(code, start_line, end_line, fixed_snippet))
