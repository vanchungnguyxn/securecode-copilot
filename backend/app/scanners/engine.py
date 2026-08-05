"""Rule-based multi-language vulnerability scanner."""

from __future__ import annotations

import hashlib
import re
from typing import List, Optional, Tuple

from app.models.schemas import Severity, Vulnerability
from app.scanners.rules import Rule, detect_language, rules_for_language


def _line_col_from_pos(code: str, pos: int) -> Tuple[int, int]:
    line = code.count("\n", 0, pos) + 1
    last_nl = code.rfind("\n", 0, pos)
    col = pos - last_nl
    return line, col


def _snippet_for_line(code: str, line: int, context: int = 0) -> str:
    lines = code.splitlines()
    idx = max(0, line - 1)
    start = max(0, idx - context)
    end = min(len(lines), idx + context + 1)
    return "\n".join(lines[start:end])


def _vid(rule_id: str, start_line: int, snippet: str) -> str:
    raw = f"{rule_id}:{start_line}:{snippet.strip()}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _excluded(rule: Rule, matched: str) -> bool:
    for pat in rule.exclude_patterns:
        if re.search(pat, matched, re.I):
            return True
    return False


class RuleScanner:
    """Static pattern scanner covering OWASP-aligned CWE rules."""

    def scan(
        self,
        code: str,
        language: str = "auto",
        filename: Optional[str] = None,
    ) -> Tuple[str, List[Vulnerability]]:
        if not language or language == "auto":
            language = detect_language(code, filename)

        rules = rules_for_language(language)
        # typescript shares JS rule set
        if language == "typescript":
            rules = rules_for_language("javascript")

        findings: List[Vulnerability] = []
        seen = set()

        for rule in rules:
            for pattern in rule.compiled():
                for match in pattern.finditer(code):
                    matched = match.group(0)
                    if _excluded(rule, matched):
                        continue
                    start_line, start_col = _line_col_from_pos(code, match.start())
                    end_line, end_col = _line_col_from_pos(code, match.end())
                    snippet = _snippet_for_line(code, start_line)
                    key = (rule.rule_id, start_line, snippet.strip())
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Vulnerability(
                            id=_vid(rule.rule_id, start_line, snippet),
                            rule_id=rule.rule_id,
                            title=rule.title,
                            severity=Severity(rule.severity),
                            cwe=rule.cwe,
                            owasp=rule.owasp,
                            language=language,
                            file=filename,
                            start_line=start_line,
                            end_line=end_line,
                            start_col=start_col,
                            end_col=end_col,
                            snippet=snippet,
                            message=rule.message,
                            confidence=rule.confidence,
                            detector="rule",
                        )
                    )

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda v: (severity_order[v.severity], v.start_line))
        return language, findings
