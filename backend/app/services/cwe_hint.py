"""Lightweight CWE/OWASP hints for ML-discovery windows.

CodeBERT is binary (vuln/safe) — it does **not** emit a CWE. Assigning a single
fixed CWE (e.g. CWE-1035 / A06) to every ML hit is semantically wrong.

Strategy:
  1. Score soft pattern families on the discovered chunk (not full RuleScanner match).
  2. If best family score >= HINT_MIN_CONFIDENCE → emit that CWE/OWASP/title.
  3. Otherwise → CWE-Unknown / Unclassified (honest “needs review”).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


HINT_MIN_CONFIDENCE = 0.55


@dataclass(frozen=True)
class CweHint:
    family: str
    cwe: str
    owasp: str
    title: str
    score: float
    evidence: str = ""


UNKNOWN = CweHint(
    family="unknown",
    cwe="CWE-Unknown",
    owasp="Unclassified",
    title="ML-discovered potential vulnerability (unclassified)",
    score=0.0,
    evidence="",
)


# Soft patterns — intentional overlap with rule sinks, but scored (not binary hit).
_FAMILIES: List[Tuple[str, str, str, str, List[Tuple[str, float]]]] = [
    (
        "sqli",
        "CWE-89",
        "A03:2021-Injection",
        "Possible SQL injection (ML region)",
        [
            (r"(?i)\b(execute|executemany|query|raw)\s*\(", 0.25),
            (r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\b", 0.25),
            (r"(?i)(f[\"'].*\bSELECT\b|%\s*\(.*\bSELECT\b|\"\s*\+\s*\w+.*SELECT)", 0.45),
            (r"(?i)(cursor\.execute\([^?]*%|execute\(f[\"'])", 0.5),
        ],
    ),
    (
        "cmdi",
        "CWE-78",
        "A03:2021-Injection",
        "Possible OS command injection (ML region)",
        [
            (r"(?i)\b(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output))\b", 0.4),
            (r"(?i)shell\s*=\s*True", 0.45),
            (r"(?i)(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)", 0.4),
            (r"(?i)\b(child_process|execSync|exec\()\b", 0.35),
        ],
    ),
    (
        "xss",
        "CWE-79",
        "A03:2021-Injection",
        "Possible XSS / HTML injection (ML region)",
        [
            (r"(?i)\.innerHTML\s*=", 0.5),
            (r"(?i)(document\.write|dangerouslySetInnerHTML)", 0.45),
            (r"(?i)(v-html|\[innerHTML\])", 0.4),
        ],
    ),
    (
        "path",
        "CWE-22",
        "A01:2021-Broken Access Control",
        "Possible path traversal (ML region)",
        [
            (r"(?i)(\.\./|\.\.\\)", 0.35),
            (r"(?i)(open\(|Path\(|readFile|FileInputStream).{0,80}\+", 0.35),
            (r"(?i)(send_file|sendfile|include\(|require\()", 0.25),
        ],
    ),
    (
        "deser",
        "CWE-502",
        "A08:2021-Software and Data Integrity Failures",
        "Possible insecure deserialization (ML region)",
        [
            (r"(?i)(pickle\.loads|yaml\.load\(|Marshal\.load|unserialize\(|ObjectInputStream)", 0.55),
            (r"(?i)(BinaryFormatter|JSON\.parse\(.*user)", 0.3),
        ],
    ),
    (
        "secret",
        "CWE-798",
        "A07:2021-Identification and Authentication Failures",
        "Possible hardcoded credential (ML region)",
        [
            (r"(?i)(password|secret|api[_-]?key|token)\s*=\s*['\"][^'\"]{6,}", 0.5),
            (r"(?i)(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})", 0.55),
        ],
    ),
    (
        "eval",
        "CWE-95",
        "A03:2021-Injection",
        "Possible code injection via dynamic eval (ML region)",
        [
            (r"(?i)\beval\s*\(", 0.5),
            (r"(?i)(exec\s*\(|Function\s*\(|setTimeout\([^,]+,\s*[^0])", 0.35),
        ],
    ),
    (
        "buffer",
        "CWE-119",
        "Unclassified",
        "Possible memory / buffer safety issue (ML region)",
        [
            (r"\b(strcpy|strcat|gets|sprintf|scanf)\s*\(", 0.5),
            (r"\b(memcpy|memmove)\s*\(", 0.25),
        ],
    ),
    (
        "ssrf",
        "CWE-918",
        "A10:2021-SSRF",
        "Possible SSRF (ML region)",
        [
            (r"(?i)(requests\.(get|post)|urllib\.request|fetch\(|HttpClient).{0,60}(url|host|target)", 0.35),
            (r"(?i)(axios\.(get|post)|http\.get)\(", 0.25),
        ],
    ),
]


def classify_cwe_hint(code: str, ml_probability: float = 0.0) -> CweHint:
    """Return best CWE hint for an ML-discovered window, or UNKNOWN."""
    text = code or ""
    if len(text.strip()) < 8:
        return UNKNOWN

    best: Optional[CweHint] = None
    for family, cwe, owasp, title, patterns in _FAMILIES:
        score = 0.0
        evidence = []
        for pat, w in patterns:
            if re.search(pat, text):
                score += w
                evidence.append(pat[:40])
        # Cap and slight boost from strong ML probability (still require patterns)
        if score > 0:
            score = min(1.0, score + max(0.0, (ml_probability - 0.85) * 0.15))
        if best is None or score > best.score:
            best = CweHint(
                family=family,
                cwe=cwe,
                owasp=owasp,
                title=title,
                score=float(score),
                evidence=",".join(evidence[:3]),
            )

    if best is None or best.score < HINT_MIN_CONFIDENCE:
        return UNKNOWN

    return best


def format_ml_discovery_message(prob: float, hint: CweHint) -> str:
    base = (
        f"ML discovery (CodeBERT p={prob:.2f}). "
        "This region was flagged without a matching SAST rule — review manually."
    )
    if hint.family == "unknown":
        return (
            base
            + " CWE/OWASP left unclassified (no reliable type signal). "
            "Source=ml-discovery."
        )
    return (
        f"{base} Soft type hint: {hint.cwe} / {hint.owasp} "
        f"(hint_confidence={hint.score:.2f}). Source=ml-discovery."
    )
