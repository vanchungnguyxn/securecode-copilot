"""Metrics for vulnerability-fix evaluation (held-out)."""

from __future__ import annotations

import ast
import math
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def normalize_code(code: str) -> str:
    code = (code or "").strip()
    if code.startswith("```"):
        lines = code.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        code = "\n".join(lines)
    # strip trailing spaces, keep structure
    return "\n".join(ln.rstrip() for ln in code.strip().splitlines())


def exact_match(pred: str, gold: str) -> bool:
    return normalize_code(pred) == normalize_code(gold)


def soft_match_legacy(pred: str, gold: str) -> Tuple[bool, bool]:
    """Legacy weak criterion — report for continuity only, not primary."""
    pn = "".join(normalize_code(pred).split()).lower()
    gn = "".join(normalize_code(gold).split()).lower()
    soft = False
    tok_hit = False
    if pn and (pn == gn or gn[:48] in pn or pn[:48] in gn):
        soft = True
    else:
        gtoks = {t for t in gold.replace("(", " ").replace(")", " ").split() if len(t) > 3}
        ptoks = set(pred.replace("(", " ").replace(")", " ").split())
        if gtoks and len(gtoks & ptoks) / len(gtoks) >= 0.45:
            soft = True
            tok_hit = True
    return soft, tok_hit


def _tokenize(code: str) -> List[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[\(\)\[\]\{\}\.,;=+\-*/<>!]+|\d+", code)


def _ngrams(tokens: Sequence[str], n: int) -> Counter:
    if len(tokens) < n:
        return Counter()
    return Counter(tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1))


def _bleu(pred: str, gold: str, max_n: int = 4) -> float:
    """Corpus-free sentence BLEU with smoothing (for CodeBLEU-approx)."""
    pred_t = _tokenize(normalize_code(pred))
    gold_t = _tokenize(normalize_code(gold))
    if not pred_t or not gold_t:
        return 0.0
    precisions = []
    for n in range(1, max_n + 1):
        pc, gc = _ngrams(pred_t, n), _ngrams(gold_t, n)
        overlap = sum((pc & gc).values())
        total = max(1, sum(pc.values()))
        # add-1 smoothing
        precisions.append((overlap + 1) / (total + 1))
    bp = 1.0 if len(pred_t) > len(gold_t) else math.exp(1 - len(gold_t) / max(1, len(pred_t)))
    score = bp * math.exp(sum(math.log(p) for p in precisions) / max_n)
    return float(score)


def _ast_keyword_match(pred: str, gold: str, language: str) -> float:
    if language != "python":
        # fallback: identifier Jaccard
        pt, gt = set(_tokenize(pred)), set(_tokenize(gold))
        if not pt or not gt:
            return 0.0
        return len(pt & gt) / len(pt | gt)
    try:
        pa = set(_ast_names(normalize_code(pred)))
        ga = set(_ast_names(normalize_code(gold)))
        if not pa or not ga:
            return 0.0
        return len(pa & ga) / len(pa | ga)
    except Exception:
        pt, gt = set(_tokenize(pred)), set(_tokenize(gold))
        return len(pt & gt) / len(pt | gt) if pt and gt else 0.0


def _ast_names(code: str) -> List[str]:
    tree = ast.parse(code)
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, ast.FunctionDef):
            names.append(node.name)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            names.append(node.func.id)
    return names


def codebleu_score(pred: str, gold: str, language: str = "python") -> Dict[str, float]:
    """
    Prefer official `codebleu` package when installed; else transparent approximation:
      0.25*BLEU + 0.25*weighted_ngram + 0.25*AST/keyword + 0.25*dataflow_proxy
    Documented as codebleu_approx when package missing.
    """
    lang = (language or "python").lower()
    lang_map = {
        "python": "python",
        "javascript": "javascript",
        "java": "java",
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",
        "csharp": "c_sharp",
        "php": "php",
    }
    mapped = lang_map.get(lang, "python")
    try:
        from codebleu import calc_codebleu

        res = calc_codebleu(
            [normalize_code(gold)],
            [normalize_code(pred)],
            lang=mapped,
            weights=(0.25, 0.25, 0.25, 0.25),
        )
        return {
            "codebleu": float(res.get("codebleu", 0.0)),
            "backend": "codebleu",
            **{k: float(v) for k, v in res.items() if isinstance(v, (int, float))},
        }
    except Exception:
        bleu = _bleu(pred, gold)
        # weighted ngram: emphasize longer ngrams slightly
        pred_t, gold_t = _tokenize(normalize_code(pred)), _tokenize(normalize_code(gold))
        wps = []
        for n, w in ((1, 0.1), (2, 0.2), (3, 0.3), (4, 0.4)):
            pc, gc = _ngrams(pred_t, n), _ngrams(gold_t, n)
            overlap = sum((pc & gc).values())
            total = max(1, sum(pc.values()))
            wps.append(w * (overlap + 1) / (total + 1))
        weighted = sum(wps)
        syntax = _ast_keyword_match(pred, gold, lang)
        # dataflow proxy: shared assignments / calls
        def flow_toks(code: str) -> Counter:
            return Counter(t for t in _tokenize(code) if len(t) > 2)

        pt, gt = flow_toks(pred), flow_toks(gold)
        inter = sum((pt & gt).values())
        dataflow = inter / max(1, sum(gt.values()))
        score = 0.25 * bleu + 0.25 * weighted + 0.25 * syntax + 0.25 * dataflow
        return {
            "codebleu": float(score),
            "backend": "codebleu_approx",
            "bleu": float(bleu),
            "weighted_ngram": float(weighted),
            "syntax_match": float(syntax),
            "dataflow_match": float(dataflow),
        }


def compile_ok(code: str, language: str) -> Tuple[bool, str]:
    lang = (language or "").lower()
    code = normalize_code(code)
    if not code.strip():
        return False, "empty"
    if lang == "python":
        try:
            ast.parse(code)
            return True, "ast.parse"
        except SyntaxError as e:
            return False, f"SyntaxError: {e}"
    if lang in {"javascript", "typescript"}:
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
                f.write(code)
                path = f.name
            r = subprocess.run(["node", "--check", path], capture_output=True, text=True, timeout=8)
            Path(path).unlink(missing_ok=True)
            return r.returncode == 0, (r.stderr or r.stdout or "node --check")[:200]
        except FileNotFoundError:
            return False, "node not available"
        except Exception as e:
            return False, str(e)
    return False, f"compile N/A for {lang}"


def _run_snippet(module_code: str, test_code: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """Execute module + tests in an isolated Python subprocess (temp file — enables inspect.getsource)."""
    blob = (
        "import re, sys\n"
        + module_code
        + "\n"
        + test_code
        + "\nprint('__OK__')\n"
    )
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(blob)
            path = f.name
        r = subprocess.run(
            [sys.executable, path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        ok = r.returncode == 0 and "__OK__" in (r.stdout or "")
        detail = (r.stderr or r.stdout or "")[-400:]
        return ok, detail
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)
    finally:
        if path:
            Path(path).unlink(missing_ok=True)


def pattern_security_ok(pred: str, forbidden: List[str], required: List[str]) -> Tuple[bool, str]:
    text = normalize_code(pred)
    for pat in forbidden or []:
        if re.search(pat, text, flags=re.IGNORECASE | re.MULTILINE):
            return False, f"forbidden:{pat}"
    for pat in required or []:
        if not re.search(pat, text, flags=re.IGNORECASE | re.MULTILINE):
            return False, f"missing:{pat}"
    return True, "ok"


def rule_scanner_clean(pred: str, language: str) -> Tuple[bool, str]:
    """Security regression: patched code should not retain classic rule hits when possible."""
    try:
        import sys
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        sys.path.insert(0, str(root / "backend"))
        from app.scanners.engine import RuleScanner

        _, findings = RuleScanner().scan(normalize_code(pred), language or "auto")
        # Empty findings = strong win; also accept if fewer critical/high
        n = len(findings)
        return n == 0, f"findings={n}"
    except Exception as e:
        return False, f"scanner_error:{e}"


def evaluate_case_static(pred: str, case: Dict[str, Any]) -> Dict[str, Any]:
    gold = case.get("secure_reference") or ""
    lang = case.get("language") or "python"
    em = exact_match(pred, gold)
    soft, tok_hit = soft_match_legacy(pred, gold)
    cb = codebleu_score(pred, gold, lang)
    can_compile = bool(case.get("has_compile"))
    cok, cdetail = compile_ok(pred, lang) if can_compile else (None, "skipped")
    return {
        "exact_match": em,
        "soft_match_legacy": soft,
        "token_overlap_legacy": tok_hit,
        "codebleu": cb["codebleu"],
        "codebleu_backend": cb.get("backend"),
        "compile_ok": cok,
        "compile_detail": cdetail,
    }


def evaluate_case_dynamic(pred: str, case: Dict[str, Any]) -> Dict[str, Any]:
    """Unit / security / functional pass rates for curated executable cases."""
    lang = case.get("language") or "python"
    out: Dict[str, Any] = {
        "unit_pass": None,
        "security_pass": None,
        "functional_pass": None,
        "security_pattern_pass": None,
        "scanner_clean": None,
    }
    if lang != "python":
        return out

    pred_n = normalize_code(pred)

    # Pattern-based security (always when configured)
    if case.get("forbidden_patterns") or case.get("required_patterns"):
        pok, pdet = pattern_security_ok(
            pred_n, case.get("forbidden_patterns") or [], case.get("required_patterns") or []
        )
        out["security_pattern_pass"] = pok
        out["security_pattern_detail"] = pdet

    # Rule scanner regression (best-effort)
    sok, sdet = rule_scanner_clean(pred_n, lang)
    out["scanner_clean"] = sok
    out["scanner_detail"] = sdet

    if case.get("unit_tests"):
        uok, udet = _run_snippet(pred_n, case["unit_tests"])
        out["unit_pass"] = uok
        out["unit_detail"] = udet[-300:]
    if case.get("security_tests"):
        # inject re for convenience
        sec = "import re\n" + case["security_tests"]
        sok2, sdet2 = _run_snippet(pred_n, sec)
        out["security_pass"] = sok2
        out["security_detail"] = sdet2[-300:]
    if case.get("functional_tests"):
        fok, fdet = _run_snippet(pred_n, case["functional_tests"])
        out["functional_pass"] = fok
        out["functional_detail"] = fdet[-300:]

    # Combined security: executable security test if present else pattern + scanner
    if out["security_pass"] is not None:
        out["security_combined"] = bool(out["security_pass"])
    else:
        parts = [p for p in (out["security_pattern_pass"], out["scanner_clean"]) if p is not None]
        out["security_combined"] = all(parts) if parts else None

    return out
