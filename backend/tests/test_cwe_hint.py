"""Tests for ML-discovery CWE hint mapping."""

from app.services.cwe_hint import HINT_MIN_CONFIDENCE, UNKNOWN, classify_cwe_hint


def test_sqli_hint():
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    h = classify_cwe_hint(code, ml_probability=0.92)
    assert h.cwe == "CWE-89"
    assert "Injection" in h.owasp
    assert h.score >= HINT_MIN_CONFIDENCE


def test_cmdi_hint():
    code = 'os.system("ping " + host)\nsubprocess.call(cmd, shell=True)'
    h = classify_cwe_hint(code, 0.9)
    assert h.cwe == "CWE-78"


def test_unknown_when_no_signal():
    code = "def add(a, b):\n    return a + b\n"
    h = classify_cwe_hint(code, 0.95)
    assert h.cwe == UNKNOWN.cwe
    assert h.owasp == "Unclassified"


def test_never_default_outdated_components():
    code = "x = 1\ny = x + 2\nprint(y)\n"
    h = classify_cwe_hint(code, 0.99)
    assert h.cwe != "CWE-1035"
    assert "Outdated Components" not in h.owasp
