import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.scanners.engine import RuleScanner


@pytest.mark.asyncio
async def test_health():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


def test_python_sqli_detection():
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
'''
    lang, findings = RuleScanner().scan(code, "python", "app.py")
    assert lang == "python"
    assert any("SQLI" in f.rule_id for f in findings)


def test_js_xss_detection():
    code = "el.innerHTML = userInput;"
    lang, findings = RuleScanner().scan(code, "javascript", "a.js")
    assert any("XSS" in f.rule_id for f in findings)


def test_java_sqli_detection():
    code = '''
String q = "SELECT * FROM users WHERE id = " + userId;
Statement st = conn.createStatement();
st.executeQuery(q);
'''
    _, findings = RuleScanner().scan(code, "java", "A.java")
    assert any("SQLI" in f.rule_id for f in findings)


def test_c_buffer_overflow():
    code = '''
#include <stdio.h>
void f(char *src) {
    char buf[16];
    strcpy(buf, src);
}
'''
    _, findings = RuleScanner().scan(code, "c", "a.c")
    assert any("BOF" in f.rule_id for f in findings)


@pytest.mark.asyncio
async def test_scan_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/scan",
            json={
                "code": 'os.system("ls " + user)',
                "language": "python",
                "filename": "x.py",
                "include_explanations": True,
                "include_fixes": True,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["vulnerability_count"] >= 1
        assert len(data["explanations"]) >= 1
        assert len(data["fixes"]) >= 1
