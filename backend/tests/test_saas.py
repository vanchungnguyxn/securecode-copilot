"""SaaS auth, quota, billing smoke tests."""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


def _email() -> str:
    return f"u_{uuid.uuid4().hex[:10]}@example.com"


@pytest.mark.asyncio
async def test_register_login_me():
    transport = ASGITransport(app=app)
    email = _email()
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Test User",
                "email": email,
                "password": "Test1234!",
                "confirm_password": "Test1234!",
                "accept_terms": True,
            },
        )
        assert r.status_code == 200, r.text
        token = r.json()["access_token"]
        me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["email"] == email
        assert me.json()["plan_code"] == "free"

        login = await client.post("/api/v1/auth/login", json={"email": email, "password": "Test1234!"})
        assert login.status_code == 200


@pytest.mark.asyncio
async def test_plans_public():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/plans")
        assert r.status_code == 200
        codes = {p["code"] for p in r.json()}
        assert {"free", "pro", "team", "enterprise"} <= codes


@pytest.mark.asyncio
async def test_analysis_requires_auth():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/analyses",
            json={"code": 'os.system("x")', "language": "python", "filename": "x.py"},
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_analysis_success_consumes_quota():
    transport = ASGITransport(app=app)
    email = _email()
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reg = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Quota User",
                "email": email,
                "password": "Test1234!",
                "confirm_password": "Test1234!",
                "accept_terms": True,
            },
        )
        token = reg.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        before = (await client.get("/api/v1/auth/me", headers=headers)).json()["used_this_month"]
        r = await client.post(
            "/api/v1/analyses",
            headers=headers,
            json={
                "code": 'SECRET = "abc"\nos.system("ping " + host)\n',
                "language": "python",
                "filename": "demo.py",
                "include_explanations": False,
                "include_fixes": False,
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "completed"
        after = (await client.get("/api/v1/auth/me", headers=headers)).json()["used_this_month"]
        assert after == before + 1


@pytest.mark.asyncio
async def test_mock_billing_upgrade():
    transport = ASGITransport(app=app)
    email = _email()
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reg = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Billing User",
                "email": email,
                "password": "Test1234!",
                "confirm_password": "Test1234!",
                "accept_terms": True,
            },
        )
        token = reg.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        co = await client.post(
            "/api/v1/billing/checkout",
            headers=headers,
            json={"plan_code": "pro", "billing_cycle": "monthly"},
        )
        assert co.status_code == 200, co.text
        txn = co.json()["transaction_id"]
        paid = await client.post(
            "/api/v1/billing/mock-pay",
            headers=headers,
            json={"transaction_id": txn},
        )
        assert paid.status_code == 200, paid.text
        assert paid.json()["plan_code"] == "pro"


@pytest.mark.asyncio
async def test_admin_requires_admin_role():
    transport = ASGITransport(app=app)
    email = _email()
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reg = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Normal",
                "email": email,
                "password": "Test1234!",
                "confirm_password": "Test1234!",
                "accept_terms": True,
            },
        )
        token = reg.json()["access_token"]
        r = await client.get("/api/v1/admin/stats", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403
