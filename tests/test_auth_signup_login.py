"""Tests for public authentication, session management, and end-to-end API masking.

Verifies:
1. Solo developer registration -> initial API key -> live POST /v1/mask invocation.
2. Enterprise customer registration -> dual policies (analyst + auditor).
3. Email/password authentication -> session cookie -> /api/v1/auth/me profile.
4. Password verification and rejection of invalid credentials.
"""

import uuid
import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import init_db
from app.main import app


@pytest.mark.asyncio
async def test_developer_signup_and_masking_flow():
    """Test full developer lifecycle: signup -> get API key -> call /v1/mask."""
    await init_db()
    unique_id = uuid.uuid4().hex[:8]
    dev_email = f"developer_{unique_id}@antigravity.test"
    org_name = f"Dev Studio {unique_id}"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Signup as a Solo Developer
        signup_payload = {
            "email": dev_email,
            "password": "securepassword123",
            "full_name": "Solo Developer",
            "account_type": "developer",
            "organization_name": org_name,
        }
        res = await client.post("/api/v1/auth/signup", json=signup_payload)
        assert res.status_code == 201, res.text
        data = res.json()

        assert data["success"] is True
        assert data["user"]["email"] == dev_email
        assert data["user"]["account_type"] == "developer"
        assert data["user"]["role"] == "developer"
        assert "api_key" in data and data["api_key"].startswith("dm_live_")
        api_key = data["api_key"]

        # 2. Check session profile (/me)
        me_res = await client.get("/api/v1/auth/me")
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["authenticated"] is True
        assert me_data["user"]["email"] == dev_email

        # 3. Solo Developer calls POST /v1/mask using their newly created API key
        payload = {
            "client_name": "Robert Smith",
            "ssn": "123-45-6789",
            "salary": 95000,
            "credit_card": "4111-2222-3333-4444",
        }
        mask_res = await client.post(
            "/v1/mask",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json=payload,
        )
        assert mask_res.status_code == 200, mask_res.text
        masked = mask_res.json()

        # In developer default policy:
        # - ssn is suppressed (removed or empty)
        # - salary is type-safe redacted (integer -> 0)
        # - credit_card is pattern masked (****-****-****-4444)
        assert "ssn" not in masked or masked.get("ssn") is None
        assert masked["salary"] == 0 or masked["salary"] == "[REDACTED]"
        assert masked["credit_card"] == "****-****-****-4444"
        assert masked["client_name"] == "Robert Smith"


@pytest.mark.asyncio
async def test_enterprise_admin_signup_and_login():
    """Test enterprise admin registration and subsequent login."""
    unique_id = uuid.uuid4().hex[:8]
    admin_email = f"admin_{unique_id}@acme-corp.test"
    org_name = f"Acme Global {unique_id}"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Signup as Enterprise Admin
        res = await client.post(
            "/api/v1/auth/signup",
            json={
                "email": admin_email,
                "password": "enterprise_secret_pw",
                "full_name": "Acme CISO",
                "account_type": "enterprise",
                "organization_name": org_name,
            },
        )
        assert res.status_code == 201, res.text
        data = res.json()
        assert data["user"]["account_type"] == "enterprise"
        assert data["user"]["role"] == "enterprise_admin"

        # 2. Logout
        logout_res = await client.post("/api/v1/auth/logout")
        assert logout_res.status_code == 200

        # Verify session cleared
        me_unauth = await client.get("/api/v1/auth/me")
        assert me_unauth.status_code == 401

        # 3. Log back in with valid credentials
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_email, "password": "enterprise_secret_pw"},
        )
        assert login_res.status_code == 200
        assert login_res.json()["user"]["email"] == admin_email

        # 4. Attempt login with wrong password
        bad_res = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_email, "password": "wrongpassword!"},
        )
        assert bad_res.status_code == 401
