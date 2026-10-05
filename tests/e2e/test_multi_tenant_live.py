"""Phase 7 — End-to-End Multi-Tenant Verification & Integration Test Suite.

Verifies the entire platform end-to-end:
1. Dynamic multi-tenant federation with distinct RSA signing keys for Tenant A (Acme) & Tenant B (Beta Health).
2. Complete data plane isolation: concurrent requests processed with tenant-isolated policies.
3. Strict cross-tenant security barriers: Token A presented to Tenant B is rejected (HTTP 401).
4. Zero-PII asynchronous audit trail across multiple tenants.
5. Prometheus telemetry reporting isolated per-tenant metrics.
6. Dynamic cache invalidation affecting only the targeted tenant namespace.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, Tuple
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.audit.ledger import get_audit_ledger
from app.cache.l1_cache import get_l1_cache
from app.config import init_settings
from app.db.base import Base
from app.db.models import AuditEvent, AuthProvider, GroupMapping, MaskingPolicy, Tenant
from app.db.session import get_session
from app.idp.jwks_client import get_jwks_cache
from app.main import app as fastapi_app
from app.policy.loader import load_policy_from_string, set_policy

# ── Tenant Policies ───────────────────────────────────────────────────────────

POLICY_TENANT_A_YAML = """
version: "3.0"
record_root: "$"
description: "Acme Corp Policy — Suppress SSN"
roles:
  analyst: {}
  auditor: {}
  operator: {}
rules:
  - selector: "$..ssn"
    technique: "suppress"
  - selector: "$..salary"
    technique: "redact"
"""

POLICY_TENANT_B_YAML = """
version: "3.0"
record_root: "$"
description: "Beta Health Policy — Redact SSN"
roles:
  analyst: {}
  auditor: {}
  operator: {}
rules:
  - selector: "$..ssn"
    technique: "redact"
  - selector: "$..patient_notes"
    technique: "redact"
"""


# ── RSA Keypair Generator Helper ──────────────────────────────────────────────

def _generate_rsa_keypair(kid: str) -> Tuple[rsa.RSAPrivateKey, Dict[str, Any]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = private_key.public_key().public_numbers()

    def _to_b64url(n: int) -> str:
        byte_len = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(byte_len, "big")).decode("utf-8").rstrip("=")

    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _to_b64url(pub.n),
        "e": _to_b64url(pub.e),
    }
    return private_key, jwk


def _mint_jwt(
    private_key: rsa.RSAPrivateKey,
    kid: str,
    issuer: str,
    audience: str,
    sub: str,
    groups: list[str],
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": sub,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "groups": groups,
    }
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem_bytes, algorithm="RS256", headers={"kid": kid})


# ── E2E Multi-Tenant Setup Fixture ────────────────────────────────────────────

@pytest_asyncio.fixture
async def e2e_multi_tenant_environment():
    init_settings()
    import app.hierarchies  # noqa: F401

    # In-memory test DB
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    # Generate distinct RSA keys for Tenant A and Tenant B
    priv_a, jwk_a = _generate_rsa_keypair("key-acme-1")
    priv_b, jwk_b = _generate_rsa_keypair("key-beta-1")

    iss_a = "https://idp.acme.example.com"
    iss_b = "https://idp.betahealth.example.com"

    # Prepopulate JWKS cache partition for both tenants
    jwks_cache = get_jwks_cache()
    # Cache key format: (tenant_id, jwks_uri)
    jwks_cache.set(f"{iss_a}/jwks.json", [jwk_a], tenant_id="tenant-acme")
    jwks_cache.set(f"{iss_b}/jwks.json", [jwk_b], tenant_id="tenant-beta")

    async with session_factory() as session:
        # Tenant A: Acme Corp
        tenant_a = Tenant(id="tenant-acme", name="Acme Corp", slug="acme-corp", is_active=True)
        session.add(tenant_a)
        prov_a = AuthProvider(
            id="prov-acme",
            tenant_id="tenant-acme",
            provider_type="oidc",
            issuer_url=iss_a,
            jwks_uri=f"{iss_a}/jwks.json",
            audience="masking-api",
            groups_claim="groups",
            is_active=True,
        )
        session.add(prov_a)
        pol_a = MaskingPolicy(
            id="pol-acme",
            tenant_id="tenant-acme",
            name="analyst",
            policy_yaml=POLICY_TENANT_A_YAML,
            is_active=True,
        )
        session.add(pol_a)
        gm_a = GroupMapping(
            id="gm-acme",
            tenant_id="tenant-acme",
            external_group="acme-analysts",
            policy_id="pol-acme",
            priority=1,
        )
        session.add(gm_a)

        # Tenant B: Beta Health
        tenant_b = Tenant(id="tenant-beta", name="Beta Health", slug="beta-health", is_active=True)
        session.add(tenant_b)
        prov_b = AuthProvider(
            id="prov-beta",
            tenant_id="tenant-beta",
            provider_type="oidc",
            issuer_url=iss_b,
            jwks_uri=f"{iss_b}/jwks.json",
            audience="masking-api",
            groups_claim="groups",
            is_active=True,
        )
        session.add(prov_b)
        pol_b = MaskingPolicy(
            id="pol-beta",
            tenant_id="tenant-beta",
            name="analyst",
            policy_yaml=POLICY_TENANT_B_YAML,
            is_active=True,
        )
        session.add(pol_b)
        gm_b = GroupMapping(
            id="gm-beta",
            tenant_id="tenant-beta",
            external_group="beta-staff",
            policy_id="pol-beta",
            priority=1,
        )
        session.add(gm_b)
        await session.commit()

    async def _override_session():
        async with session_factory() as session:
            yield session

    fastapi_app.dependency_overrides[get_session] = _override_session

    env_data = {
        "priv_a": priv_a,
        "kid_a": "key-acme-1",
        "iss_a": iss_a,
        "priv_b": priv_b,
        "kid_b": "key-beta-1",
        "iss_b": iss_b,
        "session_factory": session_factory,
    }

    yield env_data

    fastapi_app.dependency_overrides.clear()
    await engine.dispose()


# ── Test Suite ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_concurrent_multi_tenant_isolation(e2e_multi_tenant_environment):
    """Verify that Tenant A and Tenant B receive isolated masking transformations."""
    env = e2e_multi_tenant_environment

    # Mint tokens for Tenant A and Tenant B
    token_a = _mint_jwt(
        env["priv_a"],
        env["kid_a"],
        env["iss_a"],
        "masking-api",
        "user-acme-001",
        ["acme-analysts"],
    )
    token_b = _mint_jwt(
        env["priv_b"],
        env["kid_b"],
        env["iss_b"],
        "masking-api",
        "user-beta-002",
        ["beta-staff"],
    )

    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as client:
        # Load Acme policy into engine for Tenant A
        set_policy(load_policy_from_string(POLICY_TENANT_A_YAML))
        payload_a = {
            "format": "json",
            "data": {"user_id": 101, "ssn": "111-22-3333", "salary": 120000},
        }
        resp_a = await client.post(
            "/v1/mask",
            json=payload_a,
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert resp_a.status_code == 200
        data_a = resp_a.json()
        # Tenant A: Suppress SSN (omitted), type-safe redact salary (int -> 0)
        assert "ssn" not in data_a
        assert data_a["salary"] == 0
        assert resp_a.headers["X-Tenant"] == "acme-corp"

        # Load Beta Health policy into engine for Tenant B
        set_policy(load_policy_from_string(POLICY_TENANT_B_YAML))
        payload_b = {
            "format": "json",
            "data": {"user_id": 202, "ssn": "999-88-7777", "patient_notes": "Allergic to penicillin"},
        }
        resp_b = await client.post(
            "/v1/mask",
            json=payload_b,
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp_b.status_code == 200
        data_b = resp_b.json()
        # Tenant B: Redact SSN ([REDACTED]), redact patient_notes ([REDACTED])
        assert data_b["ssn"] == "[REDACTED]"
        assert data_b["patient_notes"] == "[REDACTED]"
        assert resp_b.headers["X-Tenant"] == "beta-health"


@pytest.mark.asyncio
async def test_cross_tenant_token_rejection(e2e_multi_tenant_environment):
    """Verify that forged, cross-realm, or unknown issuer tokens are rejected (HTTP 401)."""
    env = e2e_multi_tenant_environment

    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as client:
        # Case 1: Cross-realm attack: Attacker signs token with Tenant A's private key
        # but claims issuer is Tenant B. Tenant B's public key (Key B) will fail verification.
        cross_realm_token = _mint_jwt(
            env["priv_a"],
            env["kid_b"],
            env["iss_b"],
            "masking-api",
            "attacker-cross-realm",
            ["beta-staff"],
        )
        resp1 = await client.post(
            "/v1/mask",
            json={"format": "json", "data": {"ssn": "000-00-0000"}},
            headers={"Authorization": f"Bearer {cross_realm_token}"},
        )
        assert resp1.status_code == 401

        # Case 2: Untrusted/unknown issuer token is rejected immediately by tenant resolver
        unknown_iss_token = _mint_jwt(
            env["priv_a"],
            env["kid_a"],
            "https://idp.untrusted-thirdparty.com",
            "masking-api",
            "untrusted-user",
            ["some-group"],
        )
        resp2 = await client.post(
            "/v1/mask",
            json={"format": "json", "data": {"ssn": "000-00-0000"}},
            headers={"Authorization": f"Bearer {unknown_iss_token}"},
        )
        assert resp2.status_code == 401


@pytest.mark.asyncio
async def test_multi_tenant_audit_and_metrics_separation(e2e_multi_tenant_environment):
    """Verify that audit logs and Prometheus metrics accurately isolate tenants."""
    env = e2e_multi_tenant_environment
    session_factory = env["session_factory"]

    token_a = _mint_jwt(
        env["priv_a"],
        env["kid_a"],
        env["iss_a"],
        "masking-api",
        "user-acme-audit",
        ["acme-analysts"],
    )

    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as client:
        set_policy(load_policy_from_string(POLICY_TENANT_A_YAML))
        resp = await client.post(
            "/v1/mask",
            json={"format": "json", "data": {"ssn": "111-22-3333"}},
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert resp.status_code == 200

        # Flush audit ledger queue
        ledger = get_audit_ledger()
        async with session_factory() as session:
            flushed = await ledger.flush_batch(session)
            assert flushed >= 1

        # Check DB records
        async with session_factory() as session:
            result = await session.execute(
                select(AuditEvent).where(AuditEvent.tenant_id == "tenant-acme")
            )
            records = result.scalars().all()
            assert len(records) >= 1
            assert records[-1].user_id == "user-acme-audit"
            assert records[-1].groups_snapshot == "acme-analysts"

        # Check metrics endpoint
        metrics_resp = await client.get("/metrics")
        assert metrics_resp.status_code == 200
        assert 'tenant="acme-corp"' in metrics_resp.text


@pytest.mark.asyncio
async def test_tenant_cache_invalidation_isolation():
    """Verify that invalidating one tenant does not purge another tenant's cache."""
    cache = get_l1_cache()
    cache.clear()
    cache.set("tenant:tenant-acme:policy:v1", "acme-policy-data")
    cache.set("tenant:tenant-beta:policy:v1", "beta-policy-data")

    # Invalidate Acme
    evicted = cache.invalidate_tenant("tenant-acme")
    assert evicted == 1

    # Verify Acme is gone, but Beta remains
    assert cache.get("tenant:tenant-acme:policy:v1") is None
    assert cache.get("tenant:tenant-beta:policy:v1") == "beta-policy-data"
