"""Phase 6 — Test Suite for Enterprise Zero-PII Audit Ledger & Prometheus Telemetry.

Verifies:
1. PII detection heuristics (SSN, email, credit card) and redaction.
2. Non-blocking AsyncAuditLedger enqueue and batch database persistence.
3. Strict zero-PII guarantees in AuditEvent persistence.
4. Prometheus metrics recording and GET /metrics exposition endpoint.
5. End-to-end integration: POST /v1/mask updates audit ledger and Prometheus counters.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.audit.ledger import AsyncAuditLedger, contains_pii, get_audit_ledger
from app.db.base import Base
from app.db.models import AuditEvent, AuthProvider, GroupMapping, MaskingPolicy, Tenant
from app.db.session import get_session
from app.main import app as fastapi_app
from app.policy.loader import load_policy_from_string, set_policy
from app.telemetry.metrics import (
    get_prometheus_metrics_payload,
    record_cache_hit,
    record_cache_miss,
    record_rate_limit_exceeded,
    record_request_metric,
)

DEFAULT_POLICY_YAML = """
version: "3.0"
record_root: "$"
description: "Audit test policy"
roles:
  analyst: {}
  auditor: {}
  operator: {}
rules:
  - selector: "$..ssn"
    technique: "suppress"
  - selector: "$..email"
    technique: "redact"
"""


# ── Unit Tests: Zero-PII Detection Heuristic ─────────────────────────────────

def test_contains_pii_detection():
    # Clean text
    assert not contains_pii(None)
    assert not contains_pii("")
    assert not contains_pii("user_12345")
    assert not contains_pii("engineering-group")
    assert not contains_pii("analysts,auditors")

    # SSN pattern
    assert contains_pii("123-45-6789")
    assert contains_pii("prefix 000-12-3456 suffix")

    # Email pattern
    assert contains_pii("alice@example.com")
    assert contains_pii("user.name+tag@sub.domain.org")

    # Credit card pattern
    assert contains_pii("4111-2222-3333-4444")
    assert contains_pii("5555 4444 3333 2222")


# ── Test AsyncAuditLedger Batch Flushing & Redaction ──────────────────────────

@pytest.mark.asyncio
async def test_audit_ledger_persistence_and_redaction():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    ledger = AsyncAuditLedger(queue_max_size=100)

    # 1. Record clean event
    ledger.record_event(
        tenant_id="tenant-alpha",
        user_id="usr_clean_123",
        groups=["analyst", "engineering"],
        policy_name="v3.0",
        fmt="json",
        execution_time_ms=12,
        request_id="req-clean-001",
    )

    # 2. Record event containing sensitive PII in user_id and groups
    ledger.record_event(
        tenant_id="tenant-alpha",
        user_id="ssn-123-45-6789-leaked",
        groups=["auditor", "victim@company.com"],
        policy_name="v3.0",
        fmt="xml",
        execution_time_ms=25,
        request_id="req-dirty-002",
    )

    # Flush batch directly with custom session
    async with session_factory() as session:
        count = await ledger.flush_batch(session, max_batch_size=10)
        assert count == 2

    # Query DB and verify stored events
    async with session_factory() as session:
        result = await session.execute(select(AuditEvent).order_by(AuditEvent.request_id))
        events = result.scalars().all()
        assert len(events) == 2

        # Verify clean event
        e1 = events[0]
        assert e1.tenant_id == "tenant-alpha"
        assert e1.user_id == "usr_clean_123"
        assert e1.groups_snapshot == "analyst,engineering"
        assert e1.policy_name == "v3.0"
        assert e1.format == "json"
        assert e1.execution_time_ms == 12
        assert e1.request_id == "req-clean-001"

        # Verify dirty event was redacted
        e2 = events[1]
        assert e2.tenant_id == "tenant-alpha"
        assert e2.user_id == "[REDACTED_PII]"
        assert e2.groups_snapshot == "[REDACTED_PII]"
        assert e2.policy_name == "v3.0"
        assert e2.format == "xml"
        assert e2.execution_time_ms == 25
        assert e2.request_id == "req-dirty-002"

    await engine.dispose()


# ── Test Prometheus Telemetry Helpers & Exposition ───────────────────────────

@pytest.mark.asyncio
async def test_prometheus_metrics_helpers_and_route():
    # Trigger helper functions
    record_request_metric(
        tenant="tenant-telemetry",
        role="analyst",
        fmt="json",
        status="200",
        duration_s=0.045,
    )
    record_cache_hit("l1", tenant="tenant-telemetry")
    record_cache_miss("l1", tenant="tenant-telemetry")
    record_rate_limit_exceeded(tenant="tenant-telemetry")

    # Direct payload verification
    payload, content_type = get_prometheus_metrics_payload()
    payload_str = payload.decode("utf-8")
    assert "masking_requests_total" in payload_str
    assert "masking_latency_seconds" in payload_str
    assert "masking_cache_hits_total" in payload_str
    assert "masking_cache_misses_total" in payload_str
    assert "masking_rate_limit_exceeded_total" in payload_str

    # Test HTTP GET /metrics endpoint
    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as client:
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        body = resp.text
        assert "masking_requests_total" in body
        assert 'tenant="tenant-telemetry"' in body


# ── Test End-to-End Masking triggers Audit & Metrics ─────────────────────────

@pytest_asyncio.fixture
async def audit_e2e_setup():
    from app.config import init_settings
    init_settings()
    import app.hierarchies  # noqa: F401
    pol = load_policy_from_string(DEFAULT_POLICY_YAML)
    set_policy(pol)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    async with session_factory() as session:
        t = Tenant(id="tenant-e2e-audit", name="Audit Corp", slug="audit-corp", is_active=True)
        session.add(t)
        prov = AuthProvider(
            id="prov-e2e-audit",
            tenant_id="tenant-e2e-audit",
            provider_type="oidc",
            issuer_url="https://idp.auditcorp.com",
            audience="masking-api",
            groups_claim="groups",
            is_active=True,
        )
        session.add(prov)
        pol_db = MaskingPolicy(
            id="pol-analyst",
            tenant_id="tenant-e2e-audit",
            name="analyst",
            policy_yaml=DEFAULT_POLICY_YAML,
            is_active=True,
        )
        session.add(pol_db)
        gm = GroupMapping(
            id="gm-e2e-audit",
            tenant_id="tenant-e2e-audit",
            external_group="data-analysts",
            policy_id="pol-analyst",
            priority=10,
        )
        session.add(gm)
        await session.commit()

    async def _override_get_session():
        async with session_factory() as session:
            yield session

    fastapi_app.dependency_overrides[get_session] = _override_get_session
    yield session_factory
    fastapi_app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_masking_request_generates_audit_and_metrics(audit_e2e_setup, monkeypatch):
    session_factory = audit_e2e_setup

    # Mock validate_jwt_for_tenant to return valid claims
    async def _mock_validate(token, tenant):
        return {
            "sub": "user_e2e_auditor",
            "iss": "https://idp.auditcorp.com",
            "aud": "masking-api",
            "groups": ["data-analysts"],
        }

    monkeypatch.setattr("app.routes.v1.mask.validate_jwt_for_tenant", _mock_validate)

    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as client:
        # Send inline mask request
        payload = {
            "format": "json",
            "data": {"user_id": 999, "ssn": "123-45-6789", "email": "test@auditcorp.com"},
        }
        headers = {
            "Authorization": "Bearer mock.jwt.token",
            "X-Tenant-Slug": "audit-corp",
        }
        resp = await client.post("/v1/mask", json=payload, headers=headers)
        assert resp.status_code == 200
        masked_data = resp.json()
        assert "ssn" not in masked_data  # suppressed
        assert masked_data["email"] == "[REDACTED]"  # redacted

        # Flush audit ledger queue into DB
        ledger = get_audit_ledger()
        async with session_factory() as session:
            flushed = await ledger.flush_batch(session, max_batch_size=10)
            assert flushed >= 1

        # Check DB audit record
        async with session_factory() as session:
            result = await session.execute(
                select(AuditEvent).where(AuditEvent.tenant_id == "tenant-e2e-audit")
            )
            audit_records = result.scalars().all()
            assert len(audit_records) >= 1
            rec = audit_records[-1]
            assert rec.user_id == "user_e2e_auditor"
            assert rec.groups_snapshot == "data-analysts"
            assert rec.policy_name == "3.0"
            assert rec.format == "json"
            assert rec.execution_time_ms is not None

        # Verify /metrics reflects the request
        metrics_resp = await client.get("/metrics")
        assert metrics_resp.status_code == 200
        metrics_text = metrics_resp.text
        assert 'tenant="audit-corp"' in metrics_text
        assert 'role="analyst"' in metrics_text
