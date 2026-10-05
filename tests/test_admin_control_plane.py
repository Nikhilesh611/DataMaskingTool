"""Phase 5 — Test Suite for Enterprise Control Plane Admin API & Dashboard.

Verifies:
1. Tenant CRUD & duplicate slug conflict handling
2. Identity Provider (OIDC / LDAP) configuration & connection testing
3. Group-to-Policy RBAC Mapping CRUD with priority ordering
4. Masking Policy CRUD with YAML syntax validation
5. In-Memory Masking Sandbox Simulation (JSON & XML, with/without custom policy)
6. Admin Dashboard Web UI delivery at GET /admin
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models import Tenant
from app.db.session import get_session
from app.main import app as fastapi_app


# ── In-Memory SQLite Test Fixture ─────────────────────────────────────────────

DEFAULT_POLICY_YAML = """
version: "3.0"
record_root: "$"
description: "Admin test policy"
roles:
  analyst: {}
  auditor: {}
  operator: {}
rules:
  - selector: "$..ssn"
    technique: "suppress"
  - selector: "$..name"
    technique: "redact"
  - selector: "//ssn"
    technique: "suppress"
  - selector: "//name"
    technique: "redact"
"""

@pytest_asyncio.fixture
async def admin_client():
    from app.policy.loader import load_policy_from_string, set_policy
    import app.hierarchies  # noqa: F401
    pol = load_policy_from_string(DEFAULT_POLICY_YAML)
    set_policy(pol)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _override_get_session():
        async with session_factory() as session:
            yield session

    fastapi_app.dependency_overrides[get_session] = _override_get_session

    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    fastapi_app.dependency_overrides.clear()
    await engine.dispose()


# ── 1. Tenant Management Tests ────────────────────────────────────────────────

class TestTenantManagement:
    @pytest.mark.asyncio
    async def test_create_and_list_tenants(self, admin_client: AsyncClient):
        # Create Tenant 1
        res1 = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "Acme Corp", "slug": "acme-corp", "is_active": True},
        )
        assert res1.status_code == 201
        data1 = res1.json()
        assert data1["name"] == "Acme Corp"
        assert data1["slug"] == "acme-corp"
        tenant1_id = data1["id"]

        # Create Tenant 2
        res2 = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "Global Health", "slug": "global-health", "is_active": True},
        )
        assert res2.status_code == 201

        # List Tenants
        list_res = await admin_client.get("/api/v1/admin/tenants")
        assert list_res.status_code == 200
        tenants = list_res.json()
        assert len(tenants) == 2
        slugs = [t["slug"] for t in tenants]
        assert "acme-corp" in slugs
        assert "global-health" in slugs

        # Get Tenant by ID
        get_res = await admin_client.get(f"/api/v1/admin/tenants/{tenant1_id}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == tenant1_id

    @pytest.mark.asyncio
    async def test_duplicate_slug_raises_409(self, admin_client: AsyncClient):
        await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "First Tenant", "slug": "unique-slug", "is_active": True},
        )
        # Attempt to create duplicate slug
        res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "Duplicate Tenant", "slug": "unique-slug", "is_active": True},
        )
        assert res.status_code == 409
        assert "already exists" in res.json()["detail"]

    @pytest.mark.asyncio
    async def test_delete_tenant(self, admin_client: AsyncClient):
        res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "To Delete", "slug": "to-delete", "is_active": True},
        )
        tenant_id = res.json()["id"]

        del_res = await admin_client.delete(f"/api/v1/admin/tenants/{tenant_id}")
        assert del_res.status_code == 204

        # Verify not found
        get_res = await admin_client.get(f"/api/v1/admin/tenants/{tenant_id}")
        assert get_res.status_code == 404


# ── 2. IdP Configuration Tests ────────────────────────────────────────────────

class TestIdPConfiguration:
    @pytest.mark.asyncio
    async def test_configure_and_get_idp(self, admin_client: AsyncClient):
        t_res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "IdP Tenant", "slug": "idp-tenant", "is_active": True},
        )
        tenant_id = t_res.json()["id"]

        # Configure IdP
        idp_res = await admin_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/idp",
            json={
                "provider_type": "oidc",
                "issuer_url": "https://auth.enterprise.com/realms/corp",
                "jwks_uri": "https://auth.enterprise.com/realms/corp/protocol/openid-connect/certs",
                "audience": "masking-client",
                "groups_claim": "roles",
                "is_active": True,
            },
        )
        assert idp_res.status_code == 201
        idp_data = idp_res.json()
        assert idp_data["tenant_id"] == tenant_id
        assert idp_data["issuer_url"] == "https://auth.enterprise.com/realms/corp"
        assert idp_data["groups_claim"] == "roles"

        # Get IdP configs
        list_res = await admin_client.get(f"/api/v1/admin/tenants/{tenant_id}/idp")
        assert list_res.status_code == 200
        providers = list_res.json()
        assert len(providers) == 1
        assert providers[0]["audience"] == "masking-client"

    @pytest.mark.asyncio
    async def test_test_idp_connection_invalid_endpoint(self, admin_client: AsyncClient):
        # Point to unreachable URL to verify safe failure response
        res = await admin_client.post(
            "/api/v1/admin/idp/test-connection",
            json={"jwks_uri": "http://127.0.0.1:59999/does-not-exist/jwks"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is False
        assert "Failed to fetch JWKS" in data["message"]


# ── 3. Group Mapping Tests ────────────────────────────────────────────────────

class TestGroupMappings:
    @pytest.mark.asyncio
    async def test_group_mapping_lifecycle(self, admin_client: AsyncClient):
        t_res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "Mapping Tenant", "slug": "map-tenant", "is_active": True},
        )
        tenant_id = t_res.json()["id"]

        # Create Policy first
        pol_res = await admin_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/policies",
            json={
                "name": "analyst-policy",
                "policy_yaml": "version: '3.0'\nroles:\n  analyst:\n    rules: []",
                "is_active": True,
            },
        )
        assert pol_res.status_code == 201
        policy_id = pol_res.json()["id"]

        # Add Group Mapping
        map_res = await admin_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/mappings",
            json={
                "external_group": "data_scientists",
                "policy_id": policy_id,
                "priority": 10,
            },
        )
        assert map_res.status_code == 201
        map_data = map_res.json()
        assert map_data["external_group"] == "data_scientists"
        assert map_data["priority"] == 10
        mapping_id = map_data["id"]

        # List mappings
        list_res = await admin_client.get(f"/api/v1/admin/tenants/{tenant_id}/mappings")
        assert list_res.status_code == 200
        mappings = list_res.json()
        assert len(mappings) == 1
        assert mappings[0]["policy_name"] == "analyst-policy"

        # Delete mapping
        del_res = await admin_client.delete(
            f"/api/v1/admin/tenants/{tenant_id}/mappings/{mapping_id}"
        )
        assert del_res.status_code == 204

        # Verify list is empty
        list_res2 = await admin_client.get(f"/api/v1/admin/tenants/{tenant_id}/mappings")
        assert len(list_res2.json()) == 0


# ── 4. Masking Policy Tests ───────────────────────────────────────────────────

class TestMaskingPolicies:
    @pytest.mark.asyncio
    async def test_create_and_validate_policy(self, admin_client: AsyncClient):
        t_res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "Policy Tenant", "slug": "pol-tenant", "is_active": True},
        )
        tenant_id = t_res.json()["id"]

        # Valid YAML
        valid_yaml = """
version: "3.0"
record_root: "$"
description: "Test Policy"
roles:
  analyst: {}
rules:
  - selector: "$.ssn"
    technique: "suppress"
"""
        res = await admin_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/policies",
            json={"name": "test-policy", "policy_yaml": valid_yaml, "is_active": True},
        )
        assert res.status_code == 201
        pol = res.json()
        assert pol["name"] == "test-policy"
        policy_id = pol["id"]

        # List policies
        list_res = await admin_client.get(f"/api/v1/admin/tenants/{tenant_id}/policies")
        assert list_res.status_code == 200
        assert len(list_res.json()) == 1

        # Delete policy
        del_res = await admin_client.delete(
            f"/api/v1/admin/tenants/{tenant_id}/policies/{policy_id}"
        )
        assert del_res.status_code == 204

    @pytest.mark.asyncio
    async def test_invalid_yaml_rejected(self, admin_client: AsyncClient):
        t_res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "Invalid YAML Tenant", "slug": "inv-tenant", "is_active": True},
        )
        tenant_id = t_res.json()["id"]

        # Malformed YAML
        bad_yaml = "version: 3.0\nroles: [unbalanced array: {"
        res = await admin_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/policies",
            json={"name": "bad-policy", "policy_yaml": bad_yaml, "is_active": True},
        )
        assert res.status_code == 422
        assert "Invalid policy YAML" in res.json()["detail"]


# ── 5. Live Simulator Sandbox Tests ───────────────────────────────────────────

class TestMaskingSimulator:
    @pytest.mark.asyncio
    async def test_simulate_json_masking(self, admin_client: AsyncClient):
        t_res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "Sim Tenant", "slug": "sim-tenant", "is_active": True},
        )
        tenant_id = t_res.json()["id"]

        sim_res = await admin_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/simulate",
            json={
                "format": "json",
                "data": {"user_id": 42, "ssn": "987-65-4321", "name": "John Doe"},
                "role": "analyst",
            },
        )
        assert sim_res.status_code == 200
        data = sim_res.json()
        assert data["format"] == "json"
        assert data["role"] == "analyst"
        assert data["elapsed_ms"] >= 0.0

        # Assert SSN was suppressed/masked by default pipeline policy
        masked = data["masked_output"]
        assert "ssn" not in masked
        assert masked["user_id"] == 42
        assert masked["name"] == "[REDACTED]"

    @pytest.mark.asyncio
    async def test_simulate_xml_masking(self, admin_client: AsyncClient):
        t_res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "XML Sim Tenant", "slug": "xml-sim-tenant", "is_active": True},
        )
        tenant_id = t_res.json()["id"]

        raw_xml = (
            "<patient>"
            "<id>100</id>"
            "<name>Alice</name>"
            "<ssn>123-45-6789</ssn>"
            "</patient>"
        )

        sim_res = await admin_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/simulate",
            json={
                "format": "xml",
                "data": raw_xml,
                "role": "analyst",
            },
        )
        assert sim_res.status_code == 200
        out_xml = sim_res.json()["masked_output"]
        assert "<ssn>" not in out_xml
        assert "[REDACTED]" in out_xml

    @pytest.mark.asyncio
    async def test_simulate_operator_unmasked(self, admin_client: AsyncClient):
        t_res = await admin_client.post(
            "/api/v1/admin/tenants",
            json={"name": "Op Sim Tenant", "slug": "op-sim-tenant", "is_active": True},
        )
        tenant_id = t_res.json()["id"]

        sim_res = await admin_client.post(
            f"/api/v1/admin/tenants/{tenant_id}/simulate",
            json={
                "format": "json",
                "data": {"user_id": 99, "ssn": "111-22-3333"},
                "role": "operator",
            },
        )
        assert sim_res.status_code == 200
        masked = sim_res.json()["masked_output"]
        # Operator sees raw payload untouched
        assert masked["ssn"] == "111-22-3333"


# ── 6. Admin Web UI Route Test ────────────────────────────────────────────────

class TestAdminWebUI:
    @pytest.mark.asyncio
    async def test_admin_dashboard_rendered(self, admin_client: AsyncClient):
        res = await admin_client.get("/admin")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        html = res.text
        # Assert SPA root container is present
        assert "Enterprise Data Masking Platform" in html
        assert "root" in html
