"""Phase 1 tests: multi-tenant DB schema, tenant isolation, and AES-256-GCM crypto.

Tests
-----
TestCrypto
    - encrypt → decrypt round-trip matches original plaintext
    - Different calls produce different ciphertexts (random IV)
    - Tampered ciphertext raises ValueError
    - Missing/short SECRET_KEY raises ValueError

TestDBSchema
    - All 5 tables are created by init_db()
    - Tenant with AuthProvider, MaskingPolicy, GroupMapping can be inserted
    - FK cascade: deleting Tenant removes all child rows

TestTenantIsolation
    - Querying Tenant B's policies while filtering by Tenant A returns empty set
    - GroupMappings are tenant-scoped: Tenant A cannot see Tenant B's mappings
    - AuditEvents are tenant-scoped: each tenant sees only their own records
"""

from __future__ import annotations

import os
import pytest
import pytest_asyncio

# Force an in-memory SQLite URL so tests don't touch the real database.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-16-chars")

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models import (
    AuditEvent,
    AuthProvider,
    GroupMapping,
    MaskingPolicy,
    Tenant,
)
from app.core.crypto import decrypt_secret, encrypt_secret


# ── Test fixtures ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db_session():
    """Create fresh in-memory DB and yield a session for each test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    await engine.dispose()


# ── Crypto tests ───────────────────────────────────────────────────────────────

class TestCrypto:
    def test_round_trip(self):
        """Encrypted value decrypts back to original."""
        original = "super-secret-ldap-password-!@#$"
        ciphertext = encrypt_secret(original)
        assert decrypt_secret(ciphertext) == original

    def test_different_ciphertexts_for_same_input(self):
        """Each encryption produces a unique ciphertext (random IV)."""
        secret = "same-value"
        ct1 = encrypt_secret(secret)
        ct2 = encrypt_secret(secret)
        assert ct1 != ct2, "Same input must produce different ciphertexts (random IV)"

    def test_decrypt_wrong_key_raises(self, monkeypatch):
        """Decryption with wrong key raises ValueError."""
        monkeypatch.setenv("SECRET_KEY", "correct-key-for-encryption-at-least-32ch!")
        ciphertext = encrypt_secret("my-secret")

        monkeypatch.setenv("SECRET_KEY", "a-completely-different-key-32ch!")
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_secret(ciphertext)

    def test_tampered_ciphertext_raises(self):
        """Modifying any byte of the ciphertext raises ValueError."""
        ciphertext = encrypt_secret("tamper-test")
        # Flip the last character
        tampered = ciphertext[:-1] + ("a" if ciphertext[-1] != "a" else "b")
        with pytest.raises(ValueError):
            decrypt_secret(tampered)

    def test_too_short_ciphertext_raises(self):
        """Ciphertext shorter than IV + tag raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            decrypt_secret("deadbeef")

    def test_invalid_hex_raises(self):
        """Non-hex input raises ValueError."""
        with pytest.raises(ValueError, match="Invalid hex"):
            decrypt_secret("this-is-not-hex!")

    def test_short_secret_key_raises(self, monkeypatch):
        """SECRET_KEY shorter than 32 characters raises ValueError."""
        monkeypatch.setenv("SECRET_KEY", "short-key-under-32-chars")
        with pytest.raises(ValueError, match="SECRET_KEY must be at least 32"):
            encrypt_secret("anything")

    def test_ciphertext_is_hex_string(self):
        """Output of encrypt_secret is a valid lowercase hex string."""
        ct = encrypt_secret("hello")
        assert all(c in "0123456789abcdef" for c in ct)


# ── DB schema tests ────────────────────────────────────────────────────────────

class TestDBSchema:
    @pytest.mark.asyncio
    async def test_all_tables_created(self, db_session: AsyncSession):
        """Verify all 5 core tables are accessible."""
        # If tables are missing, these queries will raise ProgrammingError
        await db_session.execute(select(Tenant))
        await db_session.execute(select(AuthProvider))
        await db_session.execute(select(MaskingPolicy))
        await db_session.execute(select(GroupMapping))
        await db_session.execute(select(AuditEvent))

    @pytest.mark.asyncio
    async def test_insert_full_tenant_tree(self, db_session: AsyncSession):
        """Insert a Tenant + all child entities and verify DB round-trip."""
        tenant = Tenant(name="Acme Corp", slug="acme-corp")
        db_session.add(tenant)
        await db_session.flush()

        # AuthProvider
        provider = AuthProvider(
            tenant_id=tenant.id,
            provider_type="oidc",
            issuer_url="https://keycloak.acme.com/realms/acme",
            audience="masking-service",
        )
        db_session.add(provider)

        # MaskingPolicy
        policy = MaskingPolicy(
            tenant_id=tenant.id,
            name="Finance Restricted",
            policy_yaml="version: 1\nroles:\n  analyst: []\n",
        )
        db_session.add(policy)
        await db_session.flush()

        # GroupMapping (needs policy.id)
        mapping = GroupMapping(
            tenant_id=tenant.id,
            external_group="finance-team",
            policy_id=policy.id,
            priority=10,
        )
        db_session.add(mapping)

        # AuditEvent
        event = AuditEvent(
            tenant_id=tenant.id,
            user_id="sub-abc123",
            policy_name="Finance Restricted",
            execution_time_ms=3,
        )
        db_session.add(event)
        await db_session.commit()

        # Reload and verify
        result = await db_session.execute(
            select(Tenant).where(Tenant.slug == "acme-corp")
        )
        loaded = result.scalar_one()
        assert loaded.name == "Acme Corp"
        assert loaded.is_active is True

    @pytest.mark.asyncio
    async def test_cascade_delete(self, db_session: AsyncSession):
        """Deleting a Tenant cascades to all child tables."""
        tenant = Tenant(name="Delete Me", slug="delete-me")
        db_session.add(tenant)
        await db_session.flush()

        policy = MaskingPolicy(
            tenant_id=tenant.id,
            name="Test Policy",
            policy_yaml="version: 1\n",
        )
        db_session.add(policy)
        await db_session.flush()

        mapping = GroupMapping(
            tenant_id=tenant.id,
            external_group="devs",
            policy_id=policy.id,
            priority=50,
        )
        db_session.add(mapping)
        await db_session.commit()

        # Delete parent
        await db_session.delete(tenant)
        await db_session.commit()

        # Child rows must be gone
        policies = (
            await db_session.execute(
                select(MaskingPolicy).where(MaskingPolicy.tenant_id == tenant.id)
            )
        ).scalars().all()
        assert policies == []

        mappings = (
            await db_session.execute(
                select(GroupMapping).where(GroupMapping.tenant_id == tenant.id)
            )
        ).scalars().all()
        assert mappings == []


# ── Tenant isolation tests ─────────────────────────────────────────────────────

class TestTenantIsolation:
    @pytest_asyncio.fixture
    async def two_tenants(self, db_session: AsyncSession):
        """Create Tenant A and Tenant B each with one policy and one mapping."""
        tenant_a = Tenant(name="Acme Corp", slug="acme")
        tenant_b = Tenant(name="Global Bank", slug="global-bank")
        db_session.add_all([tenant_a, tenant_b])
        await db_session.flush()

        policy_a = MaskingPolicy(
            tenant_id=tenant_a.id, name="Acme Policy", policy_yaml="v: 1\n"
        )
        policy_b = MaskingPolicy(
            tenant_id=tenant_b.id, name="Bank Policy", policy_yaml="v: 1\n"
        )
        db_session.add_all([policy_a, policy_b])
        await db_session.flush()

        mapping_a = GroupMapping(
            tenant_id=tenant_a.id,
            external_group="acme-analysts",
            policy_id=policy_a.id,
            priority=10,
        )
        mapping_b = GroupMapping(
            tenant_id=tenant_b.id,
            external_group="bank-auditors",
            policy_id=policy_b.id,
            priority=10,
        )
        db_session.add_all([mapping_a, mapping_b])

        event_a = AuditEvent(tenant_id=tenant_a.id, user_id="alice")
        event_b = AuditEvent(tenant_id=tenant_b.id, user_id="bob")
        db_session.add_all([event_a, event_b])

        await db_session.commit()
        return tenant_a, tenant_b

    @pytest.mark.asyncio
    async def test_policy_isolation(self, db_session: AsyncSession, two_tenants):
        """Tenant A cannot see Tenant B's policies via tenant-scoped query."""
        tenant_a, tenant_b = two_tenants

        # Query Tenant A's policies -- must NOT return Tenant B's policy
        result = await db_session.execute(
            select(MaskingPolicy).where(MaskingPolicy.tenant_id == tenant_a.id)
        )
        policies = result.scalars().all()
        assert len(policies) == 1
        assert policies[0].name == "Acme Policy"
        assert all(p.tenant_id == tenant_a.id for p in policies)

    @pytest.mark.asyncio
    async def test_group_mapping_isolation(self, db_session: AsyncSession, two_tenants):
        """Tenant B's group mappings are invisible under Tenant A's scope."""
        tenant_a, tenant_b = two_tenants

        result = await db_session.execute(
            select(GroupMapping).where(GroupMapping.tenant_id == tenant_a.id)
        )
        mappings = result.scalars().all()
        assert len(mappings) == 1
        assert mappings[0].external_group == "acme-analysts"

        # Tenant B mappings must not leak into Tenant A's results
        groups = [m.external_group for m in mappings]
        assert "bank-auditors" not in groups

    @pytest.mark.asyncio
    async def test_audit_event_isolation(self, db_session: AsyncSession, two_tenants):
        """Each tenant sees only their own audit events."""
        tenant_a, tenant_b = two_tenants

        result_a = await db_session.execute(
            select(AuditEvent).where(AuditEvent.tenant_id == tenant_a.id)
        )
        events_a = result_a.scalars().all()
        assert len(events_a) == 1
        assert events_a[0].user_id == "alice"

        result_b = await db_session.execute(
            select(AuditEvent).where(AuditEvent.tenant_id == tenant_b.id)
        )
        events_b = result_b.scalars().all()
        assert len(events_b) == 1
        assert events_b[0].user_id == "bob"

    @pytest.mark.asyncio
    async def test_cross_tenant_query_returns_empty(
        self, db_session: AsyncSession, two_tenants
    ):
        """Querying with a non-existent tenant_id returns empty results."""
        result = await db_session.execute(
            select(MaskingPolicy).where(MaskingPolicy.tenant_id == "does-not-exist")
        )
        assert result.scalars().all() == []
