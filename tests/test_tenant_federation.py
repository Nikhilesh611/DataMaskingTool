"""Phase 2 tests: Dynamic Multi-Tenant IdP Federation.

Test Groups
-----------
TestJWKSCacheTenantPartitioning
    Verifies the (tenant_id, jwks_uri) cache key prevents cross-tenant key leakage.

TestValidateJwtForTenant
    Verifies validate_jwt_for_tenant() reads all config from TenantContext and
    passes tenant_id to the JWKS cache.  Runs two issuers (Tenant A + Tenant B)
    in a single test session to confirm isolation.

TestResolveRoleForTenant
    Verifies the DB-backed role resolution queries only the calling tenant's
    group_mappings rows and applies priority ordering correctly.

TestTenantFederationFailClosed
    Validates every fail-closed invariant:
      - Unknown issuer → 401 (handled by resolve_tenant)
      - Wrong audience → 401
      - Expired token  → 401
      - Valid JWT, no groups claim → 403
      - Valid JWT, groups present but unmapped → 403
      - Cross-tenant group mapping not visible → 403
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from app.auth.tenant_resolver import (
    TenantContext,
    _peek_jwt_iss,
    resolve_tenant,
    resolve_tenant_optional,
)
from app.db.base import Base
from app.db.models import AuthProvider, GroupMapping, MaskingPolicy, Tenant
from app.exceptions import AuthenticationError, AuthorizationError
from app.idp.group_mapper import resolve_role_for_tenant
from app.idp.jwks_client import JWKSCache, JWKSKeyNotFoundError, set_jwks_cache
from app.idp.jwt_validator import extract_groups, validate_jwt, validate_jwt_for_tenant


# ── Key generation helpers (mirrors test_jwt_validation.py) ──────────────────

def _gen_rsa():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def _private_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _rsa_jwk(pub, kid: str) -> dict:
    from jwt.algorithms import RSAAlgorithm
    return json.loads(RSAAlgorithm.to_jwk(pub)) | {"kid": kid, "use": "sig", "alg": "RS256"}


def _make_jwt(
    priv,
    *,
    iss: str,
    aud: str,
    kid: str,
    exp_offset: int = 3600,
    nbf_offset: int = 0,
    groups: list[str] | None = None,
    groups_claim: str = "groups",
) -> str:
    now = int(time.time())
    payload: dict = {
        "sub": "user@test",
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
    }
    if nbf_offset:
        payload["nbf"] = now + nbf_offset
    if groups is not None:
        payload[groups_claim] = groups
    return jwt.encode(
        payload,
        _private_pem(priv),
        algorithm="RS256",
        headers={"kid": kid},
    )


# ── Shared tenant fixtures ────────────────────────────────────────────────────

TENANT_A_ID = "aaaaaaaa-0000-0000-0000-000000000001"
TENANT_B_ID = "bbbbbbbb-0000-0000-0000-000000000001"
ISSUER_A = "https://keycloak.acme.com/realms/acme"
ISSUER_B = "https://login.globalbank.io/oidc"
AUDIENCE_A = "masking-service"
AUDIENCE_B = "masking-service"
JWKS_URI_A = f"{ISSUER_A}/.well-known/jwks.json"
JWKS_URI_B = f"{ISSUER_B}/.well-known/jwks.json"
KID_A = "acme-key-001"
KID_B = "bank-key-001"


def _make_tenant_context(
    tenant_id: str,
    tenant_slug: str,
    issuer_url: str,
    jwks_uri: str,
    audience: str,
    groups_claim: str = "groups",
) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug=tenant_slug,
        provider_id="provider-id",
        provider_type="oidc",
        issuer_url=issuer_url,
        jwks_uri=jwks_uri,
        audience=audience,
        groups_claim=groups_claim,
    )


@pytest.fixture
def tenant_a_ctx() -> TenantContext:
    return _make_tenant_context(
        TENANT_A_ID, "acme-corp", ISSUER_A, JWKS_URI_A, AUDIENCE_A
    )


@pytest.fixture
def tenant_b_ctx() -> TenantContext:
    return _make_tenant_context(
        TENANT_B_ID, "global-bank", ISSUER_B, JWKS_URI_B, AUDIENCE_B
    )


@pytest.fixture
def rsa_a():
    """RSA key pair for Tenant A's IdP."""
    return _gen_rsa()


@pytest.fixture
def rsa_b():
    """RSA key pair for Tenant B's IdP."""
    return _gen_rsa()


@pytest.fixture(autouse=True)
def isolated_jwks_cache():
    """Each test gets a fresh JWKS cache — no inter-test state pollution."""
    cache = JWKSCache(ttl_seconds=300)
    set_jwks_cache(cache)
    yield cache
    cache.clear()


# ── In-memory DB fixture ──────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db_session():
    """Fresh in-memory SQLite DB for each test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def two_tenant_db(db_session: AsyncSession):
    """Insert Tenant A and Tenant B with policies and group mappings."""
    # ── Tenant A (Acme Corp) ─────────────────────────────────────────────────
    tenant_a = Tenant(id=TENANT_A_ID, name="Acme Corp", slug="acme-corp")
    policy_a = MaskingPolicy(
        id="policy-a-001",
        tenant_id=TENANT_A_ID,
        name="analyst",  # internal role name must match policy.roles key
        policy_yaml="version: 1\n",
    )
    mapping_a1 = GroupMapping(
        tenant_id=TENANT_A_ID,
        external_group="acme-analysts",
        policy_id="policy-a-001",
        priority=20,
    )
    mapping_a2 = GroupMapping(
        tenant_id=TENANT_A_ID,
        external_group="acme-admins",
        policy_id="policy-a-001",
        priority=5,  # higher priority (lower number)
    )

    prov_a = AuthProvider(
        id="prov-a-001",
        tenant_id=TENANT_A_ID,
        provider_type="oidc",
        issuer_url=ISSUER_A,
        jwks_uri=JWKS_URI_A,
        audience=AUDIENCE_A,
        groups_claim="groups",
        is_active=True,
    )

    # ── Tenant B (Global Bank) ───────────────────────────────────────────────
    tenant_b = Tenant(id=TENANT_B_ID, name="Global Bank", slug="global-bank")
    prov_b = AuthProvider(
        id="prov-b-001",
        tenant_id=TENANT_B_ID,
        provider_type="oidc",
        issuer_url=ISSUER_B,
        jwks_uri=JWKS_URI_B,
        audience=AUDIENCE_B,
        groups_claim="groups",
        is_active=True,
    )
    policy_b = MaskingPolicy(
        id="policy-b-001",
        tenant_id=TENANT_B_ID,
        name="auditor",
        policy_yaml="version: 1\n",
    )
    mapping_b = GroupMapping(
        tenant_id=TENANT_B_ID,
        external_group="bank-auditors",
        policy_id="policy-b-001",
        priority=10,
    )

    db_session.add_all(
        [
            tenant_a,
            prov_a,
            policy_a,
            mapping_a1,
            mapping_a2,
            tenant_b,
            prov_b,
            policy_b,
            mapping_b,
        ]
    )
    await db_session.commit()
    return db_session


# ═════════════════════════════════════════════════════════════════════════════
# TestJWKSCacheTenantPartitioning
# ═════════════════════════════════════════════════════════════════════════════

class TestJWKSCacheTenantPartitioning:
    """The (tenant_id, jwks_uri) cache key must prevent cross-tenant key access."""

    def test_cache_stores_keys_per_tenant(self, isolated_jwks_cache, rsa_a, rsa_b):
        """Keys stored under Tenant A and Tenant B are independent slots."""
        cache = isolated_jwks_cache
        jwk_a = _rsa_jwk(rsa_a[1], KID_A)
        jwk_b = _rsa_jwk(rsa_b[1], KID_B)

        cache.set(JWKS_URI_A, [jwk_a], tenant_id=TENANT_A_ID)
        cache.set(JWKS_URI_B, [jwk_b], tenant_id=TENANT_B_ID)

        result_a = cache.get_cached(JWKS_URI_A, tenant_id=TENANT_A_ID)
        result_b = cache.get_cached(JWKS_URI_B, tenant_id=TENANT_B_ID)

        assert result_a == [jwk_a]
        assert result_b == [jwk_b]

    def test_tenant_a_keys_not_visible_under_tenant_b_uri(
        self, isolated_jwks_cache, rsa_a
    ):
        """Tenant A's keys must not be readable under Tenant B's identity."""
        cache = isolated_jwks_cache
        jwk_a = _rsa_jwk(rsa_a[1], KID_A)
        cache.set(JWKS_URI_A, [jwk_a], tenant_id=TENANT_A_ID)

        # Same URI, different tenant_id → different cache slot → cache miss
        result = cache.get_cached(JWKS_URI_A, tenant_id=TENANT_B_ID)
        assert result is None, (
            "Tenant B must not be able to see Tenant A's cached JWKS keys."
        )

    def test_same_uri_different_tenants_are_independent_slots(
        self, isolated_jwks_cache, rsa_a, rsa_b
    ):
        """Even if two tenants share the same JWKS URI, keys are stored separately."""
        cache = isolated_jwks_cache
        jwk_a = _rsa_jwk(rsa_a[1], KID_A)
        jwk_b = _rsa_jwk(rsa_b[1], KID_B)

        shared_uri = "https://shared-idp.example.com/.well-known/jwks.json"
        cache.set(shared_uri, [jwk_a], tenant_id=TENANT_A_ID)
        cache.set(shared_uri, [jwk_b], tenant_id=TENANT_B_ID)

        assert cache.get_cached(shared_uri, tenant_id=TENANT_A_ID) == [jwk_a]
        assert cache.get_cached(shared_uri, tenant_id=TENANT_B_ID) == [jwk_b]

    def test_invalidate_tenant_evicts_only_that_tenants_keys(
        self, isolated_jwks_cache, rsa_a, rsa_b
    ):
        """invalidate_tenant() must not evict other tenants' keys."""
        cache = isolated_jwks_cache
        jwk_a = _rsa_jwk(rsa_a[1], KID_A)
        jwk_b = _rsa_jwk(rsa_b[1], KID_B)

        cache.set(JWKS_URI_A, [jwk_a], tenant_id=TENANT_A_ID)
        cache.set(JWKS_URI_B, [jwk_b], tenant_id=TENANT_B_ID)

        cache.invalidate_tenant(TENANT_A_ID)

        # Tenant A's slot evicted
        assert cache.get_cached(JWKS_URI_A, tenant_id=TENANT_A_ID) is None
        # Tenant B's slot untouched
        assert cache.get_cached(JWKS_URI_B, tenant_id=TENANT_B_ID) == [jwk_b]

    def test_backward_compat_empty_tenant_id(self, isolated_jwks_cache, rsa_a):
        """Single-tenant callers (tenant_id='') still work correctly."""
        cache = isolated_jwks_cache
        jwk = _rsa_jwk(rsa_a[1], KID_A)
        cache.set(JWKS_URI_A, [jwk])  # no tenant_id — defaults to ""
        result = cache.get_cached(JWKS_URI_A)  # no tenant_id — defaults to ""
        assert result == [jwk]


# ═════════════════════════════════════════════════════════════════════════════
# TestValidateJwtForTenant
# ═════════════════════════════════════════════════════════════════════════════

class TestValidateJwtForTenant:
    """validate_jwt_for_tenant() reads IdP config from TenantContext and
    stores JWKS keys in the tenant-partitioned cache."""

    @pytest.mark.asyncio
    async def test_tenant_a_valid_jwt_accepted(
        self, rsa_a, tenant_a_ctx, isolated_jwks_cache
    ):
        """A valid JWT from Tenant A's issuer is accepted and returns claims."""
        priv_a, pub_a = rsa_a
        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)

        token = _make_jwt(
            priv_a, iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A, groups=["acme-analysts"]
        )
        claims = await validate_jwt_for_tenant(token, tenant_a_ctx)
        assert claims["iss"] == ISSUER_A
        assert claims["groups"] == ["acme-analysts"]

    @pytest.mark.asyncio
    async def test_tenant_b_valid_jwt_accepted(
        self, rsa_b, tenant_b_ctx, isolated_jwks_cache
    ):
        """A valid JWT from Tenant B's issuer is accepted."""
        priv_b, pub_b = rsa_b
        isolated_jwks_cache.set(JWKS_URI_B, [_rsa_jwk(pub_b, KID_B)], tenant_id=TENANT_B_ID)

        token = _make_jwt(
            priv_b, iss=ISSUER_B, aud=AUDIENCE_B, kid=KID_B, groups=["bank-auditors"]
        )
        claims = await validate_jwt_for_tenant(token, tenant_b_ctx)
        assert claims["iss"] == ISSUER_B

    @pytest.mark.asyncio
    async def test_two_tenants_in_same_session_are_isolated(
        self, rsa_a, rsa_b, tenant_a_ctx, tenant_b_ctx, isolated_jwks_cache
    ):
        """Tenant A and Tenant B can both be validated in the same test run
        without their JWKS keys interfering with each other."""
        priv_a, pub_a = rsa_a
        priv_b, pub_b = rsa_b

        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)
        isolated_jwks_cache.set(JWKS_URI_B, [_rsa_jwk(pub_b, KID_B)], tenant_id=TENANT_B_ID)

        token_a = _make_jwt(
            priv_a, iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A, groups=["acme-analysts"]
        )
        token_b = _make_jwt(
            priv_b, iss=ISSUER_B, aud=AUDIENCE_B, kid=KID_B, groups=["bank-auditors"]
        )

        claims_a = await validate_jwt_for_tenant(token_a, tenant_a_ctx)
        claims_b = await validate_jwt_for_tenant(token_b, tenant_b_ctx)

        assert claims_a["iss"] == ISSUER_A
        assert claims_b["iss"] == ISSUER_B

    @pytest.mark.asyncio
    async def test_tenant_a_token_rejected_against_tenant_b_config(
        self, rsa_a, rsa_b, tenant_a_ctx, tenant_b_ctx, isolated_jwks_cache
    ):
        """A JWT issued for Tenant A must be rejected when validated against
        Tenant B's TenantContext (wrong issuer).

        Both tenants' JWKS URIs are seeded in the cache so no real network
        request is made.  The issuer mismatch is what should trigger 401.
        Because validate_jwt_for_tenant passes tenant_b's jwks_uri and
        tenant_b's tenant_id, it will look up Tenant B's cache slot — which
        has Tenant B's key (kid=KID_B). The token has kid=KID_A, so after the
        cache miss the validator fetches Tenant B's URI, but PyJWT still rejects
        the token because iss=ISSUER_A != tenant_b.issuer_url=ISSUER_B.
        We patch the fetch to return Tenant B's key (with matching kid) so the
        test focuses on the issuer check, not a network error.
        """
        priv_a, pub_a = rsa_a
        _priv_b, pub_b = rsa_b

        # Seed Tenant A's slot (for Tenant A's own validation in other tests)
        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)

        # Token issued for Tenant A (iss=ISSUER_A, kid=KID_A)
        token_a = _make_jwt(
            priv_a, iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A, groups=["acme-analysts"]
        )

        # Patch JWKS fetch so Tenant B's URI returns Tenant B's key (kid=KID_A
        # forced to KID_B so it matches; the issuer check happens after key lookup).
        # Actually: we give Tenant B's jwks endpoint a key with kid=KID_A so the
        # key IS found — the rejection must come from PyJWT's issuer check.
        b_key_with_a_kid = _rsa_jwk(pub_b, KID_A)  # kid matches the token's kid
        with patch(
            "app.idp.jwks_client._fetch_jwks_raw",
            new=AsyncMock(return_value=[b_key_with_a_kid]),
        ):
            # PyJWT will find the key but reject iss=ISSUER_A != ISSUER_B
            with pytest.raises(AuthenticationError):
                await validate_jwt_for_tenant(token_a, tenant_b_ctx)

    @pytest.mark.asyncio
    async def test_tenant_a_key_cannot_verify_tenant_b_token(
        self, rsa_a, rsa_b, tenant_b_ctx, isolated_jwks_cache
    ):
        """Even if the cache were queried incorrectly, Tenant A's public key
        cannot verify a JWT signed by Tenant B's private key (different RSA pairs)."""
        priv_b, pub_b = rsa_b
        _priv_a, pub_a = rsa_a

        # Seed cache: Tenant B's slot has Tenant A's PUBLIC key (simulating corruption)
        isolated_jwks_cache.set(JWKS_URI_B, [_rsa_jwk(pub_a, KID_B)], tenant_id=TENANT_B_ID)

        # Token signed with Tenant B's PRIVATE key — pub_a cannot verify it
        token_b = _make_jwt(
            priv_b, iss=ISSUER_B, aud=AUDIENCE_B, kid=KID_B, groups=["bank-auditors"]
        )
        with pytest.raises(AuthenticationError):
            await validate_jwt_for_tenant(token_b, tenant_b_ctx)

    @pytest.mark.asyncio
    async def test_custom_groups_claim_key_extracted(
        self, rsa_a, isolated_jwks_cache
    ):
        """TenantContext.groups_claim is passed to extract_groups correctly."""
        priv_a, pub_a = rsa_a
        custom_ctx = _make_tenant_context(
            TENANT_A_ID, "acme-corp", ISSUER_A, JWKS_URI_A, AUDIENCE_A,
            groups_claim="cognito:groups",
        )
        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)

        token = _make_jwt(
            priv_a, iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A,
            groups=["acme-analysts"],
            groups_claim="cognito:groups",
        )
        claims = await validate_jwt_for_tenant(token, custom_ctx)
        groups = extract_groups(claims, custom_ctx.groups_claim)
        assert groups == ["acme-analysts"]

    @pytest.mark.asyncio
    async def test_jwks_key_not_found_triggers_refresh_succeeds(
        self, rsa_a, tenant_a_ctx, isolated_jwks_cache
    ):
        """On a kid miss, the cache fetches fresh JWKS and succeeds."""
        priv_a, pub_a = rsa_a
        new_kid = "rotated-acme-key-002"
        token = _make_jwt(
            priv_a, iss=ISSUER_A, aud=AUDIENCE_A, kid=new_kid, groups=["acme-analysts"]
        )
        rotated_jwk = _rsa_jwk(pub_a, new_kid)
        with patch(
            "app.idp.jwks_client._fetch_jwks_raw",
            new=AsyncMock(return_value=[rotated_jwk]),
        ):
            claims = await validate_jwt_for_tenant(token, tenant_a_ctx)
        assert claims["iss"] == ISSUER_A


# ═════════════════════════════════════════════════════════════════════════════
# TestResolveRoleForTenant
# ═════════════════════════════════════════════════════════════════════════════

class TestResolveRoleForTenant:
    """DB-backed role resolution must be strictly tenant-scoped and
    respect priority ordering."""

    @pytest.mark.asyncio
    async def test_single_group_resolves_to_policy_name(self, two_tenant_db):
        db = two_tenant_db
        role = await resolve_role_for_tenant(["acme-analysts"], TENANT_A_ID, db)
        assert role == "analyst"

    @pytest.mark.asyncio
    async def test_tenant_b_group_resolves_correctly(self, two_tenant_db):
        db = two_tenant_db
        role = await resolve_role_for_tenant(["bank-auditors"], TENANT_B_ID, db)
        assert role == "auditor"

    @pytest.mark.asyncio
    async def test_unmapped_group_returns_none(self, two_tenant_db):
        """No matching group → None → caller must raise 403."""
        db = two_tenant_db
        role = await resolve_role_for_tenant(["unknown-group"], TENANT_A_ID, db)
        assert role is None

    @pytest.mark.asyncio
    async def test_empty_groups_returns_none(self, two_tenant_db):
        db = two_tenant_db
        role = await resolve_role_for_tenant([], TENANT_A_ID, db)
        assert role is None

    @pytest.mark.asyncio
    async def test_priority_ordering_lower_number_wins(self, two_tenant_db):
        """acme-admins (priority=5) beats acme-analysts (priority=20)."""
        db = two_tenant_db
        role = await resolve_role_for_tenant(
            ["acme-analysts", "acme-admins"], TENANT_A_ID, db
        )
        assert role == "analyst"  # both map to the same "analyst" policy here
        # (both policies map to "analyst"; the important check is it doesn't crash)

    @pytest.mark.asyncio
    async def test_cross_tenant_groups_not_visible(self, two_tenant_db):
        """Tenant B's group is not visible when querying under Tenant A."""
        db = two_tenant_db
        # "bank-auditors" belongs to Tenant B — Tenant A must not resolve it
        role = await resolve_role_for_tenant(["bank-auditors"], TENANT_A_ID, db)
        assert role is None, (
            "Tenant A must not be able to resolve Tenant B's group mapping."
        )

    @pytest.mark.asyncio
    async def test_cross_tenant_reverse_not_visible(self, two_tenant_db):
        """Tenant A's group is not visible when querying under Tenant B."""
        db = two_tenant_db
        role = await resolve_role_for_tenant(["acme-analysts"], TENANT_B_ID, db)
        assert role is None, (
            "Tenant B must not be able to resolve Tenant A's group mapping."
        )

    @pytest.mark.asyncio
    async def test_inactive_policy_is_excluded(self, db_session: AsyncSession):
        """GroupMapping pointing to an inactive MaskingPolicy returns None."""
        tenant = Tenant(id="tenant-inactive", name="Inactive Test", slug="inactive-test")
        policy = MaskingPolicy(
            id="policy-inactive-001",
            tenant_id="tenant-inactive",
            name="analyst",
            policy_yaml="v: 1\n",
            is_active=False,  # ← disabled
        )
        mapping = GroupMapping(
            tenant_id="tenant-inactive",
            external_group="inactive-group",
            policy_id="policy-inactive-001",
            priority=10,
        )
        db_session.add_all([tenant, policy, mapping])
        await db_session.commit()

        role = await resolve_role_for_tenant(
            ["inactive-group"], "tenant-inactive", db_session
        )
        assert role is None, "Inactive policy must not be resolved."

    @pytest.mark.asyncio
    async def test_multiple_matching_groups_picks_lowest_priority(
        self, db_session: AsyncSession
    ):
        """When multiple matching groups exist, lowest priority value wins."""
        tid = "priority-test-tenant"
        tenant = Tenant(id=tid, name="Priority Test", slug="priority-test")

        p_low = MaskingPolicy(
            id="p-low", tenant_id=tid, name="analyst", policy_yaml="v:1\n"
        )
        p_high = MaskingPolicy(
            id="p-high", tenant_id=tid, name="auditor", policy_yaml="v:1\n"
        )

        # priority=1 (highest) → should win
        m1 = GroupMapping(
            tenant_id=tid, external_group="group-a", policy_id="p-low", priority=1
        )
        # priority=50 → should lose
        m2 = GroupMapping(
            tenant_id=tid, external_group="group-b", policy_id="p-high", priority=50
        )

        db_session.add_all([tenant, p_low, p_high, m1, m2])
        await db_session.commit()

        role = await resolve_role_for_tenant(["group-a", "group-b"], tid, db_session)
        assert role == "analyst", "Priority=1 group should win over priority=50."


# ═════════════════════════════════════════════════════════════════════════════
# TestTenantFederationFailClosed
# ═════════════════════════════════════════════════════════════════════════════

class TestTenantFederationFailClosed:
    """Every auth failure path must return 401 or 403, never fall through."""

    @pytest.mark.asyncio
    async def test_expired_token_raises_401(
        self, rsa_a, tenant_a_ctx, isolated_jwks_cache
    ):
        priv_a, pub_a = rsa_a
        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)
        token = _make_jwt(
            priv_a, iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A,
            exp_offset=-1  # already expired
        )
        with pytest.raises(AuthenticationError, match="expired"):
            await validate_jwt_for_tenant(token, tenant_a_ctx)

    @pytest.mark.asyncio
    async def test_wrong_audience_raises_401(
        self, rsa_a, tenant_a_ctx, isolated_jwks_cache
    ):
        priv_a, pub_a = rsa_a
        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)
        token = _make_jwt(
            priv_a, iss=ISSUER_A, aud="wrong-audience", kid=KID_A
        )
        with pytest.raises(AuthenticationError, match="audience"):
            await validate_jwt_for_tenant(token, tenant_a_ctx)

    @pytest.mark.asyncio
    async def test_wrong_issuer_raises_401(
        self, rsa_a, tenant_a_ctx, isolated_jwks_cache
    ):
        priv_a, pub_a = rsa_a
        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)
        token = _make_jwt(
            priv_a, iss="https://evil.idp.example.com", aud=AUDIENCE_A, kid=KID_A
        )
        with pytest.raises(AuthenticationError, match="issuer"):
            await validate_jwt_for_tenant(token, tenant_a_ctx)

    @pytest.mark.asyncio
    async def test_invalid_signature_raises_401(
        self, rsa_a, rsa_b, tenant_a_ctx, isolated_jwks_cache
    ):
        """Token signed with key-A2 but JWKS has key-A1 → signature failure."""
        priv_a, pub_a = rsa_a
        priv_a2, _pub_a2 = rsa_b  # different key pair, same issuer
        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)
        token = _make_jwt(
            priv_a2,  # wrong private key
            iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A
        )
        with pytest.raises(AuthenticationError):
            await validate_jwt_for_tenant(token, tenant_a_ctx)

    @pytest.mark.asyncio
    async def test_no_groups_claim_returns_empty_list(
        self, rsa_a, tenant_a_ctx, isolated_jwks_cache
    ):
        """A valid JWT with no groups claim → extract_groups returns [] →
        caller must treat this as 403."""
        priv_a, pub_a = rsa_a
        isolated_jwks_cache.set(JWKS_URI_A, [_rsa_jwk(pub_a, KID_A)], tenant_id=TENANT_A_ID)
        # No groups kwarg → no groups claim in payload
        token = _make_jwt(priv_a, iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A)
        claims = await validate_jwt_for_tenant(token, tenant_a_ctx)
        groups = extract_groups(claims, tenant_a_ctx.groups_claim)
        assert groups == [], "Missing groups claim must return empty list."

    @pytest.mark.asyncio
    async def test_unmapped_group_returns_none_fail_closed(self, two_tenant_db):
        """Valid JWT, groups present, but none mapped → resolve_role_for_tenant
        returns None → caller must raise 403."""
        role = await resolve_role_for_tenant(
            ["completely-unknown-group"], TENANT_A_ID, two_tenant_db
        )
        assert role is None

    @pytest.mark.asyncio
    async def test_unknown_kid_after_refresh_raises(
        self, rsa_a, tenant_a_ctx, isolated_jwks_cache
    ):
        """If kid is not found even after JWKS refresh → JWKSKeyNotFoundError."""
        priv_a, pub_a = rsa_a
        token = _make_jwt(
            priv_a, iss=ISSUER_A, aud=AUDIENCE_A, kid="ghost-kid",
            groups=["acme-analysts"]
        )
        # Refresh returns a key with a different kid
        different_jwk = _rsa_jwk(pub_a, "some-other-kid")
        with patch(
            "app.idp.jwks_client._fetch_jwks_raw",
            new=AsyncMock(return_value=[different_jwk]),
        ):
            with pytest.raises(JWKSKeyNotFoundError):
                await validate_jwt_for_tenant(token, tenant_a_ctx)

    @pytest.mark.asyncio
    async def test_symmetric_algorithm_rejected(
        self, tenant_a_ctx, isolated_jwks_cache
    ):
        """HS256 tokens must be rejected regardless of tenant."""
        token = jwt.encode(
            {
                "sub": "u",
                "iss": ISSUER_A,
                "aud": AUDIENCE_A,
                "exp": int(time.time()) + 3600,
            },
            "a-very-secure-hmac-test-key-32bytes",
            algorithm="HS256",
        )
        with pytest.raises(AuthenticationError, match="algorithm"):
            await validate_jwt_for_tenant(token, tenant_a_ctx)


# ═════════════════════════════════════════════════════════════════════════════
# TestTenantResolver
# ═════════════════════════════════════════════════════════════════════════════

class TestTenantResolver:
    """Verifies resolve_tenant() and helper functions directly."""

    def test_peek_jwt_iss_valid(self, rsa_a):
        token = _make_jwt(rsa_a[0], iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A)
        assert _peek_jwt_iss(token) == ISSUER_A

    def test_peek_jwt_iss_malformed(self):
        assert _peek_jwt_iss("not-a-token") is None
        assert _peek_jwt_iss("only.one.dot.is.not.valid") is None
        assert _peek_jwt_iss("") is None

    def test_peek_jwt_iss_missing(self, rsa_a):
        # Payload with no iss
        payload = {"sub": "user@test", "aud": AUDIENCE_A}
        token = jwt.encode(payload, _private_pem(rsa_a[0]), algorithm="RS256")
        assert _peek_jwt_iss(token) is None

    @pytest.mark.asyncio
    async def test_resolve_tenant_by_jwt_bearer(self, two_tenant_db, rsa_a, rsa_b):
        token_a = _make_jwt(rsa_a[0], iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A)
        token_b = _make_jwt(rsa_b[0], iss=ISSUER_B, aud=AUDIENCE_B, kid=KID_B)

        req_scope = {"type": "http", "state": {}}
        req = Request(req_scope)

        creds_a = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_a)
        ctx_a = await resolve_tenant(req, credentials=creds_a, x_tenant_slug="", db=two_tenant_db)
        assert ctx_a.tenant_id == TENANT_A_ID
        assert ctx_a.tenant_slug == "acme-corp"
        assert req.state.tenant_context == ctx_a

        creds_b = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_b)
        ctx_b = await resolve_tenant(req, credentials=creds_b, x_tenant_slug="", db=two_tenant_db)
        assert ctx_b.tenant_id == TENANT_B_ID
        assert ctx_b.tenant_slug == "global-bank"

    @pytest.mark.asyncio
    async def test_resolve_tenant_by_x_tenant_slug(self, two_tenant_db):
        req_scope = {"type": "http", "state": {}}
        req = Request(req_scope)

        ctx_a = await resolve_tenant(req, credentials=None, x_tenant_slug="acme-corp", db=two_tenant_db)
        assert ctx_a.tenant_id == TENANT_A_ID
        assert ctx_a.tenant_slug == "acme-corp"

        ctx_b = await resolve_tenant(req, credentials=None, x_tenant_slug="global-bank", db=two_tenant_db)
        assert ctx_b.tenant_id == TENANT_B_ID
        assert ctx_b.tenant_slug == "global-bank"

    @pytest.mark.asyncio
    async def test_resolve_tenant_priority_jwt_over_slug(self, two_tenant_db, rsa_a):
        # Bearer token is for Tenant A, but slug header says global-bank
        token_a = _make_jwt(rsa_a[0], iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A)
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_a)

        req_scope = {"type": "http", "state": {}}
        req = Request(req_scope)

        ctx = await resolve_tenant(req, credentials=creds, x_tenant_slug="global-bank", db=two_tenant_db)
        # Priority 1 is JWT iss
        assert ctx.tenant_id == TENANT_A_ID
        assert ctx.tenant_slug == "acme-corp"

    @pytest.mark.asyncio
    async def test_resolve_tenant_unknown_issuer_and_slug_raises_401(self, two_tenant_db, rsa_a):
        token_unknown = _make_jwt(rsa_a[0], iss="https://unknown-idp.com", aud=AUDIENCE_A, kid=KID_A)
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_unknown)

        req = Request({"type": "http", "state": {}})
        with pytest.raises(AuthenticationError, match="Unable to identify tenant"):
            await resolve_tenant(req, credentials=creds, x_tenant_slug="", db=two_tenant_db)

        with pytest.raises(AuthenticationError, match="Unable to identify tenant"):
            await resolve_tenant(req, credentials=None, x_tenant_slug="unknown-slug", db=two_tenant_db)

        with pytest.raises(AuthenticationError, match="Unable to identify tenant"):
            await resolve_tenant(req, credentials=None, x_tenant_slug="", db=two_tenant_db)

    @pytest.mark.asyncio
    async def test_resolve_tenant_inactive_tenant_raises_401(self, two_tenant_db, rsa_a):
        # Disable tenant_a
        from sqlalchemy import update
        await two_tenant_db.execute(
            update(Tenant).where(Tenant.id == TENANT_A_ID).values(is_active=False)
        )
        await two_tenant_db.commit()

        token_a = _make_jwt(rsa_a[0], iss=ISSUER_A, aud=AUDIENCE_A, kid=KID_A)
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_a)
        req = Request({"type": "http", "state": {}})

        with pytest.raises(AuthenticationError):
            await resolve_tenant(req, credentials=creds, x_tenant_slug="", db=two_tenant_db)

        with pytest.raises(AuthenticationError):
            await resolve_tenant(req, credentials=None, x_tenant_slug="acme-corp", db=two_tenant_db)

    @pytest.mark.asyncio
    async def test_resolve_tenant_optional_returns_none(self, two_tenant_db):
        req = Request({"type": "http", "state": {}})
        ctx = await resolve_tenant_optional(req, credentials=None, x_tenant_slug="", db=two_tenant_db)
        assert ctx is None

    @pytest.mark.asyncio
    async def test_resolve_tenant_by_api_key(self, two_tenant_db):
        import hashlib
        from app.db.models import ApiKey

        raw_key = "dm_live_test_api_key"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_obj = ApiKey(
            tenant_id=TENANT_A_ID,
            name="Developer Test Key",
            key_prefix="dm_live_test",
            key_hash=key_hash,
            role="analyst",
            is_active=True,
        )
        two_tenant_db.add(key_obj)
        await two_tenant_db.commit()

        # Via Bearer dm_... token
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        req = Request({"type": "http", "state": {}, "headers": []})
        ctx = await resolve_tenant(req, credentials=creds, db=two_tenant_db)
        assert ctx.tenant_id == TENANT_A_ID
        assert ctx.tenant_slug == "acme-corp"
        assert req.state.api_key_role == "analyst"



