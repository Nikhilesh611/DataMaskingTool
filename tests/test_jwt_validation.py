"""Unit tests for JWT validation — covers all security boundary cases.

Uses cryptography library to generate real RSA and EC key pairs so we can:
  - Issue valid JWTs and verify they are accepted.
  - Issue tampered/expired/wrong-issuer/wrong-audience JWTs and verify they are rejected.
  - Simulate kid miss + JWKS refresh behavior.
  - Test extract_groups() with various claim structures.

No mocking of PyJWT internals — we exercise the real library to ensure
the security properties actually hold.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.exceptions import AuthenticationError
from app.idp.jwks_client import JWKSCache, JWKSKeyNotFoundError, set_jwks_cache
from app.idp.jwt_validator import extract_groups, validate_jwt


# ── Key generation helpers ────────────────────────────────────────────────────

def _generate_rsa_keypair() -> tuple:
    """Return (private_key, public_key) RSA 2048-bit pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def _generate_ec_keypair() -> tuple:
    """Return (private_key, public_key) EC P-256 pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def _private_key_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ── JWT issuance helper ───────────────────────────────────────────────────────

ISSUER = "https://idp.test"
AUDIENCE = "masking-service"
KID = "test-key-001"


def _make_jwt(
    private_key,
    *,
    alg: str = "RS256",
    kid: str = KID,
    iss: str = ISSUER,
    aud: str | list = AUDIENCE,
    exp_offset: int = 3600,
    nbf_offset: int = 0,
    extra_claims: dict | None = None,
) -> str:
    now = int(time.time())
    payload = {
        "sub": "user@corp.com",
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
    }
    if nbf_offset:
        payload["nbf"] = now + nbf_offset
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(
        payload,
        _private_key_pem(private_key),
        algorithm=alg,
        headers={"kid": kid} if kid else {},
    )


# ── JWKS construction helper ──────────────────────────────────────────────────

def _rsa_jwk(public_key, kid: str) -> dict:
    """Build a minimal RSA JWK from an RSA public key."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from jwt.algorithms import RSAAlgorithm
    return json.loads(RSAAlgorithm.to_jwk(public_key)) | {"kid": kid, "use": "sig", "alg": "RS256"}


def _ec_jwk(public_key, kid: str) -> dict:
    """Build a minimal EC JWK from an EC public key."""
    from jwt.algorithms import ECAlgorithm
    return json.loads(ECAlgorithm.to_jwk(public_key)) | {"kid": kid, "use": "sig", "alg": "ES256"}


# ── Fixture: pre-seeded JWKS cache (bypasses network) ────────────────────────

@pytest.fixture(autouse=True)
def isolated_jwks_cache():
    """Give each test its own JWKSCache to prevent inter-test pollution."""
    cache = JWKSCache(ttl_seconds=300)
    set_jwks_cache(cache)
    yield cache
    cache.clear()


@pytest.fixture
def rsa_keypair():
    return _generate_rsa_keypair()


@pytest.fixture
def ec_keypair():
    return _generate_ec_keypair()


@pytest.fixture
def jwks_uri():
    return "https://idp.test/.well-known/jwks.json"


def _seed_cache(cache: JWKSCache, jwks_uri: str, jwks: list[dict]) -> None:
    cache.set(jwks_uri, jwks)


# ── Valid JWT tests ───────────────────────────────────────────────────────────

class TestValidJWT:
    @pytest.mark.asyncio
    async def test_valid_rsa_jwt_accepted(self, rsa_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = rsa_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub, KID)])
        token = _make_jwt(priv, extra_claims={"groups": ["data-analysts"]})
        claims = await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)
        assert claims["iss"] == ISSUER
        assert claims["aud"] == AUDIENCE

    @pytest.mark.asyncio
    async def test_valid_ec_jwt_accepted(self, ec_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = ec_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_ec_jwk(pub, KID)])
        token = _make_jwt(priv, alg="ES256", extra_claims={"groups": ["finance-team"]})
        claims = await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)
        assert "groups" in claims

    @pytest.mark.asyncio
    async def test_groups_claim_in_returned_claims(self, rsa_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = rsa_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub, KID)])
        token = _make_jwt(priv, extra_claims={"groups": ["group-a", "group-b"]})
        claims = await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)
        assert claims["groups"] == ["group-a", "group-b"]


# ── Expired / timing tests ────────────────────────────────────────────────────

class TestExpiredAndTimingJWT:
    @pytest.mark.asyncio
    async def test_expired_jwt_raises_401(self, rsa_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = rsa_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub, KID)])
        token = _make_jwt(priv, exp_offset=-1)  # already expired
        with pytest.raises(AuthenticationError, match="expired"):
            await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)

    @pytest.mark.asyncio
    async def test_not_yet_valid_jwt_raises_401(self, rsa_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = rsa_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub, KID)])
        token = _make_jwt(priv, nbf_offset=9999)  # nbf far in the future
        with pytest.raises(AuthenticationError, match="not yet valid"):
            await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)


# ── Issuer / audience tests ───────────────────────────────────────────────────

class TestIssuerAudienceValidation:
    @pytest.mark.asyncio
    async def test_wrong_issuer_raises_401(self, rsa_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = rsa_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub, KID)])
        token = _make_jwt(priv, iss="https://evil.idp")
        with pytest.raises(AuthenticationError, match="issuer"):
            await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)

    @pytest.mark.asyncio
    async def test_wrong_audience_raises_401(self, rsa_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = rsa_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub, KID)])
        token = _make_jwt(priv, aud="other-service")
        with pytest.raises(AuthenticationError, match="audience"):
            await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)

    @pytest.mark.asyncio
    async def test_wrong_issuer_and_audience_raises_401(self, rsa_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = rsa_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub, KID)])
        token = _make_jwt(priv, iss="https://evil.idp", aud="other-service")
        with pytest.raises(AuthenticationError):
            await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)


# ── Signature tests ───────────────────────────────────────────────────────────

class TestSignatureValidation:
    @pytest.mark.asyncio
    async def test_invalid_signature_raises_401(self, rsa_keypair, isolated_jwks_cache, jwks_uri):
        priv, pub = rsa_keypair
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub, KID)])
        token = _make_jwt(priv)
        # Tamper with the signature (last segment)
        parts = token.split(".")
        parts[2] = parts[2][:-4] + "XXXX"
        tampered = ".".join(parts)
        with pytest.raises(AuthenticationError, match="signature"):
            await validate_jwt(tampered, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)

    @pytest.mark.asyncio
    async def test_key_from_different_pair_raises_401(self, isolated_jwks_cache, jwks_uri):
        """Token signed with key-A but JWKS has key-B → signature failure."""
        priv_a, pub_a = _generate_rsa_keypair()
        priv_b, pub_b = _generate_rsa_keypair()
        # JWKS has pub_b, token is signed with priv_a
        _seed_cache(isolated_jwks_cache, jwks_uri, [_rsa_jwk(pub_b, KID)])
        token = _make_jwt(priv_a)
        with pytest.raises(AuthenticationError):
            await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)


# ── Malformed token tests ─────────────────────────────────────────────────────

class TestMalformedToken:
    @pytest.mark.asyncio
    async def test_not_a_jwt_raises_401(self, isolated_jwks_cache, jwks_uri):
        with pytest.raises(AuthenticationError, match="Malformed"):
            await validate_jwt("not-a-jwt", ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)

    @pytest.mark.asyncio
    async def test_empty_string_raises_401(self, isolated_jwks_cache, jwks_uri):
        with pytest.raises(AuthenticationError):
            await validate_jwt("", ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)

    @pytest.mark.asyncio
    async def test_symmetric_alg_rejected(self, isolated_jwks_cache, jwks_uri):
        """HS256 tokens must be rejected — only asymmetric algorithms allowed."""
        token = jwt.encode(
            {"sub": "u", "iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 3600},
            "a-very-secure-hmac-test-key-32bytes",
            algorithm="HS256",
        )
        with pytest.raises(AuthenticationError, match="algorithm"):
            await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)


# ── JWKS kid rotation tests ───────────────────────────────────────────────────

class TestKidRotation:
    @pytest.mark.asyncio
    async def test_kid_not_in_cache_triggers_refresh_and_succeeds(
        self, rsa_keypair, isolated_jwks_cache, jwks_uri
    ):
        priv, pub = rsa_keypair
        new_kid = "rotated-key-002"
        # Cache is empty (simulating a rotated key not yet cached)
        token = _make_jwt(priv, kid=new_kid)
        # Patch _fetch_jwks_raw to return the new key on refresh
        new_jwk = _rsa_jwk(pub, new_kid)
        with patch(
            "app.idp.jwks_client._fetch_jwks_raw",
            new=AsyncMock(return_value=[new_jwk]),
        ):
            claims = await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)
        assert claims["iss"] == ISSUER

    @pytest.mark.asyncio
    async def test_kid_not_found_even_after_refresh_raises_401(
        self, rsa_keypair, isolated_jwks_cache, jwks_uri
    ):
        priv, pub = rsa_keypair
        unknown_kid = "completely-unknown-kid"
        token = _make_jwt(priv, kid=unknown_kid)
        # Patch refresh to return keys that still don't match
        different_jwk = _rsa_jwk(pub, "some-other-kid")
        with patch(
            "app.idp.jwks_client._fetch_jwks_raw",
            new=AsyncMock(return_value=[different_jwk]),
        ):
            with pytest.raises(JWKSKeyNotFoundError):
                await validate_jwt(token, ISSUER, AUDIENCE, jwks_uri_override=jwks_uri)


# ── extract_groups tests ──────────────────────────────────────────────────────

class TestExtractGroups:
    def test_standard_groups_claim(self):
        claims = {"sub": "u", "groups": ["finance-team", "data-analysts"]}
        assert extract_groups(claims, "groups") == ["finance-team", "data-analysts"]

    def test_missing_claim_returns_empty(self):
        claims = {"sub": "u"}
        assert extract_groups(claims, "groups") == []

    def test_non_list_claim_returns_empty(self):
        claims = {"sub": "u", "groups": "finance-team"}  # string, not list
        assert extract_groups(claims, "groups") == []

    def test_custom_claim_key(self):
        claims = {"sub": "u", "cognito:groups": ["admin-users"]}
        assert extract_groups(claims, "cognito:groups") == ["admin-users"]

    def test_filters_non_string_entries(self):
        claims = {"sub": "u", "groups": ["valid-group", 42, None, "another"]}
        result = extract_groups(claims, "groups")
        assert result == ["valid-group", "another"]

    def test_empty_groups_list(self):
        claims = {"sub": "u", "groups": []}
        assert extract_groups(claims, "groups") == []
