"""End-to-end tests for the /mask endpoint in enterprise_jwt auth mode.

These tests exercise the full auth stack from HTTP request to masked response
using a real TestClient, real RSA keys, and real PyJWT encoding/decoding.

Security boundary coverage:
  - Valid JWT + authorized group → correct masking profile applied
  - Expired JWT → 401
  - Invalid signature → 401
  - Wrong issuer → 401
  - Wrong audience → 401
  - Missing Authorization header → 401
  - Malformed Bearer token → 401
  - Valid JWT, groups claim absent → 403
  - Valid JWT, groups present, none mapped → 403
  - Multiple groups, deterministic priority resolution
  - AUTH_MODE=local still works (existing test suite regression guard)
  - No auth failure returns unmasked data (invariant check)
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.idp.jwks_client import JWKSCache, set_jwks_cache
from tests.test_jwt_validation import (
    AUDIENCE,
    ISSUER,
    KID,
    _generate_rsa_keypair,
    _make_jwt,
    _rsa_jwk,
    _seed_cache,
    _private_key_pem,
)


# ── Policy used for enterprise tests ─────────────────────────────────────────

ENTERPRISE_POLICY = """
version: "3.0"
record_root: "$.patients[*]"

roles:
  analyst:
    default_fallback: drop_subtree
  auditor:
    default_fallback: masked
  operator:
    default_fallback: default_allow

profiles:
  pii_mask:
    rules:
      - selector: "$..name"
        technique: redact
      - selector: "$..ssn"
        technique: suppress

scopes:
  - path: "$.patients[*]"
    roles:
      analyst:
        strategy: masked
        profile: pii_mask
      auditor:
        strategy: masked
        profile: pii_mask
      operator:
        strategy: default_allow
      default:
        strategy: masked
        profile: pii_mask

rules: []
k_anonymity:
  enabled: false
  k: 2
  quasi_identifiers: []
"""

SAMPLE_DATA = json.dumps({
    "patients": [
        {"name": "Alice", "ssn": "111-22-3333", "dob": "1985-07-23"},
        {"name": "Bob",   "ssn": "444-55-6666", "dob": "1985-07-23"},
    ]
})

GROUP_MAPPINGS = [
    {"group": "data-analysts", "internal_role": "analyst",  "priority": 20},
    {"group": "finance-team",  "internal_role": "auditor",  "priority": 10},
    {"group": "admin-users",   "internal_role": "operator", "priority": 1},
]


# ── Fixture: enterprise TestClient ────────────────────────────────────────────

@pytest.fixture(scope="module")
def enterprise_client_env():
    """TestClient wired to enterprise_jwt auth mode."""
    import gc
    import shutil

    import app.hierarchies  # ensure registered

    data_dir = tempfile.mkdtemp()
    try:
        # Write sample data
        data_path = os.path.join(data_dir, "sample.json")
        with open(data_path, "w") as f:
            f.write(SAMPLE_DATA)
        data_file = os.path.basename(data_path)

        # Write policy
        policy_path = os.path.join(data_dir, "policy.yaml")
        with open(policy_path, "w") as f:
            f.write(ENTERPRISE_POLICY)

        # Write group mappings
        mappings_path = os.path.join(data_dir, "group_mappings.json")
        with open(mappings_path, "w") as f:
            json.dump(GROUP_MAPPINGS, f)

        audit_log = os.path.join(data_dir, "audit.log")

        priv, pub = _generate_rsa_keypair()
        jwk = _rsa_jwk(pub, KID)
        jwks_uri = f"{ISSUER}/.well-known/jwks.json"

        env_vars = {
            "DATA_DIR":        data_dir,
            "POLICY_PATH":     policy_path,
            "AUDIT_LOG_PATH":  audit_log,
            "API_TOKENS":      json.dumps({"local-tok": "analyst"}),
            "APP_LOG_LEVEL":   "WARNING",
            "AUTH_MODE":       "enterprise_jwt",
            "IDP_ISSUER":      ISSUER,
            "IDP_AUDIENCE":    AUDIENCE,
            "IDP_MAPPINGS_PATH": mappings_path,
            "IDP_GROUPS_CLAIM": "groups",
            "IDP_JWKS_URI":     jwks_uri,
        }

        with patch.dict(os.environ, env_vars):
            import app.config as cfg_mod
            cfg_mod._settings = None
            from app.policy import loader as pl_mod
            pl_mod._policy = None

            # Reset auth module state
            import app.auth as auth_mod
            from app.auth import EnvTokenStore
            auth_mod._store = EnvTokenStore()

            # Pre-seed JWKS cache so no network calls are made
            cache = JWKSCache(ttl_seconds=300)
            _seed_cache(cache, jwks_uri, [jwk])
            set_jwks_cache(cache)

            # Reset group mapper
            from app.idp.group_mapper import GroupMappingStore, set_group_mapping_store
            store = GroupMappingStore()
            store.load(mappings_path)
            set_group_mapping_store(store)

            from app.main import app as fastapi_app
            with TestClient(fastapi_app) as c:
                yield c, data_file, priv, pub, jwks_uri

    finally:
        gc.collect()
        shutil.rmtree(data_dir, ignore_errors=True)


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Valid JWT tests ───────────────────────────────────────────────────────────

class TestEnterpriseValidJWT:
    def test_analyst_group_gets_masked_data(self, enterprise_client_env):
        client, fname, priv, pub, _ = enterprise_client_env
        token = _make_jwt(priv, extra_claims={"groups": ["data-analysts"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        if resp.status_code != 200:
            print("RESP BODY:", resp.json())
        assert resp.status_code == 200
        data = resp.json()
        # analyst: name should be redacted, ssn suppressed
        assert data["patients"][0]["name"] == "[REDACTED]"
        assert "ssn" not in data["patients"][0]

    def test_auditor_group_gets_masked_data(self, enterprise_client_env):
        client, fname, priv, pub, _ = enterprise_client_env
        token = _make_jwt(priv, extra_claims={"groups": ["finance-team"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 200

    def test_x_role_header_reflects_resolved_role(self, enterprise_client_env):
        client, fname, priv, pub, _ = enterprise_client_env
        token = _make_jwt(priv, extra_claims={"groups": ["data-analysts"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.headers.get("X-Role") == "analyst"

    def test_finance_team_resolves_to_auditor_role(self, enterprise_client_env):
        client, fname, priv, pub, _ = enterprise_client_env
        token = _make_jwt(priv, extra_claims={"groups": ["finance-team"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.headers.get("X-Role") == "auditor"


# ── Failure modes — must all be 4xx/5xx, never unmasked ──────────────────────

class TestEnterpriseFailClosed:
    def test_missing_auth_header_returns_401(self, enterprise_client_env):
        client, fname, *_ = enterprise_client_env
        resp = client.post("/mask", json={"filename": fname})
        assert resp.status_code == 401
        # Critically: response must NOT contain patient data
        body = resp.text
        assert "Alice" not in body
        assert "111-22" not in body

    def test_malformed_bearer_returns_401(self, enterprise_client_env):
        client, fname, *_ = enterprise_client_env
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer("not.a.jwt"))
        assert resp.status_code == 401
        assert "Alice" not in resp.text

    def test_expired_jwt_returns_401(self, enterprise_client_env):
        client, fname, priv, *_ = enterprise_client_env
        token = _make_jwt(priv, exp_offset=-1, extra_claims={"groups": ["data-analysts"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 401
        assert "Alice" not in resp.text

    def test_wrong_issuer_returns_401(self, enterprise_client_env):
        client, fname, priv, *_ = enterprise_client_env
        token = _make_jwt(priv, iss="https://evil.idp", extra_claims={"groups": ["data-analysts"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 401
        assert "Alice" not in resp.text

    def test_wrong_audience_returns_401(self, enterprise_client_env):
        client, fname, priv, *_ = enterprise_client_env
        token = _make_jwt(priv, aud="other-service", extra_claims={"groups": ["data-analysts"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 401
        assert "Alice" not in resp.text

    def test_invalid_signature_returns_401(self, enterprise_client_env):
        client, fname, priv, *_ = enterprise_client_env
        token = _make_jwt(priv, extra_claims={"groups": ["data-analysts"]})
        parts = token.split(".")
        parts[2] = parts[2][:-4] + "XXXX"
        tampered = ".".join(parts)
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(tampered))
        assert resp.status_code == 401
        assert "Alice" not in resp.text

    def test_valid_jwt_no_groups_claim_returns_403(self, enterprise_client_env):
        client, fname, priv, *_ = enterprise_client_env
        # JWT is valid but has no groups claim
        token = _make_jwt(priv)
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 403
        assert "Alice" not in resp.text

    def test_valid_jwt_unmapped_group_returns_403(self, enterprise_client_env):
        client, fname, priv, *_ = enterprise_client_env
        token = _make_jwt(priv, extra_claims={"groups": ["unregistered-group"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 403
        assert "Alice" not in resp.text

    def test_key_from_different_pair_returns_401(self, enterprise_client_env):
        """JWT signed by an unknown key (not in JWKS) must be rejected."""
        client, fname, priv, pub, jwks_uri = enterprise_client_env
        different_priv, _ = _generate_rsa_keypair()
        token = _make_jwt(different_priv, extra_claims={"groups": ["data-analysts"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 401
        assert "Alice" not in resp.text


# ── Multi-group determinism ───────────────────────────────────────────────────

class TestMultiGroupResolution:
    def test_higher_priority_group_wins(self, enterprise_client_env):
        """admin-users (priority=1) beats data-analysts (priority=20)."""
        client, fname, priv, *_ = enterprise_client_env
        token = _make_jwt(priv, extra_claims={"groups": ["data-analysts", "admin-users"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 200
        assert resp.headers.get("X-Role") == "operator"

    def test_result_independent_of_jwt_claim_order(self, enterprise_client_env):
        """Same groups in different order produce the same role."""
        client, fname, priv, *_ = enterprise_client_env
        t1 = _make_jwt(priv, extra_claims={"groups": ["data-analysts", "finance-team"]})
        t2 = _make_jwt(priv, extra_claims={"groups": ["finance-team", "data-analysts"]})
        r1 = client.post("/mask", json={"filename": fname}, headers=_bearer(t1))
        r2 = client.post("/mask", json={"filename": fname}, headers=_bearer(t2))
        assert r1.headers.get("X-Role") == r2.headers.get("X-Role") == "auditor"

    def test_one_mapped_one_unmapped_uses_mapped(self, enterprise_client_env):
        client, fname, priv, *_ = enterprise_client_env
        token = _make_jwt(priv, extra_claims={"groups": ["data-analysts", "unknown-group"]})
        resp = client.post("/mask", json={"filename": fname}, headers=_bearer(token))
        assert resp.status_code == 200
        assert resp.headers.get("X-Role") == "analyst"
