"""Endpoint integration tests using FastAPI's TestClient."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Generator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


# ── Policy YAML used for endpoint tests ──────────────────────────────────────

ENDPOINT_POLICY = """
version: "1.0"
record_root: "$.patients[*]"
rules:
  - selector: "$..name"
    technique: redact
  - selector: "$..ssn"
    technique: suppress
  - selector: "$..dob"
    technique: generalize
    hierarchy: date
    level: 2
"""

SAMPLE_JSON = json.dumps({
    "patients": [
        {"name": "Alice", "ssn": "111-22", "dob": "1985-01-01"},
        {"name": "Bob",   "ssn": "333-44", "dob": "1985-01-01"},
    ]
}).encode()

TOKENS = {
    "tok-analyst": "analyst",
    "tok-operator": "operator",
    "tok-auditor": "auditor",
}


@pytest.fixture(scope="module")
def client_env():
    """Set up a temp dir and patch env vars, then yield a TestClient."""
    import gc
    import shutil

    import app.hierarchies  # ensure registered

    data_dir = tempfile.mkdtemp()
    try:
        data_path = os.path.join(data_dir, "sample.json")
        with open(data_path, "wb") as f:
            f.write(SAMPLE_JSON)
        data_file = os.path.basename(data_path)

        policy_file_path = os.path.join(data_dir, "test_policy.yaml")
        with open(policy_file_path, "w") as pf:
            pf.write(ENDPOINT_POLICY)

        audit_log = os.path.join(data_dir, "audit.log")

        env_vars = {
            "DATA_DIR": data_dir,
            "POLICY_PATH": policy_file_path,
            "AUDIT_LOG_PATH": audit_log,
            "API_TOKENS": json.dumps(TOKENS),
            "APP_LOG_LEVEL": "WARNING",
        }

        with patch.dict(os.environ, env_vars):
            import app.config as cfg_mod
            cfg_mod._settings = None
            from app.policy import loader as pl_mod
            pl_mod._policy = None
            import app.auth as auth_mod
            from app.auth import EnvTokenStore
            auth_mod._store = EnvTokenStore()

            from app.main import app as fastapi_app
            with TestClient(fastapi_app) as c:
                yield c, data_file, audit_log

    finally:
        gc.collect()
        shutil.rmtree(data_dir, ignore_errors=True)


class TestHealthEndpoint:
    def test_health_returns_200(self, client_env):
        client, _, _ = client_env
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "policy_version" in data

    def test_health_no_auth_required(self, client_env):
        client, _, _ = client_env
        resp = client.get("/health")
        assert resp.status_code == 200


class TestMaskEndpoint:
    def test_analyst_gets_masked_json(self, client_env):
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["patients"][0]["name"] == "[REDACTED]"
        assert "ssn" not in data["patients"][0]

    def test_analyst_response_headers_present(self, client_env):
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert "X-Request-ID" in resp.headers
        assert "X-Policy-Version" in resp.headers
        assert "X-Conflict-Count" in resp.headers
        assert "X-Uncovered-Count" in resp.headers
        assert "X-K-Anonymity-Achieved" in resp.headers

    def test_auditor_gets_labelled_output(self, client_env):
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-API-Token": "tok-auditor"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "WOULD APPLY" in data["patients"][0]["name"]

    def test_operator_gets_raw_bytes(self, client_env):
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-API-Token": "tok-operator"},
        )
        assert resp.status_code == 200
        # Raw bytes should still be valid JSON (our sample is JSON)
        data = resp.json()
        assert "patients" in data

    def test_operator_writes_audit_log(self, client_env):
        client, fname, audit_log = client_env
        client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-API-Token": "tok-operator"},
        )
        assert os.path.exists(audit_log)
        content = open(audit_log).read()
        assert fname in content

    def test_missing_token_returns_401(self, client_env):
        client, fname, _ = client_env
        resp = client.post("/mask", json={"filename": fname})
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, client_env):
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-API-Token": "bad-token"},
        )
        assert resp.status_code == 401

    def test_missing_file_returns_404(self, client_env):
        client, _, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": "nonexistent.json"},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 404

    def test_unsupported_extension_returns_400(self, client_env):
        client, _, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": "file.txt"},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 400

    def test_request_id_in_every_response(self, client_env):
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert "X-Request-ID" in resp.headers


class TestPolicyEndpoint:
    def test_auditor_can_access_policy(self, client_env):
        client, _, _ = client_env
        resp = client.get("/policy", headers={"X-API-Token": "tok-auditor"})
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data

    def test_operator_can_access_policy(self, client_env):
        client, _, _ = client_env
        resp = client.get("/policy", headers={"X-API-Token": "tok-operator"})
        assert resp.status_code == 200

    def test_analyst_gets_403(self, client_env):
        client, _, _ = client_env
        resp = client.get("/policy", headers={"X-API-Token": "tok-analyst"})
        assert resp.status_code == 403


class TestAuditEndpoints:
    def test_coverage_requires_auditor(self, client_env):
        client, fname, _ = client_env
        resp = client.get(
            f"/audit/coverage?filename={fname}",
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 403

    def test_auditor_can_get_coverage(self, client_env):
        client, fname, _ = client_env
        resp = client.get(
            f"/audit/coverage?filename={fname}",
            headers={"X-API-Token": "tok-auditor"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "covered_nodes" in data
        assert "uncovered_nodes" in data

    def test_conflicts_endpoint_returns_404_for_unknown_id(self, client_env):
        client, _, _ = client_env
        resp = client.get(
            "/audit/conflicts/nonexistent-id",
            headers={"X-API-Token": "tok-auditor"},
        )
        assert resp.status_code == 404

    def test_conflicts_endpoint_returns_log_after_mask(self, client_env):
        client, fname, _ = client_env
        mask_resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-API-Token": "tok-auditor"},
        )
        rid = mask_resp.headers.get("X-Request-ID")
        assert rid
        conf_resp = client.get(
            f"/audit/conflicts/{rid}",
            headers={"X-API-Token": "tok-auditor"},
        )
        assert conf_resp.status_code == 200
        data = conf_resp.json()
        assert "conflicts" in data


# ─────────────────────────────────────────────────────────────────────────────
# v2.0 Tests: X-Masking-Role header
# ─────────────────────────────────────────────────────────────────────────────

class TestXMaskingRoleHeader:
    """Tests for the X-Masking-Role header (v2 role resolution)."""

    def test_analyst_via_masking_role_header(self, client_env):
        """X-Masking-Role: analyst masks the document (no X-API-Token needed)."""
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "analyst"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["patients"][0]["name"] == "[REDACTED]"
        assert "ssn" not in data["patients"][0]

    def test_auditor_via_masking_role_header(self, client_env):
        """X-Masking-Role: auditor returns labelled output."""
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "auditor"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "WOULD APPLY" in data["patients"][0]["name"]

    def test_operator_via_masking_role_header(self, client_env):
        """X-Masking-Role: operator returns raw bytes unchanged."""
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "operator"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "patients" in data

    def test_masking_role_takes_priority_over_token(self, client_env):
        """X-Masking-Role overrides X-API-Token when both are present."""
        client, fname, _ = client_env
        # Token says operator, header says analyst — header should win
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={
                "X-Masking-Role": "analyst",
                "X-API-Token":    "tok-operator",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # analyst masking applied (name redacted), not operator pass-through
        assert data["patients"][0]["name"] == "[REDACTED]"

    def test_unknown_masking_role_returns_401(self, client_env):
        """Unknown role in X-Masking-Role header → 401 Unauthorized."""
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "superadmin"},
        )
        assert resp.status_code == 401

    def test_no_auth_headers_returns_401(self, client_env):
        """Neither X-Masking-Role nor X-API-Token → 401."""
        client, fname, _ = client_env
        resp = client.post("/mask", json={"filename": fname})
        assert resp.status_code == 401

    def test_masking_role_header_case_insensitive(self, client_env):
        """X-Masking-Role value is lower-cased before comparison."""
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "ANALYST"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["patients"][0]["name"] == "[REDACTED]"

    def test_role_header_returned_in_response(self, client_env):
        """X-Role response header reflects the resolved role."""
        client, fname, _ = client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "analyst"},
        )
        assert resp.headers.get("X-Role") == "analyst"


# ─────────────────────────────────────────────────────────────────────────────
# v2.0 Tests: scope response headers
# ─────────────────────────────────────────────────────────────────────────────

# A v2 policy fixture for endpoint tests (scopes + profiles)
V2_ENDPOINT_POLICY = """
version: "2.0"
record_root: "$.patients[*]"

profiles:
  mini_pii:
    rules:
      - selector: "$..name"
        technique: redact
      - selector: "$..ssn"
        technique: suppress

scopes:
  - path: "$.patients[*].billing"
    roles:
      analyst:
        strategy: drop_subtree
      auditor:
        strategy: masked
      default:
        strategy: drop_subtree
    rules:
      - selector: "$..card_number"
        technique: mask_pattern
        pattern: "****-{last4}"

  - path: "$.patients[*].personal_info"
    apply_profile: mini_pii
    roles:
      analyst:
        strategy: masked
      default:
        strategy: masked

rules:
  - selector: "$..patient_id"
    technique: pseudonymize
    consistent: true

k_anonymity:
  enabled: false
  k: 2
  quasi_identifiers: []
"""


@pytest.fixture(scope="module")
def v2_client_env():
    """TestClient fixture wired to the v2 endpoint policy and v2 sample data."""
    import gc
    import json as json_mod
    import shutil

    import app.hierarchies  # ensure registered

    data_dir = tempfile.mkdtemp()
    try:
        # Write v2 sample data
        v2_data = json_mod.dumps({
            "patients": [
                {
                    "patient_id": "P001",
                    "personal_info": {"name": "Alice", "ssn": "111-22-3333"},
                    "billing": {"card_number": "4111-1111-1111-1234", "cvv": "123"},
                },
                {
                    "patient_id": "P002",
                    "personal_info": {"name": "Bob", "ssn": "444-55-6666"},
                    "billing": {"card_number": "5500-0000-0000-0004", "cvv": "456"},
                },
            ]
        })
        data_path = os.path.join(data_dir, "v2_sample.json")
        with open(data_path, "w") as f:
            f.write(v2_data)
        data_file = os.path.basename(data_path)

        policy_path = os.path.join(data_dir, "v2_policy.yaml")
        with open(policy_path, "w") as pf:
            pf.write(V2_ENDPOINT_POLICY)

        audit_log = os.path.join(data_dir, "audit.log")
        env_vars = {
            "DATA_DIR":        data_dir,
            "POLICY_PATH":     policy_path,
            "AUDIT_LOG_PATH":  audit_log,
            "API_TOKENS":      json_mod.dumps({"tok-analyst": "analyst", "tok-auditor": "auditor"}),
            "APP_LOG_LEVEL":   "WARNING",
        }

        with patch.dict(os.environ, env_vars):
            import app.config as cfg_mod
            cfg_mod._settings = None
            from app.policy import loader as pl_mod
            pl_mod._policy = None
            import app.auth as auth_mod
            from app.auth import EnvTokenStore
            auth_mod._store = EnvTokenStore()

            from app.main import app as fastapi_app
            with TestClient(fastapi_app) as c:
                yield c, data_file

    finally:
        gc.collect()
        shutil.rmtree(data_dir, ignore_errors=True)


class TestV2ScopeResponseHeaders:
    """Verify new v2 scope headers appear in the /mask response."""

    def test_scope_headers_present_for_analyst(self, v2_client_env):
        client, fname = v2_client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "analyst"},
        )
        assert resp.status_code == 200
        assert "X-Scopes-Evaluated" in resp.headers
        assert "X-Scopes-Dropped" in resp.headers
        assert "X-Profiles-Applied" in resp.headers

    def test_scopes_evaluated_is_positive(self, v2_client_env):
        client, fname = v2_client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "analyst"},
        )
        evaluated = int(resp.headers["X-Scopes-Evaluated"])
        assert evaluated > 0, "Should have evaluated at least one scope"

    def test_analyst_has_scopes_dropped(self, v2_client_env):
        client, fname = v2_client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "analyst"},
        )
        dropped = int(resp.headers["X-Scopes-Dropped"])
        assert dropped > 0, "analyst should have at least one drop_subtree scope"

    def test_profiles_applied_contains_mini_pii(self, v2_client_env):
        client, fname = v2_client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "analyst"},
        )
        profiles = resp.headers.get("X-Profiles-Applied", "")
        assert "mini_pii" in profiles

    def test_auditor_has_zero_dropped_scopes(self, v2_client_env):
        client, fname = v2_client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "auditor"},
        )
        # auditor has strategy: masked for billing, not drop_subtree
        dropped = int(resp.headers["X-Scopes-Dropped"])
        assert dropped == 0, f"auditor should not drop any scopes, got {dropped}"

    def test_analyst_billing_dropped_in_output(self, v2_client_env):
        """Functional: analyst does not see billing key."""
        client, fname = v2_client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "analyst"},
        )
        data = resp.json()
        for patient in data["patients"]:
            assert "billing" not in patient

    def test_auditor_billing_present_and_masked(self, v2_client_env):
        """Functional: auditor sees billing with masked card_number."""
        client, fname = v2_client_env
        resp = client.post(
            "/mask",
            json={"filename": fname},
            headers={"X-Masking-Role": "auditor"},
        )
        data = resp.json()
        patient = data["patients"][0]
        assert "billing" in patient
        card = patient["billing"].get("card_number", "")
        assert "****" in str(card), f"Expected masked card, got: {card}"
