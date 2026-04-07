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
