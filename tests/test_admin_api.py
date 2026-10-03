"""Tests for Enterprise Admin Control Plane REST API endpoints.
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.idp.group_mapper import GroupMapping, GroupMappingStore, set_group_mapping_store
from app.policy.loader import load_policy_from_string
from app.routes.admin import router as admin_router


@pytest.fixture
def admin_client_env():
    """Set up TestClient with isolated temporary policy file and group mappings."""
    tmpdir = tempfile.mkdtemp()
    try:
        policy_file = os.path.join(tmpdir, "policy.yaml")
        mappings_file = os.path.join(tmpdir, "group_mappings.json")
        audit_file = os.path.join(tmpdir, "audit.log")

        # Initial policy content
        sample_policy_yaml = """
version: "3.0"
record_root:
  - "$.patients[*]"

roles:
  analyst:
    default_fallback: drop_subtree
  auditor:
    default_fallback: masked
  operator:
    default_fallback: default_allow

profiles:
  personal_pii:
    rules:
      - selector: "$..email"
        technique: redact

scopes:
  - path: "$..email"
    roles:
      analyst:
        profile: personal_pii
      auditor:
        strategy: masked
"""
        with open(policy_file, "w", encoding="utf-8") as f:
            f.write(sample_policy_yaml)

        # Initial mappings
        initial_mappings = [
            {"group": "admin-users", "internal_role": "operator", "priority": 1},
            {"group": "finance-team", "internal_role": "auditor", "priority": 10},
            {"group": "data-analysts", "internal_role": "analyst", "priority": 20},
        ]
        with open(mappings_file, "w", encoding="utf-8") as f:
            json.dump(initial_mappings, f)

        # Load policy singleton
        from app.policy import loader as pl_mod
        pl_mod._policy = load_policy_from_string(sample_policy_yaml)

        # Environment patch
        env_vars = {
            "DATA_DIR": tmpdir,
            "POLICY_PATH": policy_file,
            "AUDIT_LOG_PATH": audit_file,
            "API_TOKENS": '{"tok-analyst": "analyst"}',
            "AUTH_MODE": "enterprise_jwt",
            "IDP_ISSUER": "http://localhost:8088",
            "IDP_AUDIENCE": "masking-service",
            "IDP_MAPPINGS_PATH": mappings_file,
            "ADMIN_USERNAME": "testadmin",
            "ADMIN_PASSWORD": "testpassword123",
            "ADMIN_TOKEN": "static-admin-api-key",
        }

        with patch.dict(os.environ, env_vars):
            from app.config import init_settings
            init_settings()

            from app.main import app as fastapi_app
            from app.idp.group_mapper import get_group_mapping_store
            with TestClient(fastapi_app) as client:
                yield client, policy_file, mappings_file, get_group_mapping_store()
    finally:
        import logging
        logging.shutdown()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestAdminAuth:
    def test_login_success(self, admin_client_env):
        client, *_ = admin_client_env
        resp = client.post(
            "/api/v1/admin/login",
            json={"username": "testadmin", "password": "testpassword123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "token" in data
        assert data["token"].startswith("admin_session_")

    def test_login_invalid_credentials(self, admin_client_env):
        client, *_ = admin_client_env
        resp = client.post(
            "/api/v1/admin/login",
            json={"username": "testadmin", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    def test_unauthorized_admin_access(self, admin_client_env):
        client, *_ = admin_client_env
        resp = client.get("/api/v1/admin/mappings")
        assert resp.status_code == 401

    def test_static_admin_token_access(self, admin_client_env):
        client, *_ = admin_client_env
        resp = client.get(
            "/api/v1/admin/mappings",
            headers={"X-Admin-API-Key": "static-admin-api-key"},
        )
        assert resp.status_code == 200


class TestAdminGroupMappingsCRUD:
    def _login(self, client):
        resp = client.post(
            "/api/v1/admin/login",
            json={"username": "testadmin", "password": "testpassword123"},
        )
        return resp.json()["token"]

    def test_list_mappings(self, admin_client_env):
        client, *_ = admin_client_env
        token = self._login(client)
        resp = client.get(
            "/api/v1/admin/mappings",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        groups = [m["group"] for m in data["mappings"]]
        assert "finance-team" in groups

    def test_upsert_and_delete_mapping(self, admin_client_env):
        client, _, mappings_file, store = admin_client_env
        token = self._login(client)

        # Upsert
        resp = client.post(
            "/api/v1/admin/mappings",
            json={"group": "hr-team", "internal_role": "auditor", "priority": 5},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert store.get("hr-team") is not None
        assert store.get("hr-team").priority == 5

        # Check file persisted
        with open(mappings_file, "r", encoding="utf-8") as f:
            file_data = json.load(f)
        file_groups = [item["group"] for item in file_data]
        assert "hr-team" in file_groups

        # Delete
        resp = client.delete(
            "/api/v1/admin/mappings/hr-team",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert store.get("hr-team") is None


class TestAdminSimulationAndPolicy:
    def _login(self, client):
        resp = client.post(
            "/api/v1/admin/login",
            json={"username": "testadmin", "password": "testpassword123"},
        )
        return resp.json()["token"]

    def test_simulate_resolution(self, admin_client_env):
        client, *_ = admin_client_env
        token = self._login(client)
        resp = client.post(
            "/api/v1/admin/simulate-resolution",
            json={"groups": ["data-analysts", "admin-users"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["resolved_role"] == "operator"

    def test_get_and_update_policy(self, admin_client_env):
        client, policy_file, *_ = admin_client_env
        token = self._login(client)

        # Get policy
        resp = client.get(
            "/api/v1/admin/policy",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "yaml_content" in resp.json()

        # Update policy with valid YAML
        new_yaml = """
version: "3.0"
record_root:
  - "$.patients[*]"
roles:
  analyst:
    default_fallback: drop_subtree
profiles:
  test_prof:
    rules:
      - selector: "$..email"
        technique: redact
scopes: []
"""
        resp = client.put(
            "/api/v1/admin/policy",
            json={"yaml_content": new_yaml},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Verify file content updated
        with open(policy_file, "r", encoding="utf-8") as f:
            saved_yaml = f.read()
        assert "test_prof" in saved_yaml

    def test_update_policy_invalid_yaml(self, admin_client_env):
        client, *_ = admin_client_env
        token = self._login(client)
        resp = client.put(
            "/api/v1/admin/policy",
            json={"yaml_content": "invalid_yaml: [unclosed_bracket"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400


class TestAdminSandbox:
    def _login(self, client):
        resp = client.post(
            "/api/v1/admin/login",
            json={"username": "testadmin", "password": "testpassword123"},
        )
        return resp.json()["token"]

    def test_sandbox_mask(self, admin_client_env):
        client, *_ = admin_client_env
        token = self._login(client)
        resp = client.post(
            "/api/v1/admin/sandbox",
            json={
                "payload": {"email": "test@example.com"},
                "role": "analyst",
                "format": "json",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "masked_output" in data
        assert "metrics" in data
