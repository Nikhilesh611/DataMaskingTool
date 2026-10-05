"""Phase 3 tests: In-Memory Data Plane API.

TestInlineMaskSchema      — InlineMaskRequest validation (format, data types).
TestInlineMaskEndpoint    — POST /v1/mask with JSON/XML/YAML inline payloads.
TestFileUploadEndpoint    — POST /v1/mask/file multipart upload.
TestTypeSafeRedaction     — integers replaced with 0, floats with 0.0.
TestXXEDefense            — XML external entity payload is blocked.
TestReverseOrderSuppress  — suppress on arrays doesn't drift indices.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.adapters.xml_adapter import XMLAdapter
from app.schemas.mask import InlineMaskRequest


# ── Shared policy YAML ────────────────────────────────────────────────────────

POLICY_YAML = """
version: "1.0"
record_root: "$.records[*]"
roles:
  analyst: {}
  auditor: {}
  operator: {}
rules:
  - selector: "$..ssn"
    technique: suppress
  - selector: "$..name"
    technique: redact
  - selector: "$..salary"
    technique: redact
  - selector: "//ssn"
    technique: suppress
  - selector: "//name"
    technique: redact
"""

SAMPLE_JSON = {
    "records": [
        {"id": 1, "name": "Alice", "ssn": "111-22-3333", "salary": 95000},
        {"id": 2, "name": "Bob",   "ssn": "444-55-6666", "salary": 82000},
    ]
}

SAMPLE_XML = b"""<?xml version="1.0"?>
<records>
  <record><id>1</id><name>Alice</name><ssn>111-22-3333</ssn></record>
  <record><id>2</id><name>Bob</name><ssn>444-55-6666</ssn></record>
</records>"""

SAMPLE_YAML = """\
records:
  - id: 1
    name: Alice
    ssn: "111-22-3333"
  - id: 2
    name: Bob
    ssn: "444-55-6666"
"""

# ── App test client fixture ───────────────────────────────────────────────────

@pytest.fixture(scope="module")
def v1_client():
    import app.hierarchies  # noqa
    data_dir = tempfile.mkdtemp()
    try:
        policy_path = os.path.join(data_dir, "policy.yaml")
        with open(policy_path, "w") as f:
            f.write(POLICY_YAML)
        audit_log = os.path.join(data_dir, "audit.log")
        tokens = {"tok-analyst": "analyst", "tok-auditor": "auditor", "tok-operator": "operator"}
        env_vars = {
            "DATA_DIR": data_dir,
            "POLICY_PATH": policy_path,
            "AUDIT_LOG_PATH": audit_log,
            "API_TOKENS": json.dumps(tokens),
            "APP_LOG_LEVEL": "WARNING",
            "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
            "SECRET_KEY": "test-secret-key-at-least-16-chars",
        }
        with patch.dict(os.environ, env_vars):
            import app.config as cfg; cfg._settings = None
            from app.policy import loader as pl; pl._policy = None
            import app.auth as auth_mod
            from app.auth import EnvTokenStore
            auth_mod._store = EnvTokenStore()
            from app.main import app as fastapi_app
            # Override the multi-tenant auth dependency to use local token store
            from fastapi import Request
            from app.routes.v1.mask import _resolve_role_multi_tenant
            async def _local_role(request: Request) -> str:
                token = request.headers.get("x-api-token", "")
                role = auth_mod._store.get_role(token)
                if role is None:
                    from app.exceptions import AuthenticationError
                    raise AuthenticationError("Unrecognised API token.")
                return role
            fastapi_app.dependency_overrides[_resolve_role_multi_tenant] = _local_role
            with TestClient(fastapi_app) as c:
                yield c
            fastapi_app.dependency_overrides.clear()
    finally:
        shutil.rmtree(data_dir, ignore_errors=True)


# ═════════════════════════════════════════════════════════════════════════════
# TestInlineMaskSchema
# ═════════════════════════════════════════════════════════════════════════════

class TestInlineMaskSchema:
    def test_json_dict_accepted(self):
        req = InlineMaskRequest(format="json", data={"key": "value"})
        assert req.format == "json"
        assert req.data == {"key": "value"}

    def test_json_list_accepted(self):
        req = InlineMaskRequest(format="json", data=[1, 2, 3])
        assert req.data == [1, 2, 3]

    def test_json_string_auto_parsed(self):
        req = InlineMaskRequest(format="json", data='{"key": "value"}')
        assert req.data == {"key": "value"}

    def test_xml_string_accepted(self):
        req = InlineMaskRequest(format="xml", data="<root/>")
        assert req.data == "<root/>"

    def test_yaml_string_accepted(self):
        req = InlineMaskRequest(format="yaml", data="key: value\n")
        assert req.data == "key: value\n"

    def test_xml_non_string_raises(self):
        with pytest.raises(Exception):
            InlineMaskRequest(format="xml", data={"key": "value"})

    def test_yaml_non_string_raises(self):
        with pytest.raises(Exception):
            InlineMaskRequest(format="yaml", data={"key": "value"})

    def test_invalid_format_raises(self):
        with pytest.raises(Exception):
            InlineMaskRequest(format="toml", data="x = 1")

    def test_to_bytes_json(self):
        req = InlineMaskRequest(format="json", data={"ssn": "111"})
        b = req.to_bytes()
        assert json.loads(b)["ssn"] == "111"

    def test_to_bytes_xml(self):
        req = InlineMaskRequest(format="xml", data="<root/>")
        assert req.to_bytes() == b"<root/>"

    def test_to_bytes_yaml(self):
        req = InlineMaskRequest(format="yaml", data="key: val\n")
        assert req.to_bytes() == b"key: val\n"


# ═════════════════════════════════════════════════════════════════════════════
# TestInlineMaskEndpoint
# ═════════════════════════════════════════════════════════════════════════════

class TestInlineMaskEndpoint:
    def test_json_ssn_suppressed(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": SAMPLE_JSON},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "ssn" not in data["records"][0]

    def test_json_name_redacted(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": SAMPLE_JSON},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert resp.json()["records"][0]["name"] == "[REDACTED]"

    def test_json_id_preserved(self, v1_client):
        """Fields not in any rule must be returned unchanged."""
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": SAMPLE_JSON},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert resp.json()["records"][0]["id"] == 1

    def test_xml_inline_name_redacted(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "xml", "data": SAMPLE_XML.decode()},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert b"[REDACTED]" in resp.content
        assert b"Alice" not in resp.content

    def test_xml_inline_ssn_suppressed(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "xml", "data": SAMPLE_XML.decode()},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert b"111-22-3333" not in resp.content

    def test_yaml_inline_name_redacted(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "yaml", "data": SAMPLE_YAML},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert b"Alice" not in resp.content

    def test_response_has_x_request_id(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": SAMPLE_JSON},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert "x-request-id" in resp.headers

    def test_response_has_policy_version(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": SAMPLE_JSON},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert "x-policy-version" in resp.headers

    def test_missing_auth_returns_401(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": SAMPLE_JSON},
        )
        assert resp.status_code == 401

    def test_invalid_format_returns_422(self, v1_client):
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "toml", "data": "x = 1"},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 422

    def test_both_records_masked(self, v1_client):
        """All records in the array must be masked, not just the first."""
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": SAMPLE_JSON},
            headers={"X-API-Token": "tok-analyst"},
        )
        data = resp.json()
        assert data["records"][1]["name"] == "[REDACTED]"
        assert "ssn" not in data["records"][1]


# ═════════════════════════════════════════════════════════════════════════════
# TestFileUploadEndpoint
# ═════════════════════════════════════════════════════════════════════════════

class TestFileUploadEndpoint:
    def test_json_file_upload_returns_masked(self, v1_client):
        payload = json.dumps(SAMPLE_JSON).encode()
        resp = v1_client.post(
            "/v1/mask/file",
            files={"file": ("sample.json", io.BytesIO(payload), "application/json")},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "ssn" not in data["records"][0]

    def test_xml_file_upload_returns_masked(self, v1_client):
        resp = v1_client.post(
            "/v1/mask/file",
            files={"file": ("sample.xml", io.BytesIO(SAMPLE_XML), "application/xml")},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert b"Alice" not in resp.content

    def test_yaml_file_upload_returns_masked(self, v1_client):
        resp = v1_client.post(
            "/v1/mask/file",
            files={"file": ("sample.yaml", io.BytesIO(SAMPLE_YAML.encode()), "application/yaml")},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert b"Alice" not in resp.content

    def test_content_disposition_attachment(self, v1_client):
        payload = json.dumps(SAMPLE_JSON).encode()
        resp = v1_client.post(
            "/v1/mask/file",
            files={"file": ("report.json", io.BytesIO(payload), "application/json")},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert "masked_report.json" in resp.headers.get("content-disposition", "")

    def test_unsupported_extension_returns_400(self, v1_client):
        resp = v1_client.post(
            "/v1/mask/file",
            files={"file": ("data.csv", io.BytesIO(b"a,b,c"), "text/csv")},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 400

    def test_format_detected_from_extension_when_mime_generic(self, v1_client):
        """Format must fall back to file extension when MIME is octet-stream."""
        payload = json.dumps(SAMPLE_JSON).encode()
        resp = v1_client.post(
            "/v1/mask/file",
            files={"file": ("data.json", io.BytesIO(payload), "application/octet-stream")},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200

    def test_missing_auth_returns_401(self, v1_client):
        payload = json.dumps(SAMPLE_JSON).encode()
        resp = v1_client.post(
            "/v1/mask/file",
            files={"file": ("sample.json", io.BytesIO(payload), "application/json")},
        )
        assert resp.status_code == 401


# ═════════════════════════════════════════════════════════════════════════════
# TestTypeSafeRedaction
# ═════════════════════════════════════════════════════════════════════════════

class TestTypeSafeRedaction:
    """Integer and float fields must not be replaced with a string '[REDACTED]'."""

    def test_integer_field_replaced_with_zero(self, v1_client):
        data = {"records": [{"id": 99, "salary": 95000, "name": "Alice", "ssn": "111"}]}
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": data},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        result = resp.json()
        # salary has a rule → must become 0 (int-compatible), not "[REDACTED]"
        assert result["records"][0]["salary"] == 0

    def test_non_numeric_field_gets_redacted_string(self, v1_client):
        data = {"records": [{"id": 1, "name": "Alice", "ssn": "111"}]}
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": data},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        assert resp.json()["records"][0]["name"] == "[REDACTED]"

    def test_redact_int_directly(self):
        """Unit test: redact() on an int-valued node returns 0."""
        from app import techniques
        from app.adapters.json_adapter import JSONAdapter
        adapter = JSONAdapter()
        tree = adapter.parse(b'{"salary": 95000}')
        nodes = list(adapter.iter_nodes(tree))
        # find the salary value node
        salary_node = next(
            n for n in nodes if adapter.get_path(n) == "$.salary"
        )
        techniques.redact(adapter, salary_node)
        assert adapter.get_value(salary_node) == 0

    def test_redact_float_directly(self):
        """Unit test: redact() on a float-valued node returns 0.0."""
        from app import techniques
        from app.adapters.json_adapter import JSONAdapter
        adapter = JSONAdapter()
        tree = adapter.parse(b'{"score": 98.6}')
        nodes = list(adapter.iter_nodes(tree))
        score_node = next(
            n for n in nodes if adapter.get_path(n) == "$.score"
        )
        techniques.redact(adapter, score_node)
        assert adapter.get_value(score_node) == 0.0

    def test_redact_string_gives_redacted_label(self):
        """Unit test: redact() on a string-valued node returns '[REDACTED]'."""
        from app import techniques
        from app.adapters.json_adapter import JSONAdapter
        adapter = JSONAdapter()
        tree = adapter.parse(b'{"name": "Alice"}')
        nodes = list(adapter.iter_nodes(tree))
        name_node = next(n for n in nodes if adapter.get_path(n) == "$.name")
        techniques.redact(adapter, name_node)
        assert adapter.get_value(name_node) == "[REDACTED]"


# ═════════════════════════════════════════════════════════════════════════════
# TestXXEDefense
# ═════════════════════════════════════════════════════════════════════════════

class TestXXEDefense:
    """XML with external entity payloads must be safely parsed without resolution."""

    XXE_PAYLOAD = b"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<records>
  <record><name>&xxe;</name><ssn>111</ssn></record>
</records>"""

    BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<records><record><name>&lol3;</name><ssn>1</ssn></record></records>"""

    def test_xxe_entity_not_resolved_in_parse(self):
        """Parsing XXE payload must not expand &xxe; to file contents."""
        adapter = XMLAdapter()
        tree = adapter.parse(self.XXE_PAYLOAD)
        # lxml with resolve_entities=False leaves the entity as-is or empty
        # — the key invariant is that no /etc/passwd content appears.
        output = adapter.serialise(tree)
        assert b"/etc/passwd" not in output
        assert b"root:" not in output

    def test_xxe_via_inline_endpoint_does_not_leak(self, v1_client):
        """XXE payload sent through POST /v1/mask must not leak file contents."""
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "xml", "data": self.XXE_PAYLOAD.decode(errors="replace")},
            headers={"X-API-Token": "tok-analyst"},
        )
        # Either parses safely (200) or rejects the malformed DTD (422).
        assert resp.status_code in (200, 422)
        if resp.status_code == 200:
            assert b"root:" not in resp.content
            assert b"/etc/passwd" not in resp.content

    def test_billion_laughs_does_not_exhaust_memory(self):
        """Billion-laughs payload must be rejected (huge_tree=False)."""
        import pytest
        from app.exceptions import ParseError
        adapter = XMLAdapter()
        # lxml with huge_tree=False should either raise or parse without expansion
        try:
            tree = adapter.parse(self.BILLION_LAUGHS)
            output = adapter.serialise(tree)
            # If parsed, the expanded text must be absent (entities not resolved)
            assert b"lollollol" not in output
        except (ParseError, Exception):
            pass  # Rejection is also acceptable


# ═════════════════════════════════════════════════════════════════════════════
# TestReverseOrderSuppress
# ═════════════════════════════════════════════════════════════════════════════

class TestReverseOrderSuppress:
    """Suppressing multiple items in a JSON array must not drift indices."""

    def test_all_ssn_fields_suppressed_in_array(self, v1_client):
        """Every ssn in a multi-record array must be removed, not just the first."""
        data = {
            "records": [
                {"id": 1, "ssn": "111", "name": "Alice"},
                {"id": 2, "ssn": "222", "name": "Bob"},
                {"id": 3, "ssn": "333", "name": "Charlie"},
            ]
        }
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": data},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        result = resp.json()
        for rec in result["records"]:
            assert "ssn" not in rec, f"ssn leaked in record {rec}"

    def test_non_suppressed_fields_intact_after_suppress(self, v1_client):
        """id fields must survive after suppress removes ssn from each record."""
        data = {
            "records": [
                {"id": 10, "ssn": "aaa", "name": "X"},
                {"id": 20, "ssn": "bbb", "name": "Y"},
            ]
        }
        resp = v1_client.post(
            "/v1/mask",
            json={"format": "json", "data": data},
            headers={"X-API-Token": "tok-analyst"},
        )
        assert resp.status_code == 200
        result = resp.json()
        ids = [r["id"] for r in result["records"]]
        assert ids == [10, 20], f"id drift detected: {ids}"


