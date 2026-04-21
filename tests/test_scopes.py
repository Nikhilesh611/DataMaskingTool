"""End-to-end scope + profile + strategy integration tests.

Each test runs the full pipeline (Phase 0 → 3) against the v2 sample data
and verifies the structural and value-level outcomes for each role/strategy
combination.

Coverage matrix
---------------
Strategy         | Format | Role     | Test
-----------------|--------|----------|-----
drop_subtree     | JSON   | analyst  | test_analyst_json_billing_dropped
drop_subtree     | XML    | analyst  | test_analyst_xml_billing_dropped
masked           | JSON   | auditor  | test_auditor_json_billing_masked
synthesize       | JSON   | analyst  | test_analyst_json_address_synthesized
deep_redact      | JSON   | analyst  | test_analyst_json_clinical_notes_deep_redacted
deep_redact      | XML    | analyst  | test_analyst_xml_clinical_notes_deep_redacted
default_allow    | JSON   | analyst  | test_analyst_json_doctor_untouched
mask_pattern     | JSON   | auditor  | test_auditor_json_card_number_mask_pattern
pii_profile      | JSON   | analyst  | test_analyst_json_pii_profile_applied
scope_events     | JSON   | analyst  | test_pipeline_result_scope_metadata
"""

from __future__ import annotations

import json

import pytest

from app.adapters.json_adapter import JSONAdapter
from app.adapters.xml_adapter import XMLAdapter
from app.pipeline.runner import run_pipeline
from tests.conftest import SAMPLE_V2_JSON, SAMPLE_V2_XML


# ── Helpers ───────────────────────────────────────────────────────────────────

def run_json(v2_policy, role: str) -> tuple:
    """Run pipeline on SAMPLE_V2_JSON.  Returns (parsed_output_dict, result)."""
    result = run_pipeline(SAMPLE_V2_JSON.encode(), "json", v2_policy, role)
    data = json.loads(result.output_bytes)
    return data, result


def run_xml(v2_policy, role: str) -> bytes:
    """Run pipeline on SAMPLE_V2_XML.  Returns serialised output bytes."""
    result = run_pipeline(SAMPLE_V2_XML, "xml", v2_policy, role)
    return result.output_bytes


# ── drop_subtree strategy ──────────────────────────────────────────────────────

def test_analyst_json_billing_dropped(v2_policy):
    """analyst: billing subtrees are completely absent from the JSON output."""
    data, _ = run_json(v2_policy, "analyst")
    for patient in data["patients"]:
        assert "billing" not in patient, \
            f"Expected 'billing' to be dropped for patient {patient.get('patient_id')}"


def test_analyst_xml_billing_dropped(v2_policy):
    """analyst: <billing> elements are completely absent from the XML output."""
    xml_out = run_xml(v2_policy, "analyst")
    assert b"<billing>" not in xml_out
    assert b"4111" not in xml_out, "Card number digits should not appear"


# ── masked strategy with card_profile (auditor sees billing) ──────────────────

def test_auditor_json_billing_masked(v2_policy):
    """auditor: billing subtree is present and card_number has a masking label."""
    data, _ = run_json(v2_policy, "auditor")
    for patient in data["patients"]:
        assert "billing" in patient, "auditor should see billing subtree"
        card = str(patient["billing"].get("card_number", ""))
        # Auditor sees a WOULD APPLY label (not actual masking)
        assert "WOULD APPLY" in card or "****" in card, \
            f"card_number should have masking info, got: {card}"
        # CVV gets a WOULD APPLY: suppress label (not removed) for auditor
        cvv = str(patient["billing"].get("cvv", ""))
        assert "WOULD APPLY" in cvv, f"CVV should have suppress label for auditor, got: {cvv}"


def test_auditor_json_card_number_mask_pattern(v2_policy):
    """auditor: card_number output has a WOULD APPLY: mask_pattern label."""
    data, _ = run_json(v2_policy, "auditor")
    patient = data["patients"][0]
    card = str(patient["billing"].get("card_number", ""))
    # Auditor sees the label, not the real masked value
    assert "mask_pattern" in card or "WOULD APPLY" in card, \
        f"Expected mask_pattern label for auditor, got: {card}"


# ── synthesize strategy ───────────────────────────────────────────────────────

def test_analyst_json_address_synthesized(v2_policy):
    """analyst: address subtrees have synthetic values (not original, not [REDACTED])."""
    data, _ = run_json(v2_policy, "analyst")
    for patient in data["patients"]:
        addr = patient["personal_info"]["contact"]["address"]
        street = addr.get("street", "")
        city   = addr.get("city", "")
        # Should not contain real values
        assert "Main St" not in street and "Oak Ave" not in street and "Pine" not in street, \
            f"Street should be synthesized, got: {street}"
        # Should contain synthetic values (from SYNTHETIC_VALUES lookup or [SYNTHETIC])
        assert street != "", "Synthesized street should not be empty"
        # Structure preserved — keys still exist
        assert "street" in addr
        assert "city" in addr
        assert "zip" in addr


def test_analyst_json_address_structure_preserved(v2_policy):
    """analyst/synthesize: address object keys are retained, only values replaced."""
    data, _ = run_json(v2_policy, "analyst")
    addr = data["patients"][0]["personal_info"]["contact"]["address"]
    assert set(addr.keys()) == {"street", "city", "zip"}, \
        f"Expected keys {{street, city, zip}}, got {set(addr.keys())}"


# ── deep_redact strategy ──────────────────────────────────────────────────────

def test_analyst_json_clinical_notes_deep_redacted(v2_policy):
    """analyst: all clinical_notes leaf values are [REDACTED]."""
    data, _ = run_json(v2_policy, "analyst")
    for patient in data["patients"]:
        notes = patient["medical_history"]["clinical_notes"]
        for key, val in notes.items():
            assert val == "[REDACTED]", \
                f"Expected [REDACTED] for notes.{key}, got: {val}"


def test_analyst_xml_clinical_notes_deep_redacted(v2_policy):
    """XML analyst: clinical_notes leaf values are [REDACTED]."""
    xml_out = run_xml(v2_policy, "analyst")
    # Confirm original content is gone
    assert b"chest pain" not in xml_out
    assert b"Diabetic" not in xml_out
    # Confirm [REDACTED] placeholder is present
    assert b"[REDACTED]" in xml_out


def test_auditor_json_clinical_notes_deep_redacted(v2_policy):
    """auditor also gets deep_redact on clinical_notes (same strategy for both)."""
    data, _ = run_json(v2_policy, "auditor")
    for patient in data["patients"]:
        notes = patient["medical_history"]["clinical_notes"]
        for key, val in notes.items():
            assert val == "[REDACTED]", \
                f"Auditor should also see [REDACTED] for notes.{key}, got: {val}"


# ── default_allow strategy ────────────────────────────────────────────────────

def test_analyst_json_doctor_untouched(v2_policy):
    """analyst: assigned_doctor subtree passes through unchanged (default_allow)."""
    data, _ = run_json(v2_policy, "analyst")
    patient = data["patients"][0]
    doctor = patient["assigned_doctor"]
    assert doctor["doctor_id"] == "DOC-104", f"doctor_id changed: {doctor['doctor_id']}"
    assert doctor["name"] == "Dr. Smith",    f"name changed: {doctor['name']}"
    assert doctor["department"] == "Cardiology"


def test_auditor_json_doctor_untouched(v2_policy):
    """auditor: assigned_doctor also passes through (default_allow skips auditor labelling)."""
    data, _ = run_json(v2_policy, "auditor")
    patient = data["patients"][0]
    doctor = patient["assigned_doctor"]
    assert doctor["doctor_id"] == "DOC-104"


# ── masked strategy — pii_profile applied ─────────────────────────────────────

def test_analyst_json_pii_profile_applied(v2_policy):
    """analyst: personal_info.name is redacted, ssn is suppressed via pii_profile."""
    data, _ = run_json(v2_policy, "analyst")
    for patient in data["patients"]:
        pi = patient["personal_info"]
        assert pi["name"] == "[REDACTED]", f"name should be redacted, got: {pi['name']}"
        assert "ssn" not in pi, "ssn should be suppressed"


def test_analyst_xml_pii_profile_applied(v2_policy):
    """XML analyst: <name> is redacted, <ssn> is absent."""
    xml_out = run_xml(v2_policy, "analyst")
    assert b"Alice Johnson" not in xml_out
    assert b"Bob Williams" not in xml_out
    assert b"<ssn>" not in xml_out


def test_analyst_json_email_pseudonymized(v2_policy):
    """analyst: email is pseudonymized (starts with ANON_)."""
    data, _ = run_json(v2_policy, "analyst")
    email = data["patients"][0]["personal_info"]["contact"]["email"]
    assert email.startswith("ANON_"), f"Email should be pseudonymized, got: {email}"


# ── PipelineResult scope metadata ─────────────────────────────────────────────

def test_pipeline_result_scope_metadata(v2_policy):
    """PipelineResult correctly tracks scope event metadata."""
    result = run_pipeline(SAMPLE_V2_JSON.encode(), "json", v2_policy, "analyst")
    assert result.scopes_evaluated > 0, "Should have evaluated at least one scope"
    assert result.scopes_dropped > 0, "Analyst should have at least one drop_subtree scope"
    assert "pii_profile" in result.profiles_applied or "card_profile" in result.profiles_applied


def test_pipeline_result_no_scope_events_for_v1_policy(v1_policy):
    """v1 policy (no scopes) produces zero scope events."""
    import json as _json
    v1_doc = _json.dumps({
        "patients": [
            {"id": "P001", "name": "Alice", "dob": "1985-07-23", "ssn": "111-22-3333"},
        ]
    })
    result = run_pipeline(v1_doc.encode(), "json", v1_policy, "analyst")
    assert result.scopes_evaluated == 0
    assert result.scopes_dropped == 0
    assert result.profiles_applied == []


# ── Operator bypasses completely ──────────────────────────────────────────────

def test_operator_json_gets_raw_output(v2_policy):
    """operator role bypasses pipeline; raw document returned unchanged."""
    result = run_pipeline(SAMPLE_V2_JSON.encode(), "json", v2_policy, "operator")
    data = json.loads(result.output_bytes)
    patient = data["patients"][0]
    assert patient["personal_info"]["name"] == "Alice Johnson"
    assert patient["billing"]["card_number"] == "4111-1111-1111-1234"
