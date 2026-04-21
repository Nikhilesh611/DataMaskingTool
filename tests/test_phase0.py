"""Tests for Phase 0 — Scope Evaluation.

Verifies that evaluate_scopes correctly:
  - selects subtree root nodes
  - resolves role-based strategies
  - expands profile rules into full MaskingRule objects
  - populates member IDs for all subtree nodes
  - records scope events for the audit trail
  - handles empty scopes gracefully
  - applies last-writer-wins for overlapping scopes
"""

from __future__ import annotations

import json

import pytest

from app.adapters.json_adapter import JSONAdapter
from app.adapters.xml_adapter import XMLAdapter
from app.pipeline.phase0 import evaluate_scopes
from tests.conftest import SAMPLE_V2_JSON, SAMPLE_V2_XML


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def json_adapter():
    return JSONAdapter()


@pytest.fixture
def xml_adapter():
    return XMLAdapter()


@pytest.fixture
def json_tree(json_adapter):
    return json_adapter.parse(SAMPLE_V2_JSON.encode())


@pytest.fixture
def xml_tree(xml_adapter):
    return xml_adapter.parse(SAMPLE_V2_XML)


# ── Tests — empty policy ───────────────────────────────────────────────────────

def test_empty_scopes_returns_empty_plan(json_adapter, json_tree, v2_policy):
    """A policy with no scopes produces an empty ScopePlan."""
    from app.policy.loader import load_policy_from_string
    mini = load_policy_from_string("""
version: "1.0"
record_root: "$.patients[*]"
rules:
  - selector: "$..name"
    technique: redact
""")
    plan = evaluate_scopes(json_adapter, json_tree, mini, "analyst")
    assert plan.members == {}
    assert plan.subtree_roots == []
    assert plan.scope_events == []
    assert plan.expansion_rule_ids == set()


# ── Tests — strategy resolution ────────────────────────────────────────────────

def test_analyst_billing_scope_is_drop_subtree(json_adapter, json_tree, v2_policy):
    """analyst role → billing scope → drop_subtree strategy."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    # Find billing-related scope events
    billing_events = [e for e in plan.scope_events if "billing" in e["path"]]
    assert len(billing_events) >= 1
    assert all(e["strategy"] == "drop_subtree" for e in billing_events)


def test_auditor_billing_scope_is_masked(json_adapter, json_tree, v2_policy):
    """auditor role → billing scope → masked strategy."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "auditor")
    billing_events = [e for e in plan.scope_events if "billing" in e["path"]]
    assert len(billing_events) >= 1
    assert all(e["strategy"] == "masked" for e in billing_events)


def test_analyst_address_scope_is_synthesize(json_adapter, json_tree, v2_policy):
    """analyst role → address scope → synthesize strategy."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    addr_events = [e for e in plan.scope_events if "address" in e["path"]]
    assert len(addr_events) >= 1
    assert all(e["strategy"] == "synthesize" for e in addr_events)


def test_analyst_clinical_notes_is_deep_redact(json_adapter, json_tree, v2_policy):
    """analyst role → clinical_notes scope → deep_redact strategy."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    notes_events = [e for e in plan.scope_events if "clinical_notes" in e["path"]]
    assert len(notes_events) >= 1
    assert all(e["strategy"] == "deep_redact" for e in notes_events)


def test_assigned_doctor_is_default_allow(json_adapter, json_tree, v2_policy):
    """assigned_doctor scope → default_allow for all roles."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    doctor_events = [e for e in plan.scope_events if "assigned_doctor" in e["path"]]
    assert len(doctor_events) >= 1
    assert all(e["strategy"] == "default_allow" for e in doctor_events)


# ── Tests — member population ──────────────────────────────────────────────────

def test_billing_members_present_in_plan(json_adapter, json_tree, v2_policy):
    """All nodes inside the billing subtrees should appear in plan.members."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    assert len(plan.members) > 0, "members dict should not be empty"
    # Verify at least some members have drop_subtree strategy
    drop_members = [d for d in plan.members.values() if d.strategy == "drop_subtree"]
    assert len(drop_members) > 0


def test_doctor_members_are_default_allow(json_adapter, json_tree, v2_policy):
    """Nodes inside assigned_doctor subtrees have default_allow decision."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    allow_members = [d for d in plan.members.values() if d.strategy == "default_allow"]
    assert len(allow_members) > 0


# ── Tests — profile expansion ──────────────────────────────────────────────────

def test_profile_rules_expanded_into_masking_rules(json_adapter, json_tree, v2_policy):
    """Masked scope with apply_profile should have expanded_rules populated."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    # Find a record with personal_info scope
    personal_info_decisions = [
        d for d in plan.members.values()
        if d.strategy == "masked" and d.profile_name == "pii_profile"
    ]
    assert len(personal_info_decisions) > 0
    assert len(personal_info_decisions[0].expanded_rules) > 0


def test_expansion_rule_ids_populated(json_adapter, json_tree, v2_policy):
    """expansion_rule_ids should contain IDs of all scope-expanded rules."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    assert len(plan.expansion_rule_ids) > 0


# ── Tests — scope events ───────────────────────────────────────────────────────

def test_scope_events_have_expected_keys(json_adapter, json_tree, v2_policy):
    """Every scope event should have path, profile, strategy, role keys."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    for event in plan.scope_events:
        assert "path" in event
        assert "profile" in event
        assert "strategy" in event
        assert "role" in event
        assert event["role"] == "analyst"


# ── Tests — XML ────────────────────────────────────────────────────────────────

def test_xml_billing_scope_drop_subtree(xml_adapter, xml_tree, v2_policy):
    """XML: billing scope resolves to drop_subtree for analyst."""
    plan = evaluate_scopes(xml_adapter, xml_tree, v2_policy, "analyst")
    billing_events = [e for e in plan.scope_events if "billing" in e["path"]]
    assert any(e["strategy"] == "drop_subtree" for e in billing_events)


def test_xml_clinical_notes_deep_redact(xml_adapter, xml_tree, v2_policy):
    """XML: clinical_notes scope resolves to deep_redact for analyst."""
    plan = evaluate_scopes(xml_adapter, xml_tree, v2_policy, "analyst")
    notes_events = [e for e in plan.scope_events if "clinical_notes" in e["path"]]
    assert any(e["strategy"] == "deep_redact" for e in notes_events)


# ── Tests — overlapping scopes (last-writer-wins) ──────────────────────────────

def test_inner_scope_overrides_outer_for_address_nodes(json_adapter, json_tree, v2_policy):
    """Address nodes should have synthesize (inner scope), not masked (outer personal_info scope)."""
    plan = evaluate_scopes(json_adapter, json_tree, v2_policy, "analyst")
    # Address nodes are inside personal_info (masked) but also inside address scope (synthesize)
    # The last-processed inner scope should win.
    synthesize_members = [d for d in plan.members.values() if d.strategy == "synthesize"]
    assert len(synthesize_members) > 0, "Address nodes should have synthesize strategy"
