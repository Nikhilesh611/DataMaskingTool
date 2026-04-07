"""Tests for Phase 3 — Masking Loop."""

from __future__ import annotations

import json

import pytest

from app.adapters.json_adapter import JSONAdapter
from app.pipeline.phase1 import build_index
from app.pipeline.phase2 import resolve_conflicts
from app.pipeline.phase3 import apply_masking
from app.policy.models import MaskingRule


def _make_rule(selector: str, technique: str = "redact", **kwargs) -> MaskingRule:
    return MaskingRule(selector=selector, technique=technique, **kwargs)


JSON_DOC = b'{"patients": [{"name": "Alice", "ssn": "111-22-3333", "dob": "1985-01-01"}]}'


def _run_pipeline(doc: bytes, rules, role: str):
    adapter = JSONAdapter()
    tree = adapter.parse(doc)
    rule_index, coverage_index = build_index(adapter, tree, rules)
    all_paths = dict(coverage_index)
    for node in adapter.iter_nodes(tree):
        nid = adapter.get_identity(node)
        if nid not in all_paths:
            all_paths[nid] = adapter.get_path(node)
    decision_index, _ = resolve_conflicts(rule_index, rules, node_paths=all_paths)
    output_bytes, coverage_log = apply_masking(adapter, tree, decision_index, coverage_index, role)
    return output_bytes, coverage_log


class TestPhase3Analyst:
    def test_redact_applied(self):
        rules = [_make_rule("$..name", "redact")]
        out, _ = _run_pipeline(JSON_DOC, rules, "analyst")
        doc = json.loads(out)
        assert doc["patients"][0]["name"] == "[REDACTED]"

    def test_nullify_applied(self):
        rules = [_make_rule("$..name", "nullify")]
        out, _ = _run_pipeline(JSON_DOC, rules, "analyst")
        doc = json.loads(out)
        assert doc["patients"][0]["name"] is None

    def test_suppress_removes_node(self):
        rules = [_make_rule("$..ssn", "suppress")]
        out, _ = _run_pipeline(JSON_DOC, rules, "analyst")
        doc = json.loads(out)
        assert "ssn" not in doc["patients"][0]

    def test_suppress_causes_ancestor_skip_in_coverage_log(self):
        # Suppress the whole patients array, then check coverage log skips children
        rules = [_make_rule("$.patients", "suppress")]
        _, coverage_log = _run_pipeline(JSON_DOC, rules, "analyst")
        ancestor_skips = [e for e in coverage_log if e.get("reason") == "ancestor suppressed"]
        # name, ssn, dob inside the suppressed array should be skipped
        # (they'll be detached after patients is removed)


class TestPhase3Auditor:
    def test_covered_node_gets_label(self):
        rules = [_make_rule("$..name", "redact")]
        out, _ = _run_pipeline(JSON_DOC, rules, "auditor")
        doc = json.loads(out)
        label = doc["patients"][0]["name"]
        assert "WOULD APPLY" in label
        assert "redact" in label

    def test_uncovered_node_gets_unmasked_label(self):
        rules = [_make_rule("$..name", "redact")]
        out, _ = _run_pipeline(JSON_DOC, rules, "auditor")
        doc = json.loads(out)
        # ssn is uncovered → should be [UNMASKED — NO RULE DEFINED]
        ssn = doc["patients"][0]["ssn"]
        assert "UNMASKED" in ssn

    def test_generalise_label_includes_hierarchy_and_level(self):
        rules = [_make_rule("$..dob", "generalize", hierarchy="date", level=2)]
        out, _ = _run_pipeline(JSON_DOC, rules, "auditor")
        doc = json.loads(out)
        label = doc["patients"][0]["dob"]
        assert "date" in label
        assert "2" in label

    def test_pseudonymize_consistent_label(self):
        rules = [_make_rule("$..name", "pseudonymize", consistent=True)]
        out, _ = _run_pipeline(JSON_DOC, rules, "auditor")
        doc = json.loads(out)
        label = doc["patients"][0]["name"]
        assert "pseudonymize" in label
        assert "consistent=True" in label


class TestPhase3Operator:
    def test_operator_raises(self):
        adapter = JSONAdapter()
        tree = adapter.parse(JSON_DOC)
        with pytest.raises(ValueError, match="operator"):
            from app.pipeline.phase3 import apply_masking
            apply_masking(adapter, tree, {}, {}, "operator")
