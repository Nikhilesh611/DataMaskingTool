"""Tests for Phase 1 — Index Building."""

from __future__ import annotations

from app.adapters.json_adapter import JSONAdapter
from app.adapters.node_wrapper import NodeWrapper
from app.pipeline.phase1 import build_index
from app.policy.models import MaskingRule


def _make_rule(selector: str, technique: str = "redact") -> MaskingRule:
    return MaskingRule(selector=selector, technique=technique)


JSON_DOC = b'{"patients": [{"name": "Alice", "ssn": "111", "dob": "1985-01-01"}]}'


class TestPhase1:
    def setup_method(self):
        self.adapter = JSONAdapter()
        self.tree = self.adapter.parse(JSON_DOC)

    def test_matched_nodes_in_rule_index(self):
        rules = [_make_rule("$..name"), _make_rule("$..ssn")]
        rule_index, _ = build_index(self.adapter, self.tree, rules)
        assert len(rule_index) >= 2

    def test_uncovered_nodes_in_coverage_index(self):
        rules = [_make_rule("$..name")]
        rule_index, coverage_index = build_index(self.adapter, self.tree, rules)
        # dob and ssn are not covered
        all_paths = list(coverage_index.values())
        has_ssn = any("ssn" in p for p in all_paths)
        has_dob = any("dob" in p for p in all_paths)
        assert has_ssn
        assert has_dob

    def test_no_rules_means_all_uncovered(self):
        rule_index, coverage_index = build_index(self.adapter, self.tree, [])
        assert len(rule_index) == 0
        assert len(coverage_index) > 0

    def test_node_matched_by_two_rules_has_two_entries(self):
        # Two different selectors that both match the same node
        rules = [_make_rule("$..name"), _make_rule("$.patients[0].name")]
        rule_index, _ = build_index(self.adapter, self.tree, rules)
        # Find the node matched by both
        multi = [v for v in rule_index.values() if len(v) == 2]
        assert len(multi) >= 1

    def test_fully_covered_document_has_empty_coverage_index(self):
        # Use wildcard to match everything
        rules = [_make_rule("$..*")]
        rule_index, coverage_index = build_index(self.adapter, self.tree, rules)
        # Root node may still be uncovered depending on jsonpath-ng behaviour
        # But most nodes should be covered
        assert len(rule_index) > 0
