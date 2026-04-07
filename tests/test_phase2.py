"""Tests for Phase 2 — Conflict Resolution and specificity scoring."""

from __future__ import annotations

import pytest

from app.pipeline.phase2 import resolve_conflicts, score_selector
from app.policy.models import MaskingRule


def _make_rule(selector: str, technique: str = "redact") -> MaskingRule:
    return MaskingRule(selector=selector, technique=technique)


class TestSpecificityScorer:
    def test_absolute_path_scores_higher_than_recursive(self):
        specific = score_selector("$.patients[0].name")
        vague = score_selector("$..name")
        assert specific > vague

    def test_named_field_scores_higher_than_wildcard(self):
        named = score_selector("$.a.b.c")
        wild = score_selector("$.*.*.*")
        assert named > wild

    def test_predicate_increases_score(self):
        with_pred = score_selector("$.patients[?(@.age > 18)].name")
        without_pred = score_selector("$.patients[0].name")
        assert with_pred >= without_pred

    def test_xpath_absolute_scores_higher_than_descendants(self):
        specific = score_selector("/patients/patient/name")
        vague = score_selector("//name")
        assert specific > vague

    def test_returns_integer(self):
        assert isinstance(score_selector("$.a.b"), int)

    def test_empty_selector_returns_integer(self):
        assert isinstance(score_selector(""), int)


class TestConflictResolution:
    def test_single_rule_wins_without_conflict_log(self):
        rule = _make_rule("$.a.b")
        rule_index = {1: [rule]}
        decision, conflicts = resolve_conflicts(rule_index, [rule])
        assert decision[1] is rule
        assert len(conflicts) == 0

    def test_higher_specificity_wins(self):
        vague_rule = _make_rule("$..name", "redact")
        specific_rule = _make_rule("$.patients[0].name", "nullify")
        rules = [vague_rule, specific_rule]
        rule_index = {42: [vague_rule, specific_rule]}
        decision, conflicts = resolve_conflicts(rule_index, rules)
        assert decision[42] is specific_rule
        assert len(conflicts) == 1

    def test_document_order_breaks_ties(self):
        rule_a = _make_rule("$..x", "redact")  # appears first
        rule_b = _make_rule("$..y", "nullify")  # appears second — different selector but same score
        # Manually assign equal scores by using same selector length
        rule_c = _make_rule("$..x", "nullify")  # same selector as rule_a — will have same score
        rules = [rule_a, rule_c]
        rule_index = {7: [rule_a, rule_c]}
        decision, conflicts = resolve_conflicts(rule_index, rules)
        # rule_a appears first → wins on tiebreak
        assert decision[7] is rule_a

    def test_conflict_log_contains_path(self):
        rule_a = _make_rule("$..name", "redact")
        rule_b = _make_rule("$.patients.name", "nullify")
        rules = [rule_a, rule_b]
        rule_index = {99: [rule_a, rule_b]}
        node_paths = {99: "$.patients.name"}
        _, conflicts = resolve_conflicts(rule_index, rules, node_paths=node_paths)
        assert len(conflicts) == 1
        assert conflicts[0]["node_path"] == "$.patients.name"

    def test_no_field_values_in_conflict_log(self):
        """Conflict log must not contain original field values."""
        rule_a = _make_rule("$..ssn")
        rule_b = _make_rule("$.patients.ssn")
        rules = [rule_a, rule_b]
        rule_index = {5: [rule_a, rule_b]}
        node_paths = {5: "$.patients.ssn"}
        _, conflicts = resolve_conflicts(rule_index, rules, node_paths=node_paths)
        # Ensure no "value" key exists in conflict records
        for c in conflicts:
            assert "value" not in c
            for loser in c.get("losers", []):
                assert "value" not in loser
