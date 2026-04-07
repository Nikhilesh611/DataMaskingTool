"""Tests for policy loading (from YAML strings — no file I/O)."""

from __future__ import annotations

import pytest

from app.exceptions import PolicyValidationError
from app.policy.loader import load_policy_from_string


VALID_POLICY = """
version: "1.0"
record_root: "$.patients[*]"
rules:
  - selector: "$..ssn"
    technique: suppress
  - selector: "$..dob"
    technique: generalize
    hierarchy: date
    level: 2
"""


class TestPolicyLoading:
    def test_valid_policy_loads(self):
        policy = load_policy_from_string(VALID_POLICY)
        assert policy.version == "1.0"
        assert len(policy.rules) == 2

    def test_invalid_technique_name_raises(self):
        bad = VALID_POLICY.replace("suppress", "explode")
        with pytest.raises(PolicyValidationError) as exc_info:
            load_policy_from_string(bad)
        assert "explode" in str(exc_info.value) or "technique" in str(exc_info.value).lower()

    def test_generalise_without_hierarchy_raises(self):
        bad = """
version: "1.0"
record_root: "$"
rules:
  - selector: "$..dob"
    technique: generalize
    level: 2
"""
        with pytest.raises(PolicyValidationError):
            load_policy_from_string(bad)

    def test_generalise_without_level_raises(self):
        bad = """
version: "1.0"
record_root: "$"
rules:
  - selector: "$..dob"
    technique: generalize
    hierarchy: date
"""
        with pytest.raises(PolicyValidationError):
            load_policy_from_string(bad)

    def test_negative_level_raises(self):
        bad = """
version: "1.0"
record_root: "$"
rules:
  - selector: "$..dob"
    technique: generalize
    hierarchy: date
    level: -1
"""
        with pytest.raises(PolicyValidationError):
            load_policy_from_string(bad)

    def test_unregistered_hierarchy_raises(self):
        bad = """
version: "1.0"
record_root: "$"
rules:
  - selector: "$..dob"
    technique: generalize
    hierarchy: nonexistent_hierarchy
    level: 1
"""
        with pytest.raises(PolicyValidationError):
            load_policy_from_string(bad)

    def test_k_less_than_2_raises(self):
        bad = """
version: "1.0"
record_root: "$"
rules: []
k_anonymity:
  enabled: true
  k: 1
  quasi_identifiers: ["$..dob"]
"""
        with pytest.raises(PolicyValidationError):
            load_policy_from_string(bad)

    def test_malformed_yaml_raises(self):
        with pytest.raises(PolicyValidationError):
            load_policy_from_string("{ unclosed: [bracket")

    def test_empty_rules_allowed(self):
        minimal = "version: '1.0'\nrecord_root: '$'\nrules: []\n"
        policy = load_policy_from_string(minimal)
        assert policy.rules == []

    def test_policy_is_frozen(self):
        policy = load_policy_from_string(VALID_POLICY)
        with pytest.raises(Exception):
            policy.version = "2.0"  # type: ignore[misc]
