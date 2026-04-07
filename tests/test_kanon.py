"""Tests for the k-anonymity engine."""

from __future__ import annotations

import json

import pytest

from app.adapters.json_adapter import JSONAdapter
from app.pipeline.kanon import enforce_k_anonymity
from app.policy.loader import load_policy_from_string


# Helper: build a JSON document with n patients each with a distinct QI value
def _make_patients(n: int, same_dob: bool = False) -> bytes:
    patients = [
        {
            "id": f"P{i:03}",
            "name": f"Patient{i}",
            "dob": "1985-01-01" if same_dob else f"198{i % 10}-01-01",
            "zipcode": "10001" if same_dob else f"1000{i % 10}",
        }
        for i in range(n)
    ]
    return json.dumps({"patients": patients}).encode()


POLICY_YAML_K2 = """
version: "1.0"
record_root: "$.patients[*]"
rules:
  - selector: "$..dob"
    technique: generalize
    hierarchy: date
    level: 2
  - selector: "$..zipcode"
    technique: generalize
    hierarchy: zipcode
    level: 1
k_anonymity:
  enabled: true
  k: 2
  quasi_identifiers:
    - "$..dob"
    - "$..zipcode"
"""

POLICY_YAML_K_DISABLED = """
version: "1.0"
record_root: "$.patients[*]"
rules: []
k_anonymity:
  enabled: false
  k: 2
  quasi_identifiers: ["$..dob"]
"""


class TestKAnonEngine:
    def test_returns_none_when_disabled(self):
        policy = load_policy_from_string(POLICY_YAML_K_DISABLED)
        adapter = JSONAdapter()
        tree = adapter.parse(_make_patients(4))
        result = enforce_k_anonymity(adapter, tree, policy)
        assert result is None

    def test_achieved_when_all_same_qi(self):
        """All patients have identical QI values → k=2 trivially satisfied."""
        policy = load_policy_from_string(POLICY_YAML_K2)
        doc = _make_patients(4, same_dob=True)
        adapter = JSONAdapter()
        tree = adapter.parse(doc)
        report = enforce_k_anonymity(adapter, tree, policy)
        assert report is not None
        assert report.achieved

    def test_report_not_exception_when_k_cannot_be_achieved(self):
        """Even when k is unreachable, engine returns KAnonReport, not an exception."""
        policy = load_policy_from_string(POLICY_YAML_K2)
        # Only 1 patient: can never form a 2-member class
        doc = _make_patients(1, same_dob=False)
        adapter = JSONAdapter()
        tree = adapter.parse(doc)
        # Should not raise
        report = enforce_k_anonymity(adapter, tree, policy)
        assert report is not None
        assert isinstance(report.achieved, bool)

    def test_report_contains_violating_classes(self):
        policy = load_policy_from_string(POLICY_YAML_K2)
        doc = _make_patients(1, same_dob=False)
        adapter = JSONAdapter()
        tree = adapter.parse(doc)
        report = enforce_k_anonymity(adapter, tree, policy)
        if not report.achieved:
            assert isinstance(report.violating_classes, list)

    def test_k_achieved_bool_field_present(self):
        policy = load_policy_from_string(POLICY_YAML_K2)
        doc = _make_patients(4, same_dob=True)
        adapter = JSONAdapter()
        tree = adapter.parse(doc)
        report = enforce_k_anonymity(adapter, tree, policy)
        assert hasattr(report, "achieved")

    def test_to_dict(self):
        policy = load_policy_from_string(POLICY_YAML_K2)
        doc = _make_patients(4, same_dob=True)
        adapter = JSONAdapter()
        tree = adapter.parse(doc)
        report = enforce_k_anonymity(adapter, tree, policy)
        d = report.to_dict()
        assert "achieved" in d
        assert "iterations" in d
        assert "violating_classes" in d
        assert "final_qi_levels" in d
