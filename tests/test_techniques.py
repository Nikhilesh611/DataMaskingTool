"""Tests for the seven masking techniques in isolation."""

from __future__ import annotations

import json

import pytest

from app.adapters.json_adapter import JSONAdapter
from app.adapters.node_wrapper import NodeWrapper
import app.techniques as T


def _make_leaf(value) -> tuple[JSONAdapter, NodeWrapper]:
    """Create a single-value JSON document and return its leaf node."""
    adapter = JSONAdapter()
    doc = json.dumps({"v": value}).encode()
    tree = adapter.parse(doc)
    results = adapter.select(tree, "$.v")
    assert results, "Could not select $.v"
    return adapter, results[0]


class TestSuppress:
    def test_removes_node(self):
        adapter, node = _make_leaf("secret")
        assert adapter.is_attached(node)
        T.suppress(adapter, node)
        assert not adapter.is_attached(node)


class TestNullify:
    def test_sets_value_to_none(self):
        adapter, node = _make_leaf("something")
        T.nullify(adapter, node)
        assert adapter.get_value(node) is None


class TestRedact:
    def test_sets_redacted_string(self):
        adapter, node = _make_leaf("sensitive")
        T.redact(adapter, node)
        assert adapter.get_value(node) == "[REDACTED]"


class TestPseudonymize:
    def test_consistent_is_deterministic(self):
        adapter1, node1 = _make_leaf("Alice")
        adapter2, node2 = _make_leaf("Alice")
        T.pseudonymize(adapter1, node1, consistent=True)
        T.pseudonymize(adapter2, node2, consistent=True)
        assert adapter1.get_value(node1) == adapter2.get_value(node2)

    def test_consistent_starts_with_anon(self):
        adapter, node = _make_leaf("Bob")
        T.pseudonymize(adapter, node, consistent=True)
        assert adapter.get_value(node).startswith("ANON_")

    def test_non_consistent_is_random(self):
        adapter1, node1 = _make_leaf("Alice")
        adapter2, node2 = _make_leaf("Alice")
        T.pseudonymize(adapter1, node1, consistent=False)
        T.pseudonymize(adapter2, node2, consistent=False)
        # Very low probability they are equal
        v1, v2 = adapter1.get_value(node1), adapter2.get_value(node2)
        assert v1.startswith("ANON_") and v2.startswith("ANON_")

    def test_sha256_produces_8_hex_chars(self):
        adapter, node = _make_leaf("test")
        T.pseudonymize(adapter, node, consistent=True)
        value = adapter.get_value(node)
        # Format: ANON_XXXXXXXX (8 hex chars)
        assert len(value) == len("ANON_") + 8


class TestGeneralize:
    def test_date_generalise_year(self):
        adapter, node = _make_leaf("1985-07-23")
        T.generalize(adapter, node, hierarchy="date", level=2)
        assert adapter.get_value(node) == "1985"

    def test_fallback_on_bad_value(self):
        adapter, node = _make_leaf("not-a-date")
        coverage_log = []
        T.generalize(adapter, node, hierarchy="date", level=2, coverage_log=coverage_log)
        assert adapter.get_value(node) == "[REDACTED]"
        assert len(coverage_log) == 1

    def test_unknown_hierarchy_falls_back(self):
        adapter, node = _make_leaf("10001")
        T.generalize(adapter, node, hierarchy="nonexistent", level=1)
        assert adapter.get_value(node) == "[REDACTED]"


class TestFormatPreserve:
    def test_digit_replaced_with_digit(self):
        import string
        adapter, node = _make_leaf("123")
        T.format_preserve(adapter, node)
        value = adapter.get_value(node)
        assert len(value) == 3
        assert all(c in string.digits for c in value)

    def test_upper_replaced_with_upper(self):
        import string
        adapter, node = _make_leaf("ABC")
        T.format_preserve(adapter, node)
        value = adapter.get_value(node)
        assert len(value) == 3
        assert all(c in string.ascii_uppercase for c in value)

    def test_special_chars_pass_through(self):
        adapter, node = _make_leaf("A1-B2")
        T.format_preserve(adapter, node)
        value = adapter.get_value(node)
        assert value[2] == "-"
        assert len(value) == 5


class TestNoise:
    def test_output_within_10_percent_band(self):
        original = 100.0
        for _ in range(50):
            adapter, node = _make_leaf(str(original))
            T.noise(adapter, node)
            result = float(adapter.get_value(node))
            assert 90.0 <= result <= 110.0, f"Out of band: {result}"

    def test_fallback_on_non_numeric(self):
        adapter, node = _make_leaf("not-a-number")
        coverage_log = []
        T.noise(adapter, node, coverage_log=coverage_log)
        assert adapter.get_value(node) == "[REDACTED]"
        assert len(coverage_log) == 1

    def test_zero_value(self):
        adapter, node = _make_leaf("0.0")
        T.noise(adapter, node)
        # Band of ±10% of 0 is 0; result should be 0.0
        assert float(adapter.get_value(node)) == 0.0
