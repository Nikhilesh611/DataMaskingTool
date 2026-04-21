"""Unit tests for v2.0 technique functions.

Tests
-----
mask_pattern       — all {last4}, {last2}, {first4}, {first2} placeholders
deep_redact_subtree — leaf-only redaction, structure preservation
synthesize_subtree  — SYNTHETIC_VALUES lookup + DEFAULT_SYNTHETIC fallback
                     for both JSON and XML subtrees
_extract_field_name — field name extraction from path strings
"""

from __future__ import annotations

import pytest

from app.adapters.json_adapter import JSONAdapter
from app.adapters.xml_adapter import XMLAdapter
from app.adapters.node_wrapper import wrap_tree
from app import techniques


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_json_tree(data: dict):
    return wrap_tree(data)


def get_leaf_values(tree, adapter):
    """Walk tree, collect all scalar values."""
    result = []
    for node in adapter.iter_nodes(tree):
        if adapter.is_leaf_node(node):
            result.append(adapter.get_value(node))
    return result


# ── mask_pattern tests ────────────────────────────────────────────────────────

class TestMaskPattern:
    def setup_method(self):
        self.adapter = JSONAdapter()
        self.tree = wrap_tree({"card": "4111-1111-1111-1234"})
        self.node = self.tree.value["card"]

    def test_last4_placeholder(self):
        techniques.mask_pattern(self.adapter, self.node, pattern="****-****-****-{last4}")
        assert self.adapter.get_value(self.node) == "****-****-****-1234"

    def test_last2_placeholder(self):
        techniques.mask_pattern(self.adapter, self.node, pattern="XXXX-{last2}")
        assert self.adapter.get_value(self.node) == "XXXX-34"

    def test_first4_placeholder(self):
        techniques.mask_pattern(self.adapter, self.node, pattern="{first4}-****")
        assert self.adapter.get_value(self.node) == "4111-****"

    def test_first2_placeholder(self):
        techniques.mask_pattern(self.adapter, self.node, pattern="{first2}XXXXXXXXXX")
        assert self.adapter.get_value(self.node) == "41XXXXXXXXXX"

    def test_static_pattern_no_placeholders(self):
        techniques.mask_pattern(self.adapter, self.node, pattern="[CARD REDACTED]")
        assert self.adapter.get_value(self.node) == "[CARD REDACTED]"

    def test_combined_placeholders(self):
        # Shows first2 and last4 in same pattern
        techniques.mask_pattern(self.adapter, self.node, pattern="{first2}XX-XXXX-XXXX-{last4}")
        assert self.adapter.get_value(self.node) == "41XX-XXXX-XXXX-1234"

    def test_short_value_last4_graceful(self):
        short_node = wrap_tree({"code": "AB"}).value["code"]
        techniques.mask_pattern(self.adapter, short_node, pattern="****-{last4}")
        val = self.adapter.get_value(short_node)
        assert "AB" in val  # Falls back to full value when shorter than 4 chars

    def test_none_value_treated_as_empty(self):
        null_node = wrap_tree({"x": None}).value["x"]
        techniques.mask_pattern(self.adapter, null_node, pattern="MASKED-{last4}")
        val = self.adapter.get_value(null_node)
        assert "MASKED-" in val


# ── deep_redact_subtree tests ─────────────────────────────────────────────────

class TestDeepRedactSubtree:
    def setup_method(self):
        self.adapter = JSONAdapter()

    def test_all_leaves_become_redacted(self):
        tree = wrap_tree({"info": {"name": "Alice", "ssn": "123-45-6789"}})
        subtree_root = tree.value["info"]
        techniques.deep_redact_subtree(self.adapter, subtree_root)
        assert subtree_root.value["name"].value == "[REDACTED]"
        assert subtree_root.value["ssn"].value == "[REDACTED]"

    def test_nested_structure_preserved(self):
        tree = wrap_tree({"contact": {"address": {"street": "123 Main", "city": "NY"}}})
        subtree_root = tree.value["contact"]
        techniques.deep_redact_subtree(self.adapter, subtree_root)
        # Keys still exist
        assert "address" in subtree_root.value
        assert "street" in subtree_root.value["address"].value
        # Values redacted
        assert subtree_root.value["address"].value["street"].value == "[REDACTED]"
        assert subtree_root.value["address"].value["city"].value == "[REDACTED]"

    def test_list_items_redacted(self):
        tree = wrap_tree({"tags": ["alpha", "beta", "gamma"]})
        subtree_root = tree.value["tags"]
        techniques.deep_redact_subtree(self.adapter, subtree_root)
        for item in subtree_root.value:
            assert item.value == "[REDACTED]"

    def test_xml_deep_redact(self):
        xml_adapter = XMLAdapter()
        raw = b"""<notes>
          <admission>Patient was admitted in pain.</admission>
          <discharge>Patient recovered well.</discharge>
        </notes>"""
        from lxml import etree
        root = etree.fromstring(raw)
        techniques.deep_redact_subtree(xml_adapter, root)
        assert root.find("admission").text == "[REDACTED]"
        assert root.find("discharge").text == "[REDACTED]"

    def test_container_node_value_not_overwritten(self):
        """Container node's dict/list value is preserved; only leaves change."""
        tree = wrap_tree({"group": {"a": "val1", "b": "val2"}})
        subtree_root = tree.value["group"]
        original_type = type(subtree_root.value)
        techniques.deep_redact_subtree(self.adapter, subtree_root)
        assert isinstance(subtree_root.value, original_type), \
            "Container dict should not be replaced"


# ── synthesize_subtree tests ──────────────────────────────────────────────────

class TestSynthesizeSubtree:
    def setup_method(self):
        self.adapter = JSONAdapter()

    def test_known_field_gets_synthetic_value(self):
        tree = wrap_tree({"address": {"street": "123 Real St", "city": "RealCity", "zip": "99999"}})
        subtree_root = tree.value["address"]
        techniques.synthesize_subtree(self.adapter, subtree_root)
        street = subtree_root.value["street"].value
        city   = subtree_root.value["city"].value
        assert street != "123 Real St", "Street should be replaced"
        assert city != "RealCity",      "City should be replaced"
        # Check they got values from SYNTHETIC_VALUES
        assert street == techniques.SYNTHETIC_VALUES.get("street", street)
        assert city   == techniques.SYNTHETIC_VALUES.get("city", city)

    def test_unknown_field_gets_default_synthetic(self):
        tree = wrap_tree({"record": {"foobar_field": "original_value"}})
        subtree_root = tree.value["record"]
        techniques.synthesize_subtree(self.adapter, subtree_root)
        val = subtree_root.value["foobar_field"].value
        assert val == techniques.DEFAULT_SYNTHETIC

    def test_structure_preserved(self):
        tree = wrap_tree({"contact": {"email": "a@a.com", "phone": "555-0000"}})
        subtree_root = tree.value["contact"]
        techniques.synthesize_subtree(self.adapter, subtree_root)
        assert "email" in subtree_root.value
        assert "phone" in subtree_root.value

    def test_email_field_gets_synthetic_email(self):
        tree = wrap_tree({"data": {"email": "real@domain.com"}})
        subtree_root = tree.value["data"]
        techniques.synthesize_subtree(self.adapter, subtree_root)
        val = subtree_root.value["email"].value
        assert val == techniques.SYNTHETIC_VALUES["email"]

    def test_xml_synthesize(self):
        xml_adapter = XMLAdapter()
        raw = b"""<address>
          <street>123 Real St</street>
          <city>RealCity</city>
        </address>"""
        from lxml import etree
        root = etree.fromstring(raw)
        techniques.synthesize_subtree(xml_adapter, root)
        assert root.find("street").text != "123 Real St"
        assert root.find("city").text != "RealCity"

    def test_none_leaf_value_becomes_synthetic(self):
        tree = wrap_tree({"info": {"name": None}})
        subtree_root = tree.value["info"]
        techniques.synthesize_subtree(self.adapter, subtree_root)
        val = subtree_root.value["name"].value
        # "name" is in SYNTHETIC_VALUES
        assert val == techniques.SYNTHETIC_VALUES.get("name", techniques.DEFAULT_SYNTHETIC)


# ── _extract_field_name helper ────────────────────────────────────────────────

def test_extract_field_name_json_path():
    adapter = JSONAdapter()
    tree = wrap_tree({"patient": {"billing": {"card_number": "1234"}}})
    node = tree.value["patient"].value["billing"].value["card_number"]
    name = techniques._extract_field_name(adapter, node)
    assert name == "card_number"


def test_extract_field_name_xml_element():
    xml_adapter = XMLAdapter()
    from lxml import etree
    raw = b"<billing><card_number>1234</card_number></billing>"
    root = etree.fromstring(raw)
    leaf = root.find("card_number")
    name = techniques._extract_field_name(xml_adapter, leaf)
    assert name == "card_number"
