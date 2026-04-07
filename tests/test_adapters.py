"""Tests for XML, JSON, and YAML format adapters."""

from __future__ import annotations

import pytest

from app.adapters.json_adapter import JSONAdapter
from app.adapters.xml_adapter import XMLAdapter
from app.adapters.yaml_adapter import YAMLAdapter


# ── Fixtures ──────────────────────────────────────────────────────────────────

XML_DOC = b"""<?xml version="1.0"?>
<root>
  <child>hello</child>
  <child>world</child>
  <parent>
    <nested>deep</nested>
  </parent>
</root>"""

JSON_DOC = b'{"a": {"b": "hello", "c": [1, 2, 3]}, "d": "world"}'
YAML_DOC = b"a:\n  b: hello\n  c:\n    - 1\n    - 2\n    - 3\nd: world\n"


# ── XML Adapter ───────────────────────────────────────────────────────────────

class TestXMLAdapter:
    def setup_method(self):
        self.adapter = XMLAdapter()
        self.tree = self.adapter.parse(XML_DOC)

    def test_parse_returns_element(self):
        from lxml import etree
        assert isinstance(self.tree, etree._Element)

    def test_iter_visits_all_elements(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        tags = [n.tag for n in nodes]
        assert "root" in tags
        assert "child" in tags
        assert "parent" in tags
        assert "nested" in tags

    def test_get_value_returns_text(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        children = [n for n in nodes if n.tag == "child"]
        values = [self.adapter.get_value(n) for n in children]
        assert "hello" in values
        assert "world" in values

    def test_set_value(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        child = next(n for n in nodes if n.tag == "child")
        self.adapter.set_value(child, "modified")
        assert self.adapter.get_value(child) == "modified"

    def test_identity_is_stable_int(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        ids = [self.adapter.get_identity(n) for n in nodes]
        assert all(isinstance(i, int) for i in ids)
        # Same node → same id
        node = nodes[0]
        assert self.adapter.get_identity(node) == self.adapter.get_identity(node)

    def test_select_xpath(self):
        results = self.adapter.select(self.tree, "//child")
        assert len(results) == 2

    def test_select_returns_elements_only(self):
        # Text nodes should be filtered out
        results = self.adapter.select(self.tree, "//child/text()")
        # Text nodes are strings, not elements — should be empty
        assert results == []

    def test_remove_node(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        child = next(n for n in nodes if n.tag == "child")
        assert self.adapter.is_attached(child)
        self.adapter.remove_node(child)
        assert not self.adapter.is_attached(child)

    def test_removing_parent_detaches_children(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        parent = next(n for n in nodes if n.tag == "parent")
        nested = next(n for n in nodes if n.tag == "nested")
        assert self.adapter.is_attached(nested)
        self.adapter.remove_node(parent)
        # nested is a child of parent — should now be detached
        assert not self.adapter.is_attached(nested)

    def test_root_is_attached(self):
        assert self.adapter.is_attached(self.tree)

    def test_serialise_produces_bytes(self):
        out = self.adapter.serialise(self.tree)
        assert isinstance(out, bytes)
        assert b"<root>" in out or b"<?xml" in out

    def test_get_path(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        nested = next(n for n in nodes if n.tag == "nested")
        path = self.adapter.get_path(nested)
        assert "nested" in path
        assert "root" in path


# ── JSON Adapter ──────────────────────────────────────────────────────────────

class TestJSONAdapter:
    def setup_method(self):
        self.adapter = JSONAdapter()
        self.tree = self.adapter.parse(JSON_DOC)

    def test_parse_returns_node_wrapper(self):
        from app.adapters.node_wrapper import NodeWrapper
        assert isinstance(self.tree, NodeWrapper)

    def test_iter_visits_all_nodes(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        # root + a + a.b + a.c + a.c[0,1,2] + d = 8 nodes
        assert len(nodes) >= 5

    def test_get_and_set_value(self):
        from app.adapters.node_wrapper import NodeWrapper
        nodes = list(self.adapter.iter_nodes(self.tree))
        leaf = next(n for n in nodes if isinstance(n, NodeWrapper) and n.value == "hello")
        self.adapter.set_value(leaf, "modified")
        assert self.adapter.get_value(leaf) == "modified"

    def test_identity_is_stable(self):
        nodes = list(self.adapter.iter_nodes(self.tree))
        n = nodes[0]
        assert self.adapter.get_identity(n) == id(n)

    def test_select_jsonpath(self):
        results = self.adapter.select(self.tree, "$.a.b")
        assert len(results) == 1
        from app.adapters.node_wrapper import NodeWrapper
        assert isinstance(results[0], NodeWrapper)

    def test_remove_node(self):
        result = self.adapter.select(self.tree, "$.d")
        assert result
        node = result[0]
        assert self.adapter.is_attached(node)
        self.adapter.remove_node(node)
        assert not self.adapter.is_attached(node)

    def test_removing_parent_detaches_children(self):
        a_nodes = self.adapter.select(self.tree, "$.a")
        b_nodes = self.adapter.select(self.tree, "$.a.b")
        assert a_nodes and b_nodes
        a_node = a_nodes[0]
        b_node = b_nodes[0]
        assert self.adapter.is_attached(b_node)
        self.adapter.remove_node(a_node)
        assert not self.adapter.is_attached(a_node)
        # After parent removed, b's parent reference is severed
        assert not self.adapter.is_attached(b_node)

    def test_serialise_roundtrip(self):
        import json
        out = self.adapter.serialise(self.tree)
        parsed = json.loads(out)
        assert parsed["d"] == "world"


# ── YAML Adapter ──────────────────────────────────────────────────────────────

class TestYAMLAdapter:
    def setup_method(self):
        self.adapter = YAMLAdapter()
        self.tree = self.adapter.parse(YAML_DOC)

    def test_parse_equivalent_to_json(self):
        json_adapter = JSONAdapter()
        json_tree = json_adapter.parse(JSON_DOC)
        yaml_tree = self.tree
        # Both should have the same logical structure
        from app.adapters.node_wrapper import unwrap_tree
        assert unwrap_tree(json_tree) == unwrap_tree(yaml_tree)

    def test_select_same_as_json(self):
        json_adapter = JSONAdapter()
        json_tree = json_adapter.parse(JSON_DOC)
        yaml_results = self.adapter.select(self.tree, "$.a.b")
        json_results = json_adapter.select(json_tree, "$.a.b")
        assert len(yaml_results) == len(json_results)

    def test_serialise_produces_yaml(self):
        out = self.adapter.serialise(self.tree)
        assert isinstance(out, bytes)
        import yaml
        parsed = yaml.safe_load(out)
        assert parsed["d"] == "world"
