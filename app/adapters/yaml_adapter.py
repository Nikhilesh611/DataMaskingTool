"""YAML format adapter — wraps PyYAML + jsonpath-ng.

PyYAML's ``safe_load`` produces the same Python dict/list structure as
``json.loads``, so this adapter reuses the NodeWrapper, traversal, and
selector logic from ``node_wrapper.py`` and ``json_adapter.py`` entirely.
The only differences are the parser and serialiser at the edges.
"""

from __future__ import annotations

from typing import Any, Iterable, List

import yaml

from app.adapters.base import FormatAdapter
from app.adapters.json_adapter import JSONAdapter, _find_by_jsonpath_path, _to_plain_with_index
from app.adapters.node_wrapper import (
    NodeWrapper,
    is_node_attached,
    iter_wrapped,
    unwrap_tree,
    wrap_tree,
)
from app.exceptions import ParseError

# jsonpath-ng is already imported transitively through json_adapter.
from jsonpath_ng import parse as jp_parse
from jsonpath_ng.exceptions import JsonPathParserError


class YAMLAdapter(FormatAdapter):
    """Concrete adapter for YAML files.

    Shares *all* traversal, wrapping, selector, attachment, and path logic
    with ``JSONAdapter``.  Only ``parse`` and ``serialise`` differ.
    """

    # Delegate shared behaviour to a JSONAdapter instance.
    _json_adapter = JSONAdapter()

    # ── Parsing / serialisation ───────────────────────────────────────────────

    def parse(self, raw: bytes) -> NodeWrapper:
        try:
            data = yaml.safe_load(raw.decode("utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            raise ParseError(
                filename="<unknown>",
                fmt="yaml",
                reason=str(exc),
            ) from exc
        # yaml.safe_load returns None for an empty document
        if data is None:
            data = {}
        return wrap_tree(data)

    def parse_with_filename(self, raw: bytes, filename: str) -> NodeWrapper:
        try:
            data = yaml.safe_load(raw.decode("utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            raise ParseError(filename=filename, fmt="yaml", reason=str(exc)) from exc
        if data is None:
            data = {}
        return wrap_tree(data)

    def serialise(self, tree: NodeWrapper) -> bytes:
        plain = unwrap_tree(tree)
        return yaml.dump(plain, allow_unicode=True, default_flow_style=False).encode("utf-8")

    # ── All other methods delegate to the shared JSON/YAML logic ─────────────

    def iter_nodes(self, tree: NodeWrapper) -> Iterable[NodeWrapper]:
        yield from iter_wrapped(tree)

    def iter_subtree(self, subtree_root: NodeWrapper) -> Iterable[NodeWrapper]:
        """Yield *subtree_root* and every wrapped descendant in depth-first order."""
        yield from iter_wrapped(subtree_root)

    def is_leaf_node(self, node: NodeWrapper) -> bool:
        """Return True if *node* holds a scalar value (not a dict or list)."""
        return self._json_adapter.is_leaf_node(node)

    def get_identity(self, node: NodeWrapper) -> int:
        return id(node)

    def get_value(self, node: NodeWrapper) -> Any:
        return self._json_adapter.get_value(node)

    def set_value(self, node: NodeWrapper, value: Any) -> None:
        self._json_adapter.set_value(node, value)

    def remove_node(self, node: NodeWrapper) -> None:
        self._json_adapter.remove_node(node)

    def is_attached(self, node: NodeWrapper) -> bool:
        return is_node_attached(node)

    def select(self, tree: NodeWrapper, selector: str) -> List[NodeWrapper]:
        return self._json_adapter.select(tree, selector)

    def get_path(self, node: NodeWrapper) -> str:
        return node.path
