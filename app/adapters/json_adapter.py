"""JSON format adapter — wraps the standard ``json`` library + jsonpath-ng.

Parsing produces a NodeWrapper tree (see node_wrapper.py).  All pipeline
operations work exclusively against NodeWrapper objects; raw Python dicts and
lists are never exposed to the pipeline.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, List

from jsonpath_ng import parse as jp_parse
from jsonpath_ng.exceptions import JsonPathParserError

from app.adapters.base import FormatAdapter
from app.adapters.node_wrapper import (
    NodeWrapper,
    _sever_subtree,
    is_node_attached,
    iter_wrapped,
    unwrap_tree,
    wrap_tree,
)
from app.exceptions import ParseError


class JSONAdapter(FormatAdapter):
    """Concrete adapter for JSON files."""

    # ── Parsing / serialisation ───────────────────────────────────────────────

    def parse(self, raw: bytes) -> NodeWrapper:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParseError(
                filename="<unknown>",
                fmt="json",
                reason=str(exc),
            ) from exc
        return wrap_tree(data)

    def parse_with_filename(self, raw: bytes, filename: str) -> NodeWrapper:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParseError(filename=filename, fmt="json", reason=str(exc)) from exc
        return wrap_tree(data)

    def serialise(self, tree: NodeWrapper) -> bytes:
        plain = unwrap_tree(tree)
        return json.dumps(plain, indent=2, default=str).encode("utf-8")

    # ── Tree traversal ────────────────────────────────────────────────────────

    def iter_nodes(self, tree: NodeWrapper) -> Iterable[NodeWrapper]:
        yield from iter_wrapped(tree)

    # ── Node identity & value ─────────────────────────────────────────────────

    def get_identity(self, node: NodeWrapper) -> int:
        return id(node)

    def get_value(self, node: NodeWrapper) -> Any:
        return node.value if not isinstance(node.value, (dict, list)) else node.value

    def set_value(self, node: NodeWrapper, value: Any) -> None:
        node.value = value
        # Reflect the change in the parent's container so that unwrap_tree
        # picks it up at serialisation time.
        if node.parent is not None:
            pval = node.parent.value
            if isinstance(pval, dict) and isinstance(node.key, str):
                pval[node.key] = node
            elif isinstance(pval, list) and isinstance(node.key, int):
                pval[node.key] = node

    # ── Attachment & removal ──────────────────────────────────────────────────

    def remove_node(self, node: NodeWrapper) -> None:
        if node.parent is None:
            return  # Cannot remove root.
        pval = node.parent.value
        if isinstance(pval, dict) and isinstance(node.key, str):
            pval.pop(node.key, None)
            _sever_subtree(node)
        elif isinstance(pval, list) and isinstance(node.key, int):
            # Remove by identity match rather than index (index may have shifted).
            try:
                pval.remove(node)
            except ValueError:
                pass
            # Update sibling indices.
            for i, sibling in enumerate(pval):
                if isinstance(sibling, NodeWrapper):
                    sibling.key = i
            _sever_subtree(node)

    def is_attached(self, node: NodeWrapper) -> bool:
        return is_node_attached(node)

    # ── Selector evaluation ───────────────────────────────────────────────────

    def select(self, tree: NodeWrapper, selector: str) -> List[NodeWrapper]:
        """Evaluate a JSONPath expression and return matching NodeWrapper objects."""
        try:
            expr = jp_parse(selector)
        except (JsonPathParserError, Exception):
            return []

        # Build a plain Python representation that jsonpath-ng can traverse,
        # but keep a mapping back to NodeWrapper objects so we can return them.
        plain = _to_plain_with_index(tree)
        matches = expr.find(plain)

        # Resolve each match back to its NodeWrapper via path.
        results: List[NodeWrapper] = []
        for match in matches:
            path_str = str(match.full_path)
            wrapper = _find_by_jsonpath_path(tree, path_str)
            if wrapper is not None and wrapper not in results:
                results.append(wrapper)
        return results

    # ── Path string ───────────────────────────────────────────────────────────

    def get_path(self, node: NodeWrapper) -> str:
        return node.path


# ── Internal helpers ──────────────────────────────────────────────────────────

def _to_plain_with_index(wrapper: NodeWrapper) -> Any:
    """Convert a NodeWrapper tree to a plain Python structure for jsonpath-ng."""
    if isinstance(wrapper.value, dict):
        return {k: _to_plain_with_index(child) for k, child in wrapper.value.items()}
    if isinstance(wrapper.value, list):
        return [_to_plain_with_index(child) for child in wrapper.value]
    return wrapper.value


def _find_by_jsonpath_path(root: NodeWrapper, path_str: str) -> NodeWrapper | None:
    """Walk the NodeWrapper tree following a jsonpath-ng path string."""
    # jsonpath-ng serialises paths as e.g. "key1.key2[0].key3"
    # We parse this incrementally.
    import re

    # Split into tokens: plain keys or [N] indices.
    tokens = re.split(r"\.|\[(\d+)\]", path_str)
    # re.split with a capturing group inserts the captured part as well.
    # Rebuild a clean token list.
    parts: List[str | int] = []
    i = 0
    raw_tokens = re.findall(r"\[(\d+)\]|([^\.\[\]]+)", path_str)
    for idx_match, key_match in raw_tokens:
        if idx_match:
            parts.append(int(idx_match))
        elif key_match:
            parts.append(key_match)

    current = root
    for part in parts:
        if current is None:
            return None
        val = current.value
        if isinstance(part, int):
            if isinstance(val, list) and part < len(val):
                current = val[part]
            else:
                return None
        else:
            if isinstance(val, dict) and part in val:
                current = val[part]
            else:
                return None
    return current
