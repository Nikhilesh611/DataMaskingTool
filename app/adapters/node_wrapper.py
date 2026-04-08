"""NodeWrapper — lightweight parent-tracking wrapper for JSON / YAML nodes.

Because ``json.loads`` and ``yaml.safe_load`` produce plain Python dicts and
lists with no concept of parent, path, or identity, the JSON and YAML adapters
wrap every value in this object at parse time.

Both adapters share the wrapping logic exported from this module so there is
no duplication between them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional, Union


@dataclass(eq=False)
class NodeWrapper:
    """Carries a document value together with structural metadata."""

    value: Any
    """The actual scalar, dict, or list value at this position."""

    parent: Optional["NodeWrapper"] = field(default=None, repr=False)
    """Reference to the parent wrapper, or *None* for the root."""

    key: Optional[Union[str, int]] = field(default=None)
    """The key (dict) or index (list) that points to this node in its parent."""

    path: str = field(default="$")
    """Dot-notation JSONPath from the document root (e.g. ``$.patients.0.dob``)."""

    _is_root: bool = field(default=False, repr=False)
    """True only for the document root created by wrap_tree.  Used to
    distinguish the real root (parent=None, _is_root=True) from a severed
    node (parent=None, _is_root=False) after remove_node."""


# ── Shared traversal & wrapping helpers ──────────────────────────────────────

def wrap_tree(raw: Any) -> NodeWrapper:
    """Recursively wrap a plain Python structure into a NodeWrapper tree.

    This is the entry point called by both JSON and YAML adapters after parsing.
    """
    root = NodeWrapper(value=None, parent=None, key=None, path="$", _is_root=True)
    _fill(root, raw, path="$")
    return root


def _fill(wrapper: NodeWrapper, raw: Any, path: str) -> None:
    """Set ``wrapper.value`` to a recursively-wrapped copy of *raw*."""
    if isinstance(raw, dict):
        wrapped: Any = {}
        for k, v in raw.items():
            child_path = f"{path}.{k}"
            child = NodeWrapper(value=None, parent=wrapper, key=k, path=child_path)
            _fill(child, v, child_path)
            wrapped[k] = child
        wrapper.value = wrapped

    elif isinstance(raw, list):
        wrapped = []
        for i, v in enumerate(raw):
            child_path = f"{path}[{i}]"
            child = NodeWrapper(value=None, parent=wrapper, key=i, path=child_path)
            _fill(child, v, child_path)
            wrapped.append(child)
        wrapper.value = wrapped

    else:
        wrapper.value = raw


def iter_wrapped(root: NodeWrapper) -> Iterable[NodeWrapper]:
    """Yield every NodeWrapper in the tree in depth-first order."""
    yield root
    if isinstance(root.value, dict):
        for child in root.value.values():
            yield from iter_wrapped(child)
    elif isinstance(root.value, list):
        for child in root.value:
            yield from iter_wrapped(child)


def unwrap_tree(wrapper: NodeWrapper) -> Any:
    """Reconstruct a plain Python structure from a NodeWrapper tree.

    Used by adapters at serialisation time.
    """
    if isinstance(wrapper.value, dict):
        return {k: unwrap_tree(child) for k, child in wrapper.value.items()}
    if isinstance(wrapper.value, list):
        return [unwrap_tree(child) for child in wrapper.value]
    return wrapper.value


def _sever_subtree(node: NodeWrapper) -> None:
    """Recursively set parent=None for *node* and all its descendants.

    Called by remove_node so that is_node_attached returns False not only for
    the directly-removed node but also for all nodes in its subtree.
    """
    node.parent = None
    if isinstance(node.value, dict):
        for child in node.value.values():
            if isinstance(child, NodeWrapper):
                _sever_subtree(child)
    elif isinstance(node.value, list):
        for child in node.value:
            if isinstance(child, NodeWrapper):
                _sever_subtree(child)


def is_node_attached(node: NodeWrapper) -> bool:
    """Return True if *node* is still reachable from the root.

    A node becomes detached when its parent reference is severed via
    ``_sever_subtree`` (called by ``remove_node``).  The document root is
    distinguished from a detached node by the ``_is_root`` flag.
    """
    if node.parent is None:
        # Either the document root (always attached) or a severed node.
        return node._is_root
    parent = node.parent
    pval = parent.value
    if isinstance(pval, dict):
        stored = pval.get(node.key)
        return stored is node
    if isinstance(pval, list):
        idx = node.key
        if not isinstance(idx, int) or idx >= len(pval):
            return False
        return pval[idx] is node
    return False
