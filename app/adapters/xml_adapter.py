"""XML format adapter — wraps lxml.

All pipeline operations on XML documents go through this adapter.
The pipeline never imports lxml directly.
"""

from __future__ import annotations

from typing import Any, Iterable, List

from lxml import etree

from app.adapters.base import FormatAdapter
from app.exceptions import ParseError


class XMLTreeWrapper:
    """Holds references to all lxml elements to keep proxies alive and id() stable."""
    def __init__(self, root: etree._Element):
        self.root = root
        self.keep_alive = list(root.iter())


class XMLAdapter(FormatAdapter):
    """Concrete adapter for XML files using lxml."""

    # ── Parsing / serialisation ───────────────────────────────────────────────

    def parse(self, raw: bytes) -> XMLTreeWrapper:
        try:
            tree = etree.fromstring(raw)
            return XMLTreeWrapper(tree)
        except etree.XMLSyntaxError as exc:
            # lxml provides line/column information in the exception.
            location = f"line {exc.lineno}, col {exc.offset}" if exc.lineno else None
            raise ParseError(
                filename="<unknown>",
                fmt="xml",
                reason=str(exc),
                location=location,
            ) from exc

    def parse_with_filename(self, raw: bytes, filename: str) -> XMLTreeWrapper:
        """Variant that records the filename in any ParseError for cleaner logs."""
        try:
            tree = etree.fromstring(raw)
            return XMLTreeWrapper(tree)
        except etree.XMLSyntaxError as exc:
            location = f"line {exc.lineno}, col {exc.offset}" if exc.lineno else None
            raise ParseError(
                filename=filename,
                fmt="xml",
                reason=str(exc),
                location=location,
            ) from exc

    def serialise(self, tree: XMLTreeWrapper) -> bytes:
        # Before serialising, we don't strictly need keep_alive anymore, but we serialize the root.
        return etree.tostring(tree.root, pretty_print=True, xml_declaration=True, encoding="UTF-8")

    # ── Tree traversal ────────────────────────────────────────────────────────

    def iter_nodes(self, tree: XMLTreeWrapper) -> Iterable[etree._Element]:
        """Yield every element in depth-first document order via lxml's iter."""
        yield from tree.root.iter()

    # ── Node identity & value ─────────────────────────────────────────────────

    def get_identity(self, node: etree._Element) -> int:
        return id(node)

    def get_value(self, node: etree._Element) -> Any:
        """Return the element's text content (may be None)."""
        return node.text

    def set_value(self, node: etree._Element, value: Any) -> None:
        """Set the element's text.  *None* produces a self-closing tag."""
        node.text = str(value) if value is not None else None

    # ── Attachment & removal ──────────────────────────────────────────────────

    def remove_node(self, node: etree._Element) -> None:
        parent = node.getparent()
        if parent is not None:
            parent.remove(node)
        # Root node removal is a no-op (cannot detach the document root).

    def is_attached(self, node: etree._Element) -> bool:
        """Return True if *node* is reachable from the tree root.

        lxml children retain their parent reference even after the parent
        has been removed from the root, so we must walk the entire parent
        chain up to a node that has no parent and verify it is indeed the root.
        """
        current = node
        while True:
            parent = current.getparent()
            if parent is None:
                # current has no parent — it is either the document root
                # or a detached subtree root.
                try:
                    root = current.getroottree().getroot()
                    return root is current
                except Exception:
                    return False
            # Confirm current is still a direct child of parent.
            if current not in parent:
                return False
            current = parent

    # ── Selector evaluation ───────────────────────────────────────────────────

    def select(self, tree: XMLTreeWrapper, selector: str) -> List[etree._Element]:
        """Evaluate an XPath 1.0 expression against *tree*."""
        try:
            if isinstance(tree, XMLTreeWrapper):
                results = tree.root.xpath(selector)
            else:
                # Handle case where a raw lxml element is passed 
                # (e.g. kanon.py uses select() relative to individual nodes)
                results = tree.xpath(selector)
        except etree.XPathEvalError as exc:
            # Invalid XPath — return empty list rather than crashing.
            return []
        # XPath can return text nodes (strings) as well as elements.
        # We only care about element nodes that the pipeline can mutate.
        return [r for r in results if isinstance(r, etree._Element)]

    # ── Path string ───────────────────────────────────────────────────────────

    def get_path(self, node: etree._Element) -> str:
        """Build a simple slash-separated path from the root to *node*."""
        parts: List[str] = []
        current: etree._Element | None = node
        while current is not None:
            tag = current.tag if isinstance(current.tag, str) else str(current.tag)
            # Strip namespace if present.
            if "}" in tag:
                tag = tag.split("}", 1)[1]
            parts.append(tag)
            current = current.getparent()
        return "/" + "/".join(reversed(parts))
