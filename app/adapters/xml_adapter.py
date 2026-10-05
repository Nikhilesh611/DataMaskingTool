"""XML format adapter — wraps lxml.

All pipeline operations on XML documents go through this adapter.
The pipeline never imports lxml directly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, List

from lxml import etree

from app.adapters.base import FormatAdapter
from app.exceptions import ParseError


@dataclass
class XMLAttributeNode:
    """Represents an XML attribute so it can be passed around like an element."""
    element: etree._Element
    attr_name: str

class XMLTreeWrapper:
    """Holds references to all lxml elements to keep proxies alive and id() stable."""
    def __init__(self, root: etree._Element):
        self.root = root
        self.keep_alive = list(root.iter())


class XMLAdapter(FormatAdapter):
    """Concrete adapter for XML files using lxml."""

    # ── Parsing / serialisation ───────────────────────────────────────────────

    # Hardened parser: no external entities, no DTD loading, no network access.
    # This fully blocks XXE (XML External Entity) injection attacks.
    _PARSER = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,  # block billion-laughs / deeply nested bombs
    )

    def parse(self, raw: bytes) -> XMLTreeWrapper:
        try:
            tree = etree.fromstring(raw, parser=self._PARSER)
            return XMLTreeWrapper(tree)
        except etree.XMLSyntaxError as exc:
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
            tree = etree.fromstring(raw, parser=self._PARSER)
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

    def iter_nodes(self, tree: XMLTreeWrapper) -> Iterable[Any]:
        """Yield every element and its attributes in depth-first document order."""
        for elem in tree.root.iter():
            yield elem
            for attr_name in elem.attrib:
                yield XMLAttributeNode(elem, attr_name)

    def iter_subtree(self, subtree_root: Any) -> Iterable[Any]:
        """Yield *subtree_root* and every descendant in depth-first order.

        *subtree_root* must be a raw lxml ``_Element`` (as returned by
        ``select``), not an ``XMLTreeWrapper``.
        """
        if isinstance(subtree_root, XMLAttributeNode):
            yield subtree_root
            return
        for elem in subtree_root.iter():
            yield elem
            for attr_name in elem.attrib:
                yield XMLAttributeNode(elem, attr_name)

    def is_leaf_node(self, node: Any) -> bool:
        """Return True if *node* is a scalar leaf (no child elements)."""
        if isinstance(node, XMLAttributeNode):
            return True
        # An element is a leaf when it has no child element nodes.
        return len(list(node)) == 0

    # ── Node identity & value ─────────────────────────────────────────────────

    def get_identity(self, node: Any) -> int:
        if isinstance(node, XMLAttributeNode):
            return hash((id(node.element), node.attr_name))
        return id(node)

    def get_value(self, node: Any) -> Any:
        """Return the element's text content or attribute value."""
        if isinstance(node, XMLAttributeNode):
            return node.element.get(node.attr_name)
        return node.text

    def set_value(self, node: Any, value: Any) -> None:
        """Set the element's text or attribute. *None* produces a self-closing tag or drops attr."""
        if isinstance(node, XMLAttributeNode):
            if value is None:
                node.element.attrib.pop(node.attr_name, None)
            else:
                node.element.set(node.attr_name, str(value))
        else:
            node.text = str(value) if value is not None else None

    # ── Attachment & removal ──────────────────────────────────────────────────

    def remove_node(self, node: Any) -> None:
        if isinstance(node, XMLAttributeNode):
            node.element.attrib.pop(node.attr_name, None)
            return
        parent = node.getparent()
        if parent is not None:
            parent.remove(node)
        # Root node removal is a no-op (cannot detach the document root).

    def is_attached(self, node: Any) -> bool:
        """Return True if *node* is reachable from the tree root.

        lxml children retain their parent reference even after the parent
        has been removed from the root, so we must walk the entire parent
        chain up to a node that has no parent and verify it is indeed the root.
        """
        if isinstance(node, XMLAttributeNode):
            if node.attr_name not in node.element.attrib:
                return False
            return self.is_attached(node.element)

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
        """Evaluate an XPath 1.0 expression against *tree*.

        Namespace handling
        ------------------
        If the selector contains ``local-name()`` it is used as-is (the
        caller already wrote a namespace-agnostic expression).  Otherwise, if
        the document has a default namespace, selectors without a prefix may
        match nothing; in that case we automatically re-evaluate the selector
        using ``*[local-name()='tag']`` style expansion so enterprise XML
        schemas with default namespaces work without policy changes.
        """
        try:
            if isinstance(tree, XMLTreeWrapper):
                results = tree.root.xpath(selector)
            else:
                results = tree.xpath(selector)
        except etree.XPathEvalError:
            return []
        except etree.XPathSyntaxError:
            return []

        # If nothing matched and the document has a default namespace, retry
        # with a namespace-stripped selector (local-name() strategy).
        if not results and isinstance(tree, XMLTreeWrapper):
            root_ns = tree.root.nsmap.get(None)
            if root_ns and "local-name" not in selector:
                ns_selector = re.sub(
                    r"(?<![:\w])([A-Za-z_][\w\-]*)",
                    lambda m: f"*[local-name()='{m.group(1)}']"
                    if m.group(1) not in ("and", "or", "not", "div", "mod")
                    else m.group(1),
                    selector,
                )
                try:
                    if isinstance(tree, XMLTreeWrapper):
                        results = tree.root.xpath(ns_selector)
                    else:
                        results = tree.xpath(ns_selector)
                except (etree.XPathEvalError, etree.XPathSyntaxError):
                    results = []

        nodes = []
        for r in results:
            if isinstance(r, etree._Element):
                nodes.append(r)
            elif hasattr(r, 'is_attribute') and r.is_attribute:
                nodes.append(XMLAttributeNode(r.getparent(), r.attrname))
        return nodes

    # ── Path string ───────────────────────────────────────────────────────────

    def get_path(self, node: Any) -> str:
        """Build a simple slash-separated path from the root to *node*."""
        if isinstance(node, XMLAttributeNode):
            return self.get_path(node.element) + f"/@{node.attr_name}"

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
