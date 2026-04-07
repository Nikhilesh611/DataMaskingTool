"""Abstract base class that all format adapters must implement.

The pipeline never calls lxml, json, or yaml directly — it only calls the
methods defined here.  Format-specific code is entirely contained within
the three concrete adapter implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable, List


class FormatAdapter(ABC):
    """Contract that XML, JSON, and YAML adapters must satisfy."""

    @abstractmethod
    def parse(self, raw: bytes) -> Any:
        """Parse *raw* bytes into an internal node tree.

        Returns an opaque tree object suitable for all other methods.
        Raises ``ParseError`` on malformed input.
        """

    @abstractmethod
    def iter_nodes(self, tree: Any) -> Iterable[Any]:
        """Yield every node in *tree* in depth-first document order."""

    @abstractmethod
    def get_identity(self, node: Any) -> int:
        """Return a stable integer that uniquely identifies *node* in memory."""

    @abstractmethod
    def get_value(self, node: Any) -> Any:
        """Return the current value of *node* (string, number, None, …)."""

    @abstractmethod
    def set_value(self, node: Any, value: Any) -> None:
        """Replace the current value of *node* with *value*."""

    @abstractmethod
    def remove_node(self, node: Any) -> None:
        """Detach *node* from the tree.  Descendants are implicitly removed."""

    @abstractmethod
    def is_attached(self, node: Any) -> bool:
        """Return *True* if *node* is still connected to the tree root."""

    @abstractmethod
    def select(self, tree: Any, selector: str) -> List[Any]:
        """Evaluate *selector* against *tree* and return matching nodes.

        The selector language (XPath for XML, JSONPath for JSON/YAML) is
        determined by the concrete adapter.
        """

    @abstractmethod
    def serialise(self, tree: Any) -> bytes:
        """Serialise *tree* back to raw bytes in the adapter's native format."""

    @abstractmethod
    def get_path(self, node: Any) -> str:
        """Return a human-readable path string from the root to *node*."""
