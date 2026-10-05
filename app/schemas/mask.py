"""Request / response schemas for the v1 masking endpoints.

Inline payload masking (POST /v1/mask)
---------------------------------------
``InlineMaskRequest`` — body: format + raw data dict/string/bytes.
``MaskResponse``       — response envelope with masked output + metadata.

File upload masking (POST /v1/mask/file)
-----------------------------------------
Accepts ``UploadFile`` (multipart/form-data).  The response is a
``StreamingResponse`` with the masked file as a download attachment;
no Pydantic model is needed for the response.

Format literals
---------------
``"json"``  — body ``data`` field must be a JSON-serialisable dict or list.
``"xml"``   — body ``data`` field must be a raw XML string.
``"yaml"``  — body ``data`` field must be a raw YAML string.
"""

from __future__ import annotations

from typing import Any, Literal, Union

from pydantic import BaseModel, Field, model_validator


# ── Accepted format literals ──────────────────────────────────────────────────

FormatLiteral = Literal["json", "xml", "yaml"]

_CONTENT_TYPES: dict[str, str] = {
    "json": "application/json",
    "xml":  "application/xml",
    "yaml": "application/yaml",
}


# ── Inline masking request ────────────────────────────────────────────────────

class InlineMaskRequest(BaseModel):
    """Request body for ``POST /v1/mask``.

    Attributes
    ----------
    format:
        One of ``"json"``, ``"xml"``, ``"yaml"``.
    data:
        The payload to mask.

        * For ``"json"``: a JSON-serialisable ``dict`` or ``list``.
        * For ``"xml"`` / ``"yaml"``: a raw string containing the document.

    Example (JSON)::

        {
          "format": "json",
          "data": {"user_id": 1042, "ssn": "123-45-6789"}
        }

    Example (XML)::

        {
          "format": "xml",
          "data": "<patient><name>Alice</name><ssn>111</ssn></patient>"
        }
    """

    format: FormatLiteral = Field(default="json", description="Document format: json, xml, or yaml.")
    data: Union[dict, list, str] = Field(
        ...,
        description=(
            "Payload to mask. dict/list for JSON; raw string for XML or YAML."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _coerce_input(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "format" in data and "data" in data:
                return data
            return {"format": "json", "data": data}
        if isinstance(data, list):
            return {"format": "json", "data": data}
        return data

    @model_validator(mode="after")
    def _validate_data_type(self) -> "InlineMaskRequest":

        if self.format == "json" and isinstance(self.data, str):
            # Accept JSON-encoded string and parse it for convenience.
            import json as _json
            try:
                parsed = _json.loads(self.data)
            except Exception as exc:
                raise ValueError(
                    f"'data' is a string but could not be parsed as JSON: {exc}"
                ) from exc
            object.__setattr__(self, "data", parsed)
        if self.format in ("xml", "yaml") and not isinstance(self.data, str):
            raise ValueError(
                f"'data' must be a string for format='{self.format}'."
            )
        return self

    def to_bytes(self) -> bytes:
        """Serialise ``data`` to bytes ready for the pipeline."""
        import json as _json
        import yaml as _yaml

        if self.format == "json":
            return _json.dumps(self.data).encode("utf-8")
        if self.format in ("xml", "yaml"):
            return str(self.data).encode("utf-8")
        raise ValueError(f"Unknown format: {self.format!r}")

    @property
    def content_type(self) -> str:
        return _CONTENT_TYPES[self.format]
