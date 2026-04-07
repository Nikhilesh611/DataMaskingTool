"""Shared pytest fixtures for the masking API test suite."""

from __future__ import annotations

import os
import tempfile
from typing import Generator

import pytest

# ── Minimal valid policy YAML ─────────────────────────────────────────────────

MINIMAL_POLICY_YAML = """
version: "1.0"
record_root: "$.patients[*]"
rules:
  - selector: "$..ssn"
    technique: suppress
  - selector: "$..dob"
    technique: generalize
    hierarchy: date
    level: 2
  - selector: "$..name"
    technique: redact
"""

SAMPLE_JSON_DOC = """{
  "patients": [
    {"id": "P001", "name": "Alice", "dob": "1985-07-23", "ssn": "111-22-3333", "zipcode": "10001"},
    {"id": "P002", "name": "Bob",   "dob": "1985-07-23", "ssn": "444-55-6666", "zipcode": "10001"}
  ]
}"""

SAMPLE_YAML_DOC = """
patients:
  - id: P001
    name: Alice
    dob: "1985-07-23"
    ssn: 111-22-3333
    zipcode: "10001"
  - id: P002
    name: Bob
    dob: "1985-07-23"
    ssn: 444-55-6666
    zipcode: "10001"
"""

SAMPLE_XML_DOC = b"""<?xml version="1.0"?>
<patients>
  <patient id="P001">
    <name>Alice</name>
    <dob>1985-07-23</dob>
    <ssn>111-22-3333</ssn>
    <zipcode>10001</zipcode>
  </patient>
  <patient id="P002">
    <name>Bob</name>
    <dob>1985-07-23</dob>
    <ssn>444-55-6666</ssn>
    <zipcode>10001</zipcode>
  </patient>
</patients>"""


@pytest.fixture
def tmp_data_dir() -> Generator[str, None, None]:
    """Temporary directory containing sample data files."""
    with tempfile.TemporaryDirectory() as d:
        # Write sample files
        with open(os.path.join(d, "sample.json"), "w") as f:
            f.write(SAMPLE_JSON_DOC)
        with open(os.path.join(d, "sample.yaml"), "w") as f:
            f.write(SAMPLE_YAML_DOC)
        with open(os.path.join(d, "sample.xml"), "wb") as f:
            f.write(SAMPLE_XML_DOC)
        with open(os.path.join(d, "sample.txt"), "w") as f:
            f.write("plain text")
        yield d


@pytest.fixture(autouse=True)
def ensure_hierarchies():
    """Ensure all built-in hierarchies are registered before each test."""
    import app.hierarchies  # noqa: F401
