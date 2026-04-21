"""Shared pytest fixtures for the masking API test suite — v2.0."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Generator

import pytest

# ── v1 minimal policy ──────────────────────────────────────────────────────────

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

# ── v2 policy YAML ────────────────────────────────────────────────────────────

V2_POLICY_YAML = """
version: "2.0"
record_root:
  - "$.patients[*]"
  - "//patient"

profiles:
  pii_profile:
    rules:
      - selector: "$..name"
        technique: redact
      - selector: "//name"
        technique: redact
      - selector: "$..ssn"
        technique: suppress
      - selector: "//ssn"
        technique: suppress
      - selector: "$..email"
        technique: pseudonymize
        consistent: true
      - selector: "//email"
        technique: pseudonymize
        consistent: true
  card_profile:
    rules:
      - selector: "$..card_number"
        technique: mask_pattern
        pattern: "****-****-****-{last4}"
      - selector: "//card_number"
        technique: mask_pattern
        pattern: "****-****-****-{last4}"
      - selector: "$..cvv"
        technique: suppress
      - selector: "//cvv"
        technique: suppress
  address_profile:
    rules:
      - selector: "$..street"
        technique: mask_pattern
        pattern: "[STREET REDACTED]"
      - selector: "//street"
        technique: mask_pattern
        pattern: "[STREET REDACTED]"
      - selector: "$..city"
        technique: redact
      - selector: "//city"
        technique: redact

scopes:
  - path: "$.patients[*].personal_info"
    apply_profile: pii_profile
    roles:
      analyst:
        strategy: masked
      auditor:
        strategy: masked
      default:
        strategy: masked

  - path: "//personal_info"
    apply_profile: pii_profile
    roles:
      analyst:
        strategy: masked
      auditor:
        strategy: masked
      default:
        strategy: masked

  - path: "$.patients[*].personal_info.contact.address"
    apply_profile: address_profile
    roles:
      analyst:
        strategy: synthesize
      auditor:
        strategy: masked
      default:
        strategy: drop_subtree

  - path: "//address"
    apply_profile: address_profile
    roles:
      analyst:
        strategy: synthesize
      auditor:
        strategy: masked
      default:
        strategy: drop_subtree

  - path: "$.patients[*].medical_history.clinical_notes"
    roles:
      analyst:
        strategy: deep_redact
      auditor:
        strategy: deep_redact
      default:
        strategy: drop_subtree

  - path: "//clinical_notes"
    roles:
      analyst:
        strategy: deep_redact
      auditor:
        strategy: deep_redact
      default:
        strategy: drop_subtree

  - path: "$.patients[*].billing"
    apply_profile: card_profile
    roles:
      analyst:
        strategy: drop_subtree
      auditor:
        strategy: masked
      default:
        strategy: drop_subtree

  - path: "//billing"
    apply_profile: card_profile
    roles:
      analyst:
        strategy: drop_subtree
      auditor:
        strategy: masked
      default:
        strategy: drop_subtree

  - path: "$.patients[*].assigned_doctor"
    roles:
      default:
        strategy: default_allow

  - path: "//assigned_doctor"
    roles:
      default:
        strategy: default_allow

rules:
  - selector: "$..patient_id"
    technique: pseudonymize
    consistent: true
  - selector: "//@id"
    technique: pseudonymize
    consistent: true

k_anonymity:
  enabled: false
  k: 2
  quasi_identifiers: []
"""

# ── v2 sample data ────────────────────────────────────────────────────────────

SAMPLE_V2_JSON = json.dumps({
    "patients": [
        {
            "patient_id": "P001",
            "personal_info": {
                "name": "Alice Johnson",
                "dob": "1985-07-23",
                "ssn": "123-45-6789",
                "contact": {
                    "email": "alice@example.com",
                    "phone": "555-100-2001",
                    "address": {
                        "street": "123 Main St",
                        "city": "New York",
                        "zip": "10001"
                    }
                }
            },
            "medical_history": {
                "diagnosis": "J18.9",
                "bloodpressure": "120.5",
                "clinical_notes": {
                    "admission_note": "Patient presented with chest pain.",
                    "discharge_summary": "Discharged after 3 days."
                }
            },
            "billing": {
                "card_number": "4111-1111-1111-1234",
                "cvv": "123",
                "amount": "450.00"
            },
            "assigned_doctor": {
                "doctor_id": "DOC-104",
                "name": "Dr. Smith",
                "department": "Cardiology"
            }
        },
        {
            "patient_id": "P002",
            "personal_info": {
                "name": "Bob Williams",
                "dob": "1972-03-14",
                "ssn": "987-65-4321",
                "contact": {
                    "email": "bob@example.com",
                    "phone": "555-200-3002",
                    "address": {
                        "street": "456 Oak Ave",
                        "city": "Chicago",
                        "zip": "60601"
                    }
                }
            },
            "medical_history": {
                "diagnosis": "E11.9",
                "bloodpressure": "138.0",
                "clinical_notes": {
                    "admission_note": "Diabetic, routine checkup.",
                    "discharge_summary": "Discharged same day."
                }
            },
            "billing": {
                "card_number": "5500-0000-0000-0004",
                "cvv": "456",
                "amount": "1200.50"
            },
            "assigned_doctor": {
                "doctor_id": "DOC-205",
                "name": "Dr. Lee",
                "department": "Endocrinology"
            }
        }
    ]
})

SAMPLE_V2_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<patients>
  <patient id="P001">
    <personal_info>
      <name>Alice Johnson</name>
      <dob>1985-07-23</dob>
      <ssn>123-45-6789</ssn>
      <contact>
        <email>alice@example.com</email>
        <phone>555-100-2001</phone>
        <address>
          <street>123 Main St</street>
          <city>New York</city>
          <zip>10001</zip>
        </address>
      </contact>
    </personal_info>
    <medical_history>
      <diagnosis>J18.9</diagnosis>
      <bloodpressure>120.5</bloodpressure>
      <clinical_notes>
        <admission_note>Patient presented with chest pain.</admission_note>
        <discharge_summary>Discharged after 3 days.</discharge_summary>
      </clinical_notes>
    </medical_history>
    <billing>
      <card_number>4111-1111-1111-1234</card_number>
      <cvv>123</cvv>
      <amount>450.00</amount>
    </billing>
    <assigned_doctor>
      <doctor_id>DOC-104</doctor_id>
      <name>Dr. Smith</name>
      <department>Cardiology</department>
    </assigned_doctor>
  </patient>
  <patient id="P002">
    <personal_info>
      <name>Bob Williams</name>
      <dob>1972-03-14</dob>
      <ssn>987-65-4321</ssn>
      <contact>
        <email>bob@example.com</email>
        <phone>555-200-3002</phone>
        <address>
          <street>456 Oak Ave</street>
          <city>Chicago</city>
          <zip>60601</zip>
        </address>
      </contact>
    </personal_info>
    <medical_history>
      <diagnosis>E11.9</diagnosis>
      <bloodpressure>138.0</bloodpressure>
      <clinical_notes>
        <admission_note>Diabetic, routine checkup.</admission_note>
        <discharge_summary>Discharged same day.</discharge_summary>
      </clinical_notes>
    </medical_history>
    <billing>
      <card_number>5500-0000-0000-0004</card_number>
      <cvv>456</cvv>
      <amount>1200.50</amount>
    </billing>
    <assigned_doctor>
      <doctor_id>DOC-205</doctor_id>
      <name>Dr. Lee</name>
      <department>Endocrinology</department>
    </assigned_doctor>
  </patient>
</patients>"""


@pytest.fixture
def tmp_data_dir() -> Generator[str, None, None]:
    """Temporary directory containing v1 and v2 sample data files."""
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "sample.json"), "w") as f:
            f.write(SAMPLE_JSON_DOC)
        with open(os.path.join(d, "sample.yaml"), "w") as f:
            f.write(SAMPLE_YAML_DOC)
        with open(os.path.join(d, "sample.xml"), "wb") as f:
            f.write(SAMPLE_XML_DOC)
        with open(os.path.join(d, "sample.txt"), "w") as f:
            f.write("plain text")
        # v2 samples
        with open(os.path.join(d, "sample_v2.json"), "w") as f:
            f.write(SAMPLE_V2_JSON)
        with open(os.path.join(d, "sample_v2.xml"), "wb") as f:
            f.write(SAMPLE_V2_XML)
        yield d


@pytest.fixture(autouse=True)
def ensure_hierarchies():
    """Ensure all built-in hierarchies are registered before each test."""
    import app.hierarchies  # noqa: F401


@pytest.fixture
def v1_policy():
    """Load and return the minimal v1 MaskingPolicy."""
    import app.hierarchies  # noqa: F401
    from app.policy.loader import load_policy_from_string
    return load_policy_from_string(MINIMAL_POLICY_YAML)


@pytest.fixture
def v2_policy():
    """Load and return the v2 MaskingPolicy with profiles and scopes."""
    import app.hierarchies  # noqa: F401
    from app.policy.loader import load_policy_from_string
    return load_policy_from_string(V2_POLICY_YAML)
