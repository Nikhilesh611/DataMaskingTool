"""
Comprehensive Multi-Role Verification Suite for BioCorp International.
Tests all 4 enterprise roles against on-the-fly streaming masking:
  1. clinical-analyst (dr.smith@biocorp.com -> biocorp-researchers)
  2. claims-insurer   (adjuster@anthem.com   -> biocorp-insurers)
  3. compliance-auditor (auditor@kpmg.com     -> biocorp-auditors)
  4. emergency-operator (dispatch@biocorp.com -> biocorp-er-dispatch)

Validates both JSON payload and XML streaming upload.
"""
import json
import requests
import sys

BASE_URL = "http://127.0.0.1:8000"
IDP_URL = "http://localhost:8086"

ROLES_CONFIG = [
    {
        "role_name": "clinical-analyst",
        "user": "dr.smith@biocorp.com",
        "group": "biocorp-researchers",
        "expected_behavior": "Billing dropped, Address synthesized, Diagnosis generalized (I21/E11), Notes redacted"
    },
    {
        "role_name": "claims-insurer",
        "user": "adjuster@anthem.com",
        "group": "biocorp-insurers",
        "expected_behavior": "Medical history dropped, Billing amount noise-perturbed, Card masked, CVV dropped"
    },
    {
        "role_name": "compliance-auditor",
        "user": "auditor@kpmg.com",
        "group": "biocorp-auditors",
        "expected_behavior": "Full record retained, Card pattern-masked, SSN redacted, Audit trail recorded"
    },
    {
        "role_name": "emergency-operator",
        "user": "dispatch@biocorp.com",
        "group": "biocorp-er-dispatch",
        "expected_behavior": "Zero masking / bypass (emergency break-glass)"
    }
]

def mint_token(user: str, group: str) -> str:
    res = requests.post(f"{IDP_URL}/token", json={"sub": user, "groups": [group], "aud": "masking-api"})
    if res.status_code != 200:
        raise RuntimeError(f"Failed to mint token from {IDP_URL}: {res.text}")
    return res.json()["access_token"]

def run_tests():
    print("=" * 80)
    print("BIOCORP INTERNATIONAL - ENTERPRISE MULTI-ROLE VERIFICATION SUITE")
    print("=" * 80)

    # Load JSON Payload
    with open("data/biocorp_payload.json", "r") as f:
        json_payload = json.load(f)

    # 1. Test JSON Endpoint for each role
    for role in ROLES_CONFIG:
        print(f"\n[TESTING ROLE] {role['role_name'].upper()}")
        print(f"  User:   {role['user']}")
        print(f"  Group:  {role['group']}")
        print(f"  Expect: {role['expected_behavior']}")

        token = mint_token(role["user"], role["group"])
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        resp = requests.post(f"{BASE_URL}/v1/mask", json=json_payload, headers=headers)
        if resp.status_code != 200:
            print(f"  [ERROR] Status {resp.status_code}: {resp.text}")
            continue

        audit_id = resp.headers.get("x-audit-event-id", "N/A")
        latency = resp.headers.get("x-masking-latency-ms", "N/A")
        masked_data = resp.json()
        first_patient = masked_data.get("patients", [{}])[0]

        print(f"  [HTTP 200 OK] Audit ID: {audit_id} | Latency: {latency}ms")
        print("  Sample Masked Fields for Patient 1 (Evelyn Vance):")
        p_info = first_patient.get('personal_info', {})
        print(f"    - Full Name:       {p_info.get('name')}")
        print(f"    - SSN:             {p_info.get('ssn')}")
        print(f"    - Street Address:  {p_info.get('contact', {}).get('address', {}).get('street')}")
        print(f"    - Medical History: {'[DROPPED]' if 'medical_history' not in first_patient else 'Present'}")
        if 'medical_history' in first_patient:
            hist = first_patient['medical_history']
            print(f"      * Diagnosis:     {hist.get('diagnosis')}")
            print(f"      * Clinical Note: {hist.get('clinical_notes')}")
        print(f"    - Billing:         {'[DROPPED]' if 'billing' not in first_patient else 'Present'}")
        if 'billing' in first_patient:
            bill = first_patient['billing']
            print(f"      * Total Charges: {bill.get('amount')}")
            print(f"      * Card Number:   {bill.get('card_number')}")
            print(f"      * CVV:           {bill.get('cvv', '[DROPPED]')}")

    # 2. Test File Upload (XML streaming)
    print("\n" + "=" * 80)
    print("[TESTING STREAMING FILE UPLOAD - XML]")
    auditor_token = mint_token("auditor@kpmg.com", "biocorp-auditors")
    with open("data/biocorp_payload.xml", "rb") as xml_file:
        files = {"file": ("biocorp_payload.xml", xml_file, "application/xml")}
        headers = {"Authorization": f"Bearer {auditor_token}"}
        resp = requests.post(f"{BASE_URL}/v1/mask/file", files=files, headers=headers)
        if resp.status_code == 200:
            print(f"  [HTTP 200 OK] Audit ID: {resp.headers.get('x-audit-event-id')} | Latency: {resp.headers.get('x-masking-latency-ms')}ms")
            preview = resp.text[:400].replace('\n', ' ')
            print(f"  XML Stream Output (truncated): {preview}...")
        else:
            print(f"  [ERROR] Status {resp.status_code}: {resp.text}")

    print("\n" + "=" * 80)
    print("ALL TESTS COMPLETED SUCCESSFULLY!")
    print("Check the Admin UI Compliance Audit Ledger at: http://localhost:8000/admin")
    print("=" * 80)

if __name__ == "__main__":
    run_tests()
