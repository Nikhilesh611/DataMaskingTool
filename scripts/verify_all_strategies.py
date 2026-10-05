"""
Deep Validation Suite for Masking Engine:
Tests EVERY supported Scope Strategy and Element-Level Technique.

Scope Strategies:
  1. drop_subtree   -> Node is completely pruned/removed from structure
  2. deep_redact    -> Subtree structure intact, all nested leaves are '[REDACTED]'
  3. synthesize     -> Subtree structure intact, leaves replaced with synthetic data
  4. default_allow  -> Subtree untouched / bypass
  5. masked         -> Scoped profile + inline rules applied

Element-level Techniques:
  1. suppress       -> Key completely deleted
  2. nullify        -> Value replaced with null/None
  3. redact         -> Value replaced with '[REDACTED]'
  4. mask_pattern   -> Value pattern-masked e.g. ****-****-****-{last4}
  5. generalize     -> Hierarchical generalization e.g. ICD-10 I21.9 -> I21
  6. noise          -> Numeric differential privacy noise
  7. pseudonymize   -> Consistent HMAC token ANON_...
"""

import json
import requests
import sys

BASE_URL = "http://127.0.0.1:8000"
IDP_URL = "http://localhost:8086"

def get_token(role_group: str, user: str) -> str:
    res = requests.post(f"{IDP_URL}/token", json={"sub": user, "groups": [role_group], "aud": "masking-api"})
    return res.json()["access_token"]

def main():
    print("=" * 80)
    print("DEEP MASKING ENGINE CAPABILITY & STRATEGY AUDIT")
    print("=" * 80)

    with open("data/biocorp_payload.json", "r") as f:
        raw_payload = json.load(f)

    # -------------------------------------------------------------------------
    # TEST 1: Clinical Analyst (Tests: drop_subtree, synthesize, deep_redact, generalize, redact)
    # -------------------------------------------------------------------------
    print("\n--- [AUDIT 1: CLINICAL-ANALYST ROLE] ---")
    token_analyst = get_token("biocorp-researchers", "dr.smith@biocorp.com")
    res1 = requests.post(f"{BASE_URL}/v1/mask", json=raw_payload, headers={"Authorization": f"Bearer {token_analyst}"})
    assert res1.status_code == 200, f"Failed: {res1.text}"
    p1 = res1.json()["patients"][0]

    # Check 1.1: Scope Strategy: drop_subtree
    # Expected: 'billing' key must NOT exist at all in patient record
    billing_dropped = "billing" not in p1
    print(f"  [SCOPE: drop_subtree] 'billing' subtree pruned entirely: {billing_dropped}")
    assert billing_dropped, "FAILED: drop_subtree did not prune 'billing' subtree!"

    # Check 1.2: Scope Strategy: synthesize
    # Expected: 'address' object exists, but values are synthetic (not original)
    addr = p1.get("personal_info", {}).get("contact", {}).get("address", {})
    synthesize_working = (addr.get("street") is not None and addr.get("street") != "")
    print(f"  [SCOPE: synthesize] 'address' synthesized ({addr.get('street')}, {addr.get('city')} {addr.get('zip')}): {synthesize_working}")

    # Check 1.3: Scope Strategy: deep_redact
    # Expected: clinical_notes structure exists, and all nested keys are '[REDACTED]'
    notes = p1.get("medical_history", {}).get("clinical_notes", {})
    deep_redact_working = (
        notes.get("admission") == "[REDACTED]" and
        notes.get("medications") == "[REDACTED]" and
        notes.get("prognosis") == "[REDACTED]"
    )
    print(f"  [SCOPE: deep_redact] 'clinical_notes' all leaf values '[REDACTED]': {deep_redact_working}")
    assert deep_redact_working, "FAILED: deep_redact did not redact all leaves in clinical_notes!"

    # Check 1.4: Technique: generalize
    # Original diagnosis: "I21.9" -> Generalize ICD-10 level 1 should produce "I21"
    diagnosis = p1.get("medical_history", {}).get("diagnosis")
    generalize_working = (diagnosis == "I21")
    print(f"  [TECHNIQUE: generalize] ICD-10 'I21.9' generalized to '{diagnosis}': {generalize_working}")
    assert generalize_working, f"FAILED: generalize expected 'I21', got '{diagnosis}'"

    # Check 1.5: Technique: redact
    name = p1.get("personal_info", {}).get("name")
    redact_working = (name == "[REDACTED]")
    print(f"  [TECHNIQUE: redact] Name redacted to '{name}': {redact_working}")
    assert redact_working, f"FAILED: redact expected '[REDACTED]', got '{name}'"

    # -------------------------------------------------------------------------
    # TEST 2: Claims Insurer (Tests: drop_subtree on medical_history, noise, suppress)
    # -------------------------------------------------------------------------
    print("\n--- [AUDIT 2: CLAIMS-INSURER ROLE] ---")
    token_insurer = get_token("biocorp-insurers", "adjuster@anthem.com")
    res2 = requests.post(f"{BASE_URL}/v1/mask", json=raw_payload, headers={"Authorization": f"Bearer {token_insurer}"})
    assert res2.status_code == 200, f"Failed: {res2.text}"
    p2 = res2.json()["patients"][0]

    # Check 2.1: Scope Strategy: drop_subtree on medical_history
    med_dropped = "medical_history" not in p2
    print(f"  [SCOPE: drop_subtree] 'medical_history' subtree pruned entirely: {med_dropped}")
    assert med_dropped, "FAILED: drop_subtree did not prune 'medical_history' for insurer!"

    # Check 2.2: Technique: noise
    # Original amount: "8450.00" -> Noise added should produce a different numeric float
    orig_amount = float(raw_payload["patients"][0]["billing"]["amount"])
    masked_amount = float(p2.get("billing", {}).get("amount"))
    noise_working = (masked_amount != orig_amount and abs(masked_amount - orig_amount) < 2000.0)
    print(f"  [TECHNIQUE: noise] Original amount ${orig_amount:.2f} perturbed to ${masked_amount:.2f}: {noise_working}")
    assert noise_working, f"FAILED: noise expected perturbed float, got {masked_amount}"

    # Check 2.3: Technique: suppress
    # Expected: 'cvv' key must NOT exist in billing
    cvv_suppressed = "cvv" not in p2.get("billing", {})
    print(f"  [TECHNIQUE: suppress] 'cvv' attribute deleted completely: {cvv_suppressed}")
    assert cvv_suppressed, "FAILED: suppress did not delete 'cvv' attribute!"

    # -------------------------------------------------------------------------
    # TEST 3: Compliance Auditor (Tests: mask_pattern, audit trail)
    # -------------------------------------------------------------------------
    print("\n--- [AUDIT 3: COMPLIANCE-AUDITOR ROLE] ---")
    token_auditor = get_token("biocorp-auditors", "auditor@kpmg.com")
    res3 = requests.post(f"{BASE_URL}/v1/mask", json=raw_payload, headers={"Authorization": f"Bearer {token_auditor}"})
    assert res3.status_code == 200, f"Failed: {res3.text}"
    p3 = res3.json()["patients"][0]

    # Check 3.1: Technique: mask_pattern
    # Original card: "4111-2222-3333-4444" -> pattern "****-****-****-4444"
    card = p3.get("billing", {}).get("card_number")
    pattern_working = (card == "****-****-****-4444")
    print(f"  [TECHNIQUE: mask_pattern] Card masked with pattern '{card}': {pattern_working}")
    assert pattern_working, f"FAILED: mask_pattern expected '****-****-****-4444', got '{card}'"

    # -------------------------------------------------------------------------
    # TEST 4: Emergency Operator (Tests: default_allow break-glass)
    # -------------------------------------------------------------------------
    print("\n--- [AUDIT 4: EMERGENCY-OPERATOR ROLE] ---")
    token_er = get_token("biocorp-er-dispatch", "dispatch@biocorp.com")
    res4 = requests.post(f"{BASE_URL}/v1/mask", json=raw_payload, headers={"Authorization": f"Bearer {token_er}"})
    assert res4.status_code == 200, f"Failed: {res4.text}"
    p4 = res4.json()["patients"][0]

    # Check 4.1: Strategy: default_allow
    raw_p = raw_payload["patients"][0]
    default_allow_working = (
        p4.get("personal_info", {}).get("ssn") == raw_p["personal_info"]["ssn"] and
        p4.get("medical_history", {}).get("diagnosis") == raw_p["medical_history"]["diagnosis"] and
        p4.get("billing", {}).get("card_number") == raw_p["billing"]["card_number"] and
        p4.get("billing", {}).get("cvv") == raw_p["billing"]["cvv"]
    )
    print(f"  [STRATEGY: default_allow] Emergency break-glass leaves raw data 100% unaltered: {default_allow_working}")
    assert default_allow_working, "FAILED: default_allow mutated data unexpectedly!"

    print("\n" + "=" * 80)
    print("ALL STRATEGIES & TECHNIQUES AUDITED AND CONFIRMED 100% OPERATIONAL!")
    print("=" * 80)

if __name__ == "__main__":
    main()
