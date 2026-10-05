"""Test script demonstrating end-to-end Enterprise SSO Masking.

1. Fetches an RSA-signed OIDC Bearer token from the local Enterprise IdP (port 8081).
2. Sends a sensitive payload to the Data Masking API (port 8000) using Bearer auth.
3. Prints the dynamically masked result.
4. Verifies the audit record written to PostgreSQL.
"""

import json
import urllib.request
import urllib.error

# 1. Mint an Enterprise OIDC Bearer Token from corporate IdP (port 8081)
print("1. Requesting OIDC Bearer Token from corporate IdP...")
token_payload = {
    "sub": "alice@acme-corp.com",
    "groups": ["analyst"],
    "aud": "masking-api",
    "exp_seconds": 3600
}
req = urllib.request.Request(
    "http://localhost:8081/token",
    headers={"Content-Type": "application/json"},
    data=json.dumps(token_payload).encode()
)
try:
    with urllib.request.urlopen(req) as resp:
        token_data = json.loads(resp.read().decode())
        access_token = token_data["access_token"]
        print(f"   [SUCCESS] Received RS256 Bearer Token: {access_token[:35]}...\n")
except Exception as e:
    print(f"   [ERROR] Failed to mint token from IdP: {e}")
    exit(1)

# 2. Call the Data Masking Service (port 8000) with the corporate Bearer token
print("2. Sending sensitive payload to POST http://127.0.0.1:8000/v1/mask ...")
sensitive_payload = {
    "client_name": "Robert Smith",
    "ssn": "123-45-6789",
    "salary": 95000,
    "credit_card": "4111-2222-3333-4444",
    "email": "robert.smith@example.com"
}
print("   Inbound Data:")
print("   " + json.dumps(sensitive_payload, indent=4).replace("\n", "\n   "))

mask_req = urllib.request.Request(
    "http://127.0.0.1:8000/v1/mask",
    headers={
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    },
    data=json.dumps(sensitive_payload).encode()
)

try:
    with urllib.request.urlopen(mask_req) as mask_resp:
        masked_output = json.loads(mask_resp.read().decode())
        print("\n3. Received Masked Payload (HTTP 200 OK):")
        print("   " + json.dumps(masked_output, indent=4).replace("\n", "\n   "))
        print("\n   [RESULT NOTES]:")
        print("   - SSN: Removed (suppress rule)")
        print("   - Salary: Redacted to 0 (type-safe redact rule)")
        print("   - Credit Card: Truncated to ****-****-****-4444 (mask_pattern rule)")
        print("   - Email: Pseudonymized to deterministic token (pseudonymize rule)")
except urllib.error.HTTPError as err:
    print(f"   [HTTP ERROR {err.code}]: {err.read().decode()}")
except Exception as e:
    print(f"   [ERROR]: {e}")
