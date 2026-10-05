"""JWT Signature and Claim Verification Test Suite.

Demonstrates the critical distinction between:
- "Decoding a JWT" (trivial base64 parsing, zero trust)
- "Validating a JWT" (cryptographic signature + issuer + audience + expiry checks)
"""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
import urllib.request
import jwt
from jwt import PyJWKClient, ExpiredSignatureError, InvalidSignatureError, InvalidIssuerError, InvalidAudienceError, DecodeError

JWKS_URL = "http://localhost:8081/realms/lab-realm/protocol/openid-connect/certs"
TOKEN_URL = "http://localhost:8081/realms/lab-realm/protocol/openid-connect/token"
CLIENT_ID = "lab-client"
CLIENT_SECRET = "lab-client-secret-12345"
EXPECTED_ISSUER = "http://localhost:8081/realms/lab-realm"
EXPECTED_AUDIENCE = "account"


def get_token(username="alice", password="alice123") -> str:
    data = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid profile email",
    }).encode("utf-8")
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def main():
    print("Fetching valid access token from Keycloak...")
    token = get_token("alice", "alice123")
    
    # Initialize JWK client to fetch public signing key from Keycloak
    jwks_client = PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    print(f"Signing Key ID (kid) retrieved from JWKS: {signing_key.key_id}")
    print(f"Algorithm: {signing_key.algorithm_name}")

    results = []

    # ── Test 1: Valid JWT ─────────────────────────────────────────────────────
    print("\n--- Test 1: Valid JWT ---")
    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=EXPECTED_ISSUER,
            audience=EXPECTED_AUDIENCE,
        )
        print("RESULT: SUCCESS")
        print(f"Verified Subject: {payload.get('sub')}")
        print(f"Verified Username: {payload.get('preferred_username')}")
        print(f"Verified Groups: {payload.get('groups')}")
        results.append({"test": "1. Valid JWT", "expected": "PASS", "observed": "PASS", "detail": "Cryptographic signature and all claims valid."})
    except Exception as e:
        print(f"FAILED: {e}")
        results.append({"test": "1. Valid JWT", "expected": "PASS", "observed": "FAIL", "detail": str(e)})

    # ── Test 2: Modified Payload (Attacker attempts privilege escalation) ───────
    print("\n--- Test 2: Modified Payload (Tampered Claims) ---")
    parts = token.split(".")
    raw_header, raw_payload, raw_signature = parts[0], parts[1], parts[2]
    
    # Attacker alters payload to add "admin" group and changes username to "admin"
    rem = len(raw_payload) % 4
    if rem > 0:
        raw_payload += "=" * (4 - rem)
    tampered_json = json.loads(base64.urlsafe_b64decode(raw_payload.encode()).decode())
    tampered_json["preferred_username"] = "admin"
    tampered_json["groups"] = ["finance", "security", "admin"]
    
    tampered_payload_b64 = b64url_encode(json.dumps(tampered_json).encode())
    tampered_token = f"{raw_header}.{tampered_payload_b64}.{raw_signature}"
    
    try:
        jwt.decode(
            tampered_token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=EXPECTED_ISSUER,
            audience=EXPECTED_AUDIENCE,
        )
        results.append({"test": "2. Modified Payload", "expected": "FAIL (InvalidSignatureError)", "observed": "PASS (VULNERABILITY!)", "detail": "Accepted tampered payload!"})
    except InvalidSignatureError as e:
        print("RESULT: REJECTED AS EXPECTED (InvalidSignatureError)")
        print("Detail: Asymmetric signature mismatch — payload modification detected!")
        results.append({"test": "2. Modified Payload", "expected": "FAIL (InvalidSignatureError)", "observed": "FAIL (InvalidSignatureError)", "detail": str(e)})

    # ── Test 3: Modified Signature Bytes ──────────────────────────────────────
    print("\n--- Test 3: Modified Signature Bytes ---")
    bad_signature = raw_signature[:-4] + "AAAA"
    bad_sig_token = f"{raw_header}.{raw_payload}.{bad_signature}"
    try:
        jwt.decode(
            bad_sig_token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=EXPECTED_ISSUER,
            audience=EXPECTED_AUDIENCE,
        )
        results.append({"test": "3. Modified Signature", "expected": "FAIL (InvalidSignatureError)", "observed": "PASS", "detail": "Accepted bad signature!"})
    except InvalidSignatureError as e:
        print("RESULT: REJECTED AS EXPECTED (InvalidSignatureError)")
        results.append({"test": "3. Modified Signature", "expected": "FAIL (InvalidSignatureError)", "observed": "FAIL (InvalidSignatureError)", "detail": str(e)})

    # ── Test 4: Expired Token ─────────────────────────────────────────────────
    print("\n--- Test 4: Expired Token ---")
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    dummy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    expired_token = jwt.encode(
        {"sub": "alice", "exp": int(time.time()) - 3600, "iss": EXPECTED_ISSUER, "aud": EXPECTED_AUDIENCE},
        dummy_key,
        algorithm="RS256"
    )
    try:
        jwt.decode(
            expired_token,
            dummy_key.public_key(),
            algorithms=["RS256"],
            issuer=EXPECTED_ISSUER,
            audience=EXPECTED_AUDIENCE,
        )
        results.append({"test": "4. Expired Token", "expected": "FAIL (ExpiredSignatureError)", "observed": "PASS", "detail": "Accepted expired token!"})
    except ExpiredSignatureError as e:
        print("RESULT: REJECTED AS EXPECTED (ExpiredSignatureError)")
        print(f"Detail: {e}")
        results.append({"test": "4. Expired Token", "expected": "FAIL (ExpiredSignatureError)", "observed": "FAIL (ExpiredSignatureError)", "detail": str(e)})

    # ── Test 5: Wrong Issuer ──────────────────────────────────────────────────
    print("\n--- Test 5: Wrong Issuer ---")
    try:
        jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer="http://rogue-idp.attacker.com/realms/fake",
            audience=EXPECTED_AUDIENCE,
        )
        results.append({"test": "5. Wrong Issuer", "expected": "FAIL (InvalidIssuerError)", "observed": "PASS", "detail": "Accepted wrong issuer!"})
    except InvalidIssuerError as e:
        print("RESULT: REJECTED AS EXPECTED (InvalidIssuerError)")
        print(f"Detail: {e}")
        results.append({"test": "5. Wrong Issuer", "expected": "FAIL (InvalidIssuerError)", "observed": "FAIL (InvalidIssuerError)", "detail": str(e)})

    # ── Test 6: Wrong Audience ────────────────────────────────────────────────
    print("\n--- Test 6: Wrong Audience ---")
    try:
        jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=EXPECTED_ISSUER,
            audience="payment-service-api",  # Token is only minted for 'account'
        )
        results.append({"test": "6. Wrong Audience", "expected": "FAIL (InvalidAudienceError)", "observed": "PASS", "detail": "Accepted wrong audience!"})
    except InvalidAudienceError as e:
        print("RESULT: REJECTED AS EXPECTED (InvalidAudienceError)")
        print(f"Detail: {e}")
        results.append({"test": "6. Wrong Audience", "expected": "FAIL (InvalidAudienceError)", "observed": "FAIL (InvalidAudienceError)", "detail": str(e)})

    # Save summary
    with open("07-jwt-verification/verification_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nVerification test suite completed. Results saved to 07-jwt-verification/verification_results.json")


if __name__ == "__main__":
    main()
