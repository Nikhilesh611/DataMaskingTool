# JWT Signature Verification Observations (Phase 7)

## Status: OBSERVED (directly tested using Keycloak JWKS and PyJWT cryptographic verification)

---

## 1. Test Matrix Summary

| Test Case | Attack / Condition | Expected | Observed | Exception | What Failed |
|---|---|---|---|---|---|
| **1. Valid JWT** | Legitimate Keycloak token | PASS | **PASS** | None | Verified valid RSA-256 signature, issuer, audience, and expiration. |
| **2. Modified Payload** | Attacker altered `groups` to `["admin"]` | FAIL | **REJECTED** | `InvalidSignatureError` | RSA signature hash mismatch on modified payload string. |
| **3. Modified Signature** | Tampered signature bytes | FAIL | **REJECTED** | `InvalidSignatureError` | Cryptographic signature decryption failed. |
| **4. Expired Token** | `exp` timestamp in past | FAIL | **REJECTED** | `ExpiredSignatureError` | Token is past expiration time. |
| **5. Wrong Issuer** | Tampered `iss` claim | FAIL | **REJECTED** | `InvalidIssuerError` | Issuer does not match trusted Keycloak realm URL. |
| **6. Wrong Audience** | Token audience is not recipient service | FAIL | **REJECTED** | `InvalidAudienceError` | Token minted for different service (`account` vs `my-service`). |

---

## 2. Fundamental Distinction: "Decoding" vs "Validating" a JWT

### What is "Decoding a JWT"?
- **[OBSERVED]** Decoding is simply executing `base64url_decode()` on the header and payload strings.
- Anyone on the internet can forge any JSON payload (e.g. `{"user": "admin", "roles": ["superadmin"]}`), base64-encode it, and send it in an `Authorization` header.
- **NEVER trust a decoded JWT without validation.**

### What is "Validating a JWT"?
- **[OBSERVED]** Validating requires:
  1. Fetching the public verification key (`kid`) from the trusted IdP's JWKS endpoint (`/.well-known/jwks.json` or `/certs`).
  2. Performing cryptographic signature verification over `header_b64 + "." + payload_b64` using the RSA public key.
  3. Verifying that `iss` strictly matches the trusted IdP URL.
  4. Verifying that `aud` matches the target service's client ID.
  5. Verifying that `exp` is in the future (`exp > current_unix_time`).
  6. Verifying that `nbf` (not before) is in the past.

---

## 3. Architectural Implications
- **Stateless Verification**: The receiving API service only needs to fetch the IdP's JWKS public keys once and cache them. After that, the service can validate incoming tokens for thousands of requests **completely offline without making network calls to the IdP**.
