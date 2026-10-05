# Live Demonstration Script: Enterprise Authentication & Authorization Lab

**Duration**: 10–15 Minutes  
**Target Audience**: Project Advisor / Technical Reviewers

---

## Step 1: OpenLDAP Inspection & Direct Bind (3 Mins)

### SHOW:
Terminal window with OpenLDAP query.

### DO:
```bash
python 02-direct-ldap/ldap_auth_client.py alice alice123
python 02-direct-ldap/ldap_auth_client.py alice wrongpassword
```

### OBSERVE:
- Successful bind returns user attributes and discovered group `["finance"]`.
- `token_returned_by_ldap: null`.
- Failed bind returns error code `49 (invalidCredentials)`.

### EXPLAIN:
- LDAP is a directory database, not a token issuer.
- Authentication is connection-bound (Bind). No portable token is produced.
- Group discovery requires a separate reverse search on `ou=Groups`.

### DO NOT CLAIM:
- Do not claim that LDAP is obsolete; it remains the primary directory store in most large enterprises (e.g. Active Directory).

---

## Step 2: Keycloak Token Minting & Group Claims (4 Mins)

### SHOW:
Keycloak token response and decoded JWT payload.

### DO:
```bash
python 04-keycloak-tokens/obtain_and_inspect_tokens.py
python 04-keycloak-tokens/configure_group_mapper_and_compare.py
```

### OBSERVE:
- Default Keycloak JWT contains standard claims (`sub`, `iss`, `aud`, `exp`, `roles`) but **no groups**.
- After attaching the OIDC group membership mapper, the JWT payload contains `groups: ["finance"]`.

### EXPLAIN:
- Identity Providers issue self-contained, cryptographically signed Bearer JWTs.
- Token claims are fully customizable via protocol mappers.
- Tokens can be carried downstream across multiple microservices.

### DO NOT CLAIM:
- Do not claim that all JWTs contain groups by default.

---

## Step 3: Cryptographic JWT Verification & Security Failures (4 Mins)

### SHOW:
Live execution of the JWT verification test suite.

### DO:
```bash
python 07-jwt-verification/test_verification.py
```

### OBSERVE:
- Test 1 (Valid JWT): Verified RS256 signature using public key from Keycloak JWKS (`/certs`).
- Test 2 (Tampered Payload): Injecting `groups: ["admin"]` triggers `InvalidSignatureError`.
- Test 4 (Expired Token): Triggers `ExpiredSignatureError`.
- Test 6 (Wrong Audience): Triggers `InvalidAudienceError`.

### EXPLAIN:
- Decoding a JWT (`base64url_decode`) provides zero trust.
- True validation verifies the asymmetric RSA signature against the IdP's cached JWKS public key.
- Verification is stateless and sub-millisecond; no network call to the IdP is needed per request.

### DO NOT CLAIM:
- Do not claim that JWT validation protects against stolen tokens before expiration (requires token revocation/introspection if immediate revocation is required).

---

## Step 4: HashiCorp Vault: Real Enterprise Integration (4 Mins)

### SHOW:
Vault terminal demonstrating external JWT authentication and policy mapping.

### DO:
```bash
python 10-vault-jwt/setup_and_test_vault_jwt.py
```

### OBSERVE:
- Alice presents her Keycloak JWT to Vault $\rightarrow$ Vault verifies signature against Keycloak JWKS $\rightarrow$ Maps `groups: ["finance"]` to `finance-policy` $\rightarrow$ Issues internal Vault token.
- When Alice requests the unauthorized `security-role`, Vault rejects the request with `HTTP 400 (claim "groups" does not match bound claim)`.

### EXPLAIN:
- This is the blueprint for our 20-Credit Data Masking Framework:
  1. The enterprise IdP handles user authentication.
  2. Our service validates the JWT statelessly using JWKS.
  3. Our service maps the validated group/role claims to declarative masking policies.

### DO NOT CLAIM:
- Do not claim that Vault is our masking tool; Vault is the proven enterprise architectural reference.
