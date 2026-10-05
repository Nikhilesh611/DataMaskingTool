# Enterprise Authentication & Authorization: Executive Summary for Project Advisor

**Objective**: Experimentally research and validate how real enterprise authentication and authorization systems (OpenLDAP, Keycloak, HashiCorp Vault) operate, to design a robust, enterprise-grade integration model for our 20-Credit Centralized Data Masking Framework.

---

## 1. Experimental Lab Setup
We deployed and tested a fully reproducible local lab:
- **OpenLDAP 1.5.0**: Users `alice` (in `finance`) and `bob` (in `security`).
- **Keycloak 25.0**: OIDC IdP with realm `lab-realm`, protocol mappers, and OAuth2 client credentials.
- **HashiCorp Vault 1.17**: Configured with both LDAP and JWT/OIDC authentication engines.
- **Python Test Harness**: Live LDAP queries, JWT verification against JWKS, and security failure test suite.

---

## 2. Key Findings & Observed Evidence

### 1. LDAP Mechanics
- **[OBSERVED]** LDAP is a directory database, not a token issuer.
- **[OBSERVED]** A successful LDAP `bind` returns only a connection status (`result: 0 Success`); it returns **no tokens, no metadata, and no groups**.
- **[OBSERVED]** Discovering user groups requires a secondary reverse search query on `ou=Groups`.

### 2. Identity Provider (Keycloak) & Tokens
- **[OBSERVED]** Keycloak issues signed RS256 Bearer JWTs containing identity claims (`sub`, `iss`, `aud`, `exp`).
- **[OBSERVED]** Groups are **NOT** in the token by default; they require an explicit protocol mapper.
- **[OBSERVED]** Machine-to-machine services authenticate without humans via OAuth2 Client Credentials (`grant_type=client_credentials`), receiving a service account token.

### 3. JWT Decoding vs. Validation
- **[OBSERVED]** "Decoding" is simple base64 parsing (zero security).
- **[OBSERVED]** "Validating" requires cryptographic RS256 signature verification against public keys from the IdP's JWKS endpoint (`/certs`), plus strict checks on `iss`, `aud`, and `exp`.
- **[OBSERVED]** Tampered payloads, forged signatures, expired tokens, rogue issuers, and mismatched audiences were all reliably rejected.

### 4. HashiCorp Vault: The Enterprise Integration Blueprint
- **[OBSERVED]** Vault demonstrates the exact pattern for third-party enterprise integration:
  - **Decoupled Auth**: Vault does not store user passwords; it delegates authentication to OpenLDAP or Keycloak.
  - **Claim Mapping**: Vault maps external LDAP groups (`finance`) or JWT claims (`groups: ["finance"]`) to internal Vault ACL policies (`finance-policy`).
  - **Policy Enforcement**: Vault authorizes access locally based on the attached policy.
  - **Privilege Escalation Prevention**: When Alice presented her valid JWT requesting the unauthorized `security-role`, Vault verified the signature but rejected the login due to a claim mismatch (`HTTP 400`).

---

## 3. How This Research Informs Our 20-Credit Data Masking Architecture

| Enterprise Auth Lesson | Application to Data Masking Framework |
|---|---|
| **Delegated Authentication** | The Masking Service does not manage user credentials. It validates incoming Bearer JWTs using the enterprise IdP's JWKS endpoint. |
| **Stateless Verification** | The Masking Service caches the IdP's public keys and validates tokens locally in sub-milliseconds without network roundtrips to the IdP. |
| **Claim-to-Policy Mapping** | The Masking Service maps verified JWT claims (e.g. `groups = ["analyst"]`) directly to declarative YAML masking scopes and profiles. |
| **M2M Support** | Backend pipelines calling the Masking API authenticate via standard OAuth2 Client Credentials. |
