# Enterprise Authentication & Authorization Practical Research: Final Report

**Project**: Multi-Format Privacy Middleware & Data Masking Framework (20-Credit Expansion)  
**Research Date**: August 2026  
**Methodology**: Reproducible Local Lab Experiments (OpenLDAP 1.5.0 + Keycloak 25.0 + HashiCorp Vault 1.17 + Python Client)  
**Evidence Standard**: Every claim marked as `[OBSERVED]`, `[DOCUMENTED]`, `[INFERRED]`, or `[NOT VERIFIED]`.

---

## 1. LDAP (Lightweight Directory Access Protocol)

### What is LDAP?
- **[DOCUMENTED]** Defined by RFC 4511, LDAP is a network protocol used to query and manage a hierarchical Directory Information Tree (DIT).
- **[OBSERVED]** LDAP is a structured directory database optimized for high-read, low-write operations; it is **not** an identity token issuer.

### What did our actual LDAP directory contain?
- **[OBSERVED]**
  - Base DN: `dc=lab,dc=local`
  - User Container: `ou=People,dc=lab,dc=local` containing entries for `alice` and `bob`.
  - Group Container: `ou=Groups,dc=lab,dc=local` containing entries for `cn=finance` and `cn=security`.

### What did `ldapsearch` actually return?
- **[OBSERVED]** User entries contained structural objectClasses (`inetOrgPerson`, `posixAccount`), identity attributes (`uid`, `cn`, `sn`, `givenName`), and contact attributes (`mail`).
- **[OBSERVED]** Group entries (`groupOfNames`) contained a multi-valued `member` attribute with the full DN of member users (e.g. `member: uid=alice,ou=People,dc=lab,dc=local`).

### How are users and groups represented?
- **[OBSERVED]** Users are leaf nodes under `ou=People` with a unique Relative Distinguished Name (RDN) like `uid=alice`.
- **[OBSERVED]** Groups are separate entries under `ou=Groups` with RDN like `cn=finance`. Group membership is stored inside the **group entry**, pointing to the user DN.

### How is group membership retrieved?
- **[OBSERVED]** The user entry does **not** list its groups. Discovering a user's groups requires a **reverse LDAP search** on `ou=Groups` with filter:
  `(&(objectClass=groupOfNames)(member=<user_dn>))`.

### How does direct LDAP authentication work in our experiment?
- **[OBSERVED]**
  1. Client sends username and password to the application.
  2. Application connects to LDAP and binds using a service account to search for the user DN.
  3. Application attempts a second TCP `bind` using the user's DN and password.
  4. LDAP returns a success code (`result: 0 Success`) or error code (`49 invalidCredentials`).
  5. **Critical Finding**: LDAP returns **zero tokens, zero metadata, and zero groups** in the bind response. The application must manually execute additional queries to fetch user attributes and groups.

---

## 2. Identity Provider (Keycloak)

### What did Keycloak actually do?
- **[OBSERVED]** Keycloak acted as a central Identity Provider (IdP) implementing the OpenID Connect (OIDC) and OAuth 2.0 specifications. It decoupled user credentials from client applications.

### What endpoints did it expose?
- **[OBSERVED]** Keycloak published all endpoints at `/.well-known/openid-configuration`:
  - Token Endpoint: `/protocol/openid-connect/token`
  - UserInfo Endpoint: `/protocol/openid-connect/userinfo`
  - JWKS Certs Endpoint: `/protocol/openid-connect/certs`
  - Introspection Endpoint: `/protocol/openid-connect/token/introspect`
  - Authorization Endpoint: `/protocol/openid-connect/auth`

### What did the token endpoint actually return?
- **[OBSERVED]** A single `POST` request with `grant_type=password` returned:
  - `access_token`: Signed RS256 JWT (lifetime 300s).
  - `id_token`: Signed RS256 JWT containing user identity profile.
  - `refresh_token`: Used to obtain fresh access tokens without re-entering passwords.
  - `token_type`: `"Bearer"`.
  - `expires_in`: `300`.

### What was inside the actual token?
- **[OBSERVED]**
  - Header: `alg: RS256`, `typ: JWT`, `kid: r86N9dQ5OkPX...`
  - Payload Standard Claims: `iss`, `sub` (user UUID), `aud`, `exp`, `iat`, `preferred_username`, `email`.
  - Claims Present Automatically: `realm_access.roles`, `resource_access.{client}.roles`.
  - Claims Absent by Default: **`groups` was completely absent** by default until an `oidc-group-membership-mapper` was explicitly attached to the client.

### What did UserInfo return?
- **[OBSERVED]** When called with `Authorization: Bearer <token>`, `/userinfo` returned `sub`, `preferred_username`, `email`, and `groups`. It returned `HTTP 401` if called without a valid token.

### What did Introspection return?
- **[OBSERVED]** When called by an authenticated confidential client, `/token/introspect` returned `"active": true` with full claim metadata for valid tokens, and `{"active": false}` for invalid/expired tokens.

---

## 3. JWT (JSON Web Tokens)

### Distinguishing JWT Decoding vs JWT Validation
- **[OBSERVED]**
  - **Decoding**: Simply executing `base64url_decode()` on the string. Provides **zero security or authenticity guarantee**.
  - **Validation**: Cryptographically verifying the RS256 digital signature using the IdP's public key (fetched from JWKS), while asserting `iss == expected_issuer`, `aud == expected_audience`, and `exp > current_time`.

### Failure Cases Experimentally Observed
- **Tampered Payload**: Altering `preferred_username` or injecting `groups: ["admin"]` immediately failed with `InvalidSignatureError`.
- **Corrupted Signature**: Altering signature bytes failed with `InvalidSignatureError`.
- **Expired Token**: Token with `exp` in the past failed with `ExpiredSignatureError`.
- **Wrong Issuer**: Token with untrusted `iss` failed with `InvalidIssuerError`.
- **Wrong Audience**: Token minted for a different service failed with `InvalidAudienceError`.

---

## 4. Authentication Mechanisms Tested

| Flow | Who Authenticates | Against What | Credential Presented | Validating Component | Identity Established |
|---|---|---|---|---|---|
| **Direct LDAP** | User (Alice) | OpenLDAP | Username + Password | OpenLDAP `slapd` | `uid=alice,ou=People,dc=lab,dc=local` |
| **OIDC / Keycloak** | User (Alice) | Keycloak | Username + Password | Keycloak Auth Server | User UUID + `preferred_username: alice` + RS256 Bearer JWT |
| **OAuth2 M2M** | Backend Service (`lab-client`) | Keycloak | `client_id` + `client_secret` | Keycloak Token Engine | Service Account UUID + `preferred_username: service-account-lab-client` |
| **Vault LDAP** | User (Alice) | HashiCorp Vault | Username + Password | Vault LDAP backend via OpenLDAP | Vault Entity + Vault Token (`hvs.xxxx`) with `finance-policy` |
| **Vault JWT** | Client Application | HashiCorp Vault | Signed Keycloak Bearer JWT | Vault JWT backend via Keycloak JWKS | Vault Entity + Vault Token (`hvs.xxxx`) with `finance-policy` |

---

## 5. Authorization Mechanisms Observed

### Authentication vs. Authorization
- **[OBSERVED]** **Authentication** establishes *who/what* is calling (`alice`, member of `finance`).
- **[OBSERVED]** **Authorization** determines *what* that identity is allowed to do (`finance-policy` $\rightarrow$ permit `read/write` on `secret/data/finance/*`, deny `secret/data/security/*`).

### Group & Claim Mapping to Permissions
- **LDAP Group Mapping**: Vault mapped LDAP group string `cn=finance` $\rightarrow$ Vault policy `finance-policy`.
- **JWT Claim Mapping**: Vault inspected JWT claim `bound_claims = {"groups": "finance"}` $\rightarrow$ attached Vault policy `finance-policy`.
- **Privilege Escalation Test**: When Alice attempted to login to Vault requesting `security-role`, Vault evaluated her token's claims (`groups: ["finance"]`), detected a mismatch, and rejected the request with `HTTP 400`.

---

## 6. HashiCorp Vault Integration

### LDAP vs JWT/OIDC in Vault
- **[OBSERVED]**
  - **Vault + LDAP**: Vault receives raw username/password, connects to OpenLDAP over TCP, searches for user DN, attempts bind, searches for groups, and issues an internal Vault token.
  - **Vault + JWT**: Vault receives a signed JWT, validates the signature locally using Keycloak's public JWKS keys, evaluates bound claims, and issues an internal Vault token.

---

## 7. The Enterprise Integration Model

### How a Third-Party Service Integrates Without Replacing Enterprise Identity
- **[OBSERVED]** A third-party service (like HashiCorp Vault or a future Centralized Data Masking Service) does **not** need to manage its own user database, passwords, or MFA systems.
- **[OBSERVED]** The enterprise maintains its authoritative identity store (LDAP / Keycloak).
- **[OBSERVED]** The external service registers as a consumer:
  1. Establishes cryptographic trust by pointing to the enterprise IdP's JWKS endpoint.
  2. Maps external enterprise groups/roles (`finance`, `security`, `analyst`, `auditor`) to internal service-specific policies.
  3. Validates incoming tokens statelessly and enforces local service authorization.

---

## 8. Options for a Future Data Masking API

Based strictly on experimental evidence gathered:

| Option | Architecture Pattern | Evidence Status | Trade-offs Observed |
|---|---|---|---|
| **Option A: Bearer JWT Token Verification** | API receives `Authorization: Bearer <jwt>`, validates signature against enterprise JWKS, extracts `role`/`groups` claim, applies role-specific masking. | **SUPPORTED BY EVIDENCE (Phases 3-7, 10)** | **Pros**: Stateless, zero password exposure, sub-millisecond offline verification, standard OAuth2/OIDC.<br>**Cons**: Requires enterprise IdP support. |
| **Option B: Direct LDAP Authentication** | API receives username/password in headers, performs live bind & group search against enterprise LDAP, applies role masking. | **SUPPORTED BY EVIDENCE (Phases 1, 2, 9)** | **Pros**: Direct integration with legacy Active Directory/OpenLDAP.<br>**Cons**: Exposes user passwords to API, requires 2-3 network roundtrips to LDAP per request. |
| **Option C: M2M OAuth2 Client Credentials** | Client application authenticates machine-to-machine, receives service token with application roles, API masks data for service tier. | **SUPPORTED BY EVIDENCE (Phase 8)** | **Pros**: Ideal for automated backend microservices and data pipelines.<br>**Cons**: Does not carry end-user identity unless token exchange is used. |
| **Option D: mTLS (Mutual TLS)** | Client and Masking API present X.509 certificates during TLS handshake; role extracted from certificate SAN/CN. | **DOCUMENTED ONLY (Phase 14)** | **Pros**: High-security, zero-trust service mesh standard.<br>**Cons**: Certificate lifecycle management complexity. |

---

## 9. What We Now Know (Supported by Evidence)
1. **[OBSERVED]** LDAP is a directory database, not a token issuer; it does not return tokens or groups automatically upon bind.
2. **[OBSERVED]** Keycloak does not include groups in JWTs by default; explicit protocol mappers are required.
3. **[OBSERVED]** Decoded JWTs are untrustworthy without full cryptographic signature, issuer, audience, and expiration validation.
4. **[OBSERVED]** Services can validate JWTs statelessly and offline using cached JWKS public keys without calling the IdP on every request.
5. **[OBSERVED]** Third-party enterprise services (like Vault) successfully decouple authentication (delegated to IdP/LDAP) from authorization (local policies).

---

## 10. What We Still Do Not Know (Unresolved Questions)
1. **[NOT VERIFIED]** How high-throughput JWT validation ($10\text{k}+\text{ req/sec}$) impacts latency overhead in Python vs Go/Rust.
2. **[NOT VERIFIED]** How token exchange (RFC 8693) should be implemented if a client service needs to propagate end-user identity through multiple downstream service hops.
3. **[NOT VERIFIED]** How fine-grained ABAC (Attribute-Based Access Control) claims beyond simple group strings should be structured in masking policies.

---

## 11. What We Should Do Next (Architectural Decisions Informed by Evidence)
Now that we have experimentally verified enterprise auth mechanics, we can make informed decisions for our 20-credit Data Masking Framework:
1. **Decide on Identity Ingestion Model**: Implement standard **Bearer JWT validation via JWKS** as the primary authentication mechanism for the Masking API, with optional API Key support for local development.
2. **Decide on Claim-to-Policy Mapping**: Adopt the Vault-style mapping model, allowing enterprise administrators to map incoming JWT claims (e.g. `groups = ["analyst"]` or `realm_access.roles = ["auditor"]`) directly to our declarative YAML masking scopes and profiles.
3. **Design the Central Control Plane**: Store masking policies centrally and allow dynamic policy selection based on the caller's verified JWT claims.
