# Comprehensive Security Failure Tests & Network Observations (Phases 15 & 16)

## Status: OBSERVED (directly recorded across all experimental runs)

---

## 1. Complete Security Failure Matrix

| Test ID | System Under Test | Attack / Failure Case | Expected Result | Observed Result | Rejecting Component | Reason for Rejection |
|---|---|---|---|---|---|---|
| **SEC-01** | OpenLDAP | Wrong user password (`wrongpassword`) | Reject bind | `ldap_bind: Invalid credentials (49)` | OpenLDAP slapd | Password hash comparison failed in directory. |
| **SEC-02** | OpenLDAP | Nonexistent user (`charlie`) | Reject bind | `ldap_bind: Invalid credentials (49)` | OpenLDAP slapd | User entry not found in tree (returns error 49 to prevent enumeration). |
| **SEC-03** | Keycloak | UserInfo called without Authorization header | `HTTP 401` | `HTTP 401 Unauthorized` | Keycloak UserInfo filter | Missing Bearer token in request headers. |
| **SEC-04** | Keycloak | UserInfo called with forged token (`fake.token`) | `HTTP 401` | `HTTP 401 Unauthorized` | Keycloak UserInfo filter | Malformed token string. |
| **SEC-05** | Keycloak | Introspection called without client credentials | `HTTP 401` | `HTTP 401 Unauthorized` | Keycloak Introspect filter | Missing confidential client secret. |
| **SEC-06** | Keycloak | Introspection of fake/invalid token | `active: false` | `{"active": false}` (Status 200) | Keycloak Token Manager | Token ID not found in active session store. |
| **SEC-07** | PyJWT | Tampered JWT payload (added `admin` group) | `InvalidSignatureError` | `InvalidSignatureError` | PyJWT / OpenSSL | Asymmetric SHA-256 hash mismatch over altered payload. |
| **SEC-08** | PyJWT | Corrupted signature bytes | `InvalidSignatureError` | `InvalidSignatureError` | PyJWT / OpenSSL | Public key decryption of RSA signature failed. |
| **SEC-09** | PyJWT | Expired token (`exp` in past) | `ExpiredSignatureError` | `ExpiredSignatureError` | PyJWT Claim Validator | Token expiration timestamp `< current_time`. |
| **SEC-10** | PyJWT | Rogue Issuer (`iss = http://rogue-idp...`) | `InvalidIssuerError` | `InvalidIssuerError` | PyJWT Claim Validator | Issuer does not match configured trusted IdP URL. |
| **SEC-11** | PyJWT | Wrong Audience (`aud = payment-service`) | `InvalidAudienceError` | `InvalidAudienceError` | PyJWT Claim Validator | Token was minted for `account`, not the requested API. |
| **SEC-12** | Vault LDAP | Alice with wrong password | `HTTP 400` / Deny | `HTTP 400: ldap operation failed: failed to bind as user` | Vault LDAP auth engine | LDAP bind failed. |
| **SEC-13** | Vault JWT | Alice claiming `security-role` (Privilege Escalation) | `HTTP 400` / Deny | `HTTP 400: claim "groups" does not match bound claim` | Vault JWT auth engine | JWT `groups` claim contains `finance`, but role requires `security`. |

---

## 2. HTTP Wire Traffic Analysis (What Goes on the Wire)

### Direct LDAP Wire Traffic
- **Client $\rightarrow$ App**: HTTP `POST /login` with `{"username": "alice", "password": "..."}`. *(Raw password is on the wire!)*
- **App $\rightarrow$ LDAP**: TCP 389 LDAP Bind packet containing user DN + cleartext password.

### Keycloak OIDC / JWT Wire Traffic
- **Client $\rightarrow$ Keycloak**: HTTP `POST /protocol/openid-connect/token` with `client_id`, `client_secret`, `username`, `password`.
- **Keycloak $\rightarrow$ Client**: HTTP `200 OK` with JSON containing signed `access_token` (RS256 JWT) and `id_token`.
- **Client $\rightarrow$ Resource API**: HTTP `POST /data` with `Authorization: Bearer <jwt>`. *(User password is NEVER on the wire to resource servers!)*
- **Resource API $\rightarrow$ Keycloak**: HTTP `GET /protocol/openid-connect/certs` (performed once on startup to cache public keys).
