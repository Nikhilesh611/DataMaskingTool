# Keycloak Token & Claim Observations (Phases 3B, 3C, 4)

## Status: OBSERVED (directly tested with Keycloak 25.0 against `lab-realm`)

---

## 1. Token Endpoint Response Structure
**[OBSERVED]** A single `POST /protocol/openid-connect/token` call with `grant_type=password` returns:
```json
{
  "access_token": "[JWT RS256]",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "refresh_token": "[JWT RS256]",
  "token_type": "Bearer",
  "id_token": "[JWT RS256]",
  "not-before-policy": 0,
  "session_state": "5bc0269b-ae8d-4d0a-b3ac-f6216397187f",
  "scope": "openid profile email"
}
```

---

## 2. JWT Structure Analysis

### Header
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "r86N9dQ5OkPX_CiSmhyLAAgh97oluY6jSRlzLGF24kY"
}
```
- **[OBSERVED]**: Algorithm is `RS256` (Asymmetric RSA SHA-256).
- **[OBSERVED]**: `kid` (Key ID) points directly to the matching public key published at the JWKS certs endpoint.

### Payload Standard Claims
- `iss`: `http://localhost:8081/realms/lab-realm` (Issuer authority)
- `sub`: `4e2dae28-abd5-49e5-a890-8a54eae8bb57` (User unique internal UUID)
- `aud`: `account` (Audience)
- `exp`: Expiration UNIX timestamp (300 seconds / 5 mins lifetime)
- `iat`: Issued-at UNIX timestamp
- `preferred_username`: `alice` (Human-readable username)
- `email`: `alice@lab.local`

---

## 3. Answers to Core Questions on Groups & Roles

### Does Keycloak automatically put groups in the token?
**[OBSERVED]** **NO.** In default Keycloak configuration, even if a user is assigned to a group (e.g. Alice in `finance`), the `groups` claim is completely omitted from both the Access Token and the ID Token.

### How are groups added?
**[OBSERVED]** Groups only appear when an administrator explicitly configures an `oidc-group-membership-mapper` protocol mapper on the client or client scope. Once added, `groups: ["finance"]` is injected into the JWT payload.

### Are groups and roles different in Keycloak?
**[OBSERVED]** **YES.**
- **Roles**: Built into Keycloak's core security model. They appear automatically under `realm_access.roles` (realm-wide) and `resource_access.{client}.roles` (client-specific).
- **Groups**: Organizational containers used to group users. They do not appear in tokens unless mapped to a custom claim via protocol mappers.

### Where are they represented?
| Identity Dimension | Default Keycloak Location | With Group Mapper Location |
|---|---|---|
| Username | `preferred_username` | `preferred_username` |
| Unique User ID | `sub` | `sub` |
| Realm Roles | `realm_access.roles` | `realm_access.roles` |
| Client Roles | `resource_access.{clientId}.roles` | `resource_access.{clientId}.roles` |
| Group Membership | **ABSENT** | `groups: ["finance"]` |
