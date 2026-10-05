# Keycloak OIDC Discovery Observations (Phase 3A)

## Status: OBSERVED (directly fetched from `http://localhost:8081/realms/lab-realm/.well-known/openid-configuration`)

---

## Published Endpoints

| Endpoint | Published URL | Purpose in OIDC Spec |
|---|---|---|
| **Issuer (`iss`)** | `http://localhost:8081/realms/lab-realm` | Unique authority identifier for this realm |
| **Authorization** | `http://localhost:8081/realms/lab-realm/protocol/openid-connect/auth` | User browser login flow |
| **Token** | `http://localhost:8081/realms/lab-realm/protocol/openid-connect/token` | Exchange credentials/code for tokens |
| **UserInfo** | `http://localhost:8081/realms/lab-realm/protocol/openid-connect/userinfo` | Get user claims using Bearer access token |
| **JWKS / Certs** | `http://localhost:8081/realms/lab-realm/protocol/openid-connect/certs` | Public keys for JWT signature verification |
| **Introspection** | `http://localhost:8081/realms/lab-realm/protocol/openid-connect/token/introspect` | Query active status and metadata of a token |
| **Revocation** | `http://localhost:8081/realms/lab-realm/protocol/openid-connect/revoke` | Revoke a refresh or access token |
| **End Session** | `http://localhost:8081/realms/lab-realm/protocol/openid-connect/logout` | Single sign-out endpoint |

## Supported Scopes & Claims
- **Scopes**: `openid`, `profile`, `email`, `roles`, `address`, `phone`, `offline_access`, `microprofile-jwt`
- **Claims**: `aud`, `sub`, `iss`, `auth_time`, `name`, `given_name`, `family_name`, `preferred_username`, `email`, `acr`
- **[OBSERVED]**: Note that `groups` is **NOT** listed in default `claims_supported`!

---

## Architectural Meaning
- **[OBSERVED]**: The OIDC discovery endpoint (`/.well-known/openid-configuration`) allows applications and external services (like HashiCorp Vault) to dynamically auto-configure all auth endpoints using only the base Issuer URL (`iss`).
