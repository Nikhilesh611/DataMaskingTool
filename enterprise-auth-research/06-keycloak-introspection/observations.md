# Keycloak Token Introspection Observations (Phase 6)

## Status: OBSERVED (directly tested against `/realms/lab-realm/protocol/openid-connect/token/introspect`)

---

## 1. RFC 7662 Introspection Mechanism
**[OBSERVED]** Token introspection allows a resource server / API service to query the IdP in real time to verify whether a presented token is currently valid and active.

---

## 2. Answers to Research Questions

### What does introspection return?
**[OBSERVED]**
- **If token is valid and active**: Returns `HTTP 200 OK` with `"active": true`, `client_id`, `sub`, `exp`, `iat`, `scope`, `groups`, and roles (`realm_access`).
- **If token is invalid, forged, or expired**: Returns `HTTP 200 OK` with only `{"active": false}`.

### What authorization & identity information does it expose?
**[OBSERVED]** It exposes the complete set of claims that were minted into the token, including `groups: ["finance"]`, `realm_access.roles`, and user subject identity.

### Who is allowed to call introspection?
**[OBSERVED]** Only **authenticated clients** (confidential clients presenting valid `client_id` + `client_secret` credentials). Unauthenticated requests are rejected with **`HTTP 401 Unauthorized`**.

---

## 3. Comparison: Local Signature Verification vs Token Introspection

| Dimension | Local JWKS Verification (Phase 7) | Central Token Introspection (Phase 6) |
|---|---|---|
| **Network Overhead** | **Zero per request** (keys cached locally) | **1 network roundtrip per API call** |
| **Instant Revocation Detection** | No (valid until `exp` timestamp) | **Yes** (IdP checks session revocation state live) |
| **IdP Availability Dependency** | Low (survives temporary IdP outages) | High (IdP must be online for every request) |
| **Client Credentials Required** | No (only needs public JWKS keys) | Yes (`client_secret` needed by API service) |
