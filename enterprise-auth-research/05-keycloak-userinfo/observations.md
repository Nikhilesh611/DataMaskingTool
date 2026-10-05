# Keycloak UserInfo Endpoint Observations (Phase 5)

## Status: OBSERVED (directly tested against `/realms/lab-realm/protocol/openid-connect/userinfo`)

---

## 1. UserInfo Response Structure
**[OBSERVED]** When called with `Authorization: Bearer <valid_access_token>`, the UserInfo endpoint returns:
```json
{
  "sub": "4e2dae28-abd5-49e5-a890-8a54eae8bb57",
  "email_verified": true,
  "name": "Alice User",
  "groups": [
    "finance"
  ],
  "preferred_username": "alice",
  "given_name": "Alice",
  "family_name": "User",
  "email": "alice@lab.local"
}
```

---

## 2. Answers to Research Questions

### What information does UserInfo return?
**[OBSERVED]** It returns user profile claims: `sub`, `preferred_username`, `name`, `given_name`, `family_name`, `email`, `email_verified`, and any custom mapped claims (e.g. `groups`).

### Is group information returned?
**[OBSERVED]** **YES**, because our group mapper was configured with `"userinfo.token.claim": "true"`. If that setting is disabled in the mapper, groups are excluded from UserInfo.

### Is role information returned?
**[OBSERVED]** **NO.** UserInfo returns identity/profile attributes, not access control structures (`realm_access` and `resource_access` remain in the Access Token only).

### What information is available in UserInfo that is not in the token?
**[OBSERVED]** In lightweight token architectures, the access token can be kept minimal (containing only `sub`, `iss`, `aud`, `exp`), and applications call UserInfo on demand to fetch full profile metadata (reducing JWT payload size on the wire).

### What authentication is required to call UserInfo?
**[OBSERVED]** Calling without an `Authorization: Bearer` header or with an invalid/expired token returns **`HTTP 401 Unauthorized`**.
