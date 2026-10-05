# Phase 0 — Official Documentation Sources

## Status: DOCUMENTED (collected from official sources, not yet experimentally verified)

---

## 1. OpenLDAP

### Source: OpenLDAP Software Administrator's Guide
- **URL**: https://www.openldap.org/doc/admin26/
- **Covers**: Directory structure, schema, users, groups, access control, authentication

### Key Claims to Verify Experimentally

| Claim | Source | Needs Verification |
|---|---|---|
| LDAP entries are organized in a hierarchical tree (DIT) | Admin Guide Ch.5 | Yes — inspect actual tree structure |
| Users are typically stored under `ou=People` using `inetOrgPerson` objectClass | Admin Guide | Yes — inspect actual user entry attributes |
| Groups use `groupOfNames` (with `member` DN attribute) or `posixGroup` (with `memberUid`) | Admin Guide | Yes — inspect actual group entry |
| The **Bind** operation is how a client authenticates | RFC 4511, Admin Guide | Yes — test bind success/failure |
| Simple Bind sends DN + password in cleartext (needs TLS) | Admin Guide | Yes — observe actual bind behavior |
| LDAP does NOT return a "token" after authentication | RFC 4511 | Yes — observe actual bind response |
| `ldapsearch` returns matching entries with all requested attributes | man ldapsearch | Yes — capture actual output |
| Failed bind returns error code 49 (invalidCredentials) | RFC 4511 | Yes — test with wrong password |

### ldapsearch Command Reference
- **URL**: `man ldapsearch` / https://www.openldap.org/software/man.cgi?query=ldapsearch
- **Key flags**: `-x` (simple auth), `-H` (URI), `-D` (bind DN), `-W` (prompt password), `-b` (search base), `-s` (scope)

---

## 2. Keycloak (Identity Provider / OIDC)

### Source: Keycloak Official Documentation
- **URL**: https://www.keycloak.org/documentation
- **Server Admin Guide**: https://www.keycloak.org/docs/latest/server_admin/
- **Securing Apps Guide**: https://www.keycloak.org/docs/latest/securing_apps/

### Key Endpoints (per OIDC spec)
| Endpoint | Path | Purpose |
|---|---|---|
| Discovery | `/realms/{realm}/.well-known/openid-configuration` | Lists all endpoints and supported features |
| Token | `/realms/{realm}/protocol/openid-connect/token` | Issues access tokens, ID tokens, refresh tokens |
| UserInfo | `/realms/{realm}/protocol/openid-connect/userinfo` | Returns claims about authenticated user |
| JWKS | `/realms/{realm}/protocol/openid-connect/certs` | Public keys for JWT signature verification |
| Introspection | `/realms/{realm}/protocol/openid-connect/token/introspect` | Validates token and returns active/inactive + claims |
| Authorization | `/realms/{realm}/protocol/openid-connect/auth` | Redirects user for interactive login |

### Key Claims to Verify Experimentally

| Claim | Source | Needs Verification |
|---|---|---|
| Realm roles appear under `realm_access.roles` in access token | Keycloak docs | Yes — decode actual token |
| Client roles appear under `resource_access.{clientId}.roles` | Keycloak docs | Yes — decode actual token |
| Groups are NOT in tokens by default — require a Group Membership mapper | Keycloak docs | Yes — compare tokens before/after mapper config |
| Client Credentials grant (`grant_type=client_credentials`) issues token without human user | Keycloak docs | Yes — test machine-to-machine flow |
| Service account tokens have a `clientId` as subject, not a user ID | Keycloak docs | Yes — compare with user token |
| UserInfo endpoint requires a valid Bearer access token | OIDC spec | Yes — test with/without token |
| Token introspection requires client authentication | Keycloak docs | Yes — test introspection call |

---

## 3. HashiCorp Vault

### Source: Vault Official Documentation
- **URL**: https://developer.hashicorp.com/vault/docs
- **Auth Concepts**: https://developer.hashicorp.com/vault/docs/concepts/auth
- **LDAP Auth**: https://developer.hashicorp.com/vault/docs/auth/ldap
- **JWT/OIDC Auth**: https://developer.hashicorp.com/vault/docs/auth/jwt
- **Policies**: https://developer.hashicorp.com/vault/docs/concepts/policies
- **Identity**: https://developer.hashicorp.com/vault/docs/concepts/identity

### Key Claims to Verify Experimentally

| Claim | Source | Needs Verification |
|---|---|---|
| Vault uses "deny by default" — no access without explicit policy | Policies doc | Yes — test with no policy |
| LDAP auth method: Vault connects to LDAP server, performs bind on behalf of user | LDAP auth doc | Yes — configure and test |
| LDAP auth method: Vault discovers group membership via LDAP search | LDAP auth doc | Yes — observe group mapping |
| LDAP groups are mapped to Vault policies via group names | LDAP auth doc | Yes — configure mapping, test access |
| JWT auth method: Vault validates JWT signature using JWKS or static key | JWT auth doc | Yes — configure against Keycloak |
| JWT auth method: Vault checks issuer (`iss`), audience (`aud`), expiry (`exp`) | JWT auth doc | Yes — test with valid/invalid tokens |
| JWT claims can be mapped to Vault identity metadata and policies | JWT auth doc | Yes — configure claim-to-policy mapping |
| After successful auth, Vault returns its own Vault token (not the original credential) | Auth concepts doc | Yes — inspect actual login response |
| Vault creates Entity + Alias for each authenticated identity | Identity doc | Yes — inspect identity store after login |
| Multiple auth methods for same person can link to single Entity | Identity doc | Yes — test LDAP + JWT for same user |

---

## 4. Cross-Cutting Questions for Experimental Verification

These are NOT answered by documentation alone:

1. Does LDAP itself return a token after successful bind? (Hypothesis: No)
2. Does Keycloak automatically include group membership in access tokens? (Hypothesis: No, requires mapper)
3. Is a decoded JWT trustworthy without signature verification? (Hypothesis: No)
4. Does Vault create its own users, or rely entirely on external identity? (Hypothesis: External only)
5. Can the same user authenticate via both LDAP and JWT/OIDC to Vault? (Hypothesis: Yes, linked via Entity)
6. What exactly crosses the boundary between enterprise identity system and Vault? (Needs observation)
