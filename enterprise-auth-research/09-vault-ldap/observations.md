# HashiCorp Vault + LDAP Integration Observations (Phase 9)

## Status: OBSERVED (directly tested with HashiCorp Vault 1.17 against OpenLDAP 1.5.0)

---

## 1. Vault LDAP Configuration & Mechanics

### How is LDAP configured in Vault?
**[OBSERVED]** Vault's `auth/ldap` engine is configured via `POST /v1/auth/ldap/config` with:
- `url`: LDAP server endpoint (`ldap://openldap:389`)
- `userdn`: User search base (`ou=People,dc=lab,dc=local`)
- `userattr`: Username attribute in user entries (`uid`)
- `groupdn`: Group search base (`ou=Groups,dc=lab,dc=local`)
- `groupfilter`: Group membership filter (`(&(objectClass=groupOfNames)(member={{.UserDN}}))`)
- `groupattr`: Attribute containing group name (`cn`)
- `binddn` / `bindpass`: Admin/service credentials for initial search.

### How does Vault determine group membership?
**[OBSERVED]** 
1. Client calls `POST /v1/auth/ldap/login/alice` with `{"password": "alice123"}`.
2. Vault uses its service bind to find Alice's user entry $\rightarrow$ discovers `userDN = uid=alice,ou=People,dc=lab,dc=local`.
3. Vault attempts a bind using Alice's userDN and password to verify credentials.
4. If bind succeeds, Vault executes `groupfilter` on `groupdn` $\rightarrow$ discovers group `cn=finance`.
5. Vault looks up internal mappings for group `finance` $\rightarrow$ finds `policies = ["finance-policy"]`.

---

## 2. Answers to Research Questions

### What happens when Alice logs in?
**[OBSERVED]**
- Vault authenticates Alice against OpenLDAP.
- Discovers Alice belongs to `finance`.
- Assigns Vault policies: `['default', 'finance-policy']`.
- Creates an internal Vault **Entity** and **Entity Alias** linking Alice's LDAP identity.
- Issues a new **Vault Client Token** (`hvs.xxxx`).

### What happens when Bob logs in?
**[OBSERVED]**
- Discovers Bob belongs to `security`.
- Assigns Vault policies: `['default', 'security-policy']`.
- Issues a separate Vault Client Token with `security-policy` attached.

### What does the Vault login API receive?
**[OBSERVED]** The login API receives:
- HTTP Method: `POST`
- Path: `/v1/auth/ldap/login/<username>`
- Body: `{"password": "<raw_password>"}`

### What does Vault return after successful authentication?
**[OBSERVED]** Vault returns a JSON object containing:
- `auth.client_token`: An opaque Vault bearer token (`hvs.xxxx`) for all subsequent Vault API calls.
- `auth.policies`: List of authorized Vault ACL policies (`['default', 'finance-policy']`).
- `auth.metadata`: Identity metadata extracted from LDAP (`{"username": "alice"}`).
- `auth.entity_id`: Vault's internal persistent identifier for the user.
- `auth.lease_duration`: Token lifetime (TTL).

### Does Vault create its own token?
**[OBSERVED]** **YES.** Vault discards the raw LDAP password immediately and issues its own cryptographically secure, internal Vault token. The client uses *this Vault token* for all subsequent requests to Vault.
