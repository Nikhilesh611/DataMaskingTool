# Enterprise Integration Model: Authentication vs. Authorization

## Status: OBSERVED & INFERRED (proven via live OpenLDAP, Keycloak, and Vault experiments)

---

## 1. Authentication vs. Authorization in Practice

```
[ CLIENT ] ──( 1. Presents Credential / JWT )──> [ AUTHENTICATION ENGINE ]
                                                           │
                                                ( 2. Verifies Identity )
                                                - Validates Password/Signature
                                                - Establishes 'Who' (Alice / finance)
                                                           │
                                                           ▼
                                                [ IDENTITY CONTEXT ]
                                                - Principal: alice
                                                - Groups: ["finance"]
                                                           │
                                                ( 3. Maps to Permissions )
                                                           │
                                                           ▼
                                                [ AUTHORIZATION ENGINE ]
                                                - Evaluates ACL Policies
                                                - Checks Capabilities (read/mask/deny)
                                                           │
                                                ( 4. Executes Action )
                                                           ▼
                                                [ TARGET RESOURCE ]
```

### Exact Breakdown

| Stage | Action in Vault / Enterprise | Observed Evidence |
|---|---|---|
| **AUTHENTICATION**<br>*(Establishing "Who")* | 1. Receive JWT / LDAP password<br>2. Cryptographically verify signature or perform LDAP bind<br>3. Extract verified principal (`sub: 4e2dae28-...`, `preferred_username: alice`) and group claims (`groups: ["finance"]`). | **Point in Code**: `/auth/jwt/login` or `/auth/ldap/login` verification step. |
| **BOUNDARY** | Identity is verified and immutable. The identity context (`alice`, `finance`) is passed to the authorization engine. | Vault creates an internal **Entity** representing Alice. |
| **AUTHORIZATION**<br>*(Establishing "What")* | 1. Match verified groups (`finance`) against registered roles/policies.<br>2. Attach authorized policies (`finance-policy`).<br>3. Intercept subsequent API requests and check if the attached policy permits the requested operation on the target path. | **Point in Code**: Policy enforcement engine evaluating `path "secret/data/finance/*" { capabilities = ["read"] }`. |

---

## 2. The Enterprise Integration Model (How a 3rd-Party Service Integrates)

A central question for enterprise architecture is: **How can an external/third-party service integrate into an enterprise without replacing the enterprise's existing identity systems?**

```
┌─────────────────────────────────────────────────────────────┐
│                 ENTERPRISE IDENTITY BOUNDARY                │
│                                                             │
│   [ OpenLDAP / Active Directory ]   OR   [ Keycloak / Okta ]│
│   - Stores Users (Alice, Bob)            - Handles MFA / SSO│
│   - Stores Groups (Finance, Sec)         - Issues Signed JWT│
└──────────────────────────────┬──────────────────────────────┘
                               │
               ( Public JWKS Certs OR LDAP Bind )
               ( Trust Established Once by Admin )
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│            THIRD-PARTY SERVICE (Vault / Masking Tool)        │
│                                                             │
│   1. Trust Verifier (Checks JWKS signatures / LDAP bind)    │
│   2. Identity Mapper (Maps external groups -> local roles)  │
│   3. Local Policy Engine (Enforces service-specific ACLs)   │
│   4. Resource Executor (Returns secrets / masked payloads)  │
└─────────────────────────────────────────────────────────────┘
```

### Answers to the 12 Integration Questions

1. **What must the enterprise administrator configure?**
   - Register the service client ID in the IdP (or create a readonly LDAP service account).
   - Ensure the group membership mapper is enabled in the IdP to include group claims in tokens.
2. **What must the external service configure?**
   - The IdP Discovery URL (`oidc_discovery_url`) or LDAP server endpoint.
   - Role/Policy mapping rules (e.g. Map external group `finance` $\rightarrow$ internal policy `finance-policy`).
3. **What does the enterprise identity system remain responsible for?**
   - User lifecycle (creating/disabling employees).
   - Password resets, MFA enforcement, and authentication security.
   - Master group membership (who is in `finance` vs `security`).
4. **What does the external service become responsible for?**
   - Verifying incoming tokens/credentials.
   - Service-specific authorization (defining what `finance-policy` means inside the service).
   - Audit logging of service operations.
5. **How does the service establish trust with LDAP?**
   - Via administrative Bind credentials (`binddn` + `bindpass`) over TLS.
6. **How does the service establish trust with an IdP?**
   - Via public key cryptography (fetching public certs from `/.well-known/jwks.json`). **No shared secrets needed!**
7. **Does the service require replacing the enterprise identity system?**
   - **NO.** The service acts as a consumer of existing enterprise identity.
8. **Does the service create its own users?**
   - **NO.** It creates ephemeral or mapped identity aliases (Entities) linked to the external enterprise identity.
9. **What information crosses the Enterprise $\rightarrow$ Service boundary?**
   - Only public signing keys (JWKS) and OIDC discovery metadata.
10. **What information crosses the Client $\rightarrow$ Service boundary?**
    - The signed JWT Access Token containing user claims and group names (or username/password in direct LDAP mode).
