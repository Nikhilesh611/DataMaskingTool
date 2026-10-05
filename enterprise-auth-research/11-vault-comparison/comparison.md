# Evidence-Based Comparison: LDAP vs. JWT/OIDC Authentication in Vault

## Status: OBSERVED & DOCUMENTED (based on direct tests in Phases 1, 2, 9, and 10)

---

## Direct Comparison Matrix

| Dimension | LDAP Authentication (Observed) | JWT / OIDC Authentication (Observed) |
|---|---|---|
| **1. Identity Source** | Enterprise Directory Server (OpenLDAP, Active Directory) | Centralized Identity Provider (Keycloak, Okta, Entra ID) |
| **2. Authentication Input** | Plaintext Username + Password sent to Vault | Cryptographically signed Bearer JWT token sent to Vault |
| **3. Who Performs Authentication** | Vault connects to LDAP server and executes `bind` | IdP authenticates the user; Vault only validates token signature |
| **4. How Groups Are Obtained** | Vault performs a secondary LDAP search query on `ou=Groups` | Groups are extracted directly from claims inside the validated JWT payload |
| **5. How Identity Is Represented** | Hierarchical DN string (`uid=alice,ou=People,dc=lab,dc=local`) | Claims structure (`sub: UUID`, `preferred_username: alice`) |
| **6. What Vault Receives** | `POST /v1/auth/ldap/login/alice` with `{"password": "..."}` | `POST /v1/auth/jwt/login` with `{"jwt": "...", "role": "..."}` |
| **7. What Vault Validates** | TCP bind success with LDAP server | RSA-256 signature, `iss`, `aud`, `exp`, and `bound_claims` |
| **8. How Authorization Is Determined** | Mapped from LDAP group DN/CN to Vault ACL policies | Mapped from JWT claims (`groups`, `roles`) via Vault JWT Role definitions |
| **9. What Vault Returns** | Opaque Vault token (`hvs.xxxx`) + attached policies | Opaque Vault token (`hvs.xxxx`) + attached policies |
| **10. Required Vault Configuration** | LDAP server URI, bind DN, password, user/group search filters | OIDC discovery URL, bound audiences, bound claims, user claims |
| **11. Who Needs Configuration** | Vault must have service account credentials to query LDAP | Vault only needs public JWKS keys (zero shared secrets needed) |
| **12. Identity Updates** | Immediate (every login queries live LDAP directory) | Eventual (token claims valid until `exp` timestamp; refreshes on next token issuance) |
| **13. Human Authentication** | User types password directly into client app / Vault | User logs in via secure IdP browser SSO (supports MFA, WebAuthn, FIDO2) |
| **14. Machine Authentication** | Requires dedicated service accounts with static passwords | Standard OAuth2 Client Credentials (`grant_type=client_credentials`) |
| **15. Security Considerations** | Exposes user passwords to intermediate services; requires direct network path to LDAP | Decouples credentials from services; intermediate services never see user passwords |
| **16. Operational Complexity** | High network coupling (Vault needs direct TCP line to directory) | Low coupling (Vault and IdP only need HTTP/HTTPS connectivity to JWKS) |

---

## Key Synthesis
1. **[OBSERVED]** Both methods achieve the exact same end state in Vault: an internal Vault Token with role-specific ACL policies (`finance-policy`, `security-policy`).
2. **[OBSERVED]** The critical difference is **credential decoupling**:
   - In LDAP, the consuming service (Vault) must receive and process raw user passwords.
   - In JWT/OIDC, the consuming service never sees user passwords; it verifies a cryptographic assertion issued by the trusted IdP.
