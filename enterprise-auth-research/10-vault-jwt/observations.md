# HashiCorp Vault + JWT / OIDC Integration Observations (Phase 10)

## Status: OBSERVED (directly tested with HashiCorp Vault 1.17 against Keycloak 25.0)

---

## 1. Vault JWT Configuration & Mechanics

### What does Vault need to know about the IdP?
**[OBSERVED]** Vault needs only the **`oidc_discovery_url`** (`http://keycloak:8080/realms/lab-realm`). From this single URL, Vault automatically discovers the JWKS public certs endpoint, token issuer, and algorithms.

### Does Vault use OIDC discovery / JWKS?
**[OBSERVED]** **YES.** Vault fetches the public signing keys from Keycloak's JWKS endpoint and verifies incoming JWT signatures locally without calling Keycloak for every login.

### What claims does Vault inspect?
**[OBSERVED]**
- `iss` (Issuer): Strictly validated against the configured discovery URL.
- `aud` (Audience): Validated against `bound_audiences`.
- `exp` (Expiration): Validated to ensure token is fresh.
- `user_claim` (`preferred_username` or `sub`): Used as the identity identifier.
- `bound_claims` (e.g. `{"groups": "finance"}`): Evaluated to ensure the token satisfies role membership requirements.

---

## 2. Answers to Research Questions

### How are JWT claims mapped to Vault identity and policies?
**[OBSERVED]** Vault uses named **JWT Roles** (`/auth/jwt/role/<role_name>`):
```json
{
  "role_type": "jwt",
  "bound_audiences": ["account"],
  "bound_claims": { "groups": "finance" },
  "token_policies": ["finance-policy"],
  "user_claim": "preferred_username"
}
```
When a client presents a JWT requesting `role=finance-role`, Vault:
1. Validates the cryptographic signature against Keycloak JWKS.
2. Checks that the JWT contains `groups: ["finance"]`.
3. If verified, attaches the internal Vault policy `finance-policy`.
4. If a user (like Alice) tries to claim `security-role`, Vault rejects the login with:
   `"error validating claims: claim \"groups\" does not match any associated bound claim values"`.

### What request does the client send to Vault?
**[OBSERVED]**
- `POST /v1/auth/jwt/login`
- Body: `{"jwt": "<signed_bearer_token>", "role": "finance-role"}`
- **Note**: The client NEVER sends user passwords to Vault; it only presents the signed JWT issued by Keycloak!

### What does Vault return?
**[OBSERVED]** Vault returns its own **Vault Client Token (`hvs.xxxx`)** with the mapped policies attached.
