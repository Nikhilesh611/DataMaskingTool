# Machine-to-Machine & Service Identity Observations (Phase 8)

## Status: OBSERVED (directly tested via OAuth2 Client Credentials grant with Keycloak 25.0)

---

## 1. Machine vs Human Token Comparison

| Dimension | Human User Token (Alice - Phase 3/4) | Service Account Token (`lab-client` - Phase 8) |
|---|---|---|
| **Grant Type** | `password` / `authorization_code` | `client_credentials` |
| **Credentials Required** | Username + Password (or MFA) | `client_id` + `client_secret` |
| **Subject (`sub`)** | Alice's User UUID (`4e2dae28-...`) | Keycloak Service Account UUID (`37adead6-...`) |
| **Username (`preferred_username`)** | `alice` | `service-account-lab-client` |
| **Client ID (`azp`, `client_id`)** | `lab-client` | `lab-client` |
| **Personal Profile Claims** | `email`, `given_name`, `family_name`, `name` | **ABSENT** |
| **Groups Claim** | `["finance"]` | **ABSENT** |
| **Roles (`realm_access.roles`)** | Alice's user roles | Roles assigned to the Service Account |

---

## 2. Answers to Research Questions

### 1. Can a machine/application authenticate without a human?
**[OBSERVED]** **YES.** Using the standard OAuth2 Client Credentials Grant (`grant_type=client_credentials`), any backend daemon, cron job, or microservice can authenticate directly using its provisioned client credentials.

### 2. What token is returned?
**[OBSERVED]** A cryptographically signed RS256 Bearer JWT Access Token identical in structure and signature format to a human user token.

### 3. What is the subject (`sub`)?
**[OBSERVED]** The `sub` claim contains the internal UUID of a dedicated **service account user entity** generated automatically by Keycloak for that client (`service-account-lab-client`).

### 4. Where do application roles/permissions appear?
**[OBSERVED]** Roles assigned to the client application appear under `realm_access.roles` and `resource_access.{clientId}.roles`. Downstream microservices inspect these roles to authorize service-to-service API calls.
