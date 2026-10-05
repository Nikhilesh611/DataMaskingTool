# Other Enterprise Authentication Methods (Phase 14)

---

## Evaluation of Candidate Methods

### 1. OAuth2 Client Credentials (M2M)
- **Status**: **TESTED (Observed in Phase 8)**
- **Who authenticates**: Backend machine, batch job, or microservice daemon.
- **Credential presented**: `client_id` + `client_secret` exchanged for signed RS256 Bearer JWT.
- **Who verifies it**: IdP issues token; receiving service verifies signature via JWKS.
- **Identity established**: Synthetic Service Account identity (`service-account-lab-client`).
- **Authorization applied**: Roles assigned to the service account.
- **Relevance to Masking Service**: **HIGH**. Required when an upstream backend service calls the Masking API on behalf of batch pipelines without user sessions.

---

### 2. Mutual TLS (mTLS)
- **Status**: **DOCUMENTED ONLY**
- **Who authenticates**: Client service and server service simultaneously.
- **Credential presented**: X.509 client certificate during TLS handshake.
- **Who verifies it**: TLS termination layer (Nginx, Envoy, or application TLS stack) against trusted Certificate Authority (CA) root.
- **Identity established**: Common Name (CN) or Subject Alternative Name (SAN) inside client certificate (e.g. `spiffe://cluster.local/ns/prod/sa/billing-service`).
- **Authorization applied**: Gateway or service maps client CN/SAN to allowed endpoints.
- **Vault support**: Yes (`auth/cert` auth method).
- **Relevance to Masking Service**: **HIGH** for zero-trust service-mesh environments (e.g. Istio / Envoy).

---

### 3. API Keys (Pre-Shared Tokens)
- **Status**: **DOCUMENTED & CURRENTLY USED IN V1 TOOL**
- **Who authenticates**: Client application or operator.
- **Credential presented**: Static secret token in HTTP header (e.g. `X-API-Token: secret-token-123`).
- **Who verifies it**: Receiving application checks in-memory table or database.
- **Identity established**: Static role mapped to the token (`analyst`, `operator`).
- **Authorization applied**: Hardcoded role lookup.
- **Vault support**: Vault tokens (`hvs.xxxx`) function as high-entropy scoped API keys.
- **Relevance to Masking Service**: **MEDIUM**. Useful for simple local testing or legacy apps, but lacks automated key rotation, user context, and decentralized verification.

---

### 4. HashiCorp Vault AppRole
- **Status**: **DOCUMENTED ONLY**
- **Who authenticates**: Automated machines and CI/CD pipelines.
- **Credential presented**: Two-part credential: `RoleID` (semi-static identifier) + `SecretID` (one-time or short-lived token).
- **Who verifies it**: Vault AppRole backend.
- **Identity established**: Named AppRole entity.
- **Authorization applied**: Policies attached to the AppRole.
- **Vault support**: Native (`auth/approle`).
- **Relevance to Masking Service**: **HIGH** if the Masking Service needs to retrieve encryption keys dynamically from Vault.

---

### 5. Kubernetes & Cloud Workload Identity (SPIFFE / OIDC Federation)
- **Status**: **DOCUMENTED ONLY**
- **Who authenticates**: Container Pods in Kubernetes or cloud VMs (AWS/GCP/Azure).
- **Credential presented**: Projected Service Account Token (OIDC JWT signed by Kubernetes API server / Cloud IAM).
- **Who verifies it**: Receiving service validates signature against Kubernetes/Cloud JWKS endpoint.
- **Identity established**: `system:serviceaccount:<namespace>:<serviceaccount-name>`.
- **Authorization applied**: Namespace/ServiceAccount RBAC mapping.
- **Vault support**: Native (`auth/kubernetes`).
- **Relevance to Masking Service**: **HIGH** for cloud-native Kubernetes deployments.
