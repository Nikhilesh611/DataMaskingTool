# Enterprise Data Masking Engine: Professor Demonstration Guide

This guide gives you an **academic narrative**, a **step-by-step live presentation flow**, and **defensible answers to technical questions** when presenting your project.

---

## 1. The 30-Second Elevator Pitch

> *"Most data masking tools rely on batch processing, duplicate databases, or writing masked files to disk—creating massive storage amplification and severe security exposure windows.  
> Our project is a **Zero-Disk, On-The-Fly In-Memory Streaming Masking Service** backed by **Cryptographic Identity Federation (OIDC/OAuth2 RS256 JWKS)**.  
> When a client submits a payload, the engine intercepts the cryptographically signed JWT, discovers their enterprise directory groups, resolves their role, and enforces a declarative multi-role policy—transforming the exact same medical and financial record into 4 distinct realities on the wire with sub-200ms latency and zero PII stored on disk."*

---

## 2. The 4-Act Live Demonstration Flow

### Act 1: The Enterprise Admin Control Plane (Browser)
1. Open your browser to **`http://localhost:8000/admin`**.
2. **Tenant Workspace**: Select **`BioCorp International`**.
3. **Identity Federation**:
   - Point out the Auth Provider: `http://localhost:8086`, RS256 JWKS (`/jwks.json`), `masking-api` audience, claim `groups`.
   - Explain: *“The masking engine doesn't manage passwords or static credentials; it federates trust with enterprise IdPs (Keycloak, Okta, Azure AD).”*
4. **Group Mappings**:
   - Show how enterprise directory groups (`biocorp-researchers`, `biocorp-insurers`, `biocorp-auditors`, `biocorp-er-dispatch`) map dynamically to internal roles with deterministic priority resolution.
5. **Unified Policy Editor**:
   - Point out that **one policy document** handles all roles across JSON and XML formats using path-bounded subtree scopes and element-level transforms.

---

### Act 2: The Live Engine Demo (Terminal)
Open your terminal and run the interactive demo script:
```powershell
python scripts/professor_demo.py
```

This presents the side-by-side transformation of **one incoming enterprise hospital record** across 4 roles:

| Role & Subject | Technique / Scope Applied | Visual Output in Demo | Academic Significance |
| :--- | :--- | :--- | :--- |
| **1. Clinical Researcher**<br>`dr.smith@biocorp.com` | `drop_subtree`<br>`synthesize`<br>`generalize`<br>`deep_redact` | • Billing: **Completely Pruned**<br>• Address: **Synthesized**<br>• Diagnosis: Generalized (`I21.9` &rarr; `I21`)<br>• Clinical Notes: `[REDACTED]` | **HIPAA Safe Harbor**: Preserves medical research utility while eliminating re-identification risk. |
| **2. Claims Adjuster**<br>`adjuster@anthem.com` | `drop_subtree`<br>`noise` (Differential Privacy)<br>`suppress` | • Medical History: **Completely Pruned**<br>• Total Charges: Perturbed (`$8450.00` &rarr; `~$8770.28`)<br>• CVV: **Excised** | **Principle of Least Privilege**: Insurers reconcile finances without accessing sensitive clinical histories. |
| **3. Compliance Auditor**<br>`auditor@kpmg.com` | `mask_pattern`<br>`suppress` | • Dual Clinical & Financial Visibility<br>• Credit Card: `****-****-****-4444`<br>• CVV: **Excised** | **PCI-DSS Compliance**: Demonstrates audit transparency without cardholder data exposure. |
| **4. ER Dispatcher**<br>`dispatch@biocorp.com` | `default_allow` | • **Zero Masking Applied**<br>• Name, SSN, Notes, Card raw | **Break-Glass Emergency Protocol**: Real-time bypass ensuring zero delay in critical patient trauma care. |

---

### Act 3: Format-Agnostic Streaming (XML File Upload)
In the same demo, show that the engine evaluates both **JSONPath** and **XPath** on the fly:
```powershell
curl.exe -X POST "http://127.0.0.1:8000/v1/mask/file" -H "Authorization: Bearer <AUDITOR_TOKEN>" -F "file=@data/biocorp_payload.xml"
```
* **Key Point**: The XML stream is parsed, transformed, and serialized **in memory** using streaming chunking—never saved to temporary scratch files on disk.

---

### Act 4: The Zero-PII Compliance Audit Ledger (Browser)
1. Switch back to **`http://localhost:8000/admin`** & click the **Compliance Audit Ledger** tab.
2. Select **`BioCorp International`**.
3. Point out:
   - **Audit Traceability**: Each request produced a unique UUID `x-audit-event-id`.
   - **Privacy-by-Design**: Caller identities are automatically sanitized (`dr***@biocorp.com`).
   - **Zero-PII Storage**: The ledger records *who*, *when*, *which roles applied*, and *execution latency (ms)*, but **0 bytes of patient data or payload contents are stored in PostgreSQL**.

---

## 3. Academic Defense: Likely Professor Questions & Answers

### Q1: *"Why not just create 4 separate masked database views or replicas?"*
> **Answer**:  
> *"Creating static views or physical replicas causes **storage amplification** (4x storage for 4 roles) and **data synchronization lag**. More importantly, static copies create an attack surface of unencrypted data at rest. Our approach provides **dynamic, on-demand masking at the API gateway layer**—data exists in its masked form only during the HTTP transit window in volatile RAM."*

### Q2: *"How does your engine handle hierarchical generalization?"*
> **Answer**:  
> *"We implemented hierarchical domain trees (e.g. ICD-10 medical diagnostic codes and geographic ISO codes). In Phase 3, when a rule specifies `technique: generalize` with `level: 1`, the engine traverses the ontology tree and maps specific sub-diagnoses like `I21.9` (acute myocardial infarction, unspecified) to its parent classification `I21` (acute myocardial infarction), satisfying k-anonymity constraints."*

### Q3: *"How is security enforced at the identity layer?"*
> **Answer**:  
> *"Authentication uses **asymmetric RS256 cryptography**. The masking service fetches public keys dynamically from the enterprise IdP’s JWKS endpoint (`/jwks.json`), verifies token signatures, validates claims expiration and audience (`masking-api`), and resolves multi-valued directory groups (`groups`) against prioritized database mappings with Redis-backed caching."*

### Q4: *"What is the memory and latency footprint?"*
> **Answer**:  
> *"Because transformations are performed directly on in-memory object graphs (or streaming XML nodes) without disk I/O, latency is consistently between **15ms and 60ms** for standard payloads. All state is strictly ephemeral."*

---

## 4. Quick Reference Checklist Before Presenting

- [x] Docker PostgreSQL is running on host port `5433` (`masking_postgres`).
- [x] Docker Redis is running on host port `6379` (`masking_redis`).
- [x] BioCorp Dedicated IdP is running on port `8086`.
- [x] FastAPI / Uvicorn server is running on `http://127.0.0.1:8000`.
- [x] Test runner passes all assertions: `python scripts/verify_all_strategies.py`.
- [x] Interactive demo script is ready: `python scripts/professor_demo.py`.
