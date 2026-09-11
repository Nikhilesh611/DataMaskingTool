# DataMaskingTool — Project Knowledge Base

> **Purpose**: Persistent context for AI coding assistants. Keep this file updated as the project evolves.

---

## Project Overview

A **FastAPI-based privacy-preserving middleware** that masks sensitive fields in XML, JSON, and YAML data files before returning them to callers. Auth is role-based; the masking behavior per role is driven entirely by a YAML policy file.

**Stack**: Python · FastAPI · Pydantic v2 · lxml · jsonpath-ng · PyYAML · uvicorn

---

## Directory Map

```
DataMaskingTool/
├── app/
│   ├── main.py              # FastAPI app + lifespan + exception handlers + router mounts
│   ├── auth.py              # Auth layer: TokenStore, require_role(), resolve_role()
│   ├── config.py            # Settings dataclass (env-var driven, singleton)
│   ├── exceptions.py        # Custom exception hierarchy (all map to HTTP codes in main.py)
│   ├── file_reader.py       # Reads & format-detects files from DATA_DIR
│   ├── logging_config.py    # Structured app logger + append-only audit logger
│   ├── middleware.py        # RequestIDMiddleware (injects X-Request-ID)
│   ├── techniques.py        # All masking technique implementations (suppress/redact/etc.)
│   ├── adapters/            # Format-specific tree adapters (XML/JSON/YAML)
│   ├── hierarchies/         # Generalization hierarchy registry + built-ins
│   ├── pipeline/            # Phase 0-3 masking pipeline + k-anonymity + runner
│   │   ├── phase0.py        # Scope evaluation (matches scopes in policy to tree nodes)
│   │   ├── phase1.py        # Rule index building (selector → node mapping)
│   │   ├── phase2.py        # Conflict resolution across overlapping rules
│   │   ├── phase3.py        # Technique application + synthesize/deep_redact strategies
│   │   ├── kanon.py         # k-anonymity enforcement
│   │   └── runner.py        # Orchestrates phases 0-3; returns PipelineResult
│   ├── policy/
│   │   ├── models.py        # Pydantic v2 models: MaskingPolicy, ScopeRule, RoleDefinition, etc.
│   │   └── loader.py        # load_policy() + get_policy() singleton
│   └── routes/
│       ├── mask.py          # POST /mask — main masking endpoint
│       ├── audit.py         # GET /audit/coverage, GET /audit/conflicts/{id}
│       ├── policy.py        # GET /policy (operator + auditor only)
│       └── health.py        # GET /health
├── data/                    # Sample data files (XML/JSON/YAML)
├── tests/                   # pytest test suite
├── policy_v3.yaml           # Current production policy example
├── requirements.txt
├── .env / .env.example
└── CLAUDE.md                # ← This file
```

---

## Auth System (Current — v2)

### Resolution Order in `resolve_role()`
1. **`X-Masking-Role` header** — trusted direct role injection (no crypto); suitable for internal/trusted networks.
2. **`X-API-Token` header** — token-to-role lookup in `EnvTokenStore` (reads `API_TOKENS` JSON env var).

### Roles (defined in policy YAML + hard-coded behavior in routes)
| Role | Behavior |
|---|---|
| `operator` | Raw unmasked data; writes audit log entry |
| `auditor` | Masked per audit profile; can access `/audit/*` and `/policy` |
| `analyst` | Masked per analyst profile; limited fields |
| `insurer` | Masked per insurer profile; billing-focused |

### Token Store
- `TokenStore` (Protocol) — interface for role lookup
- `EnvTokenStore` — reads `API_TOKENS={"token": "role"}` from env
- `set_token_store()` / `get_token_store()` — test override helpers

---

## Policy System (v3)

Policy YAML has the following top-level sections:

```yaml
version: "3.0"
record_root: [...]      # XPath/JSONPath selectors for record boundaries
roles: {...}            # Role registry with default_fallback strategies
profiles: {...}         # Named reusable rule sets (ProfileRule lists)
scopes: [...]           # Path-bounded zones with per-role strategies
rules: [...]            # Global inline MaskingRule list
k_anonymity: {...}      # Optional k-anonymity config
```

### Techniques Available
`suppress` | `nullify` | `redact` | `pseudonymize` | `generalize` | `format_preserve` | `noise` | `mask_pattern`

### Scope Strategies
`masked` | `drop_subtree` | `default_allow` | `deep_redact` | `synthesize`

---

## Masking Pipeline Phases

| Phase | File | Description |
|---|---|---|
| 0 | `phase0.py` | Scope evaluation — matches policy scopes to subtree nodes |
| 1 | `phase1.py` | Rule indexing — maps selectors to matched nodes |
| 2 | `phase2.py` | Conflict resolution — handles overlapping rules |
| 3 | `phase3.py` | Technique application — applies masking + strategies |
| k | `kanon.py` | k-anonymity enforcement post-masking |

---

## API Endpoints

| Method | Path | Auth Required | Description |
|---|---|---|---|
| POST | `/mask` | Any valid role | Main masking endpoint |
| GET | `/audit/coverage` | auditor only | Node coverage report |
| GET | `/audit/conflicts/{id}` | auditor only | Conflict log by request ID |
| GET | `/policy` | operator or auditor | Returns loaded policy |
| GET | `/health` | None | Liveness check |

---

## Configuration (Env Vars)

| Variable | Required | Description |
|---|---|---|
| `DATA_DIR` | ✅ | Directory of data files to serve |
| `POLICY_PATH` | ✅ | Path to policy YAML file |
| `AUDIT_LOG_PATH` | ✅ | Path for append-only audit log |
| `API_TOKENS` | ✅ | JSON: `{"token": "role"}` |
| `APP_LOG_LEVEL` | ❌ | Default: `INFO` |

---

## Next Feature: Enterprise IdP Integration

### Architectural Boundary (Definitive)

```
ENTERPRISE BOUNDARY
  User/Service → LDAP/AD → Keycloak/Okta/Entra → JWT issued

MASKING SERVICE BOUNDARY
  ① Validate JWT (PyJWT + cryptography — RS256/ES256)
     - iss, aud, exp, nbf validated by library
     - JWKS fetched via OIDC discovery or explicit IDP_JWKS_URI
     - JWKS cached; refreshed once on kid miss
  ② Extract IdP groups from configurable claim (default: "groups")
  ③ Resolve internal role via group_mappings.json
     - IdP group → internal masking role (e.g. "finance-team" → "auditor")
     - Priority ordering for multi-group users
     - No mapping → HTTP 403 (fail closed)
  ④ Existing masking pipeline — UNCHANGED
     - run_pipeline(..., role="auditor") — same interface as always
  ⑤ Return masked data
```

**The masking service is not an enterprise login system.**
It validates tokens the IdP already issued; it does not store enterprise users or passwords.

### Concept Glossary

| Term | Owner | Meaning |
|---|---|---|
| **IdP group** | Enterprise | LDAP/Keycloak group (e.g. `finance-team`); appears as a JWT claim |
| **IdP role** | Enterprise | App role from IdP if present — NOT used in Phase 1 |
| **Internal masking role** | Masking service | Key in `policy.roles` (e.g. `analyst`); what the pipeline consumes |
| **Masking profile** | Masking service | Named rule set in policy YAML; assigned to scopes via `RoleStrategy` |
| **Group mapping** | Masking service admin | `group_mappings.json`: IdP group → internal role. Single source of truth |

**Translation chain**:
```
JWT "groups": ["finance-team"]
    → group_mappings["finance-team"] = "auditor"       (masking service config)
    → policy.roles["auditor"]                          (policy YAML)
    → scope.roles["auditor"].profile = "card_data"     (policy YAML)
    → masking pipeline applies card_data profile rules
```

### Fail-Closed Security Invariants
**There is no situation where an auth failure returns unmasked data.**

| Condition | Response |
|---|---|
| Missing/malformed/expired/wrong-iss/wrong-aud JWT | 401 |
| Invalid JWT signature | 401 |
| Valid JWT, no groups claim | 403 |
| Valid JWT, groups present, none mapped | 403 |
| JWKS endpoint unreachable | 503 |
| Auth mode = enterprise_jwt, IDP_ISSUER missing | startup exit |

### Multiple-Group Resolution
Priority ordering on `group_mappings.json` entries. Each entry has an optional
`priority: int` (default 0; lower = higher priority). First matching group by
priority wins. Deterministic — not dependent on JWT claim order.

### Auth Mode
`AUTH_MODE` env var: `local` (default) or `enterprise_jwt`. **Deployment/startup
configuration only — not hot-switchable.** Both modes produce the same `role: str`
interface for the pipeline. Zero pipeline changes.

### Library Choice
`pyjwt[cryptography]` — actively maintained, handles RS256/ES256, validates
all standard claims automatically. `httpx` (already present) for JWKS fetch.

### New Modules (Phase 1)
```
app/idp/
  __init__.py
  oidc_discovery.py   — OIDC discovery fetch + metadata cache
  jwks_client.py      — JWKS fetch + kid-based cache + rotation handling
  jwt_validator.py    — validate_jwt(), extract_groups()
  group_mapper.py     — GroupMapping model, GroupMappingStore, resolve_role()
```

### Configuration (Phase 1 new env vars)
| Var | When Required | Notes |
|---|---|---|
| `AUTH_MODE` | Never | `local` default |
| `IDP_ISSUER` | enterprise_jwt | Trust anchor; used for validation |
| `IDP_AUDIENCE` | enterprise_jwt | Expected `aud` claim |
| `IDP_MAPPINGS_PATH` | enterprise_jwt | Path to group_mappings.json |
| `IDP_JWKS_URI` | Optional | Skip OIDC discovery (air-gapped) |
| `IDP_GROUPS_CLAIM` | Optional | Claim key; default `groups` |
| `IDP_JWKS_CACHE_TTL_SECONDS` | Optional | Default 300 |
| `ADMIN_TOKEN` | Phase 2 | Separate admin credential |

### Phase Roadmap
- **Phase 1**: JWT validation, JWKS/OIDC, group mapper, pipeline integration, local/jwt auth modes, tests
- **Phase 2**: Small admin API (4 endpoints) for managing group mappings at runtime
- **Phase 3**: Multi-profile merging, advanced config — only if actually needed

### What Is NOT Changing
- `app/pipeline/` — zero changes
- `app/policy/models.py` — zero changes (no `idp_groups` in policy YAML)
- All existing `auth.py` functions — preserved, unchanged
- All existing routes except `mask.py` (1-line dependency change)

---

## Known Patterns & Conventions

- **Exception → HTTP mapping**: All exceptions defined in `exceptions.py`; handlers registered centrally in `main.py`. Never catch `MaskingAPIError` subclasses inside routes.
- **Policy singleton**: `get_policy()` from `app.policy.loader` — always use this, never re-parse.
- **Settings singleton**: `get_settings()` from `app.config` — same pattern.
- **Test overrides**: Use `set_token_store()` + `app.dependency_overrides` for auth mocking.
- **Audit log**: Append-only flat text, written directly to `AUDIT_LOG_PATH`. Operator access always writes an entry.

---

## Running Locally

```bash
# Install deps
pip install -r requirements.txt

# Set env (copy .env.example → .env and fill in values)
cp .env.example .env

# Start server
uvicorn app.main:app --reload --port 8000
```

---

*Last updated: 2026-09-07*
