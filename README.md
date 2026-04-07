# Multi-Format Data Masking API

A privacy-preserving middleware REST API that masks sensitive data in **XML**, **JSON**, and **YAML** files using a declarative YAML policy.

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
```

Required variables:

| Variable | Description |
|---|---|
| `DATA_DIR` | Directory containing data files to mask |
| `POLICY_PATH` | Path to masking policy YAML |
| `AUDIT_LOG_PATH` | Path for operator audit log |
| `API_TOKENS` | JSON object: `{"token": "role", ...}` |

Valid roles: `analyst`, `auditor`, `operator`.

### 3. Run the Server

```bash
uvicorn app.main:app --reload --port 8000
```

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/mask` | Required | Mask a file by filename |
| `GET` | `/audit/coverage?filename=<name>` | Auditor | Node coverage report (no values) |
| `GET` | `/audit/conflicts/{request_id}` | Auditor | Conflict log for a past request |
| `GET` | `/policy` | Auditor / Operator | Dump current policy |
| `GET` | `/health` | None | Health check |

### POST /mask

```bash
curl -X POST http://localhost:8000/mask \
  -H "X-API-Token: <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"filename": "sample.json"}'
```

**Response headers:**

| Header | Description |
|---|---|
| `X-Request-ID` | Unique request ID for audit correlation |
| `X-Policy-Version` | Version of the applied policy |
| `X-Conflict-Count` | Number of multi-rule conflicts resolved |
| `X-Uncovered-Count` | Number of nodes with no matching rule |
| `X-K-Anonymity-Achieved` | `true` / `false` |

---

## Role Behaviour

| Role | Behaviour |
|---|---|
| `analyst` | Applies masking techniques — receives masked data |
| `auditor` | Receives labelled output showing what *would* be applied; uncovered nodes labelled `[UNMASKED — NO RULE DEFINED]` |
| `operator` | Receives raw unchanged data; every access written to the audit log |

---

## Policy Format

```yaml
version: "1.0"
record_root: "$.patients[*]"     # JSONPath to record root (for k-anonymity)

rules:
  - selector: "$..ssn"           # JSONPath or XPath selector
    technique: suppress          # remove node entirely
  
  - selector: "$..name"
    technique: redact            # replace with [REDACTED]
  
  - selector: "$..email"
    technique: pseudonymize
    consistent: true             # deterministic SHA-256 hash
  
  - selector: "$..dob"
    technique: generalize
    hierarchy: date              # registered hierarchy name
    level: 2                     # 0=original, 1=YYYY-MM, 2=YYYY, 3=decade, 4=*
  
  - selector: "$..bp"
    technique: noise             # ±10% random perturbation
  
  - selector: "$..address"
    technique: nullify           # set to null/None

k_anonymity:
  enabled: true
  k: 2
  quasi_identifiers:
    - "$..dob"
    - "$..zipcode"
```

### Masking Techniques

| Technique | Effect |
|---|---|
| `suppress` | Removes the node from the document entirely |
| `nullify` | Sets the value to `null` |
| `redact` | Replaces value with `[REDACTED]` |
| `pseudonymize` | ANON_XXXXXXXX — consistent (SHA-256) or random |
| `generalize` | Replaces value with a generalised version via a hierarchy |
| `format_preserve` | Replaces digits/letters with random chars of same type |
| `noise` | Adds ±10% uniform random noise to numeric values |

### Built-in Hierarchies

| Name | Levels |
|---|---|
| `date` | 0=full, 1=YYYY-MM, 2=YYYY, 3=decade, 4=* |
| `zipcode` | 0=full … N=trailing `*` mask |
| `icd10` | 0=full, 1=3-char category, 2=chapter (J**), 3=*** |

---

## Architecture

```
app/
├── main.py                  # FastAPI app, lifespan, exception handlers
├── config.py                # Env-var settings
├── auth.py                  # Token → role RBAC
├── middleware.py             # Request-ID injection
├── file_reader.py           # Path-safe file loading
├── techniques.py            # 7 masking technique callables
├── adapters/
│   ├── base.py              # FormatAdapter ABC
│   ├── node_wrapper.py      # NodeWrapper (JSON/YAML parent tracking)
│   ├── xml_adapter.py       # lxml XML adapter
│   ├── json_adapter.py      # json + jsonpath-ng adapter
│   ├── yaml_adapter.py      # PyYAML adapter
│   └── registry.py          # Format detection + adapter registry
├── policy/
│   ├── models.py            # Pydantic v2 policy models
│   └── loader.py            # YAML loading + validation singleton
├── hierarchies/
│   ├── base.py              # Hierarchy ABC + registry
│   ├── date_hierarchy.py
│   ├── zipcode_hierarchy.py
│   └── icd10_hierarchy.py
└── pipeline/
    ├── phase1.py            # Index building (rule + coverage indexes)
    ├── phase2.py            # Conflict resolution (specificity scoring)
    ├── phase3.py            # Masking loop (format-blind, role-aware)
    ├── kanon.py             # k-Anonymity engine
    └── runner.py            # Orchestrates all phases → PipelineResult
```

**Format-blind pipeline**: The three-phase pipeline knows nothing about XML, JSON, or YAML. All format differences are encapsulated in the `FormatAdapter` implementations.

---

## Running Tests

```bash
python -m pytest tests/ -q
```

Test coverage includes:
- Adapter unit tests (XML, JSON, YAML): parse, iter, select, get/set/remove, attach
- Phase 1–3 unit tests
- All 7 technique isolation tests
- All 3 hierarchy tests (5–4 levels + fallbacks + saturation)
- k-Anonymity engine tests
- Policy validation (valid + 8 error cases)
- File reader security tests (path traversal, null bytes)
- Endpoint integration tests (all 4 routes, all 3 roles)
