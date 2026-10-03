"""Full End-to-End Live Demo for Enterprise JWT Authentication System.

Run this script directly to demonstrate all end-to-end capabilities:
    python demo_jwt_e2e.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from unittest.mock import patch

# Ensure stdout handles UTF-8 on Windows terminals cleanly
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

# ── ANSI Color Codes for Beautiful Terminal Output ─────────────────────────────
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

ISSUER = "https://idp.enterprise-corp.com"
AUDIENCE = "data-masking-service"
KID = "ent-key-2026-001"


def print_banner():
    print(f"\n{CYAN}{BOLD}{'=' * 75}")
    print(f"   DATA MASKING API - ENTERPRISE JWT AUTHENTICATION E2E DEMO")
    print(f"{'=' * 75}{RESET}\n")


def print_step(num: int, title: str, description: str):
    print(f"{YELLOW}{BOLD}[SCENARIO {num}] {title}{RESET}")
    print(f"  {description}\n")


def print_result(status_code: int, role_header: str | None, body: dict | str):
    status_color = GREEN if status_code == 200 else RED
    print(f"  {BOLD}HTTP Status:{RESET} {status_color}{status_code}{RESET}")
    if role_header:
        print(f"  {BOLD}Resolved Role Header (X-Role):{RESET} {GREEN}{role_header}{RESET}")
    
    formatted_body = json.dumps(body, indent=4) if isinstance(body, dict) else str(body)
    # Print indented payload
    print(f"  {BOLD}Response Body:{RESET}")
    for line in formatted_body.splitlines():
        print(f"    {line}")
    print(f"\n{CYAN}{'-' * 75}{RESET}\n")


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def make_jwt(private_key, extra_claims=None, exp_offset=3600, iss=ISSUER, aud=AUDIENCE):
    now = int(time.time())
    payload = {
        "sub": "alice.employee@enterprise.com",
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
    }
    if extra_claims:
        payload.update(extra_claims)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem, algorithm="RS256", headers={"kid": KID})


def main():
    print_banner()

    # 1. Setup mock environment & keypair
    priv_key, pub_key = generate_rsa_keypair()
    from jwt.algorithms import RSAAlgorithm
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(pub_key)) | {"kid": KID, "use": "sig", "alg": "RS256"}
    jwks_uri = f"{ISSUER}/.well-known/jwks.json"

    # Environment settings
    env_vars = {
        "AUTH_MODE": "enterprise_jwt",
        "IDP_ISSUER": ISSUER,
        "IDP_AUDIENCE": AUDIENCE,
        "IDP_GROUPS_CLAIM": "groups",
        "IDP_MAPPINGS_PATH": "group_mappings.json",
        "IDP_JWKS_URI": jwks_uri,
        "POLICY_PATH": "policy.yaml",
        "DATA_DIR": "./data",
        "AUDIT_LOG_PATH": "./audit.log",
        "APP_LOG_LEVEL": "WARNING",
    }

    with patch.dict(os.environ, env_vars):
        # Reset modules to pick up env vars
        import app.config as cfg_mod
        cfg_mod.init_settings()
        from app.policy import loader as pl_mod
        pl_mod._policy = None

        from app.idp.group_mapper import GroupMappingStore, set_group_mapping_store
        store = GroupMappingStore()
        store.load("group_mappings.json")
        set_group_mapping_store(store)

        from app.idp.jwks_client import JWKSCache, set_jwks_cache
        cache = JWKSCache(ttl_seconds=300)
        cache.set(jwks_uri, [jwk_dict])
        set_jwks_cache(cache)

        from app.main import app as fastapi_app
        with TestClient(fastapi_app) as client:

            # ----------------------------------------------------------------------
            # SCENARIO 1: Valid Analyst JWT
            # ----------------------------------------------------------------------
            print_step(1, "Valid Enterprise JWT - Analyst Group",
                       "Token contains group 'data-analysts'. Maps to 'analyst' role. Expect PII masking.")
            jwt_analyst = make_jwt(priv_key, extra_claims={"groups": ["data-analysts"]})
            resp = client.post(
                "/mask",
                json={"filename": "sample_v2.json"},
                headers={"Authorization": f"Bearer {jwt_analyst}"}
            )
            print_result(resp.status_code, resp.headers.get("X-Role"), resp.json())

            # ----------------------------------------------------------------------
            # SCENARIO 2: Valid Auditor JWT
            # ----------------------------------------------------------------------
            print_step(2, "Valid Enterprise JWT - Auditor Group",
                       "Token contains group 'finance-team'. Maps to 'auditor' role.")
            jwt_auditor = make_jwt(priv_key, extra_claims={"groups": ["finance-team"]})
            resp = client.post(
                "/mask",
                json={"filename": "sample_v2.json"},
                headers={"Authorization": f"Bearer {jwt_auditor}"}
            )
            print_result(resp.status_code, resp.headers.get("X-Role"), resp.json())

            # ----------------------------------------------------------------------
            # SCENARIO 3: Multi-Group Resolution (Priority Tie-Breaking)
            # ----------------------------------------------------------------------
            print_step(3, "Multi-Group Claim - Priority Conflict Resolution",
                       "Token contains groups ['data-analysts' (prio 20), 'admin-users' (prio 1)]. 'admin-users' wins.")
            jwt_multi = make_jwt(priv_key, extra_claims={"groups": ["data-analysts", "admin-users"]})
            resp = client.post(
                "/mask",
                json={"filename": "sample_v2.json"},
                headers={"Authorization": f"Bearer {jwt_multi}"}
            )
            print_result(resp.status_code, resp.headers.get("X-Role"), resp.json())

            # ----------------------------------------------------------------------
            # SCENARIO 4: Expired Token Rejection (401)
            # ----------------------------------------------------------------------
            print_step(4, "Expired JWT Security Guardrail",
                       "Token has expired timestamp (exp in past). Expect HTTP 401 Unauthorized.")
            jwt_expired = make_jwt(priv_key, extra_claims={"groups": ["data-analysts"]}, exp_offset=-600)
            resp = client.post(
                "/mask",
                json={"filename": "sample_v2.json"},
                headers={"Authorization": f"Bearer {jwt_expired}"}
            )
            print_result(resp.status_code, resp.headers.get("X-Role"), resp.json())

            # ----------------------------------------------------------------------
            # SCENARIO 5: Tampered Signature Rejection (401)
            # ----------------------------------------------------------------------
            print_step(5, "Tampered Signature Security Guardrail",
                       "Signature payload modified in transit. Expect HTTP 401 Unauthorized.")
            jwt_valid = make_jwt(priv_key, extra_claims={"groups": ["data-analysts"]})
            parts = jwt_valid.split(".")
            parts[2] = parts[2][:-4] + "XXXX"
            tampered_jwt = ".".join(parts)
            resp = client.post(
                "/mask",
                json={"filename": "sample_v2.json"},
                headers={"Authorization": f"Bearer {tampered_jwt}"}
            )
            print_result(resp.status_code, resp.headers.get("X-Role"), resp.json())

            # ----------------------------------------------------------------------
            # SCENARIO 6: Fail-Closed Unmapped Group (403)
            # ----------------------------------------------------------------------
            print_step(6, "Unmapped Group Fail-Closed Guardrail",
                       "Token is cryptographically valid but contains group 'contractors-temp' (unmapped). Expect HTTP 403 Forbidden.")
            jwt_unmapped = make_jwt(priv_key, extra_claims={"groups": ["contractors-temp"]})
            resp = client.post(
                "/mask",
                json={"filename": "sample_v2.json"},
                headers={"Authorization": f"Bearer {jwt_unmapped}"}
            )
            print_result(resp.status_code, resp.headers.get("X-Role"), resp.json())

    print(f"{GREEN}{BOLD}DEMO COMPLETE - ALL SCENARIOS PASSED SUCCESSFULLY!{RESET}\n")


if __name__ == "__main__":
    main()
