"""Phase 7 — Mock Enterprise OIDC Identity Provider Server.

Used for local development, Docker Compose lab, and end-to-end multi-realm tests.
Spawns an independent mock IdP with distinct RSA keys per realm/tenant.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

REALM_NAME = os.getenv("IDP_REALM", "tenant-a")
ISSUER_PORT = int(os.getenv("PORT", "8081"))
ISSUER_URL = os.getenv("IDP_ISSUER_URL", f"http://localhost:{ISSUER_PORT}")

# Generate RSA keypair on startup
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()
_public_numbers = _public_key.public_numbers()

def _to_b64url(n: int) -> str:
    byte_len = (n.bit_length() + 7) // 8
    raw = n.to_bytes(byte_len, "big")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

_KID = f"key-{REALM_NAME}-001"
_JWKS: Dict[str, Any] = {
    "keys": [
        {
            "kty": "RSA",
            "kid": _KID,
            "use": "sig",
            "alg": "RS256",
            "n": _to_b64url(_public_numbers.n),
            "e": _to_b64url(_public_numbers.e),
        }
    ]
}

app = FastAPI(title=f"Mock IdP - {REALM_NAME}")

@app.get("/.well-known/openid-configuration")
def openid_configuration():
    return {
        "issuer": ISSUER_URL,
        "jwks_uri": f"{ISSUER_URL}/jwks.json",
        "authorization_endpoint": f"{ISSUER_URL}/authorize",
        "token_endpoint": f"{ISSUER_URL}/token",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }

@app.get("/jwks.json")
def jwks():
    return _JWKS

class TokenRequest(BaseModel):
    sub: str = "user-1"
    groups: list[str] = ["analysts"]
    aud: str = "masking-api"
    exp_seconds: int = 3600

@app.post("/token")
def mint_token(req: TokenRequest):
    now = int(time.time())
    payload = {
        "iss": ISSUER_URL,
        "sub": req.sub,
        "aud": req.aud,
        "iat": now,
        "exp": now + req.exp_seconds,
        "groups": req.groups,
    }
    pem_bytes = _private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode(payload, pem_bytes, algorithm="RS256", headers={"kid": _KID})
    return {"access_token": token, "token_type": "Bearer", "expires_in": req.exp_seconds}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=ISSUER_PORT)
