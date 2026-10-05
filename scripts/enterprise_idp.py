"""Enterprise Custom Identity Provider (IdP) & JWKS Generator.

Allows users to spin up their own dedicated OIDC Identity Provider with:
- Its own unique RSA 2048-bit keypair (JWKS)
- Its own realm and port (e.g. 8085, 9000, etc.)
- Full control over users, directory groups, and token minting

Usage:
  # 1. Start your custom IdP server on your chosen port:
  python scripts/enterprise_idp.py start --port 8085 --realm healthcorp

  # 2. Mint tokens for any user and directory groups:
  python scripts/enterprise_idp.py mint --port 8085 --user "alice@healthcorp.com" --groups "clinicians,researchers"
"""

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

def _to_b64url(n: int) -> str:
    byte_len = (n.bit_length() + 7) // 8
    raw = n.to_bytes(byte_len, "big")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def get_or_create_keypair(realm: str):
    """Load existing RSA keypair or generate a new unique 2048-bit RSA key for this realm."""
    keys_dir = Path(".idp_keys") / realm
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_file = keys_dir / "private_key.pem"

    if priv_file.exists():
        with open(priv_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(priv_file, "wb") as f:
            f.write(pem_bytes)

    public_key = private_key.public_key()
    return private_key, public_key

def create_idp_app(realm: str, port: int):
    issuer_url = f"http://localhost:{port}"
    kid = f"key-{realm}-001"
    private_key, public_key = get_or_create_keypair(realm)
    pub_numbers = public_key.public_numbers()

    jwks_data: Dict[str, Any] = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _to_b64url(pub_numbers.n),
                "e": _to_b64url(pub_numbers.e),
            }
        ]
    }

    app = FastAPI(title=f"Custom Enterprise IdP - {realm}")

    @app.get("/.well-known/openid-configuration")
    def oidc_config():
        return {
            "issuer": issuer_url,
            "jwks_uri": f"{issuer_url}/jwks.json",
            "authorization_endpoint": f"{issuer_url}/authorize",
            "token_endpoint": f"{issuer_url}/token",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    @app.get("/jwks.json")
    def get_jwks():
        return jwks_data

    class TokenRequest(BaseModel):
        sub: str = "user-1"
        groups: List[str] = ["analysts"]
        aud: str = "masking-api"
        exp_seconds: int = 3600

    @app.post("/token")
    def mint_token(req: TokenRequest):
        now = int(time.time())
        payload = {
            "iss": issuer_url,
            "sub": req.sub,
            "aud": req.aud,
            "iat": now,
            "exp": now + req.exp_seconds,
            "groups": req.groups,
        }
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(payload, pem_bytes, algorithm="RS256", headers={"kid": kid})
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": req.exp_seconds,
            "claims": payload
        }

    return app, issuer_url, kid

def cmd_start(args):
    print("=" * 70)
    print(f"[IDP] STARTING CUSTOM ENTERPRISE IDP: realm='{args.realm}' on port {args.port}")
    print("=" * 70)
    app, issuer_url, kid = create_idp_app(args.realm, args.port)
    print(f"  * Issuer URL:     {issuer_url}")
    print(f"  * OIDC Discovery: {issuer_url}/.well-known/openid-configuration")
    print(f"  * JWKS URI:       {issuer_url}/jwks.json")
    print(f"  * Key ID (kid):   {kid}")
    print(f"  * Keys Location:  .idp_keys/{args.realm}/")
    print("=" * 70)
    print("Listening for OIDC discovery & JWKS verification requests...\n")
    uvicorn.run(app, host="0.0.0.0", port=args.port)

def cmd_mint(args):
    import urllib.request
    import urllib.error

    url = f"http://localhost:{args.port}/token"
    groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    req_body = {
        "sub": args.user,
        "groups": groups,
        "aud": args.aud,
        "exp_seconds": args.exp
    }

    try:
        req = urllib.request.Request(
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(req_body).encode()
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            token = data["access_token"]
            claims = data["claims"]

            print("=" * 70)
            print(f"[TOKEN] MINTED RS256 TOKEN FOR: {args.user}")
            print("=" * 70)
            print(f"  * Issuer:   {claims['iss']}")
            print(f"  * Subject:  {claims['sub']}")
            print(f"  * Groups:   {claims['groups']}")
            print(f"  * Audience: {claims['aud']}")
            print(f"  * Expires:  in {claims['exp'] - claims['iat']} seconds")
            print("=" * 70)
            print("Access Token (Bearer):")
            print(token)
            print("=" * 70)
            print("\nReady-to-use PowerShell command to test masking:")
            print(f'$token = "{token}"')
            print('curl.exe -X POST http://127.0.0.1:8000/v1/mask -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d \'{\"patient_id\":\"PT-98124\",\"ssn\":\"123-45-6789\",\"salary\":145000,\"credit_card\":\"4111-2222-3333-5678\",\"email\":\"' + args.user + '\"}\'')
            print()
    except urllib.error.URLError as e:
        print(f"[ERROR] connecting to IdP on port {args.port}: {e}")
        print(f"   Make sure your IdP is running with: python scripts/enterprise_idp.py start --port {args.port}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Custom Enterprise Identity Provider CLI")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # start
    p_start = subparsers.add_parser("start", help="Start the custom IdP server")
    p_start.add_argument("--port", type=int, default=8085, help="Port to run the IdP on (default: 8085)")
    p_start.add_argument("--realm", type=str, default="healthcorp", help="Enterprise realm name (e.g. healthcorp, apexbank)")
    p_start.set_defaults(func=cmd_start)

    # mint
    p_mint = subparsers.add_parser("mint", help="Mint a JWT token for testing")
    p_mint.add_argument("--port", type=int, default=8085, help="Port of the running IdP (default: 8085)")
    p_mint.add_argument("--user", type=str, default="dr.patel@healthcorp.com", help="User subject / email")
    p_mint.add_argument("--groups", type=str, default="clinicians", help="Comma-separated directory groups")
    p_mint.add_argument("--aud", type=str, default="masking-api", help="Token audience (default: masking-api)")
    p_mint.add_argument("--exp", type=int, default=3600, help="Expiration in seconds (default: 3600)")
    p_mint.set_defaults(func=cmd_mint)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
