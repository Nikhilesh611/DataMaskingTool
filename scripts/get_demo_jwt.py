"""Helper script to generate signed JWTs and serve a local JWKS endpoint for Swagger UI testing.

Usage:
    1. Run this script in a separate terminal:
       python get_demo_jwt.py

    2. It will print ready-to-use Bearer JWT tokens for Analyst, Auditor, and Operator roles.
    3. It will keep running a lightweight local JWKS server on http://localhost:8088/jwks.json
       so that Uvicorn can validate the signature!
"""

from __future__ import annotations

import json
import http.server
import socketserver
import os
import sys
import threading
import time

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure project root is in sys.path when running from scripts/
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "http://localhost:8088"
AUDIENCE = "masking-service"
KID = "demo-key-2026"
PORT = 8088

# Generate fixed RSA keypair for session
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key)) | {
    "kid": KID,
    "use": "sig",
    "alg": "RS256",
}
jwks_response = json.dumps({"keys": [jwk_dict]}).encode("utf-8")


class JWKSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(jwks_response)

    def log_message(self, format, *args):
        pass  # Suppress HTTP server noise


def start_jwks_server():
    with socketserver.TCPServer(("127.0.0.1", PORT), JWKSHandler) as httpd:
        httpd.serve_forever()


def make_jwt(group_name: str) -> str:
    now = int(time.time())
    payload = {
        "sub": f"user.{group_name}@enterprise.com",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 86400,  # Valid for 24 hours
        "groups": [group_name],
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem, algorithm="RS256", headers={"kid": KID})


def main():
    # Start JWKS server in background thread
    server_thread = threading.Thread(target=start_jwks_server, daemon=True)
    server_thread.start()

    analyst_token = make_jwt("data-analysts")
    auditor_token = make_jwt("finance-team")
    operator_token = make_jwt("admin-users")

    print("\n" + "=" * 75)
    print("   READY-TO-USE JWT TOKENS FOR SWAGGER UI TESTING")
    print("=" * 75 + "\n")

    print("🔑 [1] DATA ANALYST ROLE (Group: 'data-analysts' → Role: 'analyst')")
    print(f"Bearer {analyst_token}\n")

    print("🔑 [2] AUDITOR ROLE (Group: 'finance-team' → Role: 'auditor')")
    print(f"Bearer {auditor_token}\n")

    print("🔑 [3] OPERATOR ROLE (Group: 'admin-users' → Role: 'operator')")
    print(f"Bearer {operator_token}\n")

    print("-" * 75)
    print("⚙️  MAKE SURE YOUR .env FILE HAS THE FOLLOWING SETTINGS:")
    print(f"AUTH_MODE=enterprise_jwt")
    print(f"IDP_ISSUER={ISSUER}")
    print(f"IDP_AUDIENCE={AUDIENCE}")
    print(f"IDP_JWKS_URI=http://localhost:8088/jwks.json")
    print(f"IDP_MAPPINGS_PATH=group_mappings.json")
    print("-" * 75)
    print("\n🌐 JWKS server is running on http://localhost:8088/jwks.json")
    print("Press Ctrl+C to stop the JWKS server.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nJWKS server stopped.")


if __name__ == "__main__":
    main()
