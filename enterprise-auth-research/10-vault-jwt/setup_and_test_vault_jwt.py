"""Configure and test HashiCorp Vault with JWT/OIDC Authentication against Keycloak."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

VAULT_URL = "http://localhost:8200"
KEYCLOAK_URL = "http://localhost:8081"
ROOT_TOKEN = "dev-root-token"
CLIENT_ID = "lab-client"
CLIENT_SECRET = "lab-client-secret-12345"


def vault_api(method: str, path: str, token: str | None = ROOT_TOKEN, data: dict | None = None) -> tuple[int, dict]:
    url = f"{VAULT_URL}/v1{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        return e.code, json.loads(content) if content else {}


def get_keycloak_jwt(username="alice", password="alice123") -> str:
    url = f"{KEYCLOAK_URL}/realms/lab-realm/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid profile email",
    }).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def setup_vault_jwt():
    print("1. Enabling JWT Auth Method in Vault...")
    vault_api("POST", "/sys/auth/jwt", data={"type": "jwt"})

    print("2. Configuring JWT Engine with Keycloak OIDC Discovery / JWKS...")
    # Keycloak is reachable inside Docker network at http://keycloak:8080/realms/lab-realm
    # Or using jwks_url directly
    status, res = vault_api("POST", "/auth/jwt/config", data={
        "oidc_discovery_url": "http://keycloak:8080/realms/lab-realm",
        "oidc_discovery_ca_pem": "",
        "default_role": "general-role",
    })
    print(f"JWT Config status: {status}")

    print("3. Creating JWT Roles in Vault with Claim Mappings...")
    # Finance Role: checks bound_claims {"groups": "finance"}, assigns "finance-policy"
    vault_api("POST", "/auth/jwt/role/finance-role", data={
        "role_type": "jwt",
        "user_claim": "preferred_username",
        "bound_audiences": ["account"],
        "bound_claims": {
            "groups": "finance"
        },
        "token_policies": ["finance-policy"],
        "token_ttl": "1h",
    })

    # Security Role: checks bound_claims {"groups": "security"}, assigns "security-policy"
    vault_api("POST", "/auth/jwt/role/security-role", data={
        "role_type": "jwt",
        "user_claim": "preferred_username",
        "bound_audiences": ["account"],
        "bound_claims": {
            "groups": "security"
        },
        "token_policies": ["security-policy"],
        "token_ttl": "1h",
    })
    print("JWT roles configured.")


def test_vault_jwt_login(jwt_token: str, role_name: str) -> dict:
    status, res = vault_api("POST", "/auth/jwt/login", token=None, data={
        "jwt": jwt_token,
        "role": role_name,
    })
    return {"status_code": status, "response": res}


def main():
    setup_vault_jwt()

    print("\n=== Test 1: Alice Logs in to Vault using Keycloak JWT (finance-role) ===")
    alice_jwt = get_keycloak_jwt("alice", "alice123")
    alice_res = test_vault_jwt_login(alice_jwt, "finance-role")
    print(f"Status: {alice_res['status_code']}")
    
    alice_auth = alice_res["response"].get("auth", {})
    client_token = alice_auth.get("client_token", "")
    print(f"Vault Client Token: hvs.{client_token[:6]}... (length {len(client_token)})")
    print(f"Policies Attached: {alice_auth.get('policies')}")
    print(f"Metadata Extracted from JWT: {json.dumps(alice_auth.get('metadata'), indent=2)}")
    print(f"Entity ID: {alice_auth.get('entity_id')}")

    # Redact before saving
    redacted_alice = dict(alice_res)
    if "auth" in redacted_alice["response"]:
        redacted_alice["response"]["auth"]["client_token"] = "[REDACTED_VAULT_TOKEN]"
    with open("10-vault-jwt/alice_jwt_vault_login_response.json", "w") as f:
        json.dump(redacted_alice, f, indent=2)

    print("\n=== Test 2: Bob Logs in to Vault using Keycloak JWT (security-role) ===")
    bob_jwt = get_keycloak_jwt("bob", "bob123")
    bob_res = test_vault_jwt_login(bob_jwt, "security-role")
    print(f"Status: {bob_res['status_code']}")
    bob_auth = bob_res["response"].get("auth", {})
    print(f"Policies Attached: {bob_auth.get('policies')}")

    redacted_bob = dict(bob_res)
    if "auth" in redacted_bob["response"]:
        redacted_bob["response"]["auth"]["client_token"] = "[REDACTED_VAULT_TOKEN]"
    with open("10-vault-jwt/bob_jwt_vault_login_response.json", "w") as f:
        json.dump(redacted_bob, f, indent=2)

    print("\n=== Test 3: Alice Attempts Privilege Escalation (requesting security-role) ===")
    escalate_res = test_vault_jwt_login(alice_jwt, "security-role")
    print(f"Status: {escalate_res['status_code']}")
    print("Response:", json.dumps(escalate_res["response"], indent=2))


if __name__ == "__main__":
    main()
