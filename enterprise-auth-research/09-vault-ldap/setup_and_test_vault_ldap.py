"""Configure and test HashiCorp Vault with OpenLDAP Authentication."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

VAULT_URL = "http://localhost:8200"
ROOT_TOKEN = "dev-root-token"


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


def setup_vault_ldap():
    print("1. Creating Vault Policies (finance-policy and security-policy)...")
    vault_api("PUT", "/sys/policies/acl/finance-policy", data={
        "policy": 'path "secret/data/finance/*" { capabilities = ["create", "read", "update", "delete", "list"] }'
    })
    vault_api("PUT", "/sys/policies/acl/security-policy", data={
        "policy": 'path "secret/data/security/*" { capabilities = ["create", "read", "update", "delete", "list"] }'
    })
    print("Policies created.")

    print("\n2. Enabling LDAP Auth Method in Vault...")
    # Enable LDAP auth
    vault_api("POST", "/sys/auth/ldap", data={"type": "ldap"})

    print("3. Configuring LDAP Connection in Vault...")
    # Vault connects to OpenLDAP on Docker bridge network (service name: openldap)
    status, res = vault_api("POST", "/auth/ldap/config", data={
        "url": "ldap://openldap:389",
        "userdn": "ou=People,dc=lab,dc=local",
        "userattr": "uid",
        "groupdn": "ou=Groups,dc=lab,dc=local",
        "groupattr": "cn",
        "groupfilter": "(&(objectClass=groupOfNames)(member={{.UserDN}}))",
        "binddn": "cn=admin,dc=lab,dc=local",
        "bindpass": "adminpassword",
        "insecure_tls": True,
    })
    print(f"LDAP Config status: {status}")

    print("\n4. Mapping LDAP Groups to Vault Policies...")
    # Map LDAP group 'finance' -> 'finance-policy'
    vault_api("POST", "/auth/ldap/groups/finance", data={"policies": ["finance-policy"]})
    # Map LDAP group 'security' -> 'security-policy'
    vault_api("POST", "/auth/ldap/groups/security", data={"policies": ["security-policy"]})
    print("Group mappings configured.")


def test_vault_login(username: str, password: str) -> dict:
    url = f"/auth/ldap/login/{username}"
    status, res = vault_api("POST", url, token=None, data={"password": password})
    return {"status_code": status, "response": res}


def main():
    setup_vault_ldap()

    print("\n=== Test 1: Alice Logs in to Vault via LDAP ===")
    alice_res = test_vault_login("alice", "alice123")
    print(f"Status: {alice_res['status_code']}")
    
    # Redact secret token string before printing/saving
    auth_data = alice_res["response"].get("auth", {})
    client_token = auth_data.get("client_token", "")
    print(f"Vault Client Token Generated: hvs.{client_token[:6]}... (length {len(client_token)})")
    print(f"Policies Attached to Token: {auth_data.get('policies')}")
    print(f"Token Metadata (from LDAP): {json.dumps(auth_data.get('metadata'), indent=2)}")
    print(f"Entity ID in Vault: {auth_data.get('entity_id')}")

    # Redact for saving
    redacted_alice = dict(alice_res)
    if "auth" in redacted_alice["response"]:
        redacted_alice["response"]["auth"]["client_token"] = "[REDACTED_VAULT_TOKEN_s.xxxxx]"
    with open("09-vault-ldap/alice_vault_login_response.json", "w") as f:
        json.dump(redacted_alice, f, indent=2)

    print("\n=== Test 2: Bob Logs in to Vault via LDAP ===")
    bob_res = test_vault_login("bob", "bob123")
    bob_auth = bob_res["response"].get("auth", {})
    print(f"Status: {bob_res['status_code']}")
    print(f"Policies Attached to Token: {bob_auth.get('policies')}")
    print(f"Token Metadata (from LDAP): {json.dumps(bob_auth.get('metadata'), indent=2)}")

    redacted_bob = dict(bob_res)
    if "auth" in redacted_bob["response"]:
        redacted_bob["response"]["auth"]["client_token"] = "[REDACTED_VAULT_TOKEN_s.xxxxx]"
    with open("09-vault-ldap/bob_vault_login_response.json", "w") as f:
        json.dump(redacted_bob, f, indent=2)

    print("\n=== Test 3: Alice with Wrong Password ===")
    wrong_res = test_vault_login("alice", "wrongpassword")
    print(f"Status: {wrong_res['status_code']}")
    print("Response:", json.dumps(wrong_res["response"], indent=2))


if __name__ == "__main__":
    main()
