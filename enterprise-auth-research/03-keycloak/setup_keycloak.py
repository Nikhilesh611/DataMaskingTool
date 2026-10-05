"""Keycloak Setup Automation Script via Admin REST API.

Configures:
- Realm: lab-realm
- Client: lab-client (confidential, direct access grants, service accounts)
- Groups: finance, security
- Users: alice (finance), bob (security)
"""

from __future__ import annotations

import json
import urllib.request
import urllib.parse
import sys
import time

KEYCLOAK_URL = "http://localhost:8081"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
REALM_NAME = "lab-realm"
CLIENT_ID = "lab-client"
CLIENT_SECRET = "lab-client-secret-12345"


def get_admin_token() -> str:
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "client_id": "admin-cli",
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
        "grant_type": "password",
    }).encode("utf-8")
    
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        return res["access_token"]


def api_request(method: str, path: str, token: str, data: dict | None = None) -> tuple[int, Any]:
    url = f"{KEYCLOAK_URL}/admin/realms{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        return e.code, json.loads(content) if content else {}


def setup():
    print("Connecting to Keycloak Admin API...")
    token = get_admin_token()
    print("Admin token obtained.")
    
    # 1. Create Realm
    print(f"Creating realm '{REALM_NAME}'...")
    status, _ = api_request("POST", "", token, {
        "realm": REALM_NAME,
        "enabled": True,
        "displayName": "Lab Research Realm",
    })
    if status in (201, 409):
        print(f"Realm created or already exists (status {status}).")
    else:
        print(f"Realm creation status: {status}")

    # 2. Create Groups
    print("Creating groups 'finance' and 'security'...")
    api_request("POST", f"/{REALM_NAME}/groups", token, {"name": "finance"})
    api_request("POST", f"/{REALM_NAME}/groups", token, {"name": "security"})
    
    # Fetch group IDs
    _, groups = api_request("GET", f"/{REALM_NAME}/groups", token)
    group_map = {g["name"]: g["id"] for g in groups}
    print(f"Groups mapped: {group_map}")

    # 3. Create Users
    print("Creating users 'alice' and 'bob'...")
    for user, pwd, grp in [("alice", "alice123", "finance"), ("bob", "bob123", "security")]:
        status, _ = api_request("POST", f"/{REALM_NAME}/users", token, {
            "username": user,
            "enabled": True,
            "email": f"{user}@lab.local",
            "firstName": user.capitalize(),
            "lastName": "User",
            "emailVerified": True,
            "credentials": [{"type": "password", "value": pwd, "temporary": False}],
        })
        print(f"User {user} creation status: {status}")
        
        # Get user ID
        _, users = api_request("GET", f"/{REALM_NAME}/users?username={user}", token)
        if users:
            uid = users[0]["id"]
            gid = group_map.get(grp)
            if gid:
                # Add user to group
                api_request("PUT", f"/{REALM_NAME}/users/{uid}/groups/{gid}", token)
                print(f"Added {user} to {grp}")

    # 4. Create Client
    print(f"Creating client '{CLIENT_ID}'...")
    api_request("POST", f"/{REALM_NAME}/clients", token, {
        "clientId": CLIENT_ID,
        "enabled": True,
        "clientAuthenticatorType": "client-secret",
        "secret": CLIENT_SECRET,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": True,
        "publicClient": False,
        "protocol": "openid-connect",
    })
    print("Client configured.")
    print("Keycloak setup complete!")


if __name__ == "__main__":
    setup()
