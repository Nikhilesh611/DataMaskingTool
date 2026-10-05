"""Test Keycloak UserInfo endpoint with valid and invalid tokens."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Tuple, Dict, Any

USERINFO_URL = "http://localhost:8081/realms/lab-realm/protocol/openid-connect/userinfo"
TOKEN_URL = "http://localhost:8081/realms/lab-realm/protocol/openid-connect/token"
CLIENT_ID = "lab-client"
CLIENT_SECRET = "lab-client-secret-12345"


def get_token(username="alice", password="alice123") -> str:
    data = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid profile email",
    }).encode("utf-8")
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def call_userinfo(token: str | None) -> Tuple[int, Dict[str, Any]]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(USERINFO_URL, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.reason}


def main():
    print("1. Testing UserInfo WITH valid Bearer token...")
    token = get_token("alice", "alice123")
    status, res = call_userinfo(token)
    print(f"Status: {status}")
    print("Response:", json.dumps(res, indent=2))
    
    with open("05-keycloak-userinfo/userinfo_response.json", "w") as f:
        json.dump(res, f, indent=2)

    print("\n2. Testing UserInfo WITHOUT token...")
    status_no_auth, res_no_auth = call_userinfo(None)
    print(f"Status (no auth): {status_no_auth}")

    print("\n3. Testing UserInfo with INVALID token...")
    status_bad_auth, res_bad_auth = call_userinfo("invalid.bearer.token")
    print(f"Status (bad auth): {status_bad_auth}")


if __name__ == "__main__":
    main()
