"""Test Keycloak Token Introspection Endpoint (RFC 7662)."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Tuple, Dict, Any

INTROSPECT_URL = "http://localhost:8081/realms/lab-realm/protocol/openid-connect/token/introspect"
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


def introspect_token(token: str, client_id=CLIENT_ID, client_secret=CLIENT_SECRET) -> Tuple[int, Dict[str, Any]]:
    data_dict = {"token": token}
    if client_id:
        data_dict["client_id"] = client_id
    if client_secret:
        data_dict["client_secret"] = client_secret
    
    data = urllib.parse.urlencode(data_dict).encode("utf-8")
    req = urllib.request.Request(INTROSPECT_URL, data=data, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.reason}


def main():
    print("1. Introspecting VALID token with Client Authentication...")
    valid_token = get_token("alice", "alice123")
    status, res = introspect_token(valid_token)
    print(f"Status: {status}")
    print("Introspection Result:\n", json.dumps(res, indent=2))
    
    with open("06-keycloak-introspection/introspection_response.json", "w") as f:
        json.dump(res, f, indent=2)

    print("\n2. Introspecting INVALID / FAKE token...")
    status_fake, res_fake = introspect_token("fake.token.string")
    print(f"Status: {status_fake}")
    print("Introspection Result (Fake Token):", json.dumps(res_fake, indent=2))

    print("\n3. Introspecting WITHOUT client authentication (missing secret)...")
    status_unauth, res_unauth = introspect_token(valid_token, client_id=CLIENT_ID, client_secret=None)
    print(f"Status (Unauthenticated Client): {status_unauth}")
    print("Response:", json.dumps(res_unauth, indent=2))


if __name__ == "__main__":
    main()
