"""Test Machine-to-Machine (Service Account / Client Credentials) Authentication."""

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request

TOKEN_URL = "http://localhost:8081/realms/lab-realm/protocol/openid-connect/token"
CLIENT_ID = "lab-client"
CLIENT_SECRET = "lab-client-secret-12345"


def b64url_decode(part: str) -> dict:
    rem = len(part) % 4
    if rem > 0:
        part += "=" * (4 - rem)
    return json.loads(base64.urlsafe_b64decode(part.encode("utf-8")).decode("utf-8"))


def main():
    print(f"Requesting Machine-to-Machine token via Client Credentials grant from {TOKEN_URL}...")
    data = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials",
    }).encode("utf-8")
    
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        
    access_token = res["access_token"]
    parts = access_token.split(".")
    header = b64url_decode(parts[0])
    payload = b64url_decode(parts[1])
    
    decoded = {
        "header": header,
        "payload": payload,
        "raw_response_keys": list(res.keys()),
    }
    
    with open("08-service-identity/service_token_decoded.json", "w") as f:
        json.dump(decoded, f, indent=2)
        
    print("\n=== Service Account Token Header ===")
    print(json.dumps(header, indent=2))
    
    print("\n=== Service Account Token Payload ===")
    print(json.dumps(payload, indent=2))
    
    print("\n=== Key Observations ===")
    print("Subject (`sub`):", payload.get("sub"))
    print("Client ID (`azp` / `clientId`):", payload.get("azp"), "/", payload.get("clientId"))
    print("Preferred Username:", payload.get("preferred_username"))
    print("Email Present?:", "email" in payload)
    print("Groups Present?:", "groups" in payload)
    print("Realm Roles:", payload.get("realm_access", {}).get("roles"))


if __name__ == "__main__":
    main()
