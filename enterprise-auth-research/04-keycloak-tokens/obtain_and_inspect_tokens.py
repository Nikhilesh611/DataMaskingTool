"""Obtain and inspect Keycloak tokens for user Alice (Default Configuration)."""

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


def decode_jwt(jwt_str: str) -> dict:
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header = b64url_decode(parts[0])
    payload = b64url_decode(parts[1])
    return {
        "header": header,
        "payload": payload,
        "signature_raw_length_bytes": len(parts[2]),
    }


def main():
    print(f"Requesting token from {TOKEN_URL} for alice...")
    data = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": "alice",
        "password": "alice123",
        "scope": "openid profile email",
    }).encode("utf-8")
    
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
    
    print("\n=== Token Endpoint Response Keys ===")
    for k, v in res.items():
        if "token" in k:
            print(f"  {k}: [JWT String - length {len(v)} chars]")
        else:
            print(f"  {k}: {v}")
            
    access_token = res["access_token"]
    id_token = res.get("id_token")
    
    acc_decoded = decode_jwt(access_token)
    id_decoded = decode_jwt(id_token) if id_token else None
    
    # Save outputs
    with open("04-keycloak-tokens/token_response_redacted.json", "w") as f:
        redacted_res = dict(res)
        redacted_res["access_token"] = "[REDACTED_ACCESS_TOKEN_JWT]"
        redacted_res["refresh_token"] = "[REDACTED_REFRESH_TOKEN_JWT]"
        if "id_token" in redacted_res:
            redacted_res["id_token"] = "[REDACTED_ID_TOKEN_JWT]"
        json.dump(redacted_res, f, indent=2)
        
    with open("04-keycloak-tokens/access_token_decoded_default.json", "w") as f:
        json.dump(acc_decoded, f, indent=2)
        
    if id_decoded:
        with open("04-keycloak-tokens/id_token_decoded_default.json", "w") as f:
            json.dump(id_decoded, f, indent=2)

    print("\n=== Access Token Header ===")
    print(json.dumps(acc_decoded["header"], indent=2))
    
    print("\n=== Access Token Payload (Default) ===")
    print(json.dumps(acc_decoded["payload"], indent=2))

    print("\n=== Observations ===")
    print("Is 'groups' claim present in access token?:", "groups" in acc_decoded["payload"])
    print("Is 'roles' present in realm_access?:", "realm_access" in acc_decoded["payload"])
    if "realm_access" in acc_decoded["payload"]:
        print("  realm_access.roles:", acc_decoded["payload"]["realm_access"].get("roles"))


if __name__ == "__main__":
    main()
