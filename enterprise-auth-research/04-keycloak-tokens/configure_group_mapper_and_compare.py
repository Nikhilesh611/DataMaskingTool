"""Configure Keycloak Group Mapper and compare tokens before and after."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from obtain_and_inspect_tokens import decode_jwt

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
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def add_group_mapper():
    token = get_admin_token()
    
    # 1. Find client UUID
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients?clientId={CLIENT_ID}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        client_uuid = json.loads(resp.read().decode("utf-8"))[0]["id"]
        
    print(f"Client UUID: {client_uuid}")
    
    # 2. Add Group Membership Protocol Mapper
    mapper_url = f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients/{client_uuid}/protocol-mappers/models"
    mapper_payload = {
        "name": "group-membership-mapper",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-group-membership-mapper",
        "consentRequired": False,
        "config": {
            "full.path": "false",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "claim.name": "groups",
            "jsonType.label": "String",
        },
    }
    
    req = urllib.request.Request(
        mapper_url,
        data=json.dumps(mapper_payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        print("Group mapper added successfully! Status:", resp.status)


def get_alice_token():
    token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": "alice",
        "password": "alice123",
        "scope": "openid profile email",
    }).encode("utf-8")
    req = urllib.request.Request(token_url, data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    print("Adding Group Membership mapper to Keycloak client...")
    add_group_mapper()
    
    print("\nObtaining NEW token for Alice with mapper active...")
    res = get_alice_token()
    
    acc_jwt = res["access_token"]
    id_jwt = res["id_token"]
    
    acc_decoded = decode_jwt(acc_jwt)
    id_decoded = decode_jwt(id_jwt)
    
    with open("04-keycloak-tokens/access_token_decoded_with_groups.json", "w") as f:
        json.dump(acc_decoded, f, indent=2)
        
    with open("04-keycloak-tokens/id_token_decoded_with_groups.json", "w") as f:
        json.dump(id_decoded, f, indent=2)
        
    print("\n=== Access Token Payload (AFTER MAPPER) ===")
    print("groups claim:", acc_decoded["payload"].get("groups"))
    print("preferred_username:", acc_decoded["payload"].get("preferred_username"))
    
    print("\n=== ID Token Payload (AFTER MAPPER) ===")
    print("groups claim:", id_decoded["payload"].get("groups"))
    print("preferred_username:", id_decoded["payload"].get("preferred_username"))


if __name__ == "__main__":
    main()
