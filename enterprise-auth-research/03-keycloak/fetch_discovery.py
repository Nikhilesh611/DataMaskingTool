"""Fetch and parse Keycloak OIDC Discovery document."""

import json
import urllib.request

url = "http://localhost:8081/realms/lab-realm/.well-known/openid-configuration"
with urllib.request.urlopen(url) as resp:
    data = json.loads(resp.read().decode("utf-8"))

# Save full document
with open("03-keycloak/openid-configuration.json", "w") as f:
    json.dump(data, f, indent=2)

print("Saved openid-configuration.json")
print("Issuer:", data.get("issuer"))
print("Authorization Endpoint:", data.get("authorization_endpoint"))
print("Token Endpoint:", data.get("token_endpoint"))
print("UserInfo Endpoint:", data.get("userinfo_endpoint"))
print("JWKS Endpoint:", data.get("jwks_uri"))
print("Introspection Endpoint:", data.get("introspection_endpoint"))
print("Scopes Supported:", data.get("scopes_supported"))
print("Claims Supported:", data.get("claims_supported"))
