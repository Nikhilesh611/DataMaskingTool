"""Direct LDAP Authentication Test Client.

Demonstrates the exact enterprise pattern of:
Client -> Application Service -> LDAP Server

1. Looks up the user DN using an administrative/service search.
2. Binds (authenticates) using the user's DN and password.
3. If bind succeeds, performs a second search for group memberships.
4. Returns the user attributes + groups to the application.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional
from ldap3 import ALL, Connection, Server


LDAP_SERVER_URI = "ldap://localhost:389"
BASE_DN = "dc=lab,dc=local"
USERS_OU = "ou=People,dc=lab,dc=local"
GROUPS_OU = "ou=Groups,dc=lab,dc=local"

# Service account for searching (in production this would be a readonly service account)
ADMIN_DN = "cn=admin,dc=lab,dc=local"
ADMIN_PASSWORD = "adminpassword"


def authenticate_user(username: str, password: str) -> Dict[str, Any]:
    """Perform direct 2-step LDAP authentication and group discovery."""
    server = Server(LDAP_SERVER_URI, get_info=ALL)
    
    # Step 1: Search for user DN using service account
    conn = Connection(server, user=ADMIN_DN, password=ADMIN_PASSWORD, auto_bind=True)
    
    search_filter = f"(uid={username})"
    conn.search(
        search_base=USERS_OU,
        search_filter=search_filter,
        attributes=["cn", "sn", "givenName", "mail", "uid", "uidNumber", "gidNumber"],
    )
    
    if not conn.entries:
        conn.unbind()
        return {
            "authenticated": False,
            "error": "User not found in directory",
            "error_code": "USER_NOT_FOUND",
        }
    
    user_entry = conn.entries[0]
    user_dn = user_entry.entry_dn
    user_attributes = json.loads(user_entry.entry_to_json())["attributes"]
    conn.unbind()
    
    # Step 2: Attempt Simple Bind with user credentials
    user_conn = Connection(server, user=user_dn, password=password)
    bind_success = user_conn.bind()
    
    if not bind_success:
        result = user_conn.result
        user_conn.unbind()
        return {
            "authenticated": False,
            "error": "Invalid credentials",
            "ldap_result_code": result.get("result"),
            "ldap_description": result.get("description"),
            "error_code": "INVALID_CREDENTIALS",
        }
    
    user_conn.unbind()
    
    # Step 3: Retrieve group memberships using service search
    group_conn = Connection(server, user=ADMIN_DN, password=ADMIN_PASSWORD, auto_bind=True)
    group_filter = f"(&(objectClass=groupOfNames)(member={user_dn}))"
    group_conn.search(
        search_base=GROUPS_OU,
        search_filter=group_filter,
        attributes=["cn"],
    )
    
    groups: List[str] = [str(g.cn) for g in group_conn.entries]
    group_conn.unbind()
    
    return {
        "authenticated": True,
        "dn": user_dn,
        "username": username,
        "attributes": user_attributes,
        "groups": groups,
        "token_returned_by_ldap": None,  # Note: LDAP protocol does NOT return a token!
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python ldap_auth_client.py <username> <password>")
        sys.exit(1)
    
    res = authenticate_user(sys.argv[1], sys.argv[2])
    print(json.dumps(res, indent=2))
