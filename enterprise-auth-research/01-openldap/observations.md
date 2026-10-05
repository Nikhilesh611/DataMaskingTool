# OpenLDAP Experimental Observations

## Status: OBSERVED (directly tested against OpenLDAP 1.5.0)

---

## Answers to Research Questions

### 1. What does a user entry look like?
**[OBSERVED]** A user entry is an object in the LDAP tree identified by a unique Distinguished Name (DN). It contains multiple `objectClass` values defining its schema, followed by key-value attribute pairs.

```ldif
dn: uid=alice,ou=People,dc=lab,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: Alice Smith
sn: Smith
givenName: Alice
uid: alice
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/alice
mail: alice@lab.local
userPassword:: YWxpY2UxMjM=
```

### 2. What attributes exist?
**[OBSERVED]**
- Structural/Schema: `objectClass`, `dn`
- Identity: `uid` (username), `cn` (common name), `sn` (surname), `givenName`
- Contact/POSIX: `mail`, `uidNumber`, `gidNumber`, `homeDirectory`
- Security: `userPassword` (stores hashed/plain password)

### 3. What is the DN?
**[OBSERVED]** The Distinguished Name (DN) is the unique global hierarchical path to the entry in the LDAP tree:
- Alice: `uid=alice,ou=People,dc=lab,dc=local`
- Bob: `uid=bob,ou=People,dc=lab,dc=local`
- Finance Group: `cn=finance,ou=Groups,dc=lab,dc=local`

### 4. How is the username represented?
**[OBSERVED]** The username is stored in the `uid` attribute (e.g., `uid: alice`) and forms the Relative Distinguished Name (RDN) of the entry (`uid=alice`).

### 5. How is a group represented?
**[OBSERVED]** A group is a separate entry under `ou=Groups,dc=lab,dc=local` with `objectClass: groupOfNames`:
```ldif
dn: cn=finance,ou=Groups,dc=lab,dc=local
objectClass: groupOfNames
cn: finance
member: uid=alice,ou=People,dc=lab,dc=local
```

### 6. How is group membership represented?
**[OBSERVED]** In the standard `groupOfNames` schema, group membership is stored as **multi-valued `member` attributes containing the full DN of member users**.
- **Important**: The user entry (`uid=alice`) does **NOT** contain a list of groups it belongs to! Group membership is stored in the group entry, pointing *to* the user.

### 7. How can we query a user's groups?
**[OBSERVED]** Because users don't store their groups, querying a user's groups requires a **reverse search on the `ou=Groups` subtree** using a filter that matches the user's full DN:
```bash
ldapsearch -b "ou=Groups,dc=lab,dc=local" \
  "(&(objectClass=groupOfNames)(member=uid=alice,ou=People,dc=lab,dc=local))"
```

### 8. What information is returned by LDAP when searching for a user?
**[OBSERVED]** It returns all attributes permitted by access control (excluding or hashing `userPassword`). It does **not** return group membership automatically.

### 9. What happens when searching for a nonexistent user?
**[OBSERVED]** LDAP returns a successful search status code (`result: 0 Success`) with `numEntries: 0` (zero matching entries). No error is thrown.

### 10. What happens when authentication credentials are incorrect?
**[OBSERVED]** The LDAP server rejects the bind operation with:
- Error message: `ldap_bind: Invalid credentials (49)`
- Return code: `49` (`LDAP_INVALID_CREDENTIALS`)
- **Note**: The exact same error code (49) is returned for wrong password and nonexistent user DN to prevent username enumeration.

---

## Key Takeaways for Architecture
- **[OBSERVED]** LDAP is a hierarchical database, not an identity token issuer.
- **[OBSERVED]** LDAP authentication is a synchronous connection-level operation ("Bind").
- **[OBSERVED]** LDAP does **NOT** return a token (no JWT, no session ID, no cookie).
- **[OBSERVED]** Finding user groups requires a 2-step process: (1) Find user DN, (2) Search groups containing that DN as `member`.
