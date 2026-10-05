# OpenLDAP Commands Used in Experiments

## Status: OBSERVED

### 1. Search Entire Directory
```bash
docker exec lab-openldap ldapsearch -x -H ldap://localhost:389 \
  -b "dc=lab,dc=local" \
  -D "cn=admin,dc=lab,dc=local" \
  -w [REDACTED] "(objectclass=*)"
```

### 2. Search Specific User by UID
```bash
docker exec lab-openldap ldapsearch -x -H ldap://localhost:389 \
  -b "ou=People,dc=lab,dc=local" \
  -D "cn=admin,dc=lab,dc=local" \
  -w [REDACTED] "(uid=alice)"
```

### 3. Search Nonexistent User
```bash
docker exec lab-openldap ldapsearch -x -H ldap://localhost:389 \
  -b "ou=People,dc=lab,dc=local" \
  -D "cn=admin,dc=lab,dc=local" \
  -w [REDACTED] "(uid=charlie)"
```

### 4. Search All Groups
```bash
docker exec lab-openldap ldapsearch -x -H ldap://localhost:389 \
  -b "ou=Groups,dc=lab,dc=local" \
  -D "cn=admin,dc=lab,dc=local" \
  -w [REDACTED] "(objectClass=groupOfNames)"
```

### 5. Query User's Groups (Reverse Membership Lookup)
```bash
docker exec lab-openldap ldapsearch -x -H ldap://localhost:389 \
  -b "ou=Groups,dc=lab,dc=local" \
  -D "cn=admin,dc=lab,dc=local" \
  -w [REDACTED] "(&(objectClass=groupOfNames)(member=uid=alice,ou=People,dc=lab,dc=local))"
```

### 6. Authentication via Simple Bind (ldapwhoami)
```bash
# Correct credentials
docker exec lab-openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "uid=alice,ou=People,dc=lab,dc=local" -w [REDACTED]

# Incorrect password
docker exec lab-openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "uid=alice,ou=People,dc=lab,dc=local" -w [WRONG]

# Nonexistent user
docker exec lab-openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "uid=charlie,ou=People,dc=lab,dc=local" -w [PASSWORD]
```
