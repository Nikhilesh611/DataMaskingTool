# Direct LDAP Authentication Observations

## Status: OBSERVED (directly tested via Python client against local OpenLDAP)

---

## Answers to Research Questions

### 1. Where does authentication happen?
**[OBSERVED]** Authentication happens directly on the **LDAP server** during the `bind()` operation over the LDAP TCP connection (port 389/636). The application does not verify the password hash itself; it submits the DN and password to LDAP and LDAP returns a success/failure status.

### 2. What does LDAP return after successful authentication?
**[OBSERVED]** LDAP returns a boolean success status (LDAP result code `0 Success`). It returns **NO data, NO tokens, and NO user attributes** in the bind response. The bind response only confirms that the connection is now authenticated.

### 3. Does LDAP itself return a "token"?
**[OBSERVED]** **NO.** The LDAP protocol (RFC 4511) has zero concept of tokens, JWTs, bearer tokens, or sessions. Once a connection binds, the *TCP socket itself* is in an authenticated state for subsequent LDAP operations on that specific connection.

### 4. Does LDAP return groups?
**[OBSERVED]** **NO, not automatically.** The user entry does not contain group attributes. To get groups, the application must make a **second, separate LDAP search query** on `ou=Groups` looking for `member=<user_dn>`.

### 5. How does the application learn group membership?
**[OBSERVED]** The application executes a 3-step sequence:
1. **Search**: Query `ou=People` for `(uid=<username>)` using a service account to discover the user's full DN (`uid=alice,ou=People,dc=lab,dc=local`).
2. **Bind**: Open a connection and bind as the user DN with the user's password.
3. **Group Search**: Query `ou=Groups` with filter `(&(objectClass=groupOfNames)(member=<user_dn>))` to find all groups containing the user's DN.

### 6. What information would a service consuming LDAP actually receive?
**[OBSERVED]** A service integrating directly with LDAP receives:
- User DN (`uid=alice,ou=People,dc=lab,dc=local`)
- User profile attributes (`cn`, `mail`, `givenName`, `sn`, `uidNumber`)
- Group names from the reverse group search (`["finance"]`)
- **Nothing else**: No signature, no expiration timestamp, no portable token that can be passed downstream to another microservice!

---

## Critical Architectural Implications

| Feature | Direct LDAP Reality | Impact on Distributed Architecture |
|---|---|---|
| **Downstream Propagation** | No portable credential | A downstream microservice cannot verify the caller's identity without either re-checking LDAP with user credentials or relying on a trusted perimeter. |
| **Credential Exposure** | Raw user password must pass through application | The application must handle raw user credentials to bind against LDAP. |
| **Network Traffic** | 2-3 LDAP roundtrips per login | High latency under heavy login load; requires connection pooling. |
| **Authorization** | Application must map LDAP group strings to local permissions | Authorization logic is entirely custom within each application consuming LDAP. |
