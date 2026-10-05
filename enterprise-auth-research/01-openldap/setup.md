# OpenLDAP Experiment Setup

## Status: OBSERVED (directly tested with OpenLDAP 1.5.0 container)

## Environment
- **Docker Image**: `osixia/openldap:1.5.0`
- **Base DN**: `dc=lab,dc=local`
- **Admin DN**: `cn=admin,dc=lab,dc=local`
- **Admin Password**: `[REDACTED]`
- **Directory Structure**:
  - `ou=People,dc=lab,dc=local` (User container)
  - `ou=Groups,dc=lab,dc=local` (Group container)

## Seed Data Loaded

### Users (`inetOrgPerson`, `posixAccount`, `shadowAccount`)
1. **Alice Smith**
   - DN: `uid=alice,ou=People,dc=lab,dc=local`
   - Attributes: `cn: Alice Smith`, `sn: Smith`, `givenName: Alice`, `uid: alice`, `uidNumber: 1001`, `gidNumber: 1001`, `homeDirectory: /home/alice`, `mail: alice@lab.local`
2. **Bob Jones**
   - DN: `uid=bob,ou=People,dc=lab,dc=local`
   - Attributes: `cn: Bob Jones`, `sn: Jones`, `givenName: Bob`, `uid: bob`, `uidNumber: 1002`, `gidNumber: 1002`, `homeDirectory: /home/bob`, `mail: bob@lab.local`

### Groups (`groupOfNames`)
1. **finance**
   - DN: `cn=finance,ou=Groups,dc=lab,dc=local`
   - Member: `uid=alice,ou=People,dc=lab,dc=local`
2. **security**
   - DN: `cn=security,ou=Groups,dc=lab,dc=local`
   - Member: `uid=bob,ou=People,dc=lab,dc=local`
