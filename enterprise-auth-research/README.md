# Enterprise Auth Research Lab

## Prerequisites
- Docker Desktop (running)

## Quick Start

```bash
# Start all services
docker compose up -d

# Check status
docker compose ps
```

## Services

| Service | URL / Address | Credentials |
|---|---|---|
| OpenLDAP | `ldap://localhost:389` | Admin DN: `cn=admin,dc=lab,dc=local` / Password: `adminpassword` |
| Keycloak | `http://localhost:8081` | Username: `admin` / Password: `admin` |
| Vault | `http://localhost:8200` | Root Token: `dev-root-token` |

## Seed Data (OpenLDAP)

| User | Password | Group |
|---|---|---|
| `alice` (uid=alice,ou=People,dc=lab,dc=local) | `alice123` | `finance` |
| `bob` (uid=bob,ou=People,dc=lab,dc=local) | `bob123` | `security` |

## Lab Management

```bash
# Stop
docker compose down

# Reset (destroy all data)
docker compose down -v
```
