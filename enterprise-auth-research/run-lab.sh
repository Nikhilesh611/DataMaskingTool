#!/bin/bash
# Start the enterprise auth research lab
set -e
cd "$(dirname "$0")"
echo "Starting lab infrastructure (OpenLDAP + Keycloak + Vault)..."
docker compose up -d
echo ""
echo "Waiting for services to start..."
sleep 10
echo ""
echo "=== Lab Status ==="
docker compose ps
echo ""
echo "=== Access Points ==="
echo "  OpenLDAP:  ldap://localhost:389   (admin DN: cn=admin,dc=lab,dc=local / password: adminpassword)"
echo "  Keycloak:  http://localhost:8081  (admin / admin)"
echo "  Vault:     http://localhost:8200  (token: dev-root-token)"
echo ""
echo "Lab is ready."
