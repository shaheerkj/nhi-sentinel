#!/bin/bash
# Keycloak realm initializer — creates the 'nhi' realm via Admin REST API.
set -e

KEYCLOAK_URL="http://keycloak:8080"
ADMIN_USER="admin"
ADMIN_PASS="admin"
REALM="nhi"

echo "Waiting for Keycloak Admin API..."
until curl -sf "${KEYCLOAK_URL}/realms/master" > /dev/null 2>&1; do
    sleep 2
done

echo "Acquiring admin token..."
ACCESS_TOKEN=$(curl -sf -X POST \
    "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=${ADMIN_USER}" \
    -d "password=${ADMIN_PASS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Creating realm '${REALM}'..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${KEYCLOAK_URL}/admin/realms" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "realm": "'"${REALM}"'",
        "enabled": true,
        "accessTokenLifespan": 900,
        "ssoSessionMaxLifespan": 900,
        "clientAuthenticationFlow": "clients",
        "bruteForceProtected": true
    }')

if [ "$HTTP_STATUS" = "201" ]; then
    echo "Realm '${REALM}' created successfully."
elif [ "$HTTP_STATUS" = "409" ]; then
    echo "Realm '${REALM}' already exists — skipping."
else
    echo "Unexpected status creating realm: ${HTTP_STATUS}"
    exit 1
fi

echo "Keycloak initialization complete."
