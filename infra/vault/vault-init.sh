#!/bin/sh
# Vault initializer — runs once after Vault starts in dev mode.
# Enables the KV v2 secrets engine for agent key storage.
set -e

echo "Waiting for Vault to be ready..."
until vault status -address=http://vault:8200 > /dev/null 2>&1; do
    sleep 1
done

echo "Enabling KV v2 secrets engine at 'secret/'..."
vault secrets enable -address=http://vault:8200 -path=secret kv-v2 2>/dev/null || echo "KV v2 already enabled"

echo "Creating agent key storage policy..."
vault policy write -address=http://vault:8200 agent-key-policy - <<EOF
path "secret/data/agents/*" {
    capabilities = ["create", "read", "update"]
}
path "secret/metadata/agents/*" {
    capabilities = ["read", "delete", "list"]
}
EOF

echo "Vault initialization complete."
