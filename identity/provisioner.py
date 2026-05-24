"""Provision Keycloak service principals from AgentIdentityManifest.

This is the identity provisioner — it reads a manifest YAML and:
  1. Generates an RSA keypair
  2. Stores the private key in Vault
  3. Creates a Keycloak client (service principal) with the public key registered
  4. Writes the identity record to the local registry

Run via: python -m identity.cli provision <manifest.yaml>
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx
import yaml

from identity.config import Settings
from identity.manifest_schema import (
    ActiveIdentityRecord,
    AgentIdentityManifest,
    IdentityState,
)
from identity.token_manager import generate_rsa_keypair
from identity.vault_client import VaultClient

logger = logging.getLogger(__name__)


class KeycloakAdmin:
    """Thin wrapper around the Keycloak Admin REST API."""

    def __init__(self, settings: Settings) -> None:
        self._base = f"{settings.keycloak_url}/admin/realms/{settings.keycloak_realm}"
        self._token = self._get_admin_token(settings)

    def _get_admin_token(self, settings: Settings) -> str:
        resp = httpx.post(
            f"{settings.keycloak_url}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": settings.keycloak_admin_user,
                "password": settings.keycloak_admin_password,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    @property
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def create_client(self, client_id: str, public_key_pem: str) -> None:
        """Create a Keycloak client configured for JWT Bearer (Signed JWT) authentication."""
        # Strip PEM headers for Keycloak's JWKS format
        key_value = (
            public_key_pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\n", "")
            .strip()
        )

        payload = {
            "clientId": client_id,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "clientAuthenticatorType": "client-jwt",
            "attributes": {
                "jwt.credential.public.key": key_value,
                "use.jwks.url": "false",
                "token.endpoint.auth.signing.alg": "RS256",
            },
        }

        resp = httpx.post(f"{self._base}/clients", headers=self._headers, json=payload)
        if resp.status_code == 409:
            logger.warning("Client %s already exists in Keycloak", client_id)
            return
        resp.raise_for_status()
        logger.info("Created Keycloak client for %s", client_id)

    def suspend_client(self, client_id: str) -> None:
        kc_id = self._get_client_uuid(client_id)
        resp = httpx.put(
            f"{self._base}/clients/{kc_id}",
            headers=self._headers,
            json={"enabled": False},
        )
        resp.raise_for_status()
        logger.info("Suspended Keycloak client %s", client_id)

    def delete_client(self, client_id: str) -> None:
        kc_id = self._get_client_uuid(client_id)
        resp = httpx.delete(f"{self._base}/clients/{kc_id}", headers=self._headers)
        resp.raise_for_status()
        logger.info("Deleted Keycloak client %s", client_id)

    def _get_client_uuid(self, client_id: str) -> str:
        resp = httpx.get(
            f"{self._base}/clients",
            headers=self._headers,
            params={"clientId": client_id},
        )
        resp.raise_for_status()
        clients = resp.json()
        if not clients:
            raise ValueError(f"Client '{client_id}' not found in Keycloak")
        return clients[0]["id"]


class IdentityProvisioner:
    """Orchestrates the full provisioning flow from manifest to active identity."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._vault = VaultClient(settings)
        self._keycloak = KeycloakAdmin(settings)

    def provision(self, manifest_path: str) -> ActiveIdentityRecord:
        manifest = self._load_manifest(manifest_path)
        agent_id = manifest.metadata.name

        logger.info("Provisioning identity for %s", agent_id)

        # 1. Generate RSA keypair
        private_pem, public_pem = generate_rsa_keypair()

        # 2. Store in Vault
        vault_path = f"agents/{agent_id}/keypair"
        self._vault.write_agent_keypair(agent_id, private_pem, public_pem)

        # 3. Register service principal in Keycloak
        self._keycloak.create_client(agent_id, public_pem)

        # 4. Build identity record
        now = datetime.now(tz=timezone.utc)
        expires_at = now + timedelta(days=manifest.spec.credential_ttl_days)

        record = ActiveIdentityRecord(
            identity_id=agent_id,
            agent_type=manifest.spec.agent_type,
            owner_team=manifest.spec.owner_team,
            state=IdentityState.ACTIVE,
            keycloak_client_id=agent_id,
            vault_path=vault_path,
            manifest_git_sha="local",  # replaced by CI with actual sha
            created_at=now,
            expires_at=expires_at,
            scopes=manifest.spec.scopes,
        )

        logger.info(
            "Identity provisioned: %s (expires %s)",
            agent_id,
            expires_at.date(),
        )
        return record

    @staticmethod
    def _load_manifest(path: str) -> AgentIdentityManifest:
        with open(path) as f:
            data = yaml.safe_load(f)
        return AgentIdentityManifest.model_validate(data)
