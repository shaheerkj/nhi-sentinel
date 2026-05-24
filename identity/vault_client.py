"""Vault PKI integration for agent key management."""

from __future__ import annotations

import logging

import httpx

from identity.config import Settings

logger = logging.getLogger(__name__)


class VaultClient:
    def __init__(self, settings: Settings) -> None:
        self._base = settings.vault_addr
        self._headers = {"X-Vault-Token": settings.vault_token}
        self._pki_mount = settings.vault_pki_mount
        self._secrets_mount = settings.vault_secrets_mount

    def _url(self, path: str) -> str:
        return f"{self._base}/v1/{path}"

    # ------------------------------------------------------------------
    # Key storage (KV v2)
    # ------------------------------------------------------------------

    def write_agent_keypair(self, agent_id: str, private_key_pem: str, public_key_pem: str) -> None:
        path = f"{self._secrets_mount}/data/agents/{agent_id}/keypair"
        resp = httpx.put(
            self._url(path),
            headers=self._headers,
            json={"data": {"private_key": private_key_pem, "public_key": public_key_pem}},
        )
        resp.raise_for_status()
        logger.info("Stored keypair for agent %s in Vault", agent_id)

    def read_agent_private_key(self, agent_id: str) -> str:
        path = f"{self._secrets_mount}/data/agents/{agent_id}/keypair"
        resp = httpx.get(self._url(path), headers=self._headers)
        resp.raise_for_status()
        return resp.json()["data"]["data"]["private_key"]

    def read_agent_public_key(self, agent_id: str) -> str:
        path = f"{self._secrets_mount}/data/agents/{agent_id}/keypair"
        resp = httpx.get(self._url(path), headers=self._headers)
        resp.raise_for_status()
        return resp.json()["data"]["data"]["public_key"]

    def delete_agent_keypair(self, agent_id: str) -> None:
        path = f"{self._secrets_mount}/metadata/agents/{agent_id}/keypair"
        resp = httpx.delete(self._url(path), headers=self._headers)
        resp.raise_for_status()
        logger.info("Deleted keypair for agent %s from Vault", agent_id)

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def is_healthy(self) -> bool:
        try:
            resp = httpx.get(self._url("sys/health"), headers=self._headers, timeout=3)
            return resp.status_code in (200, 429, 472, 473)
        except httpx.RequestError:
            return False
