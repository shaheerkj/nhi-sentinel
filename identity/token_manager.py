"""RFC 7523 JWT Bearer Assertion token acquisition.

Flow:
  1. Load private key from disk (injected by Vault Agent sidecar) or Vault directly
  2. Build a signed JWT assertion (iss=agent_id, aud=keycloak_token_endpoint, exp=now+60s, jti=uuid4)
  3. POST to Keycloak token endpoint with grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
  4. Return the short-lived access token (TTL 15 min)
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from identity.config import Settings

logger = logging.getLogger(__name__)

_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class TokenManager:
    """Acquires short-lived access tokens from Keycloak using RFC 7523."""

    def __init__(self, agent_id: str, settings: Settings) -> None:
        self._agent_id = agent_id
        self._settings = settings
        self._token_endpoint = (
            f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
            "/protocol/openid-connect/token"
        )
        self._private_key_pem: str | None = None
        self._cached_token: str | None = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------

    def load_key_from_file(self, path: str | Path) -> None:
        """Load private key injected by Vault Agent sidecar."""
        self._private_key_pem = Path(path).read_text()
        logger.debug("Loaded private key from %s", path)

    def load_key_from_string(self, pem: str) -> None:
        self._private_key_pem = pem

    # ------------------------------------------------------------------
    # Token acquisition
    # ------------------------------------------------------------------

    def get_token(self, task_id: str, environment: str, source_ip: str) -> str:
        """Return a valid access token, re-acquiring if expired or not yet held."""
        # Leave a 30-second buffer before actual expiry to avoid using a nearly-expired token
        if self._cached_token and time.time() < self._token_expires_at - 30:
            return self._cached_token

        self._cached_token = self._acquire_token(task_id, environment, source_ip)
        self._token_expires_at = time.time() + self._settings.token_ttl_seconds
        return self._cached_token

    def _acquire_token(self, task_id: str, environment: str, source_ip: str) -> str:
        if not self._private_key_pem:
            raise RuntimeError("Private key not loaded. Call load_key_from_file() first.")

        assertion = self._build_assertion(task_id, environment, source_ip)

        resp = httpx.post(
            self._token_endpoint,
            data={
                "grant_type": _JWT_BEARER_GRANT,
                "assertion": assertion,
                "client_id": self._agent_id,
            },
            timeout=10,
        )

        if resp.status_code != 200:
            logger.error(
                "Token acquisition failed for %s: %s %s",
                self._agent_id,
                resp.status_code,
                resp.text,
            )
            raise TokenAcquisitionError(
                f"Keycloak returned {resp.status_code}: {resp.text}"
            )

        token = resp.json()["access_token"]
        logger.info("Acquired token for agent %s (task=%s)", self._agent_id, task_id)
        return token

    def _build_assertion(self, task_id: str, environment: str, source_ip: str) -> str:
        now = int(time.time())
        payload = {
            "iss": self._agent_id,
            "sub": self._agent_id,
            "aud": self._token_endpoint,
            "iat": now,
            "exp": now + self._settings.assertion_ttl_seconds,
            "jti": str(uuid.uuid4()),
            "agent_context": {
                "task_id": task_id,
                "environment": environment,
                "source_ip": source_ip,
            },
        }
        return jwt.encode(payload, self._private_key_pem, algorithm="RS256")

    # ------------------------------------------------------------------
    # Introspection (called by PEP on every action, not cached)
    # ------------------------------------------------------------------

    def introspect(self, token: str) -> dict:
        """Ask Keycloak whether a token is currently active."""
        resp = httpx.post(
            self._token_endpoint.replace("/token", "/introspect"),
            data={
                "token": token,
                "client_id": self._agent_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": self._build_introspect_assertion(),
            },
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()

    def _build_introspect_assertion(self) -> str:
        now = int(time.time())
        payload = {
            "iss": self._agent_id,
            "sub": self._agent_id,
            "aud": self._token_endpoint.replace("/token", "/introspect"),
            "iat": now,
            "exp": now + 30,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, self._private_key_pem, algorithm="RS256")


# ------------------------------------------------------------------
# Key generation utility (used by provisioner, not by agent runtime)
# ------------------------------------------------------------------

def generate_rsa_keypair() -> tuple[str, str]:
    """Return (private_key_pem, public_key_pem) for a new 2048-bit RSA keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


class TokenAcquisitionError(Exception):
    pass
