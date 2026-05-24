from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Keycloak
    keycloak_url: str = "http://localhost:8080"
    keycloak_realm: str = "nhi"
    keycloak_admin_user: str = "admin"
    keycloak_admin_password: str = "admin"

    # Vault
    vault_addr: str = "http://localhost:8200"
    vault_token: str = "dev-root-token"
    vault_pki_mount: str = "pki"
    vault_secrets_mount: str = "secret"

    # Identity registry
    postgres_dsn: str = "postgresql+asyncpg://audit_user:changeme@localhost:5432/audit"

    # Token properties
    token_ttl_seconds: int = 900       # 15 minutes
    assertion_ttl_seconds: int = 60    # JWT Bearer assertion window

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
