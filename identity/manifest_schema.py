from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


class AgentType(str, Enum):
    INFRA = "InfraAgent"
    DATA = "DataAgent"
    SECOPS = "SecOpsAgent"
    PROVISIONER = "ProvisionerAgent"


class RotationPolicy(str, Enum):
    AUTOMATIC = "automatic"
    MANUAL = "manual"


class TimeWindow(BaseModel):
    start_hour_utc: Annotated[int, Field(ge=0, le=23)]
    end_hour_utc: Annotated[int, Field(ge=0, le=23)]


class ContextBindings(BaseModel):
    environments: list[str]
    time_window: TimeWindow | None = None
    source_networks: list[str] = Field(default_factory=list)
    max_actions_per_minute: Annotated[int, Field(gt=0)] = 30


class ApprovalTrigger(BaseModel):
    risk_level: str | None = None
    action_patterns: list[str] = Field(default_factory=list)


class AgentIdentitySpec(BaseModel):
    agent_type: AgentType
    owner_team: str
    owner_contact: str

    credential_ttl_days: Annotated[int, Field(gt=0, le=365)] = 90
    rotation_policy: RotationPolicy = RotationPolicy.AUTOMATIC
    rotation_days_before_expiry: Annotated[int, Field(gt=0)] = 14

    scopes: list[str] = Field(default_factory=list)
    allowed_resource_patterns: list[str] = Field(default_factory=list)
    blocked_resource_patterns: list[str] = Field(default_factory=list)

    context_bindings: ContextBindings
    approval_required_for: list[ApprovalTrigger] = Field(default_factory=list)

    @field_validator("scopes")
    @classmethod
    def scopes_must_be_namespaced(cls, v: list[str]) -> list[str]:
        for scope in v:
            if ":" not in scope:
                raise ValueError(f"Scope '{scope}' must be namespaced (e.g. cloud:s3:read)")
        return v


class AgentIdentityMetadata(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$")
    namespace: str
    labels: dict[str, str] = Field(default_factory=dict)


class AgentIdentityManifest(BaseModel):
    """Declarative identity manifest — the source of truth for an NHI."""

    api_version: str = Field(alias="apiVersion", default="nhi-sentinel/v1")
    kind: str = "AgentIdentity"
    metadata: AgentIdentityMetadata
    spec: AgentIdentitySpec

    model_config = {"populate_by_name": True}

    @field_validator("kind")
    @classmethod
    def kind_must_be_agent_identity(cls, v: str) -> str:
        if v != "AgentIdentity":
            raise ValueError(f"kind must be 'AgentIdentity', got '{v}'")
        return v


class IdentityState(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ACTIVE = "ACTIVE"
    EXPIRING = "EXPIRING"
    EXPIRED = "EXPIRED"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class ActiveIdentityRecord(BaseModel):
    """Runtime record stored in the Identity Registry (PostgreSQL)."""

    identity_id: str
    agent_type: AgentType
    owner_team: str
    state: IdentityState
    keycloak_client_id: str
    vault_path: str
    manifest_git_sha: str
    created_at: datetime
    expires_at: datetime
    last_attested_at: datetime | None = None
    scopes: list[str] = Field(default_factory=list)
