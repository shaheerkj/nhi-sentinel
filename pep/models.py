from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ActionRequest(BaseModel):
    """Sent to OPA for every tool call before execution."""

    agent_id: str
    agent_type: str
    token_claims: dict[str, Any]
    action: str                       # e.g. "s3:GetObject"
    resource_arn: str                 # e.g. "arn:aws:s3:::my-bucket/key"
    task_id: str
    environment: str
    source_ip: str
    resource_tags: dict[str, str] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class ConditionResult(BaseModel):
    name: str
    result: bool
    detail: str | None = None


class PolicyDecision(BaseModel):
    """Structured decision returned by OPA."""

    effect: Decision
    reason: str
    policy_ref: str
    policy_version: str
    evaluated_at: str
    conditions_evaluated: list[ConditionResult] = Field(default_factory=list)
