from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ApprovalRequest(BaseModel):
    request_id: UUID
    agent_id: str
    action: str
    resource_arn: str
    task_id: str
    policy_ref: str
    risk_level: RiskLevel
    requested_at: datetime
    expires_at: datetime
    requesting_token_jti: str
    context: dict = {}
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver_identity: str | None = None
    resolved_at: datetime | None = None


class ApprovalResolution(BaseModel):
    request_id: UUID
    action: str                    # "approve" | "deny"
    approver_identity: str
    reason: str | None = None
