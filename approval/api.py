"""Approval workflow REST API.

Endpoints:
  GET  /approvals          — list pending approval requests
  GET  /approvals/{id}     — get a specific approval request
  PATCH /approvals/{id}    — resolve (approve or deny)

Runs as a standalone FastAPI service. In Docker Compose it is one of the
services agents route REQUIRE_APPROVAL decisions to.
"""

from __future__ import annotations

import os
from uuid import UUID

import redis
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from approval.models import ApprovalRequest, ApprovalResolution, ApprovalStatus
from approval.queue import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
    ApprovalQueue,
    SelfApprovalError,
)

app = FastAPI(
    title="NHI-Sentinel Approval API",
    description="Human approval workflow for REQUIRE_APPROVAL policy decisions",
    version="1.0.0",
)


def _get_queue() -> ApprovalQueue:
    r = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    return ApprovalQueue(r)


class ResolveRequest(BaseModel):
    action: str           # "approve" | "deny"
    approver_identity: str
    reason: str | None = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/approvals", response_model=list[ApprovalRequest])
def list_pending():
    """List all pending approval requests."""
    return _get_queue().list_pending()


@app.get("/approvals/{request_id}", response_model=ApprovalRequest)
def get_approval(request_id: UUID):
    """Get a specific approval request by ID."""
    try:
        return _get_queue().get(request_id)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@app.patch("/approvals/{request_id}", response_model=ApprovalRequest)
def resolve_approval(request_id: UUID, body: ResolveRequest):
    """Resolve an approval request (approve or deny).

    The approver_identity must not be the requesting agent — self-approval is blocked.
    """
    if body.action not in ("approve", "deny"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="action must be 'approve' or 'deny'",
        )

    resolution = ApprovalResolution(
        request_id=request_id,
        action=body.action,
        approver_identity=body.approver_identity,
        reason=body.reason,
    )

    try:
        return _get_queue().resolve(resolution)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ApprovalAlreadyResolvedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except SelfApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
