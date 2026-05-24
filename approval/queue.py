"""Redis-backed approval queue.

Pending approvals are stored in Redis with a TTL matching the request expiry.
A secondary set tracks all pending request IDs so operators can list them.
The queue is the source of truth — approved/denied requests are also persisted
to PostgreSQL (via the audit consumer) for durable record-keeping.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from approval.models import ApprovalRequest, ApprovalResolution, ApprovalStatus, RiskLevel

logger = logging.getLogger(__name__)

_KEY_PREFIX = "approval:"
_PENDING_SET = "approval:pending"
_DEFAULT_TTL_SECONDS = 14400  # 4 hours


class ApprovalQueue:
    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client

    # ------------------------------------------------------------------
    # Enqueue a new approval request
    # ------------------------------------------------------------------

    def enqueue(
        self,
        agent_id: str,
        action: str,
        resource_arn: str,
        task_id: str,
        policy_ref: str,
        risk_level: RiskLevel,
        token_jti: str,
        context: dict | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> ApprovalRequest:
        now = datetime.now(tz=timezone.utc)
        request = ApprovalRequest(
            request_id=uuid.uuid4(),
            agent_id=agent_id,
            action=action,
            resource_arn=resource_arn,
            task_id=task_id,
            policy_ref=policy_ref,
            risk_level=risk_level,
            requested_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            requesting_token_jti=token_jti,
            context=context or {},
            status=ApprovalStatus.PENDING,
        )

        key = f"{_KEY_PREFIX}{request.request_id}"
        self._r.setex(key, ttl_seconds, request.model_dump_json())
        self._r.sadd(_PENDING_SET, str(request.request_id))
        logger.info(
            "Approval queued: %s | agent=%s | action=%s | ttl=%ds",
            request.request_id,
            agent_id,
            action,
            ttl_seconds,
        )
        return request

    # ------------------------------------------------------------------
    # Resolve (approve or deny)
    # ------------------------------------------------------------------

    def resolve(self, resolution: ApprovalResolution) -> ApprovalRequest:
        key = f"{_KEY_PREFIX}{resolution.request_id}"
        raw = self._r.get(key)
        if not raw:
            raise ApprovalNotFoundError(f"Approval request {resolution.request_id} not found or expired")

        request = ApprovalRequest.model_validate_json(raw)

        if request.status != ApprovalStatus.PENDING:
            raise ApprovalAlreadyResolvedError(
                f"Request {resolution.request_id} is already {request.status}"
            )

        # Self-approval prevention: approver cannot be the agent's owner
        # In Phase 2: owner is derived from the agent_id prefix.
        # Phase 3: will query the identity registry for owner_team.
        if resolution.approver_identity == request.agent_id:
            raise SelfApprovalError(
                f"Agent {request.agent_id} cannot approve its own requests"
            )

        new_status = (
            ApprovalStatus.APPROVED
            if resolution.action == "approve"
            else ApprovalStatus.DENIED
        )

        request.status = new_status
        request.approver_identity = resolution.approver_identity
        request.resolved_at = datetime.now(tz=timezone.utc)

        # Update Redis record and remove from pending set
        self._r.setex(key, 3600, request.model_dump_json())  # keep for 1h after resolution
        self._r.srem(_PENDING_SET, str(resolution.request_id))

        logger.info(
            "Approval %s: %s | approver=%s | action=%s",
            new_status,
            resolution.request_id,
            resolution.approver_identity,
            request.action,
        )
        return request

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get(self, request_id: str | uuid.UUID) -> ApprovalRequest:
        key = f"{_KEY_PREFIX}{request_id}"
        raw = self._r.get(key)
        if not raw:
            raise ApprovalNotFoundError(f"Approval request {request_id} not found or expired")
        return ApprovalRequest.model_validate_json(raw)

    def list_pending(self) -> list[ApprovalRequest]:
        pending_ids = self._r.smembers(_PENDING_SET)
        results = []
        for rid in pending_ids:
            try:
                results.append(self.get(rid.decode() if isinstance(rid, bytes) else rid))
            except ApprovalNotFoundError:
                # Request expired — remove from pending set
                self._r.srem(_PENDING_SET, rid)
        return results


class ApprovalNotFoundError(Exception):
    pass


class ApprovalAlreadyResolvedError(Exception):
    pass


class SelfApprovalError(Exception):
    pass
