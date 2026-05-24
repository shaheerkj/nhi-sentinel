"""AuditEvent Pydantic model with SHA-256 hash chaining.

Every agent action — ALLOW, DENY, or REQUIRE_APPROVAL — produces an AuditEvent.
Events are chained: each event's hash covers its own fields plus the previous
event's hash, so tampering with any past event invalidates all subsequent hashes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

GENESIS_HASH = "0" * 64  # sentinel for the first event in a chain


class AuditEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    schema_version: str = "1.0"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    agent_id: str
    agent_type: str
    task_id: str
    action: str
    resource_arn: str
    decision: str  # ALLOW | DENY | REQUIRE_APPROVAL
    decision_reason: str | None = None
    policy_ref: str | None = None
    policy_version: str | None = None
    token_jti: str | None = None
    source_ip: str | None = None
    environment: str | None = None
    execution_result: dict[str, Any] | None = None
    execution_error: str | None = None
    anomaly_score: float | None = None
    previous_event_hash: str = GENESIS_HASH
    event_hash: str = ""  # set by AuditProducer.publish() — never set manually


def compute_event_hash(event: AuditEvent) -> str:
    """SHA-256 over the event's immutable fields + previous_event_hash.

    The canonical form uses only fields that must not change after the fact.
    Including previous_event_hash creates the chain: you cannot change event N
    without recomputing all hashes from N onwards.
    """
    canonical = json.dumps(
        {
            "event_id": str(event.event_id),
            "timestamp": event.timestamp.isoformat(),
            "agent_id": event.agent_id,
            "agent_type": event.agent_type,
            "task_id": event.task_id,
            "action": event.action,
            "resource_arn": event.resource_arn,
            "decision": event.decision,
            "previous_event_hash": event.previous_event_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_chain(events: list[AuditEvent]) -> bool:
    """Verify hash chain integrity. Returns False if any event was tampered with."""
    for i, event in enumerate(events):
        if compute_event_hash(event) != event.event_hash:
            return False
        if i > 0 and event.previous_event_hash != events[i - 1].event_hash:
            return False
    return True
