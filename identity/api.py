"""Identity lifecycle management API.

FastAPI service that manages the suspension state of agent identities.
The anomaly service calls POST /identities/{agent_id}/suspend when an
anomaly threshold is breached. The PEP reads the same suspension set
from Redis and refuses to allow any action for a suspended identity.

Suspension state is stored as a Redis set 'identities:suspended' so the
PEP can do a single SISMEMBER check on the hot path.

Endpoints:
  GET    /health                              — liveness
  POST   /identities/{agent_id}/suspend       — mark suspended (called by anomaly svc)
  POST   /identities/{agent_id}/unsuspend     — clear suspension (operator action)
  GET    /identities/{agent_id}/status        — current state
  GET    /identities/suspended                — list all suspended agents
  GET    /metrics                             — Prometheus exposition
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import redis
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

app = FastAPI(title="NHI-Sentinel Identity API", version="1.0.0")

_SUSPENDED_KEY = "identities:suspended"
_REASON_KEY_PREFIX = "identity:suspension_reason:"

_suspensions_total: int = 0
_unsuspensions_total: int = 0


def _get_redis() -> redis.Redis:
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    return redis.from_url(url, decode_responses=True, socket_timeout=2)


class SuspendRequest(BaseModel):
    reason: str
    suspended_at: str | None = Field(
        default=None,
        description="ISO-8601 timestamp; defaults to now if omitted",
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "nhi-identity"}


@app.post("/identities/{agent_id}/suspend")
def suspend_identity(agent_id: str, req: SuspendRequest) -> dict[str, Any]:
    global _suspensions_total
    try:
        r = _get_redis()
        added = r.sadd(_SUSPENDED_KEY, agent_id)
        suspended_at = req.suspended_at or datetime.now(tz=timezone.utc).isoformat()
        r.set(f"{_REASON_KEY_PREFIX}{agent_id}", f"{suspended_at}|{req.reason}")
    except Exception as exc:
        logger.error("Failed to suspend %s: %s", agent_id, exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")

    if added:
        _suspensions_total += 1
        logger.warning("Identity SUSPENDED: %s — %s", agent_id, req.reason)
    return {
        "agent_id": agent_id,
        "status": "SUSPENDED",
        "newly_suspended": bool(added),
        "reason": req.reason,
        "suspended_at": suspended_at,
    }


@app.post("/identities/{agent_id}/unsuspend")
def unsuspend_identity(agent_id: str) -> dict[str, Any]:
    global _unsuspensions_total
    try:
        r = _get_redis()
        removed = r.srem(_SUSPENDED_KEY, agent_id)
        r.delete(f"{_REASON_KEY_PREFIX}{agent_id}")
    except Exception as exc:
        logger.error("Failed to unsuspend %s: %s", agent_id, exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")

    if not removed:
        raise HTTPException(status_code=404, detail=f"{agent_id} was not suspended")
    _unsuspensions_total += 1
    logger.info("Identity reinstated: %s", agent_id)
    return {"agent_id": agent_id, "status": "ACTIVE"}


@app.get("/identities/{agent_id}/status")
def identity_status(agent_id: str) -> dict[str, Any]:
    try:
        r = _get_redis()
        is_suspended = bool(r.sismember(_SUSPENDED_KEY, agent_id))
        reason_blob = r.get(f"{_REASON_KEY_PREFIX}{agent_id}") if is_suspended else None
    except Exception as exc:
        logger.error("Status check failed for %s: %s", agent_id, exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")

    return {
        "agent_id": agent_id,
        "status": "SUSPENDED" if is_suspended else "ACTIVE",
        "reason": reason_blob,
    }


@app.get("/identities/suspended")
def list_suspended() -> dict[str, Any]:
    try:
        r = _get_redis()
        members = sorted(r.smembers(_SUSPENDED_KEY))
    except Exception as exc:
        logger.error("Suspended list failed: %s", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    return {"count": len(members), "agents": members}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    try:
        r = _get_redis()
        current_count = r.scard(_SUSPENDED_KEY)
    except Exception:
        current_count = 0
    lines = [
        "# HELP nhi_suspensions_total Total identity suspension events",
        "# TYPE nhi_suspensions_total counter",
        f"nhi_suspensions_total {_suspensions_total}",
        "# HELP nhi_unsuspensions_total Total identity reinstatement events",
        "# TYPE nhi_unsuspensions_total counter",
        f"nhi_unsuspensions_total {_unsuspensions_total}",
        "# HELP nhi_identities_suspended_current Currently suspended identities",
        "# TYPE nhi_identities_suspended_current gauge",
        f"nhi_identities_suspended_current {current_count}",
    ]
    return "\n".join(lines) + "\n"
