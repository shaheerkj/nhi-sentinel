"""Audit query API.

FastAPI service exposing a read-only interface to the PostgreSQL audit store.
All mutating operations are blocked at the database level (trigger-enforced
immutability); this API only ever reads.

Endpoints:
  GET /health                   — liveness
  GET /metrics                  — Prometheus exposition
  GET /events                   — paginated event query with filters
  GET /events/{event_id}        — single event by ID
  GET /events/agent/{agent_id}  — events for one agent
  GET /chain/verify/{agent_id}  — verify hash chain integrity for an agent
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse

logger = logging.getLogger(__name__)

app = FastAPI(title="NHI-Sentinel Audit API", version="1.0.0")

_POSTGRES_DSN = os.environ.get(
    "POSTGRES_DSN",
    "postgresql://audit_user:changeme@localhost:5432/audit",
)

# Prometheus counters
_queries: int = 0
_chain_verifications: int = 0
_chain_failures: int = 0


def _get_pool() -> Any:
    """Return a connection pool (lazy import — asyncpg not needed at import time)."""
    import asyncpg  # type: ignore[import]
    return asyncpg


# ---------------------------------------------------------------------------
# FastAPI endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "nhi-audit-api"}


@app.get("/events", response_model=list[dict[str, Any]])
async def list_events(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    action: Optional[str] = Query(None, description="Filter by action (prefix match)"),
    decision: Optional[str] = Query(None, description="ALLOW | DENY | REQUIRE_APPROVAL"),
    since: Optional[datetime] = Query(None, description="Events after this timestamp (ISO-8601)"),
    until: Optional[datetime] = Query(None, description="Events before this timestamp (ISO-8601)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    global _queries
    _queries += 1

    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if agent_id:
        conditions.append(f"agent_id = ${idx}")
        params.append(agent_id)
        idx += 1
    if action:
        conditions.append(f"action LIKE ${idx}")
        params.append(f"{action}%")
        idx += 1
    if decision:
        conditions.append(f"decision = ${idx}")
        params.append(decision.upper())
        idx += 1
    if since:
        conditions.append(f"timestamp >= ${idx}")
        params.append(since)
        idx += 1
    if until:
        conditions.append(f"timestamp <= ${idx}")
        params.append(until)
        idx += 1

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    params.extend([limit, offset])
    query = f"""
        SELECT * FROM audit_events
        {where}
        ORDER BY timestamp DESC
        LIMIT ${idx} OFFSET ${idx + 1}
    """

    try:
        import asyncpg  # type: ignore[import]
        conn = await asyncpg.connect(_POSTGRES_DSN)
        try:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
        finally:
            await conn.close()
    except Exception as exc:
        logger.error("Audit query failed: %s", exc)
        raise HTTPException(status_code=503, detail="Audit store unavailable")


@app.get("/events/{event_id}")
async def get_event(event_id: UUID) -> dict[str, Any]:
    global _queries
    _queries += 1

    try:
        import asyncpg  # type: ignore[import]
        conn = await asyncpg.connect(_POSTGRES_DSN)
        try:
            row = await conn.fetchrow(
                "SELECT * FROM audit_events WHERE event_id = $1", str(event_id)
            )
            if not row:
                raise HTTPException(status_code=404, detail="Event not found")
            return dict(row)
        finally:
            await conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Audit event lookup failed: %s", exc)
        raise HTTPException(status_code=503, detail="Audit store unavailable")


@app.get("/chain/verify/{agent_id}")
async def verify_chain(agent_id: str) -> dict[str, Any]:
    """Re-compute and verify the hash chain for all events from this agent.

    Returns valid=True only if every event's stored hash matches the recomputed
    hash and every previous_event_hash pointer is correct.
    """
    global _chain_verifications, _chain_failures
    _chain_verifications += 1

    try:
        import asyncpg  # type: ignore[import]
        from audit.schema import AuditEvent, verify_chain

        conn = await asyncpg.connect(_POSTGRES_DSN)
        try:
            rows = await conn.fetch(
                "SELECT * FROM audit_events WHERE agent_id = $1 ORDER BY timestamp ASC",
                agent_id,
            )
        finally:
            await conn.close()

        if not rows:
            return {"agent_id": agent_id, "valid": True, "event_count": 0, "note": "no events found"}

        events = [AuditEvent.model_validate(dict(row)) for row in rows]
        valid = verify_chain(events)
        if not valid:
            _chain_failures += 1
            logger.error("Chain integrity failure for agent %s (%d events)", agent_id, len(events))

        return {
            "agent_id": agent_id,
            "valid": valid,
            "event_count": len(events),
        }
    except Exception as exc:
        logger.error("Chain verification failed: %s", exc)
        raise HTTPException(status_code=503, detail="Verification unavailable")


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    lines = [
        "# HELP nhi_audit_queries_total Total audit API queries served",
        "# TYPE nhi_audit_queries_total counter",
        f"nhi_audit_queries_total {_queries}",
        "# HELP nhi_chain_verifications_total Total chain integrity checks",
        "# TYPE nhi_chain_verifications_total counter",
        f"nhi_chain_verifications_total {_chain_verifications}",
        "# HELP nhi_chain_failures_total Chain integrity failures detected",
        "# TYPE nhi_chain_failures_total counter",
        f"nhi_chain_failures_total {_chain_failures}",
    ]
    return "\n".join(lines) + "\n"
