"""Real-time anomaly scoring service.

Consumes the audit.events Kafka topic, maintains per-agent IsolationForest
models and BurstDetectors, and exposes a FastAPI HTTP interface for:
  - GET  /health          — liveness probe
  - GET  /metrics         — Prometheus text exposition
  - GET  /scores          — latest anomaly score per agent
  - POST /score           — score a single AuditEvent (for testing / sidecar use)

Automatic identity suspension:
  When an agent's anomaly score exceeds ANOMALY_THRESHOLD (0.95) or its
  BurstDetector fires, the service calls the identity suspension endpoint
  (configurable via IDENTITY_API_URL env var).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from anomaly.scorer import ANOMALY_THRESHOLD, AnomalyScorer, BurstDetector
from audit.schema import AuditEvent

logger = logging.getLogger(__name__)

app = FastAPI(title="NHI-Sentinel Anomaly Service", version="1.0.0")

# ---------------------------------------------------------------------------
# Per-agent state
# ---------------------------------------------------------------------------

_scorers: dict[str, AnomalyScorer] = defaultdict(AnomalyScorer)
_bursters: dict[str, BurstDetector] = defaultdict(BurstDetector)
_histories: dict[str, deque[AuditEvent]] = defaultdict(lambda: deque(maxlen=500))
_latest_scores: dict[str, float] = {}
_suspended: set[str] = set()

# Prometheus counters (simple in-memory; replace with prometheus_client in production)
_events_scored: int = 0
_suspensions: int = 0
_burst_detections: int = 0


# ---------------------------------------------------------------------------
# Kafka consumer (runs as a background task)
# ---------------------------------------------------------------------------

async def _consume_kafka() -> None:
    kafka_url = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")
    topic = os.environ.get("KAFKA_AUDIT_TOPIC", "audit.events")

    try:
        from aiokafka import AIOKafkaConsumer  # type: ignore[import]
    except ImportError:
        logger.warning("aiokafka not installed — Kafka consumer disabled")
        return

    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=kafka_url,
        group_id="nhi-anomaly-service",
        auto_offset_reset="earliest",
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
    )
    await consumer.start()
    logger.info("Kafka consumer started: %s → %s", kafka_url, topic)
    try:
        async for msg in consumer:
            try:
                event = AuditEvent.model_validate(msg.value)
                await _process_event(event)
            except Exception as exc:
                logger.error("Failed to process audit event: %s", exc)
    finally:
        await consumer.stop()


async def _process_event(event: AuditEvent) -> None:
    global _events_scored, _suspensions, _burst_detections

    agent_id = event.agent_id
    history = _histories[agent_id]
    history.append(event)

    scorer = _scorers[agent_id]
    burster = _bursters[agent_id]

    # Fit / refit the scorer once we have enough history
    if len(history) >= AnomalyScorer.MIN_FIT_SAMPLES and not scorer.fitted:
        scorer.fit(list(history))

    score = scorer.score(event)
    _latest_scores[agent_id] = score
    _events_scored += 1

    burster.record()

    log_extra = {
        "agent_id": agent_id,
        "action": event.action,
        "anomaly_score": score,
        "decision": event.decision,
    }

    if burster.is_burst():
        _burst_detections += 1
        logger.warning("Burst detected for agent %s (count=%d)", agent_id, burster.count, extra=log_extra)
        await _suspend_identity(agent_id, reason=f"Burst detection: {burster.count} events in window")
        burster.reset()
        return

    if scorer.is_anomalous(event, threshold=ANOMALY_THRESHOLD):
        _suspensions += 1
        logger.warning("Anomaly threshold breached for agent %s (score=%.4f)", agent_id, score, extra=log_extra)
        await _suspend_identity(agent_id, reason=f"Anomaly score {score:.4f} >= {ANOMALY_THRESHOLD}")
    elif score > 0.85:
        logger.warning("Elevated anomaly for agent %s (score=%.4f)", agent_id, score, extra=log_extra)
    else:
        logger.debug("Normal event for agent %s (score=%.4f)", agent_id, score, extra=log_extra)


async def _suspend_identity(agent_id: str, reason: str) -> None:
    if agent_id in _suspended:
        return
    _suspended.add(agent_id)

    identity_url = os.environ.get("IDENTITY_API_URL", "http://localhost:8002")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(
                f"{identity_url}/identities/{agent_id}/suspend",
                json={"reason": reason, "suspended_at": datetime.now(tz=timezone.utc).isoformat()},
            )
            resp.raise_for_status()
            logger.info("Identity suspended: %s — %s", agent_id, reason)
    except Exception as exc:
        logger.error("Failed to suspend identity %s: %s", agent_id, exc)


# ---------------------------------------------------------------------------
# FastAPI lifecycle
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event() -> None:
    asyncio.create_task(_consume_kafka())
    logger.info("Anomaly service started")


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "nhi-anomaly"}


@app.get("/scores")
def get_scores() -> dict[str, Any]:
    return {
        "scores": dict(_latest_scores),
        "suspended": list(_suspended),
        "events_scored": _events_scored,
    }


class ScoreRequest(BaseModel):
    event: dict[str, Any]


@app.post("/score")
def score_event(req: ScoreRequest) -> dict[str, Any]:
    event = AuditEvent.model_validate(req.event)
    agent_id = event.agent_id
    scorer = _scorers[agent_id]
    score = scorer.score(event)
    burster = _bursters[agent_id]
    burster.record()
    return {
        "agent_id": agent_id,
        "anomaly_score": score,
        "is_anomalous": scorer.is_anomalous(event),
        "is_burst": burster.is_burst(),
        "burst_score": burster.burst_score(),
    }


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    lines = [
        "# HELP nhi_anomaly_events_scored_total Total audit events scored by anomaly service",
        "# TYPE nhi_anomaly_events_scored_total counter",
        f"nhi_anomaly_events_scored_total {_events_scored}",
        "# HELP nhi_suspended_identities_total Total identity suspensions triggered by anomaly service",
        "# TYPE nhi_suspended_identities_total counter",
        f"nhi_suspended_identities_total {_suspensions}",
        "# HELP nhi_burst_detections_total Total burst detection events",
        "# TYPE nhi_burst_detections_total counter",
        f"nhi_burst_detections_total {_burst_detections}",
    ]
    for agent_id, score in _latest_scores.items():
        lines.append(f'nhi_anomaly_score{{agent_id="{agent_id}"}} {score}')
    return "\n".join(lines) + "\n"
