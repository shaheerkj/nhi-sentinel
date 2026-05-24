"""Kafka-backed audit event producer with in-memory fallback.

When Kafka is unreachable (dev, CI, offline), the producer buffers events in
an in-memory deque. Call drain() to retrieve them — used by tests to assert
that the correct events were published without a running broker.

Publishing order:
  1. Set previous_event_hash from the agent's chain state.
  2. Compute and set event_hash.
  3. Send to Kafka (or buffer locally on failure).

This producer is per-agent-instance: each agent owns its own chain state so
events from different agents form independent chains (one per agent_id).
"""

from __future__ import annotations

import logging
import os
from collections import deque
from typing import Deque

from audit.schema import GENESIS_HASH, AuditEvent, compute_event_hash

logger = logging.getLogger(__name__)

AUDIT_TOPIC = "nhi.audit.events"


class AuditProducer:
    def __init__(self, bootstrap_servers: str | None = None) -> None:
        self._bootstrap = bootstrap_servers or os.environ.get(
            "KAFKA_BOOTSTRAP", "localhost:9092"
        )
        self._last_hash: str = GENESIS_HASH
        self._fallback: Deque[AuditEvent] = deque()
        self._kafka = self._try_connect()

    def _try_connect(self):
        try:
            from kafka import KafkaProducer

            producer = KafkaProducer(
                bootstrap_servers=self._bootstrap,
                value_serializer=lambda v: v.encode("utf-8"),
                request_timeout_ms=2000,
                connections_max_idle_ms=5000,
            )
            logger.info("Kafka producer connected to %s", self._bootstrap)
            return producer
        except Exception as exc:
            logger.warning("Kafka unavailable (%s) — using in-memory fallback", exc)
            return None

    def publish(self, event: AuditEvent) -> AuditEvent:
        """Finalize chain fields and publish. Returns the completed event."""
        event.previous_event_hash = self._last_hash
        event.event_hash = compute_event_hash(event)
        self._last_hash = event.event_hash

        if self._kafka is not None:
            try:
                future = self._kafka.send(AUDIT_TOPIC, event.model_dump_json())
                future.get(timeout=5)
                logger.debug("Published audit event %s", event.event_id)
                return event
            except Exception as exc:
                logger.warning("Kafka publish failed: %s — buffering locally", exc)

        self._fallback.append(event)
        logger.debug("Buffered audit event %s in-memory", event.event_id)
        return event

    def drain(self) -> list[AuditEvent]:
        """Return and clear all buffered events. Used for testing and graceful shutdown."""
        events = list(self._fallback)
        self._fallback.clear()
        return events

    def close(self) -> None:
        if self._kafka:
            self._kafka.close()
