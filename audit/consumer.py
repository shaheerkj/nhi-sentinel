"""Kafka → PostgreSQL audit consumer.

Reads from nhi.audit.events and writes to the append-only audit_events table.
Designed to run as a standalone process (e.g. Docker Compose service).
Not used in offline tests — the AuditProducer's in-memory fallback handles that.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal

import asyncpg

from audit.schema import AuditEvent

logger = logging.getLogger(__name__)

AUDIT_TOPIC = "nhi.audit.events"

_INSERT_SQL = """
    INSERT INTO audit_events (
        event_id, schema_version, timestamp, agent_id, agent_type,
        task_id, action, resource_arn, decision, decision_reason,
        policy_ref, policy_version, token_jti, source_ip, environment,
        execution_result, execution_error, anomaly_score,
        event_hash, previous_event_hash
    ) VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10,
        $11, $12, $13, $14, $15,
        $16, $17, $18,
        $19, $20
    )
    ON CONFLICT (event_id) DO NOTHING
"""


async def _persist(conn: asyncpg.Connection, event: AuditEvent) -> None:
    await conn.execute(
        _INSERT_SQL,
        event.event_id,
        event.schema_version,
        event.timestamp,
        event.agent_id,
        event.agent_type,
        event.task_id,
        event.action,
        event.resource_arn,
        event.decision,
        event.decision_reason,
        event.policy_ref,
        event.policy_version,
        event.token_jti,
        event.source_ip,
        event.environment,
        json.dumps(event.execution_result) if event.execution_result else None,
        event.execution_error,
        event.anomaly_score,
        event.event_hash,
        event.previous_event_hash,
    )


async def run_consumer(
    bootstrap_servers: str,
    pg_dsn: str,
    group_id: str = "nhi-audit-consumer",
) -> None:
    from kafka import KafkaConsumer

    conn = await asyncpg.connect(pg_dsn)
    consumer = KafkaConsumer(
        AUDIT_TOPIC,
        bootstrap_servers=bootstrap_servers,
        group_id=group_id,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda m: m.decode("utf-8"),
    )

    logger.info("Audit consumer listening on %s", AUDIT_TOPIC)

    stop = asyncio.Event()

    def _shutdown(sig, _frame):
        logger.info("Shutting down (%s)", sig)
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        while not stop.is_set():
            records = consumer.poll(timeout_ms=500)
            for _, messages in records.items():
                for msg in messages:
                    try:
                        event = AuditEvent.model_validate_json(msg.value)
                        await _persist(conn, event)
                    except Exception as exc:
                        logger.error("Failed to persist audit event: %s", exc)
    finally:
        consumer.close()
        await conn.close()


if __name__ == "__main__":
    asyncio.run(
        run_consumer(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092"),
            pg_dsn=os.environ.get(
                "DATABASE_URL", "postgresql://nhi:nhi@localhost:5432/nhi_sentinel"
            ),
        )
    )
