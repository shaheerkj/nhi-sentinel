# ADR-004: Kafka as the Audit Event Bus

**Status:** Accepted  
**Date:** 2026-05-01  
**Deciders:** Lead Architect, Security Engineer  

---

## Context

Every agent action attempt (ALLOW, DENY, REQUIRE_APPROVAL) must be written to an immutable audit store. The design question is how audit events get from the agent to the persistent store.

Two approaches were considered:

1. **Direct write to PostgreSQL** — the PEP writes the `AuditEvent` directly to the database at decision time, synchronously, before executing the allowed action.

2. **Event bus (Kafka) with a consumer** — the PEP publishes the `AuditEvent` to a Kafka topic. A separate consumer service reads from Kafka and writes to PostgreSQL. The PEP does not hold a database connection.

A third option — writing audit events asynchronously after the action — was not considered seriously, as it would create a gap between action and audit record.

## Decision

Use **Apache Kafka** as the audit event bus. The PEP publishes to the `audit.events` topic. A separate `AuditConsumer` service reads from the topic and persists to PostgreSQL.

The PEP uses an **in-memory fallback queue** (`collections.deque`) when Kafka is unavailable. The fallback queue is drained and replayed to Kafka when the broker reconnects. The action is **not blocked** when Kafka is temporarily unavailable — the fallback ensures the audit event is not lost.

Anomaly detection runs as a second Kafka consumer group on the same topic, receiving every event in real time without the PostgreSQL consumer needing to know about it.

## Consequences

**Positive:**
- **Decoupling**: The PEP does not hold a database connection. The agent service and the audit storage layer can scale, fail, and deploy independently.
- **Replay capability**: Kafka retains events for 7 days (configurable). If the PostgreSQL consumer is down, events are not lost — they are replayed when it recovers. This is critical for audit completeness.
- **Fan-out**: Multiple consumers can read the same audit stream independently (PostgreSQL persistence + anomaly scoring + future SIEM integration) without the PEP needing to know about them.
- **Ordering guarantees**: Kafka's per-partition ordering ensures audit events for a given agent arrive in sequence, preserving the hash chain.
- **Industry credibility**: Kafka is the dominant audit and event streaming solution in enterprises. Using it demonstrates knowledge of production-grade architecture.

**Negative:**
- Kafka adds operational complexity (KRaft, broker management, topic configuration)
- Adds a non-trivial latency between action and PostgreSQL persistence (seconds, not milliseconds)
- The in-memory fallback queue is bounded — a sustained Kafka outage will eventually lose events (acceptable for a reference implementation; production would use a durable local write-ahead log)

## Offline Testing

To keep the test suite runnable without Docker, `AuditProducer.__init__()` gracefully catches broker connection failures and activates the fallback deque. Tests call `producer.drain()` to retrieve buffered events. No Kafka broker is required to run any test.

## Alternatives Rejected

**Direct PostgreSQL write (synchronous):** Rejected. This creates a tight coupling between agent operations and database availability. A slow or unavailable database would block all agent actions. The write-ahead semantics (audit before action) would require the agent to hold a database transaction open during the cloud API call.

**Direct PostgreSQL write (async / fire-and-forget):** Rejected. Fire-and-forget writes can be lost silently. For an audit system, silent loss is unacceptable.

## References

- NHI-Sentinel audit producer: `audit/producer.py`
- NHI-Sentinel audit consumer: `audit/consumer.py`
- Docker Compose: `docker-compose.yml` (kafka service)
