"""Phase 3 — Audit pipeline and anomaly detection tests.

All tests run fully offline (no Kafka, no PostgreSQL, no Docker).
AuditProducer falls back to its in-memory deque automatically.
AnomalyScorer is pure scikit-learn — no external services.

Covers:
  - AuditEvent hash computation and chain integrity
  - Tamper detection via verify_chain()
  - Producer in-memory fallback behaviour
  - Agent emits AuditEvent on both ALLOW and DENY paths
  - Anomaly scorer: fit, score, feature extraction
  - Anomaly scorer correctly ranks destructive/deny events higher than normal ones
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from moto import mock_aws

from agents.infra_agent.agent import InfraAgent
from agents.base.tool_registry import ToolRegistry
from anomaly.scorer import ANOMALY_THRESHOLD, AnomalyScorer, extract_features
from audit.producer import AuditProducer
from audit.schema import GENESIS_HASH, AuditEvent, compute_event_hash, verify_chain
from cloud_sim.bootstrap import seed_environment
from identity.token_manager import TokenManager
from pep.client import PolicyEnforcementPoint


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_event(
    agent_id: str = "agent-infra-001",
    action: str = "s3:GetObject",
    decision: str = "ALLOW",
    hour: int = 9,
    resource_arn: str = "arn:aws:s3:::bucket/key.json",
) -> AuditEvent:
    ts = datetime.now(tz=timezone.utc).replace(
        hour=hour, minute=0, second=0, microsecond=0
    )
    return AuditEvent(
        agent_id=agent_id,
        agent_type="InfraAgent",
        task_id="task-001",
        action=action,
        resource_arn=resource_arn,
        decision=decision,
        timestamp=ts,
    )


def _make_normal_events(n: int = 50) -> list[AuditEvent]:
    """Normal baseline: daytime GET/describe actions, all ALLOW."""
    events = []
    for i in range(n):
        hour = 9 + (i % 9)  # 9am–5pm
        events.append(_make_event(
            action="s3:GetObject" if i % 2 == 0 else "ec2:DescribeInstances",
            decision="ALLOW",
            hour=hour,
        ))
    return events


# ------------------------------------------------------------------
# AuditEvent hash computation
# ------------------------------------------------------------------

def test_compute_event_hash_is_deterministic():
    event = _make_event()
    assert compute_event_hash(event) == compute_event_hash(event)


def test_compute_event_hash_is_64_hex_chars():
    event = _make_event()
    h = compute_event_hash(event)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_compute_event_hash_changes_on_field_tamper():
    event = _make_event()
    h_before = compute_event_hash(event)
    event.decision = "DENY"
    h_after = compute_event_hash(event)
    assert h_before != h_after


def test_genesis_event_has_zero_previous_hash():
    producer = AuditProducer()
    published = producer.publish(_make_event())
    assert published.previous_event_hash == GENESIS_HASH


def test_hash_chain_links_consecutive_events():
    producer = AuditProducer()
    e1 = producer.publish(_make_event(action="s3:GetObject"))
    e2 = producer.publish(_make_event(action="s3:PutObject"))
    assert e2.previous_event_hash == e1.event_hash


def test_hash_chain_transitive_linkage():
    """e3's previous hash must match e2, which chains back to e1."""
    producer = AuditProducer()
    events = [producer.publish(_make_event(action=f"s3:GetObject/{i}")) for i in range(4)]
    for i in range(1, len(events)):
        assert events[i].previous_event_hash == events[i - 1].event_hash


# ------------------------------------------------------------------
# Chain verification
# ------------------------------------------------------------------

def test_verify_chain_passes_on_intact_chain():
    producer = AuditProducer()
    events = [producer.publish(_make_event()) for _ in range(5)]
    assert verify_chain(events) is True


def test_verify_chain_detects_hash_corruption():
    producer = AuditProducer()
    events = [producer.publish(_make_event()) for _ in range(3)]
    events[1].event_hash = "deadbeef" * 8  # corrupt middle event
    assert verify_chain(events) is False


def test_verify_chain_detects_field_tamper():
    producer = AuditProducer()
    events = [producer.publish(_make_event()) for _ in range(3)]
    events[0].decision = "DENY"  # tamper field without updating hash
    assert verify_chain(events) is False


def test_verify_chain_detects_broken_linkage():
    producer = AuditProducer()
    events = [producer.publish(_make_event()) for _ in range(3)]
    # Break the chain pointer without touching the hash
    events[2].previous_event_hash = GENESIS_HASH
    assert verify_chain(events) is False


# ------------------------------------------------------------------
# AuditProducer — in-memory fallback
# ------------------------------------------------------------------

def test_producer_uses_fallback_when_kafka_unreachable():
    producer = AuditProducer(bootstrap_servers="localhost:19999")
    assert producer._kafka is None


def test_producer_drain_returns_published_events():
    producer = AuditProducer()
    producer.publish(_make_event(action="s3:GetObject"))
    producer.publish(_make_event(action="s3:PutObject"))
    events = producer.drain()
    assert len(events) == 2
    assert events[0].action == "s3:GetObject"
    assert events[1].action == "s3:PutObject"


def test_producer_drain_clears_queue():
    producer = AuditProducer()
    producer.publish(_make_event())
    producer.drain()
    assert producer.drain() == []


def test_producer_event_hash_set_after_publish():
    producer = AuditProducer()
    event = _make_event()
    assert event.event_hash == ""
    published = producer.publish(event)
    assert len(published.event_hash) == 64


# ------------------------------------------------------------------
# Agent audit integration — AuditEvent emitted on both paths
# ------------------------------------------------------------------

@mock_aws
def test_infra_agent_emits_audit_event_on_allow():
    seed_environment()

    tm = MagicMock(spec=TokenManager)
    tm.get_token.return_value = "mock-token"
    tm.introspect.return_value = {
        "active": True, "agent_id": "agent-infra-001",
        "scope": "cloud:ec2:describe cloud:s3:list cloud:s3:read",
    }

    registry = ToolRegistry(granted_scopes=["cloud:ec2:describe", "cloud:s3:list", "cloud:s3:read"])
    pep = MagicMock(spec=PolicyEnforcementPoint)
    pep.enforce.return_value = None

    producer = AuditProducer()
    agent = InfraAgent("agent-infra-001", tm, registry, pep, audit_producer=producer)
    state = agent.run(
        tool_key="ec2_describe_instances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-audit-allow-001",
        environment="staging",
    )

    assert state["decision"] == "ALLOW"
    events = producer.drain()
    assert len(events) == 1
    assert events[0].decision == "ALLOW"
    assert events[0].agent_id == "agent-infra-001"
    assert len(events[0].event_hash) == 64


@mock_aws
def test_infra_agent_emits_audit_event_on_deny():
    seed_environment()

    tm = MagicMock(spec=TokenManager)
    tm.get_token.return_value = "mock-token"
    tm.introspect.return_value = {
        "active": True, "agent_id": "agent-infra-001",
        "scope": "cloud:ec2:describe",
    }

    registry = ToolRegistry(granted_scopes=["cloud:ec2:describe"])
    pep = MagicMock(spec=PolicyEnforcementPoint)
    pep.enforce.return_value = None

    producer = AuditProducer()
    agent = InfraAgent("agent-infra-001", tm, registry, pep, audit_producer=producer)
    state = agent.run(
        tool_key="s3_list_buckets",  # not in agent's granted scopes
        resource_arn="arn:aws:s3:::*",
        task_id="task-audit-deny-001",
        environment="staging",
    )

    assert state["decision"] == "DENY"
    events = producer.drain()
    assert len(events) == 1
    assert events[0].decision == "DENY"
    assert len(events[0].event_hash) == 64


@mock_aws
def test_consecutive_agent_runs_produce_linked_chain():
    """Two sequential runs must produce events where run2.previous_hash == run1.event_hash."""
    seed_environment()

    tm = MagicMock(spec=TokenManager)
    tm.get_token.return_value = "mock-token"
    tm.introspect.return_value = {
        "active": True, "agent_id": "agent-infra-001",
        "scope": "cloud:ec2:describe cloud:s3:list cloud:s3:read",
    }

    registry = ToolRegistry(granted_scopes=["cloud:ec2:describe", "cloud:s3:list", "cloud:s3:read"])
    pep = MagicMock(spec=PolicyEnforcementPoint)
    pep.enforce.return_value = None

    producer = AuditProducer()
    agent = InfraAgent("agent-infra-001", tm, registry, pep, audit_producer=producer)

    agent.run(
        tool_key="ec2_describe_instances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-chain-001",
        environment="staging",
    )
    agent.run(
        tool_key="s3_list_buckets",
        resource_arn="arn:aws:s3:::*",
        task_id="task-chain-002",
        environment="staging",
    )

    events = producer.drain()
    assert len(events) == 2
    assert verify_chain(events) is True


# ------------------------------------------------------------------
# Anomaly detection — AnomalyScorer
# ------------------------------------------------------------------

def test_anomaly_scorer_returns_zero_before_fitting():
    scorer = AnomalyScorer()
    assert scorer.score(_make_event()) == 0.0
    assert not scorer.fitted


def test_anomaly_scorer_fits_on_sufficient_events():
    scorer = AnomalyScorer()
    scorer.fit(_make_normal_events(50))
    assert scorer.fitted


def test_anomaly_scorer_skips_fit_on_too_few_events():
    scorer = AnomalyScorer()
    scorer.fit(_make_normal_events(5))  # below MIN_FIT_SAMPLES
    assert not scorer.fitted


def test_anomaly_scorer_normal_event_scores_low():
    scorer = AnomalyScorer()
    scorer.fit(_make_normal_events(100))
    normal = _make_event(action="s3:GetObject", decision="ALLOW", hour=10)
    assert scorer.score(normal) < 0.7


def test_anomaly_scorer_delete_burst_scores_higher_than_get():
    scorer = AnomalyScorer()
    scorer.fit(_make_normal_events(100))
    get_event = _make_event(action="s3:GetObject", decision="ALLOW", hour=10)
    delete_event = _make_event(action="s3:DeleteObject", decision="ALLOW", hour=2)
    assert scorer.score(delete_event) > scorer.score(get_event)


def test_anomaly_scorer_deny_scores_higher_than_allow():
    scorer = AnomalyScorer()
    scorer.fit(_make_normal_events(100))
    allow_event = _make_event(decision="ALLOW", hour=10)
    deny_event = _make_event(decision="DENY", hour=2)
    assert scorer.score(deny_event) >= scorer.score(allow_event)


def test_extract_features_length_and_bounds():
    event = _make_event(action="s3:DeleteObject", decision="DENY", hour=2)
    features = extract_features(event)
    assert len(features) == 5
    assert all(0.0 <= f <= 1.0 for f in features)


def test_extract_features_deny_flag():
    deny_event = _make_event(decision="DENY")
    allow_event = _make_event(decision="ALLOW")
    assert extract_features(deny_event)[1] == 1.0
    assert extract_features(allow_event)[1] == 0.0


def test_extract_features_destructive_flag():
    delete_event = _make_event(action="s3:DeleteObject")
    get_event = _make_event(action="s3:GetObject")
    assert extract_features(delete_event)[2] == 1.0
    assert extract_features(get_event)[2] == 0.0


def test_anomaly_score_clamped_to_unit_interval():
    scorer = AnomalyScorer()
    scorer.fit(_make_normal_events(100))
    for action, decision in [
        ("s3:GetObject", "ALLOW"),
        ("s3:DeleteBucket", "DENY"),
        ("iam:CreateRole", "ALLOW"),
        ("ec2:TerminateInstances", "DENY"),
    ]:
        score = scorer.score(_make_event(action=action, decision=decision))
        assert 0.0 <= score <= 1.0
