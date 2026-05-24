"""Behavioral baseline generation for anomaly detection.

Generates synthetic audit event histories for agent types to bootstrap
the IsolationForest model before real production traffic is available.
Also provides utilities for extracting per-agent feature statistics.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from audit.schema import AuditEvent

# ---------------------------------------------------------------------------
# Synthetic baseline generation
# ---------------------------------------------------------------------------

_INFRA_ACTIONS = [
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "s3:ListBuckets",
    "s3:GetObject",
    "s3:ListObjects",
]

_DATA_ACTIONS = [
    "s3:GetObject",
    "s3:PutObject",
    "s3:ListObjects",
    "s3:CopyObject",
]

_SECOPS_ACTIONS = [
    "securityhub:GetFindings",
    "guardduty:ListFindings",
    "cloudtrail:LookupEvents",
    "config:GetComplianceDetailsByConfigRule",
]

_PROVISIONER_ACTIONS = [
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:GetRole",
]

_AGENT_PROFILES: dict[str, dict[str, Any]] = {
    "InfraAgent": {
        "actions": _INFRA_ACTIONS,
        "active_hours": (8, 20),  # UTC
        "decision_deny_rate": 0.05,
    },
    "DataAgent": {
        "actions": _DATA_ACTIONS,
        "active_hours": (6, 22),
        "decision_deny_rate": 0.08,
    },
    "SecOpsAgent": {
        "actions": _SECOPS_ACTIONS,
        "active_hours": (0, 24),  # 24/7
        "decision_deny_rate": 0.03,
    },
    "ProvisionerAgent": {
        "actions": _PROVISIONER_ACTIONS,
        "active_hours": (9, 18),
        "decision_deny_rate": 0.20,  # high — most approvals required
    },
}


def generate_baseline_events(
    agent_id: str,
    agent_type: str,
    n: int = 500,
    days_back: int = 7,
    seed: int = 42,
) -> list[AuditEvent]:
    """Generate synthetic normal-behavior audit events for baseline training.

    Args:
        agent_id: The agent identity string.
        agent_type: Must be one of the keys in _AGENT_PROFILES.
        n: Number of events to generate.
        days_back: Events are spread over this many past days.
        seed: Random seed for reproducibility.

    Returns:
        List of AuditEvent objects representing normal behavior.
    """
    rng = random.Random(seed)
    profile = _AGENT_PROFILES.get(agent_type, _AGENT_PROFILES["InfraAgent"])
    actions = profile["actions"]
    start_hour, end_hour = profile["active_hours"]
    deny_rate = profile["decision_deny_rate"]

    now = datetime.now(tz=timezone.utc)
    events: list[AuditEvent] = []

    for _ in range(n):
        # Pick a random time in the past `days_back` days, within active hours
        day_offset = rng.uniform(0, days_back)
        hour = rng.uniform(start_hour, min(end_hour, 23))
        ts = now - timedelta(days=day_offset, hours=(now.hour - hour))

        action = rng.choice(actions)
        decision = "DENY" if rng.random() < deny_rate else "ALLOW"

        event = AuditEvent(
            event_id=uuid4(),
            timestamp=ts,
            agent_id=agent_id,
            agent_type=agent_type,
            task_id=f"task-baseline-{rng.randint(1, 20):03d}",
            action=action,
            resource_arn=f"arn:aws:s3:::data-pipeline-{rng.randint(1, 5):02d}",
            decision=decision,
            decision_reason=None if decision == "ALLOW" else "scope_check",
            policy_ref="nhi.agent.authorization" if decision == "DENY" else None,
            token_jti=str(uuid4()),
            source_ip="10.0.1.1",
            environment="staging",
        )
        events.append(event)

    return sorted(events, key=lambda e: e.timestamp)


# ---------------------------------------------------------------------------
# Feature statistics
# ---------------------------------------------------------------------------

def compute_feature_statistics(events: list[AuditEvent]) -> dict[str, Any]:
    """Compute descriptive statistics over behavioral features for an agent.

    Used for dashboard display and debugging model baselines.
    """
    if not events:
        return {}

    from anomaly.scorer import extract_features

    features = [extract_features(e) for e in events]
    n = len(features)

    feature_names = ["hour_norm", "is_deny", "is_destructive", "arn_len_norm", "action_svc"]
    stats: dict[str, Any] = {"event_count": n}

    for i, name in enumerate(feature_names):
        col = [f[i] for f in features]
        stats[name] = {
            "mean": sum(col) / n,
            "min": min(col),
            "max": max(col),
        }

    action_counts: dict[str, int] = {}
    for e in events:
        action_counts[e.action] = action_counts.get(e.action, 0) + 1
    stats["top_actions"] = sorted(action_counts.items(), key=lambda x: -x[1])[:5]

    return stats
