"""Behavioral anomaly detection using Isolation Forest.

Scores each AuditEvent for anomalousness based on per-agent behavioral features.
A score near 1.0 indicates a highly anomalous event. The standard threshold for
triggering automatic identity suspension is ANOMALY_THRESHOLD = 0.95.

Feature vector (all normalized to [0.0, 1.0]):
  0  hour_of_day     — time-of-day pattern (agents work in predictable windows)
  1  is_deny         — denied actions are unusual for a healthy agent
  2  is_destructive  — delete/terminate/destroy/purge are high-signal deviations
  3  arn_length      — unusually long ARNs may indicate path traversal
  4  action_service  — service category (s3, ec2, iam, guardduty, securityhub, other)

Fitting requirement: at least MIN_FIT_SAMPLES events.
Returns 0.0 before the model is fitted (safe default — no false positives on cold start).
"""

from __future__ import annotations

import logging

import numpy as np
from sklearn.ensemble import IsolationForest

from audit.schema import AuditEvent

logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = 0.95

_DESTRUCTIVE_KEYWORDS = frozenset(
    ("delete", "terminate", "destroy", "remove", "drop", "purge")
)
_SERVICE_ENCODING = {
    "s3": 0.0,
    "ec2": 1.0,
    "iam": 2.0,
    "guardduty": 3.0,
    "securityhub": 4.0,
}
_MAX_SERVICE_IDX = 5.0


def extract_features(event: AuditEvent) -> list[float]:
    """Return a normalized [0, 1] feature vector for an AuditEvent."""
    hour = event.timestamp.hour / 23.0
    is_deny = 1.0 if event.decision == "DENY" else 0.0
    action_lower = event.action.lower()
    is_destructive = (
        1.0 if any(kw in action_lower for kw in _DESTRUCTIVE_KEYWORDS) else 0.0
    )
    arn_len = min(len(event.resource_arn) / 200.0, 1.0)
    svc = event.action.split(":")[0].lower() if ":" in event.action else "other"
    action_svc = _SERVICE_ENCODING.get(svc, _MAX_SERVICE_IDX) / _MAX_SERVICE_IDX
    return [hour, is_deny, is_destructive, arn_len, action_svc]


class AnomalyScorer:
    """Isolation Forest scorer trained on per-agent behavioral baselines.

    Usage:
        scorer = AnomalyScorer()
        scorer.fit(baseline_events)          # train on known-good events
        score = scorer.score(new_event)      # 0.0 = normal, 1.0 = highly anomalous
        if scorer.is_anomalous(new_event):   # True if score >= ANOMALY_THRESHOLD
            suspend_identity(event.agent_id)
    """

    MIN_FIT_SAMPLES = 10

    def __init__(self, contamination: float = 0.05) -> None:
        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
        )
        self._fitted = False

    def fit(self, events: list[AuditEvent]) -> None:
        if len(events) < self.MIN_FIT_SAMPLES:
            logger.warning(
                "Only %d events for fitting (need %d) — skipping",
                len(events),
                self.MIN_FIT_SAMPLES,
            )
            return
        X = np.array([extract_features(e) for e in events])
        self._model.fit(X)
        self._fitted = True
        logger.info("AnomalyScorer fitted on %d events", len(events))

    def score(self, event: AuditEvent) -> float:
        """Return anomaly score in [0.0, 1.0]. Returns 0.0 before fitting.

        Uses decision_function (positive=inlier, negative=outlier) passed through
        a sigmoid so the mapping is self-calibrated to the model's threshold.
        df >> 0 (clearly normal)   → score near 0.0
        df == 0 (boundary)         → score = 0.5
        df << 0 (clearly anomalous) → score near 1.0
        """
        if not self._fitted:
            return 0.0
        X = np.array([extract_features(event)])
        df = float(self._model.decision_function(X)[0])
        sigmoid = 1.0 / (1.0 + np.exp(10.0 * df))
        return round(float(np.clip(sigmoid, 0.0, 1.0)), 4)

    def is_anomalous(self, event: AuditEvent, threshold: float = ANOMALY_THRESHOLD) -> bool:
        return self.score(event) >= threshold

    @property
    def fitted(self) -> bool:
        return self._fitted
