"""Behavioral anomaly detection.

Two complementary detectors:

AnomalyScorer (IsolationForest):
  Per-event behavioral feature scorer. Trained on known-good events.
  Detects unusual action types, services, or time-of-day patterns.
  Best for: novel action classes, IAM calls from wrong agent type, etc.

BurstDetector (rate-based):
  Counts events in a rolling window. Fires when rate exceeds
  baseline × threshold_multiplier.
  Best for: rogue agent delete bursts, scanning probes, DDoS-style action floods.
  Does not require training — works from the first event.

Both detectors are used together in production:
  AnomalyScorer catches qualitative deviations (what kind of action).
  BurstDetector catches quantitative deviations (how many actions).
"""

from __future__ import annotations

import logging

import numpy as np
from sklearn.ensemble import IsolationForest

from audit.schema import AuditEvent

logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = 0.95   # AnomalyScorer: triggers identity suspension
BURST_THRESHOLD = 10       # BurstDetector: events per window before suspension

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
        scorer.fit(baseline_events)
        score = scorer.score(new_event)      # 0.0 = normal, 1.0 = anomalous
        if scorer.is_anomalous(new_event, threshold=0.6):
            alert(event.agent_id)
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

        Uses decision_function (positive=inlier, negative=outlier) mapped through
        sigmoid(10x) so the output is self-calibrated to the model's boundary.
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


class BurstDetector:
    """Rate-based burst detector for rogue agent action floods.

    No training required. Works from the first event.
    Counts events recorded via record(). Fires when count exceeds
    baseline_rate × threshold_multiplier.

    Usage:
        detector = BurstDetector()
        for event in audit_stream:
            if event.agent_id == target_agent:
                detector.record()
        if detector.is_burst():
            suspend_identity(target_agent)
    """

    def __init__(
        self,
        baseline_rate: float = 2.0,
        threshold_multiplier: float = 5.0,
    ) -> None:
        """
        Args:
            baseline_rate: Expected normal events per measurement window.
            threshold_multiplier: Fires when count > baseline * this factor.
        """
        self._baseline = baseline_rate
        self._threshold = threshold_multiplier
        self._count = 0

    def record(self) -> None:
        """Record that one event occurred."""
        self._count += 1

    def record_many(self, n: int) -> None:
        """Record n events at once."""
        self._count += n

    def is_burst(self) -> bool:
        """True when the event count exceeds the burst threshold."""
        return self._count > self._baseline * self._threshold

    def burst_score(self) -> float:
        """Normalized burst severity in [0.0, 1.0].

        0.0 = at or below baseline.
        1.0 = at or above threshold (and clamped beyond).
        """
        if self._count <= self._baseline:
            return 0.0
        burst_threshold = self._baseline * self._threshold
        excess = (self._count - self._baseline) / (burst_threshold - self._baseline)
        return round(min(1.0, max(0.0, excess)), 4)

    def reset(self) -> None:
        """Reset counter for a new measurement window."""
        self._count = 0

    @property
    def count(self) -> int:
        return self._count
