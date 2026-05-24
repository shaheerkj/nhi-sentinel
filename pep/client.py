"""Policy Enforcement Point — intercepts every agent tool call.

This is not optional middleware. It is baked into execute_tool().
An agent cannot call a cloud tool without passing through here.

Evaluation order (defense in depth):
  1. OPA (Rego) — general context: token validity, scope, time window, task binding, rate limit
  2. Cedar — resource-level: DataClassification, Environment tags on S3/IAM resources
  Both layers must ALLOW. Cedar DENY overrides OPA ALLOW.

Failure modes:
  - OPA unreachable  → DENY (fail closed, always)
  - OPA returns DENY → raise PolicyDenialError
  - OPA returns REQUIRE_APPROVAL → raise ApprovalRequiredError
  - Cedar returns DENY → raise PolicyDenialError (even if OPA said ALLOW)
  - Cedar unavailable → log warning, pass through (OPA is primary)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from pep.cedar_evaluator import CedarEvaluator, CedarPrincipal, CedarRequest, CedarResource
from pep.exceptions import ApprovalRequiredError, PEPUnavailableError, PolicyDenialError
from pep.models import ActionRequest, Decision, PolicyDecision

logger = logging.getLogger(__name__)

_OPA_POLICY_PATH = "v1/data/nhi/agent/authorization/response"


class PolicyEnforcementPoint:
    def __init__(self, opa_url: str | None = None, cedar: CedarEvaluator | None = None) -> None:
        self._opa_url = (opa_url or os.environ.get("OPA_URL", "http://localhost:8181")).rstrip("/")
        self._http = httpx.Client(timeout=5)
        self._cedar = cedar or CedarEvaluator()

    # ------------------------------------------------------------------
    # Primary interface — called by execute_tool()
    # ------------------------------------------------------------------

    def enforce(self, request: ActionRequest) -> None:
        """Evaluate request against OPA. Raises on DENY or REQUIRE_APPROVAL.

        This method has no return value — if it returns normally, the action is allowed.
        Evaluation order:
          0. IP binding check (client-side, pre-OPA) — rejects replayed tokens
          1. OPA Rego — general context
          2. Cedar — resource-level tags
        """
        self._check_ip_binding(request)
        decision = self._evaluate(request)

        log_extra = {
            "agent_id": request.agent_id,
            "action": request.action,
            "resource": request.resource_arn,
            "effect": decision.effect,
            "policy_ref": decision.policy_ref,
        }

        if decision.effect == Decision.ALLOW:
            # Layer 2: Cedar resource policy check
            cedar_decision = self._evaluate_cedar(request)
            if not cedar_decision.permitted:
                logger.warning("Cedar DENY overrides OPA ALLOW | agent=%s | action=%s", request.agent_id, request.action)
                raise PolicyDenialError(
                    request.action,
                    f"Cedar resource policy denied: {cedar_decision.reason}",
                    "nhi.cedar.resource_policy",
                )
            logger.info("PEP ALLOW", extra=log_extra)
            return

        if decision.effect == Decision.REQUIRE_APPROVAL:
            logger.warning("PEP REQUIRE_APPROVAL", extra=log_extra)
            request_id = self._queue_approval(request, decision)
            raise ApprovalRequiredError(request.action, request.resource_arn, request_id)

        # DENY
        logger.warning("PEP DENY", extra=log_extra)
        raise PolicyDenialError(request.action, decision.reason, decision.policy_ref)

    # ------------------------------------------------------------------
    # IP binding (Layer 0 — pre-OPA)
    # ------------------------------------------------------------------

    def _check_ip_binding(self, request: ActionRequest) -> None:
        """Reject tokens replayed from an unauthorized source IP.

        If the token carries a source_ip claim (written at issuance time by
        TokenManager), the request must originate from that exact IP. A mismatch
        means the token was used by a different host — either stolen or leaked.
        OPA is never consulted for an IP-mismatched request.
        """
        token_ip = request.token_claims.get("source_ip") or (
            (request.token_claims.get("agent_context") or {}).get("source_ip")
        )
        if token_ip and token_ip != request.source_ip:
            logger.warning(
                "IP binding violation | agent=%s | token_ip=%s | request_ip=%s",
                request.agent_id,
                token_ip,
                request.source_ip,
            )
            raise PolicyDenialError(
                request.action,
                f"Token IP binding violation: token bound to {token_ip}, request from {request.source_ip}",
                "pep.ip_binding",
            )

    # ------------------------------------------------------------------
    # OPA evaluation
    # ------------------------------------------------------------------

    def _evaluate(self, request: ActionRequest) -> PolicyDecision:
        try:
            resp = self._http.post(
                f"{self._opa_url}/{_OPA_POLICY_PATH}",
                json={"input": request.model_dump()},
            )
            resp.raise_for_status()
        except httpx.RequestError as exc:
            # OPA unreachable — fail closed
            logger.error("OPA unreachable: %s — failing closed (DENY)", exc)
            return PolicyDecision(
                effect=Decision.DENY,
                reason="Policy engine unreachable — fail-closed default",
                policy_ref="pep.fail_closed",
                policy_version="n/a",
                evaluated_at=datetime.now(tz=timezone.utc).isoformat(),
            )
        except httpx.HTTPStatusError as exc:
            logger.error("OPA returned error status %s", exc.response.status_code)
            return PolicyDecision(
                effect=Decision.DENY,
                reason=f"Policy engine returned HTTP {exc.response.status_code}",
                policy_ref="pep.fail_closed",
                policy_version="n/a",
                evaluated_at=datetime.now(tz=timezone.utc).isoformat(),
            )

        return PolicyDecision.model_validate(resp.json()["result"])

    # ------------------------------------------------------------------
    # Cedar evaluation
    # ------------------------------------------------------------------

    def _evaluate_cedar(self, request: ActionRequest) -> Any:
        from pep.cedar_evaluator import CedarDecision
        resource_type = self._infer_cedar_resource_type(request.action)
        if not resource_type:
            return CedarDecision(permitted=True, reason="not-cedar-governed")

        cedar_req = CedarRequest(
            principal=CedarPrincipal(
                agent_id=request.agent_id,
                agent_type=request.agent_type,
                scopes=request.token_claims.get("scopes", []),
            ),
            action=request.action,
            resource=CedarResource(
                resource_type=resource_type,
                resource_id=request.resource_arn,
                attributes=request.resource_tags,
            ),
            context=request.context,
        )
        return self._cedar.evaluate(cedar_req)

    @staticmethod
    def _infer_cedar_resource_type(action: str) -> str | None:
        if action.startswith("s3:"):
            return "NHI::S3Bucket"
        if action.startswith("iam:"):
            return "NHI::IAMRole"
        return None

    # ------------------------------------------------------------------
    # Approval queue
    # ------------------------------------------------------------------

    def _queue_approval(self, request: ActionRequest, decision: PolicyDecision) -> str:
        """Write an ApprovalRequest to Redis. Returns the request_id."""
        import uuid
        from datetime import timedelta

        import redis

        request_id = str(uuid.uuid4())
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = redis.from_url(redis_url)

        approval_data = {
            "request_id": request_id,
            "agent_id": request.agent_id,
            "action": request.action,
            "resource_arn": request.resource_arn,
            "task_id": request.task_id,
            "policy_ref": decision.policy_ref,
            "status": "PENDING",
            "requested_at": datetime.now(tz=timezone.utc).isoformat(),
        }

        ttl_seconds = int(os.environ.get("APPROVAL_TTL_SECONDS", 14400))  # 4 hours
        r.setex(f"approval:{request_id}", ttl_seconds, str(approval_data))
        logger.info("Queued approval request %s for %s", request_id, request.action)
        return request_id

    def close(self) -> None:
        self._http.close()


# ------------------------------------------------------------------
# execute_tool — the non-bypassable wrapper used by all agents
# ------------------------------------------------------------------

def execute_tool(
    pep: PolicyEnforcementPoint,
    request: ActionRequest,
    tool_fn: Callable[[], Any],
) -> Any:
    """Run a cloud tool call through the PEP. Always enforces before executing.

    Args:
        pep: The PolicyEnforcementPoint instance for this agent.
        request: The fully-constructed ActionRequest describing the intended action.
        tool_fn: A zero-argument callable that performs the actual cloud API call.

    Returns:
        The return value of tool_fn if the action is allowed.

    Raises:
        PolicyDenialError: If OPA returns DENY.
        ApprovalRequiredError: If OPA returns REQUIRE_APPROVAL.
    """
    pep.enforce(request)  # raises on DENY or REQUIRE_APPROVAL
    return tool_fn()
