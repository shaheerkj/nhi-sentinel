from __future__ import annotations


class PolicyDenialError(Exception):
    """Raised when the policy engine returns DENY."""

    def __init__(self, action: str, reason: str, policy_ref: str) -> None:
        self.action = action
        self.reason = reason
        self.policy_ref = policy_ref
        super().__init__(f"DENY [{policy_ref}] — {action}: {reason}")


class ApprovalRequiredError(Exception):
    """Raised when the policy engine returns REQUIRE_APPROVAL."""

    def __init__(self, action: str, resource_arn: str, request_id: str) -> None:
        self.action = action
        self.resource_arn = resource_arn
        self.request_id = request_id
        super().__init__(
            f"REQUIRE_APPROVAL — {action} on {resource_arn} (request_id={request_id})"
        )


class PEPUnavailableError(Exception):
    """Raised when OPA is unreachable. PEP fails closed — never fails open."""
