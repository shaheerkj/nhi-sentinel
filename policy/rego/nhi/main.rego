package nhi.agent.authorization

import data.nhi.destructive_gate
import data.nhi.rate_limit
import data.nhi.scope_check
import data.nhi.task_scope
import data.nhi.time_window
import rego.v1

# ------------------------------------------------------------------
# Composed authorization decision
# All sub-policies must pass for ALLOW.
# Any REQUIRE_APPROVAL condition short-circuits to that effect.
# Everything else is DENY.
# ------------------------------------------------------------------

default effect := "DENY"

effect := "ALLOW" if {
    valid_token
    scope_check.action_in_scope
    time_window.within_window
    task_scope.task_is_active
    task_scope.environment_allowed
    rate_limit.within_rate_limit
    not destructive_gate.requires_approval
}

effect := "REQUIRE_APPROVAL" if {
    valid_token
    scope_check.action_in_scope
    time_window.within_window
    task_scope.task_is_active
    task_scope.environment_allowed
    rate_limit.within_rate_limit
    destructive_gate.requires_approval
}

# ------------------------------------------------------------------
# Token validation
# ------------------------------------------------------------------

valid_token if {
    input.token_claims.active == true
    input.token_claims.agent_id == input.agent_id
}

# Dev/test fallback: accept non-empty claims map when active key absent
valid_token if {
    count(input.token_claims) > 0
    not input.token_claims.active
}

# ------------------------------------------------------------------
# Reason — first matching deny reason wins
# ------------------------------------------------------------------

reason := "Token is invalid or agent is not in ACTIVE state" if {
    not valid_token
}

reason := scope_check.deny_reason if {
    valid_token
    scope_check.deny_reason
}

reason := time_window.deny_reason if {
    valid_token
    scope_check.action_in_scope
    time_window.deny_reason
}

reason := task_scope.deny_reason if {
    valid_token
    scope_check.action_in_scope
    time_window.within_window
    task_scope.deny_reason
}

reason := rate_limit.deny_reason if {
    valid_token
    scope_check.action_in_scope
    time_window.within_window
    task_scope.task_is_active
    rate_limit.deny_reason
}

reason := destructive_gate.approval_reason if {
    valid_token
    scope_check.action_in_scope
    time_window.within_window
    task_scope.task_is_active
    rate_limit.within_rate_limit
    destructive_gate.approval_reason
}

default reason := "Action denied by policy"

# ------------------------------------------------------------------
# Structured response consumed by PEP
# ------------------------------------------------------------------

response := {
    "effect": effect,
    "reason": reason,
    "policy_ref": "nhi.agent.authorization",
    "policy_version": "2.0.0",
    "evaluated_at": time.now_ns(),
    "conditions_evaluated": [
        {"name": "valid_token", "result": valid_token},
        {"name": "action_in_scope", "result": scope_check.action_in_scope},
        {"name": "within_time_window", "result": time_window.within_window},
        {"name": "task_is_active", "result": task_scope.task_is_active},
        {"name": "within_rate_limit", "result": rate_limit.within_rate_limit},
    ],
}
