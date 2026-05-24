package nhi.agent.authorization

import rego.v1

# ------------------------------------------------------------------
# Top-level decision
# ------------------------------------------------------------------

default effect := "DENY"
default reason := "No policy explicitly allows this action"

effect := "ALLOW" if {
    valid_token
    action_in_scope
    within_time_window
    task_is_active
    not is_destructive_without_approval
}

effect := "REQUIRE_APPROVAL" if {
    valid_token
    action_in_scope
    within_time_window
    task_is_active
    is_destructive_without_approval
}

reason := "Token is invalid or agent is not in ACTIVE state" if {
    not valid_token
}

reason := "Action scope not present in token" if {
    valid_token
    not action_in_scope
}

reason := "Action outside agent declared time window" if {
    valid_token
    action_in_scope
    not within_time_window
}

reason := "No active task bound to this agent" if {
    valid_token
    action_in_scope
    within_time_window
    not task_is_active
}

reason := "Destructive action requires human approval" if {
    valid_token
    action_in_scope
    within_time_window
    task_is_active
    is_destructive_without_approval
}

# ------------------------------------------------------------------
# Scope mapping — action → required scope
# ------------------------------------------------------------------

action_scope_map := {
    "s3:ListBuckets":        "cloud:s3:list",
    "s3:GetObject":          "cloud:s3:read",
    "s3:PutObject":          "cloud:s3:write",
    "s3:DeleteObject":       "cloud:s3:delete",
    "s3:DeleteBucket":       "cloud:s3:delete",
    "ec2:DescribeInstances": "cloud:ec2:describe",
    "ec2:DescribeSecurityGroups": "cloud:ec2:describe",
    "ec2:TerminateInstances":"cloud:ec2:terminate",
    "iam:ListRoles":         "cloud:iam:read",
    "iam:CreateRole":        "cloud:iam:create-role",
    "iam:CreateUser":        "cloud:iam:write",
    "securityhub:GetFindings": "cloud:securityhub:read",
}

# Destructive actions always require human approval
destructive_actions := {
    "s3:DeleteObject",
    "s3:DeleteBucket",
    "ec2:TerminateInstances",
    "iam:DeleteRole",
    "iam:DeleteUser",
}

# ------------------------------------------------------------------
# Conditions
# ------------------------------------------------------------------

valid_token if {
    input.token_claims.active == true
    input.token_claims.agent_id == input.agent_id
}

# Phase 1: allow if token is a non-empty map (Keycloak not yet wired)
# Remove this fallback once Keycloak introspection is integrated
valid_token if {
    count(input.token_claims) > 0
    not input.token_claims.active  # key absent means we haven't introspected yet
}

action_in_scope if {
    required := action_scope_map[input.action]
    scopes := input.token_claims.scope
    contains(scopes, required)
}

# Fallback: check against explicit scopes array when present
action_in_scope if {
    required := action_scope_map[input.action]
    required == input.token_claims.scopes[_]
}

within_time_window if {
    # If no time_window is declared in context, allow at any time
    not input.context.time_window
}

within_time_window if {
    tw := input.context.time_window
    current_hour := time.clock([time.now_ns(), "UTC"])[0]
    current_hour >= tw.start_hour_utc
    current_hour < tw.end_hour_utc
}

task_is_active if {
    # Phase 1: accept any non-empty task_id
    count(input.task_id) > 0
}

is_destructive_without_approval if {
    input.action in destructive_actions
    not input.context.pre_approved
}

# ------------------------------------------------------------------
# Structured response consumed by PEP
# ------------------------------------------------------------------

response := {
    "effect": effect,
    "reason": reason,
    "policy_ref": "nhi.agent.authorization",
    "policy_version": "1.0.0",
    "evaluated_at": time.now_ns(),
    "conditions_evaluated": [
        {"name": "valid_token", "result": valid_token},
        {"name": "action_in_scope", "result": action_in_scope},
        {"name": "within_time_window", "result": within_time_window},
        {"name": "task_is_active", "result": task_is_active},
    ],
}
