package nhi.scope_check

import rego.v1

# Maps every cloud action to the scope that must be present in the agent's token.
# Adding a new action requires adding it here — no action is implicitly allowed.
action_scope_map := {
    "s3:ListBuckets":            "cloud:s3:list",
    "s3:GetObject":              "cloud:s3:read",
    "s3:PutObject":              "cloud:s3:write",
    "s3:DeleteObject":           "cloud:s3:delete",
    "s3:DeleteBucket":           "cloud:s3:delete",
    "ec2:DescribeInstances":     "cloud:ec2:describe",
    "ec2:DescribeSecurityGroups":"cloud:ec2:describe",
    "ec2:TerminateInstances":    "cloud:ec2:terminate",
    "ec2:StartInstances":        "cloud:ec2:start",
    "iam:ListRoles":             "cloud:iam:read",
    "iam:CreateRole":            "cloud:iam:create-role",
    "iam:AttachRolePolicy":      "cloud:iam:create-role",
    "iam:CreateUser":            "cloud:iam:write",
    "iam:DeleteRole":            "cloud:iam:write",
    "securityhub:GetFindings":   "cloud:securityhub:read",
    "guardduty:ListFindings":    "cloud:guardduty:read",
    "config:DescribeComplianceByResource": "cloud:config:read",
    "cloudtrail:LookupEvents":   "cloud:cloudtrail:read",
}

# Returns the required scope for a given action, or undefined if the action is unknown.
required_scope(action) := scope if {
    scope := action_scope_map[action]
}

# True if the token carries the required scope for this action.
# Supports both space-delimited scope string and explicit scopes array.
action_in_scope if {
    req_scope := required_scope(input.action)
    contains(input.token_claims.scope, req_scope)
}

action_in_scope if {
    req_scope := required_scope(input.action)
    req_scope == input.token_claims.scopes[_]
}

# Unknown actions are denied — there is no implicit allow for undeclared actions.
deny_reason := "Action is not registered in the scope map" if {
    not action_scope_map[input.action]
}

deny_reason := "Required scope not present in token" if {
    action_scope_map[input.action]
    not action_in_scope
}
