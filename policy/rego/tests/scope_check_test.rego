package nhi.scope_check_test

import data.nhi.scope_check
import rego.v1

# Valid token with matching scope in space-delimited string
test_action_in_scope_string if {
    scope_check.action_in_scope with input as {
        "action": "s3:GetObject",
        "token_claims": {"scope": "cloud:s3:list cloud:s3:read cloud:ec2:describe"},
    }
}

# Valid token with matching scope in array form
test_action_in_scope_array if {
    scope_check.action_in_scope with input as {
        "action": "ec2:DescribeInstances",
        "token_claims": {"scopes": ["cloud:ec2:describe", "cloud:s3:list"]},
    }
}

# Wrong scope — token has s3:list but action needs s3:write
test_action_not_in_scope if {
    not scope_check.action_in_scope with input as {
        "action": "s3:PutObject",
        "token_claims": {"scope": "cloud:s3:list cloud:s3:read"},
    }
}

# DataAgent with IAM scope not granted — hard deny
test_iam_write_blocked_without_scope if {
    not scope_check.action_in_scope with input as {
        "action": "iam:CreateUser",
        "token_claims": {"scope": "cloud:s3:read cloud:s3:write"},
    }
}

# Unknown action — not in scope map
test_unknown_action_denied if {
    not scope_check.action_in_scope with input as {
        "action": "rds:CreateCluster",
        "token_claims": {"scope": "cloud:s3:read"},
    }
}

# Deny reason set for missing scope
test_deny_reason_missing_scope if {
    scope_check.deny_reason with input as {
        "action": "s3:DeleteObject",
        "token_claims": {"scope": "cloud:s3:read"},
    }
}
