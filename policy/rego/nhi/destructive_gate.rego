package nhi.destructive_gate

import rego.v1

# Destructive actions always require human approval.
# There is no ALLOW path for these — REQUIRE_APPROVAL is the best outcome.
# A pre_approved flag (set by the approval workflow after human sign-off)
# allows the PEP to proceed after approval has been granted.

destructive_actions := {
    "s3:DeleteObject",
    "s3:DeleteBucket",
    "ec2:TerminateInstances",
    "iam:DeleteRole",
    "iam:DeleteUser",
    "iam:DetachRolePolicy",
}

# High-risk IAM write actions also require approval regardless of agent type.
iam_write_actions := {
    "iam:CreateUser",
    "iam:AttachRolePolicy",
}

requires_approval if {
    input.action in destructive_actions
    not input.context.pre_approved
}

requires_approval if {
    input.action in iam_write_actions
    not input.context.pre_approved
}

# ProvisionerAgent actions always require approval — there is no self-approval path.
requires_approval if {
    input.agent_type == "ProvisionerAgent"
    not input.context.pre_approved
}

approval_reason := "Destructive action requires human approval before execution" if {
    input.action in destructive_actions
    not input.context.pre_approved
}

approval_reason := "IAM write action requires human approval" if {
    input.action in iam_write_actions
    not input.context.pre_approved
}

approval_reason := "ProvisionerAgent actions always require human approval" if {
    input.agent_type == "ProvisionerAgent"
    not input.context.pre_approved
}
