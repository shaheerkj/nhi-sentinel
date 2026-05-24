package nhi.destructive_gate_test

import data.nhi.destructive_gate
import rego.v1

# s3:DeleteObject always requires approval
test_s3_delete_requires_approval if {
    destructive_gate.requires_approval with input as {
        "action": "s3:DeleteObject",
        "agent_type": "DataAgent",
        "context": {},
    }
}

# s3:DeleteBucket always requires approval
test_s3_delete_bucket_requires_approval if {
    destructive_gate.requires_approval with input as {
        "action": "s3:DeleteBucket",
        "agent_type": "DataAgent",
        "context": {},
    }
}

# ec2:TerminateInstances always requires approval
test_ec2_terminate_requires_approval if {
    destructive_gate.requires_approval with input as {
        "action": "ec2:TerminateInstances",
        "agent_type": "InfraAgent",
        "context": {},
    }
}

# iam:CreateUser requires approval (IAM write action)
test_iam_create_user_requires_approval if {
    destructive_gate.requires_approval with input as {
        "action": "iam:CreateUser",
        "agent_type": "ProvisionerAgent",
        "context": {},
    }
}

# ProvisionerAgent always requires approval regardless of action
test_provisioner_always_requires_approval if {
    destructive_gate.requires_approval with input as {
        "action": "iam:CreateRole",
        "agent_type": "ProvisionerAgent",
        "context": {},
    }
}

# Pre-approved destructive action does NOT require further approval
test_pre_approved_destructive_allowed if {
    not destructive_gate.requires_approval with input as {
        "action": "s3:DeleteObject",
        "agent_type": "DataAgent",
        "context": {"pre_approved": true},
    }
}

# Safe action — s3:GetObject does not require approval
test_safe_action_no_approval_required if {
    not destructive_gate.requires_approval with input as {
        "action": "s3:GetObject",
        "agent_type": "InfraAgent",
        "context": {},
    }
}
