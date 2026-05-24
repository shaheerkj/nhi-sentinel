// NHI-Sentinel — IAM Resource Authorization Policies (AWS Cedar)
//
// IAM actions are the highest-risk operations in the system.
// Cedar enforces that only ProvisionerAgent can touch IAM, and only
// using pre-approved role templates — arbitrary policy documents are forbidden.
//
// Entity model:
//   Principal: NHI::Agent { agent_type: String }
//   Action:    NHI::Action
//   Resource:  NHI::IAMRole { template_name: String, managed_by: String }

// ----------------------------------------------------------------
// PERMIT: ProvisionerAgent may create roles using approved templates only
// ----------------------------------------------------------------
permit (
    principal is NHI::Agent,
    action == NHI::Action::"iam:CreateRole",
    resource is NHI::IAMRole
)
when {
    principal.agent_type == "ProvisionerAgent" &&
    resource.managed_by == "nhi-sentinel" &&
    resource.template_name != ""
};

// ----------------------------------------------------------------
// PERMIT: InfraAgent and SecOpsAgent may list/read IAM roles (read-only)
// ----------------------------------------------------------------
permit (
    principal is NHI::Agent,
    action == NHI::Action::"iam:ListRoles",
    resource is NHI::IAMRole
)
when {
    principal.agent_type in ["InfraAgent", "SecOpsAgent"]
};

// ----------------------------------------------------------------
// FORBID: DataAgent may never touch IAM resources
// ----------------------------------------------------------------
forbid (
    principal is NHI::Agent,
    action,
    resource is NHI::IAMRole
)
when {
    principal.agent_type == "DataAgent"
};

// ----------------------------------------------------------------
// FORBID: No agent may create arbitrary IAM policies (only templates)
// ----------------------------------------------------------------
forbid (
    principal is NHI::Agent,
    action in [
        NHI::Action::"iam:CreatePolicy",
        NHI::Action::"iam:PutUserPolicy",
        NHI::Action::"iam:AttachUserPolicy"
    ],
    resource
);

// ----------------------------------------------------------------
// FORBID: No agent may perform admin-level IAM operations
// ----------------------------------------------------------------
forbid (
    principal is NHI::Agent,
    action in [
        NHI::Action::"iam:CreateUser",
        NHI::Action::"iam:DeleteUser",
        NHI::Action::"iam:UpdateAssumeRolePolicy"
    ],
    resource
);
