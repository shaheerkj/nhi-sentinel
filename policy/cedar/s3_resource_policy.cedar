// NHI-Sentinel — S3 Resource Authorization Policies (AWS Cedar)
//
// Cedar handles resource-level decisions that OPA's general-purpose Rego policies
// don't encode. Cedar has formal verification properties — you can prove these
// policies are complete and non-contradictory.
//
// Entity model:
//   Principal: NHI::Agent { agent_type: String, scopes: Set<String> }
//   Action:    NHI::Action
//   Resource:  NHI::S3Bucket { DataClassification: String, Environment: String }

// ----------------------------------------------------------------
// PERMIT: InfraAgent may list and read from public/internal buckets
// ----------------------------------------------------------------
permit (
    principal is NHI::Agent,
    action in [NHI::Action::"s3:ListBuckets", NHI::Action::"s3:GetObject"],
    resource is NHI::S3Bucket
)
when {
    principal.agent_type == "InfraAgent" &&
    resource.DataClassification in ["public", "internal"]
};

// ----------------------------------------------------------------
// PERMIT: DataAgent may read and write to public/internal buckets
// ----------------------------------------------------------------
permit (
    principal is NHI::Agent,
    action in [
        NHI::Action::"s3:GetObject",
        NHI::Action::"s3:PutObject",
        NHI::Action::"s3:ListBuckets"
    ],
    resource is NHI::S3Bucket
)
when {
    principal.agent_type == "DataAgent" &&
    resource.DataClassification in ["public", "internal"]
};

// ----------------------------------------------------------------
// FORBID: No agent may access restricted or confidential buckets
//         without explicit elevation (handled by approval workflow)
// ----------------------------------------------------------------
forbid (
    principal is NHI::Agent,
    action,
    resource is NHI::S3Bucket
)
when {
    resource.DataClassification in ["confidential", "restricted"]
};

// ----------------------------------------------------------------
// FORBID: No agent may access prod-environment resources
//         unless explicitly permitted (overrides any permit above)
// ----------------------------------------------------------------
forbid (
    principal is NHI::Agent,
    action,
    resource is NHI::S3Bucket
)
when {
    resource.Environment == "prod"
};
