"""Tool registry — maps scope-tagged tools available to agents.

Each tool entry declares:
  - The action string used in policy evaluation (e.g. "s3:GetObject")
  - The minimum scope required in the agent's token
  - The risk level (used by approval workflow)
  - Whether the action is destructive (always triggers REQUIRE_APPROVAL)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ToolSpec:
    name: str              # human-readable
    action: str            # policy action string
    required_scope: str    # must be in agent's token scopes
    risk_level: RiskLevel
    destructive: bool = False


# ------------------------------------------------------------------
# Master tool catalog
# ------------------------------------------------------------------

TOOL_CATALOG: dict[str, ToolSpec] = {
    # S3
    "s3_list_buckets": ToolSpec("List S3 Buckets", "s3:ListBuckets", "cloud:s3:list", RiskLevel.LOW),
    "s3_get_object": ToolSpec("Get S3 Object", "s3:GetObject", "cloud:s3:read", RiskLevel.LOW),
    "s3_put_object": ToolSpec("Put S3 Object", "s3:PutObject", "cloud:s3:write", RiskLevel.MEDIUM),
    "s3_delete_object": ToolSpec("Delete S3 Object", "s3:DeleteObject", "cloud:s3:delete", RiskLevel.HIGH, destructive=True),
    "s3_delete_bucket": ToolSpec("Delete S3 Bucket", "s3:DeleteBucket", "cloud:s3:delete", RiskLevel.HIGH, destructive=True),
    # EC2
    "ec2_describe_instances": ToolSpec("Describe EC2 Instances", "ec2:DescribeInstances", "cloud:ec2:describe", RiskLevel.LOW),
    "ec2_describe_security_groups": ToolSpec("Describe Security Groups", "ec2:DescribeSecurityGroups", "cloud:ec2:describe", RiskLevel.LOW),
    "ec2_terminate_instance": ToolSpec("Terminate EC2 Instance", "ec2:TerminateInstances", "cloud:ec2:terminate", RiskLevel.HIGH, destructive=True),
    # IAM
    "iam_list_roles": ToolSpec("List IAM Roles", "iam:ListRoles", "cloud:iam:read", RiskLevel.LOW),
    "iam_create_role": ToolSpec("Create IAM Role", "iam:CreateRole", "cloud:iam:create-role", RiskLevel.HIGH),
    # SecurityHub / GuardDuty
    "securityhub_get_findings": ToolSpec("Get Security Findings", "securityhub:GetFindings", "cloud:securityhub:read", RiskLevel.LOW),
}


class ToolRegistry:
    """Per-agent view of the tool catalog, filtered to the agent's granted scopes."""

    def __init__(self, granted_scopes: list[str]) -> None:
        self._granted_scopes = set(granted_scopes)
        self._available: dict[str, ToolSpec] = {
            key: spec
            for key, spec in TOOL_CATALOG.items()
            if spec.required_scope in self._granted_scopes
        }

    def get(self, tool_key: str) -> ToolSpec:
        if tool_key not in self._available:
            raise ToolNotAvailableError(
                f"Tool '{tool_key}' is not available to this agent. "
                f"Available: {list(self._available.keys())}"
            )
        return self._available[tool_key]

    def available_tools(self) -> list[str]:
        return list(self._available.keys())


class ToolNotAvailableError(Exception):
    """Raised when an agent attempts to call a tool outside its granted scopes."""
