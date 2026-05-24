"""ProvisionerAgent — creates IAM roles using pre-approved policy templates.

Default scopes: cloud:iam:create-role (template-constrained only)
Prohibited: cloud:iam:create-policy, cloud:iam:attach-user-policy, cloud:iam:*admin*
Risk level: HIGH
Approval: ALWAYS required — there is no ALLOW path for this agent
Template enforcement: only roles defined in policy/templates/iam_role_templates.yaml
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import boto3
import yaml

from agents.base.agent import AgentState, BaseAgent
from identity.manifest_schema import AgentType

logger = logging.getLogger(__name__)

_TEMPLATES_PATH = Path(__file__).parent.parent.parent / "policy" / "templates" / "iam_role_templates.yaml"


def _load_templates() -> dict:
    if not _TEMPLATES_PATH.exists():
        return {}
    with open(_TEMPLATES_PATH) as f:
        return yaml.safe_load(f) or {}


class ProvisionerAgent(BaseAgent):
    agent_type = AgentType.PROVISIONER

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._templates = _load_templates()

    def _get_tool_handlers(self) -> dict:
        return {
            "iam_create_role": self._handle_create_role,
            "iam_list_roles": self._handle_list_roles,
        }

    def _handle_create_role(self, state: AgentState) -> dict:
        template_name = state["context"].get("template_name")
        if not template_name:
            raise ValueError("ProvisionerAgent requires 'template_name' in context")

        templates = self._templates.get("templates", {})
        if template_name not in templates:
            available = list(templates.keys())
            raise ValueError(
                f"Template '{template_name}' not in approved templates. "
                f"Available: {available}"
            )

        template = templates[template_name]
        role_name = state["context"].get("role_name", f"nhi-provisioned-{template_name}")

        assume_role_policy = json.dumps(template.get("assume_role_policy_document", {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }))

        iam = boto3.client("iam", region_name=self._region)
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy,
            Tags=[
                {"Key": "ManagedBy", "Value": "nhi-sentinel"},
                {"Key": "Template", "Value": template_name},
                {"Key": "TicketRef", "Value": state["context"].get("ticket_ref", "")},
            ],
        )

        role_arn = resp["Role"]["Arn"]
        logger.info("ProvisionerAgent created role %s from template %s", role_name, template_name)
        return {"role_name": role_name, "role_arn": role_arn, "template": template_name}

    def _handle_list_roles(self, state: AgentState) -> dict:
        iam = boto3.client("iam", region_name=self._region)
        resp = iam.list_roles()
        # Only show roles managed by nhi-sentinel
        managed_roles = [
            r for r in resp.get("Roles", [])
            if any(t.get("Key") == "ManagedBy" and t.get("Value") == "nhi-sentinel"
                   for t in r.get("Tags", []))
        ]
        return {"roles": [r["RoleName"] for r in managed_roles], "count": len(managed_roles)}
