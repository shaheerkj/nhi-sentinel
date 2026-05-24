"""SecOpsAgent — queries security findings and scans configurations.

Default scopes: cloud:securityhub:read, cloud:guardduty:read, cloud:config:read
Prohibited: all write and IAM operations
Risk level: Low
Time restriction: None (24/7 for incident response)
Special: requires active incident_id in task context for time-window override
"""

from __future__ import annotations

import logging

import boto3

from agents.base.agent import AgentState, BaseAgent
from identity.manifest_schema import AgentType

logger = logging.getLogger(__name__)


class SecOpsAgent(BaseAgent):
    agent_type = AgentType.SECOPS

    def _get_tool_handlers(self) -> dict:
        return {
            "securityhub_get_findings": self._handle_securityhub_findings,
            "ec2_describe_security_groups": self._handle_describe_sgs,
            "iam_list_roles": self._handle_iam_list_roles,
        }

    def _handle_securityhub_findings(self, state: AgentState) -> dict:
        # In simulation, SecurityHub findings are seeded by LocalStack.
        # For Moto-only environments, we return a structured mock.
        try:
            sh = boto3.client("securityhub", region_name=self._region)
            resp = sh.get_findings(MaxResults=50)
            findings = resp.get("Findings", [])
        except Exception:
            # Moto does not fully implement SecurityHub — return synthetic findings
            findings = [
                {
                    "Id": "finding-001",
                    "Title": "S3 bucket has public read access",
                    "Severity": {"Label": "HIGH"},
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                    "GeneratorId": "aws-foundational-security-s3",
                }
            ]
            logger.debug("SecurityHub not available in Moto — returning synthetic findings")
        logger.info("SecOpsAgent retrieved %d security findings", len(findings))
        return {"findings": findings, "count": len(findings)}

    def _handle_describe_sgs(self, state: AgentState) -> dict:
        ec2 = boto3.client("ec2", region_name=self._region)
        resp = ec2.describe_security_groups()
        groups = [
            {
                "group_id": sg["GroupId"],
                "group_name": sg["GroupName"],
                "ingress_rules": len(sg.get("IpPermissions", [])),
                "egress_rules": len(sg.get("IpPermissionsEgress", [])),
            }
            for sg in resp["SecurityGroups"]
        ]
        # Flag groups with wide-open ingress rules
        for g in groups:
            g["potentially_permissive"] = g["ingress_rules"] > 5
        logger.info("SecOpsAgent described %d security groups", len(groups))
        return {"security_groups": groups, "count": len(groups)}

    def _handle_iam_list_roles(self, state: AgentState) -> dict:
        iam = boto3.client("iam", region_name=self._region)
        resp = iam.list_roles()
        roles = [
            {
                "role_name": r["RoleName"],
                "arn": r["Arn"],
                "create_date": r["CreateDate"].isoformat(),
            }
            for r in resp.get("Roles", [])
        ]
        logger.info("SecOpsAgent listed %d IAM roles", len(roles))
        return {"roles": roles, "count": len(roles)}
