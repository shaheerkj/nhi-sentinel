"""InfraAgent — describes and queries cloud infrastructure (read-only).

Default scopes: cloud:ec2:describe, cloud:s3:list, cloud:s3:read
Risk level: Low
Prohibited: all write operations
"""

from __future__ import annotations

import logging

import boto3

from agents.base.agent import AgentState, BaseAgent
from identity.manifest_schema import AgentType

logger = logging.getLogger(__name__)


class InfraAgent(BaseAgent):
    agent_type = AgentType.INFRA

    def _get_tool_handlers(self) -> dict:
        return {
            "ec2_describe_instances": self._handle_ec2_describe,
            "ec2_describe_security_groups": self._handle_ec2_describe_sg,
            "s3_list_buckets": self._handle_s3_list_buckets,
            "s3_get_object": self._handle_s3_get_object,
        }

    def _handle_ec2_describe(self, state: AgentState) -> dict:
        ec2 = boto3.client("ec2", region_name=self._region)
        resp = ec2.describe_instances()
        instances = [
            {
                "instance_id": i["InstanceId"],
                "state": i["State"]["Name"],
                "instance_type": i["InstanceType"],
                "tags": {t["Key"]: t["Value"] for t in i.get("Tags", [])},
            }
            for r in resp["Reservations"]
            for i in r["Instances"]
        ]
        logger.info("InfraAgent described %d EC2 instances", len(instances))
        return {"instances": instances, "count": len(instances)}

    def _handle_ec2_describe_sg(self, state: AgentState) -> dict:
        ec2 = boto3.client("ec2", region_name=self._region)
        resp = ec2.describe_security_groups()
        groups = [
            {
                "group_id": sg["GroupId"],
                "group_name": sg["GroupName"],
                "description": sg["Description"],
            }
            for sg in resp["SecurityGroups"]
        ]
        logger.info("InfraAgent described %d security groups", len(groups))
        return {"security_groups": groups, "count": len(groups)}

    def _handle_s3_list_buckets(self, state: AgentState) -> dict:
        s3 = boto3.client("s3", region_name=self._region)
        resp = s3.list_buckets()
        buckets = [b["Name"] for b in resp.get("Buckets", [])]
        logger.info("InfraAgent listed %d S3 buckets", len(buckets))
        return {"buckets": buckets, "count": len(buckets)}

    def _handle_s3_get_object(self, state: AgentState) -> dict:
        # resource_arn expected: arn:aws:s3:::bucket-name/key
        parts = state["resource_arn"].replace("arn:aws:s3:::", "").split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Cannot parse S3 ARN: {state['resource_arn']}")
        bucket, key = parts
        s3 = boto3.client("s3", region_name=self._region)
        resp = s3.get_object(Bucket=bucket, Key=key)
        content = resp["Body"].read().decode("utf-8", errors="replace")
        logger.info("InfraAgent read s3://%s/%s (%d bytes)", bucket, key, len(content))
        return {"bucket": bucket, "key": key, "content": content, "size": len(content)}
