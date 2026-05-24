"""DataAgent — moves and transforms data between pipeline stages.

Default scopes: cloud:s3:read, cloud:s3:write (tagged buckets only)
Prohibited: cloud:iam:*, cloud:ec2:*
Risk level: Medium
Resource restriction: buckets tagged DataClassification: internal or public only
"""

from __future__ import annotations

import json
import logging

import boto3

from agents.base.agent import AgentState, BaseAgent
from identity.manifest_schema import AgentType

logger = logging.getLogger(__name__)


class DataAgent(BaseAgent):
    agent_type = AgentType.DATA

    def _get_tool_handlers(self) -> dict:
        return {
            "s3_list_buckets": self._handle_s3_list,
            "s3_get_object": self._handle_s3_get,
            "s3_put_object": self._handle_s3_put,
        }

    def _handle_s3_list(self, state: AgentState) -> dict:
        s3 = boto3.client("s3", region_name=self._region)
        resp = s3.list_buckets()
        buckets = []
        for b in resp.get("Buckets", []):
            try:
                tags_resp = s3.get_bucket_tagging(Bucket=b["Name"])
                tags = {t["Key"]: t["Value"] for t in tags_resp.get("TagSet", [])}
            except Exception:
                tags = {}
            # DataAgent only operates on accessible-classification buckets
            if tags.get("DataClassification") in ("public", "internal"):
                buckets.append({"name": b["Name"], "tags": tags})
        logger.info("DataAgent listed %d accessible buckets", len(buckets))
        return {"buckets": buckets, "count": len(buckets)}

    def _handle_s3_get(self, state: AgentState) -> dict:
        parts = state["resource_arn"].replace("arn:aws:s3:::", "").split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Cannot parse S3 ARN: {state['resource_arn']}")
        bucket, key = parts
        s3 = boto3.client("s3", region_name=self._region)
        resp = s3.get_object(Bucket=bucket, Key=key)
        content = resp["Body"].read().decode("utf-8", errors="replace")
        logger.info("DataAgent read s3://%s/%s", bucket, key)
        return {"bucket": bucket, "key": key, "content": content, "bytes": len(content)}

    def _handle_s3_put(self, state: AgentState) -> dict:
        parts = state["resource_arn"].replace("arn:aws:s3:::", "").split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Cannot parse S3 ARN for put: {state['resource_arn']}")
        bucket, key = parts
        payload = state["context"].get("payload", b"")
        if isinstance(payload, dict):
            payload = json.dumps(payload).encode()
        elif isinstance(payload, str):
            payload = payload.encode()
        s3 = boto3.client("s3", region_name=self._region)
        s3.put_object(Bucket=bucket, Key=key, Body=payload)
        logger.info("DataAgent wrote %d bytes to s3://%s/%s", len(payload), bucket, key)
        return {"bucket": bucket, "key": key, "bytes_written": len(payload)}
