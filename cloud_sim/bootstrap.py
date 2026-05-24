"""Seed the Moto AWS simulation with pre-classified resources.

Called once at environment startup. Creates buckets, EC2 instances, and IAM roles
with the resource tags the policy engine evaluates.
"""

from __future__ import annotations

import logging

import boto3

logger = logging.getLogger(__name__)

# Resources are pre-seeded with these classification tags.
# Cedar and OPA policies read DataClassification to make access decisions.
_BUCKETS = [
    {
        "name": "nhi-data-public-01",
        "tags": {"DataClassification": "public", "Environment": "staging", "ManagedBy": "nhi-sentinel"},
    },
    {
        "name": "nhi-data-internal-01",
        "tags": {"DataClassification": "internal", "Environment": "staging", "ManagedBy": "nhi-sentinel"},
    },
    {
        "name": "nhi-data-confidential-01",
        "tags": {"DataClassification": "confidential", "Environment": "staging", "ManagedBy": "nhi-sentinel"},
    },
    {
        "name": "nhi-data-prod-restricted-01",
        "tags": {"DataClassification": "restricted", "Environment": "prod", "ManagedBy": "nhi-sentinel"},
    },
]

_IAM_ROLES = [
    {
        "name": "nhi-readonly-role",
        "assume_role_policy": """{
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        }""",
        "tags": {"ManagedBy": "nhi-sentinel", "RiskLevel": "low"},
    },
]


def seed_environment(region: str = "us-east-1") -> None:
    """Create all simulated resources. Must be called inside a Moto mock context."""
    _seed_s3(region)
    _seed_ec2(region)
    _seed_iam()
    logger.info("Cloud simulation environment seeded successfully")


def _seed_s3(region: str) -> None:
    s3 = boto3.client("s3", region_name=region)
    for spec in _BUCKETS:
        try:
            if region == "us-east-1":
                s3.create_bucket(Bucket=spec["name"])
            else:
                s3.create_bucket(
                    Bucket=spec["name"],
                    CreateBucketConfiguration={"LocationConstraint": region},
                )
            s3.put_bucket_tagging(
                Bucket=spec["name"],
                Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in spec["tags"].items()]},
            )
            s3.put_object(
                Bucket=spec["name"],
                Key="sample/data.json",
                Body=b'{"records": [{"id": 1, "value": "sample"}]}',
            )
            logger.debug("Created S3 bucket: %s", spec["name"])
        except s3.exceptions.BucketAlreadyOwnedByYou:
            pass


def _seed_ec2(region: str) -> None:
    ec2 = boto3.client("ec2", region_name=region)
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=2,
        MaxCount=2,
        InstanceType="t3.micro",
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Environment", "Value": "staging"},
                    {"Key": "ManagedBy", "Value": "nhi-sentinel"},
                ],
            }
        ],
    )
    logger.debug("Created EC2 instances in %s", region)


def _seed_iam() -> None:
    iam = boto3.client("iam")
    for role in _IAM_ROLES:
        try:
            iam.create_role(
                RoleName=role["name"],
                AssumeRolePolicyDocument=role["assume_role_policy"],
                Tags=[{"Key": k, "Value": v} for k, v in role["tags"].items()],
            )
            logger.debug("Created IAM role: %s", role["name"])
        except iam.exceptions.EntityAlreadyExistsException:
            pass
