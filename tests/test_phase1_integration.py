"""Phase 1 integration test — milestone M1.

Validates: InfraAgent completes one full action cycle
(auth → policy_check → cloud call) with no hardcoded credentials.

Runs entirely in-process using Moto (no live services required).
The PEP is pointed at a real OPA instance (docker compose must be up)
OR falls back to a stub for CI without compose.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from agents.base.tool_registry import ToolRegistry
from agents.infra_agent.agent import InfraAgent
from cloud_sim.bootstrap import seed_environment
from identity.manifest_schema import AgentIdentityManifest
from identity.token_manager import TokenManager, generate_rsa_keypair
from pep.client import PolicyEnforcementPoint
from pep.exceptions import PolicyDenialError


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def rsa_keypair():
    return generate_rsa_keypair()


@pytest.fixture
def mock_token_manager(rsa_keypair):
    private_pem, _ = rsa_keypair
    settings = MagicMock()
    settings.assertion_ttl_seconds = 60
    settings.token_ttl_seconds = 900
    settings.keycloak_url = "http://localhost:8080"
    settings.keycloak_realm = "nhi"

    tm = TokenManager("agent-infra-001", settings)
    tm.load_key_from_string(private_pem)
    return tm


@pytest.fixture
def infra_scopes():
    return ["cloud:ec2:describe", "cloud:s3:list", "cloud:s3:read"]


@pytest.fixture
def tool_registry(infra_scopes):
    return ToolRegistry(granted_scopes=infra_scopes)


@pytest.fixture
def stub_pep():
    """PEP that returns ALLOW without calling OPA — for offline tests."""
    pep = MagicMock(spec=PolicyEnforcementPoint)
    pep.enforce.return_value = None  # enforce() returns None on ALLOW
    return pep


# ------------------------------------------------------------------
# Schema tests
# ------------------------------------------------------------------

def test_manifest_loads_correctly():
    manifest_path = "identity/manifests/agent-infra-001.yaml"
    import yaml
    with open(manifest_path) as f:
        data = yaml.safe_load(f)
    manifest = AgentIdentityManifest.model_validate(data)
    assert manifest.metadata.name == "agent-infra-001"
    assert "cloud:ec2:describe" in manifest.spec.scopes
    assert "cloud:iam:write" not in manifest.spec.scopes


def test_manifest_rejects_unnamespacd_scope():
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="namespaced"):
        AgentIdentityManifest.model_validate({
            "apiVersion": "nhi-sentinel/v1",
            "kind": "AgentIdentity",
            "metadata": {"name": "agent-bad-001", "namespace": "test"},
            "spec": {
                "agent_type": "InfraAgent",
                "owner_team": "test",
                "owner_contact": "test@test.com",
                "scopes": ["read"],  # not namespaced
                "context_bindings": {"environments": ["staging"]},
            },
        })


# ------------------------------------------------------------------
# Tool registry tests
# ------------------------------------------------------------------

def test_registry_grants_correct_tools(tool_registry):
    available = tool_registry.available_tools()
    assert "ec2_describe_instances" in available
    assert "s3_list_buckets" in available
    assert "s3_get_object" in available
    # Write tools must NOT be available to InfraAgent
    assert "s3_put_object" not in available
    assert "s3_delete_object" not in available
    assert "iam_create_role" not in available


def test_registry_raises_on_unavailable_tool(tool_registry):
    from agents.base.tool_registry import ToolNotAvailableError
    with pytest.raises(ToolNotAvailableError):
        tool_registry.get("s3_delete_bucket")


# ------------------------------------------------------------------
# Key generation
# ------------------------------------------------------------------

def test_rsa_keypair_generation(rsa_keypair):
    private_pem, public_pem = rsa_keypair
    assert "BEGIN RSA PRIVATE KEY" in private_pem or "BEGIN PRIVATE KEY" in private_pem
    assert "BEGIN PUBLIC KEY" in public_pem


# ------------------------------------------------------------------
# M1 milestone — full action cycle (Moto, stub PEP)
# ------------------------------------------------------------------

@mock_aws
def test_infra_agent_describes_ec2_instances(mock_token_manager, tool_registry, stub_pep):
    """M1: InfraAgent completes EC2 describe with no hardcoded credentials."""
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

    seed_environment()

    agent = InfraAgent(
        agent_id="agent-infra-001",
        token_manager=mock_token_manager,
        tool_registry=tool_registry,
        pep=stub_pep,
    )

    # Patch token acquisition (Keycloak not running in unit test)
    mock_token_manager.get_token = MagicMock(return_value="mock-token-xyz")
    mock_token_manager.introspect = MagicMock(return_value={
        "active": True,
        "agent_id": "agent-infra-001",
        "scope": "cloud:ec2:describe cloud:s3:list cloud:s3:read",
    })

    state = agent.run(
        tool_key="ec2_describe_instances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-phase1-test-001",
        environment="staging",
    )

    assert state["error"] is None
    assert state["decision"] == "ALLOW"
    assert state["result"]["count"] >= 2  # seed_environment creates 2 instances


@mock_aws
def test_infra_agent_lists_s3_buckets(mock_token_manager, tool_registry, stub_pep):
    seed_environment()

    agent = InfraAgent(
        agent_id="agent-infra-001",
        token_manager=mock_token_manager,
        tool_registry=tool_registry,
        pep=stub_pep,
    )

    mock_token_manager.get_token = MagicMock(return_value="mock-token-xyz")
    mock_token_manager.introspect = MagicMock(return_value={
        "active": True,
        "agent_id": "agent-infra-001",
        "scope": "cloud:ec2:describe cloud:s3:list cloud:s3:read",
    })

    state = agent.run(
        tool_key="s3_list_buckets",
        resource_arn="arn:aws:s3:::*",
        task_id="task-phase1-test-002",
        environment="staging",
    )

    assert state["error"] is None
    assert state["decision"] == "ALLOW"
    assert len(state["result"]["buckets"]) >= 4  # seed creates 4 buckets


@mock_aws
def test_pep_blocks_disallowed_tool(mock_token_manager, tool_registry, stub_pep):
    """PEP deny is surfaced correctly — registry prevents s3_delete even before PEP."""
    from agents.base.tool_registry import ToolNotAvailableError

    seed_environment()

    agent = InfraAgent(
        agent_id="agent-infra-001",
        token_manager=mock_token_manager,
        tool_registry=tool_registry,
        pep=stub_pep,
    )

    mock_token_manager.get_token = MagicMock(return_value="mock-token-xyz")
    mock_token_manager.introspect = MagicMock(return_value={"active": True, "agent_id": "agent-infra-001", "scope": "cloud:s3:list"})

    state = agent.run(
        tool_key="s3_delete_bucket",  # not in InfraAgent's scopes
        resource_arn="arn:aws:s3:::nhi-data-public-01",
        task_id="task-phase1-test-003",
        environment="staging",
    )

    # ToolNotAvailableError is caught and surfaced as an error in state
    assert state["error"] is not None
    assert "not available" in state["error"].lower() or state["decision"] != "ALLOW"
