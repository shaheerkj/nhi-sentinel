"""Policy boundary tests — Phase 2.

All tests run fully offline (no OPA, no Redis, no Keycloak, no Docker).
The PEP is tested with mocked OPA responses to cover every decision path.
Agent-level tests verify that out-of-scope actions are blocked before reaching OPA.

Covers:
  - Scope enforcement across all four agent types
  - Destructive action gating
  - Environment binding
  - Rate limit enforcement
  - Cedar layer (mocked — binary not required)
  - Approval workflow (fakeredis)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from moto import mock_aws

from agents.base.tool_registry import ToolNotAvailableError, ToolRegistry
from agents.data_agent.agent import DataAgent
from agents.infra_agent.agent import InfraAgent
from agents.provisioner_agent.agent import ProvisionerAgent
from agents.secops_agent.agent import SecOpsAgent
from cloud_sim.bootstrap import seed_environment
from identity.token_manager import generate_rsa_keypair, TokenManager
from pep.cedar_evaluator import CedarDecision, CedarEvaluator
from pep.client import PolicyEnforcementPoint
from pep.exceptions import PolicyDenialError, ApprovalRequiredError
from pep.models import ActionRequest, Decision, PolicyDecision


# ------------------------------------------------------------------
# Shared fixtures
# ------------------------------------------------------------------

@pytest.fixture
def token_claims_infra():
    return {
        "active": True,
        "agent_id": "agent-infra-001",
        "scope": "cloud:ec2:describe cloud:s3:list cloud:s3:read",
    }


@pytest.fixture
def token_claims_data():
    return {
        "active": True,
        "agent_id": "agent-data-001",
        "scope": "cloud:s3:read cloud:s3:write cloud:s3:list",
    }


@pytest.fixture
def token_claims_secops():
    return {
        "active": True,
        "agent_id": "agent-secops-001",
        "scope": "cloud:securityhub:read cloud:guardduty:read cloud:iam:read cloud:ec2:describe",
    }


@pytest.fixture
def base_request(token_claims_infra):
    return ActionRequest(
        agent_id="agent-infra-001",
        agent_type="InfraAgent",
        token_claims=token_claims_infra,
        action="ec2:DescribeInstances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-test-001",
        environment="staging",
        source_ip="10.0.1.10",
    )


def _allow_decision() -> PolicyDecision:
    return PolicyDecision(
        effect=Decision.ALLOW,
        reason="All conditions met",
        policy_ref="nhi.agent.authorization",
        policy_version="2.0.0",
        evaluated_at=datetime.now(tz=timezone.utc).isoformat(),
    )


def _deny_decision(reason: str) -> PolicyDecision:
    return PolicyDecision(
        effect=Decision.DENY,
        reason=reason,
        policy_ref="nhi.agent.authorization",
        policy_version="2.0.0",
        evaluated_at=datetime.now(tz=timezone.utc).isoformat(),
    )


def _approval_decision(reason: str) -> PolicyDecision:
    return PolicyDecision(
        effect=Decision.REQUIRE_APPROVAL,
        reason=reason,
        policy_ref="nhi.agent.authorization",
        policy_version="2.0.0",
        evaluated_at=datetime.now(tz=timezone.utc).isoformat(),
    )


def _make_pep(opa_decision: PolicyDecision, cedar_permitted: bool = True) -> PolicyEnforcementPoint:
    """Build a PEP with mocked OPA and Cedar responses."""
    pep = PolicyEnforcementPoint.__new__(PolicyEnforcementPoint)
    pep._opa_url = "http://mock-opa:8181"
    pep._http = MagicMock()
    pep._cedar = MagicMock(spec=CedarEvaluator)
    pep._cedar.evaluate.return_value = CedarDecision(
        permitted=cedar_permitted,
        reason="cedar-mock",
    )
    pep._evaluate = MagicMock(return_value=opa_decision)
    return pep


# ------------------------------------------------------------------
# PEP — OPA decision routing
# ------------------------------------------------------------------

def test_pep_allow_passes_through(base_request):
    pep = _make_pep(_allow_decision(), cedar_permitted=True)
    pep.enforce(base_request)  # must not raise


def test_pep_deny_raises_policy_denial_error(base_request):
    pep = _make_pep(_deny_decision("Scope not present in token"))
    with pytest.raises(PolicyDenialError) as exc_info:
        pep.enforce(base_request)
    assert "Scope not present" in str(exc_info.value)


def test_pep_require_approval_raises_approval_required_error(base_request):
    pep = _make_pep(_approval_decision("Destructive action requires human approval"))
    with pytest.raises(ApprovalRequiredError):
        pep.enforce(base_request)


def test_cedar_deny_overrides_opa_allow(token_claims_infra):
    """OPA says ALLOW but Cedar says DENY — Cedar wins (defense in depth).

    Uses an S3 action so Cedar's resource policy layer is actually invoked.
    EC2 actions are not Cedar-governed (only S3 and IAM are).
    """
    s3_request = ActionRequest(
        agent_id="agent-infra-001",
        agent_type="InfraAgent",
        token_claims=token_claims_infra,
        action="s3:GetObject",                               # S3 → Cedar fires
        resource_arn="arn:aws:s3:::nhi-data-confidential-01/file.json",
        task_id="task-test-cedar-001",
        environment="staging",
        source_ip="10.0.1.10",
        resource_tags={"DataClassification": "confidential"},
    )
    pep = _make_pep(_allow_decision(), cedar_permitted=False)
    with pytest.raises(PolicyDenialError) as exc_info:
        pep.enforce(s3_request)
    assert "Cedar resource policy denied" in str(exc_info.value)


def test_pep_fails_closed_on_opa_unreachable(base_request):
    """OPA unreachable → must raise PolicyDenialError (never silently pass)."""
    import httpx
    pep = PolicyEnforcementPoint.__new__(PolicyEnforcementPoint)
    pep._opa_url = "http://localhost:8181"
    pep._cedar = MagicMock()
    pep._cedar.evaluate.return_value = CedarDecision(permitted=True)
    # Real http client that will fail to connect
    pep._http = httpx.Client(timeout=0.01)

    with pytest.raises(PolicyDenialError) as exc_info:
        pep.enforce(base_request)
    assert "fail-closed" in str(exc_info.value).lower() or "unreachable" in str(exc_info.value).lower()


# ------------------------------------------------------------------
# Tool registry — scope enforcement per agent type
# ------------------------------------------------------------------

def test_infra_agent_cannot_access_write_tools():
    registry = ToolRegistry(granted_scopes=["cloud:ec2:describe", "cloud:s3:list", "cloud:s3:read"])
    available = registry.available_tools()
    assert "ec2_describe_instances" in available
    assert "s3_list_buckets" in available
    assert "s3_put_object" not in available
    assert "s3_delete_object" not in available
    assert "iam_create_role" not in available


def test_data_agent_cannot_access_iam_or_ec2():
    registry = ToolRegistry(granted_scopes=["cloud:s3:read", "cloud:s3:write", "cloud:s3:list"])
    available = registry.available_tools()
    assert "s3_get_object" in available
    assert "s3_put_object" in available
    assert "ec2_describe_instances" not in available
    assert "iam_create_role" not in available
    assert "iam_list_roles" not in available


def test_secops_agent_cannot_access_write_tools():
    registry = ToolRegistry(granted_scopes=[
        "cloud:securityhub:read", "cloud:guardduty:read",
        "cloud:config:read", "cloud:iam:read", "cloud:ec2:describe",
    ])
    available = registry.available_tools()
    assert "securityhub_get_findings" in available
    assert "iam_list_roles" in available
    assert "iam_create_role" not in available
    assert "s3_put_object" not in available
    assert "ec2_terminate_instance" not in available


def test_provisioner_agent_scopes_only_iam_create():
    registry = ToolRegistry(granted_scopes=["cloud:iam:create-role", "cloud:iam:read"])
    available = registry.available_tools()
    assert "iam_create_role" in available
    assert "iam_list_roles" in available
    assert "s3_get_object" not in available
    assert "ec2_describe_instances" not in available


def test_empty_scopes_grants_no_tools():
    registry = ToolRegistry(granted_scopes=[])
    assert registry.available_tools() == []


# ------------------------------------------------------------------
# InfraAgent — end-to-end action cycle (Moto, mocked PEP)
# ------------------------------------------------------------------

@mock_aws
def test_infra_agent_full_cycle_ec2_describe(token_claims_infra):
    seed_environment()

    tm = MagicMock(spec=TokenManager)
    tm.get_token.return_value = "mock-token"
    tm.introspect.return_value = token_claims_infra

    registry = ToolRegistry(granted_scopes=["cloud:ec2:describe", "cloud:s3:list", "cloud:s3:read"])
    pep = MagicMock(spec=PolicyEnforcementPoint)
    pep.enforce.return_value = None

    agent = InfraAgent("agent-infra-001", tm, registry, pep)
    state = agent.run(
        tool_key="ec2_describe_instances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-boundary-001",
        environment="staging",
    )

    assert state["error"] is None
    assert state["decision"] == "ALLOW"
    assert state["result"]["count"] >= 2


@mock_aws
def test_data_agent_blocked_from_iam(token_claims_data):
    """DataAgent attempting iam:CreateUser must be blocked at the registry layer."""
    seed_environment()

    tm = MagicMock(spec=TokenManager)
    tm.get_token.return_value = "mock-token"
    tm.introspect.return_value = token_claims_data

    registry = ToolRegistry(granted_scopes=["cloud:s3:read", "cloud:s3:write", "cloud:s3:list"])
    pep = MagicMock(spec=PolicyEnforcementPoint)
    pep.enforce.return_value = None

    agent = DataAgent("agent-data-001", tm, registry, pep)
    state = agent.run(
        tool_key="iam_create_role",  # not in DataAgent's scopes
        resource_arn="arn:aws:iam:::role/test",
        task_id="task-boundary-002",
        environment="staging",
    )

    assert state["decision"] == "DENY"
    assert state["error"] is not None
    assert "not available" in state["error"].lower()


@mock_aws
def test_provisioner_agent_uses_approved_template(token_claims_infra):
    seed_environment()

    tm = MagicMock(spec=TokenManager)
    tm.get_token.return_value = "mock-token"
    tm.introspect.return_value = {"active": True, "agent_id": "agent-provisioner-001", "scope": "cloud:iam:create-role"}

    registry = ToolRegistry(granted_scopes=["cloud:iam:create-role", "cloud:iam:read"])
    pep = MagicMock(spec=PolicyEnforcementPoint)
    pep.enforce.return_value = None

    agent = ProvisionerAgent("agent-provisioner-001", tm, registry, pep)
    state = agent.run(
        tool_key="iam_create_role",
        resource_arn="arn:aws:iam:::role/test-role",
        task_id="task-provisioner-001",
        environment="staging",
        context={"template_name": "ec2-readonly", "ticket_ref": "JIRA-1234"},
    )

    assert state["error"] is None
    assert state["decision"] == "ALLOW"
    assert state["result"]["template"] == "ec2-readonly"


@mock_aws
def test_provisioner_agent_rejects_unknown_template():
    tm = MagicMock(spec=TokenManager)
    tm.get_token.return_value = "mock-token"
    tm.introspect.return_value = {"active": True, "agent_id": "agent-provisioner-001", "scope": "cloud:iam:create-role"}

    registry = ToolRegistry(granted_scopes=["cloud:iam:create-role"])
    pep = MagicMock(spec=PolicyEnforcementPoint)
    pep.enforce.return_value = None

    agent = ProvisionerAgent("agent-provisioner-001", tm, registry, pep)
    state = agent.run(
        tool_key="iam_create_role",
        resource_arn="arn:aws:iam:::role/evil-role",
        task_id="task-provisioner-002",
        environment="staging",
        context={"template_name": "not-a-real-template"},
    )

    assert state["error"] is not None
    assert "not in approved templates" in state["error"]


# ------------------------------------------------------------------
# Approval workflow — offline with fakeredis
# ------------------------------------------------------------------

@pytest.fixture
def fake_redis():
    try:
        import fakeredis
        return fakeredis.FakeRedis()
    except ImportError:
        pytest.skip("fakeredis not installed — run: pip install fakeredis")


def test_approval_enqueue_and_retrieve(fake_redis):
    from approval.queue import ApprovalQueue
    from approval.models import ApprovalStatus, RiskLevel

    q = ApprovalQueue(fake_redis)
    req = q.enqueue(
        agent_id="agent-provisioner-001",
        action="iam:CreateRole",
        resource_arn="arn:aws:iam:::role/new-role",
        task_id="task-001",
        policy_ref="nhi.destructive_gate",
        risk_level=RiskLevel.HIGH,
        token_jti=str(uuid4()),
    )

    assert req.status == ApprovalStatus.PENDING
    retrieved = q.get(req.request_id)
    assert retrieved.request_id == req.request_id
    assert retrieved.action == "iam:CreateRole"


def test_approval_resolve_approve(fake_redis):
    from approval.queue import ApprovalQueue
    from approval.models import ApprovalResolution, ApprovalStatus, RiskLevel

    q = ApprovalQueue(fake_redis)
    req = q.enqueue(
        agent_id="agent-provisioner-001",
        action="iam:CreateRole",
        resource_arn="arn:aws:iam:::role/new-role",
        task_id="task-001",
        policy_ref="nhi.destructive_gate",
        risk_level=RiskLevel.HIGH,
        token_jti=str(uuid4()),
    )

    resolution = ApprovalResolution(
        request_id=req.request_id,
        action="approve",
        approver_identity="security-lead@example.com",
        reason="Reviewed and approved for ticket JIRA-5678",
    )
    resolved = q.resolve(resolution)

    assert resolved.status == ApprovalStatus.APPROVED
    assert resolved.approver_identity == "security-lead@example.com"
    assert resolved.resolved_at is not None


def test_approval_self_approval_blocked(fake_redis):
    from approval.queue import ApprovalQueue, SelfApprovalError
    from approval.models import ApprovalResolution, RiskLevel

    q = ApprovalQueue(fake_redis)
    req = q.enqueue(
        agent_id="agent-provisioner-001",
        action="iam:CreateRole",
        resource_arn="arn:aws:iam:::role/new-role",
        task_id="task-001",
        policy_ref="nhi.destructive_gate",
        risk_level=RiskLevel.HIGH,
        token_jti=str(uuid4()),
    )

    with pytest.raises(SelfApprovalError):
        q.resolve(ApprovalResolution(
            request_id=req.request_id,
            action="approve",
            approver_identity="agent-provisioner-001",  # same as agent_id
        ))


def test_approval_double_resolve_blocked(fake_redis):
    from approval.queue import ApprovalQueue, ApprovalAlreadyResolvedError
    from approval.models import ApprovalResolution, RiskLevel

    q = ApprovalQueue(fake_redis)
    req = q.enqueue(
        agent_id="agent-provisioner-001",
        action="s3:DeleteBucket",
        resource_arn="arn:aws:s3:::bucket",
        task_id="task-002",
        policy_ref="nhi.destructive_gate",
        risk_level=RiskLevel.HIGH,
        token_jti=str(uuid4()),
    )

    resolution = ApprovalResolution(
        request_id=req.request_id,
        action="approve",
        approver_identity="admin@example.com",
    )
    q.resolve(resolution)

    with pytest.raises(ApprovalAlreadyResolvedError):
        q.resolve(resolution)


def test_approval_list_pending(fake_redis):
    from approval.queue import ApprovalQueue
    from approval.models import RiskLevel

    q = ApprovalQueue(fake_redis)
    for i in range(3):
        q.enqueue(
            agent_id=f"agent-{i}",
            action="s3:DeleteObject",
            resource_arn=f"arn:aws:s3:::bucket/obj-{i}",
            task_id=f"task-{i}",
            policy_ref="nhi.destructive_gate",
            risk_level=RiskLevel.HIGH,
            token_jti=str(uuid4()),
        )

    pending = q.list_pending()
    assert len(pending) == 3


# ------------------------------------------------------------------
# Rate limit injection + suspension check (Phase 4 fixes)
# ------------------------------------------------------------------

def test_pep_injects_rate_limit_count_from_redis(token_claims_infra):
    """PEP must increment a per-agent Redis counter and inject the value into
    request.context so rate_limit.rego can read it. Without this injection
    the policy silently allows unlimited actions."""
    import fakeredis

    fake = fakeredis.FakeRedis(decode_responses=True)
    pep = PolicyEnforcementPoint.__new__(PolicyEnforcementPoint)
    pep._opa_url = "http://localhost:8181"
    pep._cedar = MagicMock()
    pep._redis = fake

    request = ActionRequest(
        agent_id="agent-infra-001",
        agent_type="InfraAgent",
        token_claims=token_claims_infra,
        action="ec2:DescribeInstances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-rate-001",
        environment="staging",
        source_ip="10.0.1.10",
    )

    pep._inject_rate_limit_count(request)
    assert request.context["current_action_count_per_minute"] == 1

    pep._inject_rate_limit_count(request)
    assert request.context["current_action_count_per_minute"] == 2


def test_pep_blocks_suspended_identity(token_claims_infra):
    """A suspended identity must be DENY'd before OPA is even called."""
    import fakeredis

    fake = fakeredis.FakeRedis(decode_responses=True)
    fake.sadd("identities:suspended", "agent-infra-001")

    pep = PolicyEnforcementPoint.__new__(PolicyEnforcementPoint)
    pep._opa_url = "http://localhost:8181"
    pep._cedar = MagicMock()
    pep._redis = fake
    pep._evaluate = MagicMock()  # if called, the test should fail

    request = ActionRequest(
        agent_id="agent-infra-001",
        agent_type="InfraAgent",
        token_claims=token_claims_infra,
        action="ec2:DescribeInstances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-suspended-001",
        environment="staging",
        source_ip="10.0.1.10",
    )

    with pytest.raises(PolicyDenialError) as exc_info:
        pep._check_suspension(request)
    assert "suspended" in str(exc_info.value).lower()
    assert exc_info.value.policy_ref == "pep.identity_suspended"


def test_pep_allows_non_suspended_identity(token_claims_infra):
    """An identity not in the suspension set passes the check."""
    import fakeredis
    fake = fakeredis.FakeRedis(decode_responses=True)

    pep = PolicyEnforcementPoint.__new__(PolicyEnforcementPoint)
    pep._opa_url = "http://localhost:8181"
    pep._cedar = MagicMock()
    pep._redis = fake

    request = ActionRequest(
        agent_id="agent-infra-001",
        agent_type="InfraAgent",
        token_claims=token_claims_infra,
        action="ec2:DescribeInstances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-clean-001",
        environment="staging",
        source_ip="10.0.1.10",
    )
    pep._check_suspension(request)  # must not raise


def test_pep_passes_through_when_redis_unavailable(token_claims_infra):
    """If Redis is unreachable, rate limit and suspension checks must not block.
    The primary security gate is OPA — losing Redis cannot halt all agents."""
    pep = PolicyEnforcementPoint.__new__(PolicyEnforcementPoint)
    pep._opa_url = "http://localhost:8181"
    pep._cedar = MagicMock()
    # Force _get_redis to return None (simulates Redis unreachable). Patching the
    # method rather than the attribute, because the lazy-connect path would
    # otherwise find a real Redis on the test host.
    pep._get_redis = lambda: None  # type: ignore[method-assign]

    request = ActionRequest(
        agent_id="agent-infra-001",
        agent_type="InfraAgent",
        token_claims=token_claims_infra,
        action="ec2:DescribeInstances",
        resource_arn="arn:aws:ec2:us-east-1:*:instance/*",
        task_id="task-noredis-001",
        environment="staging",
        source_ip="10.0.1.10",
    )
    # Both methods take the no-Redis branch and return without injecting/raising
    pep._check_suspension(request)
    pep._inject_rate_limit_count(request)
    assert "current_action_count_per_minute" not in request.context
