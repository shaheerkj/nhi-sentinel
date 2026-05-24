"""Cedar policy evaluator — resource-level authorization layer.

Cedar runs after OPA. An action must pass BOTH layers.
Cedar enforces resource-attribute decisions (DataClassification, Environment)
that are separate from the general context evaluation OPA handles.

Implementation uses subprocess to the `cedar` CLI binary.
If the binary is not installed, the evaluator logs a warning and
returns ALLOW — OPA remains the primary enforcement layer in that case.
CI installs the cedar binary; local dev can install via:
  cargo install cedar-policy-cli
  or download from: https://github.com/cedar-policy/cedar/releases
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_CEDAR_BINARY = "cedar"
_POLICY_DIR = Path(__file__).parent.parent / "policy" / "cedar"


@dataclass
class CedarPrincipal:
    agent_id: str
    agent_type: str
    scopes: list[str] = field(default_factory=list)


@dataclass
class CedarResource:
    resource_type: str          # "NHI::S3Bucket" | "NHI::IAMRole"
    resource_id: str
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class CedarRequest:
    principal: CedarPrincipal
    action: str                 # e.g. "s3:GetObject"
    resource: CedarResource
    context: dict = field(default_factory=dict)


@dataclass
class CedarDecision:
    permitted: bool
    reason: str = ""


class CedarEvaluator:
    """Evaluates Cedar resource policies for S3 and IAM actions."""

    # Actions that trigger Cedar evaluation — others pass through
    S3_ACTIONS = {
        "s3:GetObject", "s3:PutObject", "s3:ListBuckets",
        "s3:DeleteObject", "s3:DeleteBucket",
    }
    IAM_ACTIONS = {
        "iam:CreateRole", "iam:ListRoles", "iam:AttachRolePolicy",
        "iam:CreateUser", "iam:DeleteRole", "iam:DeleteUser",
    }

    def __init__(self, policy_dir: Path | None = None) -> None:
        self._policy_dir = policy_dir or _POLICY_DIR
        self._cedar_available = shutil.which(_CEDAR_BINARY) is not None
        if not self._cedar_available:
            logger.warning(
                "cedar CLI not found — Cedar resource policies will not be enforced. "
                "OPA remains active. Install cedar CLI for full enforcement."
            )

    def evaluate(self, request: CedarRequest) -> CedarDecision:
        """Evaluate a Cedar authorization request.

        Returns CedarDecision(permitted=True) if Cedar permits the action.
        Returns CedarDecision(permitted=False) if Cedar explicitly forbids it.
        Returns CedarDecision(permitted=True) if Cedar is not installed (OPA is primary).
        """
        action_str = f"NHI::Action::\"{request.action}\""

        if not self._cedar_available:
            return CedarDecision(permitted=True, reason="cedar-cli-not-installed")

        if request.action not in self.S3_ACTIONS | self.IAM_ACTIONS:
            # Not a Cedar-governed action — pass through
            return CedarDecision(permitted=True, reason="action-not-cedar-governed")

        policy_file = self._select_policy_file(request.action)
        if not policy_file:
            return CedarDecision(permitted=True, reason="no-cedar-policy-for-action")

        entities = self._build_entities(request)
        cedar_request = {
            "principal": f"NHI::Agent::\"{request.principal.agent_id}\"",
            "action": action_str,
            "resource": f"{request.resource.resource_type}::\"{request.resource.resource_id}\"",
            "context": request.context,
        }

        return self._run_cedar(policy_file, entities, cedar_request)

    def _select_policy_file(self, action: str) -> Path | None:
        if action in self.S3_ACTIONS:
            p = self._policy_dir / "s3_resource_policy.cedar"
        elif action in self.IAM_ACTIONS:
            p = self._policy_dir / "iam_resource_policy.cedar"
        else:
            return None
        return p if p.exists() else None

    def _build_entities(self, request: CedarRequest) -> list[dict]:
        entities = [
            {
                "uid": {"type": "NHI::Agent", "id": request.principal.agent_id},
                "attrs": {
                    "agent_type": request.principal.agent_type,
                    "scopes": request.principal.scopes,
                },
                "parents": [],
            },
            {
                "uid": {
                    "type": request.resource.resource_type.replace("NHI::", "NHI::"),
                    "id": request.resource.resource_id,
                },
                "attrs": request.resource.attributes,
                "parents": [],
            },
        ]
        return entities

    def _run_cedar(
        self,
        policy_file: Path,
        entities: list[dict],
        cedar_request: dict,
    ) -> CedarDecision:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as ef:
            json.dump(entities, ef)
            entities_path = ef.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as rf:
            json.dump(cedar_request, rf)
            request_path = rf.name

        try:
            result = subprocess.run(
                [
                    _CEDAR_BINARY, "authorize",
                    "--policies", str(policy_file),
                    "--entities", entities_path,
                    "--request-json", request_path,
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.strip().lower()
            permitted = "allow" in output
            reason = "cedar-allow" if permitted else "cedar-deny"
            if not permitted:
                logger.warning(
                    "Cedar DENY | agent=%s | action=%s | resource=%s | output=%s",
                    cedar_request["principal"],
                    cedar_request["action"],
                    cedar_request["resource"],
                    result.stdout.strip(),
                )
            return CedarDecision(permitted=permitted, reason=reason)
        except subprocess.TimeoutExpired:
            logger.error("Cedar CLI timed out — failing closed")
            return CedarDecision(permitted=False, reason="cedar-timeout")
        except Exception as exc:
            logger.error("Cedar CLI error: %s — failing closed", exc)
            return CedarDecision(permitted=False, reason=f"cedar-error: {exc}")
        finally:
            Path(entities_path).unlink(missing_ok=True)
            Path(request_path).unlink(missing_ok=True)
