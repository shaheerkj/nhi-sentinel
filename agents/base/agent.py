"""Base agent class — wires together identity, PEP, tool registry, and LangGraph."""

from __future__ import annotations

import logging
import socket
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from agents.base.tool_registry import ToolRegistry, ToolSpec
from audit.producer import AuditProducer
from audit.schema import AuditEvent
from identity.manifest_schema import AgentType
from identity.token_manager import TokenManager
from pep.client import PolicyEnforcementPoint
from pep.models import ActionRequest

logger = logging.getLogger(__name__)


class AgentState(TypedDict):
    task_id: str
    environment: str
    action: str
    tool_key: str
    resource_arn: str
    resource_tags: dict
    context: dict
    result: Any
    error: str | None
    decision: str | None


class BaseAgent:
    """Structured state machine agent.

    All subclasses share the same:
        fetch_token → load_task → policy_check → execute_tool → audit_record → END
                                              ↘ error_handler → audit_record → END

    Every action attempt — whether ALLOW, DENY, or REQUIRE_APPROVAL — produces
    an AuditEvent published to the AuditProducer (Kafka or in-memory fallback).
    """

    agent_type: AgentType

    def __init__(
        self,
        agent_id: str,
        token_manager: TokenManager,
        tool_registry: ToolRegistry,
        pep: PolicyEnforcementPoint,
        region: str = "us-east-1",
        audit_producer: AuditProducer | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._token_manager = token_manager
        self._registry = tool_registry
        self._pep = pep
        self._region = region
        self._source_ip = self._get_source_ip()
        self._audit = audit_producer or AuditProducer()
        self._graph = self._build_graph()

    # ------------------------------------------------------------------
    # LangGraph state machine
    # ------------------------------------------------------------------

    def _build_graph(self) -> Any:
        graph = StateGraph(AgentState)

        graph.add_node("fetch_token", self._node_fetch_token)
        graph.add_node("load_task", self._node_load_task)
        graph.add_node("policy_check", self._node_policy_check)
        graph.add_node("execute_tool", self._node_execute_tool)
        graph.add_node("audit_record", self._node_audit_record)
        graph.add_node("error_handler", self._node_error_handler)

        graph.set_entry_point("fetch_token")
        graph.add_edge("fetch_token", "load_task")
        graph.add_edge("load_task", "policy_check")

        graph.add_conditional_edges(
            "policy_check",
            self._route_after_policy,
            {"allowed": "execute_tool", "denied": "error_handler", "approval": "error_handler"},
        )

        # Both paths converge at audit_record — every action is logged.
        graph.add_edge("execute_tool", "audit_record")
        graph.add_edge("error_handler", "audit_record")
        graph.add_edge("audit_record", END)

        return graph.compile()

    def _node_fetch_token(self, state: AgentState) -> AgentState:
        token = self._token_manager.get_token(
            task_id=state["task_id"],
            environment=state["environment"],
            source_ip=self._source_ip,
        )
        claims = self._token_manager.introspect(token)
        state["context"]["_token_claims"] = claims
        state["context"]["_token"] = token
        logger.debug("Token acquired for task %s", state["task_id"])
        return state

    def _node_load_task(self, state: AgentState) -> AgentState:
        logger.debug("Task loaded: %s", state["task_id"])
        return state

    def _node_policy_check(self, state: AgentState) -> AgentState:
        try:
            spec: ToolSpec = self._registry.get(state["tool_key"])
        except Exception as exc:
            state["decision"] = "DENY"
            state["error"] = str(exc)
            return state

        request = ActionRequest(
            agent_id=self._agent_id,
            agent_type=self.agent_type.value,
            token_claims=state["context"].get("_token_claims", {}),
            action=spec.action,
            resource_arn=state["resource_arn"],
            task_id=state["task_id"],
            environment=state["environment"],
            source_ip=self._source_ip,
            resource_tags=state.get("resource_tags", {}),
            context=state.get("context", {}),
        )
        state["context"]["_action_request"] = request.model_dump()

        try:
            self._pep.enforce(request)
            state["decision"] = "ALLOW"
        except Exception as exc:
            state["decision"] = type(exc).__name__
            state["error"] = str(exc)

        return state

    def _route_after_policy(self, state: AgentState) -> str:
        if state["decision"] == "ALLOW":
            return "allowed"
        if "ApprovalRequired" in (state["decision"] or ""):
            return "approval"
        return "denied"

    def _node_execute_tool(self, state: AgentState) -> AgentState:
        handler = self._get_tool_handlers().get(state["tool_key"])
        if not handler:
            state["error"] = f"No handler registered for tool '{state['tool_key']}'"
            return state
        try:
            state["result"] = handler(state)
        except Exception as exc:
            state["error"] = str(exc)
            logger.error("Tool execution failed: %s", exc)
        return state

    def _node_audit_record(self, state: AgentState) -> AgentState:
        result = state.get("result")
        event = AuditEvent(
            agent_id=self._agent_id,
            agent_type=self.agent_type.value,
            task_id=state["task_id"],
            action=state.get("action", state["tool_key"]),
            resource_arn=state["resource_arn"],
            decision=state.get("decision") or "UNKNOWN",
            decision_reason=state.get("error"),
            environment=state.get("environment"),
            source_ip=self._source_ip,
            execution_result=result if isinstance(result, dict) else None,
            execution_error=state.get("error"),
        )
        self._audit.publish(event)
        logger.info(
            "AUDIT | agent=%s | task=%s | action=%s | decision=%s",
            self._agent_id,
            state["task_id"],
            state.get("action"),
            state.get("decision"),
        )
        return state

    def _node_error_handler(self, state: AgentState) -> AgentState:
        logger.warning(
            "Agent action blocked | decision=%s | error=%s",
            state.get("decision"),
            state.get("error"),
        )
        return state

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(
        self,
        tool_key: str,
        resource_arn: str,
        task_id: str,
        environment: str,
        resource_tags: dict | None = None,
        context: dict | None = None,
    ) -> AgentState:
        initial_state: AgentState = {
            "task_id": task_id,
            "environment": environment,
            "action": tool_key,
            "tool_key": tool_key,
            "resource_arn": resource_arn,
            "resource_tags": resource_tags or {},
            "context": context or {},
            "result": None,
            "error": None,
            "decision": None,
        }
        return self._graph.invoke(initial_state)

    # ------------------------------------------------------------------
    # Subclass interface
    # ------------------------------------------------------------------

    def _get_tool_handlers(self) -> dict[str, Any]:
        """Return {tool_key: handler_fn} map. Override in subclasses."""
        return {}

    @staticmethod
    def _get_source_ip() -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
