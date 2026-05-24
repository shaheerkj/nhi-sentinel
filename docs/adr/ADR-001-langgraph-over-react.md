# ADR-001: LangGraph Structured State Machines over ReAct Loops

**Status:** Accepted  
**Date:** 2026-05-01  
**Deciders:** Lead Architect  

---

## Context

NHI-Sentinel requires AI agents that execute cloud API calls on behalf of machine identities. Two architecture patterns were considered for agent control flow:

1. **ReAct (Reasoning + Acting)** — the agent is given a prompt and iteratively reasons about what to do next, selecting tools in an open-ended loop until it decides it is done. This is the default pattern in LangChain and most agent frameworks.

2. **LangGraph structured state machines** — agent behavior is defined as an explicit directed graph. Each node is a named function; edges are conditional transitions. The full action space is declared at definition time.

The security governance model of NHI-Sentinel requires that every agent action be:
- **Auditable**: the action type and context must be known before execution
- **Policy-enforceable**: the PEP must be able to evaluate the action before it happens
- **Deterministic**: the same input task should produce the same action sequence

## Decision

Use **LangGraph** structured state machines as the agent control flow.

## Consequences

**Positive:**
- Every possible agent action is declared in the graph definition — there are no "surprise" actions that the policy engine has never seen
- The audit trail is naturally structured: each audit event maps to a named graph node
- Policy tests can enumerate the full action space without needing to exercise arbitrary LLM reasoning paths
- The agent cannot be manipulated into taking an action that is not in its declared graph, even if the LLM is prompted to do so — the tool registry enforces this at execution time
- Debugging is deterministic: the state machine can be replayed

**Negative:**
- Less flexible for open-ended tasks — new capabilities require explicit graph changes
- More upfront design work per agent type
- Cannot handle truly novel task types without code changes

## Alternatives Rejected

**ReAct loops:** Rejected because the action space is unbounded at definition time. An attacker embedding instructions in external data (prompt injection) could cause the LLM to reason its way into attempting any action, not just those in the agent's declared scope. The PEP would still block unauthorized actions, but the behavioral anomaly signal would be noisy and the audit trail would show the agent "attempting" a wide range of actions, making it harder to distinguish legitimate deviation from attack.

## References

- LangGraph documentation: https://langchain-ai.github.io/langgraph/
- NHI-Sentinel agent state machine: `agents/base/agent.py`
