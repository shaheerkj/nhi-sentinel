# ADR-002: Dual Policy Engine — OPA (Rego) + AWS Cedar

**Status:** Accepted  
**Date:** 2026-05-01  
**Deciders:** Lead Architect, Policy Engineer  

---

## Context

NHI-Sentinel needs a policy engine capable of evaluating authorization decisions across two distinct dimensions:

1. **Contextual / behavioral policy** — Does this agent have a valid token? Is it within its declared time window? Does the task binding match? Is the action within the agent's scope? These rules depend on request context: token claims, time of day, task metadata, rate limit state.

2. **Resource-level policy** — Does the target S3 bucket's `DataClassification` tag permit access by this agent type? Does the IAM role's `Environment` tag match the agent's declared environment? These rules depend on attributes of the target resource.

A single policy engine could theoretically handle both, but there are tradeoffs.

## Decision

Use **OPA (Open Policy Agent) with Rego** as the primary policy decision point for contextual evaluation, and **AWS Cedar** as a secondary layer for resource-level attribute-based access control.

The evaluation order is:
1. OPA evaluates the full request context → returns ALLOW, DENY, or REQUIRE_APPROVAL
2. If OPA returns ALLOW, Cedar evaluates resource tags → can override to DENY
3. Cedar DENY overrides OPA ALLOW (defense in depth)

Cedar is only evaluated for S3 and IAM actions, where resource tagging is relevant.

## Consequences

**Positive:**
- **Separation of concerns**: OPA handles the "who, when, what scope" questions; Cedar handles the "which resource" question. Each engine is optimized for its domain.
- **Formal verification**: Cedar's policy language has formal verification properties — certain policy questions can be answered mathematically, not just tested empirically. This is relevant for demonstrating compliance.
- **Defense in depth**: A misconfiguration in OPA that returns ALLOW for a restricted resource is still caught by Cedar's resource check. Two independent engines must both be compromised for an unauthorized access to succeed.
- **Industry credibility**: AWS open-sourced Cedar specifically for fine-grained resource authorization in distributed systems. Using it demonstrates knowledge of the current policy engineering landscape.

**Negative:**
- Two policy languages to maintain (Rego and Cedar) — higher cognitive load
- Cedar-python library adds a dependency
- Integration complexity: the PEP must call both engines and reconcile decisions

## Alternatives Rejected

**OPA only:** Rejected for resource-level decisions. Rego can evaluate resource tags, but the policy becomes deeply nested and harder to audit. Cedar's schema-first approach makes resource policies more readable and verifiable.

**Casbin:** Rejected. Casbin is powerful for RBAC/ABAC but lacks the formal verification properties of Cedar and the bundle distribution model of OPA. Community adoption is lower in cloud-native environments.

**Custom Python policy logic:** Rejected. Hard-coded authorization logic in Python creates a single point of failure, cannot be updated without a code deploy, and provides no auditability of the policy itself.

## References

- OPA documentation: https://www.openpolicyagent.org/
- AWS Cedar GitHub: https://github.com/cedar-policy/cedar
- NHI-Sentinel PEP: `pep/client.py`, `pep/cedar_evaluator.py`
- Rego policies: `policy/rego/`
