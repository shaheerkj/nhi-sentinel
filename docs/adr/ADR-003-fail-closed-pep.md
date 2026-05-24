# ADR-003: Policy Enforcement Point Fails Closed

**Status:** Accepted  
**Date:** 2026-05-01  
**Deciders:** Lead Architect, Security Engineer  

---

## Context

The Policy Enforcement Point (PEP) is embedded in the agent runtime. On every tool call, it sends the `ActionRequest` to OPA and waits for a decision. Two failure modes are possible when OPA is unreachable:

1. **Fail open**: If OPA is unavailable, allow the action and log a warning. This maximizes agent availability — agents can continue operating even during policy engine outages.

2. **Fail closed**: If OPA is unavailable, deny the action and raise an error. This maximizes security — an agent without an active policy engine cannot act.

This decision also applies to Cedar: if Cedar is unavailable, the question is whether OPA ALLOW is sufficient or whether unavailability should block.

## Decision

The PEP **fails closed** for OPA unavailability. If OPA is unreachable or returns an HTTP error, the PEP returns a synthetic `DENY` decision with `policy_ref="pep.fail_closed"` and raises `PolicyDenialError`. The agent cannot proceed.

For Cedar unavailability, the PEP **logs a warning and passes through** (OPA decision is honored). This is because Cedar is the secondary layer — OPA is primary. Cedar unavailability does not compromise the primary control.

This behavior is **hard-coded and non-configurable**. There is no environment variable or configuration flag that can make the PEP fail open for OPA.

## Consequences

**Positive:**
- An attacker who takes down OPA (resource exhaustion, crash, misconfiguration) gains nothing — agents are blocked, not unguarded
- The security posture of the system is not a function of infrastructure availability
- Auditors can rely on the invariant: if an action succeeded, OPA was available and said ALLOW
- Consistent with Zero Trust principle: never trust, always verify — "can't verify" = deny

**Negative:**
- OPA becomes a hard availability dependency for all agent operations
- An OPA crash or network partition will halt all agents until OPA recovers
- This is a deliberate tradeoff: correctness over availability

## Operational Implications

- OPA health must be in the on-call runbook and monitored (Prometheus health check included)
- OPA should be deployed with redundancy in production (multiple replicas, not a single sidecar)
- Agents should surface `PolicyDenialError` with `policy_ref="pep.fail_closed"` to their orchestrator, which should trigger an alert distinct from a normal DENY

## Alternatives Rejected

**Fail open with logging:** Rejected. A compromised or downed OPA becomes an attack vector — any attacker who can crash OPA gains unrestricted agent access. The blast radius of "OPA is down" becomes the blast radius of all agent identities combined.

**Configurable (fail open/closed via env var):** Rejected. Configuration drift and accidental misconfiguration in staging environments leak into production. Security properties should not be configurable without code review.

## References

- NHI-Sentinel PEP: `pep/client.py:_evaluate()`
- NIST SP 800-207 Zero Trust Architecture, Section 3.3
