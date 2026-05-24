# NHI-Sentinel

A reference-grade security platform for governing **Non-Human Identities (NHIs)** in autonomous AI agent systems. Demonstrates, in working code, how organizations should authenticate, authorize, audit, and continuously monitor AI agents operating with machine identities in cloud environments.

---

## The Problem

Enterprise environments now contain an estimated **45 non-human identities for every human identity** — service accounts, CI/CD pipelines, cloud functions, and increasingly, autonomous AI agents. These identities are typically managed with static, long-lived secrets, over-privileged, and minimally audited.

Autonomous AI agents make this worse: they can chain dozens of cloud API calls per minute, be manipulated via prompt injection to take unintended actions, and operate at a speed that makes human oversight impractical without automated controls.

Existing tooling (Cloud IAM, SIEM, secret managers) addresses parts of this. NHI-Sentinel integrates them into a coherent, agent-aware governance framework.

---

## What It Demonstrates

| Capability | Implementation |
|------------|---------------|
| **Machine identity lifecycle** | Declarative YAML manifests → Keycloak service principals → HashiCorp Vault PKI |
| **Static-secret-free authentication** | RFC 7523 JWT Bearer Assertion; 15-minute tokens; no hardcoded credentials anywhere |
| **Policy-as-code enforcement** | OPA/Rego (general context) + AWS Cedar (resource-level); dual evaluation; fail-closed |
| **Defense in depth** | 6 independent control layers; Cedar DENY overrides OPA ALLOW |
| **Immutable audit trail** | SHA-256 hash-chained events; Kafka pipeline; PostgreSQL append-only store with row-level immutability trigger |
| **Behavioral anomaly detection** | Isolation Forest per-agent baseline; real-time scoring; auto identity suspension at score > 0.95 |
| **Human approval workflow** | Redis-backed queue; self-approval blocked; 4-hour TTL; REST API |
| **Attack simulation** | Token theft/replay, prompt injection, rogue agent burst — automated test assertions |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Agent Runtime                               │
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐  │
│  │ TokenManager │   │ ToolRegistry │   │   LangGraph State      │  │
│  │ (RFC 7523)   │   │ (scope-gated)│   │   Machine              │  │
│  └──────┬───────┘   └──────┬───────┘   └──────────┬─────────────┘  │
│         └──────────────────┴───────────────────────┘                │
│                                        │                             │
│                              ┌─────────▼──────────┐                 │
│                              │  Policy Enforcement │                │
│                              │  Point  (PEP)       │                │
│                              └─────────┬───────────┘                │
└────────────────────────────────────────│────────────────────────────┘
                                         │
              ┌──────────────────────────┼─────────────────────┐
              │                          │                      │
    ┌─────────▼────────┐    ┌────────────▼──────┐   ┌─────────▼──────┐
    │   OPA / Rego     │    │  AWS Cedar         │   │  Kafka Audit   │
    │   Policy Engine  │    │  Resource Policies │   │  Event Bus     │
    └──────────────────┘    └───────────────────┘   └────────┬───────┘
                                                              │
                                           ┌──────────────────┴──────────────┐
                                           │                                 │
                                ┌──────────▼──────┐             ┌───────────▼─────┐
                                │  PostgreSQL      │             │  Anomaly Scorer │
                                │  Audit Store     │             │  (IsolationForest│
                                │  (append-only)   │             │  per agent)     │
                                └─────────────────┘             └─────────────────┘
```

### Agent State Machine

Every agent action follows the same non-bypassable path:

```
fetch_token → load_task → policy_check ──(ALLOW)──→ execute_tool ──→ audit_record → END
                                       ↘                                           ↗
                                        ──(DENY / REQUIRE_APPROVAL)──→ error_handler
```

All paths — including DENY — emit an `AuditEvent` before the graph exits.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent framework | [LangGraph](https://github.com/langchain-ai/langgraph) — structured state machines, not ReAct loops |
| LLM backend | [Ollama](https://ollama.com) — local, free, no API key required |
| LLM routing | [LiteLLM](https://github.com/BerriAI/litellm) — swap provider via one environment variable |
| Policy engine (general) | [Open Policy Agent](https://www.openpolicyagent.org/) + Rego |
| Policy engine (resource) | [AWS Cedar](https://www.cedarpolicy.com/) |
| Identity provider | [Keycloak](https://www.keycloak.org/) — self-hosted OIDC |
| Secrets | [HashiCorp Vault](https://www.vaultproject.io/) KV v2 + PKI |
| Audit bus | Apache Kafka |
| Audit store | PostgreSQL 16 with append-only immutability trigger |
| Cache / queues | Redis 7 |
| AWS simulation | [Moto](https://github.com/getmoto/moto) — fully in-process, no credentials needed |
| Anomaly detection | scikit-learn IsolationForest |
| Infrastructure | Docker Compose |

---

## Project Structure

```
nhi-sentinel/
├── agents/
│   ├── base/              # LangGraph base agent, tool registry, PEP wiring
│   ├── infra_agent/       # EC2/S3 read operations
│   ├── data_agent/        # S3 data pipeline (write to classified buckets)
│   ├── secops_agent/      # SecurityHub, GuardDuty, IAM read
│   └── provisioner_agent/ # IAM role creation (template-constrained)
├── audit/
│   ├── schema.py          # AuditEvent model + SHA-256 hash chaining
│   ├── producer.py        # Kafka producer (in-memory fallback for offline dev)
│   └── consumer.py        # Kafka → PostgreSQL persistence service
├── anomaly/
│   └── scorer.py          # IsolationForest, feature extraction, sigmoid scoring
├── approval/
│   ├── queue.py           # Redis-backed approval queue
│   └── api.py             # FastAPI approval workflow REST API
├── identity/
│   ├── manifest_schema.py # Pydantic identity manifest with scope validation
│   ├── token_manager.py   # RFC 7523 JWT Bearer assertion + caching
│   ├── vault_client.py    # Vault KV v2 keypair operations
│   └── provisioner.py     # Keycloak service principal provisioning
├── pep/
│   ├── client.py          # Policy Enforcement Point (OPA + Cedar dual evaluation)
│   ├── cedar_evaluator.py # Cedar subprocess wrapper with graceful fallback
│   ├── models.py          # ActionRequest, PolicyDecision, Decision enum
│   └── exceptions.py      # PolicyDenialError, ApprovalRequiredError
├── policy/
│   ├── rego/nhi/          # Rego bundle: main, scope, time, task, rate, destructive
│   ├── rego/tests/        # OPA unit test suite
│   ├── cedar/             # Cedar policies for S3 and IAM resources
│   └── templates/         # Pre-approved IAM role templates (YAML allowlist)
├── cloud_sim/
│   └── bootstrap.py       # Moto environment seed (buckets, EC2, IAM roles, tags)
├── attack_sim/            # Phase 4: adversary scenario harnesses
├── infra/
│   ├── postgres/init.sql  # Schema + immutability trigger
│   ├── vault/             # Vault init script
│   └── keycloak/          # Keycloak realm init
├── tests/
│   ├── test_phase1_integration.py  # Identity, token, registry, M1 milestone
│   ├── test_policy_boundaries.py   # PEP routing, scope enforcement, approvals
│   └── test_audit_pipeline.py      # Hash chaining, producer fallback, anomaly scorer
└── scope/
    └── scope.md           # Full project specification and design decisions
```

---

## Build Phases

| Phase | Goal | Status |
|-------|------|--------|
| **Phase 1** | Identity lifecycle, RFC 7523 auth, InfraAgent + Moto simulation | Complete |
| **Phase 2** | OPA + Cedar policy engine, all 4 agent types, approval workflow | Complete |
| **Phase 3** | Kafka audit pipeline, hash-chained events, anomaly detection | Complete |
| **Phase 4** | Attack simulation: token theft, prompt injection, rogue burst | In Progress |

**Current: 54 tests, all passing fully offline** — no credentials, no Docker, no running services required.

---

## Running the Tests

All tests run **fully offline**. AWS is simulated in-process via Moto. Kafka falls back to an in-memory queue automatically. Redis is replaced with fakeredis.

```bash
# Install
pip install -e ".[dev]"

# Run everything
pytest

# Run by phase
pytest tests/test_phase1_integration.py
pytest tests/test_policy_boundaries.py
pytest tests/test_audit_pipeline.py
```

---

## Running the Full Stack

```bash
docker compose up
```

| Service | Port | Purpose |
|---------|------|---------|
| Keycloak | 8080 | OIDC identity provider |
| Vault | 8200 | Secrets and PKI |
| OPA | 8181 | Policy decision point |
| Kafka | 9092 | Audit event bus |
| PostgreSQL | 5432 | Audit store |
| Redis | 6379 | Approval queue + rate limiting |
| LocalStack | 4566 | Extended AWS simulation |
| Approval API | 8000 | Human approval workflow |

---

## Key Design Decisions

**LangGraph over ReAct:** ReAct loops are non-deterministic — the agent decides which tool to call at each step. LangGraph enforces a fixed state machine: every agent follows the same `fetch_token → policy_check → execute → audit` path. Action sequences are auditable and deterministic.

**OPA + Cedar (not one or the other):** OPA evaluates general context — token validity, scopes, time windows, task binding, rate limits. Cedar evaluates resource-level authorization against `DataClassification` and `Environment` tags on S3 buckets and IAM roles. Cedar DENY overrides OPA ALLOW. A misconfiguration in one layer is caught by the other.

**Fail-closed on OPA unreachability:** If the policy engine is unreachable, the PEP returns DENY. This is hardcoded and non-configurable. Security correctness takes precedence over availability.

**RFC 7523 JWT Bearer Assertion:** Eliminates static secrets from agent runtime entirely. Agents hold only a private key injected by Vault Agent sidecar. Tokens expire in 15 minutes maximum. No `.env` files with long-lived API keys.

**Hash-chained audit events:** Modifying any past event invalidates all subsequent hashes. An attacker who compromises the audit store cannot silently edit records — the broken chain is detectable.

Full specification: [`scope/scope.md`](scope/scope.md)

---

## Policy Example

```rego
# policy/rego/nhi/main.rego
effect := "ALLOW" if {
    valid_token
    scope_check.action_in_scope
    time_window.within_window
    task_scope.task_is_active
    task_scope.environment_allowed
    rate_limit.within_rate_limit
    not destructive_gate.requires_approval
}

effect := "REQUIRE_APPROVAL" if {
    valid_token
    scope_check.action_in_scope
    destructive_gate.requires_approval
}

default effect := "DENY"
```

---

## Threat Model Coverage

| Attack Scenario | Detection Mechanism | Automated Test |
|----------------|--------------------|-|
| Token theft + IP replay | Source IP mismatch → hard DENY at PEP | Phase 4 |
| Prompt injection via S3 data | Out-of-scope action hits same PEP regardless of agent reasoning | Phase 4 |
| Rogue agent delete burst (50+) | Isolation Forest anomaly score > 0.95 → identity auto-suspension | Phase 4 |
| OPA sidecar taken offline | PEP fails closed — no bypass path | `test_pep_fails_closed_on_opa_unreachable` |
| Unauthorized IAM template | Not in YAML allowlist → DENY before cloud call | `test_provisioner_agent_rejects_unknown_template` |

Full STRIDE threat model: [`docs/threat_model.md`](docs/threat_model.md) *(Phase 4)*

---

## Environment Variables

```bash
# Identity
KEYCLOAK_URL=http://keycloak:8080
VAULT_ADDR=http://vault:8200

# Policy
OPA_URL=http://opa:8181

# Messaging
KAFKA_BOOTSTRAP=kafka:9092

# Storage
DATABASE_URL=postgresql://nhi:nhi@postgres:5432/nhi_sentinel
REDIS_URL=redis://redis:6379/0

# LLM — Ollama (local, free, no API key)
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=llama3.2
# To use a different provider: LITELLM_PROVIDER=anthropic + ANTHROPIC_API_KEY=...
```

---

*Solo project. All architecture, security design, and implementation by Syed Shaheer Khalid. [Claude Code](https://claude.ai/code) used as AI pair programmer.*
