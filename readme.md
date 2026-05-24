# NHI-Sentinel: Project Scope Document

> **Document Type:** Project Scope & Technical Specification  
> **Version:** 1.0.0  
> **Status:** Draft — Pending Stakeholder Review  
> **Classification:** Internal — Engineering  
> **Last Updated:** 2026-05-01  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Project Objectives](#3-project-objectives)
4. [Scope Boundaries](#4-scope-boundaries)
   - 4.1 [In Scope](#41-in-scope)
   - 4.2 [Out of Scope](#42-out-of-scope)
   - 4.3 [Deferred to Future Phases](#43-deferred-to-future-phases)
5. [Stakeholders & Roles](#5-stakeholders--roles)
6. [System Components](#6-system-components)
   - 6.1 [Agent Layer](#61-agent-layer)
   - 6.2 [Identity & IAM Layer](#62-identity--iam-layer)
   - 6.3 [Policy Engine](#63-policy-engine)
   - 6.4 [Cloud Simulator](#64-cloud-simulator)
   - 6.5 [Audit & Logging Layer](#65-audit--logging-layer)
   - 6.6 [Anomaly Detection Layer](#66-anomaly-detection-layer)
   - 6.7 [Approval Workflow](#67-approval-workflow)
7. [Functional Requirements](#7-functional-requirements)
8. [Non-Functional Requirements](#8-non-functional-requirements)
9. [Security Requirements](#9-security-requirements)
10. [Identity & Credential Model](#10-identity--credential-model)
11. [Policy Governance Model](#11-policy-governance-model)
12. [Data Model & Schemas](#12-data-model--schemas)
13. [Integration Points](#13-integration-points)
14. [Threat Model Summary](#14-threat-model-summary)
15. [Tech Stack Specification](#15-tech-stack-specification)
16. [Build Phases & Milestones](#16-build-phases--milestones)
17. [Testing Strategy](#17-testing-strategy)
18. [Compliance & Regulatory Alignment](#18-compliance--regulatory-alignment)
19. [Assumptions & Dependencies](#19-assumptions--dependencies)
20. [Risks & Mitigations](#20-risks--mitigations)
21. [Glossary](#21-glossary)
22. [Appendix](#22-appendix)

---

## 1. Executive Summary

**NHI-Sentinel** is a reference-grade platform for governing non-human identities (NHIs) in autonomous agentic AI systems. It demonstrates, in working code, how organizations should authenticate, authorize, audit, and continuously monitor AI agents that operate with machine identities inside cloud environments.

The platform addresses a structural gap in the current security landscape: IAM frameworks were designed for humans authenticating interactively. In 2026, the majority of cloud API calls are made by non-human principals — service accounts, CI/CD pipelines, Lambda functions, and increasingly, autonomous AI agents capable of chaining dozens of actions without human supervision. Existing tooling provides inadequate controls for this reality.

NHI-Sentinel implements:

- Declarative machine identity lifecycle management (creation → attestation → expiry)
- Short-lived, cryptographically bound access tokens using OAuth2 RFC 7523 (JWT Bearer)
- A policy-as-code governance layer (OPA/Rego + AWS Cedar) that evaluates every agent action before execution
- An append-only, tamper-evident audit trail of all agent behavior
- A behavioral anomaly detection subsystem that baselines normal agent activity and alerts on deviation
- A simulation harness for attack scenarios — prompt injection, token theft, rogue agent behavior

This project is built to industrial specification — architecture decisions, security controls, and code quality are held to the standard a staff security engineer at an enterprise would apply to a production system. It is developed by a solo engineer using **Claude Code** as an AI pair programmer across all implementation phases. All infrastructure components are open-source and self-hosted; no paid SaaS subscriptions are required to run or demo the platform.

This document defines the complete scope of the project: what is being built, why, how, and what success looks like.

---

## 2. Problem Statement

### 2.1 The Non-Human Identity Explosion

Enterprise environments in 2026 contain an estimated **45 non-human identities for every human identity**. These include:

- Microservice-to-microservice credentials
- CI/CD pipeline service accounts
- Cloud function execution roles
- RPA bot credentials
- AI agent identities (the fastest-growing category)

The overwhelming majority of these identities are managed with static, long-lived secrets stored in environment variables, configuration files, or poorly-governed secret managers. Many are over-privileged, poorly documented, and never rotated.

### 2.2 The Autonomous Agent Problem

Traditional IAM threat models assume a human operator with interactive sessions, rate-limited by human decision speed. Autonomous AI agents shatter this assumption:

- Agents can execute hundreds of cloud API calls per minute
- Agents can chain actions across multiple services, amplifying the blast radius of a compromised identity
- Agents can be manipulated through their inputs (prompt injection) to take actions their operators never intended
- The "scope" of an agent's task is not naturally bounded — without explicit enforcement, a data-processing agent may attempt to modify IAM policies

### 2.3 The Governance Gap

Existing tooling addresses parts of this problem:

- **Cloud IAM** (AWS IAM, Azure RBAC, GCP IAM) handles authorization at the cloud API level, but does not understand agent context, task scope, or behavioral history
- **SIEM/SOAR** tools can detect anomalies post-hoc but cannot prevent actions in real-time
- **Secret managers** (Vault, AWS Secrets Manager) solve credential storage but not the broader identity lifecycle
- **OPA** provides policy enforcement but requires integration work to apply to agent workflows

No single platform integrates these capabilities into a coherent, agent-aware governance framework. NHI-Sentinel is that platform.

---

## 3. Project Objectives

### Primary Objectives

| # | Objective | Success Metric |
|---|-----------|----------------|
| O-1 | Demonstrate end-to-end machine identity lifecycle for AI agents | Identity can be created, rotated, attested, and expired via declarative manifest |
| O-2 | Implement short-lived, cryptographically bound authentication | No agent holds a credential valid for more than 15 minutes; no static secrets in agent runtime |
| O-3 | Enforce fine-grained authorization via policy-as-code | Every agent action evaluated against OPA + Cedar before execution; zero bypasses |
| O-4 | Produce a complete, immutable audit trail | All action attempts (including DENY) logged to append-only store; 100% coverage |
| O-5 | Detect behavioral anomalies in real-time | Anomaly scorer consumes audit stream; p95 detection latency < 5 seconds |
| O-6 | Simulate and defend against 3+ realistic attack scenarios | Each attack scenario has a documented detection mechanism with test coverage |
| O-7 | Serve as a portfolio-grade reference implementation | Code quality, documentation, and architecture suitable for public GitHub presentation |

### Secondary Objectives

- Provide a reusable Python library (`nhi-sentinel-client`) that other projects can use to integrate with the policy enforcement layer
- Document design decisions in ADR (Architecture Decision Record) format
- Produce a STRIDE threat model document as a standalone artifact
- Demonstrate multi-cloud conceptual portability (AWS primary, Azure concepts documented)

---

## 4. Scope Boundaries

### 4.1 In Scope

#### Identity Management
- Declarative agent identity manifests (YAML schema, versioned in Git)
- Service principal provisioning into Keycloak (automated, not manual)
- Private key generation and storage in HashiCorp Vault
- JWT signed assertion flow (RFC 7523) for token acquisition
- Token introspection and validation at the Policy Enforcement Point
- Identity expiry and re-attestation workflow
- Identity inventory API (list all active NHIs with metadata)

#### Agent Implementation
- Four agent types: `InfraAgent`, `DataAgent`, `SecOpsAgent`, `ProvisionerAgent`
- LangGraph-based structured state machines (not free-form ReAct loops)
- Tool registry with scope-tagged tools
- Pre-execution and post-execution policy enforcement hooks (non-bypassable)
- Task context propagation through all agent actions

#### Policy Engine
- OPA deployment with Rego policy bundle
- Policy bundle signing (cosign) and distribution
- Cedar policy layer for resource-level decisions
- Policy CI pipeline with `rego test` and `conftest`
- Policy categories: scope enforcement, time-window restrictions, task binding, resource tagging, destructive action gating, rate limiting
- ALLOW / DENY / REQUIRE\_APPROVAL decision outcomes
- Human approval workflow (queue + simple approval API)

#### Cloud Simulation
- AWS simulation via Moto: S3, EC2, IAM, STS, CloudTrail
- LocalStack for multi-service integration scenarios
- Simulated resource tagging and classification

#### Audit & Logging
- Structured `AuditEvent` schema (Pydantic, versioned)
- Kafka event bus for audit stream (durable, ordered)
- PostgreSQL append-only audit store (row-level immutability)
- OpenTelemetry instrumentation on all components
- Grafana + Loki log aggregation and dashboards

#### Anomaly Detection
- Per-agent behavioral baseline modeling (Isolation Forest + statistical thresholds)
- Real-time scoring service consuming Kafka audit stream
- Alert generation on anomaly threshold breach
- Grafana dashboard: anomaly score time series per agent

#### Attack Simulation
- Three automated attack scenarios with test harnesses:
  1. Token theft + replay from unauthorized IP
  2. Prompt injection via malicious data payload
  3. Rogue agent action burst (simulated compromised orchestrator)
- Detection assertion tests for each scenario
- Attack/defense report generation from audit logs

#### Documentation
- Architecture diagram (draw.io source + PNG export)
- STRIDE threat model document
- API reference (OpenAPI spec for all internal APIs)
- Architecture Decision Records (minimum 5 ADRs)
- Deployment guide (Docker Compose for local, Kubernetes manifests for staging)
- Developer onboarding guide

---

### 4.2 Out of Scope

The following are explicitly **not** in scope for this project. These boundaries are firm and require a formal change request to modify.

| Category | Exclusion | Reason |
|----------|-----------|--------|
| **Production deployment** | This is not a production-ready SaaS product | Portfolio/reference implementation only |
| **Real cloud credentials** | No real AWS/Azure/GCP account will be used | All cloud interaction is simulated via Moto/LocalStack |
| **Human user IAM** | The platform governs NHIs only, not human identities | Distinct problem space; out of scope by design |
| **Multi-tenant architecture** | Single-tenant local deployment only | Adds significant complexity not relevant to the security demonstration |
| **Mobile or browser clients** | No consumer-facing UI | All interaction is via API, CLI, or the Grafana observability UI |
| **Natural language policy authoring** | Policies are written in Rego/Cedar, not plain English | LLM-to-Rego translation is a research problem, not in scope here |
| **Agent training or fine-tuning** | Agents use off-the-shelf LLMs via API | Model training is out of scope |
| **SCIM provisioning** | Identity provisioning is done via internal manifest pipeline, not SCIM | Can be added as a future integration |
| **Physical security controls** | Hardware security modules (HSMs) are not used | Vault software backend is sufficient for the reference implementation |
| **High availability / disaster recovery** | Single-node deployment | Portfolio project; HA adds operational complexity without demonstrating additional security concepts |
| **Performance benchmarking** | No SLA targets defined | Not a production system |
| **Legal / compliance certification** | No SOC 2, ISO 27001, or FedRAMP certification | Architecture demonstrates alignment with these frameworks but does not pursue certification |

---

### 4.3 Deferred to Future Phases

The following items are architecturally desirable but deferred beyond the initial MVP:

| Item | Rationale for Deferral |
|------|------------------------|
| SCIM 2.0 identity provisioning endpoint | Adds value for enterprise integration demos; complex to implement correctly |
| DPoP (RFC 9449) token binding | Enhances token theft resistance; adds implementation complexity |
| Cryptographic audit log integrity (Merkle tree) | Strengthens tamper-evidence; requires additional infrastructure |
| Multi-agent coordination governance | Agent-to-agent delegation and sub-agent scoping is architecturally novel territory |
| Azure RBAC simulation layer | Currently AWS-primary; Azure concepts documented but not implemented |
| Graph-based identity relationship visualization | Useful for demonstrating blast radius analysis |
| Federated identity (SPIFFE/SPIRE) | Natural next step for workload identity in service mesh environments |
| Real-time policy hot-reload without restart | OPA bundle update workflow currently requires restart |

---

## 5. Contributors & Roles

This is a solo engineering project. All roles are held by a single developer, with **Claude Code** serving as AI pair programmer across all implementation phases.

| Role | Held By | Scope |
|------|---------|-------|
| **Lead Architect** | Solo Developer | All architecture decisions, ADR authorship, technical direction |
| **Identity Engineer** | Solo Developer | Keycloak configuration, Vault setup, RFC 7523 token flow |
| **Agent Engineer** | Solo Developer | LangGraph agent implementation, tool registry, task orchestration |
| **Policy Engineer** | Solo Developer | Rego policy authorship, Cedar policies, policy CI pipeline |
| **Security Engineer** | Solo Developer | Threat modeling, attack simulation harness, anomaly detection |
| **DevOps / Platform** | Solo Developer | Docker Compose, Kubernetes manifests, CI/CD pipeline |
| **AI Pair Programmer** | Claude Code | Implementation assistance, code review, debugging, research across all domains |

### Development Approach

Claude Code assists with implementation across all domains — it is not a generator that produces throwaway code. Every component is reviewed, understood, and owned by the solo developer before it is committed. Architecture decisions and security tradeoffs remain the developer's responsibility; Claude Code accelerates implementation velocity and surfaces edge cases.

This mirrors how senior engineers work with AI tooling in production environments — using it as a force multiplier without ceding engineering judgment.

---

## 6. System Components

### 6.1 Agent Layer

The agent layer contains four distinct AI agent types, each with a fixed identity, bounded tool set, and constrained action graph. Agents are implemented using **LangGraph** as structured state machines — not open-ended ReAct loops — to ensure their action sequences are auditable and deterministic.

#### Agent Specifications

**`InfraAgent`**

| Attribute | Value |
|-----------|-------|
| Purpose | Describe and query infrastructure resources |
| Default scopes | `cloud:ec2:describe`, `cloud:s3:list`, `cloud:s3:read` |
| Prohibited scopes | All write operations by default |
| Risk level | Low |
| Allowed environments | staging, prod (read-only) |
| Time restriction | 08:00–20:00 UTC |
| Task binding required | Yes |

**`DataAgent`**

| Attribute | Value |
|-----------|-------|
| Purpose | Move and transform data between pipeline stages |
| Default scopes | `cloud:s3:read`, `cloud:s3:write` (tagged buckets only) |
| Prohibited scopes | `cloud:iam:*`, `cloud:ec2:*` |
| Risk level | Medium |
| Resource restriction | Buckets tagged `DataClassification: internal` or `public` only |
| Time restriction | 06:00–22:00 UTC |
| Task binding required | Yes |

**`SecOpsAgent`**

| Attribute | Value |
|-----------|-------|
| Purpose | Query security findings, scan configurations |
| Default scopes | `cloud:securityhub:read`, `cloud:guardduty:read`, `cloud:config:read` |
| Prohibited scopes | All write and IAM operations |
| Risk level | Low |
| Time restriction | None (24/7 for incident response) |
| Incident override | Requires active `incident_id` in task context |
| Task binding required | Yes |

**`ProvisionerAgent`**

| Attribute | Value |
|-----------|-------|
| Purpose | Create IAM roles using pre-approved policy templates |
| Default scopes | `cloud:iam:create-role` (template-constrained) |
| Prohibited scopes | `cloud:iam:create-policy`, `cloud:iam:attach-user-policy`, `cloud:iam:*admin*` |
| Risk level | High |
| Approval required | Always — no ALLOW path, always REQUIRE\_APPROVAL |
| Allowed policy templates | Defined in `policy/templates/iam_role_templates.yaml` |
| Task binding required | Yes, with mandatory ticket reference |

#### Agent State Machine (Common Pattern)

```
[IDLE] → [FETCH_TOKEN] → [LOAD_TASK] → [SELECT_TOOL]
            ↓                               ↓
        [TOKEN_ERROR]               [POLICY_CHECK]
                                    ↙         ↘
                               [DENIED]    [APPROVED]
                                              ↓
                                        [EXECUTE_TOOL]
                                              ↓
                                        [AUDIT_RECORD]
                                              ↓
                                    [NEXT_STEP or COMPLETE]
```

---

### 6.2 Identity & IAM Layer

#### Components

- **Keycloak** (self-hosted OIDC provider): Manages service principal registration, issues access tokens, supports token introspection
- **HashiCorp Vault**: Stores agent private keys, issues dynamic credentials, provides PKI services
- **Vault Agent Sidecar**: Injects credentials into agent runtime without agent code touching Vault directly
- **Identity Registry** (PostgreSQL): Source of truth for all active NHI manifests, linked to their Keycloak service principal IDs

#### Identity Lifecycle States

```
PENDING_APPROVAL → ACTIVE → EXPIRING (T-7 days) → EXPIRED
                      ↓
                 SUSPENDED (anomaly or manual)
                      ↓
                 REVOKED (permanent)
```

Each state transition is an immutable audit event. An identity in `SUSPENDED` or `REVOKED` state cannot obtain tokens regardless of credential validity.

#### Token Properties

| Property | Value |
|----------|-------|
| Grant type | OAuth2 Client Credentials with JWT Bearer Assertion (RFC 7523) |
| Token TTL | 15 minutes |
| Token format | Signed JWT (RS256) |
| Binding | Source IP claim validated at PEP (DPoP deferred to Phase 2) |
| Replay prevention | `jti` claim tracked in Redis (assertion window: 60 seconds) |
| Custom claims | `agent_id`, `agent_type`, `scopes[]`, `environment`, `task_id` |
| Refresh | Not supported — agent re-asserts to get a new token |

---

### 6.3 Policy Engine

#### Architecture

The policy engine follows a **PEP/PDP separation** pattern:

- **Policy Enforcement Point (PEP)**: A Python library embedded in the agent runtime. It intercepts all tool calls and sends `ActionRequest` objects to the PDP. It cannot be bypassed — it is not an optional middleware layer; it is part of the `execute_tool()` call chain.
- **Policy Decision Point (PDP)**: OPA running as a sidecar to each agent service. Receives `ActionRequest`, evaluates Rego policy bundle, returns structured decision.
- **Policy Administration Point (PAP)**: Git repository where policies are authored, reviewed (PR), tested (CI), bundled, signed, and published.

#### Decision Structure

```json
{
  "effect": "DENY",
  "reason": "Action 'iam:CreateUser' is not permitted for agent type 'DataAgent'",
  "policy_ref": "nhi.agent.authorization.scope_enforcement",
  "policy_version": "1.4.2",
  "evaluated_at": "2026-05-01T14:23:11Z",
  "conditions_evaluated": [
    { "name": "valid_token", "result": true },
    { "name": "action_in_agent_scope", "result": false },
    { "name": "within_time_window", "result": true }
  ]
}
```

#### Policy Categories

| Category | Policy File | Description |
|----------|-------------|-------------|
| Scope enforcement | `scope_check.rego` | Token scopes must include action's required scope |
| Time restriction | `time_window.rego` | Actions bounded to agent's declared operating hours |
| Task binding | `task_scope.rego` | Every action must reference an active, agent-owned task |
| Resource tagging | `resource_tags.rego` | Target resources must carry required classification tags |
| Destructive actions | `destructive_gate.rego` | Delete/terminate actions always escalate to approval |
| Rate limiting | `rate_limit.rego` | Action frequency capped per agent per time window |
| IAM write gating | `iam_write.rego` | IAM write operations require elevated approval |
| Environment policy | `environment_scope.rego` | Agents restricted to declared environment contexts |

---

### 6.4 Cloud Simulator

The cloud simulator provides an AWS-compatible API surface without requiring real cloud credentials. This is a deliberate design choice: the platform's security value is in the identity, policy, and audit layers — not in the specific cloud target.

#### Simulated Services

| Service | Library | Simulated Operations |
|---------|---------|----------------------|
| S3 | Moto | CreateBucket, PutObject, GetObject, DeleteObject, DeleteBucket, ListBuckets, GetBucketTagging |
| EC2 | Moto | DescribeInstances, DescribeSecurityGroups, TerminateInstances, StartInstances |
| IAM | Moto | CreateRole, AttachRolePolicy, CreateUser, DeleteRole, ListRoles |
| STS | Moto | AssumeRole, GetCallerIdentity |
| CloudTrail | Moto | LookupEvents (for SecOpsAgent queries) |
| SecurityHub | LocalStack | GetFindings, BatchImportFindings |

#### Resource Tagging Model

All simulated resources are pre-tagged with a classification scheme that policies evaluate:

```yaml
# Simulated resource tags (applied at environment bootstrap)
tags:
  Environment: ["dev", "staging", "prod"]
  DataClassification: ["public", "internal", "confidential", "restricted"]
  ManagedBy: ["nhi-sentinel", "manual"]
  CostCenter: ["engineering", "data-platform", "security"]
```

---

### 6.5 Audit & Logging Layer

#### Audit Event Schema (v1)

```python
class AuditEvent(BaseModel):
    event_id: UUID
    schema_version: str = "1.0"
    timestamp: datetime
    agent_id: str
    agent_type: AgentType
    task_id: str
    action: str
    resource_arn: str
    decision: Decision                    # ALLOW | DENY | REQUIRE_APPROVAL
    decision_reason: Optional[str]
    policy_ref: Optional[str]
    policy_version: Optional[str]
    token_jti: str                        # Links to token issuance event
    source_ip: str
    environment: str
    execution_result: Optional[str]       # Only present if ALLOW
    execution_error: Optional[str]
    anomaly_score: Optional[float]        # Back-filled by anomaly service
    event_hash: str                       # SHA-256 of all above fields
    previous_event_hash: str             # Chain integrity
```

#### Pipeline

```
Agent Action → PEP Decision → AuditEvent → Kafka Topic (audit.events)
                                                      ↓
                                          [Audit Consumer Service]
                                                 ↓         ↓
                                         PostgreSQL    [Anomaly Scorer]
                                         (append-only)       ↓
                                                      Grafana Alert
```

#### Immutability Enforcement

PostgreSQL audit table uses a row-level trigger that raises an exception on any UPDATE or DELETE:

```sql
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Audit records are immutable. Write attempted on event_id: %', OLD.event_id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_immutability
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
```

---

### 6.6 Anomaly Detection Layer

The anomaly detection service runs as an independent microservice, consuming the Kafka audit stream. It maintains per-agent behavioral models and scores each incoming event in near-real time.

#### Behavioral Features Tracked Per Agent

| Feature | Description |
|---------|-------------|
| `action_frequency` | Actions per minute, rolling 10-minute window |
| `action_type_distribution` | Normalized histogram of action verbs |
| `resource_entropy` | Diversity of resource ARNs accessed |
| `deny_rate` | DENY decisions as a fraction of total |
| `new_action_flag` | Action type never seen for this agent |
| `time_deviation` | Hours outside agent's declared operating window |
| `cross_environment_access` | Access to environment outside declared binding |

#### Anomaly Model

- **Training**: Isolation Forest trained on first 7 days of agent activity (minimum 500 events required before model is considered valid)
- **Scoring**: Each new event produces an anomaly score in [0, 1]. Score > 0.85 triggers alert; score > 0.95 triggers automatic identity suspension pending review
- **Cold start**: New agents (<7 days) operate under enhanced alerting — all Medium-risk actions generate an informational alert regardless of score

#### Alert Actions

| Anomaly Score | Action |
|---------------|--------|
| 0.00 – 0.70 | Normal — log only |
| 0.70 – 0.85 | Elevated — Grafana alert fired |
| 0.85 – 0.95 | High — Grafana critical alert + audit marker (routes to Slack / ntfy) |
| 0.95 – 1.00 | Critical — automatic identity suspension + Grafana alert |

---

### 6.7 Approval Workflow

The approval workflow handles `REQUIRE_APPROVAL` decisions from the policy engine.

#### Flow

```
1. PEP receives REQUIRE_APPROVAL from PDP
2. PEP creates ApprovalRequest in Redis queue
   - TTL: 4 hours (configurable per action type)
   - Contains: agent_id, action, resource, task_id, requesting_token_jti
3. Notification sent to approval channel (Slack webhook, or email — configurable)
4. Approver calls PATCH /approvals/{id}?action=approve|deny
   - Approver identity validated (must be a human user, not another agent)
   - Self-approval blocked: approver cannot be the agent's owner_team lead
5. If approved: action executed; audit record updated with approver identity
6. If denied: audit record closed as DENIED_BY_HUMAN
7. If expired: audit record closed as APPROVAL_TIMEOUT; agent receives rejection
```

#### Approval Request Schema

```python
class ApprovalRequest(BaseModel):
    request_id: UUID
    agent_id: str
    action: str
    resource_arn: str
    task_id: str
    policy_ref: str
    risk_level: RiskLevel
    requested_at: datetime
    expires_at: datetime
    requesting_token_jti: str
    context: dict
    status: ApprovalStatus               # PENDING | APPROVED | DENIED | EXPIRED
    approver_identity: Optional[str]     # Populated on resolution
    resolved_at: Optional[datetime]
```

---

## 7. Functional Requirements

### FR-1: Identity Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-1.1 | The system SHALL provision a service principal in Keycloak from a declarative identity manifest | Must Have |
| FR-1.2 | The system SHALL store agent private keys in HashiCorp Vault with automatic lease expiry | Must Have |
| FR-1.3 | The system SHALL enforce identity TTL and block token issuance for expired identities | Must Have |
| FR-1.4 | The system SHALL support identity suspension (blocking without deletion) | Must Have |
| FR-1.5 | The system SHALL expose an API to list all active NHIs with their metadata | Must Have |
| FR-1.6 | The system SHALL log every identity state transition as an immutable audit event | Must Have |
| FR-1.7 | The system SHALL support re-attestation of identities approaching expiry | Should Have |
| FR-1.8 | The system SHALL detect and alert on orphaned identities (no associated active task in 30 days) | Should Have |

### FR-2: Authentication

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-2.1 | Agents SHALL authenticate using JWT signed assertions (RFC 7523) only — no static secrets | Must Have |
| FR-2.2 | Issued access tokens SHALL have a maximum TTL of 15 minutes | Must Have |
| FR-2.3 | The identity broker SHALL validate `jti` uniqueness within the assertion window (60 seconds) | Must Have |
| FR-2.4 | The identity broker SHALL reject assertions from identities in SUSPENDED or REVOKED state | Must Have |
| FR-2.5 | Token payloads SHALL include: `agent_id`, `agent_type`, `scopes`, `environment`, `jti`, `exp` | Must Have |
| FR-2.6 | The PEP SHALL perform token introspection on every action request, not rely on cached validity | Must Have |

### FR-3: Authorization

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-3.1 | Every agent tool call SHALL be evaluated by the PEP before execution | Must Have |
| FR-3.2 | The PDP SHALL return one of: ALLOW, DENY, or REQUIRE\_APPROVAL | Must Have |
| FR-3.3 | A DENY decision SHALL include a machine-readable reason code and policy reference | Must Have |
| FR-3.4 | The PEP SHALL be non-bypassable — it is part of the call chain, not optional middleware | Must Have |
| FR-3.5 | Policies SHALL be version-controlled in Git and require PR review before deployment | Must Have |
| FR-3.6 | The policy bundle SHALL be signed and the PDP SHALL reject unsigned or invalidly-signed bundles | Should Have |
| FR-3.7 | Cedar resource policies SHALL be evaluated in addition to OPA Rego policies for S3 and IAM actions | Must Have |
| FR-3.8 | The approval workflow SHALL prevent self-approval | Must Have |
| FR-3.9 | The approval workflow SHALL enforce a maximum TTL of 4 hours before auto-expiry | Must Have |

### FR-4: Audit & Logging

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.1 | All agent action attempts (ALLOW, DENY, REQUIRE\_APPROVAL) SHALL be written to the audit log | Must Have |
| FR-4.2 | The audit store SHALL be append-only — UPDATE and DELETE operations SHALL be blocked at the database level | Must Have |
| FR-4.3 | Each audit event SHALL contain a hash of the previous event (chain integrity) | Must Have |
| FR-4.4 | Audit events SHALL be published to Kafka before (not after) the action is executed | Must Have |
| FR-4.5 | The system SHALL retain audit events for a minimum of 90 days in the primary store | Should Have |
| FR-4.6 | The system SHALL expose a query API for audit events with filtering by agent, action, time range, and decision | Must Have |

### FR-5: Anomaly Detection

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-5.1 | The anomaly service SHALL process each audit event within 5 seconds of publication to Kafka | Must Have |
| FR-5.2 | The system SHALL maintain a behavioral baseline model per agent | Must Have |
| FR-5.3 | An anomaly score > 0.95 SHALL trigger automatic identity suspension | Must Have |
| FR-5.4 | An anomaly score > 0.85 SHALL trigger a Grafana alert | Must Have |
| FR-5.5 | New agents (< 7 days) SHALL operate under enhanced alerting mode | Must Have |
| FR-5.6 | The system SHALL detect and alert on actions taken outside the agent's declared time window | Must Have |

### FR-6: Attack Simulation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-6.1 | Scenario A (Token Theft): A token replayed from an unauthorized IP SHALL result in DENY within the PEP | Must Have |
| FR-6.2 | Scenario B (Prompt Injection): A malicious instruction embedded in S3 data SHALL not result in an unauthorized action being executed | Must Have |
| FR-6.3 | Scenario C (Rogue Burst): 50+ rapid delete actions from a single agent SHALL trigger anomaly suspension | Must Have |
| FR-6.4 | Each attack scenario SHALL have an automated test that asserts the detection/prevention mechanism fired | Must Have |

---

## 8. Non-Functional Requirements

### Performance

| ID | Requirement |
|----|-------------|
| NFR-P1 | PEP policy evaluation latency: p95 < 50ms (OPA sidecar call) |
| NFR-P2 | Token acquisition latency: p95 < 200ms (Keycloak JWT issuance) |
| NFR-P3 | Audit event ingestion to Kafka: < 10ms (fire-and-forget, async) |
| NFR-P4 | Anomaly scoring: p95 < 5 seconds from Kafka publication to score |
| NFR-P5 | Approval API response: p95 < 100ms |

### Reliability

| ID | Requirement |
|----|-------------|
| NFR-R1 | Kafka consumer (audit) SHALL use consumer groups with automatic offset commit |
| NFR-R2 | If the PDP (OPA) is unreachable, the PEP SHALL default to DENY — fail closed, never fail open |
| NFR-R3 | If Kafka is unreachable, audit events SHALL be buffered locally and retried — the action SHALL NOT proceed without a successful audit write |
| NFR-R4 | Identity broker downtime SHALL result in agents being unable to act — no cached token bypass |

### Security (Non-Functional)

| ID | Requirement |
|----|-------------|
| NFR-S1 | All internal service communication SHALL use mTLS |
| NFR-S2 | All secrets in Docker Compose environment SHALL be managed via Vault, not env vars |
| NFR-S3 | Vault access logs SHALL be forwarded to the audit Kafka topic |
| NFR-S4 | The policy bundle signing key SHALL be stored in Vault, not in CI/CD environment variables |

### Observability

| ID | Requirement |
|----|-------------|
| NFR-O1 | All services SHALL emit structured JSON logs with correlation IDs |
| NFR-O2 | OpenTelemetry traces SHALL span the full request path: agent → PEP → PDP → cloud sim → audit |
| NFR-O3 | Grafana dashboards SHALL be provisioned as code (JSON, checked into the repository) |
| NFR-O4 | The following metrics SHALL be exposed: action rate per agent, deny rate, anomaly score histogram, approval queue depth, token issuance rate |

---

## 9. Security Requirements

### SR-1: Credential Security

- No static, long-lived API keys anywhere in the system
- Agent private keys are 2048-bit RSA minimum, stored in Vault with `destroy_after_n_uses: null` and explicit `max_ttl`
- Private keys are never logged, never transmitted in plaintext, never appear in application logs
- Token `jti` values are stored in Redis with TTL equal to the assertion window — after TTL expiry, the jti record is deleted (normal expiry, not a security event)

### SR-2: Defense in Depth

The system implements multiple, independent layers such that a failure or bypass of any single layer does not result in unauthorized cloud action:

| Layer | Control |
|-------|---------|
| 1 | Token validation (is this a valid, active NHI?) |
| 2 | Scope check (does the token include the required scope?) |
| 3 | OPA policy evaluation (does context satisfy all policy conditions?) |
| 4 | Cedar resource policy (does the target resource permit this agent?) |
| 5 | Cloud simulator IAM (does the simulated IAM policy allow this action?) |
| 6 | Post-execution audit + anomaly scoring |

A bypass of layer 3 (e.g., a policy misconfiguration) is still caught by layers 4 and 5. All bypass attempts, successful or not, are recorded at layer 6.

### SR-3: Separation of Duties

- The agent that requests an action cannot approve it
- The policy engine is a separate process from the agent — agents cannot modify their own policies
- The audit service is write-only from the agent's perspective — agents cannot read or modify audit records
- Identity provisioning requires a signed Git commit — it cannot be done via API call from an agent

### SR-4: Principle of Least Privilege

- Agent scopes are defined per-identity, not per-agent-type — two instances of the same agent type can have different scopes
- Scopes are additive and must be explicitly granted — there is no implicit inheritance
- The default for any new agent is zero scopes — all access must be explicitly declared in the manifest
- Policies use `default deny` — anything not explicitly permitted is denied

---

## 10. Identity & Credential Model

### 10.1 Identity Manifest Schema

```yaml
# schema version: v1
apiVersion: nhi-sentinel/v1
kind: AgentIdentity
metadata:
  name: agent-infra-001
  namespace: platform-engineering
  labels:
    team: platform
    environment: staging
    classification: autonomous-agent
spec:
  agent_type: InfraAgent
  owner_team: platform-engineering
  owner_contact: platform-oncall@example.com

  # Credential lifecycle
  credential_ttl_days: 90
  rotation_policy: automatic            # manual | automatic
  rotation_days_before_expiry: 14

  # Authorization scope
  scopes:
    - cloud:ec2:describe
    - cloud:s3:list
    - cloud:s3:read

  # Resource restrictions
  allowed_resource_patterns:
    - "arn:aws:s3:::data-pipeline-*"
    - "arn:aws:ec2:us-east-1:*:instance/*"
  blocked_resource_patterns:
    - "arn:aws:s3:::*-prod-*"           # Default block on prod buckets

  # Context bindings (evaluated by policy engine)
  context_bindings:
    environments: [staging]
    time_window:
      start_hour_utc: 8
      end_hour_utc: 20
    source_networks: ["10.0.0.0/8"]
    max_actions_per_minute: 20

  # Approval requirements
  approval_required_for:
    - risk_level: high
    - action_patterns: ["*:Delete*", "*:Terminate*"]
```

### 10.2 Token Issuance Flow

```
1. Vault Agent injects private key → /var/run/secrets/agent.key
2. Agent constructs JWT assertion:
   Header: { "alg": "RS256", "typ": "JWT" }
   Payload: {
     "iss": "agent-infra-001",
     "sub": "agent-infra-001",
     "aud": "https://identity.nhi-sentinel.internal/token",
     "iat": <now>,
     "exp": <now + 60>,
     "jti": "<uuid4>",
     "agent_context": {
       "task_id": "task-abc123",
       "environment": "staging",
       "source_ip": "10.0.1.45"
     }
   }
3. Agent signs assertion with private key
4. Agent calls POST /realms/nhi/protocol/openid-connect/token
   grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
   assertion=<signed_jwt>
5. Keycloak validates:
   - Signature against registered public key
   - exp, nbf, iat
   - iss against active identity registry
   - jti not in Redis replay cache
6. Keycloak issues access token (TTL: 15 minutes):
   {
     "agent_id": "agent-infra-001",
     "agent_type": "InfraAgent",
     "scope": "cloud:ec2:describe cloud:s3:list cloud:s3:read",
     "environment": "staging",
     "task_id": "task-abc123",
     "exp": <now + 900>,
     "jti": "<uuid4>"
   }
```

---

## 11. Policy Governance Model

### 11.1 Policy Authoring Workflow

```
1. Engineer authors policy in Rego (OPA) or Cedar
2. Engineer writes unit tests using rego_test framework
3. PR opened → CI pipeline runs:
   a. rego fmt (formatting check)
   b. rego test (unit tests must pass, coverage > 80%)
   c. conftest (policy lint rules)
   d. Policy impact analysis (what existing agent requests would change decision?)
4. Policy review by second engineer (required)
5. Merge to main → bundle build → cosign signing → OPA bundle server publish
6. OPA sidecars poll bundle server every 60 seconds → hot update (no restart required)
```

### 11.2 Policy Version Management

- Policies follow semantic versioning (`MAJOR.MINOR.PATCH`)
- Breaking changes (DENY where previously ALLOW) increment MAJOR
- Additive restrictions increment MINOR
- Bug fixes increment PATCH
- Policy audit events include `policy_version` — decision provenance is traceable

### 11.3 Policy Test Requirements

| Policy | Required Test Coverage |
|--------|----------------------|
| Scope enforcement | All scope types; valid token, missing scope, expired token |
| Time window | Within window, outside window, edge cases, SecOps override |
| Task binding | Valid task, expired task, missing task, wrong agent for task |
| Destructive actions | Each destructive action type; with and without emergency override |
| Rate limiting | Under limit, at limit, over limit; window reset |

---

## 12. Data Model & Schemas

### 12.1 Core Entities

```
AgentIdentity
├── identity_id (PK)
├── agent_type
├── owner_team
├── state (PENDING | ACTIVE | EXPIRING | EXPIRED | SUSPENDED | REVOKED)
├── keycloak_client_id
├── vault_path
├── manifest_git_sha
├── created_at
├── expires_at
└── last_attested_at

AgentScope
├── scope_id (PK)
├── identity_id (FK → AgentIdentity)
├── scope_string
└── granted_at

ActiveTask
├── task_id (PK)
├── agent_id (FK → AgentIdentity)
├── task_type
├── resource_scope[]
├── created_at
├── expires_at
└── status

AuditEvent
├── event_id (PK)
├── timestamp
├── agent_id
├── task_id
├── action
├── resource_arn
├── decision (ALLOW | DENY | REQUIRE_APPROVAL)
├── decision_reason
├── policy_ref
├── policy_version
├── token_jti
├── source_ip
├── anomaly_score
├── event_hash
└── previous_event_hash

ApprovalRequest
├── request_id (PK)
├── audit_event_id (FK → AuditEvent)
├── status (PENDING | APPROVED | DENIED | EXPIRED)
├── requested_at
├── expires_at
├── resolved_at
└── approver_identity

BehavioralBaseline
├── baseline_id (PK)
├── agent_id (FK → AgentIdentity)
├── model_version
├── trained_at
├── event_count
├── feature_statistics (JSON)
└── model_artifact_path
```

---

## 13. Integration Points

### Internal Integrations

| From | To | Protocol | Auth Method |
|------|----|----------|-------------|
| Agent runtime | Vault Agent sidecar | Unix socket / file | N/A (sidecar handles auth) |
| Agent runtime | Keycloak | HTTPS | JWT Bearer Assertion |
| Agent runtime | PEP library | In-process | N/A (library call) |
| PEP library | OPA sidecar | HTTP | mTLS |
| PEP library | Kafka | TCP | SASL/SCRAM |
| PEP library | Cloud Simulator | HTTPS | AWS SigV4 (simulated) |
| Audit Consumer | PostgreSQL | TCP | Password (Vault-managed) |
| Anomaly Service | Kafka | TCP | SASL/SCRAM |
| Anomaly Service | Redis | TCP | Password (Vault-managed) |
| Approval API | Redis | TCP | Password (Vault-managed) |

### External Integration Points (Notification Only)

| Integration | Purpose | Protocol | Cost |
|-------------|---------|----------|------|
| Slack webhook | Approval request notifications, anomaly alerts | HTTPS POST | Free (incoming webhooks) |
| Grafana Alerting | Critical anomaly alerts (score > 0.95) — fires to Slack or email | Built-in Grafana contact points | Free (self-hosted) |
| ntfy | Self-hosted push notification alternative to PagerDuty | HTTPS POST | Free (self-hosted) |
| Grafana | Metrics and log visualization | Prometheus scrape / Loki push | Free (self-hosted) |

> **No paid alerting services.** PagerDuty is excluded — critical alerts route to Grafana Alerting contact points (Slack, email, or self-hosted ntfy). This is functionally equivalent for a reference implementation and requires zero subscription.

---

## 14. Threat Model Summary

Full STRIDE analysis is documented in `docs/threat_model.md`. This section summarizes the top threats within project scope.

### 14.1 Threat: Token Theft and Replay (Spoofing / Elevation of Privilege)

**Attack vector:** Attacker compromises agent runtime or intercepts token from memory/logs and replays it from an external IP to access cloud resources.

**Mitigations:**
- Token TTL = 15 minutes (narrow usable window)
- Source IP claim validated at PEP on every call — external IP → hard DENY
- `jti` replay cache in Redis (60-second assertion window)
- All token issuances logged with IP fingerprint — anomaly detection fires on IP change mid-session
- Phase 2: DPoP (RFC 9449) binds token to ephemeral key pair — stolen token without key is unusable

**Detection signal:** `source_ip` mismatch against token's IP claim → immediate DENY + alert

---

### 14.2 Threat: Prompt Injection via External Data (Tampering / Elevation of Privilege)

**Attack vector:** Malicious actor embeds adversarial instructions in data the agent processes (S3 file, API response). The agent interprets these as legitimate instructions and attempts unauthorized actions.

**Mitigations:**
- PEP evaluates every action independently of the agent's reasoning — a manipulated action still hits the same policy engine
- Out-of-scope actions (e.g., `iam:CreateUser` attempted by `DataAgent`) are a hard DENY regardless of why the agent requested them
- Tool registry uses a fixed, registered schema — agents cannot invent new tool calls
- External data is tagged as `untrusted_input` context — policies can restrict certain actions when input source is untrusted
- `ProvisionerAgent` only accepts predefined role templates, not arbitrary policy documents

**Detection signal:** Agent attempting action class outside its historical distribution → anomaly score spike

---

### 14.3 Threat: Rogue Agent / Compromised Orchestrator (Denial of Service / Unauthorized Access)

**Attack vector:** Orchestrator service is compromised. Attacker uses it to dispatch malicious tasks to existing agents (bulk deletes, data exfiltration, backdoor IAM role creation).

**Mitigations:**
- All destructive actions (`Delete*`, `Terminate*`) are REQUIRE\_APPROVAL — orchestrator cannot approve its own tasks
- Rate limiting at PEP level: 50+ rapid actions in 2 minutes triggers circuit breaker at anomaly layer → identity auto-suspension
- Orchestrator itself has a bounded machine identity: it can dispatch task manifests but cannot directly call cloud APIs
- Task manifests are validated against a schema — arbitrary action injection via task is blocked
- New identity registration requires a signed Git commit — attacker cannot create new agent identities via orchestrator

**Detection signal:** Action frequency anomaly (isolation forest) → auto-suspension within seconds

---

### 14.4 Threat: Policy Engine Bypass via Sidecar Unavailability (Tampering)

**Attack vector:** Attacker takes down the OPA sidecar (e.g., via resource exhaustion) expecting the PEP to fail open and allow actions through.

**Mitigation:**
- PEP fails **closed** — if OPA is unreachable, the response is DENY
- This is a hard-coded, non-configurable behavior in the PEP library
- OPA unavailability is itself an alert condition (Prometheus health check)
- Agents cannot proceed to execution in `DENY` or `ERROR` state — they surface the error to the orchestrator

**Detection signal:** OPA health check failure → Grafana alert → operator investigation

---

## 15. Tech Stack Specification

### Core Runtime

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| Agent language | Python | 3.12 | LangGraph compatibility, rich security library ecosystem |
| Agent framework | LangGraph | 0.2.x | Structured state machines, auditable action graphs |
| LLM backend | Ollama | Latest | Free, local, no API key required. Runs llama3.2, qwen2.5, and other tool-calling-capable models on-device |
| LLM routing | LiteLLM | Latest | Provider-agnostic abstraction over Ollama; drop-in swap to any external provider (Anthropic, OpenAI, Groq) without code changes |
| API framework | FastAPI | 0.110+ | Async, Pydantic v2 integration, OpenAPI out of the box |
| Data validation | Pydantic | v2 | Strict schema enforcement on all data crossing service boundaries |

> **Zero LLM cost:** Ollama runs entirely on local hardware. No API keys, no rate limits, no billing. The LiteLLM abstraction means any provider can be substituted by changing one environment variable — useful when running demos on hardware that cannot run a local model.

### Identity & Secrets

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| OIDC Provider | Keycloak | 24.x | Self-hosted, full OIDC/OAuth2 compliance, service principal support |
| Secret Manager | HashiCorp Vault | 1.16.x | Dynamic secrets, PKI, comprehensive audit logging |
| JWT Library | python-jose | 3.x | RFC 7523 assertion construction |

### Policy Engine

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| Primary PDP | Open Policy Agent | 0.63.x | Industry standard, Rego is expressive, bundle distribution support |
| Resource policies | AWS Cedar (cedar-python) | 3.x | Resource-level fine-grained policies, formal verification properties |
| Policy testing | conftest | 0.49.x | Policy lint and CI enforcement |
| Bundle signing | cosign | 2.x | Supply chain integrity for policy bundles |

### Cloud Simulation

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| AWS mock | Moto | 5.x | Comprehensive AWS service simulation in Python |
| Extended simulation | LocalStack | 3.x | Multi-service scenarios, Docker-native |

### Data & Messaging

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| Audit event bus | Apache Kafka | 3.7.x | Durable, ordered, partitioned; industry standard for audit streams |
| Audit store | PostgreSQL | 16.x | ACID guarantees, trigger-based immutability, rich query capability |
| Cache / rate limit | Redis | 7.x | JTI replay cache, approval queue, rate limit counters |

### Observability

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| Tracing | OpenTelemetry | Latest | Vendor-neutral, industry standard |
| Log aggregation | Grafana Loki | 3.x | Structured log query without index overhead |
| Metrics | Prometheus | 2.x | Pull-based metrics, wide ecosystem |
| Visualization | Grafana | 10.x | Dashboard-as-code (JSON), Loki + Prometheus native |

### Anomaly Detection

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| ML framework | scikit-learn | 1.5.x | IsolationForest, no GPU required, explainable outputs |
| Streaming | kafka-python | 2.x | Kafka consumer for anomaly service |

### Infrastructure

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Local dev | Docker Compose | Single-command environment spin-up |
| Staging | Kubernetes (k3s) | Production-like deployment for integration testing |
| CI/CD | GitHub Actions | Policy CI, test suite, bundle build and sign |
| IaC | Terraform (local provider) | Simulated resource provisioning |

---

## 16. Build Phases & Milestones

### Phase 1: Core Identity & Agent

**Goal:** One agent can authenticate with a short-lived token and call a simulated cloud API.

| Task | Owner | Acceptance Criteria |
|------|-------|---------------------|
| Define identity manifest schema v1 | Identity Eng | Schema validated with Pydantic, documented |
| Stand up Keycloak in Docker Compose | Identity Eng | Keycloak accessible at `localhost:8080`, realm created |
| Implement identity provisioner | Identity Eng | `nhi-provision apply manifest.yaml` creates service principal in Keycloak |
| Stand up Vault, configure PKI | Identity Eng | Vault running, PKI secrets engine enabled, agent cert issued |
| Implement Vault Agent sidecar | Identity Eng | Private key available at `/var/run/secrets/agent.key` without agent code touching Vault |
| Implement TokenManager (RFC 7523) | Identity Eng | Agent signs assertion, receives 15-minute token from Keycloak |
| Implement InfraAgent (minimal) | Agent Eng | InfraAgent can call `ec2:DescribeInstances` against Moto |
| Stand up Moto / LocalStack | DevOps | AWS mock accessible, pre-seeded with resources and tags |
| Wire all components in Docker Compose | DevOps | `docker compose up` brings up full Phase 1 stack |

**Milestone M1:** `InfraAgent` completes one full action cycle (auth → cloud call) with no hardcoded credentials.

---

### Phase 2: Policy Engine

**Goal:** Every agent action is evaluated by OPA + Cedar before execution; no bypass path exists.

| Task | Owner | Acceptance Criteria |
|------|-------|---------------------|
| Deploy OPA as sidecar | DevOps | OPA running, health check passing |
| Write core Rego policies (5 categories) | Policy Eng | All policies have passing `rego test` suites |
| Implement PEP library | Agent Eng + Policy Eng | `execute_tool()` calls OPA; DENY raises `PolicyDenialError` |
| Integrate Cedar for S3 + IAM | Policy Eng | Cedar policy evaluated for S3 and IAM actions |
| Implement policy CI pipeline | DevOps | PR triggers `rego fmt`, `rego test`, `conftest`, coverage check |
| Implement REQUIRE\_APPROVAL workflow | Agent Eng | Approval queue in Redis; approval API functional |
| Add all four agent types | Agent Eng | All agents integrated with PEP |
| Write policy boundary tests | Policy Eng | Integration tests assert DENY for 10+ out-of-scope action types |

**Milestone M2:** Attempt to call `iam:CreateUser` from `DataAgent` → DENY returned, reason logged, no cloud API call made.

---

### Phase 3: Logging & Monitoring

**Goal:** Every action attempt (including DENY) is in an immutable audit store; anomaly detection is live.

| Task | Owner | Acceptance Criteria |
|------|-------|---------------------|
| Stand up Kafka | DevOps | Kafka broker running, `audit.events` topic created |
| Define AuditEvent schema v1 | Security Eng | Pydantic model complete, chained hash field implemented |
| Instrument PEP → Kafka publish | Agent Eng | Every PEP decision publishes AuditEvent before action |
| Build audit consumer → PostgreSQL | Security Eng | All events persisted; immutability trigger verified |
| Stand up Loki + Grafana | DevOps | Grafana accessible, Loki datasource configured |
| Add OpenTelemetry traces | All teams | Traces span agent → PEP → OPA → cloud sim → audit |
| Implement anomaly service | Security Eng | Consumes Kafka stream, scores events, writes score back to audit event |
| Build baseline model for InfraAgent | Security Eng | 500+ synthetic events generated; IsolationForest trained |
| Build Grafana dashboards | Security Eng | Action rate, deny rate, anomaly score, approval queue dashboards live |
| Implement identity suspension on anomaly | Security Eng | Score > 0.95 → identity suspended → token issuance blocked |

**Milestone M3:** Run 100 InfraAgent actions; all 100 appear in PostgreSQL audit table; Grafana dashboard shows action rate timeline.

---

### Phase 4: Attack Simulation

**Goal:** Three attack scenarios are implemented, detected, and documented with automated test assertions.

| Task | Owner | Acceptance Criteria |
|------|-------|---------------------|
| Build attack scenario test harness | Security Eng | Pytest fixtures for adversary simulation |
| Scenario A: Token theft + IP replay | Security Eng | Test asserts DENY + alert within 5 seconds |
| Scenario B: Prompt injection data payload | Security Eng | Test asserts out-of-scope action blocked regardless of agent reasoning |
| Scenario C: Rogue burst (50 deletes) | Security Eng | Test asserts identity suspension within 30 seconds |
| Generate attack/defense report | Security Eng | Markdown report auto-generated from audit log post-attack |
| Write full STRIDE threat model | Security Eng | `docs/threat_model.md` covers all 6 STRIDE categories |
| Record demo walkthrough | Lead Architect | Video: normal run → attack → detection → remediation |
| Final documentation pass | All | README, API docs, ADRs, deployment guide complete |

**Milestone M4 (Project Complete):** All three attack scenarios produce automated test PASS; audit trail covers 100% of events; demo video recorded; repository is public-ready.

---

## 17. Testing Strategy

### Test Categories

| Category | Scope | Tools | Required Coverage |
|----------|-------|-------|-------------------|
| Policy unit tests | Individual Rego rules | `rego test` | > 80% rule coverage |
| Policy integration tests | Full PEP → OPA → decision flow | pytest + OPA sidecar | All policy categories |
| Identity unit tests | Token issuance, validation, replay detection | pytest | 90% line coverage |
| Agent unit tests | Tool call construction, PEP hook | pytest + mocks | 85% line coverage |
| Audit integrity tests | Chain hash validation, immutability triggers | pytest + PostgreSQL | 100% of audit paths |
| Anomaly detection tests | Score thresholds, suspension triggers | pytest + synthetic data | All threshold boundaries |
| Attack scenario tests | Full end-to-end adversary simulation | pytest | All 3 scenarios pass |
| Contract tests | PEP → OPA API contract | Schemathesis | Breaking change detection |

### CI Pipeline Stages

```
PR Opened
    ↓
1. Lint (ruff, mypy, rego fmt)
2. Unit tests (pytest, rego test)
3. Policy coverage check (> 80%)
4. Integration tests (Docker Compose up, full stack)
5. Attack scenario tests
6. Audit integrity validation
7. Security scan (bandit, trivy)
    ↓
Merge to main
    ↓
8. Bundle build + cosign sign
9. Bundle publish to OPA bundle server
10. Demo environment deploy
```

---

## 18. Compliance & Regulatory Alignment

NHI-Sentinel does not pursue certification but is designed to demonstrate alignment with the following frameworks:

### NIST AI Risk Management Framework (AI RMF)

| Function | How NHI-Sentinel Demonstrates |
|----------|-------------------------------|
| **Govern** | Policy-as-code with Git-based approval workflow, documented risk tiers |
| **Map** | Identity manifest schema maps agent capabilities to risk levels |
| **Measure** | Audit trail provides quantitative evidence of governance effectiveness |
| **Manage** | Anomaly detection + auto-suspension are active risk management controls |

### NIST SP 800-207 (Zero Trust Architecture)

| ZTA Principle | Implementation |
|---------------|----------------|
| All resources authenticated regardless of location | PEP validates token on every call, source IP verified |
| Least privilege with dynamic enforcement | ABAC via OPA context evaluation on each request |
| Inspect and log all traffic | 100% action coverage in audit log |
| Behavioral monitoring | Anomaly service with per-agent baselines |

### EU AI Act (High-Risk System Controls)

| Requirement | Implementation |
|-------------|----------------|
| Human oversight for high-risk actions | REQUIRE\_APPROVAL workflow |
| Audit trail of autonomous decisions | Append-only PostgreSQL audit store |
| Capability limitation | Scopes + tool registry restrict agent capability surface |

### CIS Controls (Relevant Subsets)

| Control | Implementation |
|---------|----------------|
| CIS 5: Account Management | Identity lifecycle management, expiry enforcement |
| CIS 6: Access Control Management | RBAC + ABAC, scope enforcement |
| CIS 8: Audit Log Management | Kafka pipeline, immutable PostgreSQL store |
| CIS 13: Network Monitoring | Anomaly detection, behavioral baselines |

---

## 19. Assumptions & Dependencies

### Assumptions

| ID | Assumption |
|----|-----------|
| A-1 | All cloud API interactions will use simulated environments (Moto/LocalStack). No real cloud credentials will be used. |
| A-2 | Agents use a locally-running Ollama instance as the LLM backend (no API key, no cost). LiteLLM routes to `ollama/llama3.2` or any tool-calling-capable model available in the local Ollama install. Swapping to an external provider (Anthropic, OpenAI, Groq) requires only an environment variable change and is explicitly supported — it is not a core security demonstration target. |
| A-3 | Docker and Docker Compose are available in the development environment. |
| A-4 | Python 3.12 and Node.js 20 are available for development tooling. |
| A-5 | The build team has access to a GitHub repository with Actions enabled. |
| A-6 | For the purposes of the anomaly detector, synthetic audit data will be generated to bootstrap the behavioral baseline model. Real production traffic is not available. |
| A-7 | Keycloak is deployed in development mode. Production hardening (TLS, clustering, database backend) is not in scope. |

### External Dependencies

| Dependency | Type | Risk Level | Mitigation |
|-----------|------|-----------|------------|
| Ollama | Self-hosted open source | Low | Runs locally; Docker image pinned; no network dependency at runtime |
| LiteLLM | Python library | Low | Provider abstraction; Ollama is default; external providers are opt-in only |
| Keycloak | Self-hosted open source | Low | Well-established project; Docker image pinned |
| HashiCorp Vault | Self-hosted open source | Low | Docker image pinned; dev mode for local |
| OPA | Self-hosted open source | Low | Stable project; binary pinned in Dockerfile |
| Moto (AWS mock) | Python library | Low | Pinned version in requirements.txt |
| Kafka | Self-hosted open source | Low | Docker image pinned; single-broker for dev |

---

## 20. Risks & Mitigations

| ID | Risk | Probability | Impact | Mitigation |
|----|------|:-----------:|:------:|-----------|
| R-1 | OPA Rego learning curve delays policy CI completion | Medium | Medium | Allocate 2 days of policy ramp-up time in Phase 2; use existing Rego examples as templates |
| R-2 | Moto doesn't simulate the specific AWS service behavior needed for a scenario | Low | Medium | Validate Moto coverage against required services in Phase 1; fall back to LocalStack |
| R-3 | Keycloak JWT Bearer assertion flow requires non-trivial configuration | Medium | High | Prototype this flow in isolation before Phase 1 milestone; document known config pitfalls |
| R-4 | LangGraph API changes between versions break agent implementation | Low | Medium | Pin LangGraph version; document upgrade procedure |
| R-5 | Anomaly detection requires more synthetic training data than anticipated | Medium | Low | Use statistical baselines (z-score) as fallback when IsolationForest model is not yet valid |
| R-6 | Policy-as-code CI pipeline takes too long for developer iteration | Low | Low | Cache OPA binary in CI; run unit tests locally before PR |
| R-7 | Scope expands due to stakeholder requests for additional features | Medium | Medium | Maintain this scope document as the authoritative boundary; all additions require documented change request |
| R-8 | Kafka adds operational complexity that slows Phase 3 | Low | Medium | Use KRaft mode (no ZooKeeper); Docker image includes simple startup script |

---

## 21. Glossary

| Term | Definition |
|------|-----------|
| **NHI (Non-Human Identity)** | A machine identity representing a software system, agent, or automated process — not a human user |
| **Service Principal** | An identity registered in an identity provider (e.g., Keycloak, Entra ID) that represents a service or application |
| **PEP (Policy Enforcement Point)** | The component that intercepts requests and enforces policy decisions. In NHI-Sentinel, this is a Python library embedded in the agent runtime |
| **PDP (Policy Decision Point)** | The component that evaluates policies and returns ALLOW/DENY/REQUIRE\_APPROVAL. In NHI-Sentinel, this is OPA |
| **PAP (Policy Administration Point)** | The system through which policies are authored and managed — in NHI-Sentinel, this is the Git repository |
| **Rego** | The policy language used by Open Policy Agent |
| **Cedar** | AWS's open-source policy language designed for fine-grained resource authorization |
| **JWT Bearer Assertion (RFC 7523)** | An OAuth2 grant type where a client authenticates using a signed JWT instead of a client secret |
| **DPoP (RFC 9449)** | Demonstrating Proof of Possession — a mechanism that cryptographically binds an access token to a client's ephemeral key pair |
| **JTI (JWT ID)** | A unique identifier claim within a JWT, used for replay prevention |
| **ABAC** | Attribute-Based Access Control — authorization decisions based on attributes of the subject, resource, action, and environment |
| **RBAC** | Role-Based Access Control — authorization decisions based on roles assigned to an identity |
| **Zero Standing Privilege** | A security model where no persistent elevated access exists; access is granted just-in-time and expires automatically |
| **Blast Radius** | The scope of damage that can result from a compromised identity or system |
| **Isolation Forest** | An unsupervised machine learning algorithm for anomaly detection based on random partitioning |
| **STRIDE** | A threat modeling framework: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege |
| **mTLS** | Mutual TLS — both client and server authenticate with certificates |
| **OPA Bundle** | A compressed archive of Rego policies distributed to OPA instances |
| **cosign** | A tool for signing and verifying container images and other artifacts |
| **Task Binding** | The requirement that every agent action reference an active, agent-owned task — prevents unauthorized "freelance" actions |
| **Behavioral Baseline** | A statistical model of normal agent behavior used to detect anomalies |

---

## 22. Appendix

### Appendix A: Repository Structure

```
nhi-sentinel/
├── README.md
├── docker-compose.yml
├── docker-compose.test.yml
├── .github/
│   └── workflows/
│       ├── ci.yml                         # Main CI pipeline
│       ├── policy-ci.yml                  # Policy-specific checks
│       └── release.yml                    # Bundle sign and publish
├── agents/
│   ├── base/
│   │   ├── agent.py                       # Base agent class (PEP integration)
│   │   ├── token_manager.py               # RFC 7523 token acquisition
│   │   └── tool_registry.py              # Tool registration and scope enforcement
│   ├── infra_agent/
│   ├── data_agent/
│   ├── secops_agent/
│   └── provisioner_agent/
├── identity/
│   ├── manifest_schema.py                 # Pydantic schema for identity manifests
│   ├── provisioner.py                     # Manifest → Keycloak service principal
│   ├── vault_client.py                    # Vault PKI integration
│   └── cli.py                             # `nhi-provision` CLI tool
├── pep/
│   ├── client.py                          # PEP library (OPA + Cedar calls)
│   ├── models.py                          # ActionRequest, Decision, AuditEvent
│   └── exceptions.py                      # PolicyDenialError, ApprovalRequiredError
├── policy/
│   ├── rego/
│   │   ├── scope_check.rego
│   │   ├── time_window.rego
│   │   ├── task_scope.rego
│   │   ├── destructive_gate.rego
│   │   ├── rate_limit.rego
│   │   └── tests/
│   │       ├── scope_check_test.rego
│   │       └── ...
│   ├── cedar/
│   │   ├── s3_resource_policy.cedar
│   │   └── iam_resource_policy.cedar
│   └── templates/
│       └── iam_role_templates.yaml
├── audit/
│   ├── schema.py                          # AuditEvent Pydantic model
│   ├── producer.py                        # Kafka producer
│   ├── consumer.py                        # Kafka → PostgreSQL consumer
│   └── api.py                             # Audit query API
├── anomaly/
│   ├── scorer.py                          # IsolationForest model + scoring
│   ├── baseline.py                        # Feature extraction, baseline training
│   └── service.py                         # FastAPI service + Kafka consumer
├── approval/
│   ├── api.py                             # Approval workflow API
│   └── queue.py                           # Redis queue management
├── cloud_sim/
│   ├── bootstrap.py                       # Moto resource seeding
│   └── wrappers.py                        # Typed wrappers around boto3 + Moto
├── attack_sim/
│   ├── conftest.py
│   ├── test_token_theft.py
│   ├── test_prompt_injection.py
│   └── test_rogue_burst.py
├── infra/
│   ├── keycloak/
│   │   └── realm-export.json
│   ├── vault/
│   │   └── vault-config.hcl
│   └── k8s/                               # Kubernetes manifests (staging)
├── dashboards/
│   ├── agent_actions.json
│   ├── anomaly_detection.json
│   └── identity_lifecycle.json
└── docs/
    ├── architecture.md
    ├── threat_model.md
    ├── identity_lifecycle.md
    ├── api_reference.yaml                  # OpenAPI spec
    ├── adr/
    │   ├── ADR-001-langgraph-over-react.md
    │   ├── ADR-002-opa-plus-cedar.md
    │   ├── ADR-003-fail-closed-pep.md
    │   ├── ADR-004-kafka-audit-bus.md
    │   └── ADR-005-jwt-bearer-no-static-secrets.md
    └── onboarding.md
```

### Appendix B: Environment Variables Reference

```bash
# Identity
KEYCLOAK_URL=http://keycloak:8080
KEYCLOAK_REALM=nhi
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=<injected by Vault Agent>

# Policy
OPA_URL=http://opa-sidecar:8181
CEDAR_POLICY_PATH=/etc/nhi/cedar/

# Messaging
KAFKA_BOOTSTRAP_SERVERS=kafka:9092
KAFKA_AUDIT_TOPIC=audit.events

# Storage
POSTGRES_DSN=postgresql://audit_user:${POSTGRES_PASSWORD}@postgres:5432/audit
REDIS_URL=redis://redis:6379/0

# Observability
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
LOG_LEVEL=INFO

# LLM (Ollama — free, local, no API key required)
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=llama3.2                       # Any tool-calling-capable model
# To use an external provider instead, set:
# LITELLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=<your_key>

# Notifications (all free / self-hosted)
SLACK_WEBHOOK_URL=<optional>
NTFY_TOPIC_URL=<optional>                   # Self-hosted ntfy instance
```

### Appendix C: Key Design Decisions Summary

| Decision | Choice | Alternative Considered | Rationale |
|----------|--------|----------------------|-----------|
| Agent framework | LangGraph | LangChain ReAct | Structured state machines are auditable; ReAct loops are non-deterministic |
| LLM backend | Ollama (local) | OpenAI / Anthropic API | Zero cost, no API key required, fully reproducible offline. LiteLLM makes it a one-variable swap. |
| Primary PDP | OPA (Rego) | Casbin, custom logic | Industry standard, bundle distribution, active community |
| Resource policies | AWS Cedar | OPA only | Cedar has formal verification properties; separation of concerns between general policy (OPA) and resource authorization (Cedar) |
| Token grant | RFC 7523 JWT Bearer | Client secret | Eliminates static secrets from agent runtime entirely |
| Audit bus | Kafka | Direct PostgreSQL write | Durable ordering, replay capability, decouples producers from storage |
| PEP failure mode | Fail closed (DENY) | Fail open | Security correctness > availability; never allow unknown |
| ML model | IsolationForest | Deep learning | No GPU required; interpretable; works with small datasets |
| Policy storage | Git + signed bundle | Database | Auditability, PR review workflow, version history |
| Alerting | Grafana Alerting + ntfy | PagerDuty | Both are free and self-hosted; functionally equivalent for a reference implementation |

---

*Document End*

---

> **Change Control:** All modifications to this scope document require sign-off from the Project Owner and Lead Architect. Changes to Section 4 (Scope Boundaries) additionally require a documented impact assessment. This document is versioned in Git alongside the project source code.
