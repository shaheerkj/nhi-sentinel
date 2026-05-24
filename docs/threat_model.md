# NHI-Sentinel Threat Model

**Framework:** STRIDE  
**Scope:** AI agent identity and authorization platform  
**Evaluated Components:** Agent runtime, PEP, OPA/Cedar policy engine, audit pipeline, anomaly detection, approval workflow, Kafka audit bus, PostgreSQL audit store

---

## 1. Methodology

STRIDE categorizes threats across six dimensions:

| Letter | Category | Definition |
|--------|----------|------------|
| **S** | Spoofing | Impersonating another entity (agent, user, service) |
| **T** | Tampering | Unauthorized modification of data or code |
| **R** | Repudiation | Denying that an action occurred |
| **I** | Information Disclosure | Exposing data to unauthorized parties |
| **D** | Denial of Service | Making a system unavailable |
| **E** | Elevation of Privilege | Gaining capabilities beyond what was granted |

For each threat, this document records: component affected, attack vector, existing mitigations, residual risk, and detection signal.

---

## 2. Trust Boundaries

```
┌───────────────────────────────────────────────────────────────┐
│  Agent Runtime Trust Zone                                      │
│  (agent code, PEP library, Vault Agent sidecar)               │
└───────────────────────┬───────────────────────────────────────┘
                        │  HTTP / mTLS
┌───────────────────────▼───────────────────────────────────────┐
│  Policy Services Zone                                          │
│  (OPA sidecar, Cedar evaluator, Keycloak, Vault)              │
└───────────────────────┬───────────────────────────────────────┘
                        │  TCP / mTLS
┌───────────────────────▼───────────────────────────────────────┐
│  Data Services Zone                                            │
│  (Kafka, PostgreSQL, Redis, LocalStack / Moto)                 │
└───────────────────────────────────────────────────────────────┘
```

Each crossing is an authentication + authorization boundary. Failures at one layer are independent of other layers.

---

## 3. STRIDE Analysis

### 3.1 Spoofing

---

#### T-S-01 — Token Theft and IP Replay

**Component:** Policy Enforcement Point  
**Attack vector:** Attacker compromises the agent runtime (e.g. via a dependency with a backdoor, or by accessing shared memory/logs) and extracts the in-flight access token. Token is replayed from an attacker-controlled host to make authorized cloud API calls.

**Mitigations:**
- **Token TTL = 15 minutes** — narrow usable window; token is stale quickly
- **Source IP binding** — PEP compares `source_ip` claim in the token against the actual request source IP. Mismatch triggers immediate DENY before OPA is consulted (`pep.ip_binding`)
- **JTI replay cache** — the JWT `jti` is tracked in Redis for the duration of the assertion window (60 seconds). Replaying the same assertion is rejected
- **Short-lived private key TTL** — Vault enforces `max_ttl` on agent keypairs; even if the private key is stolen it expires

**Residual risk:** Low. Within the 15-minute TTL window, a token stolen and replayed from the exact same source IP would not be caught by the IP binding check. JTI replay prevention covers assertion reuse but not token reuse.

**Detection signal:** `source_ip` mismatch → `DENY` AuditEvent with `policy_ref=pep.ip_binding` → Grafana alert  
**Phase 4 test:** `TestScenarioA::test_ip_mismatch_blocked_before_opa`

---

#### T-S-02 — Agent Identity Impersonation

**Component:** Keycloak, identity registry  
**Attack vector:** Attacker registers a new agent identity (e.g. by forging an identity manifest or exploiting the provisioner API) to obtain a service principal with elevated scopes.

**Mitigations:**
- **Identity provisioning requires a signed Git commit** — automated provisioning pulls manifests only from the repository; the commit must pass CI checks
- **Manifest schema validation** — manifests are validated by `AgentIdentityManifest` Pydantic schema; malformed or overly broad scope declarations are rejected
- **Keycloak realm isolation** — agents are isolated in the `nhi` realm; cross-realm impersonation is not possible
- **Identity registry cross-check** — PEP verifies `agent_id` against the identity registry on every call; unregistered agent IDs are denied

**Residual risk:** Medium. A compromised Git repository or a malicious PR merged without review could introduce a rogue identity manifest.

**Detection signal:** New agent identity created outside the normal manifest pipeline → anomaly in identity lifecycle audit log

---

#### T-S-03 — OPA Sidecar Spoofing

**Component:** PEP → OPA communication  
**Attack vector:** Attacker redirects the PEP's OPA URL to a rogue policy engine that always returns ALLOW, bypassing policy enforcement.

**Mitigations:**
- **mTLS on PEP→OPA channel** — both sides present certificates; a rogue OPA cannot present a valid certificate
- **OPA URL is configuration (not agent-controlled)** — agents cannot modify the OPA URL; it is injected at container start via environment variable managed by the platform
- **Policy bundle signing (cosign)** — even if a rogue OPA is substituted, it cannot serve a validly-signed policy bundle without the platform signing key

**Residual risk:** Low (with mTLS). Without mTLS (development mode), Medium.

---

### 3.2 Tampering

---

#### T-T-01 — Audit Log Tampering

**Component:** PostgreSQL audit store  
**Attack vector:** Attacker with database write access attempts to delete or modify audit records to cover their tracks.

**Mitigations:**
- **Row-level immutability trigger** — PostgreSQL `BEFORE UPDATE OR DELETE` trigger raises an exception on any modification attempt
- **Hash-chained events** — each event contains SHA-256(`event fields + previous_event_hash`). Modifying any event breaks the chain from that point forward; `verify_chain()` detects it
- **Append-only Kafka topic** — events are published to Kafka (which is also append-only by design) before being written to PostgreSQL; a modified PostgreSQL record can be compared against the Kafka original
- **Separate write credentials** — the audit consumer writes to PostgreSQL with a dedicated account that has INSERT only; no UPDATE or DELETE privileges

**Residual risk:** Low. A database superuser could disable the trigger. Protection against privileged insiders requires out-of-band log archiving (e.g., S3 write-once bucket).

**Detection signal:** `verify_chain()` returns False when run against the audit store → integrity alert

---

#### T-T-02 — Policy Bundle Tampering

**Component:** OPA policy bundle  
**Attack vector:** Attacker modifies a Rego policy file to add a backdoor (e.g., `allow if input.agent_id == "backdoor"`) and publishes the tampered bundle.

**Mitigations:**
- **cosign bundle signing** — bundles are signed at CI time; OPA rejects bundles that fail signature verification
- **Policy bundle built in CI** — no human can push a bundle directly; all changes must go through the PR review pipeline
- **Policy unit tests** — `rego test` must pass with >80% coverage before a bundle can be built; a backdoor rule would likely fail existing negative tests
- **Bundle version in every AuditEvent** — the `policy_version` field in audit records means that if a malicious bundle was active during a time window, the affected events can be identified

**Residual risk:** Low. Requires compromise of the CI/CD signing key or a malicious PR merged without review.

---

#### T-T-03 — Prompt Injection via Agent Input Data

**Component:** Agent LLM reasoning step, ToolRegistry  
**Attack vector:** Adversarial instructions embedded in data the agent processes (S3 object, API response, task parameters) manipulate the LLM to attempt unauthorized tool calls.

**Mitigations:**
- **PEP evaluates every action independently** — the policy engine does not trust the agent's stated intent; it evaluates the action, resource, token, and context on their own merits
- **ToolRegistry scope check** — the agent can only call tools in its granted scope; `iam_create_role` attempted by a DataAgent is a `ToolNotAvailableError` regardless of why the agent tried it
- **Structured state machine** — LangGraph enforces a fixed action graph; the agent cannot invent new action types or skip enforcement nodes
- **Input tagging** — external data can be tagged as `untrusted_input` in the action context; policies can restrict further actions when this flag is set

**Residual risk:** Low for structured agents. Higher for free-form ReAct loops. This is a strong argument for structured state machines over unconstrained LLM tool selection.

**Detection signal:** Out-of-scope tool attempt → `DENY` AuditEvent; deviation from agent's tool distribution → anomaly score spike  
**Phase 4 test:** `TestScenarioB::test_injected_iam_action_blocked_at_registry`

---

### 3.3 Repudiation

---

#### T-R-01 — Agent Denies Taking an Action

**Component:** Audit pipeline  
**Attack vector:** An agent (or its operator) claims an action was never taken, disputes a DENY decision, or asserts that the audit log was fabricated.

**Mitigations:**
- **100% coverage** — every action attempt (ALLOW, DENY, REQUIRE_APPROVAL) produces an AuditEvent before execution; there is no code path that bypasses audit recording
- **Hash-chained immutable log** — events cannot be deleted or reordered without breaking the chain
- **Token JTI in every audit event** — `token_jti` links the audit event back to the specific token issuance record in Keycloak; the action is provably tied to an authenticated identity
- **Kafka durability** — events are published to Kafka (offset-committed) before PostgreSQL write; even if PostgreSQL is unavailable, the Kafka record serves as evidence

**Residual risk:** Very low. The combination of JTI linkage, hash chaining, and dual-store (Kafka + PostgreSQL) makes plausible denial extremely difficult.

---

#### T-R-02 — Approver Denies Approving a Destructive Action

**Component:** Approval workflow  
**Attack vector:** A human approver approves a high-risk action, the action causes damage, and the approver later claims they never approved it.

**Mitigations:**
- **Approver identity stored in AuditEvent** — `approver_identity` is written to the audit record at approval time and cannot be modified (immutability trigger)
- **Approval request TTL** — resolved approvals are kept in Redis for 1 hour and in PostgreSQL permanently; both records show the approver identity and timestamp
- **Self-approval blocked** — the requesting agent's owner cannot approve their own requests, preventing one-party "approval"

**Residual risk:** Low. Requires compromise of both the Redis and PostgreSQL stores to alter the approver record.

---

### 3.4 Information Disclosure

---

#### T-I-01 — Agent Private Key Exposure

**Component:** Vault, agent runtime  
**Attack vector:** Agent's RSA private key (used to sign JWT assertions) is exposed via logs, environment variables, error messages, or Vault API misconfiguration.

**Mitigations:**
- **Keys never in environment variables** — private keys are injected by Vault Agent sidecar into a file path (`/var/run/secrets/agent.key`); they are never in `os.environ`
- **Keys never logged** — no code in the token acquisition path logs the private key material; logging is at the `INFO` level and never includes key bytes
- **Vault lease expiry** — keys have a `max_ttl` enforced by Vault; even if extracted, they expire
- **Key rotation** — compromise triggers re-provisioning via `nhi-provision rotate <manifest>`, replacing the keypair and invalidating the old one in Keycloak

**Residual risk:** Medium. A compromised agent container with filesystem access could read the key from disk. DPoP (RFC 9449, deferred) would bind the token to an ephemeral key pair, making a stolen static key insufficient.

---

#### T-I-02 — Audit Log Data Exfiltration

**Component:** Kafka, PostgreSQL  
**Attack vector:** Attacker with read access to Kafka or PostgreSQL reads audit records containing resource ARNs, task IDs, action patterns — building a picture of the organization's infrastructure and agent behavior.

**Mitigations:**
- **SASL/SCRAM on Kafka** — consumer group authentication required; anonymous reads are not possible
- **PostgreSQL row-level security** — audit query API enforces agent-scoped reads; a DataAgent cannot read InfraAgent's audit records
- **No sensitive data in audit events** — `execution_result` fields contain metadata (counts, status) not raw data content; S3 object bodies are never in audit records

**Residual risk:** Medium. Audit metadata (which resources an agent accessed, when, how often) is inherently sensitive. Full encryption at rest is not implemented in the reference stack.

---

### 3.5 Denial of Service

---

#### T-D-01 — OPA Sidecar Resource Exhaustion

**Component:** OPA policy engine  
**Attack vector:** Attacker floods the agent with task requests, causing OPA to be overwhelmed and become unavailable.

**Mitigations:**
- **PEP fails closed** — if OPA is unreachable, `PolicyEnforcementPoint.enforce()` returns DENY; the agent stops acting rather than acting unchecked
- **Rate limiting in Rego policy** — `rate_limit.rego` caps actions per agent per time window before they reach OPA evaluation; a burst is rejected at the policy level
- **OPA health check monitoring** — Prometheus scrapes OPA `/health`; unavailability triggers a Grafana alert before the agent workload is significantly affected

**Residual risk:** Low. The fail-closed behavior ensures DoS of OPA translates to DoS of the agent, not to unauthorized agent access. The agent's workload stalls rather than proceeding unchecked.

**Detection signal:** OPA health check failure → Grafana alert  
**Phase 1 test:** `test_pep_fails_closed_on_opa_unreachable`

---

#### T-D-02 — Approval Queue Flooding

**Component:** Redis approval queue  
**Attack vector:** Attacker (or misbehaving agent) floods the REQUIRE_APPROVAL path with thousands of destructive action requests, overwhelming the human approval team and potentially exhausting Redis memory.

**Mitigations:**
- **Rate limiting in Rego policy** — `destructive_gate.rego` combined with `rate_limit.rego` limits the number of approval requests an agent can generate per time window
- **4-hour TTL on approval requests** — expired requests are automatically evicted from Redis; memory exhaustion requires sustained flooding
- **Anomaly detection** — a burst of REQUIRE_APPROVAL decisions triggers a spike in the anomaly scorer; identity may be suspended before flooding becomes severe

**Residual risk:** Low to Medium. Sustained flooding from multiple agent identities simultaneously is not rate-limited at the Redis level.

---

### 3.6 Elevation of Privilege

---

#### T-E-01 — Scope Escalation via Token Manipulation

**Component:** TokenManager, PEP  
**Attack vector:** Attacker modifies the access token (e.g. adds scopes not granted during issuance) and replays the tampered token to gain access to privileged actions.

**Mitigations:**
- **Tokens are RS256-signed by Keycloak** — modifying a token invalidates the signature; Keycloak's public key is used for verification at the PEP
- **PEP performs live token introspection** — rather than trusting cached token content, the PEP calls Keycloak's introspection endpoint on each request; a revoked or modified token returns `active: false`
- **Scope check in Rego policy** — `scope_check.rego` validates that the token's `scope` claim includes the required scope for the requested action

**Residual risk:** Very low. Breaking RS256 is computationally infeasible.

---

#### T-E-02 — ProvisionerAgent Template Bypass

**Component:** ProvisionerAgent, IAM role templates  
**Attack vector:** Attacker provides an arbitrary `template_name` or custom policy document to `ProvisionerAgent`, creating an IAM role with permissions beyond what any approved template grants.

**Mitigations:**
- **Template allowlist validation** — `ProvisionerAgent._handle_iam_create_role()` validates `context["template_name"]` against the loaded YAML allowlist; any name not in the list is rejected with an error before the cloud API is called
- **Cedar IAM resource policy** — the Cedar policy layer independently validates that the requested role creation matches an approved template, enforcing the constraint at the resource level
- **No arbitrary inline policy accepted** — ProvisionerAgent's tool handler does not accept `inline_policy` as a context parameter; only the template name is consumed

**Residual risk:** Low. Requires compromise of the `policy/templates/iam_role_templates.yaml` file and a passed CI review to add a malicious template.

**Detection signal:** Rejected template attempt → DENY AuditEvent  
**Phase 2 test:** `test_provisioner_agent_rejects_unknown_template`

---

#### T-E-03 — Rogue Orchestrator Issuing Elevated Tasks

**Component:** Orchestrator, task manifest validation  
**Attack vector:** Compromised orchestrator dispatches tasks to agents with manipulated context — claiming the environment is `dev` when it is actually `prod`, or providing a fraudulent `task_id` to bypass task binding.

**Mitigations:**
- **Task binding validation** — `task_scope.rego` verifies that the `task_id` in the ActionRequest belongs to an active, agent-owned task; tasks are not implicitly trusted
- **Environment binding** — `task_scope.rego` verifies that the `environment` in the request matches the environments declared in the agent's manifest; an InfraAgent declared for `staging` cannot act in `prod`
- **Anomaly detection** — actions in unexpected environments trigger a feature spike (cross-environment access) in the anomaly scorer

**Residual risk:** Medium. Task registry validation is not yet fully implemented (Phase 1 stub). A sufficiently privileged orchestrator could generate valid-looking task IDs.

**Detection signal:** Cross-environment access → anomaly score spike; action in undeclared environment → OPA DENY  
**Phase 4 test:** `TestScenarioC::test_rogue_burst_triggers_anomaly_threshold`

---

## 4. Threat Summary Matrix

| ID | Category | Threat | Severity | Mitigation Status |
|----|----------|--------|----------|------------------|
| T-S-01 | Spoofing | Token theft + IP replay | High | Mitigated (IP binding, TTL, JTI) |
| T-S-02 | Spoofing | Agent identity impersonation | High | Partially mitigated (Git-based provisioning) |
| T-S-03 | Spoofing | OPA sidecar spoofing | High | Mitigated (mTLS + bundle signing) |
| T-T-01 | Tampering | Audit log tampering | Critical | Mitigated (trigger + hash chain) |
| T-T-02 | Tampering | Policy bundle tampering | Critical | Mitigated (cosign + CI) |
| T-T-03 | Tampering | Prompt injection | High | Mitigated (PEP + ToolRegistry) |
| T-R-01 | Repudiation | Agent denies action | Medium | Mitigated (JTI + immutable log) |
| T-R-02 | Repudiation | Approver denies approval | Medium | Mitigated (immutable approval record) |
| T-I-01 | Info Disclosure | Private key exposure | High | Partially mitigated (no env vars; DPoP deferred) |
| T-I-02 | Info Disclosure | Audit log exfiltration | Medium | Partially mitigated (auth required; no encryption at rest) |
| T-D-01 | Denial of Service | OPA exhaustion | High | Mitigated (fail-closed PEP) |
| T-D-02 | Denial of Service | Approval queue flood | Medium | Partially mitigated (rate limit + TTL) |
| T-E-01 | Elevation of Privilege | Scope escalation via token tamper | Critical | Mitigated (RS256 signature + introspection) |
| T-E-02 | Elevation of Privilege | ProvisionerAgent template bypass | High | Mitigated (allowlist + Cedar) |
| T-E-03 | Elevation of Privilege | Rogue orchestrator elevated tasks | High | Partially mitigated (environment binding; task registry stub) |

---

## 5. Residual Risk Acceptance

The following risks are accepted for the reference implementation with documented rationale:

| Risk | Acceptance Rationale |
|------|---------------------|
| Private key on-disk (T-I-01) | DPoP (RFC 9449) deferred. In production, pair with hardware-backed key storage (TPM, HSM) or short-lived dynamic certificates from Vault PKI |
| No audit store encryption at rest (T-I-02) | Portfolio reference. Production deployment should use PostgreSQL TDE or cloud-managed encryption |
| Task registry stub (T-E-03) | Full task registry (Phase 1 TODO). Task binding is enforced by Rego; the registry validates task ownership in a follow-on implementation |

---

*STRIDE analysis complete. For implementation details of each mitigation, see the corresponding source files and test cases referenced above.*
