-- NHI-Sentinel PostgreSQL initialization
-- Creates the identity registry and audit event tables.
-- Immutability trigger prevents UPDATE/DELETE on audit_events.

-- ----------------------------------------------------------------
-- Identity registry
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_identities (
    identity_id         TEXT PRIMARY KEY,
    agent_type          TEXT NOT NULL,
    owner_team          TEXT NOT NULL,
    state               TEXT NOT NULL DEFAULT 'ACTIVE',
    keycloak_client_id  TEXT NOT NULL,
    vault_path          TEXT NOT NULL,
    manifest_git_sha    TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    last_attested_at    TIMESTAMPTZ,
    scopes              TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS agent_scopes (
    scope_id        SERIAL PRIMARY KEY,
    identity_id     TEXT NOT NULL REFERENCES agent_identities(identity_id),
    scope_string    TEXT NOT NULL,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------
-- Audit event store (append-only)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    event_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schema_version      TEXT NOT NULL DEFAULT '1.0',
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_id            TEXT NOT NULL,
    agent_type          TEXT NOT NULL,
    task_id             TEXT NOT NULL,
    action              TEXT NOT NULL,
    resource_arn        TEXT NOT NULL,
    decision            TEXT NOT NULL,         -- ALLOW | DENY | REQUIRE_APPROVAL
    decision_reason     TEXT,
    policy_ref          TEXT,
    policy_version      TEXT,
    token_jti           TEXT,
    source_ip           TEXT,
    environment         TEXT,
    execution_result    JSONB,
    execution_error     TEXT,
    anomaly_score       FLOAT,
    event_hash          TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL
);

-- Immutability trigger — no UPDATE or DELETE ever
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Audit records are immutable. Modification attempted on event_id: %',
        OLD.event_id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_immutability
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- ----------------------------------------------------------------
-- Approval requests
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approval_requests (
    request_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_event_id      UUID REFERENCES audit_events(event_id),
    agent_id            TEXT NOT NULL,
    action              TEXT NOT NULL,
    resource_arn        TEXT NOT NULL,
    task_id             TEXT NOT NULL,
    policy_ref          TEXT,
    risk_level          TEXT,
    status              TEXT NOT NULL DEFAULT 'PENDING',
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    resolved_at         TIMESTAMPTZ,
    approver_identity   TEXT
);
