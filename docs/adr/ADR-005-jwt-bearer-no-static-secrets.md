# ADR-005: JWT Bearer Assertion (RFC 7523) — No Static Secrets in Agent Runtime

**Status:** Accepted  
**Date:** 2026-05-01  
**Deciders:** Lead Architect, Identity Engineer  

---

## Context

Agents need to authenticate to the identity broker (Keycloak) to obtain short-lived access tokens. The standard OAuth2 client credentials grant uses a `client_id` + `client_secret` pair. This is the simplest approach but creates a significant security problem:

- The `client_secret` is a static, long-lived credential
- It must be present in the agent's runtime environment (env var or config file)
- If the agent is compromised, the attacker has a credential that is valid indefinitely (or until manually rotated)
- Secret rotation requires coordinated deployment across all running agent instances

Alternative: **JWT Bearer Assertion (RFC 7523)**, also known as the private key JWT flow:

1. A public/private RSA key pair is generated per agent identity
2. The public key is registered in Keycloak (the identity provider)
3. The private key is stored in HashiCorp Vault, never written to disk in the agent environment
4. At token request time, the agent (via Vault Agent sidecar) constructs a short-lived JWT assertion signed with the private key
5. Keycloak validates the signature against the registered public key and issues an access token
6. The JWT assertion has a 60-second TTL — even if captured, it cannot be replayed (JTI replay cache in Redis)

## Decision

Use **RFC 7523 JWT Bearer Assertion** as the sole authentication mechanism for agents. Static `client_secret` credentials are not used and are not provisioned for any agent identity.

The private key is injected into the agent environment by a Vault Agent sidecar at container startup. The agent code itself never calls Vault — it reads the key from a well-known path (`/var/run/secrets/agent.key`) that the sidecar populates.

## Consequences

**Positive:**
- **No static secrets in agent runtime**: A compromised agent container yields only a short-lived private key, not a reusable credential. The key is useless without Vault to issue new assertions.
- **Short assertion TTL (60 seconds)**: Even if a signed assertion is intercepted in transit, it expires before it can be replayed. The Redis JTI cache provides a second layer — each assertion JTI can only be used once.
- **Key rotation without restart**: Vault Agent renews the key before expiry and writes the new key to the well-known path. The agent's `TokenManager` reads the path on each token acquisition — no restart required.
- **Auditability**: Vault logs every key access. The identity broker logs every assertion validation. The full authentication chain is traceable.
- **Revocation**: Suspending an agent identity in the registry blocks Keycloak from issuing tokens for that identity, even if the private key is still technically valid.

**Negative:**
- More complex to implement than client credentials — requires Vault Agent sidecar, PKI configuration, and JWT library usage
- Keycloak configuration for JWT bearer assertion is non-trivial (documented in `infra/keycloak/`)
- Vault becomes a hard dependency for agent startup

## Relationship to IP Binding

The access token issued by Keycloak carries a `source_ip` claim embedded by the `TokenManager` at assertion construction time. The PEP validates this claim on every action request (Layer 0, before OPA). This provides a second factor: even if the access token is stolen, it can only be used from the IP it was issued to.

This is a practical alternative to DPoP (RFC 9449), which is deferred to a future phase.

## Alternatives Rejected

**OAuth2 client credentials (client_secret):** Rejected. Static secrets in agent runtimes are the root cause of a large proportion of cloud credential leaks. The entire premise of NHI-Sentinel is that agents should not hold static, long-lived credentials.

**mTLS-only authentication:** Rejected. mTLS requires PKI infrastructure at the transport layer and does not naturally produce the JWT-format access tokens required by the PEP. The two mechanisms can coexist (mTLS on internal services + JWT for agent auth), but mTLS alone does not satisfy the token claims requirements.

## References

- RFC 7523: https://www.rfc-editor.org/rfc/rfc7523
- TokenManager implementation: `identity/token_manager.py`
- Vault PKI setup: `infra/vault/vault-init.sh`
- Keycloak realm config: `infra/keycloak/keycloak-init.sh`
