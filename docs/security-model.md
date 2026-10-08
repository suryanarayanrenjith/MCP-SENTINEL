# Security model

## Assumptions

- The MCP client and LLM are **untrusted**. Prompt injection may succeed against the model.
- MCP servers and tools may become compromised after an initial review.
- Network location does not confer trust.
- Identity is provided by an external IdP (Keycloak / OIDC) in production; demo HS256 is local-only.
- Sentinel’s process, database, and Redis are trusted computing base for the prototype.
- Sandbox containers never receive production secrets or a Docker socket.

## Hard rules (override scoring)

- Missing/expired/wrong issuer/audience token → BLOCK
- Unknown, quarantined, or blocked server/tool → BLOCK
- Role without the requested capability → BLOCK
- Forbidden destinations / SSRF / path traversal / command injection → BLOCK
- SECRET/CRITICAL data to an external DATA_TRANSFER destination → BLOCK
- Critical runtime deviation (env + unexpected network + process spawn) → QUARANTINE + BLOCK

## Least privilege

RBAC is necessary but not sufficient. `SOC_ANALYST` can READ / EXTERNAL_LOOKUP / WRITE (incidents) but not SECRET_ACCESS, DATA_TRANSFER, or INFRASTRUCTURE_CONTROL.

Sensitive capabilities require:

1. A role that includes the capability
2. Elevated authentication context (MFA ACR/AMR) when policy demands it
3. A **temporary, workflow-bound lease**
4. Passing contextual, sequential, data-flow, and runtime checks

MFA success never means “allow everything.”

## Secrets

- No plaintext password store in Sentinel
- Demo JWT secret is environment-injected
- Tool outputs that look like secrets are flagged; logs redact short tokens
- Sandbox uses dummy credentials only

## Production extensions

- mTLS between client, Sentinel, and servers
- SPIFFE/SPIRE workload identity for agents
- eBPF runtime sensors
- OPA-only decisioning with signed policy bundles
- Hardware-backed Keycloak WebAuthn/FIDO2
- Signed MCP server attestations (in-toto / Sigstore) consumed as **evidence**
