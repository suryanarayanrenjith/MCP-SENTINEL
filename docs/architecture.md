# MCP-Sentinel architecture

MCP-Sentinel is a **Policy Enforcement Point (PEP)** sitting between an MCP client/agent and MCP servers. The **Policy Engine** is the **Policy Decision Point (PDP)**. The LLM may propose tool calls; it cannot authorize them.

```
User → LLM/Agent → MCP Client → MCP-Sentinel (PEP) → MCP Server(s) → Tools → Resources
                                      ↑
                               Policy Engine (PDP)
                               Identity / OIDC
                               Registries / Risk / MFA / Data-flow
```

## Zero-trust loop

Every `tools/call` is evaluated independently:

1. Verify user and agent identity (OIDC/JWT). Roles are taken from the IdP token, never from the MCP body.
2. Look up server and tool in local trust/integrity registries (public registry evidence is optional and locally overridable).
3. Cryptographic, structural, semantic, and behavioral integrity checks.
4. Schema/input validation (SSRF, path traversal, command injection).
5. RBAC **and** capability authorization **and** contextual workflow policy **and** risk.
6. Sequential capability-transition analysis.
7. Data-flow classification and exfiltration rules.
8. Runtime/sandbox evidence.
9. Explainable risk score (0–100) that **cannot** override hard denies.
10. Adaptive response: ALLOW / MONITOR / RESTRICT / MFA / QUARANTINE / BLOCK.
11. Temporary capability leases after step-up, bound to workflow and TTL.
12. Proxy only if ALLOW or MONITOR, then treat tool **output as untrusted**.
13. Persist a decision receipt answering who/what/why.

## Trust is never permanent

`TRUSTED` means “currently acceptable,” not “forever safe.” Integrity changes, runtime anomalies, or policy events move servers/tools to MONITORED, RESTRICTED, QUARANTINED, or BLOCKED.

## Modules

| Path | Role |
|---|---|
| `sentinel/` | Gateway PEP, pipeline, leases, receipts, demo CLI |
| `identity/` | OIDC/JWT verification, demo tokens, Keycloak realm |
| `policy/` | PDP (Python + optional OPA/Rego) |
| `integrity/` | SHA-256, structural, semantic firewall, registries |
| `workflow/` | Contextual engine + sequential analyzer |
| `dataflow/` | Data classification and exfiltration guard |
| `risk/` | Deterministic explainable scoring |
| `mfa/` | Step-up challenges (IdP ACR/AMR) |
| `monitoring/` | Behavioral baselines vs observed runtime |
| `sandbox/` | Isolated probe (synthetic resources; optional Docker) |
| `mcp_servers/` | Lab SOC MCP tools |
| `dashboard/` | Visualization / investigation / MFA completion UI |
| `tests/` | Automated security tests |

The dashboard is **not** a security authority.
