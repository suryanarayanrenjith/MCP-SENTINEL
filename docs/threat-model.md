# Threat model

## Assets

- IdP tokens and capability leases
- MCP tool permissions (secrets, infra, data export)
- Security logs, vault material, EDR actions
- Audit receipts (integrity of the investigation record)
- Sentinel policy itself

## Adversaries

1. Prompt-injected agent that tries to call privileged tools
2. Compromised previously-trusted MCP server
3. Malicious tool description / output (tool poisoning)
4. Insider with a legitimate SOC role
5. Stolen bearer token without MFA
6. Confused-deputy SSRF via tool arguments

## STRIDE (selected)

| Threat | Example | Control |
|---|---|---|
| Spoofing | Forged role in MCP JSON | Ignore request-supplied roles; JWT/OIDC only |
| Tampering | Tool schema grows SECRET_ACCESS | Semantic change firewall + RESTRICT |
| Repudiation | Silent privileged call | Signed-style receipts + event store |
| Information disclosure | `get_credentials` → `send_data` external | Data-flow guard BLOCK |
| Denial of service | Unbounded tool spawn | Sandbox pids/cpu limits; input validation |
| Elevation of privilege | MFA treated as admin | Lease scoped to one capability + re-eval |

## Abuse cases covered by demos

- Legitimate SOC path remains low-friction
- Individually allowed tools in a dangerous order are scored and blocked at exfil
- Trusted `search_logs` that starts reading the environment, calling `unknown.example`, and spawning processes is quarantined
