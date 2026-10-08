# Known limitations and production improvements

## Prototype limitations

- Demo auth uses HS256 shared secret. Production must use OIDC + JWKS (Keycloak realm is included).
- Runtime telemetry is supplied on the request (`observed_runtime`) or simulated by the lab server. Production should use sidecar/eBPF/container sensors that Sentinel independently consumes.
- Sandbox Docker execution is optional; default is an in-process synthetic probe with the same observation model.
- OPA is shipped and optional; tests use the equivalent Python PDP so CI does not require OPA.
- Single-region FastAPI process; no HA leader election.
- Public verification registry is an evidence hook (`SENTINEL_PUBLIC_REGISTRY_URL`), not a global CA.
- MCP transport is HTTP JSON for the lab tools, not full Streamable HTTP / stdio multiplexing.
- Human approval table exists; the happy path for high risk in this build is MFA + lease + re-eval.

## Future production work

- Full MCP SDK proxy (stdio, SSE, Streamable HTTP) with backpressure
- Mutual TLS and SPIFFE IDs for agents and servers
- Signed SBOMs / in-toto attestations in the integrity registry
- Policy bundles with signatures and staged rollout
- Out-of-band WebAuthn via Keycloak (already the intended IdP MFA)
- Horizontal scale with Redis streams for workflow state
- Optional OpenSearch sink for receipts
- Kubernetes Helm chart (Compose remains the supported default)
