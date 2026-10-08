# API

Base URL: `http://localhost:8443`

All enforcement APIs require `Authorization: Bearer <jwt>` except `/health` and (demo mode) `/v1/demo/token`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness |
| POST | `/v1/demo/token` | Mint demo JWT (`role`, `mfa`) |
| GET | `/v1/mcp/tools/list` | Registered tools (metadata is untrusted description) |
| POST | `/v1/mcp/tools/call` | **PEP** — authorize then optionally proxy |
| POST | `/v1/mfa/complete` | Confirm IdP MFA context for a challenge |
| GET | `/v1/dashboard/summary` | Counters for the UI |
| GET | `/v1/servers` | Server trust registry |
| GET | `/v1/tools` | Tool integrity registry |
| GET | `/v1/workflows/{id}` | Sequence + receipts |
| GET | `/v1/receipts` | Decision receipts |
| GET | `/v1/leases` | Capability leases |
| GET | `/v1/events` | Security events |
| POST | `/v1/approvals` | Human approval (SECURITY_ADMIN) |

## `POST /v1/mcp/tools/call`

```json
{
  "workflow_id": "wf-123",
  "server_id": "server-soc-01",
  "tool_name": "search_logs",
  "arguments": { "query": "10.10.20.30" },
  "user_intent": "Investigate suspicious activity from 10.10.20.30.",
  "agent_id": "soc-agent",
  "observed_runtime": {}
}
```

Response always includes `decision`, `risk_score`, `state`, `reasons`, `factors`, `receipt_id`, and `explainability`. Tool `output` is present only for ALLOW/MONITOR and is still untrusted.
