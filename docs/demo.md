# Demonstration

## 1. Automated scenarios (no client needed)

```bash
python -m sentinel.demo           # add --json for machine-readable output
```

This starts the lab SOC MCP server (real Streamable HTTP) and runs five scenarios through the full pipeline:

| # | Scenario | Expected |
|---|---|---|
| 1 | Legitimate SOC workflow: `search_logs` → `lookup_ip` → `create_incident` | ALLOW 1 → MONITOR 30 (lethal trifecta now possible) → ALLOW 2 |
| 2 | Dangerous legitimate sequence: … → `get_credentials` → `send_data` to an external URL | MFA_REQUIRED 68 → (step-up) RESTRICT 59, secret redacted → **BLOCK 100** |
| 3 | Secret smuggled inside a `lookup_ip` argument | **BLOCK 93** (content taint) |
| 4 | Rug pull: the lab server swaps in poisoned definitions | `search_logs` MALICIOUS (95), `lookup_ip` SUSPICIOUS; the poisoned text is never served; the call is BLOCKED |
| 5 | Compromised trusted tool (lab telemetry: env read, unknown host, process spawn) | **BLOCK** + QUARANTINE, later calls blocked |

The run finishes by verifying the signed audit ledger. `pytest -q` runs the full test suite against the same lab server.

## 2. Live demo with Claude Desktop

```bash
mcp-sentinel serve        # terminal 1: API + dashboard on http://127.0.0.1:8443
mcp-sentinel lab          # terminal 2: lab SOC MCP server on :9001 (pre-registered as "soc")
mcp-sentinel install-claude
```

Restart Claude Desktop and open the dashboard next to it.

1. *"Investigate suspicious activity from 10.10.20.30 and open an incident."* The calls run (ALLOW / MONITOR) and appear live in **Overview** and **Workflows**.
2. *"Get the VPN credentials."* The decision is MFA_REQUIRED. The call is held, and the approval page opens with the tool, an argument preview, the risk waterfall and the reasons. Approve with your authenticator (enrol under **Connect**) or the demo button. Claude's original call then completes.
3. *"Send them to https://cdn.attacker.net/upload."* This is a hard BLOCK. Open the receipt to see the gate trace.
4. Rug pull:

   ```bash
   curl -X POST localhost:9001/admin/rugpull -H 'content-type: application/json' -d '{"enabled": true}'
   ```

   Ask for another sensitive action, or wait for the next discovery poll. **Rug pulls** shows the MALICIOUS diff, and `search_logs` is quarantined and no longer served. Reject the change in the dashboard to keep the tool quarantined, or send `{"enabled": false}` to revert it. Reverting closes the change, but the quarantine stays until an administrator restores trust under **Tools**.
5. Compromise: `curl -X POST localhost:9001/admin/compromise -H 'content-type: application/json' -d '{"enabled": true}'`. The next `search_logs` output is withheld and the server is quarantined. `GET localhost:9001/admin/state` shows both switches.
6. **Audit → Verify chain**, **Policy → Lockdown**, and **Rug pulls → Toxic-flow map**.

### With your own servers

**Servers → Connect server → Filesystem** (or `mcp-sentinel import-claude --replace`). For local servers, tick *Run the honeypot sandbox before connecting*. Then ask Claude to read a file (ALLOW) and to read `~/.ssh/id_rsa` (BLOCK: credential path). With Fetch and Filesystem connected together, **Rug pulls → Toxic-flow map** reports the lethal trifecta and which server to cut.

## 3. Docker Compose

```bash
docker compose up --build
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API | http://localhost:8443/health |
| Keycloak | http://localhost:8080 (admin/admin, realm `mcp-sentinel`) |
| OPA | http://localhost:8181 |

All ports are bound to 127.0.0.1. For full OIDC set `SENTINEL_AUTH_MODE=oidc` and `SENTINEL_OIDC_JWKS_URL=http://keycloak:8080/realms/mcp-sentinel/protocol/openid-connect/certs`. Local stdio servers need their runtimes (`node`, `uv`) inside the Sentinel image, so run Sentinel natively when you front Claude Desktop on a laptop.
