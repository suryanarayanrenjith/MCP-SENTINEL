# Connecting LLM clients to MCP-Sentinel

MCP-Sentinel currently has a FastAPI REST control plane and a React dashboard. It is not itself a complete MCP stdio or Streamable HTTP server, and the dashboard is not an LLM client. To use it with an LLM, route the model's tool calls through an application backend or a small MCP adapter that calls Sentinel's REST gateway. Keep identity tokens and server credentials in that trusted backend.

## 1. Start Sentinel

From the repository root, configure a local development environment and start the API:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
$env:SENTINEL_DATABASE_URL = "sqlite:///./sentinel.db"
$env:SENTINEL_AUTH_MODE = "demo"
python -m uvicorn sentinel.app:app --host 127.0.0.1 --port 8443
```

In another terminal, start the dashboard:

```powershell
cd dashboard
npm install
npm run dev
```

Open the Vite URL (normally `http://localhost:5173`). The included Vite configuration proxies `/v1` and `/health` to `http://localhost:8443`. If you change either port or host, update `dashboard/vite.config.js`. Sentinel's CORS allowlist must include the dashboard origin when the browser calls a different origin directly.

Check `GET http://localhost:8443/health` for `{"status":"ok",...}` before troubleshooting client connections.

## 2. Register and verify a server

In **Integrations**, mint a demo `SECURITY_ADMIN` token for local development, or paste an administrator token issued by your OIDC provider. The token is held in browser memory for the current page session and is sent only as a Bearer token for protected management operations. Demo token minting is disabled when `SENTINEL_AUTH_MODE=oidc`.

In **Servers → Add MCP Server**, supply a unique name, publisher, endpoint, transport, version, requested capabilities, and optional auth metadata. Registration returns the server ID and a starting trust status of `MONITORED`; the entry then appears in the registry. An administrator must use **Verify** to run Sentinel's current verification probe. Review the probe classification and trust result before allowing any client to use the server.

The auth scheme, audience, and scopes fields are declarations only. Sentinel does not persist target credentials, authenticate to the target during registration, discover its live tool catalog, or forward target credentials through the current gateway. Do not enter secrets in these fields. The current verifier evaluates a synthetic expected behavior profile; it is not proof that the endpoint is reachable or safe.

Protected registration, verification, and manual trust changes require a Bearer token with `SECURITY_ADMIN` or `SYSTEM_ADMIN`. In demo mode, a local token can also be requested with:

```powershell
curl.exe -X POST "http://localhost:8443/v1/demo/token?role=SECURITY_ADMIN&subject=local-admin"
```

For production, set `SENTINEL_AUTH_MODE=oidc` and configure issuer, audience, algorithms, and JWKS/introspection settings for your identity provider. Do not expose demo mode or its signing secret to a network.

## 3. Gateway call contract

The gateway's tool-call API is:

```http
POST /v1/mcp/tools/call
Authorization: Bearer <end-user access token>
Content-Type: application/json
```

```json
{
  "workflow_id": "conversation-42",
  "server_id": "server-1234abcd",
  "tool_name": "search_records",
  "arguments": {"query": "example"},
  "user_intent": "Find the requested record"
}
```

The response decision can be `ALLOW`, `MONITOR`, `BLOCK`, or `MFA_REQUIRED`. The calling application must treat Sentinel's decision as authoritative and must not invoke or reveal a target result on `BLOCK` or `MFA_REQUIRED`. The app currently sends allowed calls to the registered endpoint's `/tools/invoke` path. A target connection or response error is returned as `execution.executed: false`; it is not represented as successful output. Ensure your target implements this expected route before connecting it.

The administrator token is for management operations. Tool calls should use the calling user's validated access token so identity and roles are evaluated for that user. Do not put tokens in model prompts, tool arguments, browser bundles, or logs.

## 4. Claude Desktop

Claude Desktop connects to MCP servers using supported MCP transports. Sentinel's gateway is REST, so it cannot be connected directly as an MCP server. The repository includes `scripts/sentinel_mcp_adapter.py`, a local stdio adapter that exposes Sentinel's registered tools and routes calls through its REST policy gateway. The adapter:

1. Implements MCP `tools/list` and `tools/call` over stdio for Claude Desktop.
2. Obtains the user's Sentinel access token using your organization's approved local credential flow.
3. Maps each exposed MCP tool to a fixed `server_id` and `tool_name`; do not accept these identifiers from model-controlled arguments.
4. Sends the tool arguments to `POST /v1/mcp/tools/call` and returns results only for allowed decisions.
5. Returns `MFA_REQUIRED` with its challenge details; the user or host application must complete step-up and retry because the adapter does not implement interactive MFA.

Claude Desktop's local server configuration uses an `mcpServers` entry with a command, arguments, and environment; follow Anthropic's [Claude Desktop local MCP guide](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) for the current config-file location and UI steps. Merge this entry into the existing config and replace the absolute paths and token:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "<absolute-path-to-python>",
      "args": ["<absolute-repo-path>/scripts/sentinel_mcp_adapter.py"],
      "env": {
        "SENTINEL_API_URL": "http://127.0.0.1:8443",
        "SENTINEL_TOKEN": "<short-lived-user-access-token>"
      }
    }
  }
}
```

The adapter reads `SENTINEL_TOKEN` from its process environment as the end-user identity for tool calls. Do not commit or share a config containing this value; use a short-lived token and replace it when it expires. Restart Claude Desktop after changing its config, inspect the exposed tool list, and test with a low-risk tool. The local adapter returns `MFA_REQUIRED` details but does not perform interactive step-up; complete MFA and retry using the host application's approved flow.

## 5. OpenAI API applications

For OpenAI, define function tools in your own application and execute them in the application backend. The model proposes a function call; your backend maps the function name to an approved Sentinel server/tool pair and calls Sentinel. Never let model arguments select arbitrary server IDs or endpoints.

An illustrative Responses API function definition is:

```json
{
  "type": "function",
  "name": "search_records",
  "description": "Search records through MCP-Sentinel policy enforcement",
  "parameters": {
    "type": "object",
    "properties": {"query": {"type": "string"}},
    "required": ["query"],
    "additionalProperties": false
  },
  "strict": true
}
```

On a function call, validate its arguments against your schema, look up the fixed server/tool mapping, and POST the gateway contract above with the end-user token and a fresh conversation workflow ID. Return the tool output to the model only when Sentinel allows execution and reports a successful execution. On `MFA_REQUIRED`, pause for the application's step-up flow, call `POST /v1/mfa/complete` with the same user's token and the challenge ID, then repeat the original gateway call. On `BLOCK`, return a concise denial without calling the target.

The model provider does not authenticate to Sentinel in this setup; your backend does. Use HTTPS and keep OpenAI API keys, Sentinel tokens, and target credentials in server-side secret storage. This design works with OpenAI tool calling in your own application; it is not a direct “connect Sentinel” toggle in the OpenAI web UI.

OpenAI's Responses API can also connect directly to a remote MCP server using a tool definition with `type: "mcp"`, `server_label`, and `server_url`, with optional authorization and approval settings. That route becomes available only after an MCP adapter exposes Sentinel tools over an MCP-compatible remote transport; Sentinel's current REST API URL is not a valid MCP `server_url`. See the official [OpenAI remote MCP tool guide](https://platform.openai.com/docs/guides/tools-remote-mcp) and keep approval enabled while evaluating tools.

## 6. Sandbox and verification result semantics

The dashboard's standalone sandbox form compares expected and simulated observed behavior profiles using Sentinel's sandbox policy engine. Registration and Verify use a synthetic profile that declares network access to the configured endpoint and disallows process spawning and environment access. Neither flow starts the target in a container, connects to it, invokes a real tool, nor performs a live penetration test. Display those results as policy-probe evidence only.

For production use, add a separately isolated runner that launches the server with explicit CPU, memory, filesystem, network, and credential boundaries, captures runtime observations, and stores signed evidence. Do not label a synthetic probe as a live server test.

## Useful endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | API health |
| `GET /v1/mcp/tools/list` | Sentinel's currently registered tool catalog |
| `POST /v1/mcp/tools/call` | Identity, policy, and risk decision plus permitted execution |
| `POST /v1/servers` | Admin-only server registration |
| `POST /v1/servers/{server_id}/verify` | Admin-only synthetic verification probe |
| `POST /v1/sandbox/probe` | Standalone expected-versus-observed policy probe |

See [API](api.md), [Security model](security-model.md), and [Limitations](limitations.md) for the project's broader control-plane behavior and current limitations.
