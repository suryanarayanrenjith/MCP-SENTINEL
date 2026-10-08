# MCP-Sentinel

**An adaptive, zero-trust security control plane for the Model Context Protocol.**

Add **one** MCP server to Claude Desktop or Claude Code: MCP-Sentinel. Then connect your own MCP servers from its dashboard. Those can be local `npx` / `uvx` / Docker / Python servers or remote Streamable HTTP / SSE servers. They all appear in Claude behind Sentinel, and **every tool call is verified, risk-scored and enforced outside the model**, before, during and after execution.

The LLM can only *propose* a tool call. Sentinel decides.

```
 Claude Desktop / Claude Code ──stdio──► sentinel.bridge ─┐
 Cursor / VS Code / any client ──Streamable HTTP /mcp────►├─ MCP-Sentinel ─► your MCP servers (stdio · HTTP · SSE)
 Dashboard ───────────────────────────────REST /v1───────►┘
      identity → server trust → tool integrity (pinned) → input validation → RBAC × capability → policy / lockdown
      → sequence · context · data flow · content taint · behaviour → risk = likelihood × impact
      → obligations (MFA step-up · human approval · scoped lease) → execute → output firewall → signed receipt
```

Sentinel ships with an **empty registry**: no built-in or demo servers. See **[DEMO.md](DEMO.md)** for a 15-minute live demo built entirely from official MCP reference servers, and **[docs/mcp-servers.md](docs/mcp-servers.md)** for servers verified to work.

## What makes it different

| | |
|---|---|
| **Rug-pull firewall** | Each tool's raw wire definition is pinned on first sight and re-verified on a schedule, on `tools/list_changed`, and just before sensitive calls. Drift is diffed and classified (COSMETIC / BENIGN / SUSPICIOUS / MALICIOUS). **The model only ever receives the pinned definition**, so a changed description never reaches the LLM before review. Tested on real package updates of the official servers. |
| **Vulnerability scanner** (SecureMCP port) | A Python port of [SecureMCP](https://github.com/makalin/SecureMCP) with its stubs implemented: OAuth / token analysis (JWT `alg`/`exp`/scope/audience, token formats, RFC 9728 / 8414 metadata, PKCE S256), authentication and server-integrity probes (TLS, auth bypass with bogus credentials, Origin / DNS-rebinding, CORS, session ids), and prompt-injection testing of tools, prompts and resources, including opt-in active probes against read-only tools that run **inside the honeypot**. HTML/JSON reports with A–F grades. Every server is scanned automatically when it is added: the server is always added, but the scan recommends fixes and a severe finding marks it **NOT SAFE** and restricts its sensitive tools. |
| **Honeypot sandbox** | New local servers can first run in a decoy home full of canary credentials, behind a recording egress proxy, with process-tree monitoring. |
| **Tool-poisoning scanner** | Hidden `<IMPORTANT>` blocks, instruction overrides, secrecy directives, approval-bypass wording, credential-path references, cross-server shadowing, Unicode-tag / zero-width / bidi / ANSI smuggling, encoded payloads, all checked in descriptions *and* parameter metadata. Tuned on real servers to avoid false positives. |
| **Content-level taint tracking** | Secrets returned by any tool are redacted for the model and fingerprinted. If those bytes later leave through *any* tool, even URL-, base64- or hex-encoded, the call is hard-blocked. |
| **Lethal-trifecta breaker** | Per workflow and across the whole toolset: private data + untrusted content + egress is detected, and Sentinel names the smallest set of servers to restrict. |
| **Evidence-fusion risk engine** | Risk = likelihood (noisy-OR of independent evidence) × impact (capability, data class, destructiveness, egress), with decaying per-workflow memory and an additive explanation waterfall. Hard policy always wins. |
| **Out-of-band step-up** | RFC 6238 TOTP (replay-protected) or human approval. Claude's call is *held open* while you approve in the browser, then completes inline under a short-lived, scoped capability lease. |
| **Output firewall** | Invisible / ANSI characters stripped, secrets redacted, prompt injections withheld or spotlighted, outputs withheld when the server misbehaved during the call. |
| **Tamper-evident ledger** | Every decision is a SHA-256 hash-chained, Ed25519-signed receipt with its gate trace and risk factors. |

## Quick start

Requirements: Python ≥ 3.11, and Node 18+ for the dashboard and `npx` servers. Optionally [uv](https://docs.astral.sh/uv/) for `uvx` servers.

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
(cd dashboard && npm install && npm run build)         # Windows: cd dashboard; npm install; npm run build; cd ..

mcp-sentinel serve                  # API + dashboard on http://127.0.0.1:8443
mcp-sentinel install-claude         # Claude Desktop  (or: mcp-sentinel install-claude-code)
```

Then add servers in the dashboard (**Servers → Connect server**; presets for Filesystem, Memory, Fetch, Git, Time, …), or move the ones you already use behind Sentinel:

```bash
mcp-sentinel import-claude --replace              # from Claude Desktop
mcp-sentinel import-claude --from code --replace  # from Claude Code (~/.claude.json, .mcp.json)
```

Sentinel announces new tools with `tools/list_changed`. Clients that honour it refresh on their own; in Claude Code run `/mcp` to reconnect if needed. Claude Desktop caches its tool list: toggle the connector or restart it. Until then, new tools are usable immediately through `sentinel_discover_tools` / `sentinel_invoke`, which go through the same enforcement.

Tests: `pytest -q`. The suite runs against a real MCP server over stdio and Streamable HTTP.

Docker Compose (Postgres, Redis, Keycloak, OPA; the image includes Node and uv for stdio servers): `docker compose up --build`, then open http://localhost:3000.

## Documentation

- **[DEMO.md](DEMO.md)**: live demo script · [Compatible MCP servers](docs/mcp-servers.md)
- [Architecture](docs/architecture.md) · [Risk engine](docs/risk-engine.md) · [Rug-pull detection](docs/rug-pull-detection.md) · [Vulnerability scanner](docs/vulnerability-scanner.md)
- [Claude Desktop, Claude Code & other clients](docs/llm-integration.md) · [API](docs/api.md)
- [Security model](docs/security-model.md) · [Threat model](docs/threat-model.md) · [Limitations](docs/limitations.md)

Apache-2.0. Self-hostable, model-agnostic, client-agnostic and server-agnostic. The vulnerability scanner ports ideas from SecureMCP (MIT, © Mehmet T. Akalin).
