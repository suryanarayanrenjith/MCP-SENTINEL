# MCP-Sentinel

**An adaptive, zero-trust security control plane for the Model Context Protocol.**

Add **one** MCP server to Claude Desktop or Claude Code: MCP-Sentinel. Then connect your own MCP servers from its dashboard. Those can be local `npx` / `uvx` / Docker / Python servers or remote Streamable HTTP / SSE servers. They all appear in Claude behind Sentinel, and **every tool call is verified, risk-scored and enforced outside the model**, before, during and after execution.

**Every call to a local server is first run in a sandbox.** A throw-away copy of the server works on a copy of your files, with decoy credentials and no real network. Sentinel only lets the real call happen if that run was clean. A malicious call is blocked even if someone clicks "approve". A surprising one waits for a person, with a preview of exactly which files would change. Anything the real call does that the sandbox didn't predict is reverted on the spot.

The LLM can only *propose* a tool call. Sentinel decides.

```
 Claude Desktop / Claude Code ──stdio──► sentinel.bridge ─┐
 Cursor / VS Code / any client ──Streamable HTTP /mcp────►├─ MCP-Sentinel ─► your MCP servers (stdio · HTTP · SSE)
 Dashboard ───────────────────────────────REST /v1───────►┘
      identity → server trust → tool integrity (pinned) → input validation → RBAC × capability → policy / lockdown
      → sequence · context · data flow · content taint · behaviour → risk = likelihood × impact
      → obligations (MFA step-up · human approval · scoped lease) → sandbox pre-flight (shadow run, verdict, preview)
      → execute → verify real effect vs. prediction (revert surprises, undo journal) → output firewall → signed receipt
```

Sentinel ships with an **empty registry**: no built-in or demo servers. See **[DEMO.md](DEMO.md)** for a 15-minute live demo built entirely from official MCP reference servers, and **[docs/mcp-servers.md](docs/mcp-servers.md)** for servers verified to work.

## What makes it different

| | |
|---|---|
| **Sandboxed tool calls** (shadow execution) | Zero trust per call: every call to a local server is executed first against a copy of its folders in a Docker sandbox (`--network none`, read-only image, all capabilities dropped, unprivileged user) with planted decoy credentials. Inside, a supervisor runs a DNS sinkhole and connection sinks (every destination is logged and nothing leaves), inotify on the decoy home, a process log and command shims. Rules judge what the call **did**: reading or leaking planted credentials, a read-only tool changing files, deleting files it wasn't asked to touch, git hooks / startup-script persistence, network utilities, unexpected hosts, mass deletion. MALICIOUS is blocked even after approval and the tool quarantined; SUSPICIOUS goes to a human with the preview. A process backend is used when Docker is unavailable. [Details](docs/sandbox.md) |
| **Effect preview on approvals** | The approval page shows what the call *would* do (each file created / modified / deleted, with a unified diff, plus network attempts and programs started), because it already ran in the sandbox. A non-expert approves the effect, not a JSON blob. |
| **Time machine (undo)** | Every file change a real call makes is journalled with the previous version. One click (or `POST /v1/undo/{receipt}`) puts the files back. |
| **Sandbox-evasion tripwire** | After the real call, its effect is diffed against the sandbox prediction. Changes the sandbox didn't see are reverted immediately, the output is withheld from the model and the tool is quarantined. |
| **Blast-radius guard** | A call that would delete more than 25 files, wipe half a folder or rewrite 100+ files is blocked, whoever approves it. Moves and renames are recognised. |
| **Behaviour audit on add** | Adding a local server exercises every tool once in the sandbox on a synthetic workspace (never your files). Malicious tools are quarantined before the model can call them, and each tool's observed behaviour becomes its contract. |
| **"Is it safe?" verdict** | Adding a server always succeeds, and the dialog answers in plain language: SAFE, CAUTION, or **NOT SAFE**, with a numbered list of fixes. The verdict combines the vulnerability scan, supply-chain checks and the behaviour audit. NOT SAFE servers keep their sensitive tools restricted until an admin fixes them or accepts the risk. |
| **Rug-pull firewall** | Each tool's raw wire definition is pinned on first sight and re-verified on a schedule, on `tools/list_changed`, and just before sensitive calls. Drift is diffed and classified (COSMETIC / BENIGN / SUSPICIOUS / MALICIOUS). **The model only ever receives the pinned definition**, so a changed description never reaches the LLM before review. Tested on real package updates of the official servers. |
| **Vulnerability scanner** (SecureMCP port) | A Python port of [SecureMCP](https://github.com/makalin/SecureMCP) with its stubs implemented: OAuth / token analysis (JWT `alg`/`exp`/scope/audience, token formats, RFC 9728 / 8414 metadata, PKCE S256), authentication and server-integrity probes (TLS, auth bypass with bogus credentials, Origin / DNS-rebinding, CORS, session ids), and prompt-injection testing of tools, prompts and resources, including opt-in active probes against read-only tools that run **inside the honeypot**. HTML/JSON reports with A–F grades. Every server is scanned automatically when it is added: the server is always added, but the scan recommends fixes and a severe finding marks it **NOT SAFE** and restricts its sensitive tools. |
| **Honeypot** | A process-level run in a decoy home full of canary credentials behind a recording egress proxy. It is the registration check when the sandbox is switched off, and it hosts the scanner's active probes for local servers. |
| **Tool-poisoning scanner** | Hidden `<IMPORTANT>` blocks, instruction overrides, secrecy directives, approval-bypass wording, credential-path references, cross-server shadowing, Unicode-tag / zero-width / bidi / ANSI smuggling, encoded payloads, all checked in descriptions *and* parameter metadata. Tuned on real servers to avoid false positives. |
| **Content-level taint tracking** | Secrets returned by any tool are redacted for the model and fingerprinted. If those bytes later leave through *any* tool, even URL-, base64- or hex-encoded, the call is hard-blocked. |
| **Lethal-trifecta breaker** | Per workflow and across the whole toolset: private data + untrusted content + egress is detected, and Sentinel names the smallest set of servers to restrict. |
| **Evidence-fusion risk engine** | Risk = likelihood (noisy-OR of independent evidence) × impact (capability, data class, destructiveness, egress), with decaying per-workflow memory and an additive explanation waterfall. Hard policy always wins. |
| **Out-of-band step-up** | RFC 6238 TOTP (replay-protected) or human approval. Claude's call is *held open* while you approve in the browser, then completes inline under a short-lived, scoped capability lease. |
| **Output firewall** | Invisible / ANSI characters stripped, secrets redacted, prompt injections withheld or spotlighted, outputs withheld when the server misbehaved during the call. |
| **Tamper-evident ledger** | Every decision is a SHA-256 hash-chained, Ed25519-signed receipt with its gate trace and risk factors. |

## Quick start

Requirements: Python ≥ 3.11, and Node 18+ for the dashboard and `npx` servers. Optionally [uv](https://docs.astral.sh/uv/) for `uvx` servers. **Docker Desktop / Engine is strongly recommended**: with it, sandbox pre-flights are fully contained. Open **Sandbox → Build image** once (Sentinel also builds it on first use). Without Docker, Sentinel uses the process sandbox (observation only) and escalates write and execute calls it cannot verify.

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

## Next add-ons worth building

Implemented in this release: sandbox pre-flight, effect previews, the time machine, the evasion tripwire, the blast-radius guard, the behaviour audit and the safety verdict. Natural next steps with high demo value:

* **One-tap approvals in Slack / Teams / mobile push** carrying the same effect preview, so a person approves the effect from anywhere.
* **Workflow replay**: a timeline of an agent session (calls, sandbox runs, taint flows, decisions) that can be exported as an incident report.
* **gVisor / Firecracker runtime** for the sandbox (`--runtime=runsc`), and the option to run the real stdio servers in containers too.
* **Signed server attestations** (Sigstore) plus a shared, signed feed of observed rug pulls and malicious tool behaviours.
* **Per-user upstream OAuth**, so each person's calls use their own credentials.

## Documentation

- **[DEMO.md](DEMO.md)**: live demo script · [Compatible MCP servers](docs/mcp-servers.md)
- [Sandboxed tool calls](docs/sandbox.md) · [Architecture](docs/architecture.md) · [Risk engine](docs/risk-engine.md) · [Rug-pull detection](docs/rug-pull-detection.md) · [Vulnerability scanner](docs/vulnerability-scanner.md)
- [Claude Desktop, Claude Code & other clients](docs/llm-integration.md) · [API](docs/api.md)
- [Security model](docs/security-model.md) · [Threat model](docs/threat-model.md) · [Limitations](docs/limitations.md)

Apache-2.0. Self-hostable, model-agnostic, client-agnostic and server-agnostic. The vulnerability scanner ports ideas from SecureMCP (MIT, © Mehmet T. Akalin).
