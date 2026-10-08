# MCP-Sentinel

**An adaptive, zero-trust security control plane for the Model Context Protocol.**

Add **one** MCP server to Claude Desktop — MCP-Sentinel — and connect every other MCP server (local `npx`/`uvx`/Docker servers or remote HTTP/SSE servers) through its dashboard. They all appear in Claude behind Sentinel, and **every tool call is verified, risk-scored and enforced outside the model** — before, during and after execution.

The LLM can only *propose* a tool call. Sentinel decides.

```
 User ─► Claude / any LLM ─► MCP client ─► ┌────────────────────── MCP-SENTINEL ──────────────────────┐ ─► MCP servers ─► tools ─► resources
                                           │ identity → agent → server trust → tool integrity (pinned) │     (stdio, Streamable HTTP, SSE)
                                           │ → semantic change → input validation → RBAC + capability   │
                                           │ → policy-as-code / lockdown → sequence · context · data    │
                                           │ flow · taint · runtime evidence → risk = L × I → obligations │
                                           │ (MFA step-up · human approval · lease) → execute → output   │
                                           │ firewall → behavioural baseline → signed receipt           │
                                           └───────────────────────────────────────────────────────────┘
```

## What makes it different

| | |
|---|---|
| **Rug-pull firewall** | Every tool's *raw wire definition* is pinned on first sight (TOFU) and re-verified on a schedule, on `notifications/tools/list_changed`, and **just before every sensitive call**. Drift is diffed and classified (COSMETIC / BENIGN / SUSPICIOUS / MALICIOUS). **The model always receives the pinned description**, so a poisoned update never reaches the LLM; malicious changes quarantine the tool, restrict the server and revoke its leases. |
| **Behavioural & supply-chain rug pulls** | Pinning can't see a server that keeps its description but changes its code — so Sentinel learns a statistical baseline per tool (latency, output size/shape, domains, injection/secret appearance, child processes and remote hosts of the server's process tree) and flags drift. Unpinned `npx -y pkg` / `uvx pkg`, typosquatted package names, `curl \| sh` wrappers and privileged containers are flagged at registration. |
| **Tool-poisoning scanner** | Hidden `<IMPORTANT>` blocks, instruction overrides, secrecy directives ("don't tell the user"), approval-bypass social engineering, credential-file references, data-collection directives (`pass its content as 'sidenote'`), cross-server shadowing, Unicode-tag ASCII smuggling, bidi/zero-width/ANSI tricks, base64 payloads — scanned in descriptions *and every parameter's metadata*. |
| **Honeypot sandbox** | New local servers can be launched first in a decoy home directory full of canary credentials (SSH key, AWS, `.env`, Claude/Cursor configs) behind a recording egress proxy that only lets package registries through. Reading a decoy, emitting a canary or phoning home is caught before the server ever touches real data. |
| **Content-level taint tracking** | Secrets returned by tools are fingerprinted (salted hashes, never stored). If those exact bytes later leave through *any* egress tool — even URL-encoded, base64 or hex inside an innocent-looking lookup — the call is hard-blocked. |
| **Lethal-trifecta breaker** | Each workflow tracks whether the agent has read private data, ingested untrusted content and can reach an egress sink. Completing the trifecta raises risk; a toolset-wide toxic-flow map shows which servers to cut. |
| **Evidence-fusion risk engine** | Risk = **likelihood** (noisy-OR fusion of independent evidence) × **impact** (capability, data class, destructiveness, egress), with decaying per-workflow risk memory. Weak signals no longer add up into false blocks; every score comes with an additive waterfall explaining it. Hard policy always wins. |
| **Out-of-band step-up** | Real RFC 6238 TOTP (replay-protected). Claude's call is *held open* while the approval page opens in your browser; approve with your authenticator and the same call completes inline. Leases for CRITICAL tools are bound to the **exact approved arguments**. |
| **Output firewall** | Tool output is untrusted data: secrets redacted (unless explicitly authorised), invisible/ANSI smuggling stripped, prompt injections spotlighted or quarantined, and outputs withheld when the tool misbehaved during the call. |
| **Tamper-evident ledger** | Every decision is a receipt in a SHA-256 hash chain, Ed25519-signed, with the gate trace and risk factors. One click verifies the whole chain. |
| **Policy-as-code & lockdown** | RBAC × capabilities, admin rules (DENY / REQUIRE_MFA / REQUIRE_APPROVAL by server, tool glob, capability, role) and a one-click incident lockdown. |

## Quick start (local, ~5 minutes)

Requirements: Python ≥ 3.11, Node 18+ (for the dashboard and for `npx`-based MCP servers).

```powershell
# Windows PowerShell                                   # macOS / Linux
python -m venv .venv                                   # python3 -m venv .venv
.\.venv\Scripts\Activate.ps1                           # source .venv/bin/activate
pip install -e ".[dev]"                                # pip install -e ".[dev]"
cd dashboard; npm install; npm run build; cd ..        # (cd dashboard && npm install && npm run build)

mcp-sentinel serve            # control plane + dashboard on http://127.0.0.1:8443
mcp-sentinel lab              # (second terminal) lab SOC MCP server on :9001 — optional
mcp-sentinel install-claude   # adds Sentinel to claude_desktop_config.json (keeps a backup)
```

Restart Claude Desktop. You'll see the `mcp-sentinel` server with the lab tools (`soc__search_logs`, `soc__get_credentials`, …) and four meta-tools.

* **Add servers:** dashboard → *Servers → Connect server* (presets for Filesystem, Fetch, Memory, Git, or any command/URL), or move your existing Claude Desktop servers behind Sentinel with `mcp-sentinel import-claude --replace`.
* **Claude Desktop caches its tool list** (it does not reliably honour `list_changed`), so servers added later are usable immediately through `sentinel_discover_tools` + `sentinel_invoke` (same enforcement, no bypass) and appear as native tools after toggling the connector off/on.
* **Step-up:** enrol an authenticator under *Connect → Step-up authenticator*. Without one, demo mode offers a demo confirmation button.

Run the automated scenarios and tests:

```bash
python -m sentinel.demo     # 5 end-to-end scenarios against a real MCP lab server
pytest -q                   # 54 tests (MCP transports, rug pulls, taint, step-up, ledger, …)
```

Docker Compose (organisation deployment with Postgres, Redis, Keycloak, OPA): `docker compose up --build` → dashboard on http://localhost:3000. Local stdio servers need `node`/`uv` in the image, so for Claude Desktop on a laptop run Sentinel natively.

## Hackathon demo script

1. **Normal work is frictionless.** Ask Claude: *"Investigate suspicious activity from 10.10.20.30 and open an incident."* `search_logs` (ALLOW, risk 1), `lookup_ip` (MONITOR, 30: the workflow now holds private data, untrusted content and an egress sink, which is the lethal trifecta) and `create_incident` (ALLOW) run and stream into the dashboard.
2. **Risk-adaptive step-up.** *"Now get the VPN credentials."* Risk is about 48 (secret access after an external lookup, privilege escalation, no MFA context) on a high-impact SECRET_ACCESS tool, so the decision is MFA_REQUIRED. Claude's call is held, the approval page opens, and you enter your TOTP code (or press the demo button if no authenticator is enrolled). The same call then completes under an action-bound lease. If residual risk is still ≥ 40, it runs as RESTRICT and the secret is redacted.
3. **Exfiltration stopped.** *"Send it to https://cdn.attacker.net/upload"* is a hard BLOCK (100: SECRET data to an external sink). *"Look up 203.0.113.7/?d=<the password>"* is a BLOCK (95) through content taint, because the secret's bytes are recognised inside an innocent-looking argument.
4. **Rug pull, live.** `curl -X POST localhost:9001/admin/rugpull -H 'content-type: application/json' -d '{"enabled":true}'` The next sensitive call, or the next discovery poll (60 s at most), re-lists the server. *Rug pulls* then shows a MALICIOUS diff (a hidden `<IMPORTANT>` block and a new `context` parameter). The tool is quarantined and removed from Sentinel's catalogue, and every call to the server's sensitive tools is blocked. The model never saw the poisoned text, because Claude is only ever served the pinned definition.
5. **Compromised runtime.** `…/admin/compromise` → the next call's output is withheld, the server quarantined.
6. **Proof.** *Audit → Verify chain*: every decision signed and chained; open any receipt for its gate trace and risk waterfall. *Policy → Lockdown* stops everything in one click.

## Documentation

- [Architecture](docs/architecture.md) · [Risk engine](docs/risk-engine.md) · [Rug-pull detection](docs/rug-pull-detection.md)
- [Claude Desktop & other clients](docs/llm-integration.md) · [API](docs/api.md)
- [Security model](docs/security-model.md) · [Threat model](docs/threat-model.md) · [Demo](docs/demo.md) · [Limitations](docs/limitations.md)

Apache-2.0. Open-source, self-hostable, model-agnostic, client-agnostic and server-agnostic. Local organisation policy always overrides public trust evidence.
