# MCP-Sentinel

**Adaptive Zero-Trust Security Control Plane for the Model Context Protocol (MCP).**

MCP-Sentinel is an open, self-hostable, model-agnostic PEP/PDP placed between an AI agent/MCP client and MCP servers. The LLM can propose actions. **Sentinel makes the authoritative security decision outside the model.**

Never permanently trust a user, agent, MCP server, tool, description, output, authorization state, or previously approved capability. Continuously verify identity, integrity, authorization, workflow context, capability usage, runtime behavior, and data flow — then enforce controls according to risk.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
$env:SENTINEL_DATABASE_URL = "sqlite:///./sentinel.db"
$env:SENTINEL_AUTH_MODE = "demo"
python -m uvicorn sentinel.app:app --port 8443
```

```powershell
pytest -q
python -m sentinel.demo
```

Dashboard (optional): `cd dashboard && npm install && npm run dev`

Compose: `docker compose up --build`

## What it enforces

- OIDC/JWT identity (Keycloak-ready) — **roles never taken from MCP requests**
- RBAC + capability leases + contextual policy + risk
- Four-level tool integrity (crypto, structural, semantic, behavioral)
- Semantic change firewall
- Sequential workflow attack detection
- Prompt-injection **detection plus server-side enforcement**
- Input/output validation (SSRF, traversal, injection)
- Data-flow guard (SECRET → external transfer → BLOCK)
- Adaptive responses with MFA step-up (assurance only, not a bypass)
- Explainable receipts for every decision

## Documentation

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Threat model](docs/threat-model.md)
- [API](docs/api.md)
- [LLM client integration (Claude Desktop and OpenAI)](docs/llm-integration.md)
- [Demo](docs/demo.md)
- [Limitations](docs/limitations.md)

Apache-2.0. Local organization policy always overrides any public trust evidence.
