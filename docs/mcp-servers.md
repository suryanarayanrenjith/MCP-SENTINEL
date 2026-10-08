# Compatible MCP servers

MCP-Sentinel speaks standard MCP to every upstream server: stdio (any command), Streamable HTTP, and legacy HTTP+SSE. Any spec-compliant server works. Add a server under **Servers → Connect server** (presets cover the ones below), or import your existing Claude Desktop / Claude Code configuration with `mcp-sentinel import-claude`.

## Verified with Sentinel

Each server below was registered through the API, honeypot-sandboxed, discovered and pinned, vulnerability-scanned, and called through the stdio bridge (the process Claude launches).

| Server | Launch (pinned) | Tools | Notes from testing |
|---|---|---|---|
| **Filesystem** | `npx -y @modelcontextprotocol/server-filesystem@2026.8.31 <folder>` | 14 | Reads ALLOW; credential paths (`~/.ssh`, `.env`, …) BLOCK before the server sees them; writes are WRITE capability; file contents are DLP-redacted |
| **Memory** (knowledge graph) | `npx -y @modelcontextprotocol/server-memory@2026.8.31` | 9 | Grade A; active probes run against `search_nodes` inside the honeypot |
| **Everything** (MCP reference/test server) | `npx -y @modelcontextprotocol/server-everything@2026.8.31` | 13 | Exercises every content type: images, `structuredContent`, resource links, annotations and long-running tasks all pass through. `get-env` is correctly classified as SECRET_ACCESS. Also verified in `streamableHttp` and `sse` modes |
| **Fetch** | `uvx mcp-server-fetch==2026.8.18` | 1 | EXTERNAL_LOOKUP + egress sink: taint tracking blocks secrets placed in URLs. Needs outbound internet |
| **Git** | `uvx mcp-server-git==2026.8.18 --repository <repo>` | 12 | Status/log/diff ALLOW; `git_reset` is a HIGH-sensitivity write |
| **Time** | `uvx mcp-server-time==2026.8.18` | 2 | Grade A |
| **Sequential Thinking** | `npx -y @modelcontextprotocol/server-sequential-thinking@2026.8.31` | 1 | Grade A |

Transports verified against the official MCP TypeScript SDK: Streamable HTTP with `Mcp-Session-Id` sessions, legacy HTTP+SSE, and automatic fallback from an HTTP URL to SSE. Paginated `tools/list` and servers that write stray non-protocol lines to stdout are handled.

## Expected to work (remote servers)

These use Streamable HTTP with a static header or no authentication, which Sentinel supports. They could not be reached from our test environment (egress policy), so they are listed without a guarantee.

| Server | URL | Auth |
|---|---|---|
| DeepWiki | `https://mcp.deepwiki.com/mcp` | none |
| Context7 (library docs) | `https://mcp.context7.com/mcp` | none, or an API key header |
| GitHub (remote) | `https://api.githubcopilot.com/mcp/` | `Authorization: Bearer <fine-grained PAT>` |

Servers that **only** offer an interactive OAuth login (no static token) are not supported yet: Sentinel does not run the MCP OAuth flow to upstream servers. A common workaround is a local stdio wrapper such as `npx mcp-remote <url>`, which handles the login and exposes stdio to Sentinel.

## Tips

* **Pin versions** (`pkg@1.2.3`, `pkg==1.2.3`). An unpinned `npx -y pkg` can run different code on every launch, so Sentinel flags it as a supply-chain rug-pull risk.
* **Secrets go in the server's environment field.** They are stored encrypted, never shown to the model, and the scanner flags tokens passed on the command line.
* **Windows:** use `npx` / `uvx` as usual; Sentinel resolves `npx.cmd`. If a launcher isn't found, give its absolute path.
* **First launch of an `npx`/`uvx` server** downloads the package; registration waits up to `SENTINEL_UPSTREAM_CONNECT_TIMEOUT_SECONDS` (90 s).
* If `npx` reports `ENOTEMPTY` or `ERR_MODULE_NOT_FOUND` inside `~/.npm/_npx`, an install was interrupted. Delete that folder and retry (Sentinel's error message says so).
* Run `mcp-sentinel scan -- <command …>` or `mcp-sentinel scan <url>` to vulnerability-scan a server *before* adding it.
