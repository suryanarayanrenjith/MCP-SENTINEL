# Known limitations

## Verification scope

* The MCP frontend (stdio bridge and `/mcp`) was exercised with scripted JSON-RPC clients: handshake, `tools/list`, calls, held step-up, `list_changed` and live rug pulls. It has **not** been tested inside Claude Desktop itself. Client behaviour can differ in its details, such as progress-notification timeouts and how `open_url` is handled.
* Claude Desktop caches its tool list and does not reliably honour `notifications/tools/list_changed`. Servers added after Claude starts can be used straight away through `sentinel_discover_tools` / `sentinel_invoke`; to see them as native tools, toggle the connector or restart Claude.
* A held step-up call lasts `SENTINEL_WAIT_SECONDS` (50 s by default), which is chosen to stay under typical client request timeouts. If approval comes later, Claude has to call the tool again. The lease is then already in place.

## Detection limits

* The poisoning scanner and capability inference are heuristics: patterns, a verb lexicon, schema shape. A novel phrasing can evade them, and unusual tool names can be over-classified. Every result is shown with its evidence and can be overridden with a locked profile.
* TOFU pinning trusts the **first** definition it sees. The honeypot, the scanner and supply-chain checks reduce that risk but cannot remove it. Pre-approved curated profiles are the strongest option.
* Behavioural baselines need at least 5 samples before they flag drift, and a slow, gradual drift can stay under the z-score thresholds.
* Process and network monitoring uses psutil snapshots taken around each call and every few seconds. Very short-lived processes or connections can be missed, and remote HTTP servers can only be observed through their outputs.
* The honeypot runs the server as the **same OS user** in a decoy HOME behind a recording proxy. It is a best-effort detector, not a security boundary: a server that ignores `HOME`/proxy variables, or one that delays malicious behaviour, can evade it. Use containers or VMs for real isolation.
* Content-taint tracking matches exact values and common encodings (URL, base64, hex). Secrets that are transformed (split, encrypted, paraphrased) are not matched. The data-flow rules and the trifecta evidence still apply.
* Sentinel cannot see what the model writes in its *reply*. It controls tool calls and tool outputs only.

## Platform

* Single process. Upstream sessions, background jobs and hot state (unless Redis is configured) live in one API process, so there is no high availability.
* Only MCP **tools** are proxied. Resources, prompts and sampling are not forwarded (Sentinel answers `resources/list` and `prompts/list` with empty lists), and upstream server→client requests other than `ping` are refused.
* Remote upstream servers authenticate with static headers or bearer tokens. MCP OAuth authorisation flows to upstream servers are not implemented.
* Demo mode uses an HS256 shared secret and offers demo confirmation in place of MFA. Use OIDC (`SENTINEL_AUTH_MODE=oidc`) and TOTP or IdP MFA outside a local demo.
* OPA/Rego is shipped as an optional PDP (`SENTINEL_OPA_ENABLED`). Tests use the equivalent Python PDP.

## Future work

* container sandboxing (gVisor/Firecracker) for the honeypot and for running stdio servers
* MCP OAuth 2.1 to upstream servers, and per-user upstream credentials
* signed server attestations (Sigstore, in-toto) and a shared, signed rug-pull intelligence feed
* resource and prompt proxying with the same pinning and scanning
* WebAuthn step-up directly in the approval page
* Redis streams and leader election for horizontal scale
