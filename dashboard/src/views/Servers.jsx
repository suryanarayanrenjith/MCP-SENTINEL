import { useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, Chips, Drawer, Empty, ErrorNote, Findings, Json, Modal, Pill, Tabs } from "../components/ui.jsx";
import { routeTo, timeAgo } from "../format.js";

const PRESETS = [
  { label: "Filesystem", name: "Filesystem", command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "<absolute path to a folder>"] },
  { label: "Fetch", name: "Fetch", command: "uvx", args: ["mcp-server-fetch"] },
  { label: "Memory", name: "Memory", command: "npx", args: ["-y", "@modelcontextprotocol/server-memory"] },
  { label: "Git", name: "Git", command: "uvx", args: ["mcp-server-git", "--repository", "<absolute path to a repo>"] },
  { label: "Lab SOC (stdio)", name: "Lab SOC stdio", command: "python", args: ["-m", "mcp_servers.soc_server", "--stdio"] },
];

function parseLines(text) {
  return text.split("\n").map((l) => l.trim()).filter(Boolean);
}

function parseKV(text, sep) {
  const out = {};
  for (const line of parseLines(text)) {
    const i = line.indexOf(sep);
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

function AddServerModal({ onClose, onDone, toast }) {
  const [mode, setMode] = useState("Local (stdio)");
  const [form, setForm] = useState({ server_name: "", command: "", args: "", env: "", cwd: "", url: "", transport: "http", bearer: "", headers: "", sandbox: true, publisher: "", description: "" });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = mode === "Local (stdio)"
        ? { server_name: form.server_name, transport: "stdio", command: form.command, args: parseLines(form.args), env: parseKV(form.env, "="), cwd: form.cwd, run_sandbox: form.sandbox, publisher: form.publisher, description: form.description }
        : { server_name: form.server_name, transport: form.transport, endpoint: form.url, bearer_token: form.bearer, headers: parseKV(form.headers, ":"), run_sandbox: false, publisher: form.publisher, description: form.description };
      const res = await api.post("/v1/servers", body);
      setResult(res);
      onDone();
      toast(res.message || "Server registered");
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }

  if (result) {
    const d = result.discovery || {};
    return (
      <Modal title={`Registered: ${form.server_name}`} onClose={onClose} wide>
        <div className="row gap wrap">
          <span className="mono">{result.server_id}</span>
          <Pill value={result.trust_status} />
          <Pill value={result.risk_state} />
        </div>
        {result.sandbox && (
          <Card title="Honeypot sandbox" subtitle="Launched with a decoy home directory, canary credentials and a recording egress proxy">
            <div className="row gap"><Pill value={result.sandbox.classification} /> <span className="muted small">{result.sandbox.evidence?.duration_s}s</span></div>
            <ul className="plain">{(result.sandbox.anomalies || []).map((a, i) => <li key={i} className="danger-text">{a}</li>)}</ul>
            {(result.sandbox.anomalies || []).length === 0 && <p className="good-text">No canary access, egress or suspicious processes observed.</p>}
          </Card>
        )}
        <Card title="Discovery">
          {d.error ? <ErrorNote error={d.error} /> : (
            <table className="table compact">
              <thead><tr><th>Tool</th><th>Scan</th><th>Capabilities</th></tr></thead>
              <tbody>{(d.added || []).map((t) => <tr key={t.tool}><td className="mono">{t.tool}</td><td><Pill value={t.verdict} /></td><td><Chips items={t.capabilities} /></td></tr>)}</tbody>
            </table>
          )}
        </Card>
        {(result.findings || []).length > 0 && <Card title="Supply-chain findings"><Findings items={result.findings} /></Card>}
        <div className="modal-actions"><button className="btn btn-primary" onClick={onClose}>Done</button></div>
      </Modal>
    );
  }

  return (
    <Modal title="Connect an MCP server" onClose={onClose} wide>
      <Tabs tabs={["Local (stdio)", "Remote (HTTP / SSE)"]} value={mode} onChange={setMode} />
      <form onSubmit={submit} className="form">
        {mode === "Local (stdio)" && (
          <div className="presets">
            <span className="muted small">Presets:</span>
            {PRESETS.map((p) => (
              <button type="button" key={p.label} className="btn btn-sm" onClick={() => setForm((f) => ({ ...f, server_name: p.name, command: p.command, args: p.args.join("\n") }))}>{p.label}</button>
            ))}
          </div>
        )}
        <label>Name<input className="input" required value={form.server_name} onChange={(e) => set("server_name", e.target.value)} placeholder="e.g. Filesystem" /></label>
        {mode === "Local (stdio)" ? (
          <>
            <label>Command<input className="input mono" required value={form.command} onChange={(e) => set("command", e.target.value)} placeholder="npx / uvx / python / node / docker" /></label>
            <label>Arguments <span className="muted small">(one per line)</span><textarea className="input mono" rows={4} value={form.args} onChange={(e) => set("args", e.target.value)} /></label>
            <label>Environment <span className="muted small">(KEY=value per line — stored encrypted, never shown to the model)</span><textarea className="input mono" rows={3} value={form.env} onChange={(e) => set("env", e.target.value)} placeholder="GITHUB_PERSONAL_ACCESS_TOKEN=…" /></label>
            <label>Working directory <span className="muted small">(optional)</span><input className="input mono" value={form.cwd} onChange={(e) => set("cwd", e.target.value)} /></label>
            <label className="checkbox-row"><input type="checkbox" checked={form.sandbox} onChange={(e) => set("sandbox", e.target.checked)} /> Run the honeypot sandbox before connecting (decoy credentials, egress recording, process monitoring)</label>
            <p className="muted small">Pin package versions (<span className="mono">pkg@1.2.3</span>): an unpinned <span className="mono">npx -y pkg</span> can change code on any launch — Sentinel flags it as a supply-chain rug-pull risk.</p>
          </>
        ) : (
          <>
            <label>URL<input className="input mono" required value={form.url} onChange={(e) => set("url", e.target.value)} placeholder="https://example.com/mcp" /></label>
            <label>Transport
              <select className="input" value={form.transport} onChange={(e) => set("transport", e.target.value)}>
                <option value="http">Streamable HTTP (falls back to SSE automatically)</option>
                <option value="sse">Legacy HTTP+SSE</option>
              </select>
            </label>
            <label>Bearer token <span className="muted small">(optional, stored encrypted)</span><input className="input mono" type="password" autoComplete="off" value={form.bearer} onChange={(e) => set("bearer", e.target.value)} /></label>
            <label>Extra headers <span className="muted small">(Name: value per line)</span><textarea className="input mono" rows={2} value={form.headers} onChange={(e) => set("headers", e.target.value)} /></label>
          </>
        )}
        <label>Description<input className="input" value={form.description} onChange={(e) => set("description", e.target.value)} /></label>
        <ErrorNote error={error} />
        <div className="modal-actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Sandboxing, connecting & scanning…" : "Connect & verify"}</button>
        </div>
      </form>
    </Modal>
  );
}

function ImportModal({ onClose, onDone, toast }) {
  const [text, setText] = useState("");
  const [sandbox, setSandbox] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  async function run() {
    setBusy(true);
    setError("");
    try {
      const res = await api.post("/v1/servers/import", { config: text, connect: true, run_sandbox: sandbox });
      setResult(res);
      onDone();
      toast(`Imported ${res.imported.length} server(s)`);
    } catch (e) {
      setError(e.message);
    }
    setBusy(false);
  }
  return (
    <Modal title="Import from Claude Desktop / Cursor config" onClose={onClose} wide>
      <p className="muted">Paste the contents of <span className="mono">claude_desktop_config.json</span> (or any <span className="mono">mcpServers</span> block). Each server is registered behind Sentinel; Sentinel's own entry is skipped. Then replace those entries in Claude with the single <span className="mono">mcp-sentinel</span> entry (or run <span className="mono">mcp-sentinel import-claude --replace</span>).</p>
      <textarea className="input mono" rows={10} value={text} onChange={(e) => setText(e.target.value)} placeholder='{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/Documents"]}}}' />
      <label className="checkbox-row"><input type="checkbox" checked={sandbox} onChange={(e) => setSandbox(e.target.checked)} /> Honeypot-sandbox each local server first</label>
      <ErrorNote error={error} />
      {result && (
        <table className="table compact">
          <thead><tr><th>Server</th><th>Result</th></tr></thead>
          <tbody>{result.results.map((r) => <tr key={r.name}><td>{r.name}</td><td>{r.error ? <span className="danger-text">{String(r.error)}</span> : r.skipped ? <span className="muted">{r.skipped}</span> : <span><Pill value={r.trust_status} /> {r.tools} tools</span>}</td></tr>)}</tbody>
        </table>
      )}
      <div className="modal-actions">
        <button className="btn" onClick={onClose}>Close</button>
        <button className="btn btn-primary" disabled={busy || !text.trim()} onClick={run}>{busy ? "Importing…" : "Import"}</button>
      </div>
    </Modal>
  );
}

function ServerDetail({ serverId, onClose, toast, isAdmin }) {
  const [tab, setTab] = useState("Tools");
  const [busy, setBusy] = useState("");
  const detail = usePoll(() => api.get(`/v1/servers/${serverId}`), [serverId], 4000);
  const s = detail.data;
  async function act(label, fn) {
    setBusy(label);
    try {
      await fn();
      toast(`${label} done`);
      detail.reload();
    } catch (e) {
      toast(`${label} failed: ${e.message}`, true);
    }
    setBusy("");
  }
  if (!s) return <Drawer title="Server" onClose={onClose}><ErrorNote error={detail.error} /></Drawer>;
  const actions = isAdmin && (
    <>
      <button className="btn btn-sm" disabled={!!busy} onClick={() => act("Re-scan", () => api.post(`/v1/servers/${serverId}/discover`))}>{busy === "Re-scan" ? "Scanning…" : "Re-scan"}</button>
      <button className="btn btn-sm btn-primary" disabled={!!busy} onClick={() => act("Verify", () => api.post(`/v1/servers/${serverId}/verify`))}>{busy === "Verify" ? "Verifying…" : "Verify"}</button>
    </>
  );
  return (
    <Drawer title={s.server_name} onClose={onClose} actions={actions}>
      <div className="row gap wrap">
        <Pill value={s.trust_status} /> <Pill value={s.risk_state} /> <span className="chip">{s.transport}</span>
        <span className="mono small">{s.slug}__*</span>
        {s.connection?.connected ? <span className="good-text small">● connected{s.connection.pid ? ` (pid ${s.connection.pid})` : ""}</span> : <span className="muted small">○ not connected</span>}
        {!s.enabled && <span className="chip warning">disabled</span>}
      </div>
      <p className="mono small muted">{s.endpoint}</p>
      {s.last_error && <ErrorNote error={s.last_error} />}
      {isAdmin && (
        <div className="row gap wrap">
          <select className="input input-sm" value={s.trust_status} onChange={(e) => act("Trust change", () => api.put(`/v1/servers/${serverId}/trust`, { trust_status: e.target.value, reason: "dashboard" }))}>
            {["TRUSTED", "MONITORED", "RESTRICTED", "QUARANTINED", "BLOCKED"].map((t) => <option key={t}>{t}</option>)}
          </select>
          <button className="btn btn-sm" onClick={() => act(s.enabled ? "Disable" : "Enable", () => api.patch(`/v1/servers/${serverId}`, { enabled: !s.enabled }))}>{s.enabled ? "Disable" : "Enable"}</button>
          {s.transport === "stdio" && <button className="btn btn-sm" disabled={!!busy} onClick={() => act("Sandbox", () => api.post(`/v1/servers/${serverId}/sandbox`))}>{busy === "Sandbox" ? "Running honeypot…" : "Run honeypot sandbox"}</button>}
          <button className="btn btn-sm btn-danger" onClick={() => { if (window.confirm(`Remove ${s.server_name} from Sentinel?`)) act("Remove", async () => { await api.del(`/v1/servers/${serverId}`); onClose(); }); }}>Remove</button>
        </div>
      )}
      <Tabs tabs={["Tools", "Findings", "Sandbox", "Changes", "Logs", "Config"]} value={tab} onChange={setTab} />
      {tab === "Tools" && (
        <table className="table compact">
          <thead><tr><th>Exposed as</th><th>Capabilities</th><th>Trust</th><th>Review</th></tr></thead>
          <tbody>{(s.tools || []).map((t) => (
            <tr key={t.tool_id} className="clickable" onClick={() => routeTo(`/tools/${encodeURIComponent(t.tool_id)}`)}>
              <td className="mono">{t.exposed_name}</td><td><Chips items={t.capabilities} /></td><td><Pill value={t.trust_status} /></td><td><Pill value={t.review_state} /></td>
            </tr>
          ))}</tbody>
        </table>
      )}
      {tab === "Findings" && <Findings items={s.findings} />}
      {tab === "Sandbox" && (s.sandbox_report ? (
        <div className="stack">
          <div className="row gap"><Pill value={s.sandbox_report.classification} /><span className="muted small">{s.sandbox_report.evidence?.duration_s}s · decoys: {(s.sandbox_report.evidence?.decoys || []).join(", ")}</span></div>
          <Findings items={s.sandbox_report.evidence?.findings} />
          <Json value={s.sandbox_report.evidence} />
        </div>
      ) : <Empty>No sandbox run yet{s.transport !== "stdio" ? " (remote servers are verified through discovery and transport checks)" : ""}.</Empty>)}
      {tab === "Changes" && ((s.changes || []).length === 0 ? <Empty>No definition changes recorded.</Empty> : (
        <table className="table compact">
          <thead><tr><th>Tool</th><th>Class</th><th>Status</th><th>Detected</th></tr></thead>
          <tbody>{s.changes.map((c) => (
            <tr key={c.change_id} className="clickable" onClick={() => routeTo(`/integrity/${c.change_id}`)}>
              <td className="mono">{c.tool}</td><td><Pill value={c.classification} /></td><td><Pill value={c.status} /></td><td className="muted">{timeAgo(c.detected_at)}</td>
            </tr>
          ))}</tbody>
        </table>
      ))}
      {tab === "Logs" && <pre className="json logs">{(s.logs || []).join("\n") || "No server output captured."}</pre>}
      {tab === "Config" && <Json value={{ config: s.config, server_info: s.server_info, protocol: s.protocol_version, connection: s.connection, last_discovery: s.last_discovery_summary }} />}
    </Drawer>
  );
}

export default function Servers({ toast, isAdmin, selected }) {
  const servers = usePoll(() => api.get("/v1/servers"), [], 4000);
  const [modal, setModal] = useState(null);
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>MCP servers</h1>
          <p className="muted">Every server Claude can reach goes through Sentinel. Local servers are launched by Sentinel (and can be honeypot-sandboxed first); remote ones are reached over Streamable HTTP or SSE.</p>
        </div>
        {isAdmin && (
          <div className="row gap">
            <button className="btn" onClick={() => setModal("import")}>Import Claude config</button>
            <button className="btn btn-primary" onClick={() => setModal("add")}>＋ Connect server</button>
          </div>
        )}
      </div>
      <ErrorNote error={servers.error} />
      <div className="server-grid">
        {(servers.data || []).map((s) => (
          <button key={s.server_id} className={`server-card ${s.trust_status}`} onClick={() => routeTo(`/servers/${s.server_id}`)}>
            <div className="row between">
              <strong>{s.server_name}</strong>
              <Pill value={s.trust_status} />
            </div>
            <div className="mono small muted truncate">{s.endpoint}</div>
            <div className="row gap wrap small">
              <span className="chip">{s.transport}</span>
              <span>{s.tool_count} tools</span>
              {s.tools_at_risk > 0 && <span className="danger-text">{s.tools_at_risk} at risk</span>}
              {s.findings.filter((f) => ["HIGH", "CRITICAL", "MEDIUM"].includes(f.severity)).length > 0 && <span className="warn-text">{s.findings.length} findings</span>}
              {s.sandbox_classification && <Pill value={s.sandbox_classification} />}
            </div>
            <div className="row between small muted">
              <span>{s.connection?.connected ? "● connected" : s.discovery_status === "ERROR" ? "⚠ unreachable" : "○ idle"}</span>
              <span>scanned {timeAgo(s.last_discovery_time)}</span>
            </div>
          </button>
        ))}
        {servers.data && servers.data.length === 0 && <Empty>No servers yet — connect one.</Empty>}
      </div>
      {modal === "add" && <AddServerModal onClose={() => setModal(null)} onDone={servers.reload} toast={toast} />}
      {modal === "import" && <ImportModal onClose={() => setModal(null)} onDone={servers.reload} toast={toast} />}
      {selected && <ServerDetail serverId={selected} onClose={() => routeTo("/servers")} toast={toast} isAdmin={isAdmin} />}
    </div>
  );
}
