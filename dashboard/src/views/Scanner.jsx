import { useState } from "react";
import { api, fetchFile, usePoll } from "../api.js";
import { Card, Empty, ErrorNote, Findings, Pill, Tabs } from "../components/ui.jsx";
import { timeAgo } from "../format.js";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function GradeBadge({ scan, size = "" }) {
  if (!scan || !scan.grade) return <span className="grade-badge none" title="not scanned yet">–</span>;
  return <span className={`grade-badge ${scan.grade} ${size}`} title={`security grade ${scan.grade} (${scan.score ?? scan.summary?.score}/100)`}>{scan.grade}</span>;
}

function Report({ scan }) {
  const [tab, setTab] = useState("Findings");
  if (!scan) return <Empty>Run a scan or pick one from the history to see its report.</Empty>;
  const r = scan.report || {};
  const s = r.summary || scan.summary || {};
  const vulns = r.vulnerabilities || [];
  return (
    <div className="stack">
      <div className="report-head">
        <GradeBadge scan={{ grade: s.grade, score: s.score }} size="lg" />
        <div className="report-meta">
          <div className="report-title">{scan.name || r.target}</div>
          <div className="muted small mono break">{r.target}</div>
          <div className="muted small">{r.transport} · {r.active ? "active + passive" : "passive"} scan · {timeAgo(scan.created_at)} · {r.duration_s}s · {s.score}/100</div>
        </div>
        <div className="row gap wrap report-actions">
          <button className="btn btn-sm" onClick={() => fetchFile(`/v1/scans/${scan.scan_id}/report.html`, { open: true })}>Open report</button>
          <button className="btn btn-sm" onClick={() => fetchFile(`/v1/scans/${scan.scan_id}/report.html?download=1`, { filename: `mcp-scan-${scan.scan_id.slice(0, 8)}.html` })}>HTML</button>
          <button className="btn btn-sm" onClick={() => fetchFile(`/v1/scans/${scan.scan_id}/report.json`, { filename: `mcp-scan-${scan.scan_id.slice(0, 8)}.json` })}>JSON</button>
        </div>
      </div>
      <div className="sev-tiles">
        {SEVERITIES.map((k) => (
          <div key={k} className={`sev-tile ${k}`}><b>{s[`${k.toLowerCase()}_count`] ?? 0}</b><span>{k.toLowerCase()}</span></div>
        ))}
      </div>
      <Tabs tabs={["Findings", "Checks", "Inventory"]} value={tab} onChange={setTab} />
      {tab === "Findings" && (vulns.length === 0 ? <Empty>No vulnerabilities found by the checks that ran.</Empty> : (
        <ul className="vulns">
          {vulns.map((v, i) => (
            <li key={i} className={`vuln ${v.severity}`}>
              <div className="row gap wrap"><Pill value={v.severity} /><strong className="grow">{v.title}</strong><span className="mono small muted">{v.id}</span></div>
              <div className="muted small">{v.type} · {v.location}</div>
              <p>{v.description}</p>
              {v.evidence && <div className="mono small evidence">{v.evidence}</div>}
              <p className="small"><strong>Fix:</strong> {v.remediation}</p>
            </li>
          ))}
        </ul>
      ))}
      {tab === "Checks" && (
        <table className="table">
          <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>{(r.checks || []).map((c, i) => <tr key={i}><td>{c.check}</td><td><Pill value={c.status === "done" ? "ACTIVE" : c.status.toUpperCase()} title={c.status} /></td><td className="small">{c.detail}</td></tr>)}</tbody>
        </table>
      )}
      {tab === "Inventory" && (
        <div className="stack small">
          <div><strong>Server:</strong> <span className="mono">{JSON.stringify(r.server_info?.serverInfo || {})}</span> · protocol {r.server_info?.protocolVersion || "?"}</div>
          <div><strong>Tools ({r.inventory?.tools ?? 0}):</strong> <span className="mono">{(r.inventory?.tool_names || []).join(", ")}</span></div>
          <div><strong>Prompts:</strong> {r.inventory?.prompts ?? 0} · <strong>Resources:</strong> {r.inventory?.resources ?? 0}</div>
          {r.inventory?.active_probe && <div><strong>Active probes:</strong> {r.inventory.active_probe.payloads.join(", ")} → {r.inventory.active_probe.probed_tools.join(", ") || "no read-only tool qualified"}</div>}
          {r.inventory?.honeypot && <div><strong>Honeypot:</strong> <Pill value={r.inventory.honeypot.classification} /> ({r.inventory.honeypot.duration_s}s)</div>}
        </div>
      )}
      {(r.errors || []).length > 0 && <ErrorNote error={r.errors.join(" · ")} />}
    </div>
  );
}

function AdhocForm({ onDone, toast, isAdmin }) {
  const [form, setForm] = useState({ kind: "url", endpoint: "", transport: "http", command: "", args: "", bearer: "", active: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = form.kind === "url"
        ? { transport: form.transport, endpoint: form.endpoint.trim(), bearer_token: form.bearer, active: form.active }
        : { transport: "stdio", command: form.command.trim(), args: form.args.split("\n").map((a) => a.trim()).filter(Boolean), active: form.active };
      const res = await api.post("/v1/scans", body);
      toast(`Scan finished: grade ${res.grade}`);
      onDone(res);
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }
  return (
    <form className="form" onSubmit={submit}>
      <div className="row gap">
        <label className="checkbox-row"><input type="radio" checked={form.kind === "url"} onChange={() => set("kind", "url")} /> Remote URL</label>
        <label className="checkbox-row"><input type="radio" checked={form.kind === "cmd"} onChange={() => set("kind", "cmd")} /> Local command (stdio)</label>
      </div>
      {form.kind === "url" ? (
        <>
          <label>URL<input className="input mono" required value={form.endpoint} onChange={(e) => set("endpoint", e.target.value)} placeholder="https://example.com/mcp" /></label>
          <div className="row gap">
            <label className="grow">Transport<select className="input" value={form.transport} onChange={(e) => set("transport", e.target.value)}><option value="http">Streamable HTTP</option><option value="sse">SSE (legacy)</option></select></label>
            <label className="grow">Bearer token <span className="muted small">(optional; analysed, never stored)</span><input className="input mono" type="password" autoComplete="off" value={form.bearer} onChange={(e) => set("bearer", e.target.value)} /></label>
          </div>
        </>
      ) : (
        <>
          <label>Command<input className="input mono" required value={form.command} onChange={(e) => set("command", e.target.value)} placeholder="npx" /></label>
          <label>Arguments <span className="muted small">(one per line)</span><textarea className="input mono" rows={2} value={form.args} onChange={(e) => set("args", e.target.value)} placeholder={"-y\n@modelcontextprotocol/server-memory@2026.8.31"} /></label>
        </>
      )}
      <label className="checkbox-row"><input type="checkbox" checked={form.active} onChange={(e) => set("active", e.target.checked)} /> Active probes: send injection payloads to read-only tools{form.kind === "cmd" ? " (runs inside the honeypot sandbox)" : ""}</label>
      <ErrorNote error={error} />
      <div className="modal-actions"><button className="btn btn-primary" disabled={busy || !isAdmin}>{busy ? "Scanning…" : "Scan"}</button></div>
    </form>
  );
}

export default function Scanner({ toast, isAdmin }) {
  const servers = usePoll(() => api.get("/v1/servers"), [], 15000);
  const history = usePoll(() => api.get("/v1/scans?limit=30"), [], 15000);
  const [current, setCurrent] = useState(null);
  const [busy, setBusy] = useState("");
  const [honeypot, setHoneypot] = useState(null);
  const [error, setError] = useState("");

  async function scanServer(s, active) {
    setBusy(`${s.server_id}:${active ? "active" : "passive"}`);
    setError("");
    try {
      const res = await api.post(`/v1/servers/${s.server_id}/scan`, { active });
      setCurrent(res);
      toast(`${s.server_name}: grade ${res.grade}`);
      servers.reload();
      history.reload();
    } catch (e) {
      setError(e.message);
    }
    setBusy("");
  }
  async function runHoneypot(s) {
    setBusy(`${s.server_id}:honeypot`);
    setError("");
    try {
      const res = await api.post(`/v1/servers/${s.server_id}/sandbox`);
      setHoneypot({ name: s.server_name, ...res.sandbox });
      toast(`Honeypot: ${res.sandbox.classification}`);
      servers.reload();
    } catch (e) {
      setError(e.message);
    }
    setBusy("");
  }
  async function openScan(id) {
    try {
      setCurrent(await api.get(`/v1/scans/${id}`));
    } catch (e) {
      setError(e.message);
    }
  }

  const list = servers.data || [];
  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Vulnerability scanner</h1>
        <p className="muted">A Python port of SecureMCP, extended to the MCP protocol: OAuth and token analysis, authentication and server-integrity probes (TLS, auth bypass, Origin / DNS-rebinding, CORS, session ids), and prompt-injection testing of tools, prompts and resources. Active probes send SecureMCP's five payload types to read-only tools only; for local servers they run inside the honeypot.</p>
      </div></div>
      <ErrorNote error={error} />
      <div className="grid-2">
        <Card title="Your servers" subtitle="Every server is scanned passively when it is added">
          {list.length === 0 ? <Empty>No servers yet. Add one under Servers.</Empty> : (
            <table className="table">
              <thead><tr><th>Grade</th><th>Server</th><th>Last scan</th><th /></tr></thead>
              <tbody>
                {list.map((s) => (
                  <tr key={s.server_id}>
                    <td><button type="button" className="link-btn" disabled={!s.vuln_scan} onClick={() => s.vuln_scan && openScan(s.vuln_scan.scan_id)}><GradeBadge scan={s.vuln_scan} /></button></td>
                    <td><strong>{s.server_name}</strong><div className="muted small">{s.transport}{s.vuln_scan?.worst && s.vuln_scan.worst !== "NONE" ? ` · worst: ${s.vuln_scan.worst.toLowerCase()}` : ""}</div></td>
                    <td className="small muted">{s.vuln_scan ? timeAgo(s.vuln_scan.at) : "never"}</td>
                    <td>
                      <div className="row gap wrap right">
                        <button className="btn btn-sm" disabled={!!busy || !isAdmin} onClick={() => scanServer(s, false)}>{busy === `${s.server_id}:passive` ? "Scanning…" : "Scan"}</button>
                        <button className="btn btn-sm" disabled={!!busy || !isAdmin} onClick={() => scanServer(s, true)} title="also sends injection payloads to read-only tools">{busy === `${s.server_id}:active` ? "Probing…" : "Active"}</button>
                        {s.transport === "stdio" && <button className="btn btn-sm" disabled={!!busy || !isAdmin} onClick={() => runHoneypot(s)}>{busy === `${s.server_id}:honeypot` ? "Running…" : "Honeypot"}</button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Scan a server without adding it" subtitle="Like `mcp-sentinel scan <url | -- command>`">
          <AdhocForm onDone={(res) => { setCurrent(res); history.reload(); }} toast={toast} isAdmin={isAdmin} />
        </Card>
      </div>
      {honeypot && (
        <Card title={`Honeypot run · ${honeypot.name}`} subtitle="Decoy HOME with canary credentials, registry-only egress proxy, process monitoring" actions={<button className="btn btn-sm" onClick={() => setHoneypot(null)}>Close</button>}>
          <div className="row gap"><Pill value={honeypot.classification} /><span className="muted small">{honeypot.evidence?.duration_s}s · tools: {(honeypot.evidence?.tools_discovered || []).join(", ")}</span></div>
          <Findings items={honeypot.evidence?.findings} />
        </Card>
      )}
      <Card title="Report"><Report scan={current} /></Card>
      <Card title="Scan history">
        {(history.data || []).length === 0 ? <Empty>No scans yet.</Empty> : (
          <table className="table">
            <thead><tr><th>Grade</th><th>Target</th><th>Findings</th><th>Mode</th><th>When</th></tr></thead>
            <tbody>
              {history.data.map((h) => (
                <tr key={h.scan_id} className="clickable" onClick={() => openScan(h.scan_id)}>
                  <td><GradeBadge scan={h} /></td>
                  <td><strong>{h.name}</strong><div className="muted small mono">{h.target}</div></td>
                  <td className="small">{h.summary.critical_count} critical · {h.summary.high_count} high · {h.summary.medium_count} medium · {h.summary.low_count} low</td>
                  <td className="small">{h.active ? "active" : "passive"}</td>
                  <td className="small muted">{timeAgo(h.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
