import { useState } from "react";
import { api, usePoll } from "../api.js";
import { Card, Empty, ErrorNote, Findings, Json, Pill } from "../components/ui.jsx";

export default function Sandbox({ toast, isAdmin }) {
  const servers = usePoll(() => api.get("/v1/servers"), []);
  const [serverId, setServerId] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);
  const [form, setForm] = useState({ tool_name: "search_logs", expected: '{"filesystem": ["synthetic/logs"], "network": [], "process_spawn": false, "environment_access": false}', observed: "" });
  const [probe, setProbe] = useState(null);
  const [error, setError] = useState("");
  const stdio = (servers.data || []).filter((s) => s.transport === "stdio");

  async function runHoneypot() {
    setBusy(true);
    setError("");
    try {
      const res = await api.post(`/v1/servers/${serverId}/sandbox`);
      setReport(res.sandbox);
      toast(`Sandbox: ${res.sandbox.classification}`);
    } catch (e) {
      setError(e.message);
    }
    setBusy(false);
  }

  async function runProbe() {
    setError("");
    try {
      const expected = JSON.parse(form.expected || "{}");
      const observed = form.observed.trim() ? JSON.parse(form.observed) : null;
      setProbe(await api.post("/v1/sandbox/probe", { tool_name: form.tool_name, expected_behavior: expected, simulated_observed: observed }));
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Sandbox</h1>
        <p className="muted">New or changed local servers can be run in a honeypot before they touch real resources: a decoy home directory with canary SSH/AWS/.env/Claude-config credentials, a recording egress proxy that only lets package registries through, and process-tree monitoring.</p>
      </div></div>
      <Card title="Honeypot run" subtitle="Evidence, not permanent trust — results feed the server's trust state">
        {stdio.length === 0 ? <Empty>No local (stdio) servers registered.</Empty> : (
          <div className="row gap">
            <select className="input" value={serverId} onChange={(e) => setServerId(e.target.value)}>
              <option value="">Choose a local server…</option>
              {stdio.map((s) => <option key={s.server_id} value={s.server_id}>{s.server_name}</option>)}
            </select>
            <button className="btn btn-primary" disabled={!serverId || busy || !isAdmin} onClick={runHoneypot}>{busy ? "Running…" : "Run honeypot"}</button>
          </div>
        )}
        {report && (
          <div className="stack">
            <div className="row gap"><Pill value={report.classification} /><span className="muted small">{report.evidence?.duration_s}s · tools: {(report.evidence?.tools_discovered || []).join(", ")}</span></div>
            <Findings items={report.evidence?.findings} />
            <Json value={report.evidence} />
          </div>
        )}
      </Card>
      <Card title="Behaviour profile comparison" subtitle="Compare a declared baseline with observed (or simulated) behaviour — no code is executed">
        <div className="form">
          <label>Tool<input className="input mono" value={form.tool_name} onChange={(e) => setForm({ ...form, tool_name: e.target.value })} /></label>
          <label>Expected behaviour (JSON)<textarea className="input mono" rows={3} value={form.expected} onChange={(e) => setForm({ ...form, expected: e.target.value })} /></label>
          <label>Observed behaviour (JSON, optional)<textarea className="input mono" rows={3} value={form.observed} onChange={(e) => setForm({ ...form, observed: e.target.value })} placeholder='{"filesystem": ["synthetic/logs", "/etc/environ"], "network": ["unknown.example"], "process_spawn": true, "environment_access": true}' /></label>
          <div className="modal-actions"><button className="btn" onClick={runProbe}>Compare</button></div>
        </div>
        {probe && (
          <div className="stack">
            <div className="row gap"><Pill value={probe.classification} /><span>risk {probe.risk_score}</span></div>
            <ul className="plain">{(probe.anomalies || []).map((a, i) => <li key={i} className="danger-text">{a}</li>)}</ul>
          </div>
        )}
      </Card>
      <ErrorNote error={error} />
    </div>
  );
}
