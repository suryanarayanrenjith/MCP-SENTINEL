import { useEffect, useMemo, useState, useCallback } from "react";
import { getDemoAdminToken, getJson, postJson, putJson } from "./api.js";

const VIEWS = ["Dashboard", "Servers", "Tools", "Workflows", "Risk", "Leases", "Sandbox", "MFA", "Integrations"];

/* ── Add Server Modal ──────────────────────────────────────── */
function AddServerModal({ onClose, onAdded, token, setToken }) {
  const [form, setForm] = useState({
    server_name: "",
    endpoint: "",
    publisher: "",
    version: "1.0.0",
    transport: "http",
    capabilities: ["READ"],
    description: "",
    run_sandbox: true,
    auth_scheme: "none",
    auth_audience: "",
    auth_scopes: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);

  const capOptions = ["READ", "WRITE", "EXTERNAL_LOOKUP", "SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL"];

  function toggleCap(cap) {
    setForm((f) => ({
      ...f,
      capabilities: f.capabilities.includes(cap)
        ? f.capabilities.filter((c) => c !== cap)
        : [...f.capabilities, cap],
    }));
  }

  async function submit(e) {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await postJson("/v1/servers", {
        ...form,
        auth_scopes: form.auth_scopes.split(",").map((scope) => scope.trim()).filter(Boolean),
      }, token);
      setResult(res);
      if (res.server_id) onAdded();
    } catch (err) {
      setResult({ error: err.message });
    }
    setSubmitting(false);
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>🖥️ Register New MCP Server</h2>
        {!result ? (
          <form onSubmit={submit}>
            <div className="form-row">
              <div className="form-group">
                <label>Server Name *</label>
                <input className="input" required value={form.server_name}
                  onChange={(e) => setForm({ ...form, server_name: e.target.value })}
                  placeholder="e.g. GitHub MCP Server" />
              </div>
              <div className="form-group">
                <label>Publisher</label>
                <input className="input" value={form.publisher}
                  onChange={(e) => setForm({ ...form, publisher: e.target.value })}
                  placeholder="e.g. github.com" />
              </div>
            </div>
            <div className="form-group full">
              <label>Sentinel admin bearer token *</label>
              <input className="input" type="password" required value={token}
                onChange={(e) => setToken(e.target.value)} placeholder="SECURITY_ADMIN or SYSTEM_ADMIN token" autoComplete="off" />
              <small className="field-help">Used only to authorize registration with Sentinel. Never stored in the server record.</small>
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>Server authentication (declared)</label>
                <select value={form.auth_scheme} onChange={(e) => setForm({ ...form, auth_scheme: e.target.value })}>
                  <option value="none">None</option><option value="bearer">Bearer token</option>
                  <option value="oauth2">OAuth 2.0</option><option value="mtls">Mutual TLS</option>
                </select>
              </div>
              <div className="form-group">
                <label>Auth audience</label>
                <input className="input" value={form.auth_audience}
                  onChange={(e) => setForm({ ...form, auth_audience: e.target.value })} placeholder="Optional resource/audience" />
              </div>
            </div>
            <div className="form-group full">
              <label>Requested scopes (comma separated)</label>
              <input className="input" value={form.auth_scopes}
                onChange={(e) => setForm({ ...form, auth_scopes: e.target.value })} placeholder="tools:read, files:read" />
              <small className="field-help">Sentinel records these declared requirements. It does not store target credentials or proxy them yet.</small>
            </div>
            <div className="form-row">
              <div className="form-group full">
                <label>{form.transport === "stdio" ? "Command / endpoint *" : "Endpoint URL *"}</label>
                <input className="input" required value={form.endpoint}
                  onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
                  placeholder={form.transport === "stdio" ? "Recorded command (not launched by Sentinel)" : "e.g. http://localhost:9001/mcp"} />
              </div>
            </div>
            <p className="field-help">The current gateway invokes HTTP servers using /tools/invoke. stdio/SSE values can be recorded, but this gateway does not launch stdio processes or connect using SSE.</p>
            <div className="form-row">
              <div className="form-group">
                <label>Version</label>
                <input className="input" value={form.version}
                  onChange={(e) => setForm({ ...form, version: e.target.value })} />
              </div>
              <div className="form-group">
                <label>Transport</label>
                <select value={form.transport} onChange={(e) => setForm({ ...form, transport: e.target.value })}>
                  <option value="http">HTTP</option>
                  <option value="stdio">stdio</option>
                  <option value="sse">SSE</option>
                </select>
              </div>
            </div>
            <div className="form-group full" style={{ marginBottom: 14 }}>
              <label>Requested Capabilities</label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {capOptions.map((cap) => (
                  <label key={cap} className="checkbox-row">
                    <input type="checkbox" checked={form.capabilities.includes(cap)}
                      onChange={() => toggleCap(cap)} />
                    <span className="mono">{cap}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="form-group full" style={{ marginBottom: 14 }}>
              <label>Description</label>
              <textarea className="input" rows={2} value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Brief description of what this MCP server provides..." />
            </div>
            <label className="checkbox-row">
              <input type="checkbox" checked={form.run_sandbox}
                onChange={(e) => setForm({ ...form, run_sandbox: e.target.checked })} />
              Run declared-behavior sandbox probe on registration
            </label>
            <p className="field-help">This evaluates a synthetic policy profile. It does not connect to or execute the remote MCP server.</p>
            <div className="modal-actions">
              <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={submitting || !token.trim()}>
                {submitting ? "Registering..." : "Register Server"}
              </button>
            </div>
          </form>
        ) : (
          <div>
            {result.error ? (
              <div className="err">Error: {result.error}</div>
            ) : (
              <>
                <p style={{ marginBottom: 12, color: "var(--green-300)" }}>
                  ✅ {result.message}
                </p>
                <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                  <div className="stat-card" style={{ flex: 1 }}>
                    <div className="label">Server ID</div>
                    <div className="mono" style={{ color: "var(--green-400)" }}>{result.server_id}</div>
                  </div>
                  <div className="stat-card" style={{ flex: 1 }}>
                    <div className="label">Trust Status</div>
                    <span className={`pill ${result.trust_status}`}>{result.trust_status}</span>
                  </div>
                  <div className="stat-card" style={{ flex: 1 }}>
                    <div className="label">Risk State</div>
                    <span className={`pill ${result.risk_state}`}>{result.risk_state}</span>
                  </div>
                </div>
                {result.sandbox && (
                  <div className="sandbox-panel">
                    <h3>🧪 Sandbox Verification Result</h3>
                    <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
                      <span className={`pill ${result.sandbox.classification}`}>
                        {result.sandbox.classification}
                      </span>
                      <span className="mono">Risk: {result.sandbox.risk_score}</span>
                    </div>
                    {result.sandbox.anomalies?.length > 0 && (
                      <ul style={{ paddingLeft: 18, marginBottom: 10 }}>
                        {result.sandbox.anomalies.map((a, i) => (
                          <li key={i} style={{ color: "var(--danger)", fontSize: 12, marginBottom: 4 }}>{a}</li>
                        ))}
                      </ul>
                    )}
                    <pre>{JSON.stringify(result.sandbox.evidence, null, 2)}</pre>
                  </div>
                )}
              </>
            )}
            <div className="modal-actions">
              <button className="btn btn-primary" onClick={onClose}>Close</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Main App ──────────────────────────────────────────────── */
export default function App() {
  const [view, setView] = useState("Dashboard");
  const [theme, setTheme] = useState(() => localStorage.getItem("sentinel-theme") || "dark");
  const [summary, setSummary] = useState(null);
  const [servers, setServers] = useState([]);
  const [tools, setTools] = useState([]);
  const [receipts, setReceipts] = useState([]);
  const [leases, setLeases] = useState([]);
  const [events, setEvents] = useState([]);
  const [workflowId, setWorkflowId] = useState("");
  const [workflow, setWorkflow] = useState(null);
  const [token, setToken] = useState("");
  const [tokenBusy, setTokenBusy] = useState(false);
  const [challenge, setChallenge] = useState("");
  const [mfaMsg, setMfaMsg] = useState("");
  const [error, setError] = useState("");
  const [showAddServer, setShowAddServer] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [sandboxForm, setSandboxForm] = useState({ tool_name: "", expected_behavior: "{}", simulated_observed: "" });
  const [sandboxResult, setSandboxResult] = useState(null);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("sentinel-theme", theme);
  }, [theme]);

  const showToast = useCallback((msg, isError = false) => {
    setToast({ msg, isError });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const refresh = useCallback(async () => {
    try {
      setError("");
      const [s, srv, t, r, l, ev] = await Promise.all([
        getJson("/v1/dashboard/summary"),
        getJson("/v1/servers"),
        getJson("/v1/tools"),
        getJson("/v1/receipts"),
        getJson("/v1/leases"),
        getJson("/v1/events"),
      ]);
      setSummary(s);
      setServers(srv);
      setTools(t);
      setReceipts(r);
      setLeases(l);
      setEvents(ev);
      if (r[0] && !workflowId) setWorkflowId(r[0].workflow_id);
    } catch (e) {
      setError(String(e.message || e));
    }
  }, [workflowId]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [refresh]);

  async function loadWorkflow() {
    if (!workflowId) return;
    try {
      setWorkflow(await getJson(`/v1/workflows/${encodeURIComponent(workflowId)}`));
    } catch (e) {
      showToast(`Could not load workflow: ${e.message}`, true);
    }
  }

  async function completeMfa() {
    try {
      const result = await postJson("/v1/mfa/complete", { challenge_id: challenge }, token);
      setMfaMsg(JSON.stringify(result, null, 2));
    } catch (e) {
      showToast(`MFA completion failed: ${e.message}`, true);
    }
  }

  async function verifyServer(serverId) {
    try {
      const res = await postJson(`/v1/servers/${serverId}/verify`, {}, token);
      setVerifyResult({ id: serverId, ...res });
      showToast(`Server ${serverId} verified — ${res.trust_status}`);
      refresh();
    } catch (e) {
      showToast(`Verification failed: ${e.message}`, true);
    }
  }

  async function updateTrust(serverId, status) {
    try {
      await putJson(`/v1/servers/${serverId}/trust`, { trust_status: status }, token);
      showToast(`Trust updated to ${status}`);
      refresh();
    } catch (e) {
      showToast(`Failed: ${e.message}`, true);
    }
  }

  async function mintAdminToken() {
    setTokenBusy(true);
    try {
      const result = await getDemoAdminToken();
      setToken(result.access_token);
      showToast("Demo SECURITY_ADMIN token ready for this session");
    } catch (e) {
      showToast(`Could not mint demo token: ${e.message}`, true);
    } finally {
      setTokenBusy(false);
    }
  }

  async function runSandbox() {
    try {
      let expected;
      try { expected = JSON.parse(sandboxForm.expected_behavior); }
      catch { showToast("Expected behavior must be valid JSON", true); return; }
      let observed = null;
      if (sandboxForm.simulated_observed.trim()) {
        try { observed = JSON.parse(sandboxForm.simulated_observed); }
        catch { showToast("Observed behavior must be valid JSON", true); return; }
      }
      const res = await postJson("/v1/sandbox/probe", {
        tool_name: sandboxForm.tool_name,
        expected_behavior: expected,
        simulated_observed: observed,
      });
      setSandboxResult(res);
    } catch (e) {
      showToast(`Sandbox failed: ${e.message}`, true);
    }
  }

  const selected = useMemo(
    () => receipts.find((x) => x.workflow_id === workflowId) || receipts[0],
    [receipts, workflowId]
  );

  return (
    <>
      <div className="live-bg" />
      <div className="app">
        <nav className="nav">
          <div className="brand">MCP-SENTINEL</div>
          {VIEWS.map((name) => (
            <button key={name} className={view === name ? "active" : ""} onClick={() => setView(name)}>
              {name}
            </button>
          ))}
          <div className="nav-right">
            <span className="pulse" title="Live — auto-refreshes every 5s" />
            <button className="btn btn-sm btn-secondary" onClick={refresh}>↻ Refresh</button>
            <button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}>
              {theme === "dark" ? "☀️" : "🌙"}
            </button>
          </div>
        </nav>

        <main className="main">
          {error && <p className="err">⚠️ Gateway unreachable: {error}. Start the API on :8443.</p>}

          {/* ── Dashboard ────────────────────────────────────── */}
          {view === "Dashboard" && summary && (
            <>
              <h1>Zero-Trust Control Plane</h1>
              <p className="subtitle">Real-time overview of all MCP server security posture, risk signals, and access decisions.</p>
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="label">Total Servers</div>
                  <div className="value">{summary.servers.total}</div>
                  <div className="hint">MCP servers under Sentinel governance</div>
                </div>
                <div className="stat-card">
                  <div className="label">Trusted</div>
                  <div className="value">{summary.servers.trusted}</div>
                  <div className="hint">Registry status is TRUSTED; open server verification details for its evidence</div>
                </div>
                <div className="stat-card warning">
                  <div className="label">Monitored</div>
                  <div className="value">{summary.servers.monitored + summary.servers.restricted}</div>
                  <div className="hint">Servers under elevated observation</div>
                </div>
                <div className="stat-card danger">
                  <div className="label">Quarantined / Blocked</div>
                  <div className="value">{summary.servers.quarantined + summary.servers.blocked}</div>
                  <div className="hint">Servers with detected anomalies — all calls blocked</div>
                </div>
                <div className="stat-card danger">
                  <div className="label">High-Risk Calls</div>
                  <div className="value">{summary.high_risk_calls}</div>
                  <div className="hint">Tool calls with risk score ≥ 60</div>
                </div>
                <div className="stat-card danger">
                  <div className="label">Blocked Calls</div>
                  <div className="value">{summary.blocked_calls}</div>
                  <div className="hint">Calls denied by policy, risk, or data-flow guard</div>
                </div>
                <div className="stat-card mfa">
                  <div className="label">MFA Challenges</div>
                  <div className="value">{summary.mfa_challenges}</div>
                  <div className="hint">Step-up authentication required before access</div>
                </div>
                <div className="stat-card info">
                  <div className="label">Active Leases</div>
                  <div className="value">{summary.active_leases}</div>
                  <div className="hint">Temporary capability grants (TTL-bound)</div>
                </div>
                <div className={`stat-card ${summary.overall_risk >= 60 ? "danger" : summary.overall_risk >= 30 ? "warning" : ""}`}>
                  <div className="label">Overall Risk</div>
                  <div className="value">{summary.overall_risk}</div>
                  <div className="hint">Highest risk score across all recent decisions</div>
                </div>
              </div>
              {receipts.length > 0 && (
                <>
                  <h1>Recent Decisions</h1>
                  <p className="subtitle">Last {Math.min(receipts.length, 10)} authorization decisions from the pipeline.</p>
                  <div className="table-wrapper">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Tool</th><th>Decision</th><th>Risk</th><th>Identity</th><th>Workflow</th><th>Time</th>
                        </tr>
                      </thead>
                      <tbody>
                        {receipts.slice(0, 10).map((r) => (
                          <tr key={r.receipt_id}>
                            <td className="mono">{r.tool}</td>
                            <td><span className={`pill ${r.decision}`}>{r.decision}</span></td>
                            <td className="mono">{r.risk_score}</td>
                            <td className="mono">{r.identity}</td>
                            <td className="mono" style={{ maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis" }}>{r.workflow_id}</td>
                            <td className="mono" style={{ fontSize: 11 }}>{new Date(r.timestamp).toLocaleTimeString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </>
          )}

          {/* ── Servers ──────────────────────────────────────── */}
          {view === "Servers" && (
            <>
              <h1>MCP Server Trust Registry</h1>
              <p className="subtitle">Register servers under an admin identity, review their declared capabilities, and run Sentinel's verification probe before enabling client use.</p>
              <div className="toolbar">
                <button className="btn btn-primary" onClick={() => setShowAddServer(true)}>
                  ➕ Add MCP Server
                </button>
              </div>
              <div className="table-wrapper">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Server</th><th>Publisher</th><th>Version</th><th>Declared Auth</th><th>Trust</th><th>Risk</th><th>Integrity</th><th>Last Verified</th><th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {servers.map((s) => (
                      <tr key={s.server_id}>
                        <td>
                          <strong>{s.server_name}</strong>
                          <div className="reasons">{s.server_id}</div>
                          <div className="mono" style={{ fontSize: 11 }}>{s.endpoint}</div>
                        </td>
                        <td>{s.publisher}</td>
                        <td className="mono">{s.version}</td>
                        <td><span className="pill info">{s.auth_scheme || "none"}</span>{s.auth_scopes?.length > 0 && <div className="reasons">{s.auth_scopes.join(", ")}</div>}</td>
                        <td><span className={`pill ${s.trust_status}`}>{s.trust_status}</span></td>
                        <td><span className={`pill ${s.risk_state === "NORMAL" ? "NORMAL" : s.risk_state === "CRITICAL" ? "CRITICAL" : "SUSPICIOUS"}`}>{s.risk_state}</span></td>
                        <td className="mono" style={{ fontSize: 11 }}>{(s.integrity_hash || "").slice(0, 16)}…</td>
                        <td>{s.last_verification_time ? new Date(s.last_verification_time).toLocaleString() : "—"}</td>
                        <td style={{ whiteSpace: "nowrap" }}>
                          <button className="btn btn-sm btn-primary" onClick={() => verifyServer(s.server_id)} disabled={!token.trim()}>🔍 Verify</button>
                          {" "}
                          {s.trust_status === "QUARANTINED" && (
                            <button className="btn btn-sm btn-secondary" onClick={() => updateTrust(s.server_id, "MONITORED")} disabled={!token.trim()}>Unquarantine</button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {verifyResult && (
                <div className="sandbox-panel" style={{ marginTop: 20 }}>
                  <h3>🧪 Verification Result — {verifyResult.id}</h3>
                  <div style={{ display: "flex", gap: 12, marginBottom: 10 }}>
                    <span className={`pill ${verifyResult.trust_status}`}>{verifyResult.trust_status}</span>
                    <span className={`pill ${verifyResult.sandbox?.classification}`}>{verifyResult.sandbox?.classification}</span>
                    <span className="mono">Risk: {verifyResult.sandbox?.risk_score}</span>
                  </div>
                  <pre>{JSON.stringify(verifyResult.sandbox, null, 2)}</pre>
                </div>
              )}
            </>
          )}

          {/* ── Tools ────────────────────────────────────────── */}
          {view === "Tools" && (
            <>
              <h1>Tool Integrity Registry</h1>
              <p className="subtitle">Every tool is tracked with cryptographic integrity, capability classification, and behavioral baselines.</p>
              <div className="table-wrapper">
                <table className="table">
                  <thead>
                    <tr><th>Tool</th><th>Capability</th><th>Sensitivity</th><th>Trust</th><th>Expected Behavior</th></tr>
                  </thead>
                  <tbody>
                    {tools.map((t) => (
                      <tr key={t.tool_id}>
                        <td>
                          <strong className="mono">{t.tool_name}</strong>
                          <div className="reasons">{t.server_id}</div>
                        </td>
                        <td><span className={`pill ${t.capability}`}>{t.capability}</span></td>
                        <td>{t.sensitivity}</td>
                        <td><span className={`pill ${t.trust_status}`}>{t.trust_status}</span></td>
                        <td className="mono" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }}>
                          {JSON.stringify(t.expected_behavior)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* ── Workflows ────────────────────────────────────── */}
          {view === "Workflows" && (
            <>
              <h1>Workflow Investigation</h1>
              <p className="subtitle">Trace the full sequence of tool calls in any workflow. Each call shows the decision and reasons.</p>
              <div className="toolbar">
                <input className="input" style={{ maxWidth: 300 }} value={workflowId}
                  onChange={(e) => setWorkflowId(e.target.value)} placeholder="Enter workflow_id..." />
                <button className="btn btn-primary" onClick={loadWorkflow}>Load Workflow</button>
              </div>
              {workflow && (
                <>
                  <div className="flow">
                    {workflow.receipts.map((r, i) => (
                      <span key={r.receipt_id} className="flow">
                        <span className="node">
                          {r.tool} <span className={`pill ${r.decision}`}>{r.decision}</span>
                          <span className="mono" style={{ fontSize: 11 }}>({r.risk_score})</span>
                        </span>
                        {i < workflow.receipts.length - 1 && <span className="arrow">→</span>}
                      </span>
                    ))}
                  </div>
                  {workflow.receipts.map((r) => (
                    <div className="card" key={r.receipt_id} style={{ marginBottom: 12 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                        <strong className="mono">{r.tool}</strong>
                        <span className={`pill ${r.decision}`}>{r.decision}</span>
                        <span className="mono">Risk: {r.risk_score}</span>
                      </div>
                      <ul style={{ paddingLeft: 18 }}>
                        {(r.reasons || []).map((x, i) => (
                          <li key={i} className="reasons" style={{ marginBottom: 2 }}>{x}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </>
              )}
            </>
          )}

          {/* ── Risk ─────────────────────────────────────────── */}
          {view === "Risk" && selected && (
            <>
              <h1>Risk Analysis</h1>
              <p className="subtitle">Deep-dive into risk factors for each authorization decision. Every score is explainable.</p>
              <div className="toolbar">
                <select className="input" style={{ maxWidth: 300 }} value={selected.workflow_id}
                  onChange={(e) => setWorkflowId(e.target.value)}>
                  {[...new Set(receipts.map((r) => r.workflow_id))].map((id) => (
                    <option key={id}>{id}</option>
                  ))}
                </select>
              </div>
              {receipts
                .filter((r) => r.workflow_id === selected.workflow_id)
                .map((r) => (
                  <div className="card" key={r.receipt_id} style={{ marginBottom: 14 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                      <strong className="mono">{r.tool}</strong>
                      <span className={`pill ${r.decision}`}>{r.decision}</span>
                      <span className="mono">Score: {r.risk_score}</span>
                    </div>
                    <div className="reasons" style={{ marginBottom: 8 }}>
                      Sequence: {(r.previous_tools || []).join(" → ") || "first call"}
                    </div>
                    <ul style={{ paddingLeft: 18 }}>
                      {(r.reasons || []).map((x, i) => (
                        <li key={i} style={{ fontSize: 13, marginBottom: 3, color: "var(--text-secondary)" }}>{x}</li>
                      ))}
                    </ul>
                  </div>
                ))}
            </>
          )}

          {/* ── Leases ───────────────────────────────────────── */}
          {view === "Leases" && (
            <>
              <h1>Capability Leases</h1>
              <p className="subtitle">Time-limited, workflow-scoped capability grants issued after MFA step-up. Automatically expire.</p>
              <div className="table-wrapper">
                <table className="table">
                  <thead>
                    <tr><th>Capability</th><th>Tool</th><th>State</th><th>Expires</th><th>Revocation</th></tr>
                  </thead>
                  <tbody>
                    {leases.map((l) => (
                      <tr key={l.lease_id}>
                        <td className="mono">{l.capability}</td>
                        <td className="mono">{l.tool_name}</td>
                        <td><span className={`pill ${l.state}`}>{l.state}</span></td>
                        <td className="mono" style={{ fontSize: 12 }}>{new Date(l.expires_at).toLocaleString()}</td>
                        <td className="reasons">{l.revoked_reason || "—"}</td>
                      </tr>
                    ))}
                    {leases.length === 0 && (
                      <tr><td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: 30 }}>No leases issued yet. Leases are created when MFA step-up is completed.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* ── Sandbox ──────────────────────────────────────── */}
          {view === "Sandbox" && (
            <>
              <h1>Sandbox Testing</h1>
              <p className="subtitle">Evaluate a synthetic expected/observed behavior profile against Sentinel’s sandbox policy engine. This does not execute a server or tool.</p>
              <div className="card" style={{ marginBottom: 20 }}>
                <div className="form-row">
                  <div className="form-group">
                    <label>Tool Name</label>
                    <input className="input" value={sandboxForm.tool_name}
                      onChange={(e) => setSandboxForm({ ...sandboxForm, tool_name: e.target.value })}
                      placeholder="e.g. search_logs" />
                  </div>
                  <div className="form-group">
                    <label>Expected Behavior (JSON)</label>
                    <textarea className="input" rows={3} value={sandboxForm.expected_behavior}
                      onChange={(e) => setSandboxForm({ ...sandboxForm, expected_behavior: e.target.value })}
                      placeholder='{"filesystem": ["synthetic/logs"], "network": [], "process_spawn": false, "environment_access": false}' />
                  </div>
                </div>
                <div className="form-group full" style={{ marginBottom: 14 }}>
                  <label>Simulated Observed Behavior (JSON, optional — leave blank for clean test)</label>
                  <textarea className="input" rows={3} value={sandboxForm.simulated_observed}
                    onChange={(e) => setSandboxForm({ ...sandboxForm, simulated_observed: e.target.value })}
                    placeholder='{"filesystem": ["synthetic/logs", "/etc/environ"], "network": ["unknown.example"], "process_spawn": true, "environment_access": true}' />
                </div>
                <button className="btn btn-primary" onClick={runSandbox} disabled={!sandboxForm.tool_name}>
                  🧪 Run Sandbox Probe
                </button>
              </div>
              {sandboxResult && (
                <div className="sandbox-panel">
                  <h3>Probe Result</h3>
                  <div style={{ display: "flex", gap: 12, marginBottom: 14, flexWrap: "wrap" }}>
                    <span className={`pill ${sandboxResult.classification}`}>{sandboxResult.classification}</span>
                    <span className="mono">Risk Score: {sandboxResult.risk_score}</span>
                    <span className="mono">Isolated: {sandboxResult.isolated ? "Yes" : "No"}</span>
                  </div>
                  {sandboxResult.anomalies?.length > 0 && (
                    <>
                      <strong style={{ fontSize: 13, color: "var(--danger)" }}>⚠️ Anomalies Detected:</strong>
                      <ul style={{ paddingLeft: 18, marginTop: 6, marginBottom: 14 }}>
                        {sandboxResult.anomalies.map((a, i) => (
                          <li key={i} style={{ color: "var(--danger)", fontSize: 13, marginBottom: 3 }}>{a}</li>
                        ))}
                      </ul>
                    </>
                  )}
                  {sandboxResult.anomalies?.length === 0 && (
                    <p style={{ color: "var(--green-300)", marginBottom: 14 }}>✅ No anomalies detected. Tool behavior matches expected baseline.</p>
                  )}
                  <pre>{JSON.stringify(sandboxResult, null, 2)}</pre>
                </div>
              )}
            </>
          )}

          {/* ── MFA ──────────────────────────────────────────── */}
          {view === "MFA" && (
            <>
              <h1>Step-Up Authentication</h1>
              <p className="subtitle">MFA only increases authentication assurance. After success, Sentinel re-evaluates authorization, risk, and grants a temporary workflow-bound lease.</p>
              <div className="card">
                <div className="form-row">
                  <div className="form-group">
                    <label>Bearer Token (with MFA ACR)</label>
                    <input className="input" placeholder="Paste token with MFA claims..." value={token}
                      onChange={(e) => setToken(e.target.value)} />
                  </div>
                  <div className="form-group">
                    <label>Challenge ID</label>
                    <input className="input" placeholder="From mfa_challenge_id in decision response..." value={challenge}
                      onChange={(e) => setChallenge(e.target.value)} />
                  </div>
                </div>
                <button className="btn btn-primary" onClick={completeMfa}>🔐 Complete MFA Challenge</button>
              </div>
              {mfaMsg && (
                <div className="sandbox-panel" style={{ marginTop: 16 }}>
                  <h3>MFA Result</h3>
                  <pre>{mfaMsg}</pre>
                </div>
              )}
            </>
          )}

          {view === "Integrations" && (
            <>
              <h1>Connect clients and authorize admins</h1>
              <p className="subtitle">Sentinel exposes a REST security gateway. Use it from your MCP host or wrap its endpoints as host tools; this dashboard itself is not an MCP server.</p>
              <div className="card" style={{ marginBottom: 16 }}>
                <h3>Dashboard admin session</h3>
                <p className="field-help">Registration, verification, and trust changes require a SECURITY_ADMIN or SYSTEM_ADMIN bearer token. Demo tokens work only when SENTINEL_AUTH_MODE=demo.</p>
                <div className="form-row" style={{ marginTop: 12 }}>
                  <div className="form-group">
                    <label>Sentinel bearer token</label>
                    <input className="input" type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} placeholder="Not saved after this page session" />
                  </div>
                  <div className="form-group" style={{ justifyContent: "end" }}>
                    <button className="btn btn-secondary" onClick={mintAdminToken} disabled={tokenBusy}>{tokenBusy ? "Requesting…" : "Mint demo SECURITY_ADMIN token"}</button>
                  </div>
                </div>
                <p className="field-help">For production, configure OIDC and paste an administrator token issued by your identity provider. Do not use demo tokens outside local development.</p>
              </div>
              <div className="card" style={{ marginBottom: 16 }}>
                <h3>Claude Desktop</h3>
                <p className="field-help">This repo includes a local stdio adapter at <code>scripts/sentinel_mcp_adapter.py</code>. It exposes Sentinel’s registered tool catalog and sends calls through the REST policy gateway with the user token supplied to the adapter. Use a short-lived user token and keep it out of shared config files.</p>
                <pre>{`POST http://localhost:8443/v1/mcp/tools/call
Authorization: Bearer <user access token>
Content-Type: application/json

{"workflow_id":"claude-session-1","server_id":"server-…","tool_name":"<approved-tool>","arguments":{}}`}</pre>
                <pre>{`{
  "mcpServers": {
    "mcp-sentinel": {
      "command": "python",
      "args": ["<absolute-repo-path>/scripts/sentinel_mcp_adapter.py"],
      "env": {
        "SENTINEL_API_URL": "http://127.0.0.1:8443",
        "SENTINEL_TOKEN": "<short-lived-user-access-token>"
      }
    }
  }
}`}</pre>
                <p className="field-help">Merge this entry into Claude Desktop’s <code>claude_desktop_config.json</code>. Use the absolute Python executable and adapter path. Keep the config private, use a short-lived user token, restart Claude Desktop, and confirm only Sentinel’s registered tools appear.</p>
              </div>
              <div className="card" style={{ marginBottom: 16 }}>
                <h3>OpenAI</h3>
                <p className="field-help">For an application using OpenAI tool calling, define a function for each allowed Sentinel tool. Your application backend must execute the function by POSTing to Sentinel’s gateway with a user access token, then return the gateway decision and output to the model. Never put service credentials in browser code or model context.</p>
                <pre>{`POST http://localhost:8443/v1/mcp/tools/call
Authorization: Bearer <user access token>
Content-Type: application/json

{"workflow_id":"openai-session-1","server_id":"server-…","tool_name":"<approved-tool>","arguments":{}}`}</pre>
                <p className="field-help">Treat ALLOW/MONITOR/BLOCK/MFA_REQUIRED as authoritative; only surface tool output when Sentinel returns it. See <code>docs/llm-integration.md</code> for setup, function schema, and security details.</p>
              </div>
              <div className="card">
                <h3>What registration and verification mean</h3>
                <p className="field-help">A successful registration stores the endpoint, declared transport/auth metadata, and requested capability list with initial MONITORED trust. The optional probe scores a synthetic policy profile; Verify runs that same type of probe and updates trust based on its classification. Neither action currently authenticates to the remote MCP endpoint, fetches its tool catalog, or executes its tools.</p>
                <p className="field-help">Declared auth scheme, audience, and scopes are metadata only. Target credentials are not stored, and the current gateway does not forward target credentials. Use an independently authenticated adapter/proxy until target credential handling is implemented.</p>
              </div>
            </>
          )}
        </main>
      </div>

      {/* Modals */}
      {showAddServer && (
        <AddServerModal token={token} setToken={setToken} onClose={() => setShowAddServer(false)} onAdded={() => { refresh(); showToast("Server registered!"); }} />
      )}

      {/* Toast */}
      {toast && (
        <div className={`toast ${toast.isError ? "error" : ""}`}>
          {toast.isError ? "❌" : "✅"} {toast.msg}
        </div>
      )}
    </>
  );
}
