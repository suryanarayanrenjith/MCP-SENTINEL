import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, mintDemoToken, safeStorage, setApiToken, usePoll } from "./api.js";
import { RiskWaterfall } from "./components/charts.jsx";
import { Drawer, Json, Meter, Pill } from "./components/ui.jsx";
import { routeTo, timeAgo } from "./format.js";
import Alerts from "./views/Alerts.jsx";
import Approvals, { ApprovalPage } from "./views/Approvals.jsx";
import Audit, { Leases } from "./views/Audit.jsx";
import Connect from "./views/Connect.jsx";
import Integrity from "./views/Integrity.jsx";
import Overview from "./views/Overview.jsx";
import Policy from "./views/Policy.jsx";
import Sandbox from "./views/Sandbox.jsx";
import Scanner from "./views/Scanner.jsx";
import Servers from "./views/Servers.jsx";
import Tools from "./views/Tools.jsx";
import Workflows from "./views/Workflows.jsx";

const NAV = [
  ["overview", "Overview", "◈"],
  ["servers", "Servers", "▤"],
  ["tools", "Tools", "⚙"],
  ["integrity", "Rug pulls", "⚠"],
  ["approvals", "Approvals", "✋"],
  ["sandbox", "Sandbox", "⧉"],
  ["alerts", "Alerts", "🔔"],
  ["workflows", "Workflows", "⇢"],
  ["audit", "Audit", "≣"],
  ["leases", "Leases", "⏱"],
  ["policy", "Policy", "⚖"],
  ["scanner", "Scanner", "⌕"],
  ["connect", "Connect", "⚡"],
];

function useHashRoute() {
  const parse = () => (window.location.hash.replace(/^#\/?/, "") || "overview").split("/").map((p) => decodeURIComponent(p));
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const onChange = () => setRoute(parse());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

function useSession() {
  const storage = safeStorage();
  const [token, setTokenState] = useState(() => {
    const t = (storage && storage.getItem("sentinel-token")) || "";
    setApiToken(t);
    return t;
  });
  const [identity, setIdentity] = useState(null);
  const [info, setInfo] = useState(null);
  const [error, setError] = useState("");

  const setToken = useCallback((t) => {
    setApiToken(t);
    try {
      if (storage) storage.setItem("sentinel-token", t || "");
    } catch {
      /* storage unavailable: keep the token in memory only */
    }
    setTokenState(t || "");
  }, [storage]);

  const switchTo = useCallback(async (subject, role) => {
    const res = await mintDemoToken(subject, role);
    setToken(res.access_token);
  }, [setToken]);

  useEffect(() => {
    api.get("/v1/integrations/info").then(setInfo).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!info) return;
    if (!token && info.auth_mode === "demo") {
      switchTo("local-user", "SECURITY_ADMIN").catch((e) => setError(`demo sign-in failed: ${e.message}`));
      return;
    }
    if (!token) return;
    api.get("/v1/auth/whoami")
      .then((id) => { setIdentity(id); setError(""); })
      .catch((e) => {
        if (e.status === 401 && info.auth_mode === "demo") switchTo(identity?.subject || "local-user", "SECURITY_ADMIN").catch(() => {});
        else setError(e.message);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, info]);

  const roles = identity?.roles || [];
  return {
    token,
    identity,
    authMode: info?.auth_mode || "demo",
    dashboardInfo: info,
    isAdmin: roles.includes("SECURITY_ADMIN") || roles.includes("SYSTEM_ADMIN"),
    setToken,
    switchTo,
    error,
  };
}

function ReceiptDrawer({ receipt, onClose }) {
  const ex = receipt.payload?.explainability || {};
  return (
    <Drawer title={`Receipt ${receipt.receipt_id.slice(0, 8)}`} onClose={onClose}>
      <div className="row gap wrap">
        <span className="mono">{receipt.tool}</span>
        <Pill value={receipt.decision} kind="decision" />
        <Meter value={receipt.risk_score} width={140} />
        <span className="muted small">seq {receipt.seq} · {timeAgo(receipt.timestamp)}</span>
      </div>
      <dl className="kv">
        <dt>Identity</dt><dd>{receipt.identity} via <span className="mono">{receipt.agent}</span></dd>
        <dt>Policy</dt><dd className="mono">{receipt.payload?.policy_id}</dd>
        <dt>Likelihood × impact</dt><dd>{ex.likelihood !== undefined ? `${Math.round(ex.likelihood * 100)}% × ${ex.impact}` : "—"}</dd>
        <dt>Workflow</dt><dd className="mono small">{receipt.workflow_id} · prior: {(receipt.previous_tools || []).join(" → ") || "first call"}</dd>
        {receipt.payload?.restrictions?.length > 0 && <><dt>Restrictions</dt><dd>{receipt.payload.restrictions.join(", ")}</dd></>}
        <dt>Ledger hash</dt><dd className="mono tiny">{receipt.receipt_hash}</dd>
      </dl>
      <h4>Why</h4>
      <ul className="plain">{(receipt.reasons || []).map((r, i) => <li key={i}>• {r}</li>)}</ul>
      <h4>Risk factors</h4>
      <RiskWaterfall factors={ex.risk_factors} total={receipt.risk_score} />
      <h4>Gates</h4>
      <div className="gates">{(ex.gates || []).map((g, i) => <span key={i} className={`gate ${g.status}`} title={g.detail}>{g.status === "pass" ? "✓" : g.status === "warn" ? "!" : "✕"} {g.gate}</span>)}</div>
      <h4>Arguments (redacted)</h4>
      <Json value={receipt.payload?.arguments_preview} />
    </Drawer>
  );
}

function InboxPopup({ inbox, onDismiss }) {
  const items = [...(inbox?.mfa || []), ...(inbox?.approvals || [])];
  if (items.length === 0) return null;
  return (
    <div className="inbox-popup" role="alert">
      <div className="row between"><strong>⚠ {items.length} action{items.length > 1 ? "s" : ""} waiting for you</strong><button className="icon-btn" onClick={onDismiss} aria-label="Dismiss">✕</button></div>
      {items.slice(0, 3).map((it) => {
        const id = it.challenge_id || it.approval_id;
        return (
          <button key={id} className="inbox-pop-item" onClick={() => routeTo(`/approve/${it.kind}/${id}`)}>
            <span>{it.kind === "mfa" ? "🔐" : "✋"} <span className="mono">{it.exposed_name || it.tool_name}</span></span>
            <span className="small muted">risk {it.risk_score} · {it.subject}</span>
          </button>
        );
      })}
    </div>
  );
}

export default function App() {
  const route = useHashRoute();
  const session = useSession();
  const [theme, setTheme] = useState(() => {
    try {
      return window.localStorage.getItem("sentinel-theme") || "dark";
    } catch {
      return "dark";
    }
  });
  const [toastMsg, setToastMsg] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [popupHidden, setPopupHidden] = useState(false);
  const seen = useRef(new Set());
  const summary = usePoll(() => api.get("/v1/dashboard/summary"), [session.token], 3000);
  const inbox = usePoll(() => (session.token ? api.get("/v1/inbox") : Promise.resolve(null)), [session.token], 2000);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      window.localStorage.setItem("sentinel-theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  const toast = useCallback((msg, isError = false) => {
    setToastMsg({ msg, isError });
    setTimeout(() => setToastMsg(null), 4500);
  }, []);

  useEffect(() => {
    const items = [...(inbox.data?.mfa || []), ...(inbox.data?.approvals || [])];
    for (const it of items) {
      const id = it.challenge_id || it.approval_id;
      if (seen.current.has(id)) continue;
      seen.current.add(id);
      setPopupHidden(false);
      const text = `${it.kind === "mfa" ? "Step-up" : "Approval"} needed: ${it.exposed_name || it.tool_name} (risk ${it.risk_score})`;
      toast(text);
      try {
        if (window.Notification && Notification.permission === "granted") new Notification("MCP-Sentinel", { body: text });
      } catch {
        /* notifications unavailable */
      }
    }
  }, [inbox.data, toast]);

  const page = route[0];
  const sub = route.slice(1).join("/") || null;
  const pendingCount = inbox.data?.count || 0;
  const s = summary.data;

  const content = useMemo(() => {
    const common = { toast, isAdmin: session.isAdmin };
    switch (page) {
      case "servers": return <Servers {...common} selected={sub} />;
      case "tools": return <Tools {...common} selected={sub} />;
      case "integrity": return <Integrity {...common} selected={sub} />;
      case "approvals": return <Approvals inbox={inbox.data} />;
      case "approve": return <ApprovalPage kind={route[1]} id={route[2]} session={session} toast={toast} />;
      case "workflows": return <Workflows selected={sub} />;
      case "audit": return <Audit onReceipt={setReceipt} />;
      case "leases": return <Leases {...common} />;
      case "policy": return <Policy {...common} />;
      case "scanner": return <Scanner {...common} />;
      case "sandbox": return <Sandbox {...common} />;
      case "alerts": return <Alerts {...common} />;
      case "connect": return <Connect session={session} toast={toast} />;
      default: return <Overview summary={s} onReceipt={setReceipt} />;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, sub, route, session.isAdmin, session.identity, session.token, s, inbox.data, toast]);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">◆</span>
          <div><div className="brand-name">MCP-SENTINEL</div><div className="brand-sub">zero-trust MCP control plane</div></div>
        </div>
        <nav>
          {NAV.map(([key, label, icon]) => (
            <a key={key} href={`#/${key}`} className={page === key || (key === "approvals" && page === "approve") ? "active" : ""}>
              <span className="nav-icon" aria-hidden="true">{icon}</span>{label}
              {key === "approvals" && pendingCount > 0 && <span className="badge">{pendingCount}</span>}
              {key === "integrity" && s?.rug_pulls > 0 && <span className="badge">{s.rug_pulls}</span>}
            </a>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="small">{session.identity ? <>Signed in as <strong>{session.identity.subject}</strong></> : "Not signed in"}</div>
          <div className="small muted">{session.authMode} mode · {s?.store_backend || "…"} store</div>
          <div className="row gap">
            <button className="btn btn-sm" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>{theme === "dark" ? "Light" : "Dark"} theme</button>
            {window.Notification && Notification.permission === "default" && <button className="btn btn-sm" onClick={() => Notification.requestPermission()}>Notify me</button>}
          </div>
        </div>
      </aside>
      <main className="main">
        {s && s.lockdown && s.lockdown !== "off" && (
          <div className="lockdown-banner">⛔ LOCKDOWN ACTIVE ({s.lockdown.replace("_", " ")}) — <a href="#/policy">manage</a></div>
        )}
        {summary.error && <div className="err">⚠ Control plane unreachable: {summary.error}. Start it with <span className="mono">mcp-sentinel serve</span>.</div>}
        {session.error && <div className="err">⚠ {session.error}</div>}
        {content}
      </main>
      {!popupHidden && page !== "approve" && <InboxPopup inbox={inbox.data} onDismiss={() => setPopupHidden(true)} />}
      {receipt && <ReceiptDrawer receipt={receipt} onClose={() => setReceipt(null)} />}
      {toastMsg && <div className={`toast ${toastMsg.isError ? "error" : ""}`} role="status">{toastMsg.isError ? "✕" : "✓"} {toastMsg.msg}</div>}
    </div>
  );
}
