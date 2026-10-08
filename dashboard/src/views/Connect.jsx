import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { api, usePoll } from "../api.js";
import { Card, CopyButton, ErrorNote, Pill } from "../components/ui.jsx";

function TotpEnrollment({ session, toast }) {
  const status = usePoll(() => (session.token ? api.get("/v1/mfa/totp/status") : Promise.resolve(null)), [session.token]);
  const [enroll, setEnroll] = useState(null);
  const [qr, setQr] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    if (!enroll) return;
    QRCode.toDataURL(enroll.otpauth_uri, { margin: 1, width: 200 }).then(setQr).catch(() => setQr(""));
  }, [enroll]);
  async function start() {
    setError("");
    try {
      setEnroll(await api.post("/v1/mfa/totp/enroll", status.data?.enrolled ? { code } : {}));
      setCode("");
    } catch (e) {
      setError(e.message);
    }
  }
  async function activate() {
    setError("");
    try {
      await api.post("/v1/mfa/totp/activate", { code });
      toast("Authenticator activated — step-ups now require your TOTP code");
      setEnroll(null);
      setCode("");
      status.reload();
    } catch (e) {
      setError(e.message);
    }
  }
  if (!session.token) return <p className="muted">Sign in first.</p>;
  return (
    <div className="stack">
      <p>Status for <strong>{session.identity?.subject}</strong>: {status.data?.enrolled ? <span className="good-text">authenticator active</span> : <span className="warn-text">no authenticator — step-ups fall back to demo confirmation</span>}</p>
      {!enroll && (
        <div className="row gap">
          {status.data?.enrolled && <input className="input otp" placeholder="current code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} maxLength={6} />}
          <button className="btn btn-primary" onClick={start}>{status.data?.enrolled ? "Rotate authenticator" : "Enrol authenticator (TOTP)"}</button>
        </div>
      )}
      {enroll && (
        <div className="totp-enroll">
          {qr && <img src={qr} width={200} height={200} alt="TOTP QR code" />}
          <div className="stack">
            <p className="small">Scan with Google Authenticator, Microsoft Authenticator, 1Password or Authy — or type the secret:</p>
            <div className="row gap"><span className="mono secret">{enroll.secret}</span><CopyButton text={enroll.secret} /></div>
            <div className="row gap">
              <input className="input otp" inputMode="numeric" maxLength={6} placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
              <button className="btn btn-primary" disabled={code.length !== 6} onClick={activate}>Activate</button>
            </div>
          </div>
        </div>
      )}
      <ErrorNote error={error} />
    </div>
  );
}

export default function Connect({ session, toast }) {
  const claude = usePoll(() => api.get("/v1/integrations/claude-desktop"), []);
  const c = claude.data;
  const [subject, setSubject] = useState(session.identity?.subject || "local-user");
  const [role, setRole] = useState("SECURITY_ADMIN");
  const [pasted, setPasted] = useState("");
  const configText = c ? JSON.stringify(c.config, null, 2) : "";
  return (
    <div className="stack">
      <div className="page-head"><div>
        <h1>Connect</h1>
        <p className="muted">Add one MCP server to Claude Desktop — MCP-Sentinel — and every server you connect here appears behind it, risk-gated.</p>
      </div></div>
      <div className="grid-2">
        <Card title="1 · Claude Desktop" subtitle="Settings → Developer → Edit Config, or let the CLI do it">
          {!c ? <ErrorNote error={claude.error || "Loading…"} /> : (
            <div className="stack">
              <div className="row between"><span className="small muted">claude_desktop_config.json</span><CopyButton text={configText} /></div>
              <pre className="json">{configText}</pre>
              <p className="small">Or run (keeps a backup of your config):</p>
              <div className="row gap"><code className="mono small cmd">{c.cli}</code><CopyButton text={c.cli} /></div>
              <p className="small">Move your existing Claude Desktop servers behind Sentinel in one step:</p>
              <div className="row gap"><code className="mono small cmd">{c.import_cli} --replace</code><CopyButton text={`${c.import_cli} --replace`} /></div>
              <ul className="plain small muted">
                {Object.entries(c.config_paths).map(([os, path]) => <li key={os}>{os}: <span className="mono">{path}</span></li>)}
              </ul>
              <ul className="plain small">{c.notes.map((n) => <li key={n}>ⓘ {n}</li>)}</ul>
            </div>
          )}
        </Card>
        <Card title="2 · Other MCP clients" subtitle="Streamable HTTP endpoint (Claude Code, Cursor, VS Code, MCP Inspector)">
          {c && (
            <div className="stack">
              <div className="row gap"><code className="mono small cmd">{c.streamable_http_url}</code><CopyButton text={c.streamable_http_url} /></div>
              <div className="row gap"><code className="mono small cmd">{c.claude_code}</code><CopyButton text={c.claude_code} /></div>
              <p className="small muted">Send <span className="mono">Authorization: Bearer &lt;token&gt;</span>. The endpoint validates Origin (DNS-rebinding defence) and is bound to 127.0.0.1 by default.</p>
            </div>
          )}
        </Card>
      </div>
      <div className="grid-2">
        <Card title="3 · Your identity" subtitle="Roles always come from the token — never from MCP requests">
          <p>Signed in as <strong>{session.identity?.subject || "—"}</strong> {(session.identity?.roles || []).map((r) => <Pill key={r} value={r} />)} {session.identity?.mfa_satisfied && <Pill value="MFA" />}</p>
          {session.authMode === "demo" ? (
            <div className="row gap wrap">
              <input className="input input-sm" value={subject} onChange={(e) => setSubject(e.target.value)} />
              <select className="input input-sm" value={role} onChange={(e) => setRole(e.target.value)}>
                {["USER", "DEVELOPER", "SOC_ANALYST", "SECURITY_ADMIN", "SYSTEM_ADMIN"].map((r) => <option key={r}>{r}</option>)}
              </select>
              <button className="btn btn-sm" onClick={() => session.switchTo(subject, role)}>Use demo identity</button>
              <p className="muted small">Demo mode: Claude Desktop's bridge acts as <span className="mono">local-user</span> by default — sign in as the same subject to approve its step-ups.</p>
            </div>
          ) : (
            <div className="row gap">
              <input className="input mono" type="password" autoComplete="off" placeholder="Paste an access token from your IdP" value={pasted} onChange={(e) => setPasted(e.target.value)} />
              <button className="btn btn-sm" onClick={() => session.setToken(pasted)}>Use token</button>
            </div>
          )}
        </Card>
        <Card title="4 · Step-up authenticator" subtitle="Real RFC 6238 TOTP; codes are single-use (replay-protected)">
          <TotpEnrollment session={session} toast={toast} />
        </Card>
      </div>
    </div>
  );
}
