from __future__ import annotations

from typing import Any

from identity.tokens import mint_demo_token
from sentinel.catalog import SOC_SERVER_ID
from sentinel.config import get_settings

INTENT = "Investigate suspicious activity from 10.10.20.30."


def headers(role: str = "SOC_ANALYST", mfa: bool = False, subject: str = "user-123") -> dict[str, str]:
    s = get_settings()
    token = mint_demo_token(s, subject=subject, roles=[role], acr=s.mfa_acr if mfa else None, amr=["otp"] if mfa else ["pwd"])
    return {"Authorization": f"Bearer {token}"}


def call(client, workflow: str, tool: str, arguments: dict[str, Any], hdrs: dict[str, str], **extra: Any) -> dict[str, Any]:
    body = {
        "workflow_id": workflow,
        "server_id": extra.pop("server_id", SOC_SERVER_ID),
        "tool_name": tool,
        "arguments": arguments,
        "user_intent": extra.pop("user_intent", INTENT),
        "agent_id": "soc-agent",
        **extra,
    }
    resp = client.post("/v1/mcp/tools/call", headers=hdrs, json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()
