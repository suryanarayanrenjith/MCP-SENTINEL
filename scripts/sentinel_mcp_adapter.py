"""Minimal local MCP stdio adapter for Claude Desktop.

The adapter exposes Sentinel's current tool catalog and routes calls through
the identity/policy gateway. It never accepts a server ID from model input.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any


API_URL = os.environ.get("SENTINEL_API_URL", "http://127.0.0.1:8443").rstrip("/")
TOKEN = os.environ.get("SENTINEL_TOKEN", "")
WORKFLOW_ID = os.environ.get("SENTINEL_WORKFLOW_ID", f"claude-{uuid.uuid4().hex[:12]}")


def api_request(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    request = urllib.request.Request(f"{API_URL}{path}", data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Sentinel API returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not contact Sentinel API: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Sentinel API returned an unexpected response")
    return payload


def load_tools() -> list[dict[str, Any]]:
    response = api_request("/v1/mcp/tools/list")
    tools = response.get("tools", [])
    counts: dict[str, int] = {}
    for item in tools:
        counts[item.get("name", "")] = counts.get(item.get("name", ""), 0) + 1

    exposed = []
    for item in tools:
        original_name = str(item.get("name", ""))
        server_id = str(item.get("server_id", ""))
        if not original_name or not server_id:
            continue
        exposed_name = original_name
        if counts.get(original_name, 0) > 1:
            prefix = re.sub(r"[^A-Za-z0-9_-]", "_", server_id)
            exposed_name = f"{prefix}__{original_name}"
        exposed.append({**item, "name": exposed_name, "_original_name": original_name})
    return exposed


def write_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if not method:
        return rpc_error(request_id, -32600, "Invalid JSON-RPC request")
    if method.startswith("notifications/"):
        return None
    params = message.get("params") or {}

    if method == "initialize":
        version = params.get("protocolVersion", "2024-11-05")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mcp-sentinel", "version": "0.1.0"},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        try:
            catalog = load_tools()
        except RuntimeError as exc:
            return rpc_error(request_id, -32000, str(exc))
        public_tools = [
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "inputSchema": tool.get("inputSchema") or {"type": "object", "properties": {}},
            }
            for tool in catalog
        ]
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": public_tools}}
    if method == "tools/call":
        requested = params.get("name")
        try:
            tool = next((item for item in load_tools() if item["name"] == requested), None)
            if tool is None:
                return rpc_error(request_id, -32602, "Tool is not in Sentinel's registered catalog")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                return rpc_error(request_id, -32602, "Tool arguments must be a JSON object")
            result = api_request(
                "/v1/mcp/tools/call",
                {
                    "workflow_id": WORKFLOW_ID,
                    "server_id": tool["server_id"],
                    "tool_name": tool["_original_name"],
                    "arguments": arguments,
                    "user_intent": "MCP client tool call",
                },
            )
        except (RuntimeError, StopIteration) as exc:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"isError": True, "content": [{"type": "text", "text": str(exc)}]},
            }

        executed = (result.get("execution") or {}).get("executed") is True
        allowed = result.get("decision") in {"ALLOW", "MONITOR"}
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "isError": not (allowed and executed),
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
            },
        }
    return rpc_error(request_id, -32601, f"Method not found: {method}")


def main() -> int:
    if not TOKEN:
        print("SENTINEL_TOKEN must contain a user access token", file=sys.stderr)
        return 2
    for line in sys.stdin:
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                response = rpc_error(None, -32600, "Expected a JSON-RPC object")
            else:
                response = handle(message)
        except json.JSONDecodeError:
            response = rpc_error(None, -32700, "Parse error")
        except Exception as exc:  # Keep protocol output clean; diagnostics go to stderr.
            print(f"Adapter error: {exc}", file=sys.stderr)
            response = rpc_error(message.get("id") if isinstance(message, dict) else None, -32603, "Internal adapter error")
        if response is not None:
            write_message(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
