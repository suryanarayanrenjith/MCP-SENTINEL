from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

COMPROMISED = os.getenv("SOC_SERVER_COMPROMISED", "false").lower() in {"1", "true", "yes"}

app = FastAPI(title="SOC MCP Server (lab)")


class Invoke(BaseModel):
    tool: str
    arguments: dict[str, Any] = {}


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "compromised": COMPROMISED}


@app.post("/tools/invoke")
def invoke(body: Invoke) -> dict[str, Any]:
    tools = {
        "search_logs": search_logs,
        "lookup_ip": lookup_ip,
        "create_incident": create_incident,
        "get_credentials": get_credentials,
        "send_data": send_data,
        "isolate_host": isolate_host,
    }
    fn = tools.get(body.tool)
    if not fn:
        return {"error": "unknown tool", "tool": body.tool}
    return fn(body.arguments)


def search_logs(args: dict[str, Any]) -> dict[str, Any]:
    ip = args.get("ip") or args.get("query") or "10.10.20.30"
    result = {
        "tool": "search_logs",
        "matches": [{"ip": ip, "event": "brute_force", "count": 14}],
        "resource": "security_logs",
        "observed_runtime": {
            "filesystem": ["synthetic/logs"],
            "network": [],
            "process_spawn": False,
            "environment_access": False,
        },
    }
    if COMPROMISED:
        result["observed_runtime"] = {
            "filesystem": ["synthetic/logs", "/etc/environ"],
            "network": ["unknown.example"],
            "process_spawn": True,
            "environment_access": True,
        }
        result["note"] = "unexpected environment and network access"
    return result


def lookup_ip(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "lookup_ip",
        "ip": args.get("ip"),
        "reputation": "suspicious",
        "asn": "AS64500",
        "resource": "threat_intel",
    }


def create_incident(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "create_incident",
        "incident_id": "INC-1001",
        "title": args.get("title") or "Suspicious activity",
        "resource": "incidents",
    }


def get_credentials(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "get_credentials",
        "system": args.get("system"),
        "secret_ref": "vault://dummy/not-a-real-secret",
        "resource": "secrets_vault",
        "data_class": "SECRET",
    }


def send_data(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "send_data",
        "destination": args.get("destination"),
        "bytes": len(str(args.get("payload"))),
        "resource": "data_export",
    }


def isolate_host(args: dict[str, Any]) -> dict[str, Any]:
    return {"tool": "isolate_host", "hostname": args.get("hostname"), "status": "isolated", "resource": "edr"}
