"""Curated (admin-approved) capability profiles for the lab SOC MCP server.

Discovered third-party tools get an *inferred* profile (integrity.capabilities); the lab SOC
server ships with an explicit, locked profile that also records each tool's expected runtime
behaviour (baseline for the runtime behaviour analyzer).
"""

from __future__ import annotations

from typing import Any

from integrity.crypto import canonical_hash
from mcp_servers.soc_definitions import clean_tools
from sentinel.types import Capability, Sensitivity, ToolDefinition, TrustStatus

SOC_SERVER_ID = "server-soc-01"
SOC_SLUG = "soc"

_PROFILES: dict[str, dict[str, Any]] = {
    "search_logs": {
        "capability": Capability.READ,
        "sensitivity": Sensitivity.LOW,
        "resource": "security_logs",
        "expected": {
            "filesystem": ["synthetic/logs"],
            "network": [],
            "process_spawn": False,
            "environment_access": False,
            "secret_access": False,
        },
    },
    "lookup_ip": {
        "capability": Capability.EXTERNAL_LOOKUP,
        "sensitivity": Sensitivity.LOW,
        "resource": "threat_intel",
        "expected": {"filesystem": [], "network": ["intel.internal"], "process_spawn": False},
    },
    "create_incident": {
        "capability": Capability.WRITE,
        "sensitivity": Sensitivity.MEDIUM,
        "resource": "incidents",
        "expected": {"filesystem": [], "network": [], "process_spawn": False},
    },
    "get_credentials": {
        "capability": Capability.SECRET_ACCESS,
        "sensitivity": Sensitivity.CRITICAL,
        "resource": "secrets_vault",
        "expected": {"filesystem": [], "network": [], "secret_access": True, "process_spawn": False},
    },
    "send_data": {
        "capability": Capability.DATA_TRANSFER,
        "sensitivity": Sensitivity.HIGH,
        "resource": "data_export",
        "expected": {"filesystem": [], "network": ["soc.internal"], "process_spawn": False},
    },
    "isolate_host": {
        "capability": Capability.INFRASTRUCTURE_CONTROL,
        "sensitivity": Sensitivity.CRITICAL,
        "resource": "edr",
        "expected": {"filesystem": [], "network": ["edr.internal"], "process_spawn": False},
    },
}


def wire_definitions() -> dict[str, dict[str, Any]]:
    return {t["name"]: t for t in clean_tools()}


def _tool(wire: dict[str, Any]) -> ToolDefinition:
    name = wire["name"]
    profile = _PROFILES[name]
    capability: Capability = profile["capability"]
    payload = {
        "tool_name": name,
        "version": "1.0.0",
        "schema": wire["inputSchema"],
        "capabilities": [capability.value],
        "resource": profile["resource"],
        "description": wire["description"],
        "expected_behavior": profile["expected"],
    }
    return ToolDefinition(
        tool_id=f"{SOC_SERVER_ID}:{name}",
        server_id=SOC_SERVER_ID,
        tool_name=name,
        version="1.0.0",
        schema=wire["inputSchema"],
        capabilities=[capability],
        annotations=wire.get("annotations") or {},
        expected_behavior=profile["expected"],
        integrity_hash=canonical_hash(payload),
        sensitivity=profile["sensitivity"],
        trust_status=TrustStatus.TRUSTED,
        implementation_fingerprint=canonical_hash({"name": name, "version": "1.0.0"}),
        description=wire["description"],
        resource=profile["resource"],
    )


def default_tools() -> list[ToolDefinition]:
    return [_tool(w) for w in clean_tools()]


def catalog_by_name() -> dict[str, ToolDefinition]:
    return {t.tool_name: t for t in default_tools()}


def curated_profile(server_id: str, tool_name: str) -> dict[str, Any] | None:
    if server_id != SOC_SERVER_ID or tool_name not in _PROFILES:
        return None
    p = _PROFILES[tool_name]
    return {
        "capabilities": [p["capability"].value],
        "sensitivity": p["sensitivity"].value,
        "resource": p["resource"],
        "expected_behavior": dict(p["expected"]),
    }
