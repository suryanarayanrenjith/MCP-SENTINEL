from __future__ import annotations

from integrity.crypto import canonical_hash
from sentinel.types import Capability, Sensitivity, ToolDefinition, TrustStatus

SOC_SERVER_ID = "server-soc-01"


def _tool(
    name: str,
    *,
    capability: Capability,
    sensitivity: Sensitivity,
    resource: str,
    description: str,
    schema: dict,
    expected: dict,
    version: str = "1.0.0",
) -> ToolDefinition:
    payload = {
        "tool_name": name,
        "version": version,
        "schema": schema,
        "capabilities": [capability.value],
        "resource": resource,
        "description": description,
        "expected_behavior": expected,
    }
    return ToolDefinition(
        tool_id=f"{SOC_SERVER_ID}:{name}",
        server_id=SOC_SERVER_ID,
        tool_name=name,
        version=version,
        schema=schema,
        capabilities=[capability],
        annotations={"title": name},
        expected_behavior=expected,
        integrity_hash=canonical_hash(payload),
        sensitivity=sensitivity,
        trust_status=TrustStatus.TRUSTED,
        implementation_fingerprint=canonical_hash({"name": name, "version": version}),
        description=description,
        resource=resource,
    )


def default_tools() -> list[ToolDefinition]:
    return [
        _tool(
            "search_logs",
            capability=Capability.READ,
            sensitivity=Sensitivity.LOW,
            resource="security_logs",
            description="Search security logs for an IP or indicator.",
            schema={
                "type": "object",
                "properties": {"query": {"type": "string"}, "ip": {"type": "string"}},
                "required": ["query"],
            },
            expected={
                "filesystem": ["synthetic/logs"],
                "network": [],
                "process_spawn": False,
                "environment_access": False,
                "secret_access": False,
            },
        ),
        _tool(
            "lookup_ip",
            capability=Capability.EXTERNAL_LOOKUP,
            sensitivity=Sensitivity.LOW,
            resource="threat_intel",
            description="Lookup an IP in threat intelligence.",
            schema={
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
            expected={"filesystem": [], "network": ["intel.internal"], "process_spawn": False},
        ),
        _tool(
            "create_incident",
            capability=Capability.WRITE,
            sensitivity=Sensitivity.MEDIUM,
            resource="incidents",
            description="Create a SOC incident ticket.",
            schema={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "ip": {"type": "string"},
                    "severity": {"type": "string"},
                },
                "required": ["title"],
            },
            expected={"filesystem": [], "network": [], "process_spawn": False},
        ),
        _tool(
            "get_credentials",
            capability=Capability.SECRET_ACCESS,
            sensitivity=Sensitivity.CRITICAL,
            resource="secrets_vault",
            description="Retrieve credentials for a named system.",
            schema={
                "type": "object",
                "properties": {"system": {"type": "string"}},
                "required": ["system"],
            },
            expected={"filesystem": [], "network": [], "secret_access": True, "process_spawn": False},
        ),
        _tool(
            "send_data",
            capability=Capability.DATA_TRANSFER,
            sensitivity=Sensitivity.HIGH,
            resource="data_export",
            description="Send data to an approved destination.",
            schema={
                "type": "object",
                "properties": {
                    "destination": {"type": "string", "format": "uri"},
                    "payload": {"type": "string"},
                },
                "required": ["destination", "payload"],
            },
            expected={"filesystem": [], "network": ["soc.internal"], "process_spawn": False},
        ),
        _tool(
            "isolate_host",
            capability=Capability.INFRASTRUCTURE_CONTROL,
            sensitivity=Sensitivity.CRITICAL,
            resource="edr",
            description="Isolate a host from the network.",
            schema={
                "type": "object",
                "properties": {"hostname": {"type": "string"}},
                "required": ["hostname"],
            },
            expected={"filesystem": [], "network": ["edr.internal"], "process_spawn": False},
        ),
    ]


def catalog_by_name() -> dict[str, ToolDefinition]:
    return {t.tool_name: t for t in default_tools()}
