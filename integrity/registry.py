from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from integrity.crypto import canonical_hash
from integrity.firewall import ChangeReport, SemanticChangeFirewall
from sentinel.db import ServerRow, ToolRow
from sentinel.types import Capability, Sensitivity, ToolDefinition, TrustStatus


class IntegrityRegistry:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.firewall = SemanticChangeFirewall()

    def upsert_server(self, data: dict[str, Any]) -> tuple[ServerRow, ChangeReport | None]:
        existing = self.session.get(ServerRow, data["server_id"])
        integrity = data.get("integrity_hash") or canonical_hash(
            {k: data[k] for k in ("server_id", "publisher", "version", "endpoint") if k in data}
        )
        report = None
        if existing:
            report = self.firewall.compare(
                {
                    "schema": existing.metadata_json,
                    "capabilities": existing.approved_capabilities,
                    "version": existing.version,
                    "resource": existing.server_id,
                    "description": existing.server_name,
                    "sensitivity": Sensitivity.MEDIUM.value,
                },
                {
                    "schema": data.get("metadata_json") or {},
                    "capabilities": data.get("approved_capabilities") or existing.approved_capabilities,
                    "version": data.get("version") or existing.version,
                    "resource": existing.server_id,
                    "description": data.get("server_name") or existing.server_name,
                    "sensitivity": Sensitivity.MEDIUM.value,
                },
            )
            existing.version = data.get("version", existing.version)
            existing.endpoint = data.get("endpoint", existing.endpoint)
            existing.integrity_hash = integrity
            existing.last_verification_time = datetime.now(timezone.utc)
            if report.security_relevant:
                existing.trust_status = report.recommended_status.value
            self.session.add(existing)
            self.session.commit()
            return existing, report
        row = ServerRow(
            server_id=data["server_id"],
            server_name=data["server_name"],
            publisher=data["publisher"],
            version=data["version"],
            endpoint=data["endpoint"],
            transport=data.get("transport", "http"),
            trust_status=data.get("trust_status", TrustStatus.TRUSTED.value),
            approved_capabilities=data.get("approved_capabilities", []),
            integrity_hash=integrity,
            last_verification_time=datetime.now(timezone.utc),
            risk_state=data.get("risk_state", "NORMAL"),
            metadata_json=data.get("metadata_json") or {},
        )
        self.session.add(row)
        self.session.commit()
        return row, None

    def upsert_tool(self, tool: ToolDefinition) -> tuple[ToolRow, ChangeReport | None]:
        existing = self.session.get(ToolRow, tool.tool_id)
        report = None
        if existing:
            old = {
                "schema": existing.schema_json,
                "capabilities": existing.capabilities,
                "version": existing.version,
                "annotations": existing.annotations,
                "resource": existing.resource,
                "description": existing.description,
                "sensitivity": existing.sensitivity,
                "network": (existing.expected_behavior or {}).get("network", []),
            }
            new = {
                "schema": tool.schema,
                "capabilities": [c.value for c in tool.capabilities],
                "version": tool.version,
                "annotations": tool.annotations,
                "resource": tool.resource,
                "description": tool.description,
                "sensitivity": tool.sensitivity.value,
                "network": (tool.expected_behavior or {}).get("network", []),
            }
            report = self.firewall.compare(old, new)
            existing.schema_json = tool.schema
            existing.capabilities = [c.value for c in tool.capabilities]
            existing.version = tool.version
            existing.annotations = tool.annotations
            existing.expected_behavior = tool.expected_behavior
            existing.integrity_hash = tool.integrity_hash
            existing.sensitivity = tool.sensitivity.value
            existing.implementation_fingerprint = tool.implementation_fingerprint
            existing.description = tool.description
            existing.resource = tool.resource
            existing.last_seen = datetime.now(timezone.utc)
            if report.security_relevant:
                existing.trust_status = report.recommended_status.value
            self.session.add(existing)
            self.session.commit()
            return existing, report
        row = ToolRow(
            tool_id=tool.tool_id,
            server_id=tool.server_id,
            tool_name=tool.tool_name,
            version=tool.version,
            schema_json=tool.schema,
            capabilities=[c.value for c in tool.capabilities],
            annotations=tool.annotations,
            expected_behavior=tool.expected_behavior,
            integrity_hash=tool.integrity_hash,
            sensitivity=tool.sensitivity.value,
            trust_status=tool.trust_status.value,
            implementation_fingerprint=tool.implementation_fingerprint,
            description=tool.description,
            resource=tool.resource,
        )
        self.session.add(row)
        self.session.commit()
        return row, None

    def get_server(self, server_id: str) -> ServerRow | None:
        return self.session.get(ServerRow, server_id)

    def get_tool(self, server_id: str, tool_name: str) -> ToolRow | None:
        return (
            self.session.query(ToolRow)
            .filter(ToolRow.server_id == server_id, ToolRow.tool_name == tool_name)
            .one_or_none()
        )

    def set_server_status(self, server_id: str, status: TrustStatus) -> None:
        row = self.get_server(server_id)
        if row:
            row.trust_status = status.value
            self.session.add(row)
            self.session.commit()

    def set_tool_status(self, tool_id: str, status: TrustStatus) -> None:
        row = self.session.get(ToolRow, tool_id)
        if row:
            row.trust_status = status.value
            self.session.add(row)
            self.session.commit()

    def verify_level1_crypto(self, tool: ToolRow, presented: dict[str, Any]) -> bool:
        return tool.integrity_hash == canonical_hash(presented) or tool.integrity_hash == presented.get(
            "integrity_hash"
        )

    def verify_level2_structural(self, tool: ToolRow, presented: dict[str, Any]) -> list[str]:
        issues = []
        if presented.get("schema") and presented["schema"] != tool.schema_json:
            issues.append("schema mismatch")
        if presented.get("version") and presented["version"] != tool.version:
            issues.append("version mismatch")
        if presented.get("capabilities") and set(presented["capabilities"]) != set(tool.capabilities):
            issues.append("capability mismatch")
        return issues
