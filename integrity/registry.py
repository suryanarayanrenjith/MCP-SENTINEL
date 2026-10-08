from __future__ import annotations

import re as _re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from integrity.crypto import canonical_hash
from integrity.firewall import ChangeReport, SemanticChangeFirewall
from sentinel.db import ServerRow, ToolRow
from sentinel.dlp import strip_invisible
from sentinel.types import Sensitivity, ToolDefinition, TrustStatus


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


# ── helpers shared by discovery, the gateway and the API ─────────────────────────────────────

HIDDEN_FROM_MODEL = {TrustStatus.QUARANTINED.value, TrustStatus.BLOCKED.value}


def slugify(name: str, max_len: int = 20) -> str:
    slug = _re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")
    slug = _re.sub(r"_(mcp|server|mcp_server)$", "", slug) or "server"
    return slug[:max_len].strip("_") or "server"


def unique_slug(session: Session, name: str, exclude_server_id: str | None = None) -> str:
    base = slugify(name)
    taken = {
        (r.slug or "")
        for r in session.query(ServerRow).all()
        if r.server_id != exclude_server_id
    }
    if base not in taken:
        return base
    for i in range(2, 1000):
        candidate = f"{base[:17]}_{i}"
        if candidate not in taken:
            return candidate
    return f"{base[:12]}_{canonical_hash(name)[:6]}"


def exposed_name_for(slug: str, tool_name: str) -> str:
    """Namespaced, client-safe tool name (Claude requires ^[a-zA-Z0-9_-]{1,64}$).

    Always namespacing prevents cross-server shadowing through name collisions.
    """
    clean_tool = _re.sub(r"[^A-Za-z0-9_-]", "_", tool_name) or "tool"
    name = f"{slug}__{clean_tool}"
    if len(name) <= 64:
        return name
    suffix = canonical_hash(tool_name)[:6]
    return f"{slug}__{clean_tool[: 64 - len(slug) - 9]}_{suffix}"


def neutral_description(row: ToolRow, findings: int) -> str:
    return (
        f"[MCP-Sentinel] The original description of '{row.tool_name}' is withheld pending security review "
        f"({findings} finding(s)). Calls are evaluated with elevated caution."
    )


def served_definition(row: ToolRow) -> dict[str, Any]:
    """The definition the *model* sees: the pinned (approved) one, never an unreviewed drift."""
    approved = row.approved_definition or {}
    if approved:
        base = dict(approved)
        base["description"] = strip_invisible(str(base.get("description") or ""))
        return base
    live = dict(row.live_definition or {}) or {
        "name": row.tool_name,
        "description": row.description,
        "inputSchema": row.schema_json or {"type": "object"},
        "annotations": row.annotations or {},
    }
    serious = [f for f in (row.scan_findings or []) if f.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}]
    if serious:
        schema = dict(live.get("inputSchema") or {"type": "object"})
        props = schema.get("properties")
        if isinstance(props, dict):
            schema["properties"] = {
                k: {kk: vv for kk, vv in (v or {}).items() if kk not in {"description", "title", "examples", "default"}}
                if isinstance(v, dict) else v
                for k, v in props.items()
            }
        live["inputSchema"] = schema
        live["description"] = neutral_description(row, len(serious))
    else:
        live["description"] = strip_invisible(str(live.get("description") or ""))
    return live


def is_exposed(row: ToolRow, server: ServerRow | None) -> bool:
    if server is None or row.removed or row.review_state == "REJECTED":
        return False
    if row.trust_status in HIDDEN_FROM_MODEL or server.trust_status in HIDDEN_FROM_MODEL:
        return False
    return server.enabled is not False
