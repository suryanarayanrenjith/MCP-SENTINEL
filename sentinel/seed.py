from __future__ import annotations

import os

from integrity import scanner
from integrity.capabilities import infer
from integrity.crypto import canonical_hash
from integrity.registry import exposed_name_for
from mcp_servers.soc_definitions import clean_tools
from sentinel.catalog import SOC_SERVER_ID, SOC_SLUG, curated_profile
from sentinel.db import ServerRow, ToolRow, init_db, session_scope
from sentinel.types import Capability, ReviewState, TrustStatus, utcnow


def _seed_tool(server: ServerRow, wire: dict, row: ToolRow | None) -> ToolRow:
    name = wire["name"]
    profile = curated_profile(SOC_SERVER_ID, name) or {}
    raw = infer(wire, server_transport="http")
    scan = scanner.scan_tool(wire, annotation_conflicts=raw.annotation_conflicts)
    wire_hash = canonical_hash(wire)
    if row is None:
        row = ToolRow(
            tool_id=f"{SOC_SERVER_ID}:{name}",
            server_id=SOC_SERVER_ID,
            tool_name=name,
            trust_status=TrustStatus.TRUSTED.value,
            first_seen=utcnow(),
        )
    row.version = "1.0.0"
    row.description = wire["description"]
    row.schema_json = wire["inputSchema"]
    row.annotations = wire.get("annotations") or {}
    row.title = wire.get("title") or ""
    row.capabilities = profile.get("capabilities") or [c.value for c in raw.capabilities]
    row.sensitivity = profile.get("sensitivity") or raw.sensitivity.value
    row.resource = profile.get("resource") or raw.resource
    row.expected_behavior = profile.get("expected_behavior") or {}
    row.integrity_hash = wire_hash
    row.implementation_fingerprint = canonical_hash({"name": name, "version": "1.0.0"})
    row.live_definition = wire
    row.live_hash = wire_hash
    row.approved_definition = wire
    row.approved_hash = wire_hash
    row.review_state = ReviewState.APPROVED.value
    row.removed = False
    row.profile_locked = True
    inference = raw.as_dict()
    inference["locked"] = {k: profile.get(k) for k in ("capabilities", "sensitivity", "resource")}
    inference["capabilities"] = row.capabilities
    inference["sensitivity"] = row.sensitivity
    row.inference = inference
    row.flow_roles = inference["flow_roles"]
    row.scan_findings = [f.as_dict() for f in scan.findings]
    row.exposed_name = exposed_name_for(server.slug or SOC_SLUG, name)
    row.last_seen = utcnow()
    return row


def seed() -> None:
    init_db()
    endpoint = os.getenv("SENTINEL_SOC_ENDPOINT", "http://localhost:9001/mcp")
    with session_scope() as session:
        server = session.get(ServerRow, SOC_SERVER_ID)
        if server is None:
            server = ServerRow(
                server_id=SOC_SERVER_ID,
                server_name="SOC MCP Server (lab)",
                publisher="mcp-sentinel-lab",
                version="1.0.0",
                endpoint=endpoint,
                transport="http",
                trust_status=TrustStatus.TRUSTED.value,
                approved_capabilities=[c.value for c in Capability],
                integrity_hash=canonical_hash({"server": SOC_SERVER_ID, "version": "1.0.0"}),
                risk_state="NORMAL",
                metadata_json={
                    "description": "Lab SOC MCP server with a curated, locked capability profile.",
                    "lab": True,
                    "baseline_established": True,
                },
                slug=SOC_SLUG,
                enabled=True,
                managed=True,
                discovery_status="NEVER",
                findings=[],
            )
            session.add(server)
        else:  # upgrade rows written by older versions without touching security state
            server.slug = server.slug or SOC_SLUG
            server.managed = True if server.managed is None else server.managed
            server.enabled = True if server.enabled is None else server.enabled
            server.endpoint = endpoint
            meta = dict(server.metadata_json or {})
            meta.setdefault("baseline_established", True)
            server.metadata_json = meta
        existing = {t.tool_name: t for t in session.query(ToolRow).filter(ToolRow.server_id == SOC_SERVER_ID).all()}
        for wire in clean_tools():
            row = existing.get(wire["name"])
            if row is not None and row.approved_hash:
                continue  # already pinned: never overwrite (a detected rug pull must survive restarts)
            session.add(_seed_tool(server, wire, row))
        session.commit()


if __name__ == "__main__":
    seed()
