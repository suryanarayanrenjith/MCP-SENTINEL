from __future__ import annotations

import os

from integrity.crypto import canonical_hash
from integrity.registry import IntegrityRegistry
from sentinel.catalog import SOC_SERVER_ID, default_tools
from sentinel.db import get_session_factory, init_db
from sentinel.types import Capability, TrustStatus


def seed() -> None:
    init_db()
    session = get_session_factory()()
    registry = IntegrityRegistry(session)
    registry.upsert_server(
        {
            "server_id": SOC_SERVER_ID,
            "server_name": "SOC MCP Server",
            "publisher": "mcp-sentinel-lab",
            "version": "1.0.0",
            "endpoint": os.getenv("SENTINEL_SOC_ENDPOINT", "http://localhost:9001/mcp"),
            "transport": "http",
            "trust_status": TrustStatus.TRUSTED.value,
            "approved_capabilities": [c.value for c in Capability],
            "integrity_hash": canonical_hash({"server": SOC_SERVER_ID, "version": "1.0.0"}),
            "risk_state": "NORMAL",
        }
    )
    for tool in default_tools():
        registry.upsert_tool(tool)
    session.close()


if __name__ == "__main__":
    seed()
