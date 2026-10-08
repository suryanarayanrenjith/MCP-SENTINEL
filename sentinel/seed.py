"""Database initialisation.

MCP-Sentinel ships with an empty registry: every MCP server is added by the user (dashboard,
API, or ``mcp-sentinel import-claude``). Databases created by older versions contained a
built-in lab server; it is removed here so it never shows up in a client again.
"""

from __future__ import annotations

from sentinel.db import ServerRow, ToolChangeRow, ToolRow, init_db, session_scope

LEGACY_LAB_SERVER_IDS = ("server-soc-01",)


def remove_legacy_lab_server() -> int:
    removed = 0
    with session_scope() as session:
        for server_id in LEGACY_LAB_SERVER_IDS:
            row = session.get(ServerRow, server_id)
            if row is None or not (row.metadata_json or {}).get("lab"):
                continue
            session.query(ToolChangeRow).filter(ToolChangeRow.server_id == server_id).delete()
            session.query(ToolRow).filter(ToolRow.server_id == server_id).delete()
            session.delete(row)
            removed += 1
        session.commit()
    return removed


def reset_interrupted_registrations() -> None:
    with session_scope() as session:
        for row in session.query(ServerRow).filter(ServerRow.discovery_status == "REGISTERING").all():
            row.discovery_status = "NEVER"
        session.commit()


def seed() -> None:
    """Create tables (and add new columns to older databases)."""
    init_db()
    remove_legacy_lab_server()
    reset_interrupted_registrations()


if __name__ == "__main__":
    seed()
