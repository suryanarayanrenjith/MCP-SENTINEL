"""Database initialisation.

MCP-Sentinel ships with an empty registry: every MCP server is added by the user (dashboard,
API, or ``mcp-sentinel import-claude``).
"""

from __future__ import annotations

from sentinel.db import ServerRow, init_db, session_scope


def reset_interrupted_registrations() -> None:
    with session_scope() as session:
        for row in session.query(ServerRow).filter(ServerRow.discovery_status == "REGISTERING").all():
            row.discovery_status = "NEVER"
        session.commit()


def seed() -> None:
    """Create tables (and add new columns to older databases)."""
    init_db()
    reset_interrupted_registrations()


if __name__ == "__main__":
    seed()
