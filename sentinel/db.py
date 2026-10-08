from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterator

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from sentinel.config import get_settings
from sentinel.types import utcnow

log = logging.getLogger("sentinel.db")


class Base(DeclarativeBase):
    pass


class ServerRow(Base):
    __tablename__ = "servers"

    server_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    server_name: Mapped[str] = mapped_column(String(256))
    publisher: Mapped[str] = mapped_column(String(256))
    version: Mapped[str] = mapped_column(String(64))
    endpoint: Mapped[str] = mapped_column(String(512))
    transport: Mapped[str] = mapped_column(String(32), default="http")
    trust_status: Mapped[str] = mapped_column(String(32), default="MONITORED")
    registration_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approved_capabilities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    integrity_hash: Mapped[str] = mapped_column(String(128), default="")
    last_verification_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_state: Mapped[str] = mapped_column(String(32), default="MONITOR")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # --- live upstream connection / discovery -------------------------------------------------
    slug: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=True)
    managed: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)  # Sentinel connects to it
    config_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True, default="")
    server_info: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=dict)
    pinned_server_info: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=dict)
    last_discovery_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    discovery_status: Mapped[str | None] = mapped_column(String(32), nullable=True, default="NEVER")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True, default="")
    findings: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True, default=list)


class ToolRow(Base):
    __tablename__ = "tools"

    tool_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(128), index=True)
    tool_name: Mapped[str] = mapped_column(String(256), index=True)
    version: Mapped[str] = mapped_column(String(64))
    schema_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    capabilities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    annotations: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    expected_behavior: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    integrity_hash: Mapped[str] = mapped_column(String(128))
    sensitivity: Mapped[str] = mapped_column(String(32))
    trust_status: Mapped[str] = mapped_column(String(32), default="MONITORED")
    implementation_fingerprint: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    resource: Mapped[str] = mapped_column(String(256), default="")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # --- TOFU pinning / rug-pull detection ----------------------------------------------------
    title: Mapped[str | None] = mapped_column(String(256), nullable=True, default="")
    exposed_name: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    live_definition: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=dict)
    live_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, default="")
    approved_definition: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=dict)
    approved_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, default="")
    scan_findings: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True, default=list)
    inference: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=dict)
    flow_roles: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True, default=list)
    review_state: Mapped[str | None] = mapped_column(String(32), nullable=True, default="APPROVED")
    removed: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    profile_locked: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    baseline: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=dict)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=utcnow)
    last_change_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default="")


class ReceiptRow(Base):
    __tablename__ = "receipts"

    receipt_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(String(128), index=True)
    identity: Mapped[str] = mapped_column(String(256))
    agent: Mapped[str] = mapped_column(String(256))
    server: Mapped[str] = mapped_column(String(128))
    tool: Mapped[str] = mapped_column(String(256))
    decision: Mapped[str] = mapped_column(String(32), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)
    previous_tools: Mapped[list[Any]] = mapped_column(JSON, default=list)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    # --- tamper-evident hash chain -------------------------------------------------------------
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True, unique=True, index=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, default="")
    receipt_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, default="")
    signature: Mapped[str | None] = mapped_column(Text, nullable=True, default="")


class LeaseRow(Base):
    __tablename__ = "leases"

    lease_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(String(128), index=True)
    subject: Mapped[str] = mapped_column(String(256))
    capability: Mapped[str] = mapped_column(String(64))
    tool_name: Mapped[str] = mapped_column(String(256))
    state: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_reason: Mapped[str] = mapped_column(String(512), default="")
    server_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default="")
    scope_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, default="")


class ApprovalRow(Base):
    __tablename__ = "approvals"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(String(128), index=True)
    tool_name: Mapped[str] = mapped_column(String(256))
    subject: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32), default="PENDING")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolver: Mapped[str] = mapped_column(String(256), default="")
    request_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    server_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default="")
    request_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, default="", index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    reasons: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)


class EventRow(Base):
    __tablename__ = "security_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class WorkflowCallRow(Base):
    __tablename__ = "workflow_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workflow_id: Mapped[str] = mapped_column(String(128), index=True)
    tool_name: Mapped[str] = mapped_column(String(256))
    capability: Mapped[str] = mapped_column(String(64))
    resource: Mapped[str] = mapped_column(String(256), default="")
    destination: Mapped[str] = mapped_column(String(512), default="")
    data_class: Mapped[str] = mapped_column(String(32), default="INTERNAL")
    allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    server_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default="")
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True, default="")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    flow_roles: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True, default=list)
    subject: Mapped[str | None] = mapped_column(String(256), nullable=True, default="")


class ToolChangeRow(Base):
    """A detected change of a tool definition relative to its pinned (approved) version."""

    __tablename__ = "tool_changes"

    change_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tool_id: Mapped[str] = mapped_column(String(256), index=True)
    server_id: Mapped[str] = mapped_column(String(128), index=True)
    tool_name: Mapped[str] = mapped_column(String(256))
    change_type: Mapped[str] = mapped_column(String(32), default="MODIFIED")  # ADDED / MODIFIED / REMOVED
    classification: Mapped[str] = mapped_column(String(32))
    score: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    diff: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    old_definition: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    new_definition: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    resolved_by: Mapped[str] = mapped_column(String(256), default="")
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MfaEnrollmentRow(Base):
    __tablename__ = "mfa_enrollments"

    subject: Mapped[str] = mapped_column(String(256), primary_key=True)
    secret_encrypted: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_step: Mapped[int] = mapped_column(Integer, default=0)  # replay protection


class PolicyRuleRow(Base):
    __tablename__ = "policy_rules"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    match: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    effect: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuntimeFlagRow(Base):
    __tablename__ = "runtime_flags"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(256), default="")


class VulnScanRow(Base):
    """A vulnerability scan report (SecureMCP-style) for a registered server or an ad-hoc target."""

    __tablename__ = "vuln_scans"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    server_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    target: Mapped[str] = mapped_column(String(512), default="")
    name: Mapped[str] = mapped_column(String(256), default="")
    transport: Mapped[str] = mapped_column(String(16), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    grade: Mapped[str] = mapped_column(String(2), default="")
    worst: Mapped[str] = mapped_column(String(16), default="NONE")
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    created_by: Mapped[str] = mapped_column(String(256), default="")


_engine = None
_Session = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        is_sqlite = settings.database_url.startswith("sqlite")
        connect_args = {"check_same_thread": False, "timeout": 30} if is_sqlite else {}
        _engine = create_engine(settings.database_url, future=True, connect_args=connect_args, pool_pre_ping=True)
        if is_sqlite:

            @event.listens_for(_engine, "connect")
            def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
                cursor = dbapi_connection.cursor()
                # WAL lets background discovery/monitor threads write while API requests read.
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.close()

    return _engine


def get_session_factory():
    global _Session
    if _Session is None:
        _Session = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _Session


@contextmanager
def session_scope() -> Iterator[Session]:
    """Short-lived session for background jobs (never share sessions across threads)."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def _literal_default(column) -> str | None:
    default = column.default
    if default is None or not getattr(default, "is_scalar", False):
        return None
    value = default.arg
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return None


def _auto_migrate(engine) -> None:
    """Additive schema migration: add columns introduced after a database was first created."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            present = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present:
                    continue
                col_type = column.type.compile(dialect=engine.dialect)
                ddl = f'ALTER TABLE {table.name} ADD COLUMN "{column.name}" {col_type}'
                literal = _literal_default(column)
                if literal is not None:
                    ddl += f" DEFAULT {literal}"
                log.info("auto-migrate: %s", ddl)
                conn.execute(text(ddl))


def init_db() -> None:
    engine = get_engine()
    Base.metadata.create_all(engine)
    _auto_migrate(engine)


def reset_engine() -> None:
    global _engine, _Session
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _Session = None
