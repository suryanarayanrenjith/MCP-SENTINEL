from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from sentinel.config import get_settings
from sentinel.types import utcnow


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


_engine = None
_Session = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
        _engine = create_engine(settings.database_url, future=True, connect_args=connect_args)
    return _engine


def get_session_factory():
    global _Session
    if _Session is None:
        _Session = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _Session


def init_db() -> None:
    Base.metadata.create_all(get_engine())


def reset_engine() -> None:
    global _engine, _Session
    _engine = None
    _Session = None
