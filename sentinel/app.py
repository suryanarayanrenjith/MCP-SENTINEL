from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from identity.tokens import mint_demo_token
from integrity.crypto import canonical_hash
from integrity.registry import IntegrityRegistry
from identity.verifier import IdentityError
from sandbox.manager import SandboxManager
from sentinel.catalog import SOC_SERVER_ID
from sentinel.config import Settings, get_settings
from sentinel.db import (
    ApprovalRow,
    EventRow,
    LeaseRow,
    ReceiptRow,
    ServerRow,
    ToolRow,
    WorkflowCallRow,
    get_session_factory,
    init_db,
)
from sentinel.logging import configure_logging
from sentinel.pipeline import ControlPlane
from sentinel.seed import seed
from sentinel.store import StateStore
from sentinel.types import Capability, ToolCallRequest, TrustStatus

store = StateStore()


def db_session() -> Session:
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    init_db()
    seed()
    global store
    store = StateStore(settings.redis_url)
    yield


app = FastAPI(
    title="MCP-Sentinel",
    description="Adaptive Zero-Trust Security Control Plane for Model Context Protocol",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CallBody(BaseModel):
    workflow_id: str
    server_id: str = SOC_SERVER_ID
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_intent: str = ""
    agent_id: str | None = None
    destination: str | None = None
    resource: str | None = None
    observed_runtime: dict[str, Any] | None = None


class MfaCompleteBody(BaseModel):
    challenge_id: str


class ApprovalBody(BaseModel):
    approval_id: str
    decision: str


def plane(session: Session = Depends(db_session), settings: Settings = Depends(get_settings)) -> ControlPlane:
    return ControlPlane(session, store, settings)


def require_admin(cp: ControlPlane, authorization: str | None):
    try:
        identity = cp.identity.verify(authorization)
    except IdentityError as exc:
        raise HTTPException(401, exc.message) from exc
    if "SECURITY_ADMIN" not in identity.roles and "SYSTEM_ADMIN" not in identity.roles:
        raise HTTPException(403, "operation requires SECURITY_ADMIN")
    return identity


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "component": "mcp-sentinel"}


@app.post("/v1/demo/token")
def demo_token(
    role: str = "SOC_ANALYST",
    subject: str = "user-123",
    mfa: bool = False,
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    if settings.auth_mode != "demo":
        raise HTTPException(403, "demo tokens disabled")
    token = mint_demo_token(
        settings,
        subject=subject,
        roles=[role],
        acr=settings.mfa_acr if mfa else None,
        amr=["pwd", "otp"] if mfa else ["pwd"],
    )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/v1/mcp/tools/call")
async def tools_call(
    body: CallBody,
    request: Request,
    cp: ControlPlane = Depends(plane),
    authorization: str | None = Header(default=None),
    session: Session = Depends(db_session),
) -> dict[str, Any]:
    req = ToolCallRequest(**body.model_dump())
    decision, identity = cp.authorize(authorization, req)
    result: dict[str, Any] = {
        "decision": decision.decision.value,
        "risk_score": decision.risk.score,
        "state": decision.risk.band.value,
        "reasons": decision.reasons,
        "factors": [f.model_dump() for f in decision.risk.factors],
        "receipt_id": decision.receipt_id,
        "policy_id": decision.policy_id,
        "lease_id": decision.lease_id,
        "mfa_challenge_id": decision.mfa_challenge_id,
        "explainability": decision.explainability,
    }
    if decision.decision.value not in {"ALLOW", "MONITOR"}:
        return result
    server = session.get(ServerRow, body.server_id)
    if not server:
        raise HTTPException(404, "server missing")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            proxied = await client.post(
                server.endpoint.replace("/mcp", "/tools/invoke"),
                json={"tool": body.tool_name, "arguments": body.arguments},
            )
            proxied.raise_for_status()
            payload = proxied.json()
    except (httpx.HTTPError, ValueError) as exc:
        result["execution"] = {
            "executed": False,
            "error": str(exc),
            "note": "Sentinel could not obtain a valid response from the configured server. No successful tool output is reported.",
        }
        return result
    issues = cp.inspect_output(payload)
    result["execution"] = {"executed": True}
    result["output"] = payload
    result["output_issues"] = issues
    result["note"] = "Tool output is untrusted and never authorizes a later high-risk action."
    return result


@app.post("/v1/mfa/complete")
def mfa_complete(
    body: MfaCompleteBody,
    authorization: str | None = Header(default=None),
    cp: ControlPlane = Depends(plane),
) -> dict[str, Any]:
    identity = cp.identity.verify(authorization)
    try:
        challenge = cp.mfa.complete(body.challenge_id, identity)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    lease = cp.leases.grant(
        workflow_id=challenge.workflow_id,
        subject=identity.subject,
        capability=Capability(challenge.capability),
        tool_name=challenge.tool_name,
    )
    return {
        "status": "mfa_satisfied",
        "challenge_id": challenge.challenge_id,
        "lease_id": lease.lease_id,
        "note": "MFA increased assurance only. Re-run the tool call; Sentinel will re-evaluate policy and risk.",
    }


@app.get("/v1/dashboard/summary")
def dashboard_summary(session: Session = Depends(db_session)) -> dict[str, Any]:
    servers = session.query(ServerRow).all()
    counts: dict[str, int] = {}
    for s in servers:
        counts[s.trust_status] = counts.get(s.trust_status, 0) + 1
    receipts = session.query(ReceiptRow).all()
    high = sum(1 for r in receipts if r.risk_score >= 60)
    blocked = sum(1 for r in receipts if r.decision == "BLOCK")
    mfa = sum(1 for r in receipts if r.decision == "MFA_REQUIRED")
    leases = session.query(LeaseRow).filter(LeaseRow.state.in_(["ACTIVE", "EXPIRING"])).count()
    anomalies = session.query(EventRow).filter(EventRow.event_type == "decision").count()
    overall = max((r.risk_score for r in receipts), default=0)
    return {
        "servers": {
            "total": len(servers),
            "trusted": counts.get("TRUSTED", 0),
            "monitored": counts.get("MONITORED", 0),
            "restricted": counts.get("RESTRICTED", 0),
            "quarantined": counts.get("QUARANTINED", 0),
            "blocked": counts.get("BLOCKED", 0),
        },
        "high_risk_calls": high,
        "blocked_calls": blocked,
        "mfa_challenges": mfa,
        "active_leases": leases,
        "events": anomalies,
        "overall_risk": overall,
    }


@app.get("/v1/servers")
def list_servers(session: Session = Depends(db_session)) -> list[dict[str, Any]]:
    rows = session.query(ServerRow).all()
    return [
        {
            "server_id": r.server_id,
            "server_name": r.server_name,
            "publisher": r.publisher,
            "version": r.version,
            "trust_status": r.trust_status,
            "risk_state": r.risk_state,
            "last_verification_time": r.last_verification_time.isoformat() if r.last_verification_time else None,
            "approved_capabilities": r.approved_capabilities,
            "integrity_hash": r.integrity_hash,
            "endpoint": r.endpoint,
            "transport": r.transport,
            "auth_scheme": (r.metadata_json or {}).get("auth_scheme", "none"),
            "auth_audience": (r.metadata_json or {}).get("auth_audience", ""),
            "auth_scopes": (r.metadata_json or {}).get("auth_scopes", []),
            "description": (r.metadata_json or {}).get("description", ""),
        }
        for r in rows
    ]


@app.get("/v1/tools")
def list_tools(session: Session = Depends(db_session)) -> list[dict[str, Any]]:
    rows = session.query(ToolRow).all()
    return [
        {
            "tool_id": r.tool_id,
            "tool_name": r.tool_name,
            "server_id": r.server_id,
            "capability": (r.capabilities or [None])[0],
            "sensitivity": r.sensitivity,
            "integrity_hash": r.integrity_hash,
            "trust_status": r.trust_status,
            "expected_behavior": r.expected_behavior,
            "resource": r.resource,
            "version": r.version,
        }
        for r in rows
    ]


@app.get("/v1/workflows/{workflow_id}")
def workflow_view(workflow_id: str, session: Session = Depends(db_session)) -> dict[str, Any]:
    calls = (
        session.query(WorkflowCallRow)
        .filter(WorkflowCallRow.workflow_id == workflow_id)
        .order_by(WorkflowCallRow.id.asc())
        .all()
    )
    receipts = (
        session.query(ReceiptRow)
        .filter(ReceiptRow.workflow_id == workflow_id)
        .order_by(ReceiptRow.timestamp.asc())
        .all()
    )
    return {
        "workflow_id": workflow_id,
        "calls": [
            {
                "tool": c.tool_name,
                "capability": c.capability,
                "resource": c.resource,
                "destination": c.destination,
                "allowed": c.allowed,
            }
            for c in calls
        ],
        "receipts": [
            {
                "tool": r.tool,
                "decision": r.decision,
                "risk_score": r.risk_score,
                "reasons": r.reasons,
                "receipt_id": r.receipt_id,
            }
            for r in receipts
        ],
    }


@app.get("/v1/receipts")
def list_receipts(session: Session = Depends(db_session), limit: int = 100) -> list[dict[str, Any]]:
    rows = session.query(ReceiptRow).order_by(ReceiptRow.timestamp.desc()).limit(limit).all()
    return [
        {
            "receipt_id": r.receipt_id,
            "workflow_id": r.workflow_id,
            "identity": r.identity,
            "agent": r.agent,
            "server": r.server,
            "tool": r.tool,
            "decision": r.decision,
            "risk_score": r.risk_score,
            "state": r.state,
            "reasons": r.reasons,
            "previous_tools": r.previous_tools,
            "timestamp": r.timestamp.isoformat(),
            "payload": r.payload,
        }
        for r in rows
    ]


@app.get("/v1/leases")
def list_leases(session: Session = Depends(db_session)) -> list[dict[str, Any]]:
    rows = session.query(LeaseRow).order_by(LeaseRow.created_at.desc()).all()
    return [
        {
            "lease_id": r.lease_id,
            "workflow_id": r.workflow_id,
            "capability": r.capability,
            "tool_name": r.tool_name,
            "state": r.state,
            "expires_at": r.expires_at.isoformat(),
            "revoked_reason": r.revoked_reason,
        }
        for r in rows
    ]


@app.get("/v1/events")
def list_events(session: Session = Depends(db_session), limit: int = 100) -> list[dict[str, Any]]:
    rows = session.query(EventRow).order_by(EventRow.timestamp.desc()).limit(limit).all()
    return [
        {
            "event_id": r.event_id,
            "event_type": r.event_type,
            "severity": r.severity,
            "message": r.message,
            "details": r.details,
            "timestamp": r.timestamp.isoformat(),
        }
        for r in rows
    ]


@app.post("/v1/approvals")
def create_or_resolve_approval(
    body: ApprovalBody,
    session: Session = Depends(db_session),
    authorization: str | None = Header(default=None),
    cp: ControlPlane = Depends(plane),
) -> dict[str, Any]:
    identity = cp.identity.verify(authorization)
    if "SECURITY_ADMIN" not in identity.roles and "SYSTEM_ADMIN" not in identity.roles:
        raise HTTPException(403, "human approval requires SECURITY_ADMIN")
    row = session.get(ApprovalRow, body.approval_id)
    if not row:
        raise HTTPException(404, "approval not found")
    row.status = body.decision.upper()
    row.resolver = identity.subject
    session.add(row)
    session.commit()
    return {"approval_id": row.approval_id, "status": row.status}


@app.get("/v1/mcp/tools/list")
def tools_list(session: Session = Depends(db_session)) -> dict[str, Any]:
    tools = session.query(ToolRow).all()
    return {
        "tools": [
            {
                "name": t.tool_name,
                "description": t.description,
                "inputSchema": t.schema_json,
                "server_id": t.server_id,
                "sentinel": {
                    "capabilities": t.capabilities,
                    "sensitivity": t.sensitivity,
                    "trust_status": t.trust_status,
                },
            }
            for t in tools
        ]
    }


# ── New endpoints for dashboard server management ──────────────────────


class RegisterServerBody(BaseModel):
    server_name: str
    endpoint: str
    publisher: str = ""
    version: str = "1.0.0"
    transport: str = "http"
    capabilities: list[str] = Field(default_factory=lambda: ["READ"])
    description: str = ""
    run_sandbox: bool = True
    auth_scheme: str = "none"
    auth_audience: str = ""
    auth_scopes: list[str] = Field(default_factory=list)


class UpdateTrustBody(BaseModel):
    trust_status: str
    reason: str = ""


class SandboxProbeBody(BaseModel):
    tool_name: str
    expected_behavior: dict[str, Any] = Field(default_factory=dict)
    simulated_observed: dict[str, Any] | None = None


@app.post("/v1/servers")
def register_server(
    body: RegisterServerBody,
    session: Session = Depends(db_session),
    authorization: str | None = Header(default=None),
    cp: ControlPlane = Depends(plane),
) -> dict[str, Any]:
    """Register a new MCP server with integrity verification."""
    import uuid

    identity = require_admin(cp, authorization)
    if body.transport not in {"http", "sse", "stdio"}:
        raise HTTPException(422, "transport must be http, sse, or stdio")
    if body.auth_scheme not in {"none", "bearer", "oauth2", "mtls"}:
        raise HTTPException(422, "auth_scheme must be none, bearer, oauth2, or mtls")
    if body.transport in {"http", "sse"} and not body.endpoint.startswith(("https://", "http://")):
        raise HTTPException(422, "HTTP/SSE endpoints must use an http:// or https:// URL")

    server_id = f"server-{uuid.uuid4().hex[:8]}"
    server_data = {
        "server_id": server_id,
        "server_name": body.server_name,
        "publisher": body.publisher or "unknown",
        "version": body.version,
        "endpoint": body.endpoint,
        "transport": body.transport,
        "trust_status": TrustStatus.MONITORED.value,
        "approved_capabilities": body.capabilities,
        "metadata_json": {
            "description": body.description,
            "auth_scheme": body.auth_scheme,
            "auth_audience": body.auth_audience,
            "auth_scopes": body.auth_scopes,
            "registered_by": identity.subject,
        },
        "integrity_hash": canonical_hash(
            {
                "server": server_id,
                "version": body.version,
                "endpoint": body.endpoint,
                "transport": body.transport,
                "capabilities": body.capabilities,
                "auth_scheme": body.auth_scheme,
                "auth_audience": body.auth_audience,
                "auth_scopes": body.auth_scopes,
            }
        ),
        "risk_state": "PENDING_VERIFICATION",
    }
    registry = IntegrityRegistry(session)
    registry.upsert_server(server_data)

    sandbox_result = None
    if body.run_sandbox:
        mgr = SandboxManager()
        probe = mgr.probe(
            f"{body.server_name}::health",
            {
                "filesystem": [],
                "network": [body.endpoint],
                "process_spawn": False,
                "environment_access": False,
            },
        )
        sandbox_result = probe.as_dict()
        if probe.classification in {"HIGH_RISK", "MALICIOUS_OR_COMPROMISED"}:
            row = session.get(ServerRow, server_id)
            if row:
                row.trust_status = TrustStatus.RESTRICTED.value
                row.risk_state = "HIGH"
                session.add(row)
                session.commit()
        else:
            row = session.get(ServerRow, server_id)
            if row:
                row.risk_state = "NORMAL"
                session.add(row)
                session.commit()

    return {
        "server_id": server_id,
        "trust_status": session.get(ServerRow, server_id).trust_status,
        "risk_state": session.get(ServerRow, server_id).risk_state,
        "integrity_hash": server_data["integrity_hash"],
        "auth_scheme": body.auth_scheme,
        "auth_audience": body.auth_audience,
        "auth_scopes": body.auth_scopes,
        "sandbox": sandbox_result,
        "message": f"Server '{body.server_name}' registered successfully.",
    }


@app.post("/v1/servers/{server_id}/verify")
def verify_server(
    server_id: str,
    session: Session = Depends(db_session),
    authorization: str | None = Header(default=None),
    cp: ControlPlane = Depends(plane),
) -> dict[str, Any]:
    """Run sandbox verification probe against a registered server."""
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")

    require_admin(cp, authorization)

    mgr = SandboxManager()
    probe = mgr.probe(
        f"{row.server_name}::verification",
        {
            "filesystem": [],
            "network": [row.endpoint],
            "process_spawn": False,
            "environment_access": False,
        },
    )

    if probe.classification == "CLEAN":
        row.trust_status = TrustStatus.TRUSTED.value
        row.risk_state = "NORMAL"
    elif probe.classification in {"HIGH_RISK", "MALICIOUS_OR_COMPROMISED"}:
        row.trust_status = TrustStatus.QUARANTINED.value
        row.risk_state = "CRITICAL"
    else:
        row.trust_status = TrustStatus.MONITORED.value
        row.risk_state = "ELEVATED"

    from sentinel.types import utcnow

    row.last_verification_time = utcnow()
    session.add(row)
    session.commit()

    return {
        "server_id": server_id,
        "trust_status": row.trust_status,
        "risk_state": row.risk_state,
        "sandbox": probe.as_dict(),
    }


@app.put("/v1/servers/{server_id}/trust")
def update_server_trust(
    server_id: str,
    body: UpdateTrustBody,
    session: Session = Depends(db_session),
    authorization: str | None = Header(default=None),
    cp: ControlPlane = Depends(plane),
) -> dict[str, Any]:
    """Manually update server trust status (admin action)."""
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")

    require_admin(cp, authorization)

    valid = {s.value for s in TrustStatus}
    if body.trust_status not in valid:
        raise HTTPException(400, f"Invalid trust status. Must be one of: {valid}")

    row.trust_status = body.trust_status
    session.add(row)
    session.commit()
    return {
        "server_id": server_id,
        "trust_status": row.trust_status,
        "updated": True,
    }


@app.post("/v1/sandbox/probe")
def sandbox_probe(body: SandboxProbeBody) -> dict[str, Any]:
    """Run standalone sandbox probe for any tool."""
    mgr = SandboxManager()
    expected = body.expected_behavior or {
        "filesystem": [],
        "network": [],
        "process_spawn": False,
        "environment_access": False,
    }
    probe = mgr.probe(body.tool_name, expected, body.simulated_observed)
    return probe.as_dict()

