from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TrustStatus(str, Enum):
    TRUSTED = "TRUSTED"
    MONITORED = "MONITORED"
    RESTRICTED = "RESTRICTED"
    QUARANTINED = "QUARANTINED"
    BLOCKED = "BLOCKED"


class LeaseState(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRING = "EXPIRING"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    RESTRICT = "RESTRICT"
    MFA_REQUIRED = "MFA_REQUIRED"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


class RiskBand(str, Enum):
    NORMAL = "NORMAL"
    MONITOR = "MONITOR"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class Capability(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXTERNAL_LOOKUP = "EXTERNAL_LOOKUP"
    SECRET_ACCESS = "SECRET_ACCESS"
    DATA_TRANSFER = "DATA_TRANSFER"
    INFRASTRUCTURE_CONTROL = "INFRASTRUCTURE_CONTROL"


class Sensitivity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DataClass(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    CRITICAL = "CRITICAL"


class Deviation(str, Enum):
    NORMAL = "NORMAL"
    MINOR_DEVIATION = "MINOR_DEVIATION"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class Role(str, Enum):
    USER = "USER"
    DEVELOPER = "DEVELOPER"
    SOC_ANALYST = "SOC_ANALYST"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"


CAPABILITY_SENSITIVITY: dict[Capability, Sensitivity] = {
    Capability.READ: Sensitivity.LOW,
    Capability.WRITE: Sensitivity.MEDIUM,
    Capability.EXTERNAL_LOOKUP: Sensitivity.LOW,
    Capability.SECRET_ACCESS: Sensitivity.CRITICAL,
    Capability.DATA_TRANSFER: Sensitivity.HIGH,
    Capability.INFRASTRUCTURE_CONTROL: Sensitivity.CRITICAL,
}

ROLE_DEFAULT_CAPABILITIES: dict[str, set[Capability]] = {
    Role.USER.value: {Capability.READ},
    Role.DEVELOPER.value: {Capability.READ, Capability.WRITE, Capability.EXTERNAL_LOOKUP},
    Role.SOC_ANALYST.value: {
        Capability.READ,
        Capability.EXTERNAL_LOOKUP,
        Capability.WRITE,
    },
    Role.SECURITY_ADMIN.value: {
        Capability.READ,
        Capability.WRITE,
        Capability.EXTERNAL_LOOKUP,
        Capability.SECRET_ACCESS,
        Capability.DATA_TRANSFER,
        Capability.INFRASTRUCTURE_CONTROL,
    },
    Role.SYSTEM_ADMIN.value: {
        Capability.READ,
        Capability.WRITE,
        Capability.EXTERNAL_LOOKUP,
        Capability.SECRET_ACCESS,
        Capability.DATA_TRANSFER,
        Capability.INFRASTRUCTURE_CONTROL,
    },
}

SENSITIVE_CAPABILITIES = {
    Capability.SECRET_ACCESS,
    Capability.DATA_TRANSFER,
    Capability.INFRASTRUCTURE_CONTROL,
}


class IdentityContext(BaseModel):
    subject: str
    agent_id: str
    issuer: str
    audience: str | list[str]
    expires_at: datetime | None = None
    scopes: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    acr: str | None = None
    amr: list[str] = Field(default_factory=list)
    token_valid: bool = True
    mfa_satisfied: bool = False
    session_id: str | None = None


class ToolCallRequest(BaseModel):
    workflow_id: str
    server_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_intent: str = ""
    agent_id: str | None = None
    destination: str | None = None
    resource: str | None = None
    observed_runtime: dict[str, Any] | None = None


class CapabilityProfile(BaseModel):
    capability: Capability
    sensitivity: Sensitivity
    resource: str = ""
    network: list[str] = Field(default_factory=list)
    expected_behavior: dict[str, Any] = Field(default_factory=dict)


class RiskFactor(BaseModel):
    name: str
    score: int
    reason: str


class RiskResult(BaseModel):
    score: int
    band: RiskBand
    factors: list[RiskFactor] = Field(default_factory=list)
    hard_block: bool = False
    hard_block_reason: str | None = None


class SecurityDecision(BaseModel):
    decision: Decision
    risk: RiskResult
    reasons: list[str] = Field(default_factory=list)
    required_capability: Capability | None = None
    lease_id: str | None = None
    policy_id: str | None = None
    mfa_challenge_id: str | None = None
    approval_id: str | None = None
    receipt_id: str | None = None
    explainability: dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    tool_id: str
    server_id: str
    tool_name: str
    version: str
    schema: dict[str, Any]
    capabilities: list[Capability]
    annotations: dict[str, Any] = Field(default_factory=dict)
    expected_behavior: dict[str, Any] = Field(default_factory=dict)
    integrity_hash: str
    sensitivity: Sensitivity
    trust_status: TrustStatus = TrustStatus.MONITORED
    implementation_fingerprint: str = ""
    description: str = ""
    resource: str = ""


class ServerRecord(BaseModel):
    server_id: str
    server_name: str
    publisher: str
    version: str
    endpoint: str
    transport: str = "http"
    trust_status: TrustStatus = TrustStatus.MONITORED
    registration_time: datetime = Field(default_factory=utcnow)
    approved_capabilities: list[Capability] = Field(default_factory=list)
    integrity_hash: str = ""
    last_verification_time: datetime | None = None
    risk_state: RiskBand = RiskBand.MONITOR
