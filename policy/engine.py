from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from sentinel.config import Settings
from sentinel.types import (
    ROLE_DEFAULT_CAPABILITIES,
    SENSITIVE_CAPABILITIES,
    Capability,
    IdentityContext,
    TrustStatus,
)


@dataclass
class PolicyDecision:
    allow: bool
    policy_id: str
    reasons: list[str] = field(default_factory=list)
    hard_block: bool = False
    require_mfa: bool = False
    require_lease: bool = False
    capability: Capability | None = None


class PolicyEngine:
    """Policy Decision Point. Hard rules always override risk scores."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(
        self,
        *,
        identity: IdentityContext,
        server_status: str,
        tool_status: str,
        capability: Capability,
        destination: str | None,
        lease_active: bool,
        mfa_for_request: bool,
        opa_input: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        if self.settings.opa_enabled:
            remote = self._opa(opa_input or {})
            if remote is not None:
                return remote
        return self._local(
            identity=identity,
            server_status=server_status,
            tool_status=tool_status,
            capability=capability,
            destination=destination,
            lease_active=lease_active,
            mfa_for_request=mfa_for_request,
        )

    def _local(
        self,
        *,
        identity: IdentityContext,
        server_status: str,
        tool_status: str,
        capability: Capability,
        destination: str | None,
        lease_active: bool,
        mfa_for_request: bool,
    ) -> PolicyDecision:
        reasons: list[str] = []
        if not identity.token_valid or not identity.subject:
            return PolicyDecision(False, "deny.invalid_identity", ["invalid token"], hard_block=True)
        if not identity.roles:
            return PolicyDecision(False, "deny.no_roles", ["no authorized roles in identity token"], hard_block=True)
        if server_status in {TrustStatus.BLOCKED.value, TrustStatus.QUARANTINED.value}:
            return PolicyDecision(
                False,
                "deny.server_trust",
                [f"server trust status is {server_status}"],
                hard_block=True,
            )
        if tool_status in {TrustStatus.BLOCKED.value, TrustStatus.QUARANTINED.value}:
            return PolicyDecision(
                False,
                "deny.tool_trust",
                [f"tool trust status is {tool_status}"],
                hard_block=True,
            )
        granted = set()
        for role in identity.roles:
            granted |= ROLE_DEFAULT_CAPABILITIES.get(role, set())
        if capability not in granted:
            return PolicyDecision(
                False,
                "deny.unauthorized_capability",
                [f"roles {identity.roles} do not include {capability.value}"],
                hard_block=True,
            )
        if destination and self._forbidden_destination(destination):
            return PolicyDecision(
                False,
                "deny.forbidden_destination",
                [f"forbidden destination {destination}"],
                hard_block=True,
            )
        require_lease = capability in SENSITIVE_CAPABILITIES
        require_mfa = capability in SENSITIVE_CAPABILITIES and not identity.mfa_satisfied
        if require_lease and not lease_active and mfa_for_request is False and not require_mfa:
            reasons.append("sensitive capability requires an active lease")
            return PolicyDecision(
                False,
                "deny.lease_required",
                reasons,
                require_lease=True,
                capability=capability,
            )
        if server_status == TrustStatus.RESTRICTED.value and capability in SENSITIVE_CAPABILITIES:
            return PolicyDecision(
                False,
                "deny.restricted_server",
                ["restricted server cannot use sensitive capabilities"],
                hard_block=True,
            )
        reasons.append("identity, role, server, tool, and capability checks passed")
        return PolicyDecision(
            True,
            "allow.default",
            reasons,
            require_mfa=require_mfa,
            require_lease=require_lease,
            capability=capability,
        )

    def _forbidden_destination(self, destination: str) -> bool:
        dest = destination.lower()
        blocked = ("unknown.example", "evil.example", "169.254.169.254", "metadata.google.internal")
        return any(b in dest for b in blocked)

    def _opa(self, payload: dict[str, Any]) -> PolicyDecision | None:
        try:
            resp = httpx.post(
                f"{self.settings.opa_url}/v1/data/sentinel/authz/decision",
                json={"input": payload},
                timeout=2.0,
            )
            resp.raise_for_status()
            result = (resp.json() or {}).get("result") or {}
            return PolicyDecision(
                allow=bool(result.get("allow")),
                policy_id=str(result.get("policy_id") or "opa.sentinel.authz"),
                reasons=list(result.get("reasons") or []),
                hard_block=bool(result.get("hard_block")),
                require_mfa=bool(result.get("require_mfa")),
                require_lease=bool(result.get("require_lease")),
            )
        except Exception:
            return None
