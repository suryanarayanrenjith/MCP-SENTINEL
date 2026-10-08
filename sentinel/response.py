from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinel.config import Settings
from sentinel.types import Decision, RiskBand, RiskResult, TrustStatus


class ResponseController:
    """Adaptive response with hysteresis to avoid rapid oscillation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._last: dict[str, tuple[datetime, Decision]] = {}

    def decide(
        self,
        *,
        key: str,
        risk: RiskResult,
        policy_hard_block: bool,
        require_mfa: bool,
        dataflow_block: bool,
        sequence_critical: bool,
        runtime_critical: bool,
        mfa_satisfied: bool,
        identity_valid: bool,
    ) -> Decision:
        if not identity_valid or policy_hard_block or dataflow_block or risk.hard_block:
            return self._commit(key, Decision.BLOCK)
        if sequence_critical or runtime_critical or risk.score >= self.settings.block_risk_threshold:
            return self._commit(key, Decision.BLOCK)
        if require_mfa and not mfa_satisfied:
            return self._commit(key, Decision.MFA_REQUIRED)
        if risk.band == RiskBand.HIGH_RISK:
            if require_mfa and mfa_satisfied:
                return self._commit(key, Decision.RESTRICT)
            return self._commit(key, Decision.MFA_REQUIRED)
        if risk.band == RiskBand.SUSPICIOUS:
            return self._commit(key, Decision.RESTRICT)
        if risk.band == RiskBand.MONITOR:
            return self._commit(key, Decision.MONITOR)
        return self._commit(key, Decision.ALLOW)

    def _commit(self, key: str, decision: Decision) -> Decision:
        now = datetime.now(timezone.utc)
        prev = self._last.get(key)
        if prev and now - prev[0] < timedelta(seconds=2) and self._rank(decision) < self._rank(prev[1]):
            return prev[1]
        self._last[key] = (now, decision)
        return decision

    def _rank(self, decision: Decision) -> int:
        order = [
            Decision.ALLOW,
            Decision.MONITOR,
            Decision.RESTRICT,
            Decision.MFA_REQUIRED,
            Decision.HUMAN_APPROVAL,
            Decision.QUARANTINE,
            Decision.BLOCK,
        ]
        return order.index(decision)

    def trust_after(self, decision: Decision, current: str) -> TrustStatus | None:
        if decision == Decision.BLOCK:
            return TrustStatus.QUARANTINED
        if decision == Decision.RESTRICT:
            return TrustStatus.RESTRICTED
        if decision == Decision.MONITOR:
            return TrustStatus.MONITORED
        return None
