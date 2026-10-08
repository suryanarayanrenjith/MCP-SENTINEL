from __future__ import annotations

from sentinel.config import Settings
from sentinel.types import RiskBand, RiskFactor, RiskResult, Sensitivity, TrustStatus


def band_for(score: int) -> RiskBand:
    if score <= 19:
        return RiskBand.NORMAL
    if score <= 39:
        return RiskBand.MONITOR
    if score <= 59:
        return RiskBand.SUSPICIOUS
    if score <= 79:
        return RiskBand.HIGH_RISK
    return RiskBand.CRITICAL


class RiskEngine:
    """Explainable deterministic risk. Scores never override hard policy blocks."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def score(self, signals: dict[str, tuple[int, str]], *, hard_block: bool = False, hard_reason: str | None = None) -> RiskResult:
        factors = [RiskFactor(name=k, score=v[0], reason=v[1]) for k, v in signals.items() if v[0] > 0]
        total = min(100, sum(f.score for f in factors))
        return RiskResult(
            score=total,
            band=band_for(total),
            factors=factors,
            hard_block=hard_block,
            hard_block_reason=hard_reason,
        )

    def capability_signal(self, sensitivity: Sensitivity) -> tuple[int, str]:
        mapping = {
            Sensitivity.LOW: (2, "low sensitivity capability"),
            Sensitivity.MEDIUM: (8, "medium sensitivity capability"),
            Sensitivity.HIGH: (18, "HIGH sensitivity capability"),
            Sensitivity.CRITICAL: (28, "CRITICAL capability requested"),
        }
        return mapping[sensitivity]

    def trust_signal(self, status: str) -> tuple[int, str]:
        mapping = {
            TrustStatus.TRUSTED.value: (0, "currently trusted"),
            TrustStatus.MONITORED.value: (8, "server/tool is monitored"),
            TrustStatus.RESTRICTED.value: (20, "server/tool is restricted"),
            TrustStatus.QUARANTINED.value: (40, "server/tool is quarantined"),
            TrustStatus.BLOCKED.value: (50, "server/tool is blocked"),
        }
        return mapping.get(status, (10, "unknown trust status"))
