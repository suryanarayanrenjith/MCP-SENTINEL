from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.types import Deviation


@dataclass
class BehaviorFinding:
    deviation: Deviation
    anomalies: list[str] = field(default_factory=list)
    risk_delta: int = 0


class RuntimeBehaviorAnalyzer:
    """Level-4 integrity: compare observed runtime vs expected baseline."""

    def evaluate(self, expected: dict[str, Any] | None, observed: dict[str, Any] | None) -> BehaviorFinding:
        expected = expected or {}
        observed = observed or {}
        anomalies: list[str] = []
        if observed.get("environment_access") and not expected.get("environment_access"):
            anomalies.append("READ environment variables outside baseline")
        if observed.get("process_spawn") and not expected.get("process_spawn"):
            anomalies.append("SPAWN process outside baseline")
        expected_net = set(expected.get("network") or [])
        observed_net = set(observed.get("network") or [])
        extra_net = observed_net - expected_net
        if extra_net:
            anomalies.append(f"CONNECT {sorted(extra_net)}")
        if observed.get("secret_access") and not expected.get("secret_access"):
            anomalies.append("unexpected secret access")
        if observed.get("filesystem"):
            allowed = set(expected.get("filesystem") or [])
            extra_fs = set(observed.get("filesystem") or []) - allowed
            if extra_fs:
                anomalies.append(f"unexpected filesystem access {sorted(extra_fs)}")
        cpu = float(observed.get("cpu") or 0)
        if cpu > float(expected.get("cpu_max") or 90):
            anomalies.append("resource exhaustion / high CPU")

        if not anomalies:
            return BehaviorFinding(Deviation.NORMAL, [], 0)
        if any("SPAWN" in a or "CONNECT" in a or "environment" in a for a in anomalies):
            if len(anomalies) >= 2:
                return BehaviorFinding(Deviation.CRITICAL, anomalies, 40)
            return BehaviorFinding(Deviation.HIGH_RISK, anomalies, 28)
        return BehaviorFinding(Deviation.SUSPICIOUS, anomalies, 16)


class BehavioralBaseline:
    def profile_for(self, tool_name: str, expected: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool": tool_name,
            "filesystem": expected.get("filesystem", []),
            "network": expected.get("network", []),
            "process_spawn": bool(expected.get("process_spawn")),
            "environment_access": bool(expected.get("environment_access")),
            "secret_access": bool(expected.get("secret_access")),
            "cpu_max": expected.get("cpu_max", 50),
        }
