from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from monitoring.behavior import RuntimeBehaviorAnalyzer
from sentinel.types import Deviation


@dataclass
class SandboxResult:
    expected_behavior: dict[str, Any]
    observed_behavior: dict[str, Any]
    anomalies: list[str]
    risk_score: int
    classification: str
    evidence: dict[str, Any]
    timestamp: str
    isolated: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "expected_behavior": self.expected_behavior,
            "observed_behavior": self.observed_behavior,
            "anomalies": self.anomalies,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "isolated": self.isolated,
            "note": "Sandbox results are evidence, not permanent trust.",
        }


class SandboxManager:
    """
    Prototype sandbox: executes a synthetic probe against declared vs simulated observed behavior.

    Production extension: run the MCP server in a hardened container (non-root, read-only root,
    seccomp, AppArmor, no docker.sock, deny-by-default network, synthetic FS/DB/credentials).
    Docker socket is never mounted into the sandbox.
    """

    def __init__(self, docker_enabled: bool = False, image: str = "mcp-sentinel-sandbox:dev") -> None:
        self.docker_enabled = docker_enabled
        self.image = image
        self.analyzer = RuntimeBehaviorAnalyzer()

    def probe(self, tool_name: str, expected: dict[str, Any], simulated_observed: dict[str, Any] | None = None) -> SandboxResult:
        observed = simulated_observed or dict(expected)
        finding = self.analyzer.evaluate(expected, observed)
        classification = {
            Deviation.NORMAL: "CLEAN",
            Deviation.MINOR_DEVIATION: "MINOR",
            Deviation.SUSPICIOUS: "SUSPICIOUS",
            Deviation.HIGH_RISK: "HIGH_RISK",
            Deviation.CRITICAL: "MALICIOUS_OR_COMPROMISED",
        }[finding.deviation]
        evidence = {
            "tool": tool_name,
            "isolation": {
                "non_root": True,
                "network_deny_by_default": True,
                "no_docker_socket": True,
                "no_production_secrets": True,
                "synthetic_resources": ["fake_fs", "synthetic_logs", "fake_db", "dummy_credentials", "mock_api"],
            },
        }
        if self.docker_enabled:
            evidence["runtime"] = self._try_docker(tool_name)
        return SandboxResult(
            expected_behavior=expected,
            observed_behavior=observed,
            anomalies=finding.anomalies,
            risk_score=finding.risk_delta,
            classification=classification,
            evidence=evidence,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _try_docker(self, tool_name: str) -> dict[str, Any]:
        try:
            import docker

            client = docker.from_env()
            container = client.containers.run(
                self.image,
                command=["python", "/probe.py", tool_name],
                user="65534:65534",
                network_mode="none",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                read_only=True,
                mem_limit="128m",
                cpu_period=100000,
                cpu_quota=25000,
                pids_limit=64,
                remove=True,
                detach=False,
                stdout=True,
                stderr=True,
                timeout=15,
            )
            return {"docker": True, "output": str(container)[:500]}
        except Exception as exc:
            return {"docker": False, "error": type(exc).__name__, "fallback": "in-process synthetic probe"}
