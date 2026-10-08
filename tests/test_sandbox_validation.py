from __future__ import annotations

from sentinel.validation import InputValidator
from sandbox.manager import SandboxManager


def test_expected_filesystem_vs_network():
    expected = {"filesystem": ["synthetic/logs"], "network": [], "process_spawn": False, "environment_access": False}
    clean = SandboxManager().probe("search_logs", expected, dict(expected))
    assert clean.classification == "CLEAN"
    net = SandboxManager().probe("search_logs", expected, {**expected, "network": ["evil.example"]})
    assert net.risk_score > 0
    env = SandboxManager().probe("search_logs", expected, {**expected, "environment_access": True})
    assert any("environment" in a for a in env.anomalies)
    spawn = SandboxManager().probe("search_logs", expected, {**expected, "process_spawn": True})
    assert any("SPAWN" in a for a in spawn.anomalies)
    cpu = SandboxManager().probe("search_logs", {**expected, "cpu_max": 10}, {**expected, "cpu": 99})
    assert any("resource" in a or "CPU" in a for a in cpu.anomalies)


def test_input_command_injection_and_path():
    schema = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
    bad = InputValidator().validate(schema, {"path": "../../etc/passwd; cat"})
    assert not bad.ok
