from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.types import Capability, DataClass

SUSPICIOUS_TRANSITIONS = {
    (Capability.EXTERNAL_LOOKUP, Capability.SECRET_ACCESS),
    (Capability.READ, Capability.SECRET_ACCESS),
    (Capability.SECRET_ACCESS, Capability.DATA_TRANSFER),
    (Capability.SECRET_ACCESS, Capability.EXTERNAL_LOOKUP),
}

CRITICAL_TRANSITIONS = {
    (Capability.SECRET_ACCESS, Capability.DATA_TRANSFER),
}


@dataclass
class WorkflowState:
    workflow_id: str
    intent: str = ""
    tools: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    data_classes: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)


@dataclass
class SequenceFinding:
    risk_delta: int
    reasons: list[str]
    critical: bool = False


class SequentialAnalyzer:
    """Graph/state-transition detector for short-lived workflows."""

    def analyze(self, state: WorkflowState, next_tool: str, next_cap: Capability, destination: str | None, data_class: DataClass) -> SequenceFinding:
        reasons: list[str] = []
        risk = 0
        critical = False
        prev_cap = Capability(state.capabilities[-1]) if state.capabilities else None
        if prev_cap and (prev_cap, next_cap) in SUSPICIOUS_TRANSITIONS:
            reasons.append(f"unusual capability transition {prev_cap.value} -> {next_cap.value}")
            risk += 22
        if prev_cap and (prev_cap, next_cap) in CRITICAL_TRANSITIONS:
            if data_class in {DataClass.SECRET, DataClass.CRITICAL} or DataClass.SECRET.value in state.data_classes:
                dest = (destination or "").lower()
                external = dest and not any(x in dest for x in ("internal", "localhost", "soc."))
                if external:
                    reasons.append("SECRET data flowing into DATA_TRANSFER toward an external destination")
                    risk += 40
                    critical = True
        sequence = state.tools + [next_tool]
        if sequence[-4:] == ["search_logs", "lookup_ip", "get_credentials", "send_data"] or (
            "get_credentials" in sequence and next_tool == "send_data"
        ):
            reasons.append("dangerous legitimate-looking sequence: lookup/secret then transfer")
            risk += 18
        if next_cap == Capability.SECRET_ACCESS and Capability.EXTERNAL_LOOKUP.value in state.capabilities:
            reasons.append("SECRET_ACCESS follows an external lookup")
            risk += 10
        if not reasons:
            reasons.append("sequence matches expected SOC investigation pattern" if self._looks_normal(sequence) else "no suspicious transition detected")
        return SequenceFinding(risk_delta=min(risk, 50), reasons=reasons, critical=critical)

    def _looks_normal(self, sequence: list[str]) -> bool:
        allowed = [
            ["search_logs"],
            ["search_logs", "lookup_ip"],
            ["search_logs", "lookup_ip", "create_incident"],
        ]
        return sequence in allowed
