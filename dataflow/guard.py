from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.types import Capability, DataClass
from workflow.analyzer import WorkflowState


RESOURCE_CLASS = {
    "security_logs": DataClass.INTERNAL,
    "threat_intel": DataClass.INTERNAL,
    "incidents": DataClass.CONFIDENTIAL,
    "secrets_vault": DataClass.SECRET,
    "data_export": DataClass.CONFIDENTIAL,
    "edr": DataClass.CRITICAL,
}


@dataclass
class DataFlowFinding:
    data_class: DataClass
    reasons: list[str] = field(default_factory=list)
    risk_delta: int = 0
    block: bool = False


class DataFlowGuard:
    def classify(self, resource: str, capability: Capability) -> DataClass:
        if capability == Capability.SECRET_ACCESS:
            return DataClass.SECRET
        return RESOURCE_CLASS.get(resource, DataClass.INTERNAL)

    def evaluate(
        self,
        *,
        workflow: WorkflowState,
        capability: Capability,
        resource: str,
        destination: str | None,
    ) -> DataFlowFinding:
        current = self.classify(resource, capability)
        reasons: list[str] = []
        risk = 0
        block = False
        prior_secret = DataClass.SECRET.value in workflow.data_classes or DataClass.CRITICAL.value in workflow.data_classes
        dest = (destination or "").lower()
        external = bool(dest) and not any(x in dest for x in ("internal", "localhost", "127.0.0.1", "soc."))
        if capability == Capability.DATA_TRANSFER and (prior_secret or current in {DataClass.SECRET, DataClass.CRITICAL}) and external:
            reasons.append("unauthorized SECRET/CRITICAL data transfer to an external destination")
            risk += 45
            block = True
        elif capability == Capability.DATA_TRANSFER and current in {DataClass.CONFIDENTIAL, DataClass.SECRET}:
            reasons.append("confidential data transfer requires additional controls")
            risk += 15
        return DataFlowFinding(data_class=current, reasons=reasons, risk_delta=risk, block=block)
