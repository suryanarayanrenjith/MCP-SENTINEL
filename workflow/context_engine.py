from __future__ import annotations

from dataclasses import dataclass

from sentinel.types import Capability, IdentityContext, Sensitivity, ToolCallRequest, ToolDefinition
from workflow.analyzer import WorkflowState as WF


@dataclass
class ContextFinding:
    reasonable: bool
    reasons: list[str]
    risk_delta: int


class ContextualEngine:
    """Is this tool call reasonable in the current workflow?"""

    def evaluate(
        self,
        *,
        identity: IdentityContext,
        request: ToolCallRequest,
        tool: ToolDefinition,
        workflow: WF,
        capability: Capability,
    ) -> ContextFinding:
        reasons: list[str] = []
        risk = 0
        intent = (request.user_intent or workflow.intent or "").lower()
        if capability in {Capability.SECRET_ACCESS, Capability.DATA_TRANSFER, Capability.INFRASTRUCTURE_CONTROL}:
            if intent and not any(k in intent for k in ("credential", "secret", "isolate", "exfil", "transfer", "send")):
                if "investigate" in intent or "suspicious" in intent:
                    reasons.append("critical capability is not implied by investigation-only user intent")
                    risk += 18
        if tool.sensitivity in {Sensitivity.HIGH, Sensitivity.CRITICAL} and not identity.mfa_satisfied:
            reasons.append("high-sensitivity action without elevated authentication context")
            risk += 8
        if request.arguments:
            if ".." in str(request.arguments) or "/etc/" in str(request.arguments):
                reasons.append("parameters suggest path traversal")
                risk += 20
        if workflow.tools and tool.tool_name == "send_data" and "get_credentials" in workflow.tools:
            reasons.append("transfer after secret access is not reasonable for this workflow")
            risk += 16
        reasonable = risk < 20
        if reasonable:
            reasons.append("tool call is consistent with workflow context")
        return ContextFinding(reasonable=reasonable, reasons=reasons, risk_delta=risk)
