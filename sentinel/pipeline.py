from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from dataflow.guard import DataFlowGuard
from identity.verifier import IdentityError, IdentityVerifier
from integrity.registry import IntegrityRegistry
from mfa.stepup import StepUpManager
from monitoring.behavior import RuntimeBehaviorAnalyzer
from policy.engine import PolicyEngine
from risk.engine import RiskEngine
from sandbox.manager import SandboxManager
from sentinel.catalog import catalog_by_name
from sentinel.config import Settings
from sentinel.db import WorkflowCallRow
from sentinel.injection import InjectionGuard
from sentinel.leases import CapabilityLeaseManager
from sentinel.receipts import AuditStore
from sentinel.response import ResponseController
from sentinel.store import StateStore
from sentinel.types import (
    Capability,
    Decision,
    IdentityContext,
    SecurityDecision,
    Sensitivity,
    ToolCallRequest,
    TrustStatus,
    utcnow,
)
from sentinel.validation import InputValidator, OutputValidator
from workflow.analyzer import SequentialAnalyzer, WorkflowState
from workflow.context_engine import ContextualEngine


class ControlPlane:
    """Authoritative security decision path. The LLM cannot override this."""

    def __init__(self, session: Session, store: StateStore, settings: Settings) -> None:
        self.session = session
        self.store = store
        self.settings = settings
        self.identity = IdentityVerifier(settings)
        self.registry = IntegrityRegistry(session)
        self.policy = PolicyEngine(settings)
        self.leases = CapabilityLeaseManager(session, settings)
        self.seq = SequentialAnalyzer()
        self.context = ContextualEngine()
        self.inject = InjectionGuard()
        self.inputs = InputValidator()
        self.outputs = OutputValidator()
        self.dataflow = DataFlowGuard()
        self.risk = RiskEngine(settings)
        self.mfa = StepUpManager(store)
        self.runtime = RuntimeBehaviorAnalyzer()
        self.sandbox = SandboxManager(settings.sandbox_enabled, settings.sandbox_image)
        self.response = ResponseController(settings)
        self.audit = AuditStore(session)

    def authorize(
        self,
        authorization: str | None,
        request: ToolCallRequest,
        *,
        agent_hint: str | None = None,
        complete_mfa: bool = False,
        grant_lease_after_mfa: bool = False,
    ) -> tuple[SecurityDecision, IdentityContext | None]:
        reasons: list[str] = []
        signals: dict[str, tuple[int, str]] = {}
        identity: IdentityContext | None = None
        try:
            identity = self.identity.verify(authorization, agent_hint=agent_hint or request.agent_id)
        except IdentityError as exc:
            risk = self.risk.score(
                {"identity": (40, exc.message)},
                hard_block=True,
                hard_reason=exc.message,
            )
            decision = self._finish(
                request,
                identity=None,
                decision=Decision.BLOCK,
                risk=risk,
                reasons=[exc.message],
                policy_id=f"deny.{exc.code}",
            )
            return decision, None

        if identity.agent_id and request.agent_id and request.agent_id != identity.agent_id:
            risk = self.risk.score(
                {"agent": (40, "agent identity mismatch")},
                hard_block=True,
                hard_reason="agent identity mismatch",
            )
            return (
                self._finish(
                    request,
                    identity,
                    Decision.BLOCK,
                    risk,
                    ["agent identity supplied in MCP request does not match token"],
                    "deny.agent_mismatch",
                ),
                identity,
            )

        server = self.registry.get_server(request.server_id)
        if server is None:
            risk = self.risk.score({"server": (50, "unknown server")}, hard_block=True, hard_reason="unknown server")
            return (
                self._finish(request, identity, Decision.BLOCK, risk, ["server is not in the trust registry"], "deny.unknown_server"),
                identity,
            )

        catalog = catalog_by_name()
        catalog_tool = catalog.get(request.tool_name)
        tool_row = self.registry.get_tool(request.server_id, request.tool_name)
        if tool_row is None or catalog_tool is None:
            risk = self.risk.score({"tool": (50, "unknown tool")}, hard_block=True, hard_reason="unknown tool")
            return (
                self._finish(request, identity, Decision.BLOCK, risk, ["tool is not in the integrity registry"], "deny.unknown_tool"),
                identity,
            )

        capability = Capability(tool_row.capabilities[0])
        workflow = self._load_workflow(request.workflow_id, request.user_intent)

        inj_desc = self.inject.scan(tool_row.description)
        inj_args = self.inject.scan(str(request.arguments))
        if inj_desc.detected:
            signals["prompt_injection"] = (inj_desc.risk_delta, "tool description contains injection patterns")
            reasons.extend([f"injection:{m}" for m in inj_desc.matches[:3]])
        if inj_args.detected:
            signals["prompt_injection_args"] = (inj_args.risk_delta, "arguments contain injection patterns")

        schema_issues = self.registry.verify_level2_structural(
            tool_row,
            {
                "schema": catalog_tool.schema,
                "version": catalog_tool.version,
                "capabilities": [c.value for c in catalog_tool.capabilities],
            },
        )
        if schema_issues:
            signals["integrity"] = (18, "; ".join(schema_issues))
            reasons.extend(schema_issues)

        if tool_row.trust_status in {TrustStatus.RESTRICTED.value, TrustStatus.MONITORED.value}:
            signals["semantic_change"] = (12, f"tool trust status is {tool_row.trust_status}")

        iv = self.inputs.validate(tool_row.schema_json or {}, request.arguments)
        if not iv.ok:
            signals["input"] = (iv.risk_delta, "; ".join(iv.issues))
            reasons.extend(iv.issues)
            if any("SSRF" in i or "command injection" in i or "path traversal" in i for i in iv.issues):
                risk = self.risk.score({**signals, "input": (iv.risk_delta, "; ".join(iv.issues))}, hard_block=True, hard_reason=iv.issues[0])
                return (
                    self._finish(request, identity, Decision.BLOCK, risk, reasons, "deny.input_validation"),
                    identity,
                )

        wf_state = WorkflowState(**workflow)
        seq = self.seq.analyze(
            wf_state,
            request.tool_name,
            capability,
            request.destination or request.arguments.get("destination"),
            self.dataflow.classify(tool_row.resource, capability),
        )
        if seq.risk_delta:
            signals["workflow"] = (seq.risk_delta, seq.reasons[0])
            reasons.extend(seq.reasons)
        ctx = self.context.evaluate(
            identity=identity,
            request=request,
            tool=catalog_tool,
            workflow=wf_state,
            capability=capability,
        )
        if ctx.risk_delta:
            signals["context"] = (ctx.risk_delta, ctx.reasons[0])
            reasons.extend(ctx.reasons)

        df = self.dataflow.evaluate(
            workflow=wf_state,
            capability=capability,
            resource=tool_row.resource,
            destination=request.destination or request.arguments.get("destination"),
        )
        if df.risk_delta:
            signals["dataflow"] = (df.risk_delta, df.reasons[0] if df.reasons else "data-flow risk")
            reasons.extend(df.reasons)

        runtime = self.runtime.evaluate(tool_row.expected_behavior, request.observed_runtime)
        if runtime.risk_delta:
            signals["runtime"] = (runtime.risk_delta, runtime.anomalies[0] if runtime.anomalies else "runtime deviation")
            reasons.extend(runtime.anomalies)

        lease = self.leases.active_lease(request.workflow_id, identity.subject, capability)
        mfa_ok = identity.mfa_satisfied or self.mfa.satisfied(request.workflow_id, capability.value, identity.subject)
        if grant_lease_after_mfa and mfa_ok and lease is None:
            lease = self.leases.grant(
                workflow_id=request.workflow_id,
                subject=identity.subject,
                capability=capability,
                tool_name=request.tool_name,
            )

        policy = self.policy.evaluate(
            identity=identity,
            server_status=server.trust_status,
            tool_status=tool_row.trust_status,
            capability=capability,
            destination=request.destination or request.arguments.get("destination"),
            lease_active=lease is not None,
            mfa_for_request=mfa_ok,
            opa_input={
                "token_valid": identity.token_valid,
                "roles": identity.roles,
                "server_status": server.trust_status,
                "tool_status": tool_row.trust_status,
                "capability": capability.value,
                "destination": request.destination or request.arguments.get("destination") or "",
            },
        )
        if not policy.allow and policy.hard_block:
            risk = self.risk.score(
                {**signals, "policy": (30, policy.reasons[0] if policy.reasons else "policy deny")},
                hard_block=True,
                hard_reason=policy.reasons[0] if policy.reasons else "policy deny",
            )
            decision = Decision.BLOCK
            if lease:
                self.leases.revoke(lease.lease_id, "hard policy deny")
            return (
                self._finish(request, identity, decision, risk, reasons + policy.reasons, policy.policy_id, capability, lease.lease_id if lease else None),
                identity,
            )

        signals["identity"] = (0 if identity.token_valid else 20, "identity verified" if identity.token_valid else "identity weak")
        signals["authorization"] = (0 if policy.allow else 12, policy.reasons[0] if policy.reasons else "authorization")
        signals["server_trust"] = self.risk.trust_signal(server.trust_status)
        signals["tool_integrity"] = self.risk.trust_signal(tool_row.trust_status)
        signals["capability"] = self.risk.capability_signal(Sensitivity(tool_row.sensitivity))
        if not identity.mfa_satisfied and capability.value in {"SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL"}:
            signals["authn_assurance"] = (10, "MFA authentication context not present")

        if df.block:
            risk = self.risk.score(signals, hard_block=True, hard_reason="data-flow violation")
            if lease:
                self.leases.revoke(lease.lease_id, "data-flow violation")
            self.registry.set_tool_status(tool_row.tool_id, TrustStatus.RESTRICTED)
            return (
                self._finish(
                    request,
                    identity,
                    Decision.BLOCK,
                    risk,
                    reasons + ["mandatory data-flow policy BLOCK"],
                    "deny.dataflow",
                    capability,
                    lease.lease_id if lease else None,
                ),
                identity,
            )

        if runtime.deviation.value in {"HIGH_RISK", "CRITICAL"}:
            sandbox = self.sandbox.probe(request.tool_name, tool_row.expected_behavior or {}, request.observed_runtime)
            signals["sandbox"] = (sandbox.risk_score, "sandbox evidence: " + sandbox.classification)
            if runtime.deviation.value == "CRITICAL":
                self.leases.revoke_workflow(request.workflow_id, "runtime compromise")
                self.registry.set_tool_status(tool_row.tool_id, TrustStatus.QUARANTINED)
                self.registry.set_server_status(request.server_id, TrustStatus.QUARANTINED)
                risk = self.risk.score(signals, hard_block=True, hard_reason="compromised runtime behavior")
                return (
                    self._finish(
                        request,
                        identity,
                        Decision.BLOCK,
                        risk,
                        reasons + ["runtime compromise: quarantine and block future calls"],
                        "deny.runtime",
                        capability,
                    ),
                    identity,
                )

        risk = self.risk.score(signals, hard_block=policy.hard_block, hard_reason=None)
        require_mfa = policy.require_mfa or risk.score >= self.settings.mfa_risk_threshold
        decision = self.response.decide(
            key=f"{request.workflow_id}:{request.tool_name}",
            risk=risk,
            policy_hard_block=policy.hard_block,
            require_mfa=require_mfa,
            dataflow_block=False,
            sequence_critical=seq.critical,
            runtime_critical=False,
            mfa_satisfied=mfa_ok,
            identity_valid=True,
        )
        if seq.critical:
            decision = Decision.BLOCK
            reasons.append("critical workflow transition")
            if lease:
                self.leases.revoke(lease.lease_id, "critical sequence")

        lease_id = lease.lease_id if lease else None
        challenge_id = None
        if decision == Decision.MFA_REQUIRED:
            challenge = self.mfa.require(
                workflow_id=request.workflow_id,
                subject=identity.subject,
                capability=capability.value,
                tool_name=request.tool_name,
            )
            challenge_id = challenge.challenge_id
            reasons.append("step-up MFA required; MFA does not grant unrestricted access")
        elif decision in {Decision.ALLOW, Decision.MONITOR} and policy.require_lease and lease is None and mfa_ok:
            lease = self.leases.grant(
                workflow_id=request.workflow_id,
                subject=identity.subject,
                capability=capability,
                tool_name=request.tool_name,
            )
            lease_id = lease.lease_id
            reasons.append(f"temporary capability lease granted for {self.settings.lease_default_seconds}s")

        new_trust = self.response.trust_after(decision, tool_row.trust_status)
        if new_trust and decision in {Decision.RESTRICT, Decision.BLOCK, Decision.QUARANTINE}:
            self.registry.set_tool_status(tool_row.tool_id, new_trust)

        if not reasons:
            reasons.append("all security signals consistent; request is NORMAL")

        finished = self._finish(
            request,
            identity,
            decision,
            risk,
            reasons,
            policy.policy_id,
            capability,
            lease_id,
            challenge_id,
            explain={
                "what": f"tool call {request.tool_name}",
                "who": identity.subject,
                "agent": identity.agent_id,
                "server": request.server_id,
                "tool": request.tool_name,
                "capability": capability.value,
                "resources": [tool_row.resource],
                "previous_actions": wf_state.tools,
                "policy": policy.policy_id,
                "risk_factors": [f.model_dump() for f in risk.factors],
                "final_risk": risk.score,
                "decision": decision.value,
                "mfa_satisfied": mfa_ok,
                "lease_id": lease_id,
            },
        )
        self._record_call(
            request,
            capability,
            df.data_class.value,
            finished.decision in {Decision.ALLOW, Decision.MONITOR},
        )
        return finished, identity

    def inspect_output(self, output: Any) -> list[str]:
        result = self.outputs.validate(output)
        inj = self.inject.scan(str(output))
        issues = list(result.issues)
        if inj.detected:
            issues.append("untrusted tool output contains injection patterns")
        return issues

    def _load_workflow(self, workflow_id: str, intent: str) -> dict[str, Any]:
        cached = self.store.get_json(f"wf:{workflow_id}")
        if cached:
            if intent:
                cached["intent"] = intent
            return cached
        data = {
            "workflow_id": workflow_id,
            "intent": intent,
            "tools": [],
            "capabilities": [],
            "resources": [],
            "data_classes": [],
            "destinations": [],
        }
        rows = (
            self.session.query(WorkflowCallRow)
            .filter(WorkflowCallRow.workflow_id == workflow_id)
            .order_by(WorkflowCallRow.id.asc())
            .all()
        )
        for row in rows:
            data["tools"].append(row.tool_name)
            data["capabilities"].append(row.capability)
            data["resources"].append(row.resource)
            data["data_classes"].append(row.data_class)
            if row.destination:
                data["destinations"].append(row.destination)
        self.store.setex(f"wf:{workflow_id}", self.settings.workflow_ttl_seconds, data)
        return data

    def _record_call(self, request: ToolCallRequest, capability: Capability, data_class: str, allowed: bool) -> None:
        row = WorkflowCallRow(
            workflow_id=request.workflow_id,
            tool_name=request.tool_name,
            capability=capability.value,
            resource=request.resource or "",
            destination=str(request.destination or request.arguments.get("destination") or ""),
            data_class=data_class,
            allowed=allowed,
            timestamp=utcnow(),
        )
        self.session.add(row)
        self.session.commit()
        cached = self.store.get_json(f"wf:{request.workflow_id}") or {
            "workflow_id": request.workflow_id,
            "intent": request.user_intent,
            "tools": [],
            "capabilities": [],
            "resources": [],
            "data_classes": [],
            "destinations": [],
        }
        cached["tools"] = list(cached.get("tools") or []) + [request.tool_name]
        cached["capabilities"] = list(cached.get("capabilities") or []) + [capability.value]
        cached["resources"] = list(cached.get("resources") or []) + [request.resource or ""]
        cached["data_classes"] = list(cached.get("data_classes") or []) + [data_class]
        dest = request.destination or request.arguments.get("destination")
        if dest:
            cached["destinations"] = list(cached.get("destinations") or []) + [dest]
        if request.user_intent:
            cached["intent"] = request.user_intent
        self.store.setex(f"wf:{request.workflow_id}", self.settings.workflow_ttl_seconds, cached)

    def _finish(
        self,
        request: ToolCallRequest,
        identity: IdentityContext | None,
        decision: Decision,
        risk,
        reasons: list[str],
        policy_id: str,
        capability: Capability | None = None,
        lease_id: str | None = None,
        challenge_id: str | None = None,
        explain: dict[str, Any] | None = None,
    ) -> SecurityDecision:
        previous = []
        cached = self.store.get_json(f"wf:{request.workflow_id}") or {}
        previous = list(cached.get("tools") or [])
        payload = {
            "workflow_id": request.workflow_id,
            "identity": identity.subject if identity else "anonymous",
            "agent": identity.agent_id if identity else request.agent_id or "unknown",
            "server": request.server_id,
            "tool": request.tool_name,
            "decision": decision.value,
            "risk_score": risk.score,
            "state": risk.band.value,
            "reasons": reasons,
            "previous_tools": previous,
            "policy_id": policy_id,
            "capability": capability.value if capability else None,
            "lease_id": lease_id,
            "timestamp": utcnow().isoformat(),
            "explainability": explain or {},
        }
        receipt = self.audit.write_receipt(payload)
        self.audit.write_event(
            "decision",
            risk.band.value,
            f"{decision.value} {request.tool_name}",
            {"receipt_id": receipt.receipt_id, "risk": risk.score},
        )
        return SecurityDecision(
            decision=decision,
            risk=risk,
            reasons=reasons,
            required_capability=capability,
            lease_id=lease_id,
            policy_id=policy_id,
            mfa_challenge_id=challenge_id,
            receipt_id=receipt.receipt_id,
            explainability=explain or payload,
        )
