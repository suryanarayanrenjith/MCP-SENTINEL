from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sentinel.store import StateStore
from sentinel.types import IdentityContext


@dataclass
class MfaChallenge:
    challenge_id: str
    workflow_id: str
    subject: str
    capability: str
    tool_name: str
    created_at: str
    expires_at: str
    status: str = "PENDING"


class StepUpManager:
    """MFA increases authentication assurance only. It is never a universal allow."""

    def __init__(self, store: StateStore, ttl_seconds: int = 300) -> None:
        self.store = store
        self.ttl_seconds = ttl_seconds

    def require(self, *, workflow_id: str, subject: str, capability: str, tool_name: str) -> MfaChallenge:
        now = datetime.now(timezone.utc)
        challenge = MfaChallenge(
            challenge_id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            subject=subject,
            capability=capability,
            tool_name=tool_name,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=self.ttl_seconds)).isoformat(),
        )
        self.store.setex(f"mfa:{challenge.challenge_id}", self.ttl_seconds, challenge.__dict__)
        self.store.setex(f"mfa-wf:{workflow_id}:{capability}", self.ttl_seconds, challenge.__dict__)
        return challenge

    def complete(self, challenge_id: str, identity: IdentityContext) -> MfaChallenge:
        data = self.store.get_json(f"mfa:{challenge_id}")
        if not data:
            raise ValueError("unknown or expired MFA challenge")
        challenge = MfaChallenge(**data)
        if identity.subject != challenge.subject:
            raise ValueError("MFA subject mismatch")
        if not identity.mfa_satisfied:
            raise ValueError("authentication context does not include MFA (acr/amr)")
        challenge.status = "SATISFIED"
        self.store.setex(f"mfa:{challenge_id}", self.ttl_seconds, challenge.__dict__)
        self.store.setex(
            f"mfa-ok:{challenge.workflow_id}:{challenge.capability}",
            self.ttl_seconds,
            {"subject": identity.subject, "challenge_id": challenge_id},
        )
        return challenge

    def satisfied(self, workflow_id: str, capability: str, subject: str) -> bool:
        data = self.store.get_json(f"mfa-ok:{workflow_id}:{capability}")
        return bool(data and data.get("subject") == subject)
