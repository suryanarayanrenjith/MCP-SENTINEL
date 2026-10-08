from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from sentinel.config import Settings
from sentinel.db import LeaseRow
from sentinel.types import Capability, LeaseState


class CapabilityLeaseManager:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def grant(
        self,
        *,
        workflow_id: str,
        subject: str,
        capability: Capability,
        tool_name: str,
        seconds: int | None = None,
    ) -> LeaseRow:
        ttl = seconds or self.settings.lease_default_seconds
        row = LeaseRow(
            lease_id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            subject=subject,
            capability=capability.value,
            tool_name=tool_name,
            state=LeaseState.ACTIVE.value,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
        )
        self.session.add(row)
        self.session.commit()
        return row

    def active_lease(self, workflow_id: str, subject: str, capability: Capability) -> LeaseRow | None:
        now = datetime.now(timezone.utc)
        rows = (
            self.session.query(LeaseRow)
            .filter(
                LeaseRow.workflow_id == workflow_id,
                LeaseRow.subject == subject,
                LeaseRow.capability == capability.value,
                LeaseRow.state == LeaseState.ACTIVE.value,
            )
            .all()
        )
        for row in rows:
            if row.expires_at <= now:
                row.state = LeaseState.EXPIRED.value
                self.session.add(row)
                self.session.commit()
                continue
            remaining = (row.expires_at - now).total_seconds()
            if remaining <= 15:
                row.state = LeaseState.EXPIRING.value
                self.session.add(row)
                self.session.commit()
            return row
        return None

    def revoke(self, lease_id: str, reason: str) -> None:
        row = self.session.get(LeaseRow, lease_id)
        if row:
            row.state = LeaseState.REVOKED.value
            row.revoked_reason = reason
            self.session.add(row)
            self.session.commit()

    def revoke_workflow(self, workflow_id: str, reason: str) -> int:
        rows = (
            self.session.query(LeaseRow)
            .filter(LeaseRow.workflow_id == workflow_id, LeaseRow.state.in_([LeaseState.ACTIVE.value, LeaseState.EXPIRING.value]))
            .all()
        )
        for row in rows:
            row.state = LeaseState.REVOKED.value
            row.revoked_reason = reason
            self.session.add(row)
        self.session.commit()
        return len(rows)

    def expire_due(self) -> int:
        now = datetime.now(timezone.utc)
        rows = (
            self.session.query(LeaseRow)
            .filter(LeaseRow.state.in_([LeaseState.ACTIVE.value, LeaseState.EXPIRING.value]), LeaseRow.expires_at <= now)
            .all()
        )
        for row in rows:
            row.state = LeaseState.EXPIRED.value
            self.session.add(row)
        self.session.commit()
        return len(rows)
