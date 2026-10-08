from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from sentinel.db import EventRow, ReceiptRow
from sentinel.types import utcnow


class AuditStore:
    def __init__(self, session: Session) -> None:
        self.session = session

    def write_receipt(self, payload: dict[str, Any]) -> ReceiptRow:
        row = ReceiptRow(
            receipt_id=str(uuid.uuid4()),
            workflow_id=payload.get("workflow_id", ""),
            identity=payload.get("identity", ""),
            agent=payload.get("agent", ""),
            server=payload.get("server", ""),
            tool=payload.get("tool", ""),
            decision=payload.get("decision", ""),
            risk_score=int(payload.get("risk_score") or 0),
            state=payload.get("state", ""),
            reasons=payload.get("reasons") or [],
            previous_tools=payload.get("previous_tools") or [],
            payload=payload,
            timestamp=utcnow(),
        )
        self.session.add(row)
        self.session.commit()
        return row

    def write_event(self, event_type: str, severity: str, message: str, details: dict[str, Any] | None = None) -> EventRow:
        row = EventRow(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            message=message,
            details=details or {},
            timestamp=utcnow(),
        )
        self.session.add(row)
        self.session.commit()
        return row
