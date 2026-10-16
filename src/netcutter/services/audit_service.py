"""
Audit Service.
"""
from __future__ import annotations

from typing import List
from netcutter.domain.events import AuditAction, AuditEvent
from netcutter.persistence.repository import AuditRepository


class AuditService:
    def __init__(self, audit_repo: AuditRepository):
        self.audit_repo = audit_repo

    def get_recent_events(self, limit: int = 100) -> List[AuditEvent]:
        return self.audit_repo.get_recent(limit)

    def log_event(
        self,
        action: AuditAction,
        details: str,
        device_guid: str = None,
        device_name: str = None,
        status: str = "SUCCESS",
        error: str = None,
    ) -> None:
        self.audit_repo.add(
            AuditEvent(
                action=action,
                device_guid=device_guid,
                device_name=device_name,
                details=details,
                status=status,
                error=error,
            )
        )
