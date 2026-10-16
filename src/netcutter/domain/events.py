"""
Audit and Event Logging Domain Models.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class AuditAction(str, Enum):
    BLOCK_DEVICE = "BLOCK_DEVICE"
    UNBLOCK_DEVICE = "UNBLOCK_DEVICE"
    SET_DOWNLOAD_LIMIT = "SET_DOWNLOAD_LIMIT"
    SET_UPLOAD_LIMIT = "SET_UPLOAD_LIMIT"
    REMOVE_LIMIT = "REMOVE_LIMIT"
    DEVICE_MERGED = "DEVICE_MERGED"
    DEVICE_SPLIT = "DEVICE_SPLIT"
    GATEWAY_CONNECTED = "GATEWAY_CONNECTED"
    GATEWAY_DISCONNECTED = "GATEWAY_DISCONNECTED"
    POLICY_DRIFT_DETECTED = "POLICY_DRIFT_DETECTED"
    POLICY_RECONCILED = "POLICY_RECONCILED"
    GATEWAY_HEALTH_CHECK = "GATEWAY_HEALTH_CHECK"


@dataclass
class AuditEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: AuditAction = AuditAction.BLOCK_DEVICE
    device_guid: Optional[str] = None
    device_name: Optional[str] = None
    gateway_id: Optional[str] = None
    details: str = ""
    status: str = "SUCCESS"  # SUCCESS, FAILED, WARNING
    error: Optional[str] = None
