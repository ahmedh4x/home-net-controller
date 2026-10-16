"""
Continuous State Reconciliation Service.
Monitors Desired State vs Observed State, flags drift, and executes idempotent re-application.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from netcutter.domain.events import AuditAction, AuditEvent
from netcutter.domain.models import Device, PolicyStatus
from netcutter.domain.policy import calculate_policy_diff
from netcutter.persistence.repository import AuditRepository, DeviceRepository
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.policy_service import PolicyService

logger = logging.getLogger("netcutter.reconciliation")


class ReconciliationEngine:
    def __init__(
        self,
        device_repo: DeviceRepository,
        audit_repo: AuditRepository,
        gateway_manager: GatewayManager,
        policy_service: PolicyService,
        reconcile_interval_seconds: int = 30,
        notification_service=None,
        health_service=None,
    ):
        self.device_repo = device_repo
        self.audit_repo = audit_repo
        self.gateway_manager = gateway_manager
        self.policy_service = policy_service
        self.interval = reconcile_interval_seconds
        self.notification_service = notification_service
        self.health_service = health_service

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.last_reconciliation_time: Optional[datetime] = None
        self.drift_count: int = 0

    def start(self) -> None:
        """Start the background reconciliation loop."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="NetCutter-Reconcile-Worker", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the background loop to stop and wait for termination."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.reconcile_once()
            except Exception as ex:
                logger.error(f"Reconciliation iteration error: {ex}")
            self._stop_event.wait(self.interval)

    def reconcile_once(self) -> Dict[str, str]:
        """
        Executes a single pass over all devices:
        1. Queries backend observed state
        2. Diffs against desired state
        3. Re-applies desired policies if drift is detected (unless in Safe Mode)
        """
        if self.health_service and self.health_service.is_safe_mode:
            logger.info("Reconciliation pass skipped: Application is in Safe Mode")
            return {"status": "SAFE_MODE_ACTIVE"}

        backend = self.gateway_manager.get_active_backend()
        if not backend or not backend.is_connected():
            return {"status": "BACKEND_OFFLINE"}

        results = {}
        devices = self.device_repo.get_all()
        detected_drifts = 0
        now = datetime.now(timezone.utc)

        for dev in devices:
            try:
                # Re-fetch fresh copy to avoid overwriting concurrent UI clicks
                fresh_dev = self.device_repo.get_by_guid(dev.device_guid)
                if not fresh_dev:
                    continue

                all_ips = fresh_dev.ipv4_addresses + fresh_dev.ipv6_addresses
                obs = backend.query_observed_state(fresh_dev.primary_mac, all_ips)
                fresh_dev.observed_policy = obs.to_policy_state()
                fresh_dev.last_sync = now

                diff = calculate_policy_diff(fresh_dev.desired_policy, fresh_dev.observed_policy)
                if diff.has_drift:
                    detected_drifts += 1
                    fresh_dev.policy_status = PolicyStatus.DRIFTED
                    self.device_repo.upsert(fresh_dev)

                    # Log drift
                    self.audit_repo.add(
                        AuditEvent(
                            action=AuditAction.POLICY_DRIFT_DETECTED,
                            device_guid=fresh_dev.device_guid,
                            device_name=fresh_dev.display_name,
                            details=f"Drift detected for {fresh_dev.display_name}: {diff.describe()}",
                            status="WARNING",
                        )
                    )

                    if self.notification_service:
                        from netcutter.services.notification_service import NotificationCategory
                        self.notification_service.post(
                            category=NotificationCategory.WARNING,
                            title="Policy Drift Detected",
                            message=f"Drift on '{fresh_dev.display_name}': {diff.describe()}",
                            related_guid=fresh_dev.device_guid,
                        )

                    # Auto-reconcile to desired policy
                    if diff.needs_block:
                        self.policy_service.block_device(fresh_dev.device_guid)
                    elif diff.needs_unblock:
                        self.policy_service.unblock_device(fresh_dev.device_guid)

                    if diff.needs_download_update or diff.needs_upload_update:
                        self.policy_service.set_bandwidth_limits(
                            fresh_dev.device_guid,
                            fresh_dev.desired_policy.download_limit_kbps,
                            fresh_dev.desired_policy.upload_limit_kbps,
                        )
                    elif diff.needs_download_remove and diff.needs_upload_remove:
                        self.policy_service.remove_bandwidth_limits(fresh_dev.device_guid)

                    self.audit_repo.add(
                        AuditEvent(
                            action=AuditAction.POLICY_RECONCILED,
                            device_guid=fresh_dev.device_guid,
                            device_name=fresh_dev.display_name,
                            details=f"Auto-reconciled {fresh_dev.display_name} to Desired Policy",
                            status="SUCCESS",
                        )
                    )
                    results[fresh_dev.device_guid] = "RECONCILED"
                else:
                    if fresh_dev.policy_status != PolicyStatus.SYNCHRONIZED:
                        fresh_dev.policy_status = PolicyStatus.SYNCHRONIZED
                        self.device_repo.upsert(fresh_dev)
                    results[fresh_dev.device_guid] = "SYNCHRONIZED"
            except Exception as ex:
                results[dev.device_guid] = f"ERROR: {ex}"

        self.drift_count = detected_drifts
        self.last_reconciliation_time = now
        return results
