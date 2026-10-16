"""
Policy Enforcement Service.
Coordinates policy application, state verification, invariant enforcement, and audit logging.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

from netcutter.backends.base import IGatewayBackend, PolicyExecutionResult
from netcutter.domain.events import AuditAction, AuditEvent
from netcutter.domain.models import (
    Device,
    InternetAccessState,
    PolicyStatus,
)
from netcutter.domain.state_engine import (
    EnforcementState,
    NetworkStateEngine,
    OperationState,
)
from netcutter.persistence.repository import AuditRepository, DeviceRepository
from netcutter.services.gateway_manager import GatewayManager

logger = logging.getLogger("netcutter.services.policy")


class PolicyService:
    def __init__(
        self,
        device_repo: DeviceRepository,
        audit_repo: AuditRepository,
        gateway_manager: GatewayManager,
        notification_service=None,
        health_service=None,
    ):
        self.device_repo = device_repo
        self.audit_repo = audit_repo
        self.gateway_manager = gateway_manager
        self.notification_service = notification_service
        self.health_service = health_service

    def _check_safe_mode(self, operation: str) -> Optional[PolicyExecutionResult]:
        if self.health_service:
            allowed, reason = self.health_service.is_mutation_allowed()
            if not allowed:
                err_msg = f"Operation '{operation}' rejected: {reason}"
                logger.warning(err_msg)
                if self.notification_service:
                    from netcutter.services.notification_service import NotificationCategory
                    self.notification_service.post(
                        category=NotificationCategory.WARNING,
                        title="Safe Mode Protected",
                        message=err_msg,
                    )
                return PolicyExecutionResult(success=False, operation=operation, error=err_msg)
        return None

    def block_device(self, device_guid: str) -> PolicyExecutionResult:
        guard_res = self._check_safe_mode("BLOCK")
        if guard_res:
            return guard_res

        device = self.device_repo.get_by_guid(device_guid)
        if not device:
            return PolicyExecutionResult(
                success=False, operation="BLOCK", error=f"Device {device_guid} not found"
            )

        backend = self.gateway_manager.get_active_backend()
        if not backend or not backend.is_connected():
            device.policy_status = PolicyStatus.BACKEND_UNAVAILABLE
            device.last_policy_error = "Gateway backend is offline or disconnected"
            self.device_repo.upsert(device)
            return PolicyExecutionResult(
                success=False, operation="BLOCK", error="Gateway backend is offline"
            )

        # Mark desired state
        device.desired_policy.internet_access = InternetAccessState.BLOCKED
        device.policy_status = PolicyStatus.APPLYING
        self.device_repo.upsert(device)

        # Execute on gateway
        all_ips = device.ipv4_addresses + device.ipv6_addresses
        res = backend.block_device(device.primary_mac, all_ips)

        now = datetime.now(timezone.utc)
        if res.success and res.verification_verified:
            device.observed_policy.internet_access = InternetAccessState.BLOCKED
            device.policy_status = PolicyStatus.SYNCHRONIZED
            device.last_policy_error = None
            device.last_sync = now
            status_str = "SUCCESS"
            if self.notification_service:
                from netcutter.services.notification_service import NotificationCategory
                self.notification_service.post(
                    category=NotificationCategory.SUCCESS,
                    title="Device Blocked",
                    message=f"Access blocked for '{device.display_name}' ({device.primary_mac})",
                    related_guid=device.device_guid,
                )
        else:
            device.policy_status = PolicyStatus.FAILED
            device.last_policy_error = res.error or "Verification check failed on gateway"
            status_str = "FAILED"
            if self.notification_service:
                from netcutter.services.notification_service import NotificationCategory
                self.notification_service.post(
                    category=NotificationCategory.ERROR,
                    title="Block Failed",
                    message=f"Failed to block '{device.display_name}': {device.last_policy_error}",
                    related_guid=device.device_guid,
                )

        self.device_repo.upsert(device)

        # Record Audit Event
        self.audit_repo.add(
            AuditEvent(
                action=AuditAction.BLOCK_DEVICE,
                device_guid=device.device_guid,
                device_name=device.display_name,
                gateway_id=self.gateway_manager.get_active_config().gateway_id
                if self.gateway_manager.get_active_config()
                else None,
                details=f"Block Internet access for {device.display_name} ({device.primary_mac}). Details: {res.details}",
                status=status_str,
                error=res.error,
            )
        )
        return res

    def unblock_device(self, device_guid: str) -> PolicyExecutionResult:
        guard_res = self._check_safe_mode("UNBLOCK")
        if guard_res:
            return guard_res

        device = self.device_repo.get_by_guid(device_guid)
        if not device:
            return PolicyExecutionResult(
                success=False, operation="UNBLOCK", error=f"Device {device_guid} not found"
            )

        backend = self.gateway_manager.get_active_backend()
        if not backend or not backend.is_connected():
            device.policy_status = PolicyStatus.BACKEND_UNAVAILABLE
            device.last_policy_error = "Gateway backend is offline or disconnected"
            self.device_repo.upsert(device)
            return PolicyExecutionResult(
                success=False, operation="UNBLOCK", error="Gateway backend is offline"
            )

        # Mark desired state
        device.desired_policy.internet_access = InternetAccessState.ALLOWED
        device.policy_status = PolicyStatus.APPLYING
        self.device_repo.upsert(device)

        all_ips = device.ipv4_addresses + device.ipv6_addresses
        res = backend.unblock_device(device.primary_mac, all_ips)

        now = datetime.now(timezone.utc)
        if res.success and res.verification_verified:
            device.observed_policy.internet_access = InternetAccessState.ALLOWED
            device.policy_status = PolicyStatus.SYNCHRONIZED
            device.last_policy_error = None
            device.last_sync = now
            status_str = "SUCCESS"
            if self.notification_service:
                from netcutter.services.notification_service import NotificationCategory
                self.notification_service.post(
                    category=NotificationCategory.SUCCESS,
                    title="Device Unblocked",
                    message=f"Access restored for '{device.display_name}' ({device.primary_mac})",
                    related_guid=device.device_guid,
                )
        else:
            device.policy_status = PolicyStatus.FAILED
            device.last_policy_error = res.error or "Verification check failed on gateway"
            status_str = "FAILED"
            if self.notification_service:
                from netcutter.services.notification_service import NotificationCategory
                self.notification_service.post(
                    category=NotificationCategory.ERROR,
                    title="Unblock Failed",
                    message=f"Failed to unblock '{device.display_name}': {device.last_policy_error}",
                    related_guid=device.device_guid,
                )

        self.device_repo.upsert(device)

        self.audit_repo.add(
            AuditEvent(
                action=AuditAction.UNBLOCK_DEVICE,
                device_guid=device.device_guid,
                device_name=device.display_name,
                gateway_id=self.gateway_manager.get_active_config().gateway_id
                if self.gateway_manager.get_active_config()
                else None,
                details=f"Unblock Internet access for {device.display_name} ({device.primary_mac}). Details: {res.details}",
                status=status_str,
                error=res.error,
            )
        )
        return res

    def set_bandwidth_limits(
        self, device_guid: str, dl_kbps: int, ul_kbps: int
    ) -> PolicyExecutionResult:
        guard_res = self._check_safe_mode("SET_BANDWIDTH")
        if guard_res:
            return guard_res

        device = self.device_repo.get_by_guid(device_guid)
        if not device:
            return PolicyExecutionResult(
                success=False, operation="SET_BANDWIDTH", error=f"Device {device_guid} not found"
            )

        if dl_kbps < 0 or ul_kbps < 0:
            return PolicyExecutionResult(
                success=False, operation="SET_BANDWIDTH", error="Bandwidth rates cannot be negative"
            )

        backend = self.gateway_manager.get_active_backend()
        if not backend or not backend.is_connected():
            device.policy_status = PolicyStatus.BACKEND_UNAVAILABLE
            device.last_policy_error = "Gateway backend is offline"
            self.device_repo.upsert(device)
            return PolicyExecutionResult(
                success=False, operation="SET_BANDWIDTH", error="Gateway backend is offline"
            )

        from netcutter.backends.capabilities import BackendCapabilities
        if (
            BackendCapabilities.UPLOAD_SHAPING not in backend.capabilities
            and BackendCapabilities.DOWNLOAD_SHAPING not in backend.capabilities
        ):
            device.policy_status = PolicyStatus.FAILED
            device.last_policy_error = "Bandwidth shaping is not supported by the active backend mode."
            self.device_repo.upsert(device)
            err_msg = "Bandwidth shaping is not supported in Off-Path mode. Bandwidth QoS requires a Gateway-Native backend."
            if self.notification_service:
                from netcutter.services.notification_service import NotificationCategory
                self.notification_service.post(
                    category=NotificationCategory.WARNING,
                    title="Shaping Unsupported",
                    message=err_msg,
                    related_guid=device.device_guid,
                )
            return PolicyExecutionResult(
                success=False,
                operation="SET_BANDWIDTH",
                error=err_msg,
            )

        device.desired_policy.download_limit_kbps = dl_kbps
        device.desired_policy.upload_limit_kbps = ul_kbps
        device.policy_status = PolicyStatus.APPLYING
        self.device_repo.upsert(device)

        all_ips = device.ipv4_addresses + device.ipv6_addresses
        res = backend.set_bandwidth_limit(device.primary_mac, all_ips, dl_kbps, ul_kbps)

        now = datetime.now(timezone.utc)
        if res.success and res.verification_verified:
            device.observed_policy.download_limit_kbps = dl_kbps
            device.observed_policy.upload_limit_kbps = ul_kbps
            device.policy_status = PolicyStatus.SYNCHRONIZED
            device.last_policy_error = None
            device.last_sync = now
            status_str = "SUCCESS"
            if self.notification_service:
                from netcutter.services.notification_service import NotificationCategory
                self.notification_service.post(
                    category=NotificationCategory.SUCCESS,
                    title="Bandwidth Limit Set",
                    message=f"Limits configured for '{device.display_name}': DL {dl_kbps}k / UL {ul_kbps}k",
                    related_guid=device.device_guid,
                )
        else:
            device.policy_status = PolicyStatus.FAILED
            device.last_policy_error = res.error or "Verification check failed on gateway"
            status_str = "FAILED"
            if self.notification_service:
                from netcutter.services.notification_service import NotificationCategory
                self.notification_service.post(
                    category=NotificationCategory.ERROR,
                    title="Bandwidth Config Failed",
                    message=f"Failed to set limits for '{device.display_name}': {device.last_policy_error}",
                    related_guid=device.device_guid,
                )

        self.device_repo.upsert(device)

        self.audit_repo.add(
            AuditEvent(
                action=AuditAction.SET_DOWNLOAD_LIMIT if dl_kbps > 0 else AuditAction.SET_UPLOAD_LIMIT,
                device_guid=device.device_guid,
                device_name=device.display_name,
                gateway_id=self.gateway_manager.get_active_config().gateway_id
                if self.gateway_manager.get_active_config()
                else None,
                details=f"Configured Bandwidth Limits: DL={dl_kbps} Kbps, UL={ul_kbps} Kbps for {device.display_name}",
                status=status_str,
                error=res.error,
            )
        )
        return res

    def remove_bandwidth_limits(self, device_guid: str) -> PolicyExecutionResult:
        guard_res = self._check_safe_mode("REMOVE_BANDWIDTH")
        if guard_res:
            return guard_res

        device = self.device_repo.get_by_guid(device_guid)
        if not device:
            return PolicyExecutionResult(
                success=False, operation="REMOVE_BANDWIDTH", error=f"Device {device_guid} not found"
            )

        backend = self.gateway_manager.get_active_backend()
        if not backend or not backend.is_connected():
            return PolicyExecutionResult(
                success=False, operation="REMOVE_BANDWIDTH", error="Gateway backend is offline"
            )

        device.desired_policy.download_limit_kbps = 0
        device.desired_policy.upload_limit_kbps = 0
        device.policy_status = PolicyStatus.APPLYING
        self.device_repo.upsert(device)

        all_ips = device.ipv4_addresses + device.ipv6_addresses
        res = backend.remove_bandwidth_limit(device.primary_mac, all_ips)

        now = datetime.now(timezone.utc)
        if res.success and res.verification_verified:
            device.observed_policy.download_limit_kbps = 0
            device.observed_policy.upload_limit_kbps = 0
            device.policy_status = PolicyStatus.SYNCHRONIZED
            device.last_policy_error = None
            device.last_sync = now
            status_str = "SUCCESS"
            if self.notification_service:
                from netcutter.services.notification_service import NotificationCategory
                self.notification_service.post(
                    category=NotificationCategory.INFO,
                    title="Bandwidth Limit Removed",
                    message=f"Limits removed for '{device.display_name}'",
                    related_guid=device.device_guid,
                )
        else:
            device.policy_status = PolicyStatus.FAILED
            device.last_policy_error = res.error
            status_str = "FAILED"

        self.device_repo.upsert(device)

        self.audit_repo.add(
            AuditEvent(
                action=AuditAction.REMOVE_LIMIT,
                device_guid=device.device_guid,
                device_name=device.display_name,
                gateway_id=self.gateway_manager.get_active_config().gateway_id
                if self.gateway_manager.get_active_config()
                else None,
                details=f"Removed bandwidth limits for {device.display_name}",
                status=status_str,
                error=res.error,
            )
        )
        return res
