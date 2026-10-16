"""
Domain Blocking Service for NetCutter.
Orchestrates domain rule validation, persistence, router/interceptor enforcement,
verification audits, and audit logging for blocked domain queries.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from netcutter.backends.base import IGatewayBackend, PolicyExecutionResult
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.domain_validator import is_domain_match, normalize_domain, validate_domain
from netcutter.domain.models import (
    BlockedDomainEvent,
    DomainBlockingRule,
    DomainEnforcementStatus,
    DomainMatchType,
    DomainScope,
)
from netcutter.persistence.database import Database
from netcutter.persistence.repository import DomainBlockingRepository

logger = logging.getLogger("netcutter.services.domain_blocking")


class DomainBlockingService:
    def __init__(
        self,
        db: Database,
        gateway_manager=None,
        device_service=None,
        repo: Optional[DomainBlockingRepository] = None,
    ):
        self.db = db
        self.gateway_manager = gateway_manager
        self.device_service = device_service
        self.repo = repo or DomainBlockingRepository(db)

        # Wire event listener callback into active backend if available
        self._hook_backend_callbacks()

    def _get_active_backend(self) -> Optional[IGatewayBackend]:
        if self.gateway_manager:
            try:
                return self.gateway_manager.get_active_backend()
            except Exception as ex:
                logger.debug(f"Error getting active backend: {ex}")
        return None

    def _hook_backend_callbacks(self) -> None:
        """Register domain event listener into active backend if supported."""
        backend = self._get_active_backend()
        if backend and hasattr(backend, "domain_event_callback"):
            backend.domain_event_callback = self.record_blocked_event

    def add_rule(
        self,
        raw_domain: str,
        match_type: DomainMatchType = DomainMatchType.SUBDOMAIN,
        target_scope: DomainScope = DomainScope.GLOBAL,
        target_device_guid: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Tuple[bool, Optional[DomainBlockingRule], Optional[str]]:
        """
        Validates, normalizes, persists, and enforces a domain blocking rule.
        """
        # 1. Validation & Normalization
        valid, err_msg, normalized = validate_domain(raw_domain)
        if not valid:
            return False, None, err_msg

        # 2. Scope validation
        target_device_name = None
        target_mac = None
        target_ip = None

        if target_scope == DomainScope.DEVICE:
            if not target_device_guid:
                return False, None, "A target device must be selected for device-specific domain rules."
            if self.device_service:
                dev = self.device_service.get_device_by_guid(target_device_guid)
                if not dev:
                    return False, None, f"Device with GUID '{target_device_guid}' not found."
                target_device_name = dev.display_name
                target_mac = dev.primary_mac
                target_ip = dev.primary_ipv4 if dev.ipv4_addresses else None

        # 3. Duplicate check
        existing_rules = self.repo.get_all_rules()
        for r in existing_rules:
            if r.domain == normalized and r.target_scope == target_scope:
                if target_scope == DomainScope.GLOBAL or r.target_device_guid == target_device_guid:
                    return False, None, f"A rule for domain '{normalized}' with {target_scope.value} scope already exists."

        # 4. Construct DomainBlockingRule
        now = datetime.now(timezone.utc)
        rule = DomainBlockingRule(
            domain=normalized,
            match_type=match_type,
            target_scope=target_scope,
            target_device_guid=target_device_guid,
            target_device_name=target_device_name,
            target_mac=target_mac,
            target_ip=target_ip,
            is_enabled=True,
            enforcement_status=DomainEnforcementStatus.PENDING,
            created_at=now,
            updated_at=now,
            notes=notes,
        )

        # 5. Persist to repository
        self.repo.upsert_rule(rule)

        # 6. Enforce via active backend
        backend = self._get_active_backend()
        if backend:
            self._hook_backend_callbacks()
            try:
                res: PolicyExecutionResult = backend.apply_domain_rule(rule)
                if res.success:
                    rule.enforcement_status = (
                        DomainEnforcementStatus.ACTIVE
                        if res.verification_verified
                        else DomainEnforcementStatus.PENDING
                    )
                    rule.last_error = None
                    rule.last_verified_at = now if res.verification_verified else None
                else:
                    rule.enforcement_status = DomainEnforcementStatus.FAILED
                    rule.last_error = res.error or "Failed to apply domain rule"
            except Exception as ex:
                rule.enforcement_status = DomainEnforcementStatus.FAILED
                rule.last_error = str(ex)
                logger.error(f"Error applying domain rule {rule.domain} to backend: {ex}")
        else:
            rule.enforcement_status = DomainEnforcementStatus.PENDING
            rule.last_error = "No active gateway connected"

        self.repo.upsert_rule(rule)
        return True, rule, None

    def update_rule(
        self,
        rule_id: str,
        is_enabled: Optional[bool] = None,
        match_type: Optional[DomainMatchType] = None,
        notes: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Update an existing rule's configuration or enabled state."""
        rule = self.repo.get_rule(rule_id)
        if not rule:
            return False, f"Rule with ID '{rule_id}' not found."

        if is_enabled is not None:
            rule.is_enabled = is_enabled
        if match_type is not None:
            rule.match_type = match_type
        if notes is not None:
            rule.notes = notes

        rule.updated_at = datetime.now(timezone.utc)

        backend = self._get_active_backend()
        if backend:
            if rule.is_enabled:
                res = backend.apply_domain_rule(rule)
                rule.enforcement_status = (
                    DomainEnforcementStatus.ACTIVE if res.success and res.verification_verified else DomainEnforcementStatus.PENDING
                )
                rule.last_error = res.error
            else:
                backend.remove_domain_rule(rule)
                rule.enforcement_status = DomainEnforcementStatus.PENDING
                rule.last_error = None

        self.repo.upsert_rule(rule)
        return True, None

    def delete_rule(self, rule_id: str) -> Tuple[bool, Optional[str]]:
        """Remove a domain rule from backend and database."""
        rule = self.repo.get_rule(rule_id)
        if not rule:
            return False, f"Rule with ID '{rule_id}' not found."

        backend = self._get_active_backend()
        if backend:
            try:
                backend.remove_domain_rule(rule)
            except Exception as ex:
                logger.warning(f"Error removing domain rule from backend: {ex}")

        deleted = self.repo.delete_rule(rule_id)
        return deleted, None

    def enable_rule(self, rule_id: str) -> Tuple[bool, Optional[str]]:
        return self.update_rule(rule_id, is_enabled=True)

    def disable_rule(self, rule_id: str) -> Tuple[bool, Optional[str]]:
        return self.update_rule(rule_id, is_enabled=False)

    def get_rules(
        self,
        search_query: str = "",
        scope: Optional[DomainScope] = None,
        status: Optional[DomainEnforcementStatus] = None,
    ) -> List[DomainBlockingRule]:
        rules = self.repo.get_all_rules()

        # Update live device names in case devices were renamed
        if self.device_service:
            for r in rules:
                if r.target_device_guid and not r.target_device_name:
                    dev = self.device_service.get_device_by_guid(r.target_device_guid)
                    if dev:
                        r.target_device_name = dev.display_name
                        r.target_ip = dev.primary_ipv4

        if search_query:
            q = search_query.strip().lower()
            rules = [
                r
                for r in rules
                if q in r.domain.lower()
                or (r.target_device_name and q in r.target_device_name.lower())
                or (r.target_ip and q in r.target_ip)
                or (r.notes and q in r.notes.lower())
            ]

        if scope:
            rules = [r for r in rules if r.target_scope == scope]

        if status:
            rules = [r for r in rules if r.enforcement_status == status]

        return rules

    def get_rule(self, rule_id: str) -> Optional[DomainBlockingRule]:
        return self.repo.get_rule(rule_id)

    def verify_rule(self, rule_id: str) -> Tuple[bool, str]:
        """Audit and verify live kernel / DNS state for a rule."""
        rule = self.repo.get_rule(rule_id)
        if not rule:
            return False, "Rule not found"

        if not rule.is_enabled:
            return True, "Rule is currently disabled (not enforced)"

        backend = self._get_active_backend()
        if not backend:
            rule.enforcement_status = DomainEnforcementStatus.PENDING
            rule.last_error = "Gateway backend is not connected"
            self.repo.upsert_rule(rule)
            return False, "Gateway is disconnected"

        success, details = backend.verify_domain_rule(rule)
        rule.last_verified_at = datetime.now(timezone.utc)
        if success:
            rule.enforcement_status = DomainEnforcementStatus.ACTIVE
            rule.last_error = None
        else:
            rule.enforcement_status = DomainEnforcementStatus.FAILED
            rule.last_error = details

        self.repo.upsert_rule(rule)
        return success, details

    def verify_all_rules(self) -> Dict[str, Tuple[bool, str]]:
        """Verify all enabled rules across backend."""
        results = {}
        for r in self.repo.get_all_rules():
            results[r.rule_id] = self.verify_rule(r.rule_id)
        return results

    def sync_all_rules(self) -> int:
        """Re-sync all enabled rules with the active gateway."""
        backend = self._get_active_backend()
        if not backend:
            return 0

        self._hook_backend_callbacks()
        synced = 0
        now = datetime.now(timezone.utc)
        for rule in self.repo.get_all_rules():
            if rule.is_enabled:
                res = backend.apply_domain_rule(rule)
                if res.success:
                    rule.enforcement_status = (
                        DomainEnforcementStatus.ACTIVE if res.verification_verified else DomainEnforcementStatus.PENDING
                    )
                    rule.last_error = None
                    rule.last_verified_at = now
                    synced += 1
                else:
                    rule.enforcement_status = DomainEnforcementStatus.FAILED
                    rule.last_error = res.error
                self.repo.upsert_rule(rule)
        return synced

    def record_blocked_event(self, event: BlockedDomainEvent) -> None:
        """Record an audit event and update hit counter on the matching rule."""
        self.repo.record_event(event)
        if event.rule_id:
            self.repo.increment_hits(event.rule_id, 1)

    def get_recent_events(self, limit: int = 100) -> List[BlockedDomainEvent]:
        return self.repo.get_recent_events(limit=limit)

    def clear_events(self) -> None:
        self.repo.clear_events()
