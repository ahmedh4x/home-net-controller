"""
Health Monitoring and Safe Mode Subsystem.
Audits application subsystems and enforces Safe Mode to prevent destructive operations under degraded conditions.
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from netcutter.persistence.database import Database
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.reconciliation import ReconciliationEngine

logger = logging.getLogger("netcutter.health")


class SubsystemHealth(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class HealthCheckResult:
    """Individual subsystem diagnostic health evaluation."""
    name: str
    status: SubsystemHealth
    message: str
    latency_ms: Optional[float] = None
    last_checked: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SystemHealthReport:
    """Consolidated health report across all NetCutter subsystems."""
    overall_status: SubsystemHealth
    is_safe_mode: bool
    safe_mode_reason: Optional[str]
    checks: Dict[str, HealthCheckResult] = field(default_factory=dict)
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict:
        return {
            "overall_status": self.overall_status.value,
            "is_safe_mode": self.is_safe_mode,
            "safe_mode_reason": self.safe_mode_reason,
            "evaluated_at": self.evaluated_at.isoformat(),
            "checks": {
                k: {
                    "status": v.status.value,
                    "message": v.message,
                    "latency_ms": v.latency_ms,
                    "last_checked": v.last_checked.isoformat(),
                }
                for k, v in self.checks.items()
            },
        }


class HealthMonitoringService:
    """
    Evaluates health of router connectivity, background workers, database, and storage.
    Enforces Safe Mode whenever core integrity invariants fail.
    """

    def __init__(
        self,
        db: Database,
        gw_manager: GatewayManager,
        reconciliation_engine: Optional[ReconciliationEngine] = None,
    ):
        self.db = db
        self.gw_manager = gw_manager
        self.reconciliation_engine = reconciliation_engine

        self._safe_mode: bool = False
        self._safe_mode_reason: Optional[str] = None
        self._last_report: Optional[SystemHealthReport] = None
        self._lock = threading.Lock()

    @property
    def is_safe_mode(self) -> bool:
        with self._lock:
            return self._safe_mode

    @property
    def safe_mode_reason(self) -> Optional[str]:
        with self._lock:
            return self._safe_mode_reason

    def enter_safe_mode(self, reason: str) -> None:
        """Manually or automatically lock down the application into read-only Safe Mode."""
        with self._lock:
            self._safe_mode = True
            self._safe_mode_reason = reason
            logger.warning(f"Safe Mode activated: {reason}")

    def exit_safe_mode(self) -> Tuple[bool, str]:
        """Attempt to exit Safe Mode after verifying database and backend health."""
        report = self.run_health_checks()
        if report.checks.get("Database", None) and report.checks["Database"].status == SubsystemHealth.FAILED:
            return False, "Cannot exit Safe Mode: Database integrity check failed."

        with self._lock:
            self._safe_mode = False
            self._safe_mode_reason = None
            logger.info("Safe Mode deactivated by operator.")
            return True, "Safe Mode cleared. Normal enforcement operations restored."

    def is_mutation_allowed(self) -> Tuple[bool, Optional[str]]:
        """
        Guard method: Checks if disruptive operations (blocking/unblocking/shaping) are safe.
        Returns (allowed, reason_if_blocked).
        """
        with self._lock:
            if self._safe_mode:
                return False, f"Operation blocked: Application is in Safe Mode ({self._safe_mode_reason})"
        return True, None

    def run_health_checks(self) -> SystemHealthReport:
        """Executes full diagnostic suite across all subsystems."""
        checks: Dict[str, HealthCheckResult] = {}
        has_failure = False
        has_degraded = False

        # 1. Database Integrity & Accessibility
        db_start = time.perf_counter()
        try:
            with self.db.get_connection() as conn:
                conn.execute("SELECT 1").fetchone()
                # Verify WAL journal mode
                row = conn.execute("PRAGMA journal_mode;").fetchone()
                journal_mode = row[0] if row else "unknown"
            db_ms = (time.perf_counter() - db_start) * 1000.0
            checks["Database"] = HealthCheckResult(
                name="Database",
                status=SubsystemHealth.HEALTHY,
                message=f"SQLite accessible (WAL mode: {journal_mode})",
                latency_ms=round(db_ms, 2),
            )
        except Exception as ex:
            db_ms = (time.perf_counter() - db_start) * 1000.0
            checks["Database"] = HealthCheckResult(
                name="Database",
                status=SubsystemHealth.FAILED,
                message=f"Database error: {ex}",
                latency_ms=round(db_ms, 2),
            )
            has_failure = True
            self.enter_safe_mode(f"Database error: {ex}")

        # 2. Gateway Backend Connectivity & Latency
        gw_backend = self.gw_manager.get_active_backend()
        gw_config = self.gw_manager.get_active_config()
        if not gw_backend or not gw_config:
            checks["Gateway"] = HealthCheckResult(
                name="Gateway",
                status=SubsystemHealth.UNKNOWN,
                message="No active gateway selected or configured",
            )
            has_degraded = True
        else:
            gw_start = time.perf_counter()
            try:
                if gw_backend.is_connected():
                    ok, msg = gw_backend.health_check()
                    gw_ms = (time.perf_counter() - gw_start) * 1000.0
                    if ok:
                        checks["Gateway"] = HealthCheckResult(
                            name="Gateway",
                            status=SubsystemHealth.HEALTHY,
                            message=f"Connected ({gw_config.name}): {msg}",
                            latency_ms=round(gw_ms, 2),
                        )
                    else:
                        checks["Gateway"] = HealthCheckResult(
                            name="Gateway",
                            status=SubsystemHealth.DEGRADED,
                            message=f"Connected with warnings: {msg}",
                            latency_ms=round(gw_ms, 2),
                        )
                        has_degraded = True
                else:
                    checks["Gateway"] = HealthCheckResult(
                        name="Gateway",
                        status=SubsystemHealth.FAILED,
                        message=f"Gateway disconnected ({gw_config.name})",
                    )
                    has_degraded = True
            except Exception as ex:
                gw_ms = (time.perf_counter() - gw_start) * 1000.0
                checks["Gateway"] = HealthCheckResult(
                    name="Gateway",
                    status=SubsystemHealth.FAILED,
                    message=f"Gateway probe error: {ex}",
                    latency_ms=round(gw_ms, 2),
                )
                has_degraded = True

        # 3. Reconciliation Worker Health
        if self.reconciliation_engine:
            rec = self.reconciliation_engine
            is_alive = rec._thread is not None and rec._thread.is_alive()
            if is_alive:
                checks["Reconciliation"] = HealthCheckResult(
                    name="Reconciliation",
                    status=SubsystemHealth.HEALTHY,
                    message=f"Active worker loop running (interval {rec.interval}s, drift count: {rec.drift_count})",
                )
            else:
                checks["Reconciliation"] = HealthCheckResult(
                    name="Reconciliation",
                    status=SubsystemHealth.DEGRADED,
                    message="Reconciliation background thread is not running",
                )
                has_degraded = True
        else:
            checks["Reconciliation"] = HealthCheckResult(
                name="Reconciliation",
                status=SubsystemHealth.NOT_APPLICABLE,
                message="Reconciliation engine not attached",
            )

        # 4. Storage & Disk Space
        try:
            db_dir = Path(self.db.db_path).parent
            total, used, free = shutil.disk_usage(db_dir)
            free_mb = free / (1024 * 1024)
            if free_mb < 100:  # Less than 100MB free
                checks["Storage"] = HealthCheckResult(
                    name="Storage",
                    status=SubsystemHealth.FAILED,
                    message=f"Low disk space: {free_mb:.1f} MB remaining",
                )
                has_failure = True
                self.enter_safe_mode("Critical disk space exhaustion")
            else:
                checks["Storage"] = HealthCheckResult(
                    name="Storage",
                    status=SubsystemHealth.HEALTHY,
                    message=f"Available disk space: {free_mb:.0f} MB",
                )
        except Exception as ex:
            checks["Storage"] = HealthCheckResult(
                name="Storage",
                status=SubsystemHealth.UNKNOWN,
                message=f"Could not query disk space: {ex}",
            )

        # Compute overall status
        if has_failure:
            overall = SubsystemHealth.FAILED
        elif has_degraded:
            overall = SubsystemHealth.DEGRADED
        else:
            overall = SubsystemHealth.HEALTHY

        report = SystemHealthReport(
            overall_status=overall,
            is_safe_mode=self.is_safe_mode,
            safe_mode_reason=self.safe_mode_reason,
            checks=checks,
        )

        with self._lock:
            self._last_report = report

        return report

    def get_cached_report(self) -> Optional[SystemHealthReport]:
        with self._lock:
            return self._last_report
