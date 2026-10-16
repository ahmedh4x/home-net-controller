"""
Unit tests for NotificationService, HealthMonitoringService, and Safe Mode lockdown.
"""
from pathlib import Path
from netcutter.persistence.database import Database
from netcutter.persistence.repository import GatewayRepository, NotificationRepository
from netcutter.persistence.secret_store import SecretStore
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.health_service import HealthMonitoringService
from netcutter.services.notification_service import NotificationCategory, NotificationService


def test_notification_posting_and_deduplication(tmp_path: Path):
    db_file = str(tmp_path / "test_notif.db")
    db = Database(db_file)
    repo = NotificationRepository(db)
    service = NotificationService(repo)

    toast_received = []
    service.add_toast_listener(lambda t: toast_received.append(t))

    # Post initial notification
    n1 = service.post(
        category=NotificationCategory.SUCCESS,
        title="Gateway Connected",
        message="Connected to OpenWrt router successfully",
    )
    assert len(toast_received) == 1
    assert service.get_unread_count() == 1

    # Rapid duplicate within 3 seconds should be suppressed
    n2 = service.post(
        category=NotificationCategory.SUCCESS,
        title="Gateway Connected",
        message="Connected to OpenWrt router successfully",
    )
    # Should not add a duplicate toast
    assert len(toast_received) == 1

    # Mark as read
    service.mark_read(n1.notification_id)
    assert service.get_unread_count() == 0


def test_health_monitoring_and_safe_mode(tmp_path: Path):
    db_file = str(tmp_path / "test_health.db")
    db = Database(db_file)
    gw_repo = GatewayRepository(db)
    secret_store = SecretStore()
    gw_manager = GatewayManager(db, gw_repo, secret_store)

    health_svc = HealthMonitoringService(db, gw_manager)

    # Initial state should allow mutations
    allowed, reason = health_svc.is_mutation_allowed()
    assert allowed
    assert reason is None

    # Enter Safe Mode
    health_svc.enter_safe_mode("Simulated critical error")
    assert health_svc.is_safe_mode

    # Mutation should be blocked
    allowed, reason = health_svc.is_mutation_allowed()
    assert not allowed
    assert "Safe Mode" in reason

    # Exit Safe Mode
    ok, msg = health_svc.exit_safe_mode()
    assert ok
    assert not health_svc.is_safe_mode
    allowed, _ = health_svc.is_mutation_allowed()
    assert allowed
