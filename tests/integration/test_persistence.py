"""
Integration Tests for SQLite Persistence and Repositories.
"""
import tempfile
from pathlib import Path
from netcutter.domain.models import (
    Device,
    DevicePolicyState,
    GatewayConfig,
    InternetAccessState,
)
from netcutter.domain.events import AuditAction, AuditEvent
from netcutter.persistence.database import Database
from netcutter.persistence.repository import (
    AuditRepository,
    DeviceRepository,
    GatewayRepository,
)


def test_device_repository_crud():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "test.db")
        db = Database(db_path)
        repo = DeviceRepository(db)

        dev = Device(
            display_name="Test Phone",
            primary_mac="00:11:22:33:44:55",
            ipv4_addresses=["192.168.1.150"],
            ipv6_addresses=["fe80::1"],
            hostname="test-phone-lan",
        )
        repo.upsert(dev)

        # Retrieve by GUID
        fetched = repo.get_by_guid(dev.device_guid)
        assert fetched is not None
        assert fetched.display_name == "Test Phone"
        assert fetched.primary_mac == "00:11:22:33:44:55"

        # Retrieve by MAC
        by_mac = repo.get_by_mac("00:11:22:33:44:55")
        assert by_mac is not None
        assert by_mac.device_guid == dev.device_guid

        # Update policy
        dev.desired_policy.internet_access = InternetAccessState.BLOCKED
        dev.desired_policy.download_limit_kbps = 5120
        repo.upsert(dev)

        updated = repo.get_by_guid(dev.device_guid)
        assert updated.desired_policy.internet_access == InternetAccessState.BLOCKED
        assert updated.desired_policy.download_limit_kbps == 5120

        # Delete
        repo.delete(dev.device_guid)
        assert repo.get_by_guid(dev.device_guid) is None


def test_gateway_and_audit_repositories():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "test.db")
        db = Database(db_path)
        gw_repo = GatewayRepository(db)
        audit_repo = AuditRepository(db)

        gw = GatewayConfig(name="OpenWrt Primary", host="192.168.1.1")
        gw_repo.upsert(gw)

        all_gws = gw_repo.get_all()
        assert len(all_gws) == 1
        assert all_gws[0].name == "OpenWrt Primary"

        audit_repo.add(
            AuditEvent(
                action=AuditAction.BLOCK_DEVICE,
                device_name="Test Phone",
                details="Blocked test phone",
            )
        )
        events = audit_repo.get_recent(10)
        assert len(events) == 1
        assert events[0].action == AuditAction.BLOCK_DEVICE
