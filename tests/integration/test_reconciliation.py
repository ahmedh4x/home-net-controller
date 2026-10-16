"""
Integration Tests for State Reconciliation and Drift Recovery.
"""
import tempfile
from pathlib import Path
from netcutter.backends.mock_backend import MockGatewayBackend
from netcutter.domain.models import Device, InternetAccessState, PolicyStatus
from netcutter.persistence.database import Database
from netcutter.persistence.repository import (
    AuditRepository,
    DeviceRepository,
    GatewayRepository,
)
from netcutter.persistence.secret_store import SecretStore
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.policy_service import PolicyService
from netcutter.services.reconciliation import ReconciliationEngine


def test_reconciliation_drift_detection_and_auto_recovery():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db = Database(str(Path(tmp_dir) / "test.db"))
        secret_store = SecretStore()
        device_repo = DeviceRepository(db)
        audit_repo = AuditRepository(db)
        gw_repo = GatewayRepository(db)

        gw_manager = GatewayManager(db, gw_repo, secret_store)
        mock_backend = MockGatewayBackend()
        # Mock connection
        gw_manager._active_backend = mock_backend
        gw_manager._active_config = mock_backend.config

        policy_service = PolicyService(device_repo, audit_repo, gw_manager)
        reconcile_engine = ReconciliationEngine(
            device_repo, audit_repo, gw_manager, policy_service
        )

        # 1. Create Device and Block It
        dev = Device(
            display_name="Victim PC",
            primary_mac="00:23:6c:45:89:12",
            ipv4_addresses=["192.168.1.101"],
        )
        device_repo.upsert(dev)

        res = policy_service.block_device(dev.device_guid)
        assert res.success is True
        assert res.verification_verified is True

        # Check in DB
        dev_after = device_repo.get_by_guid(dev.device_guid)
        assert dev_after.policy_status == PolicyStatus.SYNCHRONIZED
        assert dev_after.observed_policy.internet_access == InternetAccessState.BLOCKED

        # 2. Simulate Out-of-Band Router Reboot / Rule Deletion Drift
        mock_backend.inject_drift_remove_block(dev.primary_mac)

        # Confirm observed state on router was wiped
        obs = mock_backend.query_observed_state(dev.primary_mac, dev.ipv4_addresses)
        assert obs.internet_access == InternetAccessState.ALLOWED  # Mismatch!

        # 3. Trigger Reconciliation Pass
        results = reconcile_engine.reconcile_once()
        assert results[dev.device_guid] == "RECONCILED"

        # 4. Verify Router Backend was Idempotently Restored
        obs_restored = mock_backend.query_observed_state(dev.primary_mac, dev.ipv4_addresses)
        assert obs_restored.internet_access == InternetAccessState.BLOCKED

        dev_final = device_repo.get_by_guid(dev.device_guid)
        assert dev_final.policy_status == PolicyStatus.SYNCHRONIZED
