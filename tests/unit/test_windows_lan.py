"""
Unit and Mock Tests for Windows LAN Off-Path Interceptor Backend.
"""
from unittest.mock import MagicMock, patch
import pytest

from netcutter.backends.base import DiscoveredDeviceRaw, ObservedPolicy
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.backends.windows_lan import WindowsLanInterceptorBackend
from netcutter.domain.models import BackendType, GatewayConfig, InternetAccessState, PolicyStatus
from netcutter.persistence.database import Database
from netcutter.persistence.repository import AuditRepository, DeviceRepository, GatewayRepository
from netcutter.persistence.secret_store import SecretStore
from netcutter.services.device_service import DeviceService
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.identity_engine import IdentityEngine
from netcutter.services.policy_service import PolicyService


def test_windows_lan_capabilities_declaration():
    """Verify honest capabilities: Off-Path IPv4 & Discovery only, NO QoS, NO IPv6."""
    backend = WindowsLanInterceptorBackend()
    caps = backend.capabilities

    assert BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT in caps
    assert BackendCapabilities.DISCOVERY in caps

    # Proving negative: must NOT claim in-path router capabilities
    assert BackendCapabilities.UPLOAD_SHAPING not in caps
    assert BackendCapabilities.DOWNLOAD_SHAPING not in caps
    assert BackendCapabilities.IPV6_BLOCKING not in caps
    assert BackendCapabilities.NFTABLES_SETS not in caps
    assert BackendCapabilities.CONNTRACK_FLUSHING not in caps
    assert BackendCapabilities.FASTTRACK_BYPASS not in caps


def test_windows_lan_bandwidth_rejection():
    """Verify that bandwidth shaping is strictly rejected with a clear message."""
    backend = WindowsLanInterceptorBackend()
    res = backend.set_bandwidth_limit("aa:bb:cc:dd:ee:ff", ["192.168.1.50"], 5000, 2000)
    assert not res.success
    assert "NOT supported" in res.error
    assert not res.verification_verified

    res_rm = backend.remove_bandwidth_limit("aa:bb:cc:dd:ee:ff", ["192.168.1.50"])
    assert not res_rm.success
    assert "not supported" in res_rm.error


def test_windows_lan_safety_guards():
    """Verify safety checks preventing accidental blackholing of gateway or controller host."""
    backend = WindowsLanInterceptorBackend()
    backend._connected = True
    backend._gateway_ip = "192.168.1.1"
    backend._gateway_mac = "a4:f3:3b:c1:7a:24"
    backend._local_ip = "192.168.1.9"
    backend._local_mac = "04:7c:16:3f:5a:c3"

    # 1. Reject blocking gateway
    res_gw = backend.block_device("a4:f3:3b:c1:7a:24", ["192.168.1.1"])
    assert not res_gw.success
    assert "default gateway" in res_gw.error.lower()

    # 2. Reject blocking controller itself
    res_ctrl = backend.block_device("04:7c:16:3f:5a:c3", ["192.168.1.9"])
    assert not res_ctrl.success
    assert "controller host" in res_ctrl.error.lower()


def test_windows_lan_block_unblock_cycle():
    """Verify state transition and packet triggering during block and unblock."""
    backend = WindowsLanInterceptorBackend()
    backend._connected = True
    backend._iface = "\\Device\\NPF_{TEST}"
    backend._gateway_ip = "192.168.1.1"
    backend._gateway_mac = "a4:f3:3b:c1:7a:24"
    backend._local_ip = "192.168.1.9"
    backend._local_mac = "04:7c:16:3f:5a:c3"

    target_mac = "02:00:00:00:15:4d"
    target_ip = "192.168.1.2"

    with patch.object(backend, "_send_poison_packet") as mock_poison, \
         patch.object(backend, "_send_restoration_burst") as mock_restore:

        # 1. Block
        res = backend.block_device(target_mac, [target_ip])
        assert res.success
        assert res.verification_verified
        mock_poison.assert_called_once_with(target_ip, target_mac)

        # Query observed state
        obs = backend.query_observed_state(target_mac, [target_ip])
        assert obs.internet_access == InternetAccessState.BLOCKED
        assert obs.is_verified

        # 2. Unblock
        res_unblock = backend.unblock_device(target_mac, [target_ip])
        assert res_unblock.success
        assert res_unblock.verification_verified
        mock_restore.assert_called_once_with(target_ip, target_mac)

        # Query observed state after unblock
        obs_after = backend.query_observed_state(target_mac, [target_ip])
        assert obs_after.internet_access == InternetAccessState.ALLOWED


def test_policy_service_qos_rejection_with_windows_lan():
    """Ensure PolicyService rejects QoS requests when WindowsLan backend is active."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = str(Path(tmp_dir) / "test.db")
        db = Database(db_path)
        dev_repo = DeviceRepository(db)
        audit_repo = AuditRepository(db)
        gw_repo = GatewayRepository(db)
        secret_store = SecretStore()

        gw_mgr = GatewayManager(db, gw_repo, secret_store)
        policy_svc = PolicyService(dev_repo, audit_repo, gw_mgr)

        # Setup mock device
        from netcutter.domain.models import Device
        dev = Device(
            primary_mac="02:00:00:00:15:4d",
            display_name="Test iPhone",
            ipv4_addresses=["192.168.1.2"],
        )
        dev_repo.upsert(dev)

        # Active WindowsLan backend
        backend = WindowsLanInterceptorBackend()
        backend._connected = True
        gw_mgr._active_backend = backend

        res = policy_svc.set_bandwidth_limits(dev.device_guid, 2048, 1024)
        assert not res.success
        assert "not supported" in res.error.lower()

        # Device state should not drift to synchronized
        updated_dev = dev_repo.get_by_guid(dev.device_guid)
        assert updated_dev.policy_status == PolicyStatus.FAILED


def test_windows_lan_atexit_restoration():
    """Verify that atexit hook correctly triggers disconnect and restoration burst for blocked targets."""
    backend = WindowsLanInterceptorBackend()
    backend._connected = True
    backend._iface = "\\Device\\NPF_{TEST}"
    backend._gateway_ip = "192.168.1.1"
    backend._gateway_mac = "a4:f3:3b:c1:7a:24"
    backend._local_ip = "192.168.1.9"
    backend._local_mac = "04:7c:16:3f:5a:c3"

    target_mac = "02:00:00:00:15:4d"
    target_ip = "192.168.1.2"

    with patch.object(backend, "_send_poison_packet"), \
         patch.object(backend, "_send_restoration_burst") as mock_restore:
        # Block device
        backend.block_device(target_mac, [target_ip])
        assert target_mac in backend._blocked_targets

        # Trigger registered atexit handler directly
        backend._atexit_handler()

        # Restoration burst must have been executed and backend disconnected
        mock_restore.assert_called_once_with(target_ip, target_mac)
        assert not backend.is_connected()
        assert len(backend._blocked_targets) == 0


def test_windows_lan_multi_target_restoration_isolation():
    """Verify that failure to restore one target does NOT stop restoration of remaining targets."""
    backend = WindowsLanInterceptorBackend()
    backend._connected = True
    backend._iface = "\\Device\\NPF_{TEST}"
    backend._gateway_ip = "192.168.1.1"
    backend._gateway_mac = "a4:f3:3b:c1:7a:24"

    target1_mac = "11:22:33:44:55:66"
    target1_ip = "192.168.1.101"
    target2_mac = "aa:bb:cc:dd:ee:ff"
    target2_ip = "192.168.1.102"

    backend._blocked_targets[target1_mac] = (target1_ip, target1_mac)
    backend._blocked_targets[target2_mac] = (target2_ip, target2_mac)

    restored_targets = []

    def mock_restore_fn(target_ip, target_mac):
        if target_mac == target1_mac:
            raise RuntimeError("Synthetic socket error for target 1")
        restored_targets.append(target_mac)

    with patch.object(backend, "_send_restoration_burst", side_effect=mock_restore_fn):
        results = backend.disconnect()

        # Both targets were attempted; target1 reported False, target2 reported True
        assert results[target1_mac] is False
        assert results[target2_mac] is True
        assert target2_mac in restored_targets
        # Target queue cleared and backend marked disconnected
        assert len(backend._blocked_targets) == 0
        assert not backend.is_connected()


def test_windows_lan_idempotent_double_disconnect():
    """Verify that calling disconnect() repeatedly is safe and does not raise errors."""
    backend = WindowsLanInterceptorBackend()
    backend._connected = True
    backend._iface = "\\Device\\NPF_{TEST}"
    backend._gateway_ip = "192.168.1.1"
    backend._gateway_mac = "a4:f3:3b:c1:7a:24"

    # First disconnect
    res1 = backend.disconnect()
    assert isinstance(res1, dict)
    assert not backend.is_connected()

    # Second disconnect (idempotent, uninitialized / already stopped)
    res2 = backend.disconnect()
    assert isinstance(res2, dict)
    assert len(res2) == 0


def test_windows_lan_metering_lifecycle():
    """Verify active traffic metering start, stop, controller protection, and restoration."""
    backend = WindowsLanInterceptorBackend()
    backend._connected = True
    backend._iface = "\\Device\\NPF_{TEST}"
    backend._gateway_ip = "192.168.1.1"
    backend._gateway_mac = "a4:f3:3b:c1:7a:24"
    backend._local_ip = "192.168.1.9"
    backend._local_mac = "04:7c:16:3f:5a:c3"

    target_mac = "02:00:00:00:15:4d"
    target_ip = "192.0.2.55"

    with patch.object(backend, "_send_poison_packet") as mock_poison, \
         patch.object(backend, "_send_controller_protection") as mock_prot, \
         patch.object(backend, "_send_restoration_burst") as mock_restore:

        # 1. Start metering
        res = backend.start_traffic_metering(target_mac, [target_ip])
        assert res.success
        assert backend.is_metering(target_mac)
        assert target_mac in backend.get_metered_devices()
        mock_poison.assert_called_once_with(target_ip, target_mac)
        mock_prot.assert_called_once_with(target_ip, target_mac)

        # 2. Stop metering
        res_stop = backend.stop_traffic_metering(target_mac, [target_ip])
        assert res_stop.success
        assert not backend.is_metering(target_mac)
        mock_restore.assert_called_once_with(target_ip, target_mac)


