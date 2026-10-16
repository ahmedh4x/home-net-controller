"""
Unit Tests for EnforcementSupervisor and Supervised Test Workflow.
Tests target pre-flight validation, safety boundaries, emergency script generation,
mocked enforcement, watchdog auto-restoration, and target isolation.
"""
import time
from unittest.mock import MagicMock
import pytest

from netcutter.backends.base import IGatewayBackend, PolicyExecutionResult
from netcutter.services.enforcement_supervisor import (
    EnforcementSupervisor,
    SupervisedTestState,
    TargetValidationResult,
)


class DummyMockBackend(IGatewayBackend):
    def __init__(self):
        self._connected = True
        self._gateway_ip = "192.168.1.1"
        self._gateway_mac = "a4:f3:3b:c1:7a:24"
        self._local_ip = "192.168.1.9"
        self._local_mac = "04:7c:16:3f:5a:c3"
        self.blocked_calls = []
        self.unblocked_calls = []
        self.should_fail = False

    @property
    def backend_name(self) -> str:
        return "DummyMockBackend"

    @property
    def capabilities(self):
        from netcutter.backends.capabilities import BackendCapabilities
        return BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT | BackendCapabilities.DISCOVERY

    def is_connected(self) -> bool:
        return self._connected

    def connect(self) -> bool:
        return True

    def disconnect(self):
        return {}

    def discover_devices(self):
        return []

    def block_device(self, mac: str, ips: list):
        if self.should_fail:
            return PolicyExecutionResult(success=False, operation="BLOCK", error="Simulated backend failure")
        self.blocked_calls.append((mac, ips))
        return PolicyExecutionResult(success=True, operation="BLOCK", details="Blocked")

    def unblock_device(self, mac: str, ips: list):
        self.unblocked_calls.append((mac, ips))
        return PolicyExecutionResult(success=True, operation="UNBLOCK", details="Unblocked")

    def set_bandwidth_limit(self, mac: str, ips: list, dl_kbps: int, ul_kbps: int):
        return PolicyExecutionResult(success=True, operation="LIMIT")

    def remove_bandwidth_limit(self, mac: str, ips: list):
        return PolicyExecutionResult(success=True, operation="REMOVE_LIMIT")

    def query_observed_state(self, mac: str, ips: list):
        from netcutter.backends.base import ObservedPolicy
        from netcutter.domain.models import InternetAccessState
        is_b = any(m == mac for m, _ in self.blocked_calls)
        return ObservedPolicy(
            internet_access=InternetAccessState.BLOCKED if is_b else InternetAccessState.ALLOWED
        )

    def health_check(self):
        return True, "Healthy"


def test_target_validation_safety_rejections():
    backend = DummyMockBackend()
    supervisor = EnforcementSupervisor(backend)

    # Mock discovery returning known devices
    from netcutter.backends.base import DiscoveredDeviceRaw
    from netcutter.services.local_discovery import LocalSubnetDiscoveryProvider

    dev_phone = DiscoveredDeviceRaw(mac="02:00:00:00:15:4d", ipv4_addresses=["192.0.2.55"])
    dev_gw = DiscoveredDeviceRaw(mac="a4:f3:3b:c1:7a:24", ipv4_addresses=["192.168.1.1"])
    dev_pc = DiscoveredDeviceRaw(mac="04:7c:16:3f:5a:c3", ipv4_addresses=["192.168.1.9"])

    LocalSubnetDiscoveryProvider.discover_local_clients = MagicMock(return_value=[dev_phone, dev_gw, dev_pc])

    # 1. Valid Target Phone
    res_phone = supervisor.validate_target("192.0.2.55", expected_mac_suffix="15:4d")
    assert res_phone.is_valid
    assert res_phone.target_mac == "02:00:00:00:15:4d"
    assert res_phone.mac_suffix_matched
    assert res_phone.is_randomized_mac

    # 2. Suffix mismatch
    res_mismatch = supervisor.validate_target("192.0.2.55", expected_mac_suffix="99:99")
    assert not res_mismatch.is_valid
    assert "suffix" in res_mismatch.error_message.lower()

    # 3. Gateway safety rejection
    res_gw = supervisor.validate_target("192.168.1.1")
    assert not res_gw.is_valid
    assert "gateway" in res_gw.error_message.lower()

    # 4. Controller host safety rejection
    res_pc = supervisor.validate_target("192.168.1.9")
    assert not res_pc.is_valid
    assert "controller" in res_pc.error_message.lower()

    # 5. Non-existent IP
    res_missing = supervisor.validate_target("192.168.1.254")
    assert not res_missing.is_valid
    assert "not currently observed" in res_missing.error_message.lower()


def test_emergency_recovery_script_generation(tmp_path):
    supervisor = EnforcementSupervisor()
    py_path, bat_path = supervisor.write_emergency_recovery_script(
        target_ip="192.0.2.55",
        target_mac="02:00:00:00:15:4d",
        gateway_ip="192.168.1.1",
        gateway_mac="a4:f3:3b:c1:7a:24",
        output_dir=tmp_path,
    )

    assert py_path.exists()
    assert bat_path.exists()

    content = py_path.read_text(encoding="utf-8")
    assert "192.0.2.55" in content
    assert "02:00:00:00:15:4d" in content
    assert "192.168.1.1" in content
    assert "a4:f3:3b:c1:7a:24" in content


def test_supervised_enforcement_and_manual_restore():
    backend = DummyMockBackend()
    supervisor = EnforcementSupervisor(backend)

    # Apply supervised block
    res = supervisor.apply_supervised_block(
        target_ip="192.0.2.55",
        target_mac="02:00:00:00:15:4d",
        duration_seconds=10,
    )
    assert res.success
    assert supervisor.get_active_session() is not None
    assert supervisor.get_active_session().rule_applied

    # Verify backend received exact single target
    assert len(backend.blocked_calls) == 1
    mac, ips = backend.blocked_calls[0]
    assert mac == "02:00:00:00:15:4d"
    assert ips == ["192.0.2.55"]

    # Manual restore
    restore_res = supervisor.restore_target(reason="Owner test completed")
    assert restore_res.success
    assert supervisor.get_active_session() is None
    assert len(backend.unblocked_calls) == 1
    unblock_mac, unblock_ips = backend.unblocked_calls[0]
    assert unblock_mac == "02:00:00:00:15:4d"


def test_supervised_enforcement_watchdog_auto_restoration():
    backend = DummyMockBackend()
    supervisor = EnforcementSupervisor(backend)

    auto_restored = []

    def on_auto():
        auto_restored.append(True)

    # Apply supervised block with 1-second timeout
    res = supervisor.apply_supervised_block(
        target_ip="192.0.2.55",
        target_mac="02:00:00:00:15:4d",
        duration_seconds=1,
        on_auto_restore=on_auto,
    )
    assert res.success

    # Wait for watchdog to trigger (up to 2.5s)
    deadline = time.time() + 2.5
    while time.time() < deadline and len(backend.unblocked_calls) == 0:
        time.sleep(0.1)

    # Watchdog should have triggered auto-restoration
    assert len(backend.unblocked_calls) == 1
    assert supervisor.get_active_session() is None
    assert len(auto_restored) == 1


def test_failed_enforcement_never_reports_success():
    backend = DummyMockBackend()
    backend.should_fail = True
    supervisor = EnforcementSupervisor(backend)

    res = supervisor.apply_supervised_block(
        target_ip="192.0.2.55",
        target_mac="02:00:00:00:15:4d",
        duration_seconds=5,
    )
    assert not res.success
    assert "Simulated backend failure" in res.error
    assert supervisor.get_active_session() is None
