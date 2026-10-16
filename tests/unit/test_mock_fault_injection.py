"""
Unit tests for MockGatewayBackend deterministic simulation and fault injection harness.
"""
from netcutter.backends.base import DiscoveredDeviceRaw
from netcutter.backends.mock_backend import MockGatewayBackend
from netcutter.domain.models import InternetAccessState


def test_mock_backend_timeout_fault_injection():
    mock = MockGatewayBackend()
    assert mock.is_connected()

    # Normal block works
    res = mock.block_device("00:11:22:33:44:55", ["192.168.1.50"])
    assert res.success

    # Inject timeout on BLOCK operations
    mock.inject_fault_timeout(operation="BLOCK")
    res_timeout = mock.block_device("00:11:22:33:44:55", ["192.168.1.50"])
    assert not res_timeout.success
    assert "timed out" in res_timeout.error.lower()

    # Clear faults and verify recovery
    mock.clear_faults()
    res_recovered = mock.block_device("00:11:22:33:44:55", ["192.168.1.50"])
    assert res_recovered.success


def test_mock_backend_disconnect_fault_injection():
    mock = MockGatewayBackend()
    assert mock.is_connected()

    # Inject disconnect
    mock.inject_fault_disconnect()
    assert not mock.is_connected()

    res = mock.block_device("00:11:22:33:44:55", ["192.168.1.50"])
    assert not res.success
    assert "disconnected" in res.error.lower()

    # Reconnect
    mock.clear_faults()
    assert mock.is_connected()


def test_mock_backend_partial_failure_fault_injection():
    mock = MockGatewayBackend()
    mock.inject_fault_partial_failure(operation="BLOCK")

    res = mock.block_device("00:11:22:33:44:55", ["192.168.1.50"])
    assert not res.success
    assert not res.verification_verified
    assert "partial failure" in res.error.lower()


def test_mock_backend_dynamic_device_events():
    mock = MockGatewayBackend()
    initial_count = len(mock.discover_devices())

    # Add a device dynamically
    new_dev = DiscoveredDeviceRaw(
        mac="aa:bb:cc:dd:ee:ff",
        ipv4_addresses=["192.168.1.250"],
        hostname="New-Guest-Device",
    )
    mock.inject_device_joined(new_dev)
    assert len(mock.discover_devices()) == initial_count + 1

    # Remove device
    mock.inject_device_left("aa:bb:cc:dd:ee:ff")
    assert len(mock.discover_devices()) == initial_count
