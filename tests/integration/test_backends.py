"""
Integration Tests for Gateway Backends and Capability Validation.
"""
import pytest
from netcutter.backends.capabilities import (
    BackendCapabilities,
    format_capabilities_report,
)
from netcutter.backends.linux import LinuxGatewayBackend
from netcutter.backends.mock_backend import MockGatewayBackend
from netcutter.domain.models import BackendType, GatewayConfig


def test_capabilities_report():
    caps = BackendCapabilities.MAC_BLOCKING | BackendCapabilities.IPV4_BLOCKING | BackendCapabilities.IPV6_BLOCKING
    report = format_capabilities_report(caps)
    assert report["MAC Address Blocking"] == "SUPPORTED"
    assert report["IPv4 Forwarding Drops"] == "SUPPORTED"
    assert report["IPv6 Forwarding Drops"] == "SUPPORTED"
    assert report["Per-Device Upload Shaping"] == "NOT SUPPORTED"


def test_linux_gateway_validation():
    cfg = GatewayConfig(name="OpenWrt Test", host="192.168.1.1", backend_type=BackendType.OPENWRT)
    backend = LinuxGatewayBackend(cfg)

    # Valid validation checks
    assert backend._validate_mac("00:23:6C:45:89:12") == "00:23:6c:45:89:12"
    assert backend._validate_ip("192.168.1.101") == "192.168.1.101"
    assert backend._validate_ip("2001:db8::1") == "2001:db8::1"
    assert backend._validate_iface("br-lan") == "br-lan"

    # Shell injection payload rejections
    with pytest.raises(ValueError):
        backend._validate_mac("00:11:22:33:44:55; rm -rf /")
    with pytest.raises(ValueError):
        backend._validate_ip("192.168.1.1 | reboot")
    with pytest.raises(ValueError):
        backend._validate_iface("eth0 && cat /etc/shadow")


def test_mock_backend_full_lifecycle():
    backend = MockGatewayBackend()
    assert backend.connect() is True
    assert backend.is_connected() is True

    # Discovery
    devices = backend.discover_devices()
    assert len(devices) > 0

    # Block
    target_mac = devices[0].mac
    res_block = backend.block_device(target_mac, devices[0].ipv4_addresses)
    assert res_block.success is True
    assert res_block.verification_verified is True

    obs = backend.query_observed_state(target_mac, devices[0].ipv4_addresses)
    from netcutter.domain.models import InternetAccessState
    assert obs.internet_access == InternetAccessState.BLOCKED
    assert obs.packet_drop_count > 0

    # Rate limiting
    res_limit = backend.set_bandwidth_limit(target_mac, devices[0].ipv4_addresses, 5120, 1024)
    assert res_limit.success is True
    obs_limit = backend.query_observed_state(target_mac, devices[0].ipv4_addresses)
    assert obs_limit.download_limit_kbps == 5120
    assert obs_limit.upload_limit_kbps == 1024

    # Unblock
    res_unblock = backend.unblock_device(target_mac, devices[0].ipv4_addresses)
    assert res_unblock.success is True
    obs_unblock = backend.query_observed_state(target_mac, devices[0].ipv4_addresses)
    assert obs_unblock.internet_access == InternetAccessState.ALLOWED
