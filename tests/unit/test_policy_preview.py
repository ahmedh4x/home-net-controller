"""
Unit tests for Policy Preview Engine, conflict warnings, and impact calculations.
"""
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.backends.mock_backend import MockGatewayBackend
from netcutter.domain.models import Device, DevicePolicyState, InternetAccessState
from netcutter.services.policy_preview import ImpactSeverity, PolicyPreviewEngine, ProposedAction


def test_policy_preview_block_device():
    device = Device(
        display_name="Work Laptop",
        primary_mac="00:11:22:33:44:55",
        ipv4_addresses=["192.168.1.50"],
    )
    backend = MockGatewayBackend()
    target = DevicePolicyState(internet_access=InternetAccessState.BLOCKED)

    report = PolicyPreviewEngine.generate_preview(device, target, backend, backend.config)

    assert report.proposed_action == ProposedAction.BLOCK_ACCESS
    assert report.impact_level == ImpactSeverity.DISRUPTIVE
    assert report.can_execute
    assert "conntrack" in report.verification_strategy


def test_policy_preview_randomized_mac_conflict_warning():
    device = Device(
        display_name="iPhone Private Wi-Fi",
        primary_mac="be:d0:74:aa:bb:cc",  # Randomized bit set
        ipv4_addresses=["192.168.1.145"],
    )
    backend = MockGatewayBackend()
    target = DevicePolicyState(internet_access=InternetAccessState.BLOCKED)

    report = PolicyPreviewEngine.generate_preview(device, target, backend, backend.config)

    # Should detect randomized MAC conflict warning
    rand_conflicts = [c for c in report.conflicts if "Randomized MAC" in c.title]
    assert len(rand_conflicts) == 1
    assert rand_conflicts[0].severity == ImpactSeverity.NOTICE


def test_policy_preview_unsupported_shaping_gating():
    device = Device(
        display_name="Test Device",
        primary_mac="00:11:22:33:44:55",
        ipv4_addresses=["192.168.1.50"],
    )
    backend = MockGatewayBackend()
    # Mock backend overriding capabilities to simulate Windows LAN off-path (no shaping)
    backend.capabilities = BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT

    target = DevicePolicyState(download_limit_kbps=10000)
    report = PolicyPreviewEngine.generate_preview(device, target, backend, backend.config)

    assert not report.can_execute
    assert "does not support bandwidth QoS shaping" in report.block_reason
    qos_conflicts = [c for c in report.conflicts if "QoS Shaping Unsupported" in c.title]
    assert len(qos_conflicts) == 1
    assert qos_conflicts[0].severity == ImpactSeverity.DISRUPTIVE
