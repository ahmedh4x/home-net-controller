"""
Unit Tests for InstallationService, CapabilityState, and LocalSubnetDiscoveryProvider.
"""
import json
import os

from netcutter.backends.capabilities import (
    BackendCapabilities,
    CapabilityState,
    evaluate_capability_state,
)
from netcutter.services.installation_service import (
    ComponentStatus,
    DependencyItem,
    InstallationOperationResult,
    InstallationService,
    SystemReadinessReport,
)
from netcutter.services.local_discovery import LocalSubnetDiscoveryProvider


def test_capability_state_evaluation():
    # 1. Full capabilities with admin and connected
    state = evaluate_capability_state(
        cap=BackendCapabilities.DOWNLOAD_SHAPING,
        backend_capabilities=BackendCapabilities.DOWNLOAD_SHAPING | BackendCapabilities.IPV4_BLOCKING,
        backend_type_name="linux_nftables",
        is_connected=True,
        has_privileges=True,
    )
    assert state == CapabilityState.AVAILABLE

    # 2. Mock / simulator
    state_mock = evaluate_capability_state(
        cap=BackendCapabilities.IPV4_BLOCKING,
        backend_capabilities=BackendCapabilities.IPV4_BLOCKING,
        backend_type_name="mock_simulator",
        is_connected=True,
        has_privileges=False,
    )
    assert state_mock == CapabilityState.SIMULATED

    # 3. Unsupported capability
    state_unsupported = evaluate_capability_state(
        cap=BackendCapabilities.DOWNLOAD_SHAPING,
        backend_capabilities=BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT,
        backend_type_name="windows_lan",
        is_connected=True,
        has_privileges=True,
    )
    assert state_unsupported == CapabilityState.UNSUPPORTED

    # 4. Requires privileges for off-path enforcement
    state_priv = evaluate_capability_state(
        cap=BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT,
        backend_capabilities=BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT,
        backend_type_name="windows_lan",
        is_connected=True,
        has_privileges=False,
        has_npcap=True,
    )
    assert state_priv == CapabilityState.REQUIRES_PRIVILEGES

    # 5. Requires setup (Npcap driver missing)
    state_setup = evaluate_capability_state(
        cap=BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT,
        backend_capabilities=BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT,
        backend_type_name="windows_lan",
        is_connected=True,
        has_privileges=True,
        has_npcap=False,
    )
    assert state_setup == CapabilityState.REQUIRES_SETUP


def test_installation_service_audit_and_components():
    svc = InstallationService()
    report = svc.run_system_audit()

    assert isinstance(report, SystemReadinessReport)
    assert len(report.dependencies) >= 6
    assert report.disk_free_gb >= 0.0

    # Verify standard dependencies exist in report
    dep_ids = {d.id for d in report.dependencies}
    assert "python_runtime" in dep_ids
    assert "pyside6_qt" in dep_ids
    assert "cryptography_engine" in dep_ids
    assert "ssh_paramiko" in dep_ids
    assert "vc_redist" in dep_ids
    assert "npcap_driver" in dep_ids

    # Core runtimes must be READY
    python_dep = next(d for d in report.dependencies if d.id == "python_runtime")
    assert python_dep.status == ComponentStatus.READY

    pyside_dep = next(d for d in report.dependencies if d.id == "pyside6_qt")
    assert pyside_dep.status == ComponentStatus.READY

    crypto_dep = next(d for d in report.dependencies if d.id == "cryptography_engine")
    assert crypto_dep.status == ComponentStatus.READY

    ssh_dep = next(d for d in report.dependencies if d.id == "ssh_paramiko")
    assert ssh_dep.status == ComponentStatus.READY


def test_installation_service_redacted_json_export():
    svc = InstallationService()
    json_str = svc.generate_redacted_diagnostic_json()
    assert json_str is not None

    parsed = json.loads(json_str)
    assert "timestamp" in parsed
    assert "os_name" in parsed
    assert "dependencies" in parsed
    assert isinstance(parsed["dependencies"], list)
    assert len(parsed["dependencies"]) >= 6

    # Verify no raw secrets or passwords in output
    assert "password" not in json_str.lower()
    assert "secret_key" not in json_str.lower()


def test_installation_service_component_repair():
    svc = InstallationService()

    # Re-verify pyside6_qt
    res = svc.repair_component("pyside6_qt")
    assert isinstance(res, InstallationOperationResult)
    assert res.dependency_id == "pyside6_qt"

    # Unsupported repair id
    res_unknown = svc.repair_component("nonexistent_component")
    assert not res_unknown.success


def test_local_discovery_multicast_filtering():
    assert LocalSubnetDiscoveryProvider.is_multicast_or_broadcast("224.0.0.1")
    assert LocalSubnetDiscoveryProvider.is_multicast_or_broadcast("239.255.255.250")
    assert LocalSubnetDiscoveryProvider.is_multicast_or_broadcast("255.255.255.255")
    assert not LocalSubnetDiscoveryProvider.is_multicast_or_broadcast("192.168.1.1")
    assert not LocalSubnetDiscoveryProvider.is_multicast_or_broadcast("10.0.0.50")
