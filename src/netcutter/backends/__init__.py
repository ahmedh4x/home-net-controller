"""
NetCutter Backends Package.
"""
from netcutter.backends.capabilities import (
    BackendCapabilities,
    format_capabilities_report,
)
from netcutter.backends.base import (
    DiscoveredDeviceRaw,
    IGatewayBackend,
    ObservedPolicy,
    PolicyExecutionResult,
)
from netcutter.backends.linux import LinuxGatewayBackend
from netcutter.backends.openwrt import OpenWrtBackend
from netcutter.backends.mikrotik import MikroTikBackend
from netcutter.backends.mock_backend import MockGatewayBackend

__all__ = [
    "BackendCapabilities",
    "format_capabilities_report",
    "DiscoveredDeviceRaw",
    "IGatewayBackend",
    "ObservedPolicy",
    "PolicyExecutionResult",
    "LinuxGatewayBackend",
    "OpenWrtBackend",
    "MikroTikBackend",
    "MockGatewayBackend",
]
