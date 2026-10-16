"""
NetCutter Domain Package.
"""
from netcutter.domain.models import (
    BandwidthLimit,
    BackendType,
    ConfidenceLevel,
    Device,
    DevicePolicyState,
    GatewayConfig,
    GatewayStatus,
    InternetAccessState,
    PolicyStatus,
    is_locally_administered_mac,
    normalize_mac,
)
from netcutter.domain.policy import PolicyDiff, calculate_policy_diff
from netcutter.domain.identity import (
    IdentityCorrelationEvent,
    calculate_identity_confidence,
    resolve_vendor_by_mac,
)
from netcutter.domain.events import AuditAction, AuditEvent

__all__ = [
    "BandwidthLimit",
    "BackendType",
    "ConfidenceLevel",
    "Device",
    "DevicePolicyState",
    "GatewayConfig",
    "GatewayStatus",
    "InternetAccessState",
    "PolicyStatus",
    "PolicyDiff",
    "calculate_policy_diff",
    "IdentityCorrelationEvent",
    "calculate_identity_confidence",
    "resolve_vendor_by_mac",
    "AuditAction",
    "AuditEvent",
    "is_locally_administered_mac",
    "normalize_mac",
]
