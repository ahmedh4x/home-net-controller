"""
Policy Preview Engine for NetCutter.
Provides pre-execution dry-run evaluation, conflict detection, impact analysis, and verification strategies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from netcutter.backends.base import IGatewayBackend
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.models import (
    Device,
    DevicePolicyState,
    GatewayConfig,
    InternetAccessState,
)


class ImpactSeverity(str, Enum):
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    DISRUPTIVE = "DISRUPTIVE"


class ProposedAction(str, Enum):
    BLOCK_ACCESS = "BLOCK_ACCESS"
    UNBLOCK_ACCESS = "UNBLOCK_ACCESS"
    SET_BANDWIDTH = "SET_BANDWIDTH"
    REMOVE_BANDWIDTH = "REMOVE_BANDWIDTH"


@dataclass
class PolicyConflict:
    """Represents a potential operational risk, hardware conflict, or capability limitation."""
    title: str
    description: str
    severity: ImpactSeverity = ImpactSeverity.WARNING


@dataclass
class PolicyPreviewReport:
    """Comprehensive pre-execution preview report presented before applying mutations."""
    device_guid: str
    device_name: str
    primary_mac: str
    target_ips: List[str]
    proposed_action: ProposedAction
    current_desired: DevicePolicyState
    current_observed: DevicePolicyState
    target_policy: DevicePolicyState
    responsible_backend: str
    backend_supported: bool
    conflicts: List[PolicyConflict] = field(default_factory=list)
    impact_level: ImpactSeverity = ImpactSeverity.INFO
    impact_summary: str = ""
    verification_strategy: str = ""
    is_dry_run_passed: bool = True
    can_execute: bool = True
    block_reason: Optional[str] = None
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyPreviewEngine:
    """Generates deterministic dry-run previews before live router mutations."""

    @staticmethod
    def generate_preview(
        device: Device,
        target_policy: DevicePolicyState,
        backend: Optional[IGatewayBackend],
        gateway_config: Optional[GatewayConfig],
    ) -> PolicyPreviewReport:
        all_ips = list(device.ipv4_addresses + device.ipv6_addresses)
        conflicts: List[PolicyConflict] = []
        backend_name = backend.backend_name if backend else (gateway_config.name if gateway_config else "None")
        caps = backend.capabilities if backend else BackendCapabilities.NONE

        # Determine proposed action
        if target_policy.internet_access == InternetAccessState.BLOCKED and not device.desired_policy.is_blocked:
            proposed_action = ProposedAction.BLOCK_ACCESS
        elif target_policy.internet_access == InternetAccessState.ALLOWED and device.desired_policy.is_blocked:
            proposed_action = ProposedAction.UNBLOCK_ACCESS
        elif (
            target_policy.download_limit_kbps != device.desired_policy.download_limit_kbps
            or target_policy.upload_limit_kbps != device.desired_policy.upload_limit_kbps
        ):
            if target_policy.download_limit_kbps == 0 and target_policy.upload_limit_kbps == 0:
                proposed_action = ProposedAction.REMOVE_BANDWIDTH
            else:
                proposed_action = ProposedAction.SET_BANDWIDTH
        else:
            proposed_action = ProposedAction.SET_BANDWIDTH

        # 1. Capability & Backend Availability Check
        backend_supported = True
        can_execute = True
        block_reason = None

        if not backend or not backend.is_connected():
            backend_supported = False
            can_execute = False
            block_reason = "Gateway backend is currently disconnected or unreachable."
            conflicts.append(
                PolicyConflict(
                    title="Backend Disconnected",
                    description="The target gateway cannot be contacted. Changes cannot be applied.",
                    severity=ImpactSeverity.DISRUPTIVE,
                )
            )

        # Check shaping capabilities
        if target_policy.has_download_limit or target_policy.has_upload_limit:
            has_shaping = bool(
                (caps & BackendCapabilities.DOWNLOAD_SHAPING)
                or (caps & BackendCapabilities.UPLOAD_SHAPING)
            )
            if not has_shaping:
                backend_supported = False
                can_execute = False
                block_reason = "Active backend mode does not support bandwidth QoS shaping."
                conflicts.append(
                    PolicyConflict(
                        title="QoS Shaping Unsupported",
                        description=(
                            "The active backend (e.g. Windows LAN Off-Path) cannot enforce token-bucket queueing. "
                            "Real traffic control requires a Gateway-Native backend (OpenWrt or Linux with tc HTB)."
                        ),
                        severity=ImpactSeverity.DISRUPTIVE,
                    )
                )

        # Check IPv6 parity for blocking
        if target_policy.is_blocked:
            if not (caps & BackendCapabilities.IPV6_BLOCKING) and device.ipv6_addresses:
                conflicts.append(
                    PolicyConflict(
                        title="IPv6 Leakage Risk",
                        description=(
                            f"Device has IPv6 addresses ({', '.join(device.ipv6_addresses[:2])}), "
                            "but the active backend does not support IPv6 drops. Client traffic may bypass blocks over IPv6."
                        ),
                        severity=ImpactSeverity.WARNING,
                    )
                )

        # Check randomized MAC risk
        if device.is_randomized_mac:
            conflicts.append(
                PolicyConflict(
                    title="Randomized MAC Detected",
                    description=(
                        "Device uses a locally-administered (private/randomized) MAC address. "
                        "If the client rotates its MAC address upon reconnection, policy enforcement may need to be re-applied."
                    ),
                    severity=ImpactSeverity.NOTICE,
                )
            )

        # Check empty IP list
        if not all_ips and target_policy.is_blocked:
            conflicts.append(
                PolicyConflict(
                    title="No IP Addresses Mapped",
                    description=(
                        "Device has no discovered IPv4/IPv6 addresses yet. "
                        "Enforcement will rely strictly on Layer-2 MAC matching."
                    ),
                    severity=ImpactSeverity.NOTICE,
                )
            )

        # Determine Impact Level & Summary
        if proposed_action == ProposedAction.BLOCK_ACCESS:
            impact_level = ImpactSeverity.DISRUPTIVE
            impact_summary = (
                f"Immediately terminates internet connectivity for '{device.display_name}'. "
                "Existing active conntrack flows will be flushed and dropped at router forwarding stage."
            )
            verification_strategy = (
                "Query gateway kernel drop set (nftables blocked_macs or RouterOS address-list) "
                "and verify bidirectional conntrack table eviction."
            )
        elif proposed_action == ProposedAction.UNBLOCK_ACCESS:
            impact_level = ImpactSeverity.NOTICE
            impact_summary = (
                f"Restores internet access for '{device.display_name}'. "
                "Kernel drop filter will be removed and client will regain routing immediately."
            )
            verification_strategy = (
                "Query router kernel drop set to verify removal of target MAC/IP."
            )
        elif proposed_action == ProposedAction.SET_BANDWIDTH:
            impact_level = ImpactSeverity.NOTICE
            dl_str = f"{target_policy.download_limit_kbps} Kbps" if target_policy.download_limit_kbps else "Unlimited"
            ul_str = f"{target_policy.upload_limit_kbps} Kbps" if target_policy.upload_limit_kbps else "Unlimited"
            impact_summary = (
                f"Applies traffic shaping rate limits (DL: {dl_str}, UL: {ul_str}) "
                f"via router kernel hierarchical token bucket (HTB) with fq_codel leaf queues."
            )
            verification_strategy = (
                "Query active tc class hierarchy (Linux/OpenWrt) or Simple Queue (MikroTik) "
                "to verify class ID and configured burst/rate ceilings."
            )
        else:
            impact_level = ImpactSeverity.INFO
            impact_summary = f"Removes bandwidth rate limits for '{device.display_name}'."
            verification_strategy = "Verify deletion of tc classes or queue limits on router."

        return PolicyPreviewReport(
            device_guid=device.device_guid,
            device_name=device.display_name,
            primary_mac=device.primary_mac,
            target_ips=all_ips,
            proposed_action=proposed_action,
            current_desired=device.desired_policy,
            current_observed=device.observed_policy,
            target_policy=target_policy,
            responsible_backend=backend_name,
            backend_supported=backend_supported,
            conflicts=conflicts,
            impact_level=impact_level,
            impact_summary=impact_summary,
            verification_strategy=verification_strategy,
            is_dry_run_passed=can_execute,
            can_execute=can_execute,
            block_reason=block_reason,
        )
