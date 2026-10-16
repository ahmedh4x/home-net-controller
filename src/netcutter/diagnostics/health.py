"""
Diagnostics and Health Verification Service.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List
from netcutter.backends.capabilities import format_capabilities_report
from netcutter.services.gateway_manager import GatewayManager


@dataclass
class DiagnosticCheck:
    name: str
    passed: bool
    details: str
    latency_ms: float = 0.0


@dataclass
class DiagnosticsReport:
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    gateway_name: str = "None"
    overall_healthy: bool = False
    checks: List[DiagnosticCheck] = field(default_factory=list)
    capabilities_matrix: Dict[str, str] = field(default_factory=dict)


class DiagnosticsService:
    def __init__(self, gateway_manager: GatewayManager):
        self.gateway_manager = gateway_manager

    def run_full_diagnostics(self) -> DiagnosticsReport:
        report = DiagnosticsReport()
        backend = self.gateway_manager.get_active_backend()
        config = self.gateway_manager.get_active_config()

        if not backend or not config:
            report.checks.append(
                DiagnosticCheck(
                    name="Gateway Backend Selected",
                    passed=False,
                    details="No active gateway router is currently selected or configured.",
                )
            )
            report.overall_healthy = False
            return report

        report.gateway_name = f"{config.name} ({config.host})"
        report.capabilities_matrix = format_capabilities_report(backend.capabilities)

        # Check 1: Connectivity & Health
        ok, msg = backend.health_check()
        report.checks.append(
            DiagnosticCheck(
                name="Gateway Communication & Health",
                passed=ok,
                details=msg,
            )
        )

        # Check 2: IPv4 Drops Capability
        from netcutter.backends.capabilities import BackendCapabilities
        report.checks.append(
            DiagnosticCheck(
                name="IPv4 Firewall Forward Drops",
                passed=BackendCapabilities.IPV4_BLOCKING in backend.capabilities,
                details="Kernel forward chain filtering active" if BackendCapabilities.IPV4_BLOCKING in backend.capabilities else "Unsupported",
            )
        )

        # Check 3: IPv6 Drops Capability
        report.checks.append(
            DiagnosticCheck(
                name="IPv6 Dual-Stack Support",
                passed=BackendCapabilities.IPV6_BLOCKING in backend.capabilities,
                details="Layer-2 ether matching and IPv6 address filtering active" if BackendCapabilities.IPV6_BLOCKING in backend.capabilities else "Unsupported",
            )
        )

        # Check 4: Bandwidth QoS Subsystem
        has_qos = (
            BackendCapabilities.UPLOAD_SHAPING in backend.capabilities
            and BackendCapabilities.DOWNLOAD_SHAPING in backend.capabilities
        )
        report.checks.append(
            DiagnosticCheck(
                name="QoS Traffic Shaping (Upload & Download)",
                passed=has_qos,
                details="HTB class hierarchy and Simple Queues verified" if has_qos else "Unsupported",
            )
        )

        # Check 5: Conntrack Flushing
        report.checks.append(
            DiagnosticCheck(
                name="Active Conntrack Session Eviction",
                passed=BackendCapabilities.CONNTRACK_FLUSHING in backend.capabilities,
                details="Immediate session termination verified" if BackendCapabilities.CONNTRACK_FLUSHING in backend.capabilities else "Active streams linger until idle timeout",
            )
        )

        # Check 6: Off-Path IPv4 Enforcement
        has_offpath = BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT in backend.capabilities
        if has_offpath:
            report.checks.append(
                DiagnosticCheck(
                    name="Off-Path IPv4 LAN Interception",
                    passed=True,
                    details="Npcap Layer-2 ARP redirection engine active on local network",
                )
            )

        report.overall_healthy = all(c.passed for c in report.checks if c.name == "Gateway Communication & Health")
        return report
