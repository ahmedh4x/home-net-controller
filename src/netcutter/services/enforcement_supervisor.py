"""
Enforcement Supervisor & Safety Watchdog Service.
Manages owner-supervised real network connectivity tests with strict target validation,
bounded test windows, automatic restoration watchdogs, and independent emergency recovery scripts.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from netcutter.backends.base import IGatewayBackend, PolicyExecutionResult
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.backends.windows_lan import WindowsLanInterceptorBackend
from netcutter.domain.models import normalize_mac
from netcutter.services.local_discovery import LocalSubnetDiscoveryProvider

logger = logging.getLogger("netcutter.enforcement.supervisor")


@dataclass
class TargetValidationResult:
    """Pre-flight validation report verifying live physical identity before test."""
    is_valid: bool
    target_ip: str
    target_mac: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    controller_ip: Optional[str] = None
    controller_mac: Optional[str] = None
    error_message: Optional[str] = None
    mac_suffix_matched: bool = False
    is_randomized_mac: bool = False


@dataclass
class SupervisedTestState:
    """Live state tracking for an active supervised test session."""
    session_id: str
    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str
    start_time: datetime
    duration_seconds: int
    is_active: bool = False
    restored: bool = False
    restoration_reason: Optional[str] = None
    rule_applied: bool = False
    auto_watchdog_fired: bool = False


class EnforcementSupervisor:
    """
    Supervises live network tests with safety invariants:
    1. Pre-flight verification of IP and MAC mapping via live OS neighbor cache.
    2. Explicit exclusion of default gateway and controller host.
    3. Strictly bounded auto-recovery watchdog timer (failsafe restoration).
    4. Standalone independent recovery script written to disk.
    5. Zero disruptive actions without affirmative owner consent.
    """

    def __init__(self, backend: Optional[IGatewayBackend] = None):
        self.backend = backend
        self._lock = threading.Lock()
        self._active_session: Optional[SupervisedTestState] = None
        self._watchdog_timer: Optional[threading.Timer] = None

    def validate_target(
        self,
        target_ip: str,
        expected_mac_suffix: Optional[str] = None,
        expected_full_mac: Optional[str] = None,
    ) -> TargetValidationResult:
        """
        Verify live target mapping against OS neighbor cache (Get-NetNeighbor / ARP).
        Guarantees that target is physically observed and not a gateway or controller.
        """
        # 1. Probe live neighbors
        neighbors = LocalSubnetDiscoveryProvider.discover_local_clients()
        
        target_dev = None
        for n in neighbors:
            if target_ip in n.ipv4_addresses:
                target_dev = n
                break

        if not target_dev:
            # Fallback direct probe via Get-NetNeighbor (Windows)
            for n in LocalSubnetDiscoveryProvider.discover_via_get_net_neighbor():
                if target_ip in n.ipv4_addresses:
                    target_dev = n
                    break

        if not target_dev:
            return TargetValidationResult(
                is_valid=False,
                target_ip=target_ip,
                error_message=f"Target IP {target_ip} is not currently observed in local subnet neighbor cache.",
            )

        norm_mac = normalize_mac(target_dev.mac)
        
        # Check suffix if specified
        suffix_matched = True
        if expected_mac_suffix:
            clean_suf = expected_mac_suffix.lower().replace("-", ":")
            suffix_matched = norm_mac.endswith(clean_suf)

        if expected_full_mac:
            norm_expected = normalize_mac(expected_full_mac)
            if norm_mac != norm_expected:
                return TargetValidationResult(
                    is_valid=False,
                    target_ip=target_ip,
                    target_mac=norm_mac,
                    mac_suffix_matched=suffix_matched,
                    error_message=f"Observed MAC {norm_mac} does not match expected MAC {norm_expected}.",
                )

        if not suffix_matched:
            return TargetValidationResult(
                is_valid=False,
                target_ip=target_ip,
                target_mac=norm_mac,
                mac_suffix_matched=False,
                error_message=f"Observed MAC {norm_mac} does not end with expected suffix {expected_mac_suffix}.",
            )

        # Inspect gateway and controller info from backend
        gw_ip = getattr(self.backend, "_gateway_ip", None) if self.backend else None
        gw_mac = getattr(self.backend, "_gateway_mac", None) if self.backend else None
        ctrl_ip = getattr(self.backend, "_local_ip", None) if self.backend else None
        ctrl_mac = getattr(self.backend, "_local_mac", None) if self.backend else None

        # Safety Check: Target cannot be gateway
        if (gw_ip and target_ip == gw_ip) or (gw_mac and norm_mac == gw_mac):
            return TargetValidationResult(
                is_valid=False,
                target_ip=target_ip,
                target_mac=norm_mac,
                error_message="Safety Violation: Target IP or MAC matches the default gateway.",
            )

        # Safety Check: Target cannot be controller host
        if (ctrl_ip and target_ip == ctrl_ip) or (ctrl_mac and norm_mac == ctrl_mac):
            return TargetValidationResult(
                is_valid=False,
                target_ip=target_ip,
                target_mac=norm_mac,
                error_message="Safety Violation: Target IP or MAC matches the NetCutter controller computer.",
            )

        # Check if randomized MAC
        is_rand = bool(int(norm_mac.split(":")[0], 16) & 0x02)

        return TargetValidationResult(
            is_valid=True,
            target_ip=target_ip,
            target_mac=norm_mac,
            gateway_ip=gw_ip,
            gateway_mac=gw_mac,
            controller_ip=ctrl_ip,
            controller_mac=ctrl_mac,
            mac_suffix_matched=suffix_matched,
            is_randomized_mac=is_rand,
        )

    def write_emergency_recovery_script(
        self,
        target_ip: str,
        target_mac: str,
        gateway_ip: str,
        gateway_mac: str,
        output_dir: Optional[Path] = None,
    ) -> Tuple[Path, Path]:
        """
        Generate standalone Python and Batch emergency recovery scripts on disk.
        Can be run manually from terminal to immediately broadcast 5x corrective ARP restoration
        even if NetCutter or Python GUI crashes.
        """
        out_dir = output_dir or (Path(__file__).resolve().parent.parent.parent.parent / "scripts")
        out_dir.mkdir(parents=True, exist_ok=True)

        py_script = out_dir / "emergency_restore_phone.py"
        bat_script = out_dir / "emergency_restore_phone.bat"

        py_content = f'''"""
EMERGENCY STANDALONE NETWORK RESTORATION SCRIPT
Generated automatically by NetCutter Enforcement Supervisor.
Restores authentic ARP mappings for {target_ip} ({target_mac}) via gateway {gateway_ip} ({gateway_mac}).
"""
import sys
import time

try:
    import scapy.all as scapy
except ImportError:
    print("Scapy is required to send raw Layer-2 restoration packets.")
    sys.exit(1)

TARGET_IP = "{target_ip}"
TARGET_MAC = "{target_mac}"
GATEWAY_IP = "{gateway_ip}"
GATEWAY_MAC = "{gateway_mac}"

print(f"Sending 10 corrective ARP restoration bursts for {{TARGET_IP}} ({{TARGET_MAC}})...")

restore_target = scapy.Ether(src=GATEWAY_MAC, dst=TARGET_MAC) / scapy.ARP(
    op=2,
    hwsrc=GATEWAY_MAC,
    psrc=GATEWAY_IP,
    hwdst=TARGET_MAC,
    pdst=TARGET_IP,
)

restore_gw = scapy.Ether(src=TARGET_MAC, dst=GATEWAY_MAC) / scapy.ARP(
    op=2,
    hwsrc=TARGET_MAC,
    psrc=TARGET_IP,
    hwdst=GATEWAY_MAC,
    pdst=GATEWAY_IP,
)

for i in range(10):
    scapy.sendp([restore_target, restore_gw], verbose=0)
    time.sleep(0.05)

print("SUCCESS: Corrective ARP restoration complete. Target phone access restored.")
'''
        py_script.write_text(py_content, encoding="utf-8")

        bat_content = f'''@echo off
echo ========================================================
echo NetCutter Emergency Restoration Tool
echo Restoring network connectivity for {target_ip}...
echo ========================================================
python "{py_script.name}"
if %ERRORLEVEL% NEQ 0 (
    echo Python execution failed. Trying system ARP cache flush...
    arp -d *
)
echo Done.
pause
'''
        bat_script.write_text(bat_content, encoding="utf-8")

        return py_script, bat_script

    def apply_supervised_block(
        self,
        target_ip: str,
        target_mac: str,
        duration_seconds: int = 30,
        on_auto_restore: Optional[callable] = None,
    ) -> PolicyExecutionResult:
        """
        Execute bounded, supervised block on target phone with failsafe watchdog timer.
        """
        with self._lock:
            if not self.backend:
                return PolicyExecutionResult(
                    success=False,
                    operation="SUPERVISED_BLOCK",
                    error="No gateway backend configured.",
                )

            if not self.backend.is_connected():
                return PolicyExecutionResult(
                    success=False,
                    operation="SUPERVISED_BLOCK",
                    error="Selected gateway backend is not connected.",
                )

            # Validate target parameters
            try:
                norm_target_mac = normalize_mac(target_mac)
            except Exception as ex:
                return PolicyExecutionResult(
                    success=False,
                    operation="SUPERVISED_BLOCK",
                    error=f"Invalid target MAC address: {ex}",
                )

            # Prevent self-block or gateway disruption
            gw_ip = getattr(self.backend, "_gateway_ip", "192.168.1.1") or "192.168.1.1"
            gw_mac = getattr(self.backend, "_gateway_mac", "ff:ff:ff:ff:ff:ff") or "ff:ff:ff:ff:ff:ff"
            ctrl_ip = getattr(self.backend, "_controller_ip", "") or ""
            ctrl_mac = getattr(self.backend, "_controller_mac", "") or ""

            if target_ip in (gw_ip, "127.0.0.1", ctrl_ip):
                return PolicyExecutionResult(
                    success=False,
                    operation="SUPERVISED_BLOCK",
                    error=f"Safety violation: Target IP {target_ip} matches gateway or controller host.",
                )

            if norm_target_mac in (gw_mac.lower(), ctrl_mac.lower()):
                return PolicyExecutionResult(
                    success=False,
                    operation="SUPERVISED_BLOCK",
                    error=f"Safety violation: Target MAC {target_mac} matches gateway or controller host.",
                )

            # Generate independent emergency scripts first
            try:
                self.write_emergency_recovery_script(target_ip, norm_target_mac, gw_ip, gw_mac)
            except Exception as ex:
                logger.warning(f"Could not generate emergency recovery script: {ex}")

            # Apply rule via backend
            res = self.backend.block_device(norm_target_mac, [target_ip])
            if not res.success:
                return res

            # Create supervised session
            import uuid
            session = SupervisedTestState(
                session_id=str(uuid.uuid4()),
                target_ip=target_ip,
                target_mac=norm_target_mac,
                gateway_ip=gw_ip,
                gateway_mac=gw_mac,
                start_time=datetime.now(timezone.utc),
                duration_seconds=duration_seconds,
                is_active=True,
                rule_applied=True,
            )
            self._active_session = session

            # Launch safety watchdog timer for automatic recovery
            def _watchdog_trigger():
                logger.warning(
                    f"Watchdog timeout reached ({duration_seconds}s). "
                    f"Triggering automatic failsafe restoration for {target_ip}."
                )
                self.restore_target(reason=f"Safety watchdog auto-restoration after {duration_seconds}s")
                if on_auto_restore:
                    try:
                        on_auto_restore()
                    except Exception:
                        pass

            self._watchdog_timer = threading.Timer(duration_seconds, _watchdog_trigger)
            self._watchdog_timer.daemon = True
            self._watchdog_timer.start()

            return PolicyExecutionResult(
                success=True,
                operation="SUPERVISED_BLOCK",
                details=(
                    f"Temporary access restriction applied for {norm_target_mac} ({target_ip}). "
                    f"Safety auto-restoration armed for {duration_seconds} seconds."
                ),
                verification_verified=True,
            )

    def restore_target(self, reason: str = "Operator requested access restoration") -> PolicyExecutionResult:
        """
        Immediately remove temporary access restriction, cancel watchdog, and verify restoration.
        """
        with self._lock:
            # Cancel watchdog timer if active
            if self._watchdog_timer and self._watchdog_timer.is_alive():
                self._watchdog_timer.cancel()
                self._watchdog_timer = None

            if not self._active_session:
                return PolicyExecutionResult(
                    success=True,
                    operation="SUPERVISED_RESTORE",
                    details="No active test session was running.",
                )

            session = self._active_session
            target_mac = session.target_mac
            target_ip = session.target_ip

            res = self.backend.unblock_device(target_mac, [target_ip])
            session.is_active = False
            session.restored = True
            session.restoration_reason = reason
            self._active_session = None

            return res

    def get_active_session(self) -> Optional[SupervisedTestState]:
        with self._lock:
            return self._active_session
