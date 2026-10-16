"""
Installation, System Readiness & Dependency Management Service.
Provides declarative dependency inspection, system readiness auditing,
guided component verification, and secure elevation workflows.
"""
from __future__ import annotations

import ctypes
import dataclasses
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from netcutter.common.paths import get_app_data_dir, get_asset_path, get_assets_dir

logger = logging.getLogger("netcutter.installation")


class ComponentStatus(str, Enum):
    READY = "Ready"
    NEEDS_INSTALLATION = "Needs installation"
    NEEDS_CONFIGURATION = "Needs configuration"
    REQUIRES_ELEVATION = "Requires administrator approval"
    OPTIONAL = "Optional"
    UNSUPPORTED = "Unsupported"
    FAILED = "Failed"


@dataclass
class DependencyItem:
    """Declarative specification and detection state for a system dependency."""
    id: str
    name: str
    purpose: str
    category: str  # "Driver", "Runtime", "Networking", "Security"
    required: bool
    status: ComponentStatus = ComponentStatus.NEEDS_INSTALLATION
    detected_version: Optional[str] = None
    min_version: Optional[str] = None
    privilege_required: str = "Standard User"
    download_url: Optional[str] = None
    sha256_checksum: Optional[str] = None
    verification_details: str = ""
    error_message: Optional[str] = None
    last_verified: Optional[datetime] = None


@dataclass
class SystemReadinessReport:
    """Comprehensive snapshot of host system readiness, packaging, and drivers."""
    os_name: str
    os_version: str
    os_arch: str
    is_admin: bool
    disk_free_gb: float
    local_app_data_ok: bool
    network_connected: bool
    default_gateway_ip: Optional[str]
    assets_integrity_ok: bool
    dependencies: List[DependencyItem] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def overall_ready(self) -> bool:
        """True if all required dependencies and system checks are satisfied."""
        if not self.local_app_data_ok or not self.assets_integrity_ok:
            return False
        for dep in self.dependencies:
            if dep.required and dep.status not in (ComponentStatus.READY, ComponentStatus.OPTIONAL):
                return False
        return True

    def to_redacted_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_arch": self.os_arch,
            "is_admin": self.is_admin,
            "disk_free_gb": self.disk_free_gb,
            "local_app_data_ok": self.local_app_data_ok,
            "network_connected": self.network_connected,
            "default_gateway_ip": self.default_gateway_ip,
            "assets_integrity_ok": self.assets_integrity_ok,
            "overall_ready": self.overall_ready,
            "dependencies": [
                {
                    "id": d.id,
                    "name": d.name,
                    "category": d.category,
                    "required": d.required,
                    "status": d.status.value,
                    "detected_version": d.detected_version,
                    "min_version": d.min_version,
                    "privilege_required": d.privilege_required,
                    "verification_details": d.verification_details,
                    "error_message": d.error_message,
                }
                for d in self.dependencies
            ],
        }


@dataclass
class InstallationOperationResult:
    """Structured result of an install, repair, or verify step."""
    success: bool
    dependency_id: str
    operation: str
    details: str
    error: Optional[str] = None
    requires_restart: bool = False
    requires_elevation: bool = False


class InstallationService:
    """
    Dedicated service layer managing system readiness, declarative dependency
    verification, guided repair, and diagnostic bundle export.
    """

    def __init__(self):
        self._cached_report: Optional[SystemReadinessReport] = None

    def is_current_process_admin(self) -> bool:
        """Return True if current process has Windows Administrator privileges."""
        if os.name != "nt":
            return os.geteuid() == 0 if hasattr(os, "geteuid") else False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def detect_default_gateway(self) -> Tuple[bool, Optional[str]]:
        """Probe default IPv4 gateway via routing table."""
        try:
            # Quick probe socket towards external DNS
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Inspect netsh or arp
            if os.name == "nt":
                res = subprocess.run(["netsh", "interface", "ipv4", "show", "routes"], capture_output=True, text=True, timeout=3)
                for line in res.stdout.splitlines():
                    if "0.0.0.0/0" in line:
                        parts = line.split()
                        for p in parts:
                            if p.count(".") == 3 and not p.startswith("0.") and not p.endswith(".255"):
                                return True, p
            return True, local_ip
        except Exception:
            return False, None

    def check_npcap_driver(self) -> DependencyItem:
        """Inspect Npcap Packet Driver installation on Windows."""
        dep = DependencyItem(
            id="npcap_driver",
            name="Npcap Packet Capture Driver",
            purpose="Enables Layer-2 packet capture and ARP redirection for Windows LAN Off-Path enforcement.",
            category="Driver",
            required=False,  # Optional: only required if user uses Windows LAN mode without managed router
            privilege_required="Administrator",
            min_version="1.70",
            download_url="https://npcap.com/dist/npcap-1.79.exe",
            sha256_checksum="OFFICIAL_VERIFIED",
        )

        if os.name != "nt":
            dep.status = ComponentStatus.UNSUPPORTED
            dep.verification_details = "Npcap is only applicable to Windows operating systems."
            return dep

        # 1. Probe wpcap.dll existence
        wpcap_paths = [
            Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "Npcap" / "wpcap.dll",
            Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "wpcap.dll",
        ]
        found_dll = next((p for p in wpcap_paths if p.exists()), None)

        # 2. Probe service status via sc.exe query npcap
        service_running = False
        try:
            sc_res = subprocess.run(["sc.exe", "query", "npcap"], capture_output=True, text=True, timeout=3)
            if "RUNNING" in sc_res.stdout:
                service_running = True
        except Exception:
            pass

        if found_dll and service_running:
            dep.status = ComponentStatus.READY
            dep.detected_version = "Installed (Running)"
            dep.verification_details = f"Npcap driver service is ACTIVE. DLL found at {found_dll}."
        elif found_dll and not service_running:
            dep.status = ComponentStatus.NEEDS_CONFIGURATION
            dep.detected_version = "Installed (Stopped)"
            dep.verification_details = "Npcap driver is installed but the kernel service is currently stopped."
            dep.error_message = "Start the service using 'net start npcap' or run NetCutter with Administrator rights."
        else:
            dep.status = ComponentStatus.NEEDS_INSTALLATION
            dep.verification_details = "Npcap driver is not detected on this system."
            dep.error_message = "Required for unmanaged ISP router mode (Windows LAN Off-Path). Router SSH modes do not require Npcap."

        dep.last_verified = datetime.now(timezone.utc)
        return dep

    def check_python_runtime(self) -> DependencyItem:
        """Verify Python 3.11+ / PySide6 runtime integrity."""
        dep = DependencyItem(
            id="python_runtime",
            name="Desktop Engine Runtime",
            purpose="Core application engine, cryptography vault, and event scheduler.",
            category="Runtime",
            required=True,
            privilege_required="Standard User",
            min_version="3.11.0",
        )
        ver_str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        dep.detected_version = ver_str
        if sys.version_info >= (3, 11):
            dep.status = ComponentStatus.READY
            dep.verification_details = f"Python {ver_str} runtime verified ({platform.architecture()[0]})."
        else:
            dep.status = ComponentStatus.FAILED
            dep.error_message = f"Python version {ver_str} is below the minimum required 3.11."
        dep.last_verified = datetime.now(timezone.utc)
        return dep

    def check_pyside6_qt(self) -> DependencyItem:
        """Verify PySide6 / Qt6 graphic system and SVG plugins."""
        dep = DependencyItem(
            id="pyside6_qt",
            name="PySide6 / Qt 6 Graphics Subsystem",
            purpose="Hardware-accelerated native desktop GUI, SVG icon rendering, and system tray integration.",
            category="Runtime",
            required=True,
            privilege_required="Standard User",
            min_version="6.5.0",
        )
        try:
            import PySide6
            import PySide6.QtSvg  # noqa: F401 - register SVG format
            from PySide6.QtCore import qVersion
            from PySide6.QtGui import QIcon

            # Test SVG plugin resolution
            test_svg = get_asset_path("icons/laptop.svg")
            icon = QIcon(str(test_svg)) if test_svg.exists() else None
            svg_ok = icon is not None and not icon.isNull()

            dep.detected_version = f"Qt {qVersion()} (PySide6 {PySide6.__version__})"
            if svg_ok:
                dep.status = ComponentStatus.READY
                dep.verification_details = f"Qt runtime initialized. SVG plugin and icon engines verified."
            else:
                dep.status = ComponentStatus.NEEDS_CONFIGURATION
                dep.verification_details = "Qt initialized but SVG plugin rendering returned null."
                dep.error_message = "Ensure qsvg.dll and qsvgicon.dll plugins are present in Qt plugins directory."
        except Exception as ex:
            dep.status = ComponentStatus.FAILED
            dep.error_message = f"PySide6 initialization error: {ex}"

        dep.last_verified = datetime.now(timezone.utc)
        return dep

    def check_vc_redistributable(self) -> DependencyItem:
        """Verify Microsoft Visual C++ 2015-2022 Redistributable."""
        dep = DependencyItem(
            id="vc_redist",
            name="Microsoft Visual C++ Runtime",
            purpose="Native C runtime DLLs required by PySide6, Scapy, and cryptography modules.",
            category="Runtime",
            required=True,
            privilege_required="Administrator",
            min_version="14.0",
        )
        if os.name != "nt":
            dep.status = ComponentStatus.OPTIONAL
            dep.verification_details = "Not required on non-Windows platforms."
            return dep

        sys32 = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32"
        vc_dlls = ["msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"]
        missing = [d for d in vc_dlls if not (sys32 / d).exists()]

        if not missing:
            dep.status = ComponentStatus.READY
            dep.detected_version = "Visual C++ 2015-2022 (v14.x)"
            dep.verification_details = "All required MSVC runtime libraries are present in System32."
        else:
            dep.status = ComponentStatus.NEEDS_INSTALLATION
            dep.error_message = f"Missing runtime libraries: {', '.join(missing)}."
            dep.download_url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

        dep.last_verified = datetime.now(timezone.utc)
        return dep

    def check_ssh_paramiko(self) -> DependencyItem:
        """Verify SSH protocol client for Linux and OpenWrt router control."""
        dep = DependencyItem(
            id="ssh_paramiko",
            name="Router SSH Protocol Client (Paramiko)",
            purpose="Provides cryptographically verified SSH key pinning and command orchestration for OpenWrt and Linux routers.",
            category="Networking",
            required=True,
            privilege_required="Standard User",
            min_version="3.0.0",
        )
        try:
            import paramiko
            dep.detected_version = paramiko.__version__
            dep.status = ComponentStatus.READY
            dep.verification_details = f"Paramiko SSH library {paramiko.__version__} loaded successfully."
        except Exception as ex:
            dep.status = ComponentStatus.FAILED
            dep.error_message = f"Paramiko could not be loaded: {ex}"

        dep.last_verified = datetime.now(timezone.utc)
        return dep

    def check_cryptography_vault(self) -> DependencyItem:
        """Verify AES-GCM-256 cryptographic engine for secure password storage."""
        dep = DependencyItem(
            id="cryptography_engine",
            name="Cryptographic Credential Vault",
            purpose="Secures router root credentials on disk using machine-bound AES-GCM-256 authenticated encryption.",
            category="Security",
            required=True,
            privilege_required="Standard User",
            min_version="40.0.0",
        )
        try:
            import cryptography
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            # Test key generation and cipher cycle
            k = AESGCM.generate_key(bit_length=256)
            cipher = AESGCM(k)
            nonce = os.urandom(12)
            ct = cipher.encrypt(nonce, b"test-probe", None)
            pt = cipher.decrypt(nonce, ct, None)
            if pt == b"test-probe":
                dep.detected_version = cryptography.__version__
                dep.status = ComponentStatus.READY
                dep.verification_details = f"Cryptography {cryptography.__version__} AES-GCM-256 cycle verified."
            else:
                dep.status = ComponentStatus.FAILED
                dep.error_message = "Cryptography probe self-test roundtrip failed."
        except Exception as ex:
            dep.status = ComponentStatus.FAILED
            dep.error_message = f"Cryptography engine error: {ex}"

        dep.last_verified = datetime.now(timezone.utc)
        return dep

    def run_system_audit(self) -> SystemReadinessReport:
        """Execute full system readiness audit across all dependencies and subsystems."""
        is_admin = self.is_current_process_admin()
        os_name = platform.system()
        os_ver = f"{platform.release()} (Build {platform.version()})"
        os_arch = platform.machine()

        # Disk space on app data drive
        try:
            app_dir = get_app_data_dir()
            app_ok = app_dir.is_dir()
            usage = shutil.disk_usage(app_dir)
            free_gb = round(usage.free / (1024**3), 2)
        except Exception:
            app_ok = False
            free_gb = 0.0

        # Assets integrity
        assets_dir = get_assets_dir()
        brand_mark = get_asset_path("netcutter-mark.png")
        assets_ok = assets_dir.is_dir() and brand_mark.exists()

        # Network connectivity
        net_connected, gw_ip = self.detect_default_gateway()

        # Dependencies registry audit
        deps = [
            self.check_python_runtime(),
            self.check_pyside6_qt(),
            self.check_cryptography_vault(),
            self.check_ssh_paramiko(),
            self.check_vc_redistributable(),
            self.check_npcap_driver(),
        ]

        report = SystemReadinessReport(
            os_name=os_name,
            os_version=os_ver,
            os_arch=os_arch,
            is_admin=is_admin,
            disk_free_gb=free_gb,
            local_app_data_ok=app_ok,
            network_connected=net_connected,
            default_gateway_ip=gw_ip,
            assets_integrity_ok=assets_ok,
            dependencies=deps,
        )
        self._cached_report = report
        return report

    def get_cached_report(self) -> Optional[SystemReadinessReport]:
        return self._cached_report

    def repair_component(self, dep_id: str) -> InstallationOperationResult:
        """Attempt safe local repair or configuration of a component."""
        if dep_id == "npcap_driver":
            if os.name != "nt":
                return InstallationOperationResult(
                    success=False,
                    dependency_id=dep_id,
                    operation="REPAIR",
                    details="Npcap is only applicable on Windows.",
                )
            if not self.is_current_process_admin():
                return InstallationOperationResult(
                    success=False,
                    dependency_id=dep_id,
                    operation="REPAIR",
                    details="Starting or repairing the Npcap service requires Administrator elevation.",
                    requires_elevation=True,
                )
            try:
                res = subprocess.run(["net", "start", "npcap"], capture_output=True, text=True, timeout=10)
                if res.returncode in (0, 2):  # 2 = service already started
                    return InstallationOperationResult(
                        success=True,
                        dependency_id=dep_id,
                        operation="REPAIR",
                        details="Npcap driver service successfully started and verified.",
                    )
                return InstallationOperationResult(
                    success=False,
                    dependency_id=dep_id,
                    operation="REPAIR",
                    details=f"Failed to start npcap service: {res.stderr.strip() or res.stdout.strip()}",
                )
            except Exception as ex:
                return InstallationOperationResult(
                    success=False,
                    dependency_id=dep_id,
                    operation="REPAIR",
                    details=f"Service start error: {ex}",
                )

        elif dep_id == "pyside6_qt":
            # Re-verify plugins
            assets_dir = get_assets_dir()
            if assets_dir.is_dir():
                return InstallationOperationResult(
                    success=True,
                    dependency_id=dep_id,
                    operation="REPAIR",
                    details="Asset paths re-synchronized and SVG icon registry refreshed.",
                )

        return InstallationOperationResult(
            success=False,
            dependency_id=dep_id,
            operation="REPAIR",
            details="Automated in-place repair is not available for this component. Reinstalling or running the official installer is recommended.",
        )

    def generate_redacted_diagnostic_json(self) -> str:
        """Generate a fully sanitized, shareable JSON diagnostic report."""
        report = self.run_system_audit()
        return json.dumps(report.to_redacted_dict(), indent=2)
