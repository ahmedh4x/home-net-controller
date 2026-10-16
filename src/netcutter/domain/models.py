"""
Domain Models for NetCutter Network Management System.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class InternetAccessState(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"


class PolicyStatus(str, Enum):
    SYNCHRONIZED = "SYNCHRONIZED"
    APPLYING = "APPLYING"
    DRIFTED = "DRIFTED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    AMBIGUOUS = "AMBIGUOUS"


class DeviceCategory(str, Enum):
    SMARTPHONE = "Smartphone"
    LAPTOP_PC = "Windows PC / Laptop"
    MAC = "Mac"
    TABLET = "Tablet"
    SMART_TV = "Smart TV"
    PRINTER = "Printer"
    GAMING_CONSOLE = "Gaming Console"
    ROUTER_AP = "Router / AP"
    IOT_DEVICE = "IoT / Embedded"
    UNKNOWN = "Unknown Device"


class BackendType(str, Enum):
    OPENWRT = "OPENWRT"
    LINUX = "LINUX"
    MIKROTIK = "MIKROTIK"
    WINDOWS_LAN = "WINDOWS_LAN"
    MOCK = "MOCK"


class GatewayStatus(str, Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    AUTHENTICATING = "AUTHENTICATING"
    DEGRADED = "DEGRADED"
    UNKNOWN = "UNKNOWN"


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to lowercase colon-separated format."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address format: {mac}")
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


def is_locally_administered_mac(mac: str) -> bool:
    """
    Check if MAC has locally administered bit set (bit 1 of octet 0).
    Randomized MACs on iOS/Android/Windows typically set this bit.
    """
    try:
        norm = normalize_mac(mac)
        first_byte = int(norm.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def format_rate(bytes_per_sec: float) -> str:
    """Format bytes per second into human-readable B/s, KB/s, or MB/s."""
    if bytes_per_sec >= 1_000_000:
        return f"{bytes_per_sec / 1_000_000.0:.1f} MB/s"
    elif bytes_per_sec >= 1_000:
        return f"{bytes_per_sec / 1_000.0:.1f} KB/s"
    elif bytes_per_sec > 0:
        return f"{bytes_per_sec:.0f} B/s"
    return "0 B/s"


def format_bytes(total_bytes: int) -> str:
    """Format total byte count into B, KB, MB, or GB."""
    if total_bytes >= 1_000_000_000:
        return f"{total_bytes / 1_000_000_000.0:.2f} GB"
    elif total_bytes >= 1_000_000:
        return f"{total_bytes / 1_000_000.0:.1f} MB"
    elif total_bytes >= 1_000:
        return f"{total_bytes / 1_000.0:.1f} KB"
    return f"{total_bytes} B"


@dataclass
class BandwidthLimit:
    """Bandwidth limit in kilobits per second (Kbps)."""
    rate_kbps: int = 0  # 0 indicates unlimited

    @property
    def is_unlimited(self) -> bool:
        return self.rate_kbps <= 0

    @property
    def rate_mbps(self) -> float:
        return round(self.rate_kbps / 1024.0, 2)

    def to_display_string(self) -> str:
        if self.is_unlimited:
            return "Unlimited"
        if self.rate_kbps >= 1024:
            mbps = self.rate_kbps / 1024.0
            return f"{mbps:.1f} Mbps" if mbps % 1 != 0 else f"{int(mbps)} Mbps"
        return f"{self.rate_kbps} Kbps"


@dataclass
class DevicePolicyState:
    """Encapsulates the state of network enforcement for a device."""
    internet_access: InternetAccessState = InternetAccessState.ALLOWED
    download_limit_kbps: int = 0  # 0 = unlimited
    upload_limit_kbps: int = 0    # 0 = unlimited

    @property
    def is_blocked(self) -> bool:
        return self.internet_access == InternetAccessState.BLOCKED

    @property
    def has_download_limit(self) -> bool:
        return self.download_limit_kbps > 0

    @property
    def has_upload_limit(self) -> bool:
        return self.upload_limit_kbps > 0


@dataclass
class Device:
    """Represents a logical client device on the network."""
    device_guid: str = field(default_factory=lambda: str(uuid.uuid4()))
    display_name: str = "Unknown Device"
    primary_mac: str = ""
    historical_macs: List[str] = field(default_factory=list)
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    dhcp_client_id: Optional[str] = None
    duid: Optional[str] = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_online: bool = True
    confidence_level: ConfidenceLevel = ConfidenceLevel.HIGH
    is_randomized_mac: bool = False
    category: DeviceCategory = DeviceCategory.UNKNOWN
    classification_basis: str = ""
    
    # Active policy references
    desired_policy: DevicePolicyState = field(default_factory=DevicePolicyState)
    observed_policy: DevicePolicyState = field(default_factory=DevicePolicyState)
    policy_status: PolicyStatus = PolicyStatus.SYNCHRONIZED
    last_policy_error: Optional[str] = None
    last_sync: Optional[datetime] = None

    # Live Traffic Accounting
    download_rate_bps: float = 0.0
    upload_rate_bps: float = 0.0
    total_download_bytes: int = 0
    total_upload_bytes: int = 0
    last_traffic_time: Optional[datetime] = None
    traffic_monitoring_mode: str = "OFFPATH_LIMITED"

    def __post_init__(self):
        if self.primary_mac:
            self.primary_mac = normalize_mac(self.primary_mac)
            if self.primary_mac not in self.historical_macs:
                self.historical_macs.append(self.primary_mac)
            self.is_randomized_mac = is_locally_administered_mac(self.primary_mac)

    @property
    def primary_ipv4(self) -> str:
        return self.ipv4_addresses[0] if self.ipv4_addresses else "No IPv4"

    @property
    def primary_ipv6(self) -> str:
        # Prefer global unicast over link-local if available
        for ip in self.ipv6_addresses:
            if not ip.lower().startswith("fe80:"):
                return ip
        return self.ipv6_addresses[0] if self.ipv6_addresses else "No IPv6"

    @property
    def download_rate_display(self) -> str:
        return format_rate(self.download_rate_bps)

    @property
    def upload_rate_display(self) -> str:
        return format_rate(self.upload_rate_bps)

    @property
    def total_download_display(self) -> str:
        return format_bytes(self.total_download_bytes)

    @property
    def total_upload_display(self) -> str:
        return format_bytes(self.total_upload_bytes)

    @property
    def total_usage_display(self) -> str:
        return f"↓ {self.total_download_display} / ↑ {self.total_upload_display}"


@dataclass
class GatewayConfig:
    """Configuration record for connecting to a gateway router."""
    gateway_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Default Gateway"
    host: str = "192.168.1.1"
    port: int = 22
    backend_type: BackendType = BackendType.OPENWRT
    username: str = "root"
    auth_secret_id: Optional[str] = None  # Reference to encrypted credential store
    is_active: bool = True
    lan_interface: str = "br-lan"
    wan_interface: str = "eth1"
    last_sync: Optional[datetime] = None
    status: GatewayStatus = GatewayStatus.UNKNOWN
    last_error: Optional[str] = None
    # Security & Verification configuration
    ssh_host_key_fingerprint: Optional[str] = None  # e.g. "SHA256:..." pinned host key
    ssh_key_data: Optional[str] = None  # Encrypted/provided private key text/path if key auth is used
    tls_verify: bool = True  # Strict CA validation by default; False requires explicit opt-out
    tls_ca_path: Optional[str] = None  # Custom CA bundle path
    tls_fingerprint: Optional[str] = None  # SHA256 cert fingerprint for pinning self-signed certs


class DomainMatchType(str, Enum):
    """Whether a rule matches only the exact domain or also all subdomains."""
    EXACT = "EXACT"
    SUBDOMAIN = "SUBDOMAIN"


class DomainScope(str, Enum):
    """Scope of domain blocking rule."""
    GLOBAL = "GLOBAL"
    DEVICE = "DEVICE"


class DomainEnforcementStatus(str, Enum):
    """Verified enforcement status of a domain blocking rule."""
    ACTIVE = "Active"
    PENDING = "Pending"
    UNSUPPORTED = "Unsupported"
    FAILED = "Failed"


@dataclass
class DomainBlockingRule:
    """Persistent domain or website blocking rule."""
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    domain: str = ""
    match_type: DomainMatchType = DomainMatchType.SUBDOMAIN
    target_scope: DomainScope = DomainScope.GLOBAL
    target_device_guid: Optional[str] = None
    target_device_name: Optional[str] = None
    target_mac: Optional[str] = None
    target_ip: Optional[str] = None
    is_enabled: bool = True
    enforcement_status: DomainEnforcementStatus = DomainEnforcementStatus.PENDING
    last_error: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified_at: Optional[datetime] = None
    notes: Optional[str] = None
    hits_count: int = 0

    @property
    def display_scope(self) -> str:
        if self.target_scope == DomainScope.GLOBAL:
            return "All Devices (Global)"
        name = self.target_device_name or "Specific Device"
        if self.target_ip:
            return f"{name} ({self.target_ip})"
        return name

    @property
    def display_match_type(self) -> str:
        if self.match_type == DomainMatchType.SUBDOMAIN:
            return f"*.{self.domain} + root"
        return f"{self.domain} (exact)"


@dataclass
class BlockedDomainEvent:
    """Audit log entry for an intercepted or filtered domain request."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: Optional[str] = None
    domain: str = ""
    device_guid: Optional[str] = None
    device_name: Optional[str] = None
    client_ip: Optional[str] = None
    client_mac: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: str = "DNS_SINKHOLE_ZERO_IP"  # DNS_SINKHOLE_ZERO_IP, DNS_SINKHOLE_NXDOMAIN, TLS_SNI_DROP
    mechanism: str = "Layer-2 DNS Interceptor"
    details: str = ""


