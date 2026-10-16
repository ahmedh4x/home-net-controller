from enum import Enum, Flag, auto
from typing import Dict, Optional


class CapabilityState(str, Enum):
    """Explicit, typed status of an individual application or backend capability."""
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    REQUIRES_SETUP = "REQUIRES_SETUP"
    REQUIRES_PRIVILEGES = "REQUIRES_PRIVILEGES"
    UNSUPPORTED = "UNSUPPORTED"
    SIMULATED = "SIMULATED"
    ERROR = "ERROR"


class BackendCapabilities(Flag):
    NONE = 0
    MAC_BLOCKING = auto()
    IPV4_BLOCKING = auto()
    IPV6_BLOCKING = auto()
    UPLOAD_SHAPING = auto()
    DOWNLOAD_SHAPING = auto()
    CONNTRACK_FLUSHING = auto()
    FASTTRACK_BYPASS = auto()
    DISCOVERY = auto()
    NFTABLES_SETS = auto()
    TRAFFIC_COUNTERS = auto()
    OFFPATH_IPV4_ENFORCEMENT = auto()
    DOMAIN_BLOCKING = auto()
    DEVICE_DOMAIN_BLOCKING = auto()

    @classmethod
    def all_gateway_features(cls) -> "BackendCapabilities":
        return (
            cls.MAC_BLOCKING
            | cls.IPV4_BLOCKING
            | cls.IPV6_BLOCKING
            | cls.UPLOAD_SHAPING
            | cls.DOWNLOAD_SHAPING
            | cls.CONNTRACK_FLUSHING
            | cls.DISCOVERY
            | cls.NFTABLES_SETS
            | cls.TRAFFIC_COUNTERS
            | cls.DOMAIN_BLOCKING
            | cls.DEVICE_DOMAIN_BLOCKING
        )



def evaluate_capability_state(
    cap: BackendCapabilities,
    backend_capabilities: BackendCapabilities,
    backend_type_name: str,
    is_connected: bool,
    has_privileges: bool = True,
    has_npcap: bool = True,
    error: Optional[str] = None,
) -> CapabilityState:
    """Evaluate honest, typed capability state considering environment and backend."""
    if error:
        return CapabilityState.ERROR

    if "mock" in backend_type_name.lower() or "simulator" in backend_type_name.lower():
        if cap in backend_capabilities:
            return CapabilityState.SIMULATED
        return CapabilityState.UNSUPPORTED

    if cap not in backend_capabilities:
        return CapabilityState.UNSUPPORTED

    if not is_connected:
        return CapabilityState.UNAVAILABLE

    if cap == BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT:
        if not has_npcap:
            return CapabilityState.REQUIRES_SETUP
        if not has_privileges:
            return CapabilityState.REQUIRES_PRIVILEGES

    return CapabilityState.AVAILABLE


def format_capabilities_report(caps: BackendCapabilities) -> Dict[str, str]:
    """Generates an honest human-readable capabilities dictionary."""
    return {
        "MAC Address Blocking": "SUPPORTED" if BackendCapabilities.MAC_BLOCKING in caps else "NOT SUPPORTED",
        "IPv4 Forwarding Drops": "SUPPORTED" if BackendCapabilities.IPV4_BLOCKING in caps else "NOT SUPPORTED",
        "IPv6 Forwarding Drops": "SUPPORTED" if BackendCapabilities.IPV6_BLOCKING in caps else "NOT SUPPORTED",
        "Off-Path IPv4 LAN Enforcement": "SUPPORTED" if BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT in caps else "NOT SUPPORTED",
        "Per-Device Upload Shaping": "SUPPORTED" if BackendCapabilities.UPLOAD_SHAPING in caps else "NOT SUPPORTED",
        "Per-Device Download Shaping": "SUPPORTED" if BackendCapabilities.DOWNLOAD_SHAPING in caps else "NOT SUPPORTED",
        "Immediate Conntrack Termination": "SUPPORTED" if BackendCapabilities.CONNTRACK_FLUSHING in caps else "NOT SUPPORTED",
        "FastTrack Bypass Detection": "SUPPORTED" if BackendCapabilities.FASTTRACK_BYPASS in caps else "NOT SUPPORTED",
        "Dynamic ARP/NDP Discovery": "SUPPORTED" if BackendCapabilities.DISCOVERY in caps else "NOT SUPPORTED",
        "Kernel nftables Sets": "SUPPORTED" if BackendCapabilities.NFTABLES_SETS in caps else "NOT SUPPORTED",
        "Live Byte/Packet Counters": "SUPPORTED" if BackendCapabilities.TRAFFIC_COUNTERS in caps else "NOT SUPPORTED",
    }


