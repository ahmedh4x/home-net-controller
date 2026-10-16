"""
Device Identity Correlation Engine, OUI Resolver, and Evidence-Based Classifier.
Applies a strict evidence hierarchy to classify devices into honest, verified categories.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from netcutter.domain.models import (
    ConfidenceLevel,
    Device,
    DeviceCategory,
    is_locally_administered_mac,
    normalize_mac,
)

# Extended curated lookup of hardware vendor OUIs
COMMON_OUIS: Dict[str, str] = {
    # Apple
    "00:23:6c": "Apple",
    "10:65:30": "Apple",
    "18:65:90": "Apple",
    "28:cf:e9": "Apple",
    "3c:22:fb": "Apple",
    "60:45:bd": "Apple",
    "64:16:66": "Apple",
    "70:85:c2": "Apple",
    "8c:85:90": "Apple",
    "a4:83:e7": "Apple",
    "f0:18:98": "Apple",
    # Samsung
    "40:b0:34": "Samsung Electronics",
    "9c:20:7b": "Samsung Electronics",
    "50:01:d9": "Samsung Electronics",
    "00:07:ab": "Samsung Electronics",
    # Google
    "00:1a:11": "Google",
    "f4:f5:e8": "Google",
    "54:60:09": "Google",
    # Microsoft
    "00:15:5d": "Microsoft (Hyper-V)",
    "28:18:78": "Microsoft (Surface/Xbox)",
    "7c:ed:8d": "Microsoft Corp",
    # Gaming Consoles
    "00:04:1f": "Sony Interactive Entertainment (PlayStation)",
    "70:9e:29": "Sony Interactive Entertainment (PlayStation)",
    "00:09:bf": "Nintendo Co., Ltd.",
    "98:b6:e9": "Nintendo Co., Ltd.",
    # Smart TV / Streaming
    "fc:fb:fb": "Amazon Technologies (Echo/FireTV)",
    "68:54:5a": "Amazon Technologies",
    "b0:a7:37": "Roku, Inc.",
    "cc:6d:a0": "Roku, Inc.",
    "a8:23:fe": "LG Electronics",
    "00:1f:6b": "LG Electronics",
    # PC / Laptop Vendors
    "00:24:e8": "Dell",
    "00:26:b9": "Dell",
    "e4:54:e8": "Dell",
    "00:1e:67": "Intel",
    "00:21:6a": "Intel",
    "54:e1:ad": "Lenovo",
    "00:21:5c": "Lenovo",
    "04:d9:f5": "ASUSTeK Computer",
    "00:1a:2b": "Ayecom Technology",
    # Printers
    "00:1e:0b": "Hewlett Packard",
    "3c:d9:2b": "HP Inc.",
    "00:00:48": "Seiko Epson",
    "00:26:ab": "Seiko Epson",
    "00:80:77": "Brother Industries",
    "00:1e:8f": "Canon Inc.",
    # Routers & Access Points
    "00:1d:7e": "Cisco-Linksys",
    "50:c7:bf": "TP-Link",
    "e8:48:b8": "TP-Link",
    "00:14:bf": "Cisco Systems",
    "24:a4:3c": "Ubiquiti Networks",
    "dc:9f:db": "Ubiquiti Networks",
    "00:0c:42": "MikroTik",
    "48:8f:5a": "MikroTik",
    "00:18:e7": "NETGEAR",
    "20:4e:7f": "NETGEAR",
    # Virtualization & Development
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM Virtual NIC",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "24:0a:c4": "Espressif Inc. (ESP32/ESP8266)",
    "30:ae:a4": "Espressif Inc.",
}


@dataclass
class IdentityCorrelationEvent:
    """Historical audit of device identity mutations, joins, or MAC rotations."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    device_guid: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    old_mac: Optional[str] = None
    new_mac: str = ""
    reason: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH


def resolve_vendor_by_mac(mac: str) -> Optional[str]:
    """Resolve vendor from the first 3 octets (OUI)."""
    try:
        norm = normalize_mac(mac)
        if is_locally_administered_mac(norm):
            return "Randomized / Private MAC"
        oui = norm[:8]
        return COMMON_OUIS.get(oui, None)
    except Exception:
        return None


def calculate_identity_confidence(
    mac: str,
    hostname: Optional[str],
    duid: Optional[str],
    has_historical_match: bool,
) -> Tuple[ConfidenceLevel, bool]:
    """
    Computes confidence level and whether the MAC is randomized.
    Returns (ConfidenceLevel, is_randomized).
    """
    is_rand = is_locally_administered_mac(mac)
    if not is_rand:
        return ConfidenceLevel.HIGH, False

    # For randomized MACs:
    if has_historical_match:
        return ConfidenceLevel.HIGH, True
    if duid and hostname:
        return ConfidenceLevel.MEDIUM, True
    if hostname:
        return ConfidenceLevel.MEDIUM, True
    return ConfidenceLevel.AMBIGUOUS, True


def classify_device(
    mac: str,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    raw_metadata: Optional[Dict[str, str]] = None,
) -> Tuple[DeviceCategory, str, ConfidenceLevel]:
    """
    Classify a network client device based on a verified evidence hierarchy:
    1. Direct router/DHCP reported device type metadata.
    2. Specific DHCP hostname patterns.
    3. IEEE MAC OUI vendor signatures.
    4. Guarded heuristics for randomized/private MACs.

    Returns: (DeviceCategory, classification_basis, ConfidenceLevel)
    """
    is_rand = is_locally_administered_mac(mac)
    host_clean = (hostname or "").strip().lower()
    meta = raw_metadata or {}

    # --- Level 1: Direct Router / DHCP Protocol Metadata ---
    if "device_type" in meta and meta["device_type"]:
        t = meta["device_type"].lower()
        if "phone" in t or "mobile" in t:
            return DeviceCategory.SMARTPHONE, "Router reported metadata (Phone)", ConfidenceLevel.HIGH
        if "pc" in t or "desktop" in t or "laptop" in t or "computer" in t:
            return DeviceCategory.LAPTOP_PC, "Router reported metadata (PC)", ConfidenceLevel.HIGH
        if "mac" in t or "apple" in t:
            return DeviceCategory.MAC, "Router reported metadata (Mac)", ConfidenceLevel.HIGH
        if "tv" in t or "media" in t:
            return DeviceCategory.SMART_TV, "Router reported metadata (Smart TV)", ConfidenceLevel.HIGH
        if "printer" in t:
            return DeviceCategory.PRINTER, "Router reported metadata (Printer)", ConfidenceLevel.HIGH
        if "console" in t or "game" in t:
            return DeviceCategory.GAMING_CONSOLE, "Router reported metadata (Console)", ConfidenceLevel.HIGH
        if "router" in t or "ap" in t or "switch" in t:
            return DeviceCategory.ROUTER_AP, "Router reported metadata (Router/AP)", ConfidenceLevel.HIGH
        if "iot" in t or "embedded" in t:
            return DeviceCategory.IOT_DEVICE, "Router reported metadata (IoT)", ConfidenceLevel.HIGH

    # --- Level 2: DHCP Hostname Patterns ---
    if host_clean:
        # Smartphones & Tablets
        if re.search(r"\b(iphone|ios)\b", host_clean):
            conf = ConfidenceLevel.MEDIUM if is_rand else ConfidenceLevel.HIGH
            return DeviceCategory.SMARTPHONE, "DHCP hostname pattern (iPhone)", conf
        if re.search(r"\b(ipad)\b", host_clean):
            conf = ConfidenceLevel.MEDIUM if is_rand else ConfidenceLevel.HIGH
            return DeviceCategory.TABLET, "DHCP hostname pattern (iPad)", conf
        if re.search(r"(android|galaxy|pixel|redmi|xiaomi|oneplus|oppo|vivo|huawei|honor|realme|smartphone|phone)", host_clean):
            conf = ConfidenceLevel.MEDIUM if is_rand else ConfidenceLevel.HIGH
            return DeviceCategory.SMARTPHONE, "DHCP hostname pattern (Smartphone)", conf

        # PCs & Laptops
        if re.search(r"(desktop-|laptop-|win10|win11|surface-|msft-|thinkpad|latitude|inspiron|-pc\b|windows-pc|linux-server)", host_clean):
            return DeviceCategory.LAPTOP_PC, "DHCP hostname pattern (PC / Workstation)", ConfidenceLevel.HIGH
        if re.search(r"(macbook|imac|macmini|macpro)", host_clean):
            return DeviceCategory.MAC, "DHCP hostname pattern (Mac)", ConfidenceLevel.HIGH

        # Smart TV & Media Streamers
        if re.search(r"(smarttv|bravia|roku|appletv|firetv|shieldtv|chromecast|webos|tizen|kodi|cast|smart-tv)", host_clean) or host_clean.endswith("-tv") or host_clean.startswith("tv-"):
            return DeviceCategory.SMART_TV, "DHCP hostname pattern (Smart TV/Streaming)", ConfidenceLevel.HIGH

        # Printers
        if re.search(r"(printer|laserjet|deskjet|epson|brother|canon|officejet|pagepro)", host_clean):
            return DeviceCategory.PRINTER, "DHCP hostname pattern (Network Printer)", ConfidenceLevel.HIGH

        # Gaming Consoles
        if re.search(r"(playstation|ps4|ps5|xbox|nintendo|switch)", host_clean):
            return DeviceCategory.GAMING_CONSOLE, "DHCP hostname pattern (Gaming Console)", ConfidenceLevel.HIGH

        # Routers & Networking
        if re.search(r"(router|openwrt|repeater|extender|accesspoint|switch|gateway)", host_clean):
            return DeviceCategory.ROUTER_AP, "DHCP hostname pattern (Router/AP)", ConfidenceLevel.HIGH

        # IoT & Embedded
        if re.search(r"(esp8266|esp32|sonoff|tasmota|shelly|tuya|raspberrypi|arduino|homeassistant|iot|iot-device|plug)", host_clean):
            return DeviceCategory.IOT_DEVICE, "DHCP hostname pattern (IoT/Embedded)", ConfidenceLevel.HIGH

    # --- Level 3: IEEE MAC OUI Signatures ---
    if vendor and not is_rand:
        v_lower = vendor.lower()
        if "raspberry pi" in v_lower or "espressif" in v_lower:
            return DeviceCategory.IOT_DEVICE, f"IEEE OUI vendor ({vendor})", ConfidenceLevel.HIGH
        if "sony interactive" in v_lower or "nintendo" in v_lower:
            return DeviceCategory.GAMING_CONSOLE, f"IEEE OUI vendor ({vendor})", ConfidenceLevel.HIGH
        if "roku" in v_lower:
            return DeviceCategory.SMART_TV, f"IEEE OUI vendor ({vendor})", ConfidenceLevel.HIGH
        if "brother" in v_lower or "epson" in v_lower or "canon" in v_lower:
            return DeviceCategory.PRINTER, f"IEEE OUI vendor ({vendor})", ConfidenceLevel.HIGH
        if "dell" in v_lower or "lenovo" in v_lower or "intel" in v_lower:
            return DeviceCategory.LAPTOP_PC, f"IEEE OUI vendor ({vendor})", ConfidenceLevel.MEDIUM
        if "cisco" in v_lower or "tp-link" in v_lower or "netgear" in v_lower or "ubiquiti" in v_lower or "mikrotik" in v_lower:
            return DeviceCategory.ROUTER_AP, f"IEEE OUI vendor ({vendor})", ConfidenceLevel.MEDIUM

    # --- Level 4: Fallback & Randomized MAC Handling ---
    if is_rand:
        return (
            DeviceCategory.UNKNOWN,
            "Locally administered (Randomized) MAC without identifying DHCP signature",
            ConfidenceLevel.AMBIGUOUS,
        )

    return DeviceCategory.UNKNOWN, "Generic unclassified device", ConfidenceLevel.LOW


def format_device_display_name(
    raw_hostname: Optional[str],
    vendor: Optional[str],
    category: DeviceCategory,
    ipv4_addresses: Optional[List[str]] = None,
    mac: str = "",
    is_randomized: bool = False,
) -> str:
    """Format a clear, helpful, human-scannable display name for a network client."""
    # 1. Clean DHCP hostname if meaningful
    if raw_hostname:
        clean_host = raw_hostname.strip()
        if clean_host and clean_host.lower() not in ("*", "unknown", "none", "localhost", "android"):
            return clean_host
        elif clean_host.lower() == "android" and vendor and "Randomized" not in vendor:
            # e.g., Samsung Galaxy or similar if vendor known
            pass
        elif clean_host and clean_host.lower() not in ("*", "unknown", "none", "localhost"):
            return clean_host

    # Helper for IP representation
    ip_str = ipv4_addresses[0] if (ipv4_addresses and len(ipv4_addresses) > 0 and ipv4_addresses[0]) else ""
    mac_suffix = mac[-5:] if len(mac) >= 5 else ""

    # 2. Known hardware vendor (cleaned of corporate suffixes)
    clean_vendor = ""
    if vendor and not is_randomized and "Randomized" not in vendor:
        clean_vendor = re.sub(
            r",?\s*(?:Inc\b\.?|Corp\b\.?|Corporation\b|LLC\b|Ltd\b\.?|Co\.,?\s*Ltd\.?|Foundation\b|Technologies\b|Electronics\b|Interactive Entertainment\b).*$",
            "",
            vendor,
            flags=re.IGNORECASE,
        ).strip()
        if "Sony" in clean_vendor:
            clean_vendor = "Sony"
        elif "Apple" in clean_vendor:
            clean_vendor = "Apple"
        elif "Microsoft" in clean_vendor:
            clean_vendor = "Microsoft"

    # 3. Known vendor present:
    if clean_vendor:
        if category and category not in (DeviceCategory.UNKNOWN, DeviceCategory.IOT_DEVICE):
            cat_label = category.value.split(" / ")[0]  # e.g. "Smart TV", "Windows PC", "Smartphone"
            if clean_vendor.lower() in cat_label.lower():
                base_desc = cat_label
            else:
                base_desc = f"{clean_vendor} {cat_label}"
        else:
            base_desc = f"{clean_vendor} Device"

        if ip_str:
            return f"{base_desc} ({ip_str})"
        elif mac_suffix:
            return f"{base_desc} ({mac_suffix})"
        return base_desc

    # 4. Known Category without vendor (e.g. Smart TV or Gaming Console discovered by DHCP/mDNS)
    if category and category != DeviceCategory.UNKNOWN:
        cat_label = category.value.split(" / ")[0]
        if ip_str:
            return f"{cat_label} ({ip_str})"
        elif mac_suffix:
            return f"{cat_label} ({mac_suffix})"
        return cat_label

    # 5. Randomized MAC fallback
    if is_randomized:
        if ip_str:
            return f"Private Client ({ip_str})"
        elif mac_suffix:
            return f"Private Client ({mac_suffix})"
        return "Private Client"

    # 6. Standard Unidentified Device
    if ip_str:
        return f"Client ({ip_str})"
    elif mac_suffix:
        return f"Client ({mac_suffix})"
    return "Network Client"
