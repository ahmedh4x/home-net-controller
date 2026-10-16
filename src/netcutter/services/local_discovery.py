"""
Local Subnet Discovery Provider.
Discovers local IPv4/IPv6 neighbors on the local subnet using operating-system native
APIs and neighbor caches (Get-NetNeighbor, arp -a) without requiring packet drivers,
Npcap, or elevated administrator privileges.
"""
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
from typing import Dict, List, Optional, Set

from netcutter.backends.base import DiscoveredDeviceRaw
from netcutter.domain.models import normalize_mac

logger = logging.getLogger("netcutter.discovery.local")

# Common broadcast and multicast MACs/IPs to exclude from client lists
IGNORED_IPS: Set[str] = {
    "0.0.0.0",
    "255.255.255.255",
}

IGNORED_MACS: Set[str] = {
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",
}


class LocalSubnetDiscoveryProvider:
    """
    Safe, unprivileged discovery of real devices on the local subnet.
    Queries the OS neighbor cache and ARP tables, resolving hostnames and identifying gateways.
    """

    @staticmethod
    def is_multicast_or_broadcast(ip: str) -> bool:
        """Check if an IPv4 address is in multicast or broadcast ranges."""
        if ip in IGNORED_IPS:
            return True
        parts = ip.split(".")
        if len(parts) == 4 and parts[0].isdigit():
            first_octet = int(parts[0])
            # 224.0.0.0 to 239.255.255.255 is multicast
            if 224 <= first_octet <= 239:
                return True
        return False

    @staticmethod
    def get_local_interfaces() -> List[Dict[str, str]]:
        """Return list of local IPv4 interfaces with interface index and address."""
        ifaces = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
            ifaces.append({"ip": primary_ip, "name": "Primary LAN"})
        except Exception:
            pass
        return ifaces

    @classmethod
    def discover_via_get_net_neighbor(cls) -> List[DiscoveredDeviceRaw]:
        """Query PowerShell Get-NetNeighbor for IPv4 neighbors (Windows only)."""
        if os.name != "nt":
            return []

        results: Dict[str, DiscoveredDeviceRaw] = {}
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetNeighbor -AddressFamily IPv4 | Select-Object -Property IPAddress, LinkLayerAddress, State | ConvertTo-Json",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                import json
                try:
                    data = json.loads(res.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    for entry in data:
                        ip = entry.get("IPAddress", "").strip()
                        mac_raw = entry.get("LinkLayerAddress", "").strip().replace("-", ":")
                        state = entry.get("State", "")
                        if not ip or not mac_raw or state == "Unreachable":
                            continue
                        if cls.is_multicast_or_broadcast(ip):
                            continue
                        try:
                            norm_m = normalize_mac(mac_raw)
                        except Exception:
                            continue
                        if norm_m in IGNORED_MACS:
                            continue

                        hostname = cls._try_resolve_hostname(ip)
                        dev = DiscoveredDeviceRaw(
                            mac=norm_m,
                            ipv4_addresses=[ip],
                            hostname=hostname,
                            interface="Windows Neighbor Cache",
                            is_active=True,
                        )
                        results[norm_m] = dev
                except Exception as ex:
                    logger.debug(f"JSON parsing of Get-NetNeighbor output failed: {ex}")
        except Exception as ex:
            logger.debug(f"Get-NetNeighbor execution failed: {ex}")

        return list(results.values())

    @classmethod
    def discover_via_arp_table(cls) -> List[DiscoveredDeviceRaw]:
        """Query standard system arp -a table (cross-platform)."""
        results: Dict[str, DiscoveredDeviceRaw] = {}
        try:
            res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=4)
            for line in res.stdout.splitlines():
                parts = line.split()
                # Windows format: IP Physical-Address Type
                # Linux format: IP hw_type HW_address Flags Mask Device
                if len(parts) >= 3:
                    ip = parts[0]
                    mac_candidate = parts[1].replace("-", ":")
                    # Check if dynamic or valid entry
                    if cls.is_multicast_or_broadcast(ip):
                        continue
                    if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac_candidate):
                        try:
                            norm_m = normalize_mac(mac_candidate)
                        except Exception:
                            continue
                        if norm_m in IGNORED_MACS:
                            continue

                        hostname = cls._try_resolve_hostname(ip)
                        dev = DiscoveredDeviceRaw(
                            mac=norm_m,
                            ipv4_addresses=[ip],
                            hostname=hostname,
                            interface="System ARP Table",
                            is_active=True,
                        )
                        results[norm_m] = dev
        except Exception as ex:
            logger.debug(f"ARP table query failed: {ex}")

        return list(results.values())

    @classmethod
    def discover_local_clients(cls, exclude_ips: Optional[Set[str]] = None) -> List[DiscoveredDeviceRaw]:
        """
        Run comprehensive unprivileged local discovery merging Get-NetNeighbor and ARP cache.
        Filters out excluded IPs (e.g. gateway IP, local host IP).
        """
        exclude_ips = exclude_ips or set()
        devices_by_mac: Dict[str, DiscoveredDeviceRaw] = {}

        # 1. Probe Get-NetNeighbor (Windows)
        for d in cls.discover_via_get_net_neighbor():
            if any(ip in exclude_ips for ip in d.ipv4_addresses):
                continue
            devices_by_mac[d.mac] = d

        # 2. Probe ARP table
        for d in cls.discover_via_arp_table():
            if any(ip in exclude_ips for ip in d.ipv4_addresses):
                continue
            if d.mac in devices_by_mac:
                # Merge IP addresses
                existing = devices_by_mac[d.mac]
                for ip in d.ipv4_addresses:
                    if ip not in existing.ipv4_addresses:
                        existing.ipv4_addresses.append(ip)
                if not existing.hostname and d.hostname:
                    existing.hostname = d.hostname
            else:
                devices_by_mac[d.mac] = d

        return list(devices_by_mac.values())

    @staticmethod
    def _try_resolve_hostname(ip: str) -> Optional[str]:
        """Attempt safe reverse DNS lookup with short timeout."""
        try:
            socket.setdefaulttimeout(0.5)
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return None
