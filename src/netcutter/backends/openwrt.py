"""
OpenWrt Gateway Backend extending Linux Gateway Backend with OpenWrt-specific discovery.
"""
from __future__ import annotations

import json
from typing import List, Optional
from netcutter.backends.base import DiscoveredDeviceRaw
from netcutter.backends.linux import LinuxGatewayBackend
from netcutter.domain.models import GatewayConfig


class OpenWrtBackend(LinuxGatewayBackend):
    @property
    def backend_name(self) -> str:
        return f"OpenWrt Gateway ({self.config.host})"

    def discover_devices(self) -> List[DiscoveredDeviceRaw]:
        """
        Specialized OpenWrt discovery using ubus call luci-rpc getDHCPLeases
        with fallback to dnsmasq.leases and ARP/NDP tables.
        """
        devices = super().discover_devices()
        device_map = {d.mac.lower(): d for d in devices}

        # Attempt ubus query for LuCI DHCP status
        try:
            code, ubus_out, _ = self._exec_command(
                "ubus call luci-rpc getDHCPLeases 2>/dev/null || true"
            )
            if code == 0 and ubus_out.strip().startswith("{"):
                data = json.loads(ubus_out)
                dhcp_leases = data.get("dhcp_leases", [])
                for lease in dhcp_leases:
                    mac = lease.get("macaddr", "").lower()
                    ip = lease.get("ipaddr")
                    hostname = lease.get("hostname")
                    if mac:
                        if mac not in device_map:
                            dev = DiscoveredDeviceRaw(mac=mac)
                            device_map[mac] = dev
                            devices.append(dev)
                        else:
                            dev = device_map[mac]
                        if ip and ip not in dev.ipv4_addresses:
                            dev.ipv4_addresses.append(ip)
                        if hostname and not dev.hostname:
                            dev.hostname = hostname

                dhcp6_leases = data.get("dhcp6_leases", [])
                for lease in dhcp6_leases:
                    mac = lease.get("macaddr", "").lower()
                    ip6 = lease.get("ip6addr")
                    duid = lease.get("duid")
                    if mac and mac in device_map:
                        dev = device_map[mac]
                        if ip6 and ip6 not in dev.ipv6_addresses:
                            dev.ipv6_addresses.append(ip6)
                        if duid and not dev.duid:
                            dev.duid = duid
        except Exception:
            pass

        return devices
