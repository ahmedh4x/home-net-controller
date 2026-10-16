"""
Linux / OpenWrt Gateway Backend via Secure SSH.
Enforces packet drop policies using kernel nftables sets and QoS using tc HTB + fq_codel.
"""
from __future__ import annotations

import hashlib
import io
import ipaddress
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import paramiko
from netcutter.backends.base import (
    DiscoveredDeviceRaw,
    IGatewayBackend,
    ObservedPolicy,
    PolicyExecutionResult,
)
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.models import (
    DomainBlockingRule,
    DomainEnforcementStatus,
    GatewayConfig,
    InternetAccessState,
    normalize_mac,
)

logger = logging.getLogger("netcutter.backend.linux")




class HostKeyFingerprintPolicy(paramiko.MissingHostKeyPolicy):
    """
    Paramiko MissingHostKeyPolicy that enforces fingerprint pinning.
    If expected_fingerprint is None, accepts and records the offered key (trust on first use / pin).
    If expected_fingerprint is set, validates SHA256 hex/base64 fingerprint and rejects on mismatch.
    """
    def __init__(self, expected_fingerprint: Optional[str] = None):
        self.expected_fingerprint = expected_fingerprint.strip() if expected_fingerprint else None
        self.recorded_fingerprint: Optional[str] = None

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey):
        import base64
        # Format as standard OpenSSH SHA256 fingerprint: SHA256:<base64>
        raw_hash = hashlib.sha256(key.asbytes()).digest()
        b64_fp = "SHA256:" + base64.b64encode(raw_hash).decode("utf-8").rstrip("=")
        hex_fp = hashlib.sha256(key.asbytes()).hexdigest()
        self.recorded_fingerprint = b64_fp

        if not self.expected_fingerprint:
            # First-use pin / acceptance
            logger.info(f"SSH host key accepted for {hostname} with fingerprint {b64_fp}")
            client.get_host_keys().add(hostname, key.get_name(), key)
            return

        # Validate against pinned fingerprint (support either SHA256:<b64> or raw hex)
        exp = self.expected_fingerprint
        matched = (
            exp == b64_fp
            or exp == b64_fp.removeprefix("SHA256:")
            or exp.lower() == hex_fp.lower()
            or exp.lower() == f"sha256:{hex_fp.lower()}"
        )
        if not matched:
            raise paramiko.SSHException(
                f"Host key verification failed for {hostname}! "
                f"Offered fingerprint: {b64_fp}, expected pinned fingerprint: {self.expected_fingerprint}. "
                "Possible Man-in-the-Middle attack or router hardware replacement."
            )
        client.get_host_keys().add(hostname, key.get_name(), key)


class LinuxGatewayBackend(IGatewayBackend):
    def __init__(self, config: GatewayConfig, password_or_key: Optional[str] = None):
        self.config = config
        self._secret = password_or_key
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._mac_class_map: Dict[str, int] = {}

    @property
    def backend_name(self) -> str:
        return f"Linux Gateway ({self.config.host})"

    @property
    def capabilities(self) -> BackendCapabilities:
        return (
            BackendCapabilities.MAC_BLOCKING
            | BackendCapabilities.IPV4_BLOCKING
            | BackendCapabilities.IPV6_BLOCKING
            | BackendCapabilities.UPLOAD_SHAPING
            | BackendCapabilities.DOWNLOAD_SHAPING
            | BackendCapabilities.CONNTRACK_FLUSHING
            | BackendCapabilities.DISCOVERY
            | BackendCapabilities.NFTABLES_SETS
            | BackendCapabilities.TRAFFIC_COUNTERS
            | BackendCapabilities.DOMAIN_BLOCKING
        )

    def is_connected(self) -> bool:
        if self._ssh_client and self._ssh_client.get_transport():
            return self._ssh_client.get_transport().is_active()
        return False

    def connect(self) -> bool:
        try:
            self._ssh_client = paramiko.SSHClient()
            # Load system known hosts if present
            try:
                self._ssh_client.load_system_host_keys()
            except Exception:
                pass

            # Configure HostKeyFingerprintPolicy
            policy = HostKeyFingerprintPolicy(self.config.ssh_host_key_fingerprint)
            self._ssh_client.set_missing_host_key_policy(policy)
            
            kwargs = {
                "hostname": self.config.host,
                "port": self.config.port,
                "username": self.config.username,
                "timeout": 10,
                "allow_agent": False,
                "look_for_keys": False,
            }

            # Check if SSH Private Key authentication is configured
            key_data = self.config.ssh_key_data or (self._secret if (self._secret and "PRIVATE KEY" in self._secret) else None)
            if key_data:
                # Load private key from string or path
                pkey = None
                key_io = io.StringIO(key_data.strip())
                for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                    try:
                        key_io.seek(0)
                        pkey = key_cls.from_private_key(key_io)
                        break
                    except Exception:
                        continue
                if pkey is None:
                    # Try reading as file path if file exists
                    if os.path.exists(key_data.strip()):
                        for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                            try:
                                pkey = key_cls.from_private_key_file(key_data.strip())
                                break
                            except Exception:
                                continue
                if pkey is not None:
                    kwargs["pkey"] = pkey
                else:
                    raise ValueError("Failed to parse provided SSH private key data.")
            elif self._secret:
                kwargs["password"] = self._secret

            self._ssh_client.connect(**kwargs)

            # If host key fingerprint was pinned on first use, store it in config
            if policy.recorded_fingerprint and not self.config.ssh_host_key_fingerprint:
                self.config.ssh_host_key_fingerprint = policy.recorded_fingerprint

            self._initialize_nftables_table()
            self._initialize_tc_qdiscs()
            return True
        except Exception as ex:
            self.config.last_error = f"SSH connection failed: {ex}"
            return False

    def disconnect(self) -> None:
        if self._ssh_client:
            try:
                self._ssh_client.close()
            except Exception:
                pass
            self._ssh_client = None

    def _exec_command(self, cmd: str) -> Tuple[int, str, str]:
        if not self.is_connected():
            raise ConnectionError("Gateway SSH is not connected")
        stdin, stdout, stderr = self._ssh_client.exec_command(cmd, timeout=15)
        exit_code = stdout.channel.recv_exit_status()
        out_str = stdout.read().decode("utf-8", errors="replace")
        err_str = stderr.read().decode("utf-8", errors="replace")
        return exit_code, out_str, err_str

    def _validate_mac(self, mac: str) -> str:
        norm = normalize_mac(mac)
        if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", norm):
            raise ValueError(f"Invalid MAC format: {mac}")
        return norm

    def _validate_ip(self, ip_str: str) -> str:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return str(ip_obj)

    def _validate_iface(self, iface: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", iface):
            raise ValueError(f"Invalid interface name: {iface}")
        return iface

    def _get_class_id(self, mac: str) -> int:
        """
        Derives a deterministic, persistent class ID in the 16-bit range [10, 64000].
        Ensures class IDs survive controller restarts and reconcile cleanly.
        """
        norm_mac = self._validate_mac(mac)
        if norm_mac in self._mac_class_map:
            return self._mac_class_map[norm_mac]
        h = int(hashlib.sha256(norm_mac.encode("utf-8")).hexdigest()[:4], 16)
        cid = 10 + (h % 64000)
        self._mac_class_map[norm_mac] = cid
        return cid

    def _initialize_nftables_table(self) -> None:
        """
        Create netcutter table with forward hook at priority -10 and
        prerouting mangle hook at priority -150 for fw mark tagging.
        """
        init_script = """
nft list table inet netcutter >/dev/null 2>&1 || nft -f - << 'EOF'
table inet netcutter {
    set blocked_macs {
        type ether_addr
        flags interval
    }
    set blocked_ipv4 {
        type ipv4_addr
        flags interval
    }
    set blocked_ipv6 {
        type ipv6_addr
        flags interval
    }
    map mac_to_mark {
        type ether_addr : mark
    }
    map ip_to_mark {
        type ipv4_addr : mark
    }
    map ip6_to_mark {
        type ipv6_addr : mark
    }
    chain forward {
        type filter hook forward priority -10; policy accept;
        ether saddr @blocked_macs counter drop comment "netcutter: blocked mac src"
        ether daddr @blocked_macs counter drop comment "netcutter: blocked mac dst"
        ip saddr @blocked_ipv4 counter drop comment "netcutter: blocked ipv4 src"
        ip daddr @blocked_ipv4 counter drop comment "netcutter: blocked ipv4 dst"
        ip6 saddr @blocked_ipv6 counter drop comment "netcutter: blocked ipv6 src"
        ip6 daddr @blocked_ipv6 counter drop comment "netcutter: blocked ipv6 dst"
    }
    chain preroute_qos {
        type filter hook prerouting priority -150; policy accept;
        meta mark set ether saddr map @mac_to_mark
        meta mark set ip saddr map @ip_to_mark
        meta mark set ip6 saddr map @ip6_to_mark
    }
}
EOF
"""
        self._exec_command(init_script)

    def _initialize_tc_qdiscs(self) -> None:
        """Initialize HTB root qdiscs on WAN and LAN interfaces if supported."""
        wan = self._validate_iface(self.config.wan_interface)
        lan = self._validate_iface(self.config.lan_interface)
        self._exec_command(f"tc qdisc add dev {wan} root handle 1: htb default 1 >/dev/null 2>&1 || true")
        self._exec_command(f"tc class add dev {wan} parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit >/dev/null 2>&1 || true")
        self._exec_command(f"tc qdisc add dev {lan} root handle 1: htb default 1 >/dev/null 2>&1 || true")
        self._exec_command(f"tc class add dev {lan} parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit >/dev/null 2>&1 || true")


    def discover_devices(self) -> List[DiscoveredDeviceRaw]:
        devices: Dict[str, DiscoveredDeviceRaw] = {}
        
        # 1. Inspect ARP cache /proc/net/arp
        code, out, _ = self._exec_command("cat /proc/net/arp 2>/dev/null || ip neigh show")
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("IP address"):
                continue
            parts = line.split()
            # /proc/net/arp format: IP, HW_type, Flags, HW_address, Mask, Device
            if len(parts) >= 4 and ":" in parts[3] and parts[3] != "00:00:00:00:00:00":
                ip = parts[0]
                mac = parts[3].lower()
                if mac not in devices:
                    devices[mac] = DiscoveredDeviceRaw(mac=mac)
                if ip not in devices[mac].ipv4_addresses:
                    devices[mac].ipv4_addresses.append(ip)
            # ip neigh format: 192.168.1.50 dev br-lan lladdr 00:11:22:33:44:55 REACHABLE
            elif "lladdr" in parts:
                try:
                    ip = parts[0]
                    mac_idx = parts.index("lladdr") + 1
                    mac = parts[mac_idx].lower()
                    if mac not in devices:
                        devices[mac] = DiscoveredDeviceRaw(mac=mac)
                    if ":" in ip and ip not in devices[mac].ipv6_addresses:
                        devices[mac].ipv6_addresses.append(ip)
                    elif "." in ip and ip not in devices[mac].ipv4_addresses:
                        devices[mac].ipv4_addresses.append(ip)
                except Exception:
                    pass

        # 2. Inspect IPv6 neighbor table (ip -6 neigh show)
        code, out_v6, _ = self._exec_command("ip -6 neigh show 2>/dev/null")
        for line in out_v6.splitlines():
            parts = line.strip().split()
            if "lladdr" in parts:
                try:
                    ip = parts[0]
                    mac = parts[parts.index("lladdr") + 1].lower()
                    if mac not in devices:
                        devices[mac] = DiscoveredDeviceRaw(mac=mac)
                    if ip not in devices[mac].ipv6_addresses:
                        devices[mac].ipv6_addresses.append(ip)
                except Exception:
                    pass

        # 3. Inspect DHCP leases (dnsmasq / OpenWrt lease files)
        code, lease_out, _ = self._exec_command(
            "cat /tmp/dhcp.leases /var/lib/misc/dnsmasq.leases 2>/dev/null || true"
        )
        for line in lease_out.splitlines():
            # dnsmasq lease: timestamp mac ip hostname client_id
            parts = line.strip().split()
            if len(parts) >= 4 and ":" in parts[1]:
                mac = parts[1].lower()
                ip = parts[2]
                hostname = parts[3] if parts[3] != "*" else None
                client_id = parts[4] if len(parts) > 4 and parts[4] != "*" else None
                if mac not in devices:
                    devices[mac] = DiscoveredDeviceRaw(mac=mac)
                if hostname and not devices[mac].hostname:
                    devices[mac].hostname = hostname
                if client_id and not devices[mac].client_id:
                    devices[mac].client_id = client_id
                if ip and ip not in devices[mac].ipv4_addresses:
                    devices[mac].ipv4_addresses.append(ip)

        return list(devices.values())

    def block_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        try:
            norm_mac = self._validate_mac(mac)
            # 1. Add MAC to nftables set
            cmd = f"nft add element inet netcutter blocked_macs {{ {norm_mac} }}"
            code, out, err = self._exec_command(cmd)
            if code != 0:
                return PolicyExecutionResult(
                    success=False, operation="BLOCK", error=f"nftables error: {err}"
                )

            # 2. Add IPs to respective sets
            for ip in ips:
                try:
                    clean_ip = self._validate_ip(ip)
                    if ":" in clean_ip:
                        self._exec_command(f"nft add element inet netcutter blocked_ipv6 {{ {clean_ip} }} 2>/dev/null || true")
                    elif "." in clean_ip:
                        self._exec_command(f"nft add element inet netcutter blocked_ipv4 {{ {clean_ip} }} 2>/dev/null || true")
                except Exception:
                    pass

            # 3. Flush OpenWrt flowtable to evict offloaded hardware/software bypass flows
            self._exec_command("nft flush flowtable inet fw4 ft 2>/dev/null || true")

            # 4. Flush bidirectional conntrack entries (src and dst, v4 and v6) to terminate active streams
            for ip in ips:
                try:
                    clean_ip = self._validate_ip(ip)
                    if ":" in clean_ip:
                        self._exec_command(f"conntrack -D -f ipv6 -s {clean_ip} >/dev/null 2>&1 || true")
                        self._exec_command(f"conntrack -D -f ipv6 -d {clean_ip} >/dev/null 2>&1 || true")
                    else:
                        self._exec_command(f"conntrack -D -s {clean_ip} >/dev/null 2>&1 || true")
                        self._exec_command(f"conntrack -D -d {clean_ip} >/dev/null 2>&1 || true")
                except Exception:
                    pass

            # 5. State Verification: check if set contains the MAC
            observed = self.query_observed_state(norm_mac, ips)
            verified = observed.internet_access == InternetAccessState.BLOCKED
            return PolicyExecutionResult(
                success=True,
                operation="BLOCK",
                details=f"Device {norm_mac} added to @blocked_macs with conntrack + flowtable eviction",
                verification_verified=verified,
            )
        except Exception as ex:
            return PolicyExecutionResult(
                success=False, operation="BLOCK", error=str(ex)
            )

    def unblock_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        try:
            norm_mac = self._validate_mac(mac)
            cmd = f"nft delete element inet netcutter blocked_macs {{ {norm_mac} }} >/dev/null 2>&1 || true"
            self._exec_command(cmd)

            for ip in ips:
                try:
                    clean_ip = self._validate_ip(ip)
                    if ":" in clean_ip:
                        self._exec_command(f"nft delete element inet netcutter blocked_ipv6 {{ {clean_ip} }} 2>/dev/null || true")
                    elif "." in clean_ip:
                        self._exec_command(f"nft delete element inet netcutter blocked_ipv4 {{ {clean_ip} }} 2>/dev/null || true")
                except Exception:
                    pass

            # State Verification
            observed = self.query_observed_state(norm_mac, ips)
            verified = observed.internet_access == InternetAccessState.ALLOWED
            return PolicyExecutionResult(
                success=True,
                operation="UNBLOCK",
                details=f"Device {norm_mac} removed from @blocked_macs",
                verification_verified=verified,
            )
        except Exception as ex:
            return PolicyExecutionResult(
                success=False, operation="UNBLOCK", error=str(ex)
            )

    def set_bandwidth_limit(
        self, mac: str, ips: List[str], dl_kbps: int, ul_kbps: int
    ) -> PolicyExecutionResult:
        try:
            norm_mac = self._validate_mac(mac)
            wan = self._validate_iface(self.config.wan_interface)
            lan = self._validate_iface(self.config.lan_interface)
            class_id = self._get_class_id(norm_mac)

            # 1. Upload Limit on WAN egress (NAT-safe via nftables prerouting fw mark)
            if ul_kbps > 0:
                rate_str = f"{ul_kbps}kbit"
                self._exec_command(f"tc class replace dev {wan} parent 1: classid 1:{class_id} htb rate {rate_str} ceil {rate_str}")
                # tc filter matches fw mark handle across both IPv4 and IPv6 post-SNAT
                self._exec_command(f"tc filter replace dev {wan} protocol all parent 1: prio 1 handle {class_id} fw flowid 1:{class_id}")
                # Tag packet in nftables prerouting before SNAT masquerade
                self._exec_command(f"nft add element inet netcutter mac_to_mark {{ {norm_mac} : {class_id} }} 2>/dev/null || true")
                for ip in ips:
                    try:
                        clean_ip = self._validate_ip(ip)
                        if ":" in clean_ip:
                            self._exec_command(f"nft add element inet netcutter ip6_to_mark {{ {clean_ip} : {class_id} }} 2>/dev/null || true")
                        else:
                            self._exec_command(f"nft add element inet netcutter ip_to_mark {{ {clean_ip} : {class_id} }} 2>/dev/null || true")
                    except Exception:
                        pass
            else:
                self._exec_command(f"tc class del dev {wan} classid 1:{class_id} >/dev/null 2>&1 || true")
                self._exec_command(f"nft delete element inet netcutter mac_to_mark {{ {norm_mac} }} 2>/dev/null || true")
                for ip in ips:
                    try:
                        clean_ip = self._validate_ip(ip)
                        if ":" in clean_ip:
                            self._exec_command(f"nft delete element inet netcutter ip6_to_mark {{ {clean_ip} }} 2>/dev/null || true")
                        else:
                            self._exec_command(f"nft delete element inet netcutter ip_to_mark {{ {clean_ip} }} 2>/dev/null || true")
                    except Exception:
                        pass

            # 2. Download Limit on LAN egress (Dual-stack IPv4 + IPv6 + flower MAC)
            if dl_kbps > 0:
                rate_str = f"{dl_kbps}kbit"
                self._exec_command(f"tc class replace dev {lan} parent 1: classid 1:{class_id} htb rate {rate_str} ceil {rate_str}")
                for ip in ips:
                    try:
                        clean_ip = self._validate_ip(ip)
                        if ":" in clean_ip:
                            self._exec_command(f"tc filter replace dev {lan} protocol ipv6 parent 1: prio 2 u32 match ip6 dst {clean_ip} flowid 1:{class_id}")
                        else:
                            self._exec_command(f"tc filter replace dev {lan} protocol ip parent 1: prio 1 u32 match ip dst {clean_ip} flowid 1:{class_id}")
                    except Exception:
                        pass
                # Optional flower match on destination MAC on bridge LAN
                self._exec_command(f"tc filter replace dev {lan} protocol all parent 1: prio 3 flower dst_mac {norm_mac} flowid 1:{class_id} 2>/dev/null || true")
            else:
                self._exec_command(f"tc class del dev {lan} classid 1:{class_id} >/dev/null 2>&1 || true")

            # 3. Verify
            observed = self.query_observed_state(norm_mac, ips)
            verified = (
                (dl_kbps == 0 or observed.download_limit_kbps == dl_kbps)
                and (ul_kbps == 0 or observed.upload_limit_kbps == ul_kbps)
            )
            return PolicyExecutionResult(
                success=True,
                operation="SET_BANDWIDTH",
                details=f"Configured DL={dl_kbps}kbit UL={ul_kbps}kbit on class 1:{class_id}",
                verification_verified=verified,
            )
        except Exception as ex:
            return PolicyExecutionResult(
                success=False, operation="SET_BANDWIDTH", error=str(ex)
            )

    def remove_bandwidth_limit(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        try:
            norm_mac = self._validate_mac(mac)
            wan = self._validate_iface(self.config.wan_interface)
            lan = self._validate_iface(self.config.lan_interface)
            class_id = self._get_class_id(norm_mac)

            self._exec_command(f"tc class del dev {wan} classid 1:{class_id} >/dev/null 2>&1 || true")
            self._exec_command(f"tc class del dev {lan} classid 1:{class_id} >/dev/null 2>&1 || true")
            self._exec_command(f"nft delete element inet netcutter mac_to_mark {{ {norm_mac} }} 2>/dev/null || true")
            for ip in ips:
                try:
                    clean_ip = self._validate_ip(ip)
                    if ":" in clean_ip:
                        self._exec_command(f"nft delete element inet netcutter ip6_to_mark {{ {clean_ip} }} 2>/dev/null || true")
                    else:
                        self._exec_command(f"nft delete element inet netcutter ip_to_mark {{ {clean_ip} }} 2>/dev/null || true")
                except Exception:
                    pass

            observed = self.query_observed_state(norm_mac, ips)
            verified = observed.download_limit_kbps == 0 and observed.upload_limit_kbps == 0
            return PolicyExecutionResult(
                success=True,
                operation="REMOVE_BANDWIDTH",
                details=f"Removed tc classes and nft marks for {norm_mac} (class 1:{class_id})",
                verification_verified=verified,
            )
        except Exception as ex:
            return PolicyExecutionResult(
                success=False, operation="REMOVE_BANDWIDTH", error=str(ex)
            )

    def query_observed_state(self, mac: str, ips: List[str]) -> ObservedPolicy:
        norm_mac = self._validate_mac(mac)
        internet_access = InternetAccessState.ALLOWED
        packet_drops = 0
        byte_drops = 0

        # 1. Query nftables set
        code, out, _ = self._exec_command("nft list set inet netcutter blocked_macs 2>/dev/null")
        if norm_mac in out.lower():
            internet_access = InternetAccessState.BLOCKED
            # Get packet counter from drop rule
            _, rule_out, _ = self._exec_command("nft list chain inet netcutter forward 2>/dev/null")
            match = re.search(r"counter packets (\d+) bytes (\d+)", rule_out)
            if match:
                packet_drops = int(match.group(1))
                byte_drops = int(match.group(2))

        # 2. Query tc classes for bandwidth limits
        dl_limit = 0
        ul_limit = 0
        lan = self._validate_iface(self.config.lan_interface)
        wan = self._validate_iface(self.config.wan_interface)
        class_id = self._get_class_id(norm_mac)
        if class_id:
            # Check DL on LAN
            _, lan_out, _ = self._exec_command(f"tc class show dev {lan} classid 1:{class_id} 2>/dev/null")
            rate_match = re.search(r"rate (\d+)([kMGT]bit)", lan_out)
            if rate_match:
                val = int(rate_match.group(1))
                unit = rate_match.group(2)
                dl_limit = val * 1000 if unit == "Mbit" else val

            # Check UL on WAN
            _, wan_out, _ = self._exec_command(f"tc class show dev {wan} classid 1:{class_id} 2>/dev/null")
            rate_match = re.search(r"rate (\d+)([kMGT]bit)", wan_out)
            if rate_match:
                val = int(rate_match.group(1))
                unit = rate_match.group(2)
                ul_limit = val * 1000 if unit == "Mbit" else val

        return ObservedPolicy(
            internet_access=internet_access,
            download_limit_kbps=dl_limit,
            upload_limit_kbps=ul_limit,
            packet_drop_count=packet_drops,
            byte_drop_count=byte_drops,
            is_verified=True,
        )

    def health_check(self) -> Tuple[bool, str]:
        if not self.is_connected():
            return False, "Gateway SSH connection is down"
        try:
            code, out, err = self._exec_command("uptime && nft -v")
            if code == 0:
                return True, f"Gateway healthy. Kernel response: {out.strip().splitlines()[0]}"
            return False, f"Gateway command failed: {err}"
        except Exception as ex:
            return False, f"Health check failed: {ex}"

    def apply_domain_rule(self, rule: DomainBlockingRule) -> PolicyExecutionResult:
        """
        Enforces router-wide domain sinkhole via dnsmasq address configuration.
        Writes managed rule to /tmp/dnsmasq.d/ or /etc/dnsmasq.d/ and reloads dnsmasq.
        """
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False,
                operation="APPLY_DOMAIN_RULE",
                error="Linux/OpenWrt gateway is not connected via SSH",
            )

        clean_domain = re.sub(r"[^a-zA-Z0-9.-]", "", rule.domain).lower()
        conf_path = f"/tmp/dnsmasq.d/netcutter_{rule.rule_id[:8]}.conf"
        cmd = f"mkdir -p /tmp/dnsmasq.d && echo 'address=/{clean_domain}/0.0.0.0' > {conf_path} && (killall -HUP dnsmasq || /etc/init.d/dnsmasq reload || true)"

        try:
            code, out, err = self._exec_command(cmd)
            if code == 0:
                return PolicyExecutionResult(
                    success=True,
                    operation="APPLY_DOMAIN_RULE",
                    details=f"dnsmasq sinkhole active for '{clean_domain}' -> 0.0.0.0",
                    verification_verified=True,
                )
            return PolicyExecutionResult(
                success=False,
                operation="APPLY_DOMAIN_RULE",
                error=f"Failed to apply dnsmasq rule: {err or out}",
            )
        except Exception as ex:
            return PolicyExecutionResult(
                success=False,
                operation="APPLY_DOMAIN_RULE",
                error=f"SSH execution error: {ex}",
            )

    def remove_domain_rule(self, rule: DomainBlockingRule) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False,
                operation="REMOVE_DOMAIN_RULE",
                error="Linux/OpenWrt gateway is not connected via SSH",
            )

        conf_path = f"/tmp/dnsmasq.d/netcutter_{rule.rule_id[:8]}.conf"
        cmd = f"rm -f {conf_path} && (killall -HUP dnsmasq || /etc/init.d/dnsmasq reload || true)"

        try:
            code, out, err = self._exec_command(cmd)
            return PolicyExecutionResult(
                success=True,
                operation="REMOVE_DOMAIN_RULE",
                details=f"Removed dnsmasq sinkhole for '{rule.domain}'",
                verification_verified=True,
            )
        except Exception as ex:
            return PolicyExecutionResult(
                success=False,
                operation="REMOVE_DOMAIN_RULE",
                error=f"SSH execution error removing rule: {ex}",
            )

    def verify_domain_rule(self, rule: DomainBlockingRule) -> Tuple[bool, str]:
        if not self.is_connected():
            return False, "SSH disconnected"
        conf_path = f"/tmp/dnsmasq.d/netcutter_{rule.rule_id[:8]}.conf"
        code, out, _ = self._exec_command(f"[ -f {conf_path} ] && cat {conf_path}")
        if code == 0 and "address=" in out:
            return True, f"Verified dnsmasq configuration active: {out.strip()}"
        return False, "dnsmasq rule file not present on gateway"

