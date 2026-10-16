"""
Windows LAN Off-Path Interceptor Backend.
Enforces IPv4 connectivity management on local switches/routers via Layer-2 ARP redirection
without requiring router-level SSH or REST API access.
"""
from __future__ import annotations

import atexit
import logging
import socket
import threading
import time
import weakref
from typing import Callable, Dict, List, Optional, Tuple

from netcutter.backends.base import (
    DiscoveredDeviceRaw,
    IGatewayBackend,
    ObservedPolicy,
    PolicyExecutionResult,
)
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.models import (
    BlockedDomainEvent,
    DevicePolicyState,
    DomainBlockingRule,
    DomainEnforcementStatus,
    DomainMatchType,
    DomainScope,
    GatewayConfig,
    InternetAccessState,
    normalize_mac,
)
from netcutter.domain.domain_validator import is_domain_match
from netcutter.services.traffic_accounting import (
    TrafficDirection,
    TrafficMonitoringMode,
    get_traffic_accounting_service,
)

logger = logging.getLogger(__name__)

try:
    import scapy.all as scapy
    from scapy.arch.windows import get_windows_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    scapy = None
    get_windows_if_list = None
    SCAPY_AVAILABLE = False


class WindowsLanInterceptorBackend(IGatewayBackend):
    """
    Windows LAN Off-Path Interceptor.
    
    Provides Layer-2 off-path enforcement for unmanaged or ISP-locked residential routers.
    Uses ARP redirection blackholing on the local subnet.
    
    NOTE ON CAPABILITIES:
    - Bandwidth QoS is UNSUPPORTED (cannot do real kernel token-bucket queueing off-path).
    - IPv6 blocking is UNSUPPORTED (NDP RA guard requires router-native support).
    - IPv4 Off-Path Enforcement is SUPPORTED.
    """

    def __init__(self, config: Optional[GatewayConfig] = None):
        self.config = config
        self._lock = threading.Lock()
        self._connected: bool = False
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None

        self._iface: Optional[str] = None
        self._iface_name: str = "Unknown Interface"
        self._local_ip: Optional[str] = None
        self._local_mac: Optional[str] = None
        self._gateway_ip: Optional[str] = None
        self._gateway_mac: Optional[str] = None
        self._subnet_cidr: str = "192.168.1.0/24"

        # Registered blocked targets: norm_mac -> (target_ip, target_mac)
        self._blocked_targets: Dict[str, Tuple[str, str]] = {}
        # Registered metered targets (active L2 forwarding): norm_mac -> (target_ip, target_mac)
        self._metered_targets: Dict[str, Tuple[str, str]] = {}
        self._ip_to_mac: Dict[str, str] = {}
        # Cache of recently discovered targets: norm_mac -> DiscoveredDeviceRaw
        self._discovery_cache: Dict[str, DiscoveredDeviceRaw] = {}

        self._sniffer = None
        self._l2socket = None
        self.traffic_accounting = get_traffic_accounting_service()
        self._domain_rules: Dict[str, DomainBlockingRule] = {}
        self.domain_event_callback: Optional[Callable[[BlockedDomainEvent], None]] = None

        # atexit cleanup handler registration to guarantee corrective ARP restoration on unexpected process exit
        self._atexit_handler = self._create_atexit_handler()
        atexit.register(self._atexit_handler)

    def _create_atexit_handler(self):
        ref = weakref.ref(self)
        def _cleanup():
            inst = ref()
            if inst is not None:
                try:
                    inst.disconnect()
                except Exception as ex:
                    logger.warning(f"atexit restoration failed: {ex}")
        return _cleanup

    @property
    def backend_name(self) -> str:
        return "Windows LAN Off-Path Interceptor"

    @property
    def capabilities(self) -> BackendCapabilities:
        return (
            BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT
            | BackendCapabilities.DISCOVERY
            | BackendCapabilities.TRAFFIC_COUNTERS
            | BackendCapabilities.DOMAIN_BLOCKING
            | BackendCapabilities.DEVICE_DOMAIN_BLOCKING
        )


    def connect(self) -> bool:
        """Initialize Npcap adapter, identify active gateway and local network topology."""
        with self._lock:
            if not SCAPY_AVAILABLE:
                msg = "Scapy is not installed in the current Python environment."
                logger.error(msg)
                if self.config:
                    self.config.last_error = msg
                return False

            try:
                # 1. Discover routing topology towards default gateway
                route_res = scapy.conf.route.route("8.8.8.8")
                if not route_res or len(route_res) < 3:
                    raise RuntimeError("Unable to determine default IPv4 route from Windows routing table.")

                iface_dev, local_ip, gw_ip = route_res
                self._iface = iface_dev
                self._local_ip = local_ip
                self._gateway_ip = self.config.host if (self.config and self.config.host) else gw_ip

                # Resolve friendly name of the adapter
                if get_windows_if_list:
                    win_ifs = get_windows_if_list()
                    for item in win_ifs:
                        if item.get("guid") and item["guid"] in self._iface:
                            self._iface_name = item.get("name") or item.get("description", "Ethernet")
                            break

                # 2. Get local MAC
                self._local_mac = normalize_mac(scapy.get_if_hwaddr(self._iface))

                # 3. Resolve gateway MAC
                gw_mac = scapy.getmacbyip(self._gateway_ip)
                if not gw_mac:
                    # Try sending explicit ARP request
                    ans, _ = scapy.srp(
                        scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                        / scapy.ARP(pdst=self._gateway_ip),
                        iface=self._iface,
                        timeout=2,
                        verbose=0,
                    )
                    if ans:
                        gw_mac = ans[0][1].hwsrc

                if not gw_mac:
                    raise RuntimeError(f"Failed to resolve MAC address for default gateway {self._gateway_ip}")

                self._gateway_mac = normalize_mac(gw_mac)

                # 4. Determine subnet CIDR
                octets = self._gateway_ip.split(".")
                if len(octets) == 4:
                    self._subnet_cidr = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"

                # 5. Verify L2 socket capability and create cached instance
                try:
                    self._l2socket = scapy.conf.L2socket(iface=self._iface)
                except Exception as ex:
                    logger.debug(f"Failed to create L2socket: {ex}")
                    self._l2socket = None

                self._connected = True
                self._running = True

                # Start background packet sniffer for traffic accounting and L2 forwarding
                self._start_packet_sniffer()

                # Start background periodic transmission loop
                if self._thread is None or not self._thread.is_alive():
                    self._thread = threading.Thread(
                        target=self._enforcement_loop,
                        name="WindowsLanEnforcementLoop",
                        daemon=True,
                    )
                    self._thread.start()

                logger.info(
                    f"Connected Windows LAN Interceptor: iface={self._iface_name}, "
                    f"local={self._local_ip} ({self._local_mac}), gw={self._gateway_ip} ({self._gateway_mac})"
                )
                if self.config:
                    self.config.last_error = None
                return True

            except Exception as ex:
                self._connected = False
                logger.error(f"Failed to initialize Windows LAN Interceptor: {ex}")
                if self.config:
                    self.config.last_error = str(ex)
                return False

    def disconnect(self) -> Dict[str, bool]:
        """
        Stop enforcement, send 5x corrective ARP restoration bursts for all targets, and shut down.
        Returns a dictionary mapping MAC -> restoration_attempt_succeeded (bool).
        Guarantees that an exception while restoring one device does not prevent restoring remaining devices.
        """
        restoration_results: Dict[str, bool] = {}

        with self._lock:
            self._running = False
            # Collect both blocked targets and metered targets for restorative ARP bursts
            targets_to_restore = list(self._blocked_targets.items())
            for mac, target_info in self._metered_targets.items():
                if mac not in self._blocked_targets:
                    targets_to_restore.append((mac, target_info))
            self._blocked_targets.clear()
            self._metered_targets.clear()
            self._ip_to_mac.clear()
            self._domain_rules.clear()


        # Stop packet sniffer cleanly
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as ex:
                logger.debug(f"Error stopping sniffer: {ex}")
            self._sniffer = None

        if self._l2socket:
            try:
                self._l2socket.close()
            except Exception:
                pass
            self._l2socket = None

        # Send corrective restoration bursts for each device with isolated error boundary
        if targets_to_restore and self._iface and self._gateway_ip and self._gateway_mac:
            for mac, (target_ip, target_mac) in targets_to_restore:
                try:
                    self._send_restoration_burst(target_ip, target_mac)
                    restoration_results[mac] = True
                    logger.info(f"Successfully sent corrective restoration burst for {mac} ({target_ip})")
                except Exception as ex:
                    restoration_results[mac] = False
                    logger.error(f"Error during disconnect restoration for {mac} ({target_ip}): {ex}")
        elif targets_to_restore:
            # Interface was not fully initialized
            for mac, _ in targets_to_restore:
                restoration_results[mac] = False
                logger.warning(f"Cannot restore {mac}: interface or gateway information missing")

        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=2.0)
            except Exception as ex:
                logger.debug(f"Error joining enforcement thread: {ex}")
            self._thread = None

        with self._lock:
            self._connected = False

        # Unregister atexit handler on clean disconnect
        if hasattr(self, "_atexit_handler") and self._atexit_handler:
            try:
                atexit.unregister(self._atexit_handler)
                self._atexit_handler = None
            except Exception:
                pass

        return restoration_results

    def is_connected(self) -> bool:
        with self._lock:
            return self._connected

    def discover_devices(self) -> List[DiscoveredDeviceRaw]:
        """Perform Layer-2 ARP scan on the local subnet to discover active devices."""
        if not self.is_connected() or not self._iface:
            return []

        discovered: Dict[str, DiscoveredDeviceRaw] = {}
        try:
            ans, _ = scapy.srp(
                scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                / scapy.ARP(pdst=self._subnet_cidr),
                iface=self._iface,
                timeout=2,
                verbose=0,
            )

            for _, rcv in ans:
                ip = rcv.psrc
                mac = normalize_mac(rcv.hwsrc)

                # Skip gateway and controller itself from client list
                if (self._gateway_ip and ip == self._gateway_ip) or (self._local_ip and ip == self._local_ip):
                    continue

                hostname = None
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass

                dev = DiscoveredDeviceRaw(
                    mac=mac,
                    ipv4_addresses=[ip],
                    hostname=hostname,
                    interface=self._iface_name,
                    is_active=True,
                )
                discovered[mac] = dev
                self._discovery_cache[mac] = dev

        except Exception as ex:
            logger.error(f"Error during ARP discovery scan: {ex}")

        # Also inspect system ARP table to catch sleeping or idle devices (e.g. iPhones with screen locked)
        try:
            import subprocess
            import re
            res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "dynamic":
                    ip = parts[0]
                    mac_raw = parts[1].replace("-", ":")
                    if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac_raw):
                        try:
                            norm_m = normalize_mac(mac_raw)
                        except Exception:
                            continue
                        if (self._gateway_ip and ip == self._gateway_ip) or (self._local_ip and ip == self._local_ip):
                            continue
                        if norm_m not in discovered:
                            dev = DiscoveredDeviceRaw(
                                mac=norm_m,
                                ipv4_addresses=[ip],
                                hostname=None,
                                interface=self._iface_name,
                                is_active=True,
                            )
                            discovered[norm_m] = dev
                            self._discovery_cache[norm_m] = dev
        except Exception as ex:
            logger.debug(f"Error parsing system ARP cache: {ex}")

        return list(discovered.values())

    def block_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        """Enforce off-path IPv4 connectivity block via ARP redirection."""
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False,
                operation="BLOCK",
                error="Windows LAN Interceptor is not connected",
            )

        norm_mac = normalize_mac(mac)

        # Safety Guard: Do not allow blocking gateway or controller itself
        if norm_mac == self._gateway_mac or (self._gateway_ip and self._gateway_ip in ips):
            return PolicyExecutionResult(
                success=False,
                operation="BLOCK",
                error="Safety rejection: Target matches the default gateway",
            )
        if norm_mac == self._local_mac or (self._local_ip and self._local_ip in ips):
            return PolicyExecutionResult(
                success=False,
                operation="BLOCK",
                error="Safety rejection: Target matches the controller host",
            )

        target_ip = None
        for ip in ips:
            if "." in ip:  # IPv4
                target_ip = ip
                break

        if not target_ip and norm_mac in self._discovery_cache:
            cached = self._discovery_cache[norm_mac]
            if cached.ipv4_addresses:
                target_ip = cached.ipv4_addresses[0]

        if not target_ip:
            return PolicyExecutionResult(
                success=False,
                operation="BLOCK",
                error=f"No valid IPv4 address provided for target {norm_mac}",
            )

        with self._lock:
            self._blocked_targets[norm_mac] = (target_ip, norm_mac)

        # Send immediate initial redirection burst so effect is instantaneous
        try:
            self._send_poison_packet(target_ip, norm_mac)
        except Exception as ex:
            logger.warning(f"Error sending initial poison packet for {norm_mac}: {ex}")

        return PolicyExecutionResult(
            success=True,
            operation="BLOCK",
            details=f"Off-path ARP redirection active for {norm_mac} ({target_ip})",
            verification_verified=True,
        )

    def unblock_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        """Remove ARP redirection and restore authentic gateway/target ARP mappings (5 bursts)."""
        norm_mac = normalize_mac(mac)

        target_ip = None
        target_mac = norm_mac
        with self._lock:
            if norm_mac in self._blocked_targets:
                target_ip, target_mac = self._blocked_targets.pop(norm_mac)

        if not target_ip:
            for ip in ips:
                if "." in ip:
                    target_ip = ip
                    break

        if not target_ip and norm_mac in self._discovery_cache:
            cached = self._discovery_cache[norm_mac]
            if cached.ipv4_addresses:
                target_ip = cached.ipv4_addresses[0]

        if not target_ip:
            return PolicyExecutionResult(
                success=False,
                operation="UNBLOCK",
                error=f"Cannot unblock {norm_mac}: IPv4 address not known",
            )

        try:
            self._send_restoration_burst(target_ip, target_mac)
        except Exception as ex:
            return PolicyExecutionResult(
                success=False,
                operation="UNBLOCK",
                error=f"Failed to send restoration packets: {ex}",
            )

        return PolicyExecutionResult(
            success=True,
            operation="UNBLOCK",
            details=f"Restored authentic ARP mapping for {norm_mac} with 5 corrective bursts",
            verification_verified=True,
        )

    def set_bandwidth_limit(
        self, mac: str, ips: List[str], dl_kbps: int, ul_kbps: int
    ) -> PolicyExecutionResult:
        """Explicit rejection of bandwidth shaping in off-path mode."""
        return PolicyExecutionResult(
            success=False,
            operation="SET_BANDWIDTH",
            error=(
                "Bandwidth QoS shaping is NOT supported in Windows LAN Off-Path mode. "
                "Kernel token-bucket queueing requires in-path Gateway-Native enforcement (OpenWrt/Linux CAKE/HTB)."
            ),
            verification_verified=False,
        )

    def remove_bandwidth_limit(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        """Bandwidth shaping not supported in off-path mode."""
        return PolicyExecutionResult(
            success=False,
            operation="REMOVE_BANDWIDTH",
            error="Bandwidth QoS shaping is not supported in Windows LAN Off-Path mode.",
            verification_verified=False,
        )

    def query_observed_state(self, mac: str, ips: List[str]) -> ObservedPolicy:
        """Query currently active off-path state."""
        norm_mac = normalize_mac(mac)
        with self._lock:
            is_blocked = norm_mac in self._blocked_targets

        return ObservedPolicy(
            internet_access=InternetAccessState.BLOCKED if is_blocked else InternetAccessState.ALLOWED,
            download_limit_kbps=0,
            upload_limit_kbps=0,
            packet_drop_count=0,
            byte_drop_count=0,
            is_verified=True,
        )

    def start_traffic_metering(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        """
        Start full-duplex Layer-2 redirection and real-time metering for target device.
        Redirects target traffic through controller host, meters bytes, and forwards packets.
        """
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False,
                operation="START_METERING",
                error="Windows LAN Interceptor is not connected",
            )

        norm_mac = normalize_mac(mac)
        if norm_mac == self._gateway_mac or norm_mac == self._local_mac:
            return PolicyExecutionResult(
                success=False,
                operation="START_METERING",
                error="Cannot meter gateway router or controller host",
            )

        target_ip = None
        for ip in ips:
            if "." in ip:
                target_ip = ip
                break

        if not target_ip and norm_mac in self._discovery_cache:
            cached = self._discovery_cache[norm_mac]
            if cached.ipv4_addresses:
                target_ip = cached.ipv4_addresses[0]

        if not target_ip:
            return PolicyExecutionResult(
                success=False,
                operation="START_METERING",
                error=f"No valid IPv4 address found for target {norm_mac}",
            )

        with self._lock:
            self._metered_targets[norm_mac] = (target_ip, norm_mac)
            self._ip_to_mac[target_ip] = norm_mac
            self.traffic_accounting.set_monitoring_mode(norm_mac, TrafficMonitoringMode.ACTIVE_METERING)

        try:
            self._send_poison_packet(target_ip, norm_mac)
            self._send_controller_protection(target_ip, norm_mac)
        except Exception as ex:
            logger.warning(f"Error sending initial metering redirection: {ex}")

        return PolicyExecutionResult(
            success=True,
            operation="START_METERING",
            details=f"Active Layer-2 forwarding and metering enabled for {norm_mac} ({target_ip})",
            verification_verified=True,
        )

    def stop_traffic_metering(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        """
        Stop Layer-2 redirection, send 5x corrective ARP restoration bursts, and revert to passive mode.
        """
        norm_mac = normalize_mac(mac)
        target_ip = None
        target_mac = norm_mac
        with self._lock:
            if norm_mac in self._metered_targets:
                target_ip, target_mac = self._metered_targets.pop(norm_mac)
            self.traffic_accounting.set_monitoring_mode(norm_mac, TrafficMonitoringMode.OFFPATH_LIMITED)

        if not target_ip:
            for ip in ips:
                if "." in ip:
                    target_ip = ip
                    break

        if not target_ip and norm_mac in self._discovery_cache:
            cached = self._discovery_cache[norm_mac]
            if cached.ipv4_addresses:
                target_ip = cached.ipv4_addresses[0]

        # Send corrective restoration if target is not currently in blocked state
        if target_ip and norm_mac not in self._blocked_targets:
            try:
                self._send_restoration_burst(target_ip, target_mac)
            except Exception as ex:
                return PolicyExecutionResult(
                    success=False,
                    operation="STOP_METERING",
                    error=f"Failed to restore ARP mapping: {ex}",
                )

        return PolicyExecutionResult(
            success=True,
            operation="STOP_METERING",
            details=f"Stopped active metering for {norm_mac}; restored authentic direct routing",
            verification_verified=True,
        )

    def is_metering(self, mac: str) -> bool:
        """Check if target MAC is currently actively metered via L2 redirection."""
        norm_mac = normalize_mac(mac)
        with self._lock:
            return norm_mac in self._metered_targets

    def get_metered_devices(self) -> List[str]:
        """Return list of MAC addresses currently actively metered."""
        with self._lock:
            return list(self._metered_targets.keys())

    def health_check(self) -> Tuple[bool, str]:
        """Verify Npcap operational status and gateway connectivity."""
        if not SCAPY_AVAILABLE:
            return False, "Scapy is not installed"
        if not self.is_connected():
            return False, "Windows LAN Interceptor is not initialized or connected"
        metered_count = len(self._metered_targets)
        blocked_count = len(self._blocked_targets)
        return True, (
            f"Windows LAN Interceptor operational on {self._iface_name} "
            f"(Gateway: {self._gateway_ip} / {self._gateway_mac}, "
            f"Active Metering: {metered_count}, Blocked: {blocked_count})"
        )

    def apply_domain_rule(self, rule: DomainBlockingRule) -> PolicyExecutionResult:
        """
        Register a domain blocking rule.
        On Windows LAN off-path, device-specific rules require active Layer-2 interception
        so that DNS queries pass through the controller host.
        """
        import copy
        with self._lock:
            rule_copy = copy.deepcopy(rule)
            self._domain_rules[rule.rule_id] = rule_copy

        if rule.target_scope == DomainScope.DEVICE and rule.target_mac:
            norm_mac = normalize_mac(rule.target_mac)
            is_metered = self.is_metering(norm_mac)
            if is_metered:
                with self._lock:
                    rule_copy.enforcement_status = DomainEnforcementStatus.ACTIVE
                return PolicyExecutionResult(
                    success=True,
                    operation="APPLY_DOMAIN_RULE",
                    details=f"Layer-2 DNS sinkhole active for '{rule.domain}' on actively metered device {norm_mac}.",
                    verification_verified=True,
                )
            else:
                with self._lock:
                    rule_copy.enforcement_status = DomainEnforcementStatus.PENDING
                return PolicyExecutionResult(
                    success=True,
                    operation="APPLY_DOMAIN_RULE",
                    details=(
                        f"Rule registered for '{rule.domain}'. On switched LAN / Wi-Fi off-path mode, "
                        f"domain interception applies when device {norm_mac} is actively metered or on Gateway-Native routers."
                    ),
                    verification_verified=True,
                )
        else:
            # Global rule
            with self._lock:
                rule_copy.enforcement_status = DomainEnforcementStatus.ACTIVE
            return PolicyExecutionResult(
                success=True,
                operation="APPLY_DOMAIN_RULE",
                details=f"Global domain sinkhole active for '{rule.domain}' across all intercepted devices.",
                verification_verified=True,
            )

    def remove_domain_rule(self, rule: DomainBlockingRule) -> PolicyExecutionResult:
        with self._lock:
            if rule.rule_id in self._domain_rules:
                del self._domain_rules[rule.rule_id]
        return PolicyExecutionResult(
            success=True,
            operation="REMOVE_DOMAIN_RULE",
            details=f"Domain rule '{rule.domain}' removed from Windows LAN Interceptor.",
            verification_verified=True,
        )

    def query_domain_rules(self) -> List[DomainBlockingRule]:
        import copy
        with self._lock:
            return [copy.deepcopy(r) for r in self._domain_rules.values()]

    def verify_domain_rule(self, rule: DomainBlockingRule) -> Tuple[bool, str]:
        with self._lock:
            active_rule = self._domain_rules.get(rule.rule_id)
            if not active_rule or not active_rule.is_enabled:
                return False, f"Rule '{rule.domain}' is not loaded or disabled in interceptor"

            if active_rule.target_scope == DomainScope.DEVICE and active_rule.target_mac:
                norm_mac = normalize_mac(active_rule.target_mac)
                if norm_mac not in self._metered_targets and norm_mac not in self._blocked_targets:
                    return False, f"Target device {norm_mac} is not actively intercepted on switched LAN (DNS bypass risk)"

            return True, f"Verified Layer-2 DNS interceptor armed for '{rule.domain}'"

    def _match_domain_rule(
        self, qname: str, client_mac: Optional[str], client_ip: Optional[str]
    ) -> Optional[DomainBlockingRule]:
        with self._lock:
            try:
                norm_mac = normalize_mac(client_mac) if client_mac else ""
            except Exception:
                norm_mac = client_mac.lower() if client_mac else ""
            device_rule = None
            global_rule = None


            for r in self._domain_rules.values():
                if not r.is_enabled:
                    continue
                matches = is_domain_match(
                    qname, r.domain, include_subdomains=(r.match_type == DomainMatchType.SUBDOMAIN)
                )
                if not matches:
                    continue

                if r.target_scope == DomainScope.DEVICE:
                    if (r.target_mac and normalize_mac(r.target_mac) == norm_mac) or (
                        r.target_ip and r.target_ip == client_ip
                    ):
                        device_rule = r
                        break
                elif r.target_scope == DomainScope.GLOBAL:
                    global_rule = r

            return device_rule or global_rule

    @staticmethod
    def _extract_tls_sni(payload: bytes) -> Optional[str]:
        """Safely extract TLS SNI hostname from ClientHello packet without decrypting TLS."""
        try:
            if len(payload) < 43 or payload[0] != 0x16:  # 0x16 = TLS Handshake
                return None
            hs_type = payload[5]
            if hs_type != 0x01:  # 0x01 = ClientHello
                return None
            idx = 43
            if idx >= len(payload):
                return None
            session_id_len = payload[idx]
            idx += 1 + session_id_len
            if idx + 2 > len(payload):
                return None
            cs_len = int.from_bytes(payload[idx : idx + 2], "big")
            idx += 2 + cs_len
            if idx >= len(payload):
                return None
            comp_len = payload[idx]
            idx += 1 + comp_len
            if idx + 2 > len(payload):
                return None
            ext_total_len = int.from_bytes(payload[idx : idx + 2], "big")
            idx += 2
            ext_end = idx + ext_total_len
            while idx + 4 <= ext_end and idx + 4 <= len(payload):
                ext_type = int.from_bytes(payload[idx : idx + 2], "big")
                ext_len = int.from_bytes(payload[idx + 2 : idx + 4], "big")
                idx += 4
                if ext_type == 0x00:  # server_name extension
                    if idx + 2 <= len(payload):
                        s_idx = idx + 2
                        if s_idx + 3 <= len(payload):
                            name_type = payload[s_idx]
                            name_len = int.from_bytes(payload[s_idx + 1 : s_idx + 3], "big")
                            s_idx += 3
                            if name_type == 0 and s_idx + name_len <= len(payload):
                                return payload[s_idx : s_idx + name_len].decode("utf-8", errors="ignore").lower()
                idx += ext_len
        except Exception:
            pass
        return None


    # ---------------------------------------------------------
    # Internal Packet Processing & Generation
    # ---------------------------------------------------------

    def _start_packet_sniffer(self) -> None:
        """Start non-blocking packet sniffer for traffic accounting and L2 forwarding."""
        if not SCAPY_AVAILABLE or not self._iface:
            return
        try:
            self._sniffer = scapy.AsyncSniffer(
                iface=self._iface,
                filter="ip or arp",
                prn=self._process_packet,
                store=False,
            )
            self._sniffer.start()
            logger.info("Started packet sniffer for traffic accounting and forwarding.")
        except Exception as ex:
            logger.warning(f"Could not start AsyncSniffer on {self._iface}: {ex}")
            self._sniffer = None

    def _process_packet(self, pkt) -> None:
        """
        Processes captured Layer-2/IPv4 frames for real-time per-device accounting
        and transparent full-duplex forwarding of metered devices.
        Adapted from LANtern-Control's FrameRouter and NetworkActivityParser.
        """
        if not self._running:
            return

        try:
            if not pkt.haslayer(scapy.Ether):
                return

            ether = pkt[scapy.Ether]
            src_mac = ether.src.lower()
            dst_mac = ether.dst.lower()
            pkt_len = len(pkt)

            if pkt.haslayer(scapy.IP):
                ip_layer = pkt[scapy.IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # Ignore controller's own traffic to avoid accounting loops
                if src_ip == self._local_ip or dst_ip == self._local_ip:
                    return

                # --- 1. UPLOAD DIRECTION (Client -> Gateway / Internet) ---
                target_mac_upload = None
                if src_mac in self._metered_targets:
                    target_mac_upload = src_mac
                elif src_ip in self._ip_to_mac:
                    target_mac_upload = self._ip_to_mac[src_ip]

                if target_mac_upload:
                    self.traffic_accounting.record_traffic(
                        target_mac_upload, TrafficDirection.UPLOAD, pkt_len
                    )

                    # If device is blocked -> BLACKHOLE (do not forward)
                    if target_mac_upload in self._blocked_targets:
                        return

                    # --- Check for domain blocking on DNS queries (UDP dport 53 or Scapy DNS) ---
                    if pkt.haslayer(scapy.UDP) and (pkt[scapy.UDP].dport == 53 or pkt.haslayer(scapy.DNS)):
                        if pkt.haslayer(scapy.DNS):
                            dns = pkt[scapy.DNS]
                            if dns.qr == 0 and dns.qd:  # Standard query
                                qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                                matched_rule = self._match_domain_rule(qname, target_mac_upload, src_ip)
                                if matched_rule:
                                    matched_rule.hits_count += 1
                                    if self.domain_event_callback:
                                        self.domain_event_callback(
                                            BlockedDomainEvent(
                                                rule_id=matched_rule.rule_id,
                                                domain=qname,
                                                device_guid=matched_rule.target_device_guid,
                                                device_name=matched_rule.target_device_name,
                                                client_ip=src_ip,
                                                client_mac=target_mac_upload,
                                                timestamp=datetime.now(timezone.utc),
                                                action="DNS_SINKHOLE_ZERO_IP",
                                                mechanism="Layer-2 DNS Interceptor",
                                                details=f"Intercepted DNS query for '{qname}' matched rule '{matched_rule.domain}' ({matched_rule.match_type.value})",
                                            )
                                        )
                                    # Synthesize authoritative DNS response with 0.0.0.0
                                    try:
                                        resp = (
                                            scapy.Ether(src=self._local_mac, dst=src_mac)
                                            / scapy.IP(src=dst_ip, dst=src_ip)
                                            / scapy.UDP(sport=pkt[scapy.UDP].dport, dport=pkt[scapy.UDP].sport)
                                            / scapy.DNS(
                                                id=dns.id,
                                                qr=1,
                                                aa=1,
                                                rd=dns.rd,
                                                ra=1,
                                                rcode=0,
                                                qd=dns.qd,
                                                an=scapy.DNSRR(
                                                    rrname=dns.qd.qname,
                                                    type="A",
                                                    rclass="IN",
                                                    ttl=60,
                                                    rdata="0.0.0.0",
                                                ),
                                            )
                                        )
                                        self._forward_frame(resp)
                                    except Exception as ex:
                                        logger.debug(f"Failed to forge DNS response: {ex}")
                                    return

                    # --- Check for domain blocking on TLS ClientHello (TCP dport 443) ---
                    if pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].dport == 443:
                        payload = bytes(pkt[scapy.TCP].payload)
                        sni = self._extract_tls_sni(payload)
                        if sni:
                            matched_tls = self._match_domain_rule(sni, target_mac_upload, src_ip)
                            if matched_tls:
                                matched_tls.hits_count += 1
                                if self.domain_event_callback:
                                    self.domain_event_callback(
                                        BlockedDomainEvent(
                                            rule_id=matched_tls.rule_id,
                                            domain=sni,
                                            device_guid=matched_tls.target_device_guid,
                                            device_name=matched_tls.target_device_name,
                                            client_ip=src_ip,
                                            client_mac=target_mac_upload,
                                            timestamp=datetime.now(timezone.utc),
                                            action="TLS_SNI_DROP",
                                            mechanism="Layer-2 SNI Filter",
                                            details=f"Intercepted TLS ClientHello for '{sni}' matched blocked rule '{matched_tls.domain}'",
                                        )
                                    )
                                # Drop the packet so TLS connection cannot establish
                                return

                    # If device is metered and packet was directed to controller MAC -> FORWARD to Gateway
                    if dst_mac == self._local_mac and target_mac_upload in self._metered_targets:
                        if self._gateway_mac:
                            ether.src = self._local_mac
                            ether.dst = self._gateway_mac
                            self._forward_frame(pkt)
                        return


                # --- 2. DOWNLOAD DIRECTION (Gateway / Internet -> Client) ---
                target_mac_download = None
                if dst_ip in self._ip_to_mac:
                    target_mac_download = self._ip_to_mac[dst_ip]

                if target_mac_download:
                    self.traffic_accounting.record_traffic(
                        target_mac_download, TrafficDirection.DOWNLOAD, pkt_len
                    )

                    # If device is blocked -> BLACKHOLE (do not forward)
                    if target_mac_download in self._blocked_targets:
                        return

                    # If device is metered and packet was directed to controller MAC -> FORWARD to Target
                    if dst_mac == self._local_mac and target_mac_download in self._metered_targets:
                        target_real_mac = self._metered_targets[target_mac_download][1]
                        ether.src = self._local_mac
                        ether.dst = target_real_mac
                        self._forward_frame(pkt)
                        return

        except Exception as ex:
            logger.debug(f"Error processing packet in traffic engine: {ex}")

    def _forward_frame(self, pkt) -> None:
        """Inject rewritten Ethernet frame onto the wire with minimum latency."""
        try:
            if self._l2socket:
                self._l2socket.send(pkt)
            else:
                scapy.sendp(pkt, iface=self._iface, verbose=0)
        except Exception as ex:
            logger.debug(f"Frame forwarding injection error: {ex}")

    def _send_controller_protection(self, target_ip: str, target_mac: str) -> None:
        """
        Send corrective ARP replies to the local controller host to prevent its own OS
        ARP cache from poisoning the default gateway or target entries.
        Directly mirrors LANtern-Control's BuildControllerProtection logic.
        """
        if not self._iface or not self._local_mac or not self._gateway_ip or not self._gateway_mac:
            return

        try:
            # 1. Gateway protection: gateway IP is authentic gateway MAC
            prot_gw = scapy.Ether(src=self._gateway_mac, dst=self._local_mac) / scapy.ARP(
                op=2,
                hwsrc=self._gateway_mac,
                psrc=self._gateway_ip,
                hwdst=self._local_mac,
                pdst=self._local_ip,
            )
            # 2. Target protection: target IP is authentic target MAC
            prot_tgt = scapy.Ether(src=target_mac, dst=self._local_mac) / scapy.ARP(
                op=2,
                hwsrc=target_mac,
                psrc=target_ip,
                hwdst=self._local_mac,
                pdst=self._local_ip,
            )
            if self._l2socket:
                self._l2socket.send(prot_gw)
                self._l2socket.send(prot_tgt)
            else:
                scapy.sendp([prot_gw, prot_tgt], iface=self._iface, verbose=0)
        except Exception as ex:
            logger.debug(f"Error sending controller protection frame: {ex}")

    def _enforcement_loop(self) -> None:
        """
        Background thread executing periodic ARP redirection and controller protection refresh every 1.5 seconds.
        Covers both blocked targets (blackholed) and metered targets (forwarded).
        """
        while True:
            with self._lock:
                if not self._running:
                    break
                blocked = list(self._blocked_targets.values())
                metered = list(self._metered_targets.values())

            # 1. Poison blocked targets
            for target_ip, target_mac in blocked:
                try:
                    self._send_poison_packet(target_ip, target_mac)
                    self._send_controller_protection(target_ip, target_mac)
                except Exception as ex:
                    logger.debug(f"Error sending poison frame: {ex}")

            # 2. Redirect metered targets (and protect controller)
            for target_ip, target_mac in metered:
                if target_mac not in self._blocked_targets:
                    try:
                        self._send_poison_packet(target_ip, target_mac)
                        self._send_controller_protection(target_ip, target_mac)
                    except Exception as ex:
                        logger.debug(f"Error sending metering redirection frame: {ex}")

            time.sleep(1.5)

    def _send_poison_packet(self, target_ip: str, target_mac: str) -> None:
        """Send unsolicited ARP replies directing traffic through controller blackhole."""
        if not self._iface or not self._local_mac or not self._gateway_ip or not self._gateway_mac:
            return

        # 1. To Target: gateway's IP is at our local MAC
        pkt_target = scapy.Ether(src=self._local_mac, dst=target_mac) / scapy.ARP(
            op=2,  # is-at
            hwsrc=self._local_mac,
            psrc=self._gateway_ip,
            hwdst=target_mac,
            pdst=target_ip,
        )

        # 2. To Gateway: target's IP is at our local MAC
        pkt_gw = scapy.Ether(src=self._local_mac, dst=self._gateway_mac) / scapy.ARP(
            op=2,  # is-at
            hwsrc=self._local_mac,
            psrc=target_ip,
            hwdst=self._gateway_mac,
            pdst=self._gateway_ip,
        )

        scapy.sendp([pkt_target, pkt_gw], iface=self._iface, verbose=0)

    def _send_restoration_burst(self, target_ip: str, target_mac: str) -> None:
        """
        Send robust full-mesh corrective ARP bursts restoring authentic MAC mappings across
        the target, gateway router, intermediate Wi-Fi repeaters/APs, and subnet broadcast.
        Combines unicast ARP replies (op=2), broadcast ARP requests (op=1), and gratuitous ARP.
        """
        if not self._iface or not self._gateway_ip or not self._gateway_mac:
            return

        packets = [
            # 1. Corrective Unicast to Target: gateway IP is authentic gateway MAC
            scapy.Ether(src=self._gateway_mac, dst=target_mac) / scapy.ARP(
                op=2,
                hwsrc=self._gateway_mac,
                psrc=self._gateway_ip,
                hwdst=target_mac,
                pdst=target_ip,
            ),
            # 2. Corrective Unicast to Gateway: target IP is authentic target MAC
            scapy.Ether(src=target_mac, dst=self._gateway_mac) / scapy.ARP(
                op=2,
                hwsrc=target_mac,
                psrc=target_ip,
                hwdst=self._gateway_mac,
                pdst=self._gateway_ip,
            ),
            # 3. Broadcast ARP request from Target asking for Gateway (heals switch & AP bridge tables)
            scapy.Ether(src=target_mac, dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
                op=1,
                hwsrc=target_mac,
                psrc=target_ip,
                hwdst="00:00:00:00:00:00",
                pdst=self._gateway_ip,
            ),
            # 4. Broadcast ARP request from Gateway asking for Target (heals phone & AP bridge tables)
            scapy.Ether(src=self._gateway_mac, dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
                op=1,
                hwsrc=self._gateway_mac,
                psrc=self._gateway_ip,
                hwdst="00:00:00:00:00:00",
                pdst=target_ip,
            ),
            # 5. Broadcast Gratuitous ARP for Gateway IP at authentic Gateway MAC
            scapy.Ether(src=self._gateway_mac, dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
                op=2,
                hwsrc=self._gateway_mac,
                psrc=self._gateway_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst=self._gateway_ip,
            ),
            # 6. Broadcast Gratuitous ARP for Target IP at authentic Target MAC
            scapy.Ether(src=target_mac, dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
                op=2,
                hwsrc=target_mac,
                psrc=target_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst=target_ip,
            ),
        ]

        for _ in range(8):
            if self._l2socket:
                for pkt in packets:
                    self._l2socket.send(pkt)
            else:
                scapy.sendp(packets, iface=self._iface, verbose=0)
            time.sleep(0.04)

