"""
Mock Gateway Backend for Automated Testing and Deterministic Local Simulation.
Accurately models kernel nftables sets, tc classes, packet drop counters, and controlled fault injection.
"""
from __future__ import annotations

import copy
import random
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from netcutter.backends.base import (
    DiscoveredDeviceRaw,
    IGatewayBackend,
    ObservedPolicy,
    PolicyExecutionResult,
)
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.models import (
    BlockedDomainEvent,
    DomainBlockingRule,
    DomainEnforcementStatus,
    DomainMatchType,
    DomainScope,
    GatewayConfig,
    InternetAccessState,
    normalize_mac,
)
from netcutter.domain.domain_validator import is_domain_match


class MockGatewayBackend(IGatewayBackend):
    def __init__(self, config: Optional[GatewayConfig] = None):
        self.config = config or GatewayConfig(name="Mock Gateway Simulator", host="127.0.0.1")
        self._connected = True

        # Kernel simulated state
        self._blocked_mac_set: Set[str] = set()
        self._dl_limits: Dict[str, int] = {}
        self._ul_limits: Dict[str, int] = {}
        self._drop_counters: Dict[str, int] = {}
        self._domain_rules: Dict[str, DomainBlockingRule] = {}
        self._custom_capabilities: Optional[BackendCapabilities] = None

        # Fault Injection Flags & Schedules
        self._fault_timeout_ops: Set[str] = set()
        self._fault_disconnect_until: Optional[float] = None
        self._fault_auth_error: Optional[str] = None
        self._fault_partial_ops: Set[str] = set()
        self._fault_malformed_response: bool = False

        # Preset pool of simulated devices (strictly synthetic RFC 5737 documentation data)
        self._simulated_devices: List[DiscoveredDeviceRaw] = [
            DiscoveredDeviceRaw(
                mac="02:00:00:11:22:33",
                ipv4_addresses=["192.0.2.10"],
                ipv6_addresses=["2001:db8:1::10", "fe80::200:ff:fe11:2233"],
                hostname="Demo-Windows-PC",
                interface="lan",
            ),
            DiscoveredDeviceRaw(
                mac="02:00:00:44:55:66",  # Locally Administered Bit set (Randomized)
                ipv4_addresses=["192.0.2.20"],
                ipv6_addresses=["2001:db8:1::20", "fe80::200:ff:fe44:5566"],
                hostname="Demo-Smartphone",
                interface="wlan0",
                duid="00:04:7a:89:12:33:44:55",
            ),
            DiscoveredDeviceRaw(
                mac="02:00:00:77:88:99",
                ipv4_addresses=["192.0.2.30"],
                ipv6_addresses=["fe80::200:ff:fe77:8899"],
                hostname="Demo-Smart-TV",
                interface="wlan0",
            ),
            DiscoveredDeviceRaw(
                mac="02:00:00:aa:bb:cc",
                ipv4_addresses=["192.0.2.40"],
                hostname="Demo-Linux-Server",
                interface="lan",
            ),
            DiscoveredDeviceRaw(
                mac="02:00:00:dd:ee:ff",
                ipv4_addresses=["192.0.2.50"],
                hostname="Demo-IoT-Device",
                interface="wlan0",
            ),
        ]

    @property
    def backend_name(self) -> str:
        return f"Mock Gateway Simulator ({self.config.name})"

    @property
    def capabilities(self) -> BackendCapabilities:
        if self._custom_capabilities is not None:
            return self._custom_capabilities
        return BackendCapabilities.all_gateway_features()

    @capabilities.setter
    def capabilities(self, value: BackendCapabilities) -> None:
        self._custom_capabilities = value

    def is_connected(self) -> bool:
        if self._fault_disconnect_until and time.time() < self._fault_disconnect_until:
            return False
        return self._connected

    def connect(self) -> bool:
        if self._fault_auth_error:
            self._connected = False
            self.config.last_error = self._fault_auth_error
            return False
        self._connected = True
        return True

    def disconnect(self) -> None:
        self._connected = False

    def discover_devices(self) -> List[DiscoveredDeviceRaw]:
        if not self.is_connected():
            return []
        if self._fault_malformed_response:
            raise ValueError("Malformed ARP/NDP table response from router simulator")
        return [copy.deepcopy(d) for d in self._simulated_devices]

    def block_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False, operation="BLOCK", error="Gateway disconnected"
            )
        if "BLOCK" in self._fault_timeout_ops or "*" in self._fault_timeout_ops:
            return PolicyExecutionResult(
                success=False,
                operation="BLOCK",
                error="Operation timed out waiting for router confirmation",
            )
        if "BLOCK" in self._fault_partial_ops or "*" in self._fault_partial_ops:
            norm = normalize_mac(mac)
            self._blocked_mac_set.add(norm)
            return PolicyExecutionResult(
                success=False,
                operation="BLOCK",
                details="Mock: Rule added to nftables set but conntrack table flush failed",
                error="Partial failure: conntrack flush error",
                verification_verified=False,
            )

        norm = normalize_mac(mac)
        self._blocked_mac_set.add(norm)
        self._drop_counters[norm] = self._drop_counters.get(norm, 0) + 120
        return PolicyExecutionResult(
            success=True,
            operation="BLOCK",
            details=f"Mock: Added {norm} to simulated nftables set and cleared active conntrack flows",
            verification_verified=True,
        )

    def unblock_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False, operation="UNBLOCK", error="Gateway disconnected"
            )
        if "UNBLOCK" in self._fault_timeout_ops or "*" in self._fault_timeout_ops:
            return PolicyExecutionResult(
                success=False,
                operation="UNBLOCK",
                error="Operation timed out waiting for router response",
            )

        norm = normalize_mac(mac)
        self._blocked_mac_set.discard(norm)
        return PolicyExecutionResult(
            success=True,
            operation="UNBLOCK",
            details=f"Mock: Removed {norm} from simulated nftables set",
            verification_verified=True,
        )

    def set_bandwidth_limit(
        self, mac: str, ips: List[str], dl_kbps: int, ul_kbps: int
    ) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False, operation="SET_BANDWIDTH", error="Gateway disconnected"
            )
        if "SET_BANDWIDTH" in self._fault_timeout_ops or "*" in self._fault_timeout_ops:
            return PolicyExecutionResult(
                success=False,
                operation="SET_BANDWIDTH",
                error="Timeout configuring tc HTB classes on router",
            )

        norm = normalize_mac(mac)
        if dl_kbps > 0:
            self._dl_limits[norm] = dl_kbps
        else:
            self._dl_limits.pop(norm, None)
        if ul_kbps > 0:
            self._ul_limits[norm] = ul_kbps
        else:
            self._ul_limits.pop(norm, None)

        return PolicyExecutionResult(
            success=True,
            operation="SET_BANDWIDTH",
            details=f"Mock: Created HTB classes for {norm} (DL={dl_kbps}kbit UL={ul_kbps}kbit)",
            verification_verified=True,
        )

    def remove_bandwidth_limit(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False, operation="REMOVE_BANDWIDTH", error="Gateway disconnected"
            )
        if "REMOVE_BANDWIDTH" in self._fault_timeout_ops or "*" in self._fault_timeout_ops:
            return PolicyExecutionResult(
                success=False,
                operation="REMOVE_BANDWIDTH",
                error="Timeout deleting tc HTB classes on router",
            )

        norm = normalize_mac(mac)
        self._dl_limits.pop(norm, None)
        self._ul_limits.pop(norm, None)
        return PolicyExecutionResult(
            success=True,
            operation="REMOVE_BANDWIDTH",
            details=f"Mock: Removed HTB classes for {norm}",
            verification_verified=True,
        )

    def query_observed_state(self, mac: str, ips: List[str]) -> ObservedPolicy:
        if not self.is_connected():
            return ObservedPolicy(
                internet_access=InternetAccessState.ALLOWED,
                is_verified=False,
            )

        norm = normalize_mac(mac)
        is_blocked = norm in self._blocked_mac_set
        dl = self._dl_limits.get(norm, 0)
        ul = self._ul_limits.get(norm, 0)

        # Simulate incremental traffic counters
        current_drops = self._drop_counters.get(norm, 0)
        if is_blocked:
            current_drops += random.randint(5, 25)
            self._drop_counters[norm] = current_drops

        return ObservedPolicy(
            internet_access=InternetAccessState.BLOCKED if is_blocked else InternetAccessState.ALLOWED,
            download_limit_kbps=dl,
            upload_limit_kbps=ul,
            packet_drop_count=current_drops,
            byte_drop_count=current_drops * 1280,
            is_verified=True,
        )

    def health_check(self) -> Tuple[bool, str]:
        if not self.is_connected():
            return False, "Simulator connection down"
        return True, "Mock Kernel and nftables subsystem healthy (uptime 14d 2h)"

    def apply_domain_rule(self, rule: DomainBlockingRule) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False,
                operation="APPLY_DOMAIN_RULE",
                error="Simulator gateway is disconnected",
            )
        if "DOMAIN_BLOCK" in self._fault_timeout_ops or "*" in self._fault_timeout_ops:
            return PolicyExecutionResult(
                success=False,
                operation="APPLY_DOMAIN_RULE",
                error="Timed out communicating with DNS filter daemon",
            )
        
        # Save in simulator active rule set
        rule_copy = copy.deepcopy(rule)
        rule_copy.enforcement_status = DomainEnforcementStatus.ACTIVE
        self._domain_rules[rule.rule_id] = rule_copy

        return PolicyExecutionResult(
            success=True,
            operation="APPLY_DOMAIN_RULE",
            details=f"Mock: Domain filter active for '{rule.domain}' ({rule.match_type.value})",
            verification_verified=True,
        )

    def remove_domain_rule(self, rule: DomainBlockingRule) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False,
                operation="REMOVE_DOMAIN_RULE",
                error="Simulator gateway is disconnected",
            )
        if rule.rule_id in self._domain_rules:
            del self._domain_rules[rule.rule_id]
        return PolicyExecutionResult(
            success=True,
            operation="REMOVE_DOMAIN_RULE",
            details=f"Mock: Domain filter removed for '{rule.domain}'",
            verification_verified=True,
        )

    def query_domain_rules(self) -> List[DomainBlockingRule]:
        return [copy.deepcopy(r) for r in self._domain_rules.values()]

    def verify_domain_rule(self, rule: DomainBlockingRule) -> Tuple[bool, str]:
        if not self.is_connected():
            return False, "Simulator is offline"
        if rule.rule_id in self._domain_rules and self._domain_rules[rule.rule_id].is_enabled:
            return True, f"Verified DNS sinkhole active for '{rule.domain}' in simulator"
        return False, f"Rule '{rule.domain}' is not active in simulator"

    def simulate_dns_query(self, client_mac: str, domain: str) -> Tuple[bool, Optional[BlockedDomainEvent]]:
        """
        Simulate a DNS query from a client.
        Returns: (is_blocked: bool, event: Optional[BlockedDomainEvent])
        Precedence: Device-specific rule takes precedence over Global rule.
        """
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
                domain, r.domain, include_subdomains=(r.match_type == DomainMatchType.SUBDOMAIN)
            )
            if not matches:
                continue

            if r.target_scope == DomainScope.DEVICE and r.target_mac:
                if normalize_mac(r.target_mac) == norm_mac:
                    device_rule = r
                    break
            elif r.target_scope == DomainScope.GLOBAL:
                global_rule = r

        matched = device_rule or global_rule
        if matched:
            matched.hits_count += 1
            evt = BlockedDomainEvent(
                rule_id=matched.rule_id,
                domain=domain,
                device_guid=matched.target_device_guid,
                device_name=matched.target_device_name,
                client_mac=norm_mac,
                timestamp=datetime.now(timezone.utc),
                action="DNS_SINKHOLE_ZERO_IP",
                mechanism="Mock DNS Sinkhole",
                details=f"Simulated query for '{domain}' matched '{matched.domain}' ({matched.display_scope})",
            )
            return True, evt

        return False, None

    # Fault Injection and Drift Methods

    def inject_fault_disconnect(self, duration_seconds: Optional[float] = None) -> None:
        """Simulate an immediate gateway disconnection."""
        self._connected = False
        if duration_seconds:
            self._fault_disconnect_until = time.time() + duration_seconds

    def inject_fault_timeout(self, operation: str = "*") -> None:
        """Simulate a timeout error for a specific operation or all operations."""
        self._fault_timeout_ops.add(operation)

    def inject_fault_auth_error(self, message: str = "Invalid router credentials") -> None:
        """Simulate SSH or REST authentication failure."""
        self._fault_auth_error = message

    def inject_fault_partial_failure(self, operation: str = "*") -> None:
        """Simulate a partial operation completion (e.g. drop applied but conntrack flush failed)."""
        self._fault_partial_ops.add(operation)

    def inject_fault_malformed_response(self) -> None:
        """Simulate a garbled or corrupted router response."""
        self._fault_malformed_response = True

    def clear_faults(self) -> None:
        """Reset all injected faults to normal simulator operation."""
        self._connected = True
        self._fault_timeout_ops.clear()
        self._fault_disconnect_until = None
        self._fault_auth_error = None
        self._fault_partial_ops.clear()
        self._fault_malformed_response = False

    def inject_drift_external_block(self, mac: str) -> None:
        """Simulate an external administrator adding a block rule directly on the router."""
        norm = normalize_mac(mac)
        self._blocked_mac_set.add(norm)

    def inject_drift_remove_block(self, mac: str) -> None:
        """Simulate an external entity deleting the drop rule directly from the router."""
        norm = normalize_mac(mac)
        self._blocked_mac_set.discard(norm)

    def inject_drift_change_limit(self, mac: str, dl_kbps: int, ul_kbps: int = 0) -> None:
        """Simulate an external entity modifying bandwidth limits directly on the router."""
        norm = normalize_mac(mac)
        self._dl_limits[norm] = dl_kbps
        if ul_kbps:
            self._ul_limits[norm] = ul_kbps

    def inject_device_joined(self, device: DiscoveredDeviceRaw) -> None:
        """Simulate a new client connecting to the router."""
        self._simulated_devices.append(device)

    def inject_device_left(self, mac: str) -> None:
        """Simulate a client disconnecting or roaming away."""
        norm = normalize_mac(mac)
        self._simulated_devices = [d for d in self._simulated_devices if normalize_mac(d.mac) != norm]
