"""
Base Gateway Interface and Data Transfer Objects.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.models import DevicePolicyState, InternetAccessState


@dataclass
class DiscoveredDeviceRaw:
    """Raw device observation extracted from gateway tables."""
    mac: str
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    hostname: Optional[str] = None
    interface: str = "lan"
    lease_expiry: Optional[datetime] = None
    duid: Optional[str] = None
    client_id: Optional[str] = None
    is_active: bool = True


@dataclass
class PolicyExecutionResult:
    """Result of attempting a firewall or QoS policy mutation."""
    success: bool
    operation: str
    details: str = ""
    error: Optional[str] = None
    verification_verified: bool = False


@dataclass
class ObservedPolicy:
    """Live observed state queried from the router kernel."""
    internet_access: InternetAccessState = InternetAccessState.ALLOWED
    download_limit_kbps: int = 0
    upload_limit_kbps: int = 0
    packet_drop_count: int = 0
    byte_drop_count: int = 0
    is_verified: bool = True

    def to_policy_state(self) -> DevicePolicyState:
        return DevicePolicyState(
            internet_access=self.internet_access,
            download_limit_kbps=self.download_limit_kbps,
            upload_limit_kbps=self.upload_limit_kbps,
        )


class IGatewayBackend(ABC):
    """
    Contract for Gateway Enforcement and Discovery Backends.
    """
    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Name of the backend implementation."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> BackendCapabilities:
        """Flags declaring supported capabilities."""
        pass

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the gateway."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the gateway."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connection is active."""
        pass

    @abstractmethod
    def discover_devices(self) -> List[DiscoveredDeviceRaw]:
        """Query live neighbor caches, ARP tables, and DHCP leases."""
        pass

    @abstractmethod
    def block_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        """Enforce internet block on the gateway."""
        pass

    @abstractmethod
    def unblock_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        """Remove internet block from the gateway."""
        pass

    @abstractmethod
    def set_bandwidth_limit(
        self, mac: str, ips: List[str], dl_kbps: int, ul_kbps: int
    ) -> PolicyExecutionResult:
        """Apply download and/or upload bandwidth shaping."""
        pass

    @abstractmethod
    def remove_bandwidth_limit(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        """Remove traffic shaping classes for the client."""
        pass

    @abstractmethod
    def query_observed_state(self, mac: str, ips: List[str]) -> ObservedPolicy:
        """Query active kernel state (nftables sets, tc classes) for the client."""
        pass

    @abstractmethod
    def health_check(self) -> Tuple[bool, str]:
        """Verify gateway communication and service health."""
        pass

    def apply_domain_rule(self, rule: "DomainBlockingRule") -> PolicyExecutionResult:
        """
        Apply a domain blocking rule on the backend.
        Default implementation reports unsupported if backend does not implement it.
        """
        return PolicyExecutionResult(
            success=False,
            operation="APPLY_DOMAIN_RULE",
            error=f"Domain blocking is not supported by {self.backend_name}",
        )

    def remove_domain_rule(self, rule: "DomainBlockingRule") -> PolicyExecutionResult:
        """
        Remove a domain blocking rule from the backend.
        Default implementation reports unsupported if backend does not implement it.
        """
        return PolicyExecutionResult(
            success=False,
            operation="REMOVE_DOMAIN_RULE",
            error=f"Domain blocking is not supported by {self.backend_name}",
        )

    def query_domain_rules(self) -> List["DomainBlockingRule"]:
        """Query currently active domain rules from the backend."""
        return []

    def verify_domain_rule(self, rule: "DomainBlockingRule") -> Tuple[bool, str]:
        """Verify if a domain rule is actively enforced in the backend kernel/DNS."""
        return False, f"Verification unsupported by {self.backend_name}"

