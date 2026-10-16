"""
MikroTik RouterOS 7 REST API Backend.
Enforces firewall drops using address-lists and shaping using Simple Queues.
"""
from __future__ import annotations

import hashlib
import logging
import re
import ssl
from typing import Dict, List, Optional, Tuple
import requests
from requests.auth import HTTPBasicAuth
import urllib3
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

logger = logging.getLogger("netcutter.backend.mikrotik")


class MikroTikBackend(IGatewayBackend):
    def __init__(self, config: GatewayConfig, password: Optional[str] = None):
        self.config = config
        self._password = password
        self._session: Optional[requests.Session] = None
        self._base_url = f"https://{self.config.host}:{self.config.port}/rest"

    @property
    def backend_name(self) -> str:
        return f"MikroTik RouterOS ({self.config.host})"

    @property
    def capabilities(self) -> BackendCapabilities:
        return (
            BackendCapabilities.MAC_BLOCKING
            | BackendCapabilities.IPV4_BLOCKING
            | BackendCapabilities.IPV6_BLOCKING
            | BackendCapabilities.UPLOAD_SHAPING
            | BackendCapabilities.DOWNLOAD_SHAPING
            | BackendCapabilities.CONNTRACK_FLUSHING
            | BackendCapabilities.FASTTRACK_BYPASS
            | BackendCapabilities.DISCOVERY
            | BackendCapabilities.TRAFFIC_COUNTERS
            | BackendCapabilities.DOMAIN_BLOCKING
        )

    def is_connected(self) -> bool:
        return self._session is not None

    def connect(self) -> bool:
        try:
            self._session = requests.Session()
            self._session.auth = HTTPBasicAuth(self.config.username, self._password or "")

            # Configure TLS validation and cryptographic certificate pinning
            if self.config.tls_ca_path:
                self._session.verify = self.config.tls_ca_path
            elif self.config.tls_fingerprint:
                # Cryptographic certificate fingerprint pinning for self-signed router certs
                self._verify_tls_fingerprint()
                self._session.verify = False
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            elif self.config.tls_verify:
                # Default secure mode: strict system CA verification
                self._session.verify = True
            else:
                # Insecure TLS explicitly opted into by setting tls_verify=False
                logger.warning(
                    "SECURITY WARNING: Strict TLS certificate verification is disabled for MikroTik gateway %s:%s. "
                    "Connection is vulnerable to active Man-in-the-Middle (MITM) attacks. "
                    "Configure tls_ca_path or pin tls_fingerprint to secure this connection.",
                    self.config.host,
                    self.config.port,
                )
                self._session.verify = False
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Test connectivity via system resource
            res = self._session.get(f"{self._base_url}/system/resource", timeout=8)
            if res.status_code == 200:
                self._ensure_firewall_rules()
                return True
            self.config.last_error = f"RouterOS REST returned HTTP {res.status_code}"
            self._session = None
            return False
        except Exception as ex:
            self.config.last_error = f"MikroTik connection failed: {ex}"
            self._session = None
            return False

    def _verify_tls_fingerprint(self) -> None:
        """Fetch remote TLS certificate and verify SHA256 fingerprint against pinned configuration."""
        import socket
        expected_fp = self.config.tls_fingerprint.strip().lower()
        if expected_fp.startswith("sha256:"):
            expected_fp = expected_fp[7:]
        expected_fp = expected_fp.replace(":", "")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((self.config.host, self.config.port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.config.host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    raise ssl.SSLError(f"Unable to retrieve peer TLS certificate from {self.config.host}:{self.config.port}")
                actual_fp = hashlib.sha256(der_cert).hexdigest().lower()
                if actual_fp != expected_fp:
                    raise ssl.SSLError(
                        f"TLS certificate fingerprint mismatch for {self.config.host}:{self.config.port}! "
                        f"Presented: {actual_fp}, Expected: {expected_fp}. Possible Man-in-the-Middle attack."
                    )
                logger.info(f"Verified TLS certificate fingerprint for {self.config.host}: {actual_fp}")

    def disconnect(self) -> None:
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None

    def _ensure_firewall_rules(self) -> None:
        """
        Ensure drop rules for netcutter_blocked exist in both IPv4 and IPv6 forward chains,
        and inspect if FastTrack rules threaten to bypass drops.
        """
        try:
            # 1. IPv4 Forward Drop Filter
            res_v4 = self._session.get(
                f"{self._base_url}/ip/firewall/filter?src-address-list=netcutter_blocked",
                timeout=5,
            )
            if res_v4.status_code == 200 and not res_v4.json():
                self._session.put(
                    f"{self._base_url}/ip/firewall/filter",
                    json={
                        "chain": "forward",
                        "action": "drop",
                        "src-address-list": "netcutter_blocked",
                        "comment": "netcutter: blocked device drop rule",
                    },
                    timeout=5,
                )

            # 2. IPv6 Forward Drop Filter
            res_v6 = self._session.get(
                f"{self._base_url}/ipv6/firewall/filter?src-address-list=netcutter_blocked",
                timeout=5,
            )
            if res_v6.status_code == 200 and not res_v6.json():
                self._session.put(
                    f"{self._base_url}/ipv6/firewall/filter",
                    json={
                        "chain": "forward",
                        "action": "drop",
                        "src-address-list": "netcutter_blocked",
                        "comment": "netcutter: blocked device ipv6 drop rule",
                    },
                    timeout=5,
                )

            # 3. FastTrack connection inspection
            ft_res = self._session.get(
                f"{self._base_url}/ip/firewall/filter?action=fasttrack-connection",
                timeout=5,
            )
            if ft_res.status_code == 200 and ft_res.json():
                logger.warning(
                    "RouterOS FastTrack rule detected. Active connections must be terminated "
                    "via conntrack eviction to prevent firewall bypass."
                )
        except Exception as ex:
            logger.error(f"Error ensuring RouterOS firewall rules: {ex}")

    def discover_devices(self) -> List[DiscoveredDeviceRaw]:
        devices: Dict[str, DiscoveredDeviceRaw] = {}
        if not self.is_connected():
            return []

        try:
            # 1. ARP Table (/ip/arp)
            arp_res = self._session.get(f"{self._base_url}/ip/arp", timeout=8)
            if arp_res.status_code == 200:
                for entry in arp_res.json():
                    mac = entry.get("mac-address", "").lower()
                    ip = entry.get("address")
                    if mac and mac != "00:00:00:00:00:00":
                        norm = normalize_mac(mac)
                        if norm not in devices:
                            devices[norm] = DiscoveredDeviceRaw(mac=norm)
                        if ip and ip not in devices[norm].ipv4_addresses:
                            devices[norm].ipv4_addresses.append(ip)

            # 2. IPv6 Neighbors (/ipv6/neighbor)
            nd_res = self._session.get(f"{self._base_url}/ipv6/neighbor", timeout=8)
            if nd_res.status_code == 200:
                for entry in nd_res.json():
                    mac = entry.get("mac-address", "").lower()
                    ip = entry.get("address")
                    if mac:
                        norm = normalize_mac(mac)
                        if norm not in devices:
                            devices[norm] = DiscoveredDeviceRaw(mac=norm)
                        if ip and ip not in devices[norm].ipv6_addresses:
                            devices[norm].ipv6_addresses.append(ip)

            # 3. DHCP Leases (/ip/dhcp-server/lease)
            dhcp_res = self._session.get(f"{self._base_url}/ip/dhcp-server/lease", timeout=8)
            if dhcp_res.status_code == 200:
                for entry in dhcp_res.json():
                    mac = entry.get("mac-address", "").lower()
                    ip = entry.get("address")
                    host = entry.get("host-name")
                    client_id = entry.get("client-id")
                    if mac:
                        norm = normalize_mac(mac)
                        if norm not in devices:
                            devices[norm] = DiscoveredDeviceRaw(mac=norm)
                        if ip and ip not in devices[norm].ipv4_addresses:
                            devices[norm].ipv4_addresses.append(ip)
                        if host and not devices[norm].hostname:
                            devices[norm].hostname = host
                        if client_id and not devices[norm].client_id:
                            devices[norm].client_id = client_id
        except Exception:
            pass

        return list(devices.values())

    def block_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(success=False, operation="BLOCK", error="Not connected")
        try:
            norm_mac = normalize_mac(mac)
            # Add each IP to address-list netcutter_blocked and flush connections bidirectionally
            for ip in ips:
                is_v6 = ":" in ip
                endpoint = "ipv6/firewall/address-list" if is_v6 else "ip/firewall/address-list"
                conn_endpoint = "ipv6/firewall/connection/remove" if is_v6 else "ip/firewall/connection/remove"
                
                self._session.put(
                    f"{self._base_url}/{endpoint}",
                    json={
                        "list": "netcutter_blocked",
                        "address": ip,
                        "comment": f"netcutter:{norm_mac}",
                    },
                    timeout=5,
                )
                
                # Terminate active TCP/UDP connections for both src and dst
                try:
                    self._session.post(
                        f"{self._base_url}/{conn_endpoint}",
                        json={".query": [f"src-address={ip}"]},
                        timeout=5,
                    )
                    self._session.post(
                        f"{self._base_url}/{conn_endpoint}",
                        json={".query": [f"dst-address={ip}"]},
                        timeout=5,
                    )
                except Exception:
                    pass

            observed = self.query_observed_state(norm_mac, ips)
            verified = observed.internet_access == InternetAccessState.BLOCKED
            return PolicyExecutionResult(
                success=True,
                operation="BLOCK",
                details=f"Added {len(ips)} IPs for {norm_mac} to RouterOS address-list with dual-stack connection flushing",
                verification_verified=verified,
            )
        except Exception as ex:
            return PolicyExecutionResult(success=False, operation="BLOCK", error=str(ex))

    def unblock_device(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(success=False, operation="UNBLOCK", error="Not connected")
        try:
            norm_mac = normalize_mac(mac)
            for ip in ips:
                is_v6 = ":" in ip
                endpoint = "ipv6/firewall/address-list" if is_v6 else "ip/firewall/address-list"
                # Find entry ID
                query_res = self._session.get(
                    f"{self._base_url}/{endpoint}?list=netcutter_blocked&address={ip}",
                    timeout=5,
                )
                if query_res.status_code == 200:
                    for item in query_res.json():
                        item_id = item.get(".id")
                        if item_id:
                            self._session.delete(f"{self._base_url}/{endpoint}/{item_id}", timeout=5)

            observed = self.query_observed_state(norm_mac, ips)
            verified = observed.internet_access == InternetAccessState.ALLOWED
            return PolicyExecutionResult(
                success=True,
                operation="UNBLOCK",
                details=f"Removed {norm_mac} from RouterOS address-list",
                verification_verified=verified,
            )
        except Exception as ex:
            return PolicyExecutionResult(success=False, operation="UNBLOCK", error=str(ex))

    def set_bandwidth_limit(
        self, mac: str, ips: List[str], dl_kbps: int, ul_kbps: int
    ) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(success=False, operation="SET_BANDWIDTH", error="Not connected")
        try:
            norm_mac = normalize_mac(mac)
            queue_name = f"netcutter_{norm_mac.replace(':', '')}"
            target_ips = ",".join(ips) if ips else ""
            if not target_ips:
                return PolicyExecutionResult(success=False, operation="SET_BANDWIDTH", error="No IP available for target")

            # max-limit format in RouterOS: <upload>/<download> in bps
            max_limit = f"{ul_kbps}k/{dl_kbps}k"
            payload = {
                "name": queue_name,
                "target": target_ips,
                "max-limit": max_limit,
                "comment": f"netcutter limit for {norm_mac}",
            }
            # Query if queue already exists to decide between PATCH (update) or PUT (create)
            existing_res = self._session.get(f"{self._base_url}/queue/simple?name={queue_name}", timeout=5)
            existing_id = None
            if existing_res.status_code == 200:
                for item in existing_res.json():
                    if item.get("name") == queue_name:
                        existing_id = item.get(".id")
                        break

            if existing_id:
                res = self._session.patch(f"{self._base_url}/queue/simple/{existing_id}", json=payload, timeout=5)
            else:
                res = self._session.put(f"{self._base_url}/queue/simple", json=payload, timeout=5)

            if res.status_code >= 400:
                return PolicyExecutionResult(
                    success=False,
                    operation="SET_BANDWIDTH",
                    error=f"RouterOS Simple Queue failed with HTTP {res.status_code}: {res.text}",
                    verification_verified=False,
                )
            
            observed = self.query_observed_state(norm_mac, ips)
            verified = (
                (dl_kbps == 0 or observed.download_limit_kbps == dl_kbps)
                and (ul_kbps == 0 or observed.upload_limit_kbps == ul_kbps)
            )
            return PolicyExecutionResult(
                success=True,
                operation="SET_BANDWIDTH",
                details=f"{'Updated' if existing_id else 'Created'} RouterOS Simple Queue {queue_name} ({max_limit})",
                verification_verified=verified,
            )
        except Exception as ex:
            return PolicyExecutionResult(success=False, operation="SET_BANDWIDTH", error=str(ex))

    def remove_bandwidth_limit(self, mac: str, ips: List[str]) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(success=False, operation="REMOVE_BANDWIDTH", error="Not connected")
        try:
            norm_mac = normalize_mac(mac)
            queue_name = f"netcutter_{norm_mac.replace(':', '')}"
            res = self._session.get(f"{self._base_url}/queue/simple?name={queue_name}", timeout=5)
            if res.status_code == 200:
                for item in res.json():
                    q_id = item.get(".id")
                    if q_id:
                        self._session.delete(f"{self._base_url}/queue/simple/{q_id}", timeout=5)

            observed = self.query_observed_state(norm_mac, ips)
            verified = observed.download_limit_kbps == 0 and observed.upload_limit_kbps == 0
            return PolicyExecutionResult(
                success=True,
                operation="REMOVE_BANDWIDTH",
                details=f"Removed RouterOS Simple Queue {queue_name}",
                verification_verified=verified,
            )
        except Exception as ex:
            return PolicyExecutionResult(success=False, operation="REMOVE_BANDWIDTH", error=str(ex))

    def query_observed_state(self, mac: str, ips: List[str]) -> ObservedPolicy:
        if not self.is_connected():
            return ObservedPolicy(internet_access=InternetAccessState.ALLOWED, is_verified=False)

        norm_mac = normalize_mac(mac)
        is_blocked = False
        dl_limit = 0
        ul_limit = 0

        try:
            # Check address lists
            for ip in ips:
                is_v6 = ":" in ip
                endpoint = "ipv6/firewall/address-list" if is_v6 else "ip/firewall/address-list"
                res = self._session.get(
                    f"{self._base_url}/{endpoint}?list=netcutter_blocked&address={ip}",
                    timeout=5,
                )
                if res.status_code == 200 and len(res.json()) > 0:
                    is_blocked = True
                    break

            # Check Simple Queue
            queue_name = f"netcutter_{norm_mac.replace(':', '')}"
            q_res = self._session.get(f"{self._base_url}/queue/simple?name={queue_name}", timeout=5)
            if q_res.status_code == 200 and len(q_res.json()) > 0:
                item = q_res.json()[0]
                max_limit_str = item.get("max-limit", "")
                parts = max_limit_str.split("/")
                if len(parts) == 2:
                    def _parse_rate_to_kbps(s: str) -> int:
                        s = s.strip().lower()
                        if not s:
                            return 0
                        if s.endswith("g"):
                            return int(float(s[:-1]) * 1_000_000)
                        if s.endswith("m"):
                            return int(float(s[:-1]) * 1_000)
                        if s.endswith("k"):
                            return int(float(s[:-1]))
                        if s.isdigit():
                            return int(s) // 1000
                        try:
                            return int(float(s)) // 1000
                        except Exception:
                            return 0

                    ul_limit = _parse_rate_to_kbps(parts[0])
                    dl_limit = _parse_rate_to_kbps(parts[1])
        except Exception:
            return ObservedPolicy(
                internet_access=InternetAccessState.UNKNOWN,
                download_limit_kbps=0,
                upload_limit_kbps=0,
                is_verified=False,
            )

        return ObservedPolicy(
            internet_access=InternetAccessState.BLOCKED if is_blocked else InternetAccessState.ALLOWED,
            download_limit_kbps=dl_limit,
            upload_limit_kbps=ul_limit,
            is_verified=True,
        )

    def health_check(self) -> Tuple[bool, str]:
        if not self.is_connected():
            return False, "Not connected"
        try:
            res = self._session.get(f"{self._base_url}/system/resource", timeout=5)
            if res.status_code == 200:
                data = res.json()
                version = data.get("version", "unknown")
                board = data.get("board-name", "MikroTik")
                return True, f"RouterOS {version} on {board} healthy"
            return False, f"RouterOS health error HTTP {res.status_code}"
        except Exception as ex:
            return False, f"Health check failed: {ex}"

    def apply_domain_rule(self, rule: DomainBlockingRule) -> PolicyExecutionResult:
        """
        Enforce domain sinkhole via RouterOS /ip/dns/static entry.
        """
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False,
                operation="APPLY_DOMAIN_RULE",
                error="MikroTik RouterOS is not connected",
            )
        try:
            # Check if static entry already exists
            tag = f"netcutter:{rule.rule_id}"
            get_res = self._session.get(f"{self._base_url}/ip/dns/static", timeout=5)
            existing_id = None
            if get_res.status_code == 200:
                for entry in get_res.json():
                    if entry.get("comment") == tag:
                        existing_id = entry.get(".id")
                        break

            payload = {
                "name": rule.domain,
                "address": "0.0.0.0",
                "comment": tag,
                "disabled": "false" if rule.is_enabled else "true",
            }
            if existing_id:
                res = self._session.patch(f"{self._base_url}/ip/dns/static/{existing_id}", json=payload, timeout=5)
            else:
                res = self._session.put(f"{self._base_url}/ip/dns/static", json=payload, timeout=5)

            if res.status_code < 400:
                return PolicyExecutionResult(
                    success=True,
                    operation="APPLY_DOMAIN_RULE",
                    details=f"MikroTik static DNS sinkhole active for '{rule.domain}' -> 0.0.0.0",
                    verification_verified=True,
                )
            return PolicyExecutionResult(
                success=False,
                operation="APPLY_DOMAIN_RULE",
                error=f"RouterOS returned HTTP {res.status_code}: {res.text}",
            )
        except Exception as ex:
            return PolicyExecutionResult(
                success=False,
                operation="APPLY_DOMAIN_RULE",
                error=f"Error applying domain rule on MikroTik: {ex}",
            )

    def remove_domain_rule(self, rule: DomainBlockingRule) -> PolicyExecutionResult:
        if not self.is_connected():
            return PolicyExecutionResult(
                success=False,
                operation="REMOVE_DOMAIN_RULE",
                error="MikroTik RouterOS is not connected",
            )
        try:
            tag = f"netcutter:{rule.rule_id}"
            get_res = self._session.get(f"{self._base_url}/ip/dns/static", timeout=5)
            if get_res.status_code == 200:
                for entry in get_res.json():
                    if entry.get("comment") == tag:
                        eid = entry.get(".id")
                        self._session.delete(f"{self._base_url}/ip/dns/static/{eid}", timeout=5)
            return PolicyExecutionResult(
                success=True,
                operation="REMOVE_DOMAIN_RULE",
                details=f"Removed static DNS rule for '{rule.domain}' from MikroTik",
                verification_verified=True,
            )
        except Exception as ex:
            return PolicyExecutionResult(
                success=False,
                operation="REMOVE_DOMAIN_RULE",
                error=f"Error removing domain rule on MikroTik: {ex}",
            )

    def verify_domain_rule(self, rule: DomainBlockingRule) -> Tuple[bool, str]:
        if not self.is_connected():
            return False, "Not connected"
        try:
            tag = f"netcutter:{rule.rule_id}"
            get_res = self._session.get(f"{self._base_url}/ip/dns/static", timeout=5)
            if get_res.status_code == 200:
                for entry in get_res.json():
                    if entry.get("comment") == tag:
                        return True, f"Verified MikroTik DNS static entry exists for '{rule.domain}'"
            return False, "Rule not found in MikroTik DNS static table"
        except Exception as ex:
            return False, str(ex)

