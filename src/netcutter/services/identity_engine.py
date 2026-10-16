"""
Device Identity Correlation Engine.
Correlates MACs, IPs, DUIDs, Hostnames, and handles MAC Randomization.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from netcutter.backends.base import DiscoveredDeviceRaw
from netcutter.domain.identity import (
    IdentityCorrelationEvent,
    calculate_identity_confidence,
    classify_device,
    format_device_display_name,
    resolve_vendor_by_mac,
)
from netcutter.domain.models import (
    ConfidenceLevel,
    Device,
    DevicePolicyState,
    normalize_mac,
)
from netcutter.persistence.database import Database
from netcutter.persistence.repository import DeviceRepository


GENERIC_HOSTNAMES = {
    "android",
    "iphone",
    "ipad",
    "galaxy",
    "localhost",
    "pc",
    "desktop",
    "laptop",
    "unknown",
    "wireless",
    "client",
    "workstation",
    "new-host",
    "none",
    "dhcp",
    "router",
    "gateway",
}


class IdentityEngine:
    def __init__(self, db: Database, device_repo: DeviceRepository):
        self.db = db
        self.device_repo = device_repo

    def process_discovery(self, raw_items: List[DiscoveredDeviceRaw]) -> List[Device]:
        """
        Merge raw observations into domain device records.
        Applies MAC normalization, OUI vendor resolution, and identity correlation.
        """
        existing_devices = self.device_repo.get_all()
        # Index by MACs (including historical)
        mac_to_device = {}
        for dev in existing_devices:
            for m in dev.historical_macs:
                mac_to_device[m.lower()] = dev

        # Index by DUID and Hostname for correlation heuristics
        duid_to_device = {d.duid: d for d in existing_devices if d.duid}
        host_to_device = {d.hostname.lower(): d for d in existing_devices if d.hostname}

        updated_devices: List[Device] = []

        for raw in raw_items:
            norm_mac = normalize_mac(raw.mac)
            matched_device: Optional[Device] = mac_to_device.get(norm_mac)

            # Heuristic correlation: Check if a randomized MAC matches an existing known device by DUID or Hostname
            if not matched_device:
                if raw.duid and raw.duid in duid_to_device:
                    candidate = duid_to_device[raw.duid]
                    self._record_correlation_event(
                        candidate.device_guid,
                        candidate.primary_mac,
                        norm_mac,
                        f"Matched identical DHCP DUID {raw.duid}",
                        ConfidenceLevel.HIGH,
                    )
                    if norm_mac not in candidate.historical_macs:
                        candidate.historical_macs.append(norm_mac)
                    candidate.primary_mac = norm_mac
                    matched_device = candidate
                elif (
                    raw.hostname
                    and raw.hostname.lower().strip() not in GENERIC_HOSTNAMES
                    and len(raw.hostname.strip()) >= 3
                    and raw.hostname.lower() in host_to_device
                ):
                    candidate = host_to_device[raw.hostname.lower()]
                    # False-merge protection: Only auto-merge if candidate has randomized MAC
                    if candidate.is_randomized_mac:
                        self._record_correlation_event(
                            candidate.device_guid,
                            candidate.primary_mac,
                            norm_mac,
                            f"Matched unique Hostname '{raw.hostname}' (Randomized MAC rotation)",
                            ConfidenceLevel.MEDIUM,
                        )
                        if norm_mac not in candidate.historical_macs:
                            candidate.historical_macs.append(norm_mac)
                        candidate.primary_mac = norm_mac
                        matched_device = candidate

            now = datetime.now(timezone.utc)
            if matched_device:
                # Update existing record
                matched_device.last_seen = now
                matched_device.is_online = True
                if raw.ipv4_addresses:
                    matched_device.ipv4_addresses = sorted(list(set(matched_device.ipv4_addresses + raw.ipv4_addresses)))
                if raw.ipv6_addresses:
                    matched_device.ipv6_addresses = sorted(list(set(matched_device.ipv6_addresses + raw.ipv6_addresses)))
                if raw.hostname:
                    matched_device.hostname = raw.hostname
                if raw.duid:
                    matched_device.duid = raw.duid
                if raw.client_id:
                    matched_device.dhcp_client_id = raw.client_id
                if not matched_device.vendor:
                    matched_device.vendor = resolve_vendor_by_mac(norm_mac)

                cat, basis, _ = classify_device(norm_mac, matched_device.hostname, matched_device.vendor)
                matched_device.category = cat
                matched_device.classification_basis = basis

                if (
                    matched_device.display_name.startswith("Device-")
                    or matched_device.display_name.startswith("Client")
                    or matched_device.display_name.startswith("Private")
                    or not matched_device.display_name
                ):
                    matched_device.display_name = format_device_display_name(
                        matched_device.hostname,
                        matched_device.vendor,
                        cat,
                        matched_device.ipv4_addresses,
                        norm_mac,
                        matched_device.is_randomized_mac,
                    )

                self.device_repo.upsert(matched_device)
                updated_devices.append(matched_device)
            else:
                # Create brand new device record
                vendor = resolve_vendor_by_mac(norm_mac)
                confidence, is_rand = calculate_identity_confidence(
                    norm_mac, raw.hostname, raw.duid, False
                )
                cat, basis, _ = classify_device(norm_mac, raw.hostname, vendor)
                display_name = format_device_display_name(
                    raw.hostname,
                    vendor,
                    cat,
                    raw.ipv4_addresses,
                    norm_mac,
                    is_rand,
                )

                new_dev = Device(
                    display_name=display_name,
                    primary_mac=norm_mac,
                    historical_macs=[norm_mac],
                    ipv4_addresses=raw.ipv4_addresses,
                    ipv6_addresses=raw.ipv6_addresses,
                    hostname=raw.hostname,
                    vendor=vendor,
                    dhcp_client_id=raw.client_id,
                    duid=raw.duid,
                    first_seen=now,
                    last_seen=now,
                    is_online=True,
                    confidence_level=confidence,
                    is_randomized_mac=is_rand,
                    category=cat,
                    classification_basis=basis,
                )
                self.device_repo.upsert(new_dev)
                updated_devices.append(new_dev)

        return updated_devices

    def merge_devices(self, target_guid: str, source_guid: str) -> Optional[Device]:
        """Manually merge two device identities into one logical entity."""
        target = self.device_repo.get_by_guid(target_guid)
        source = self.device_repo.get_by_guid(source_guid)
        if not target or not source or target.device_guid == source.device_guid:
            return None

        # Merge historical MACs, IPs, DUIDs
        for m in source.historical_macs:
            if m not in target.historical_macs:
                target.historical_macs.append(m)
        target.ipv4_addresses = sorted(list(set(target.ipv4_addresses + source.ipv4_addresses)))
        target.ipv6_addresses = sorted(list(set(target.ipv6_addresses + source.ipv6_addresses)))
        if not target.hostname and source.hostname:
            target.hostname = source.hostname
        if not target.duid and source.duid:
            target.duid = source.duid

        self._record_correlation_event(
            target.device_guid,
            source.primary_mac,
            target.primary_mac,
            f"Manual administrative merge with {source.display_name} ({source.device_guid})",
            ConfidenceLevel.HIGH,
        )

        self.device_repo.upsert(target)
        self.device_repo.delete(source_guid)
        return target

    def _record_correlation_event(
        self, guid: str, old_mac: str, new_mac: str, reason: str, confidence: ConfidenceLevel
    ) -> None:
        with self.db.get_connection() as conn:
            import uuid
            conn.execute("""
            INSERT INTO identity_events (event_id, device_guid, timestamp, old_mac, new_mac, reason, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                guid,
                datetime.now(timezone.utc).isoformat(),
                old_mac,
                new_mac,
                reason,
                confidence.value,
            ))
            conn.commit()
