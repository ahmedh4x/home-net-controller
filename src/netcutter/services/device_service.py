"""
Device Management Service.
Coordinates device discovery, metadata updates, and status monitoring.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from netcutter.domain.models import Device, PolicyStatus
from netcutter.persistence.repository import DeviceRepository
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.identity_engine import IdentityEngine


class DeviceService:
    def __init__(
        self,
        device_repo: DeviceRepository,
        identity_engine: IdentityEngine,
        gateway_manager: GatewayManager,
    ):
        self.device_repo = device_repo
        self.identity_engine = identity_engine
        self.gateway_manager = gateway_manager

    def _enrich_device_traffic(self, dev: Device) -> Device:
        """Enrich a Device domain object with live traffic accounting snapshot data."""
        from netcutter.services.traffic_accounting import get_traffic_accounting_service
        snap = get_traffic_accounting_service().get_snapshot(dev.primary_mac)
        if snap:
            dev.download_rate_bps = snap.rx_rate_bps
            dev.upload_rate_bps = snap.tx_rate_bps
            dev.total_download_bytes = snap.rx_bytes_total
            dev.total_upload_bytes = snap.tx_bytes_total
            dev.last_traffic_time = snap.last_activity
            dev.traffic_monitoring_mode = snap.monitoring_mode.value
        return dev

    def get_all_devices(self) -> List[Device]:
        devices = self.device_repo.get_all()
        return [self._enrich_device_traffic(dev) for dev in devices]

    def get_device_by_guid(self, guid: str) -> Optional[Device]:
        device = self.device_repo.get_by_guid(guid)
        return self._enrich_device_traffic(device) if device else None

    def start_active_traffic_metering(self, guid: str) -> Tuple[bool, str]:
        """Enable active Layer-2 full-duplex traffic metering on the active backend."""
        dev = self.device_repo.get_by_guid(guid)
        if not dev:
            return False, "Device not found"
        backend = self.gateway_manager.get_active_backend()
        if not backend or not hasattr(backend, "start_traffic_metering"):
            return False, "Active gateway backend does not support Layer-2 traffic metering"
        res = backend.start_traffic_metering(dev.primary_mac, dev.ipv4_addresses)
        return res.success, res.details if res.success else (res.error or "Failed to start metering")

    def stop_active_traffic_metering(self, guid: str) -> Tuple[bool, str]:
        """Disable active Layer-2 traffic metering and restore direct authentic ARP routing."""
        dev = self.device_repo.get_by_guid(guid)
        if not dev:
            return False, "Device not found"
        backend = self.gateway_manager.get_active_backend()
        if not backend or not hasattr(backend, "stop_traffic_metering"):
            return False, "Active gateway backend does not support Layer-2 traffic metering"
        res = backend.stop_traffic_metering(dev.primary_mac, dev.ipv4_addresses)
        return res.success, res.details if res.success else (res.error or "Failed to stop metering")

    def is_device_metered(self, guid: str) -> bool:
        dev = self.device_repo.get_by_guid(guid)
        if not dev:
            return False
        backend = self.gateway_manager.get_active_backend()
        if backend and hasattr(backend, "is_metering"):
            return backend.is_metering(dev.primary_mac)
        return False

    def update_display_name(self, guid: str, new_name: str) -> Optional[Device]:
        device = self.device_repo.get_by_guid(guid)
        if device and new_name.strip():
            device.display_name = new_name.strip()
            self.device_repo.upsert(device)
            return self._enrich_device_traffic(device)
        return None

    def is_simulator_active(self) -> bool:
        backend = self.gateway_manager.get_active_backend()
        from netcutter.backends.mock_backend import MockGatewayBackend
        return isinstance(backend, MockGatewayBackend)

    def refresh_discovery(self) -> List[Device]:
        """
        Polls active gateway for live connected clients, merges observations,
        queries observed firewall/QoS state, and updates online presence.
        """
        backend = self.gateway_manager.get_active_backend()
        if not backend or not backend.is_connected():
            return self.device_repo.get_all()

        raw_items = backend.discover_devices()
        updated_devices = self.identity_engine.process_discovery(raw_items)
        active_guids = {d.device_guid for d in updated_devices}

        # Query observed kernel policy state for each active device
        now = datetime.now(timezone.utc)
        for dev in updated_devices:
            try:
                all_ips = dev.ipv4_addresses + dev.ipv6_addresses
                obs = backend.query_observed_state(dev.primary_mac, all_ips)
                dev.observed_policy = obs.to_policy_state()
                dev.last_sync = now
                
                # Check status
                if dev.desired_policy == dev.observed_policy:
                    dev.policy_status = PolicyStatus.SYNCHRONIZED
                    dev.last_policy_error = None
                else:
                    dev.policy_status = PolicyStatus.DRIFTED
                self.device_repo.upsert(dev)
            except Exception:
                pass

        # Mark devices not observed in this scan as offline if last seen > 3 minutes ago
        all_devices = self.device_repo.get_all()
        for dev in all_devices:
            if dev.device_guid not in active_guids:
                if (now - dev.last_seen).total_seconds() > 180:
                    dev.is_online = False
                    self.device_repo.upsert(dev)

        return self.device_repo.get_all()
