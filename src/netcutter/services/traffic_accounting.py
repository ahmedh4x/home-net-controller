"""
Per-Device Traffic Accounting and Rate Calculation Engine for NetCutter.
Adapted from the LANtern-Control measurement pipeline (MIT License).
Maintains cumulative byte counters, calculates instantaneous and smoothed throughput rates,
and attributes traffic by direction and MAC address.
"""
from __future__ import annotations

import collections
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Deque, Dict, List, Optional

from netcutter.domain.models import format_bytes, format_rate, normalize_mac

logger = logging.getLogger("netcutter.traffic.accounting")


class TrafficDirection(str, Enum):
    DOWNLOAD = "DOWNLOAD"  # Inbound to client (from gateway/internet)
    UPLOAD = "UPLOAD"      # Outbound from client (towards gateway/internet)


class TrafficMonitoringMode(str, Enum):
    OFFPATH_LIMITED = "OFFPATH_LIMITED"        # Passive broadcast-only on switched LAN
    ACTIVE_METERING = "ACTIVE_METERING"        # Active Layer-2 full-duplex bridge metering
    GATEWAY_NATIVE = "GATEWAY_NATIVE"          # Router kernel counters (OpenWrt/Linux)
    UNAVAILABLE = "UNAVAILABLE"                # Backend disconnected or not supported


@dataclass
class TrafficSample:
    """A point-in-time snapshot of throughput rates."""
    timestamp: float
    rx_rate_bps: float
    tx_rate_bps: float


@dataclass
class DeviceTrafficRecord:
    """Thread-safe cumulative counters and rate state for a single network device."""
    mac: str
    rx_bytes_total: int = 0
    tx_bytes_total: int = 0
    rx_packets_total: int = 0
    tx_packets_total: int = 0

    # Rate calculation state
    last_rx_bytes_snapshot: int = 0
    last_tx_bytes_snapshot: int = 0
    rx_rate_bps: float = 0.0
    tx_rate_bps: float = 0.0

    last_activity: Optional[datetime] = None
    monitoring_mode: TrafficMonitoringMode = TrafficMonitoringMode.OFFPATH_LIMITED

    # Rolling history for sparklines / charts (up to 60 samples)
    history: Deque[TrafficSample] = field(default_factory=lambda: collections.deque(maxlen=60))

    @property
    def total_bytes(self) -> int:
        return self.rx_bytes_total + self.tx_bytes_total

    @property
    def total_rate_bps(self) -> float:
        return self.rx_rate_bps + self.tx_rate_bps

    @property
    def download_rate_display(self) -> str:
        return format_rate(self.rx_rate_bps)

    @property
    def upload_rate_display(self) -> str:
        return format_rate(self.tx_rate_bps)

    @property
    def total_download_display(self) -> str:
        return format_bytes(self.rx_bytes_total)

    @property
    def total_upload_display(self) -> str:
        return format_bytes(self.tx_bytes_total)

    @property
    def total_usage_display(self) -> str:
        return f"↓ {self.total_download_display} / ↑ {self.total_upload_display}"


@dataclass(frozen=True)
class DeviceTrafficSnapshot:
    """Immutable snapshot delivered to GUI views and persistence layers."""
    mac: str
    rx_bytes_total: int
    tx_bytes_total: int
    rx_packets_total: int
    tx_packets_total: int
    rx_rate_bps: float
    tx_rate_bps: float
    total_rate_bps: float
    monitoring_mode: TrafficMonitoringMode
    last_activity: Optional[datetime]

    @property
    def download_rate_display(self) -> str:
        return format_rate(self.rx_rate_bps)

    @property
    def upload_rate_display(self) -> str:
        return format_rate(self.tx_rate_bps)

    @property
    def total_download_display(self) -> str:
        return format_bytes(self.rx_bytes_total)

    @property
    def total_upload_display(self) -> str:
        return format_bytes(self.tx_bytes_total)

    @property
    def total_usage_display(self) -> str:
        return f"↓ {self.total_download_display} / ↑ {self.total_upload_display}"


class TrafficAccountingService:
    """
    Central traffic accounting service.
    Collects raw metered byte counts from packet interceptors, calculates rates over
    elapsed time deltas, applies exponential smoothing, and distributes snapshots.
    """

    def __init__(self, smoothing_factor: float = 0.3):
        """
        :param smoothing_factor: Alpha for exponential moving average (0.0 to 1.0).
                                 0.0 = only previous, 1.0 = immediate raw delta rate.
        """
        self._lock = threading.RLock()
        self._records: Dict[str, DeviceTrafficRecord] = {}
        self._last_snapshot_time: float = time.monotonic()
        self._smoothing_factor: float = max(0.0, min(1.0, smoothing_factor))

    def record_traffic(
        self,
        mac: str,
        direction: TrafficDirection,
        byte_count: int,
        packet_count: int = 1,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """
        Thread-safe accumulation of metered traffic for a device.
        """
        if byte_count <= 0 or not mac:
            return

        try:
            norm_mac = normalize_mac(mac)
        except ValueError:
            return

        now = timestamp or datetime.now(timezone.utc)

        with self._lock:
            rec = self._records.get(norm_mac)
            if rec is None:
                rec = DeviceTrafficRecord(mac=norm_mac)
                self._records[norm_mac] = rec

            rec.last_activity = now

            if direction == TrafficDirection.DOWNLOAD:
                rec.rx_bytes_total += byte_count
                rec.rx_packets_total += packet_count
            elif direction == TrafficDirection.UPLOAD:
                rec.tx_bytes_total += byte_count
                rec.tx_packets_total += packet_count

    def set_monitoring_mode(self, mac: str, mode: TrafficMonitoringMode) -> None:
        """Update the active monitoring mode badge for a device."""
        try:
            norm_mac = normalize_mac(mac)
        except ValueError:
            return

        with self._lock:
            rec = self._records.get(norm_mac)
            if rec is None:
                rec = DeviceTrafficRecord(mac=norm_mac, monitoring_mode=mode)
                self._records[norm_mac] = rec
            else:
                rec.monitoring_mode = mode

    def take_snapshot(self) -> Dict[str, DeviceTrafficSnapshot]:
        """
        Calculates instantaneous rates based on elapsed time since the last snapshot,
        updates rolling history, applies smoothing, and returns an immutable snapshot dict.
        """
        now_mono = time.monotonic()
        with self._lock:
            delta_seconds = max(0.001, now_mono - self._last_snapshot_time)
            self._last_snapshot_time = now_mono

            snapshots: Dict[str, DeviceTrafficSnapshot] = {}

            for mac, rec in self._records.items():
                # Bytes transferred during this interval
                rx_delta = rec.rx_bytes_total - rec.last_rx_bytes_snapshot
                tx_delta = rec.tx_bytes_total - rec.last_tx_bytes_snapshot

                rec.last_rx_bytes_snapshot = rec.rx_bytes_total
                rec.last_tx_bytes_snapshot = rec.tx_bytes_total

                # Raw rates in bytes per second
                raw_rx_rate = rx_delta / delta_seconds
                raw_tx_rate = tx_delta / delta_seconds

                # Exponential smoothing: rate = alpha * raw + (1 - alpha) * prev_rate
                if self._smoothing_factor >= 1.0 or (rec.rx_rate_bps == 0.0 and raw_rx_rate == 0.0):
                    rec.rx_rate_bps = raw_rx_rate
                else:
                    rec.rx_rate_bps = (
                        self._smoothing_factor * raw_rx_rate
                        + (1.0 - self._smoothing_factor) * rec.rx_rate_bps
                    )

                if self._smoothing_factor >= 1.0 or (rec.tx_rate_bps == 0.0 and raw_tx_rate == 0.0):
                    rec.tx_rate_bps = raw_tx_rate
                else:
                    rec.tx_rate_bps = (
                        self._smoothing_factor * raw_tx_rate
                        + (1.0 - self._smoothing_factor) * rec.tx_rate_bps
                    )

                # Clamp very small numbers to zero for clean UI display
                if rec.rx_rate_bps < 1.0:
                    rec.rx_rate_bps = 0.0
                if rec.tx_rate_bps < 1.0:
                    rec.tx_rate_bps = 0.0

                # Record sample in history
                rec.history.append(
                    TrafficSample(
                        timestamp=now_mono,
                        rx_rate_bps=rec.rx_rate_bps,
                        tx_rate_bps=rec.tx_rate_bps,
                    )
                )

                snapshots[mac] = DeviceTrafficSnapshot(
                    mac=rec.mac,
                    rx_bytes_total=rec.rx_bytes_total,
                    tx_bytes_total=rec.tx_bytes_total,
                    rx_packets_total=rec.rx_packets_total,
                    tx_packets_total=rec.tx_packets_total,
                    rx_rate_bps=rec.rx_rate_bps,
                    tx_rate_bps=rec.tx_rate_bps,
                    total_rate_bps=rec.total_rate_bps,
                    monitoring_mode=rec.monitoring_mode,
                    last_activity=rec.last_activity,
                )

            return snapshots

    def get_snapshot(self, mac: str) -> Optional[DeviceTrafficSnapshot]:
        try:
            norm_mac = normalize_mac(mac)
        except ValueError:
            return None

        with self._lock:
            rec = self._records.get(norm_mac)
            if not rec:
                return None
            return DeviceTrafficSnapshot(
                mac=rec.mac,
                rx_bytes_total=rec.rx_bytes_total,
                tx_bytes_total=rec.tx_bytes_total,
                rx_packets_total=rec.rx_packets_total,
                tx_packets_total=rec.tx_packets_total,
                rx_rate_bps=rec.rx_rate_bps,
                tx_rate_bps=rec.tx_rate_bps,
                total_rate_bps=rec.total_rate_bps,
                monitoring_mode=rec.monitoring_mode,
                last_activity=rec.last_activity,
            )

    def get_history(self, mac: str) -> List[TrafficSample]:
        try:
            norm_mac = normalize_mac(mac)
        except ValueError:
            return []

        with self._lock:
            rec = self._records.get(norm_mac)
            return list(rec.history) if rec else []

    def reset_all(self) -> None:
        """Reset all counters and rate records."""
        with self._lock:
            self._records.clear()
            self._last_snapshot_time = time.monotonic()


# Global singleton instance for easy cross-module access
_global_traffic_accounting = TrafficAccountingService()


def get_traffic_accounting_service() -> TrafficAccountingService:
    return _global_traffic_accounting
