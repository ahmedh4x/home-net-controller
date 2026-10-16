"""
Unit Tests for TrafficAccountingService (adapted from LANtern-Control).
"""
import time

from netcutter.domain.models import format_bytes, format_rate
from netcutter.services.traffic_accounting import (
    DeviceTrafficSnapshot,
    TrafficAccountingService,
    TrafficDirection,
    TrafficMonitoringMode,
)


def test_rate_and_byte_formatting():
    assert format_rate(0.0) == "0 B/s"
    assert format_rate(450.0) == "450 B/s"
    assert format_rate(1500.0) == "1.5 KB/s"
    assert format_rate(2_500_000.0) == "2.5 MB/s"

    assert format_bytes(0) == "0 B"
    assert format_bytes(512) == "512 B"
    assert format_bytes(2048) == "2.0 KB"
    assert format_bytes(15_000_000) == "15.0 MB"
    assert format_bytes(2_400_000_000) == "2.40 GB"


def test_traffic_accounting_accumulation():
    service = TrafficAccountingService(smoothing_factor=1.0)
    mac = "aa:bb:cc:dd:ee:ff"

    # Record 1000 bytes download and 500 bytes upload
    service.record_traffic(mac, TrafficDirection.DOWNLOAD, 1000)
    service.record_traffic(mac, TrafficDirection.UPLOAD, 500)

    # Initial snapshot
    time.sleep(0.05)
    snapshots = service.take_snapshot()
    assert mac in snapshots

    snap = snapshots[mac]
    assert snap.rx_bytes_total == 1000
    assert snap.tx_bytes_total == 500
    assert snap.rx_packets_total == 1
    assert snap.tx_packets_total == 1
    assert snap.rx_rate_bps > 0
    assert snap.tx_rate_bps > 0
    assert snap.total_rate_bps == snap.rx_rate_bps + snap.tx_rate_bps
    assert "KB" in snap.total_download_display or "B" in snap.total_download_display


def test_traffic_accounting_idle_rate_drop():
    service = TrafficAccountingService(smoothing_factor=1.0)
    mac = "11:22:33:44:55:66"

    # Record traffic
    service.record_traffic(mac, TrafficDirection.DOWNLOAD, 5000)
    time.sleep(0.02)
    service.take_snapshot()

    # Now idle (no new traffic recorded)
    time.sleep(0.02)
    snap2 = service.take_snapshot()[mac]
    # Total bytes should remain preserved
    assert snap2.rx_bytes_total == 5000
    # Rate should drop to 0
    assert snap2.rx_rate_bps == 0.0


def test_traffic_monitoring_mode_update():
    service = TrafficAccountingService()
    mac = "02:00:00:00:15:4d"

    service.set_monitoring_mode(mac, TrafficMonitoringMode.ACTIVE_METERING)
    snap = service.get_snapshot(mac)
    assert snap is not None
    assert snap.monitoring_mode == TrafficMonitoringMode.ACTIVE_METERING

    service.set_monitoring_mode(mac, TrafficMonitoringMode.OFFPATH_LIMITED)
    snap = service.get_snapshot(mac)
    assert snap.monitoring_mode == TrafficMonitoringMode.OFFPATH_LIMITED


def test_invalid_mac_handling():
    service = TrafficAccountingService()
    service.record_traffic("invalid-mac", TrafficDirection.DOWNLOAD, 500)
    assert len(service.take_snapshot()) == 0
    assert service.get_snapshot("invalid-mac") is None
