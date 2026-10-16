"""
Renders and captures verified PNG screenshots of Home Net Controller (HNC) PySide6 desktop views.
Always enforces an isolated synthetic database with RFC 5737 demo data to guarantee privacy.
"""
from __future__ import annotations

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from PySide6.QtCore import QSize, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QApplication

from netcutter.ui_qt.app_window import NetCutterMainWindow
from netcutter.ui_qt.theme import Theme
from netcutter.persistence.database import Database
from netcutter.persistence.repository import DeviceRepository, DomainBlockingRepository
from netcutter.domain.models import Device, DeviceCategory, ConfidenceLevel, DomainBlockingRule, DomainMatchType, DomainScope


def capture_views():
    tmp_dir = tempfile.mkdtemp(prefix="hnc_safe_capture_")
    os.environ["HNC_DATA_DIR"] = tmp_dir
    os.environ["NETCUTTER_DATA_DIR"] = tmp_dir
    if "QT_QPA_PLATFORM" in os.environ and os.environ.get("FORCE_OFFSCREEN", "").lower() not in ("1", "true"):
        del os.environ["QT_QPA_PLATFORM"]

    db = Database()
    dev_repo = DeviceRepository(db)
    dom_repo = DomainBlockingRepository(db)

    # Strictly synthetic RFC 5737 demonstration dataset
    demo_devices = [
        Device(
            device_guid="dev-demo-001",
            display_name="Demo-Windows-PC",
            primary_mac="02:00:00:11:22:33",
            ipv4_addresses=["192.0.2.10"],
            ipv6_addresses=["2001:db8:1::10"],
            hostname="Demo-Windows-PC",
            vendor="Dell Inc.",
            category=DeviceCategory.LAPTOP_PC,
            is_online=True,
            confidence_level=ConfidenceLevel.HIGH,
            is_randomized_mac=False,
            classification_basis="DHCP hostname pattern (Windows PC)",
        ),
        Device(
            device_guid="dev-demo-002",
            display_name="Demo-Smartphone",
            primary_mac="02:00:00:44:55:66",
            ipv4_addresses=["192.0.2.20"],
            ipv6_addresses=["2001:db8:1::20"],
            hostname="Demo-Smartphone",
            vendor="Apple Inc.",
            category=DeviceCategory.SMARTPHONE,
            is_online=True,
            confidence_level=ConfidenceLevel.HIGH,
            is_randomized_mac=False,
            classification_basis="DHCP hostname pattern (Smartphone)",
        ),
        Device(
            device_guid="dev-demo-003",
            display_name="Demo-Smart-TV",
            primary_mac="02:00:00:77:88:99",
            ipv4_addresses=["192.0.2.30"],
            hostname="Demo-Smart-TV",
            vendor="Samsung Electronics",
            category=DeviceCategory.SMART_TV,
            is_online=True,
            confidence_level=ConfidenceLevel.HIGH,
            is_randomized_mac=False,
            classification_basis="DHCP hostname pattern (Smart TV)",
        ),
        Device(
            device_guid="dev-demo-004",
            display_name="Demo-Linux-Server",
            primary_mac="02:00:00:aa:bb:cc",
            ipv4_addresses=["192.0.2.40"],
            hostname="Demo-Linux-Server",
            vendor="Hewlett Packard Enterprise",
            category=DeviceCategory.LAPTOP_PC,
            is_online=True,
            confidence_level=ConfidenceLevel.HIGH,
            is_randomized_mac=False,
            classification_basis="DHCP hostname pattern (Linux Server)",
        ),
        Device(
            device_guid="dev-demo-005",
            display_name="Demo-IoT-Device",
            primary_mac="02:00:00:dd:ee:ff",
            ipv4_addresses=["192.0.2.50"],
            hostname="Demo-IoT-Device",
            vendor="Espressif Systems",
            category=DeviceCategory.IOT_DEVICE,
            is_online=True,
            confidence_level=ConfidenceLevel.HIGH,
            is_randomized_mac=False,
            classification_basis="DHCP hostname pattern (IoT Device)",
        ),
    ]

    for d in demo_devices:
        dev_repo.upsert(d)

    dom_repo.upsert_rule(DomainBlockingRule(
        rule_id="rule-demo-001",
        domain="example-ad-tracker.com",
        match_type=DomainMatchType.SUBDOMAIN,
        target_scope=DomainScope.GLOBAL,
        is_enabled=True,
        enforcement_status="Active",
    ))

    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(Theme.get_stylesheet())

    output_dir = Path(__file__).parent.parent / "docs" / "screenshots"
    output_dir.mkdir(parents=True, exist_ok=True)

    window = NetCutterMainWindow()
    window.resize(1380, 840)
    window.show()
    app.processEvents()

    # Stop background timers so they don't overwrite DB during capture
    if hasattr(window, "poll_timer") and window.poll_timer.isActive():
        window.poll_timer.stop()
    if hasattr(window, "discovery_timer") and window.discovery_timer.isActive():
        window.discovery_timer.stop()

    window._refresh_all_views()
    app.processEvents()

    pages = [
        ("dashboard", "dashboard.png", "hnc_demo_dashboard_v001.png"),
        ("devices", "devices.png", "hnc_demo_devices_v001.png"),
        ("activity", "activity.png", "hnc_demo_activity_v001.png"),
        ("domains", "domains.png", "hnc_demo_domains_v001.png"),
        ("more", "more_hub.png", "hnc_demo_more_hub_v001.png"),
        ("subtab:gateways", "gateways.png", "hnc_demo_gateways_v001.png"),
        ("subtab:about", "about.png", "hnc_demo_about_v001.png"),
    ]

    for page_id, fn1, fn2 in pages:
        if page_id.startswith("subtab:"):
            subtab = page_id.split(":", 1)[1]
            window.switch_page("more")
            if "more" in window.views and hasattr(window.views["more"], "switch_subtab"):
                window.views["more"].switch_subtab(subtab)
        else:
            window.switch_page(page_id)

        # Reset horizontal scroll on active table if present
        curr_view = window.stack.currentWidget()
        if hasattr(curr_view, "table"):
            curr_view.table.horizontalScrollBar().setValue(0)
            curr_view.table.verticalScrollBar().setValue(0)

        app.processEvents()
        pixmap = window.grab()
        pixmap.save(str(output_dir / fn1), "PNG")
        pixmap.save(str(output_dir / fn2), "PNG")
        print(f"Captured {page_id} view -> {fn1} and {fn2}")

    window.close()
    shutil.rmtree(tmp_dir, ignore_errors=True)
    print("All screenshots successfully captured.")


if __name__ == "__main__":
    capture_views()
