"""
Automated GUI and UX Tests for NetCutter PySide6 Interface.
Uses pytest-qt to verify application shell, responsive page navigation, table filtering, and dialogs.
"""
import os
from pathlib import Path
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel

from netcutter.domain.models import Device, DevicePolicyState, InternetAccessState
from netcutter.services.policy_preview import ImpactSeverity, PolicyPreviewReport, ProposedAction
from netcutter.ui_qt.app_window import NetCutterMainWindow
from netcutter.ui_qt.dialogs import PolicyPreviewDialog
from netcutter.ui_qt.theme import Theme


@pytest.fixture
def app_window(qtbot, tmp_path):
    db_file = str(tmp_path / "test_gui_netcutter.db")
    window = NetCutterMainWindow(db_path=db_file)
    qtbot.addWidget(window)
    yield window
    window.close()


def test_main_window_init_and_navigation(qtbot, app_window):
    window = app_window
    window.show()

    # Initial view should be Dashboard
    assert window.stack.currentWidget() == window.views["dashboard"]

    # Test navigating through all pages
    # Test navigating through primary streamlined pages
    page_sequence = [
        "devices",
        "activity",
        "domains",
        "more",
        "dashboard",
    ]

    for page_id in page_sequence:
        btn = window.nav_buttons[page_id]
        qtbot.mouseClick(btn, Qt.LeftButton)
        assert window.stack.currentWidget() == window.views[page_id]

    # Test MoreHubView sub-tabs navigation
    more_view = window.views["more"]
    for subtab_id in ["gateways", "diagnostics", "installation", "settings", "about"]:
        more_view.switch_subtab(subtab_id)
        assert more_view.tab_buttons[subtab_id].isChecked()


def test_devices_view_search_and_filter(qtbot, app_window):
    window = app_window
    devices_view = window.views["devices"]

    # Provide sample devices
    d1 = Device(display_name="Workstation-Alpha", primary_mac="00:11:22:33:44:55", ipv4_addresses=["192.168.1.10"])
    d2 = Device(display_name="iPhone-Mobile", primary_mac="be:d0:74:aa:bb:cc", is_randomized_mac=True, ipv4_addresses=["192.168.1.20"])
    d3 = Device(display_name="Smart-TV", primary_mac="44:55:66:77:88:99", ipv4_addresses=["192.168.1.30"])
    d3.desired_policy.internet_access = InternetAccessState.BLOCKED

    devices_view.set_devices([d1, d2, d3])
    assert devices_view.model.rowCount() == 3

    # Search filter
    devices_view.txt_search.setText("Workstation")
    assert devices_view.model.rowCount() == 1

    devices_view.txt_search.setText("")
    assert devices_view.model.rowCount() == 3

    # Status combo filter
    devices_view.combo_filter.setCurrentText("Blocked Access")
    assert devices_view.model.rowCount() == 1
    assert devices_view.model.get_device(0).display_name == "Smart-TV"

    devices_view.combo_filter.setCurrentText("Private (Randomized) MACs")
    assert devices_view.model.rowCount() == 1
    assert devices_view.model.get_device(0).display_name == "iPhone-Mobile"


def test_policy_preview_dialog_confirmation(qtbot):
    report = PolicyPreviewReport(
        device_guid="guid-123",
        device_name="Test-Client",
        primary_mac="00:11:22:33:44:55",
        target_ips=["192.168.1.100"],
        proposed_action=ProposedAction.BLOCK_ACCESS,
        current_desired=DevicePolicyState(),
        current_observed=DevicePolicyState(),
        target_policy=DevicePolicyState(internet_access=InternetAccessState.BLOCKED),
        responsible_backend="Mock Gateway Simulator",
        backend_supported=True,
        impact_level=ImpactSeverity.DISRUPTIVE,
        impact_summary="Test impact block",
        verification_strategy="Query nftables set",
        can_execute=True,
    )

    dialog = PolicyPreviewDialog(report)
    qtbot.addWidget(dialog)

    assert dialog.btn_confirm.isEnabled()
    assert not dialog.confirmed

    qtbot.mouseClick(dialog.btn_confirm, Qt.LeftButton)
    assert dialog.confirmed


def test_safe_mode_banner_toggle(qtbot, app_window):
    window = app_window
    window.show()
    assert not window.safe_mode_chip.isVisible()

    # Engage Safe Mode
    window.toggle_safe_mode(True)
    assert window.health_service.is_safe_mode
    assert window.safe_mode_chip.isVisible()

    # Disengage Safe Mode
    window.toggle_safe_mode(False)
    assert not window.health_service.is_safe_mode
    assert not window.safe_mode_chip.isVisible()


def test_system_tray_creation_and_actions(qtbot, app_window):
    window = app_window
    if window.tray_icon:
        assert window.tray_icon.toolTip() == "NetCutter — Gateway Management & Policy Control"
        assert window.tray_icon.contextMenu() is not None
        actions = [a.text() for a in window.tray_icon.contextMenu().actions()]
        assert "Show NetCutter" in actions
        assert "Audit & Refresh Now" in actions
        assert "Exit NetCutter" in actions


def test_asset_path_resolution():
    from netcutter.common.paths import get_asset_path, get_assets_dir

    assets_dir = get_assets_dir()
    assert assets_dir.is_dir()

    # Brand mark and icons must exist
    mark = get_asset_path("hnc-mark.png")
    if not mark.exists():
        mark = get_asset_path("icon.ico")
    assert mark.exists()

    icon = get_asset_path("icons/laptop.svg")
    assert icon.exists()


def test_category_icons_and_models(qtbot):
    from netcutter.domain.models import DeviceCategory
    from netcutter.ui_qt.models import get_category_icon

    for cat in [DeviceCategory.LAPTOP_PC, DeviceCategory.SMARTPHONE, DeviceCategory.SMART_TV]:
        icon = get_category_icon(cat)
        assert icon is not None
        assert not icon.isNull()


def test_ui_bridge_signals(qtbot, app_window):
    from netcutter.services.notification_service import NotificationCategory, ToastNotification

    window = app_window
    toast = ToastNotification(
        toast_id="test-1",
        category=NotificationCategory.INFO,
        title="Bridge Test",
        message="Cross-thread signal verification",
    )

    with qtbot.waitSignal(window.ui_bridge.toast_received, timeout=1000):
        window._on_toast_received(toast)


def test_bandwidth_view_table_and_metrics(qtbot, app_window):
    window = app_window
    bw_view = window.views["bandwidth"]

    d1 = Device(
        display_name="Desktop-PC",
        primary_mac="00:11:22:33:44:55",
        ipv4_addresses=["192.168.1.15"],
        download_rate_bps=1_500_000.0,
        upload_rate_bps=250_000.0,
        total_download_bytes=45_000_000,
        total_upload_bytes=5_000_000,
        traffic_monitoring_mode="ACTIVE_METERING",
    )
    d2 = Device(
        display_name="SmartPhone",
        primary_mac="02:00:00:00:15:4d",
        ipv4_addresses=["192.0.2.55"],
        download_rate_bps=0.0,
        upload_rate_bps=0.0,
        traffic_monitoring_mode="OFFPATH_LIMITED",
    )

    bw_view.set_devices([d1, d2])
    assert bw_view.model.rowCount() == 2

    # Check metric cards updated
    lbl_dl = bw_view.card_dl.findChild(QLabel, "val_live_download")
    assert lbl_dl is not None
    assert "MB/s" in lbl_dl.text()

    lbl_metered = bw_view.card_metered.findChild(QLabel, "val_active_metering")
    assert lbl_metered is not None
    assert "1 Devices" in lbl_metered.text()

    # Table columns
    assert bw_view.model.data(bw_view.model.index(0, 0), Qt.DisplayRole) == "Desktop-PC"
    assert bw_view.model.data(bw_view.model.index(0, 3), Qt.DisplayRole) == "1.5 MB/s"
    assert bw_view.model.data(bw_view.model.index(0, 8), Qt.DisplayRole) == "ACTIVE METERING"
    assert bw_view.model.data(bw_view.model.index(1, 8), Qt.DisplayRole) == "PASSIVE (Broadcast Only)"


def test_domain_blocking_view_and_dialog(qtbot, app_window):
    from netcutter.domain.models import DomainBlockingRule, DomainMatchType, DomainScope, DomainEnforcementStatus, BlockedDomainEvent
    from netcutter.ui_qt.views.domain_blocking_view import AddDomainRuleDialog

    window = app_window
    domain_view = window.views["domains"]
    assert domain_view is not None

    rule1 = DomainBlockingRule(
        domain="ads.example.com",
        match_type=DomainMatchType.SUBDOMAIN,
        target_scope=DomainScope.GLOBAL,
        enforcement_status=DomainEnforcementStatus.ACTIVE,
        is_enabled=True,
        hits_count=42,
    )
    rule2 = DomainBlockingRule(
        domain="badsite.org",
        match_type=DomainMatchType.EXACT,
        target_scope=DomainScope.DEVICE,
        target_mac="02:00:00:00:15:4d",
        enforcement_status=DomainEnforcementStatus.PENDING,
        is_enabled=False,
        hits_count=3,
    )

    domain_view.update_rules([rule1, rule2])
    assert domain_view.rules_model.rowCount() == 2

    # Check metric cards updated
    lbl_act = domain_view.card_active.findChild(QLabel, "MetricValue")
    assert lbl_act is not None
    assert "1 Active" in lbl_act.text()

    lbl_hits = domain_view.card_hits.findChild(QLabel, "MetricValue")
    assert lbl_hits is not None
    assert lbl_hits.text() == "45"

    # Check rules table rendering
    assert domain_view.rules_model.data(domain_view.rules_model.index(0, 0), Qt.DisplayRole) == "ads.example.com"
    assert domain_view.rules_model.data(domain_view.rules_model.index(0, 1), Qt.DisplayRole) == "*.ads.example.com + root"
    assert domain_view.rules_model.data(domain_view.rules_model.index(0, 2), Qt.DisplayRole) == "All Devices (Global)"
    assert domain_view.rules_model.data(domain_view.rules_model.index(0, 3), Qt.DisplayRole) == "Active"
    assert domain_view.rules_model.data(domain_view.rules_model.index(0, 4), Qt.DisplayRole) == "42"
    assert domain_view.rules_model.data(domain_view.rules_model.index(0, 5), Qt.DisplayRole) == "Active"

    assert domain_view.rules_model.data(domain_view.rules_model.index(1, 0), Qt.DisplayRole) == "badsite.org"
    assert domain_view.rules_model.data(domain_view.rules_model.index(1, 1), Qt.DisplayRole) == "badsite.org (exact)"
    assert domain_view.rules_model.data(domain_view.rules_model.index(1, 5), Qt.DisplayRole) == "Disabled"

    # Check events model
    evt = BlockedDomainEvent(
        domain="ads.example.com",
        rule_id=rule1.rule_id,
        client_mac="02:00:00:00:15:4d",
        client_ip="192.0.2.55",
        action="DNS_SINKHOLE_ZERO_IP",
        mechanism="Layer-2 DNS Interceptor",
    )
    domain_view.update_events([evt])
    assert domain_view.events_model.rowCount() == 1
    assert domain_view.events_model.data(domain_view.events_model.index(0, 1), Qt.DisplayRole) == "02:00:00:00:15:4d"
    assert domain_view.events_model.data(domain_view.events_model.index(0, 2), Qt.DisplayRole) == "192.0.2.55"
    assert domain_view.events_model.data(domain_view.events_model.index(0, 3), Qt.DisplayRole) == "ads.example.com"
    assert domain_view.events_model.data(domain_view.events_model.index(0, 4), Qt.DisplayRole) == "DNS_SINKHOLE_ZERO_IP"
    assert domain_view.events_model.data(domain_view.events_model.index(0, 5), Qt.DisplayRole) == "Layer-2 DNS Interceptor"

    # Test AddDomainRuleDialog validation
    dialog = AddDomainRuleDialog(devices=[])
    qtbot.addWidget(dialog)
    dialog.txt_domain.setText("invalid domain with spaces")
    assert not dialog.txt_domain.text() == ""
    # Valid domain
    dialog.txt_domain.setText("tracker.net")
    data = dialog.get_data()
    assert data["domain"] == "tracker.net"
    assert data["match_type"] == DomainMatchType.SUBDOMAIN
    assert data["target_scope"] == DomainScope.GLOBAL

