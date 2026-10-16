"""
Main Desktop Application Window for NetCutter (Qt 6 / PySide6).
Orchestrates sidebar navigation, responsive header bar, non-blocking background workers,
floating toast notifications, and policy preview confirmations.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QObject, QRunnable, QSize, Qt, QThreadPool, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)
import shiboken6

from netcutter.backends.capabilities import format_capabilities_report
from netcutter.common.crash_handler import install_crash_handler
from netcutter.common.logging import (
    generate_support_bundle,
    get_ring_buffer,
    setup_application_logging,
)
from netcutter.common.paths import get_asset_path
from netcutter.diagnostics.health import DiagnosticsService
from netcutter.domain.models import BackendType, Device, GatewayConfig, GatewayStatus
from netcutter.domain.state_engine import NetworkStateEngine
from netcutter.persistence.database import Database
from netcutter.persistence.repository import (
    AuditRepository,
    DeviceRepository,
    GatewayRepository,
    NotificationRepository,
)
from netcutter.persistence.secret_store import SecretStore
from netcutter.services.audit_service import AuditService
from netcutter.services.device_service import DeviceService
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.health_service import HealthMonitoringService
from netcutter.services.identity_engine import IdentityEngine
from netcutter.services.notification_service import (
    NotificationCategory,
    NotificationService,
    ToastNotification,
)
from netcutter.services.policy_preview import PolicyPreviewEngine
from netcutter.services.policy_service import PolicyService
from netcutter.services.reconciliation import ReconciliationEngine
from netcutter.ui_qt.components import StatusBadge, ToastContainer
from netcutter.ui_qt.dialogs import (
    BandwidthDialog,
    GatewayConfigDialog,
    PolicyPreviewDialog,
)
from netcutter.services.domain_blocking_service import DomainBlockingService
from netcutter.services.installation_service import InstallationService
from netcutter.ui_qt.theme import Theme
from netcutter.ui_qt.views.about_view import AboutView
from netcutter.ui_qt.views.activity_view import ActivityView
from netcutter.ui_qt.views.bandwidth_view import BandwidthView
from netcutter.ui_qt.views.dashboard_view import DashboardView
from netcutter.ui_qt.views.device_details_view import DeviceDetailsView
from netcutter.ui_qt.views.devices_view import DevicesView
from netcutter.ui_qt.views.diagnostics_view import DiagnosticsView
from netcutter.ui_qt.views.domain_blocking_view import DomainBlockingView
from netcutter.ui_qt.views.gateways_view import GatewaysView
from netcutter.ui_qt.views.installation_view import InstallationView
from netcutter.ui_qt.views.more_view import MoreHubView
from netcutter.ui_qt.views.notifications_view import NotificationsView
from netcutter.ui_qt.views.policies_view import PoliciesView
from netcutter.ui_qt.views.settings_view import SettingsView

logger = logging.getLogger("netcutter.app")


class UiBridge(QObject):
    """Thread-safe signal bridge for cross-thread GUI events and notifications."""
    toast_received = Signal(object)
    log_emitted = Signal(object)


class WorkerSignals(QObject):
    finished = Signal(object)
    error = Signal(str)


class FunctionWorker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    def run(self):
        try:
            res = self.fn(*self.args, **self.kwargs)
            try:
                self.signals.finished.emit(res)
            except (RuntimeError, AttributeError):
                pass
        except Exception as ex:
            try:
                self.signals.error.emit(str(ex))
            except (RuntimeError, AttributeError):
                pass


class NetCutterMainWindow(QMainWindow):
    """Authoritative PySide6 Desktop Shell for NetCutter."""

    def __init__(self, db_path: Optional[str] = None):
        super().__init__()
        self.setWindowTitle("Home Net Controller — Your Home Network. Under Your Control.")
        mark_path = get_asset_path("hnc-mark.png")
        if not mark_path.exists():
            mark_path = get_asset_path("netcutter-mark.png")
        if not mark_path.exists():
            mark_path = get_asset_path("icon.ico")
        if mark_path.exists():
            self.setWindowIcon(QIcon(str(mark_path)))
        self.resize(1280, 820)
        self.setMinimumSize(1024, 640)

        # 1. Initialize Logging, Crash Handler, Database & Core Services
        setup_application_logging()
        install_crash_handler()
        self.db = Database(db_path)
        self.secret_store = SecretStore()
        self.device_repo = DeviceRepository(self.db)
        self.gw_repo = GatewayRepository(self.db)
        self.audit_repo = AuditRepository(self.db)
        self.notif_repo = NotificationRepository(self.db)

        self.notif_service = NotificationService(self.notif_repo)
        self.gw_manager = GatewayManager(self.db, self.gw_repo, self.secret_store)
        self.health_service = HealthMonitoringService(self.db, self.gw_manager)
        self.identity_engine = IdentityEngine(self.db, self.device_repo)
        self.device_service = DeviceService(self.device_repo, self.identity_engine, self.gw_manager)
        self.policy_service = PolicyService(
            self.device_repo,
            self.audit_repo,
            self.gw_manager,
            notification_service=self.notif_service,
            health_service=self.health_service,
        )
        self.audit_service = AuditService(self.audit_repo)
        self.diag_service = DiagnosticsService(self.gw_manager)
        self.install_service = InstallationService()
        self.domain_service = DomainBlockingService(
            self.db, gateway_manager=self.gw_manager, device_service=self.device_service
        )


        self.reconcile_engine = ReconciliationEngine(
            self.device_repo,
            self.audit_repo,
            self.gw_manager,
            self.policy_service,
            reconcile_interval_seconds=30,
            notification_service=self.notif_service,
            health_service=self.health_service,
        )
        self.health_service.reconciliation_engine = self.reconcile_engine

        self.threadpool = QThreadPool.globalInstance()
        self._active_workers = set()
        self.ui_bridge = UiBridge(self)
        self.ui_bridge.toast_received.connect(self._handle_toast)
        self.ui_bridge.log_emitted.connect(self._handle_log)

        # Ensure default gateway
        self._ensure_default_gateways()

        # Connect active gateway
        active_gw = self.gw_repo.get_active()
        if active_gw:
            self.gw_manager.set_active_gateway(active_gw.gateway_id)

        # 2. Build UI Layout
        self._build_ui()
        self._init_system_tray()

        # 3. Toast and Notification Subscriptions
        self.notif_service.add_toast_listener(self._on_toast_received)
        get_ring_buffer().add_listener(self._on_log_emitted)

        # 4. Periodic Discovery and Refresh Timers
        self.timer_refresh = QTimer(self)
        self.timer_refresh.timeout.connect(self._async_refresh_discovery)
        self.timer_refresh.start(15000)

        # 5. Real-Time Traffic Accounting Snapshot Timer (1.5s interval)
        self.timer_traffic = QTimer(self)
        self.timer_traffic.timeout.connect(self._update_traffic_metrics)
        self.timer_traffic.start(1500)

        # Start Reconciliation Engine
        self.reconcile_engine.start()

        # Initial Refresh
        self._async_refresh_discovery()
        self._async_run_health_checks()
        self._async_run_installation_audit()

    def _ensure_default_gateways(self):
        gws = self.gw_repo.get_all()
        has_win_lan = any(g.backend_type == BackendType.WINDOWS_LAN for g in gws)
        if not has_win_lan:
            win_lan_gw = GatewayConfig(
                gateway_id="gw-windows-lan",
                name="Windows LAN Off-Path (Local Subnet)",
                host="192.168.1.1",
                port=0,
                backend_type=BackendType.WINDOWS_LAN,
                username="",
                is_active=False,
            )
            self.gw_repo.upsert(win_lan_gw)
            gws = self.gw_repo.get_all()

        has_mock = any(g.backend_type == BackendType.MOCK for g in gws)
        if not has_mock:
            mock_gw = GatewayConfig(
                gateway_id="gw-mock-default",
                name="Simulator Gateway (Mock Mode)",
                host="127.0.0.1",
                port=22,
                backend_type=BackendType.MOCK,
                username="admin",
                is_active=True,
            )
            self.gw_repo.upsert(mock_gw)

    def _build_ui(self):
        central = QWidget(self)
        central.setObjectName("CentralWidget")
        self.setCentralWidget(central)

        main_hbox = QHBoxLayout(central)
        main_hbox.setContentsMargins(0, 0, 0, 0)
        main_hbox.setSpacing(0)

        # --- Sidebar ---
        sidebar = QFrame()
        sidebar.setObjectName("SidebarFrame")
        sidebar.setFixedWidth(230)
        s_layout = QVBoxLayout(sidebar)
        s_layout.setContentsMargins(14, 20, 14, 16)
        s_layout.setSpacing(6)

        # Brand
        brand_layout = QHBoxLayout()
        brand_layout.setSpacing(10)
        logo_path = get_asset_path("hnc-logo.svg")
        if not logo_path.exists():
            logo_path = get_asset_path("netcutter-logo.svg")
        if logo_path.exists():
            lbl_logo = QLabel()
            pix = QPixmap(str(logo_path)).scaled(26, 26, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            lbl_logo.setPixmap(pix)
            brand_layout.addWidget(lbl_logo)

        brand_text_layout = QVBoxLayout()
        brand_text_layout.setSpacing(2)
        brand_title = QLabel("HOME NET CONTROLLER")
        brand_title.setObjectName("BrandTitle")
        brand_text_layout.addWidget(brand_title)

        brand_sub = QLabel("HNC Desktop v0.0.1")
        brand_sub.setObjectName("BrandSubtitle")
        brand_text_layout.addWidget(brand_sub)

        brand_layout.addLayout(brand_text_layout)
        brand_layout.addStretch()
        s_layout.addLayout(brand_layout)
        s_layout.addSpacing(16)

        # Primary Streamlined Nav Buttons (Phase 4 Design Architecture)
        self.nav_buttons: Dict[str, QPushButton] = {}
        pages = [
            ("dashboard", "Overview", "nav_overview.svg"),
            ("devices", "Devices", "nav_devices.svg"),
            ("activity", "Live Activity", "nav_activity.svg"),
            ("domains", "Website Blocking", "nav_domains.svg"),
            ("more", "More / Settings", "nav_settings.svg"),
        ]

        for page_id, label, icon_name in pages:
            btn = QPushButton(f"  {label}")
            icon_path = get_asset_path(f"icons/{icon_name}")
            if icon_path.exists():
                btn.setIcon(QIcon(str(icon_path)))
                btn.setIconSize(QSize(18, 18))
            btn.setProperty("class", "NavButton")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, p=page_id: self.switch_page(p))
            s_layout.addWidget(btn)
            self.nav_buttons[page_id] = btn

        s_layout.addStretch()

        # Sidebar Footer
        self.lbl_sidebar_gw = QLabel("GW: Initializing...")
        self.lbl_sidebar_gw.setStyleSheet(f"font-size: 11px; color: {Theme.TEXT_SECONDARY};")
        self.lbl_sidebar_gw.setWordWrap(True)
        s_layout.addWidget(self.lbl_sidebar_gw)

        main_hbox.addWidget(sidebar)

        # --- Content Area (Header + Stacked Pages) ---
        content_vbox = QVBoxLayout()
        content_vbox.setContentsMargins(0, 0, 0, 0)
        content_vbox.setSpacing(0)

        # Header Bar
        header_bar = QFrame()
        header_bar.setObjectName("HeaderBar")
        h_layout = QHBoxLayout(header_bar)
        h_layout.setContentsMargins(20, 10, 20, 10)

        self.lbl_header_gw = QLabel("Active Gateway: -")
        self.lbl_header_gw.setStyleSheet("font-weight: 600; font-size: 13px; color: #ffffff;")
        h_layout.addWidget(self.lbl_header_gw)

        self.badge_header_status = StatusBadge("OFFLINE", variant="danger")
        h_layout.addWidget(self.badge_header_status)

        self.safe_mode_chip = StatusBadge("SAFE MODE ACTIVE", variant="warning")
        self.safe_mode_chip.setVisible(False)
        h_layout.addWidget(self.safe_mode_chip)

        h_layout.addStretch()

        self.lbl_last_sync = QLabel("Last Sync: Never")
        self.lbl_last_sync.setStyleSheet(f"color: {Theme.TEXT_MUTED}; font-size: 12px; margin-right: 12px;")
        h_layout.addWidget(self.lbl_last_sync)

        self.btn_notif_bell = QPushButton("Notifications (0)")
        self.btn_notif_bell.setStyleSheet(f"padding: 5px 12px; font-size: 12px; background-color: {Theme.BG_CARD};")
        self.btn_notif_bell.clicked.connect(lambda: self.switch_page("notifications"))
        h_layout.addWidget(self.btn_notif_bell)

        content_vbox.addWidget(header_bar)

        # Simulator / Demo Mode Notice Banner
        self.simulator_banner = QFrame()
        self.simulator_banner.setObjectName("SimulatorBanner")
        self.simulator_banner.setStyleSheet(f"""
            QFrame#SimulatorBanner {{
                background-color: #2b1f14;
                border-bottom: 1px solid #7c4a1e;
            }}
        """)
        sim_layout = QHBoxLayout(self.simulator_banner)
        sim_layout.setContentsMargins(20, 6, 20, 6)
        sim_layout.setSpacing(12)

        lbl_sim_icon = QLabel("⚠️")
        lbl_sim_icon.setStyleSheet("font-size: 15px;")
        sim_layout.addWidget(lbl_sim_icon)

        lbl_sim_text = QLabel(
            "<b>SIMULATOR MODE ACTIVE:</b> Displaying synthetic demo clients. "
            "Switch to Windows LAN or configure a router gateway to discover real physical devices."
        )
        lbl_sim_text.setStyleSheet("font-size: 12px; color: #ffb86c;")
        lbl_sim_text.setWordWrap(True)
        sim_layout.addWidget(lbl_sim_text, stretch=1)

        btn_switch_lan = QPushButton("Switch to Windows LAN")
        btn_switch_lan.setStyleSheet(f"background-color: {Theme.CYAN}; color: #000000; font-weight: 600; font-size: 11px; padding: 4px 12px; border-radius: 4px;")
        btn_switch_lan.clicked.connect(self._switch_to_windows_lan)
        sim_layout.addWidget(btn_switch_lan)

        btn_setup_gw = QPushButton("Configure Router")
        btn_setup_gw.setStyleSheet(f"background-color: {Theme.BG_HOVER}; color: {Theme.TEXT_PRIMARY}; font-size: 11px; padding: 4px 12px; border-radius: 4px; border: 1px solid {Theme.BORDER_DEFAULT};")
        btn_setup_gw.clicked.connect(lambda: self.switch_page("gateways"))
        sim_layout.addWidget(btn_setup_gw)

        content_vbox.addWidget(self.simulator_banner)

        # Stacked Pages
        self.stack = QStackedWidget()
        self.views = {}

        # 1. Dashboard
        self.views["dashboard"] = DashboardView(self)
        self.views["dashboard"].refresh_requested.connect(self._async_refresh_discovery)
        self.views["dashboard"].reconcile_requested.connect(self._async_reconcile)
        self.views["dashboard"].diagnostics_requested.connect(self._async_run_health_checks)
        self.views["dashboard"].open_device_requested.connect(self.open_device_details)
        self.stack.addWidget(self.views["dashboard"])

        # 2. Devices
        self.views["devices"] = DevicesView(self)
        self.views["devices"].open_device_requested.connect(self.open_device_details)
        self.views["devices"].block_requested.connect(self.confirm_block_device)
        self.views["devices"].unblock_requested.connect(self.unblock_device)
        self.views["devices"].set_bandwidth_requested.connect(self.open_bandwidth_dialog)
        self.views["devices"].refresh_requested.connect(self._async_refresh_discovery)
        self.stack.addWidget(self.views["devices"])

        # 3. Device Details
        self.views["device_details"] = DeviceDetailsView(self)
        self.views["device_details"].back_requested.connect(lambda: self.switch_page("devices"))
        self.views["device_details"].block_requested.connect(self.confirm_block_device)
        self.views["device_details"].unblock_requested.connect(self.unblock_device)
        self.views["device_details"].set_bandwidth_requested.connect(self.open_bandwidth_dialog)
        self.views["device_details"].rename_requested.connect(self.rename_device)
        self.stack.addWidget(self.views["device_details"])

        # 4. Policies
        self.views["policies"] = PoliciesView(self)
        self.views["policies"].reconcile_requested.connect(self._async_reconcile)
        self.views["policies"].open_device_requested.connect(self.open_device_details)
        self.stack.addWidget(self.views["policies"])

        # 5. Bandwidth (Preserved for backwards-compatibility)
        self.views["bandwidth"] = BandwidthView(self)
        self.views["bandwidth"].set_bandwidth_requested.connect(self.open_bandwidth_dialog)
        self.views["bandwidth"].open_device_requested.connect(self.open_device_details)
        self.views["bandwidth"].start_metering_requested.connect(self._async_start_metering)
        self.views["bandwidth"].stop_metering_requested.connect(self._async_stop_metering)
        self.stack.addWidget(self.views["bandwidth"])

        # 5b. Unified Real-Time Activity & Telemetry View
        self.views["activity"] = ActivityView(self)
        self.views["activity"].set_bandwidth_requested.connect(self.open_bandwidth_dialog)
        self.views["activity"].open_device_requested.connect(self.open_device_details)
        self.views["activity"].start_metering_requested.connect(self._async_start_metering)
        self.views["activity"].stop_metering_requested.connect(self._async_stop_metering)
        self.views["activity"].refresh_requested.connect(self._async_refresh_discovery)
        self.stack.addWidget(self.views["activity"])

        # 6. Website & Domain Blocking
        self.views["domains"] = DomainBlockingView(self)
        self.views["domains"].add_rule_requested.connect(self._on_add_domain_rule)
        self.views["domains"].toggle_rule_requested.connect(self._on_toggle_domain_rule)
        self.views["domains"].delete_rule_requested.connect(self._on_delete_domain_rule)
        self.views["domains"].verify_rules_requested.connect(self._on_verify_domain_rules)
        self.views["domains"].clear_events_requested.connect(self._on_clear_domain_events)
        self.views["domains"].refresh_requested.connect(self._refresh_domain_blocking_view)
        self.stack.addWidget(self.views["domains"])

        # 7. Gateways
        self.views["gateways"] = GatewaysView(self)
        self.views["gateways"].add_gw_requested.connect(self.open_add_gateway_dialog)
        self.views["gateways"].edit_gw_requested.connect(self.open_edit_gateway_dialog)
        self.views["gateways"].delete_gw_requested.connect(self.delete_gateway)
        self.views["gateways"].activate_gw_requested.connect(self.activate_gateway)
        self.views["gateways"].test_gw_requested.connect(self.test_gateway)
        self.stack.addWidget(self.views["gateways"])

        # 8. Notifications
        self.views["notifications"] = NotificationsView(self)
        self.views["notifications"].mark_all_read_requested.connect(self.mark_all_notifications_read)
        self.views["notifications"].clear_requested.connect(self.clear_notifications)
        self.stack.addWidget(self.views["notifications"])

        # 9. Diagnostics
        self.views["diagnostics"] = DiagnosticsView(self)
        self.views["diagnostics"].run_diagnostics_requested.connect(self._async_run_health_checks)
        self.views["diagnostics"].export_bundle_requested.connect(self.export_support_bundle)
        self.views["diagnostics"].clear_logs_requested.connect(lambda: get_ring_buffer().clear())
        self.stack.addWidget(self.views["diagnostics"])

        # 10. Installation & System Readiness Center
        self.views["installation"] = InstallationView(self)
        self.views["installation"].verify_requested.connect(self._async_run_installation_audit)
        self.views["installation"].repair_requested.connect(self._async_repair_dependency)
        self.views["installation"].relaunch_elevated_requested.connect(self._relaunch_as_admin)
        self.views["installation"].export_diagnostics_requested.connect(self._export_installation_diagnostics)
        self.views["installation"].switch_to_gateways_requested.connect(lambda: self.switch_page("gateways"))
        self.stack.addWidget(self.views["installation"])

        # 11. Settings
        self.views["settings"] = SettingsView(self)
        self.views["settings"].save_settings_requested.connect(self.save_settings)
        self.views["settings"].safe_mode_toggled.connect(self.toggle_safe_mode)
        self.views["settings"].inject_fault_requested.connect(self.inject_simulation_fault)
        self.stack.addWidget(self.views["settings"])

        # 12. About
        self.views["about"] = AboutView(self)
        self.stack.addWidget(self.views["about"])

        # 13. Consolidated More / Settings Hub
        self.views["more"] = MoreHubView(
            gateways_view=self.views["gateways"],
            diagnostics_view=self.views["diagnostics"],
            installation_view=self.views["installation"],
            settings_view=self.views["settings"],
            about_view=self.views["about"],
            parent=self,
        )
        self.stack.addWidget(self.views["more"])

        content_vbox.addWidget(self.stack)
        main_hbox.addLayout(content_vbox)

        # Toast Overlay
        self.toast_container = ToastContainer(self)

        # Show Dashboard initially
        self.switch_page("dashboard")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.toast_container.reposition()

    def switch_page(self, page_id: str):
        if page_id in self.views:
            self.stack.setCurrentWidget(self.views[page_id])
            for pid, btn in self.nav_buttons.items():
                is_active = (pid == page_id)
                btn.setProperty("active", "true" if is_active else "false")
                btn.style().unpolish(btn)
                btn.style().polish(btn)
            self._refresh_all_views()

    def open_device_details(self, device_guid: str):
        dev = self.device_service.get_device_by_guid(device_guid)
        if dev:
            self.views["device_details"].load_device(dev)
            self.switch_page("device_details")

    # --- Policy Actions with Policy Preview Engine ---
    def confirm_block_device(self, device: Device):
        from netcutter.domain.models import DevicePolicyState, InternetAccessState
        target = DevicePolicyState(
            internet_access=InternetAccessState.BLOCKED,
            download_limit_kbps=device.desired_policy.download_limit_kbps,
            upload_limit_kbps=device.desired_policy.upload_limit_kbps,
        )
        report = PolicyPreviewEngine.generate_preview(
            device, target, self.gw_manager.get_active_backend(), self.gw_manager.get_active_config()
        )
        dlg = PolicyPreviewDialog(report, self)
        if dlg.exec() == PolicyPreviewDialog.Accepted and dlg.confirmed:
            self._async_execute_block(device.device_guid)

    def unblock_device(self, device_guid: str):
        dev = self.device_service.get_device_by_guid(device_guid)
        if not dev:
            return
        from netcutter.domain.models import DevicePolicyState, InternetAccessState
        target = DevicePolicyState(
            internet_access=InternetAccessState.ALLOWED,
            download_limit_kbps=dev.desired_policy.download_limit_kbps,
            upload_limit_kbps=dev.desired_policy.upload_limit_kbps,
        )
        report = PolicyPreviewEngine.generate_preview(
            dev, target, self.gw_manager.get_active_backend(), self.gw_manager.get_active_config()
        )
        dlg = PolicyPreviewDialog(report, self)
        if dlg.exec() == PolicyPreviewDialog.Accepted and dlg.confirmed:
            self._async_execute_unblock(device_guid)

    def open_bandwidth_dialog(self, device: Device):
        backend = self.gw_manager.get_active_backend()
        from netcutter.backends.capabilities import BackendCapabilities
        if backend and not (backend.capabilities & BackendCapabilities.DOWNLOAD_SHAPING):
            QMessageBox.warning(
                self,
                "Bandwidth Shaping Unsupported",
                "Bandwidth QoS shaping is NOT supported in Windows LAN Off-Path mode.\n\n"
                "Real token-bucket queueing requires in-path Gateway-Native enforcement (OpenWrt or Linux with CAKE or HTB).",
            )
            return

        def on_rates_chosen(dl_kbps: int, ul_kbps: int):
            from netcutter.domain.models import DevicePolicyState
            target = DevicePolicyState(
                internet_access=device.desired_policy.internet_access,
                download_limit_kbps=dl_kbps,
                upload_limit_kbps=ul_kbps,
            )
            report = PolicyPreviewEngine.generate_preview(
                device, target, self.gw_manager.get_active_backend(), self.gw_manager.get_active_config()
            )
            dlg = PolicyPreviewDialog(report, self)
            if dlg.exec() == PolicyPreviewDialog.Accepted and dlg.confirmed:
                self._async_execute_bandwidth(device.device_guid, dl_kbps, ul_kbps)

        dlg = BandwidthDialog(device, on_rates_chosen, self)
        dlg.exec()

    def rename_device(self, guid: str, new_name: str):
        self.device_service.update_display_name(guid, new_name)
        self.open_device_details(guid)
        self._refresh_all_views()

    # --- Gateway Management ---
    def open_add_gateway_dialog(self):
        dlg = GatewayConfigDialog(
            None,
            on_save=self._save_gateway,
            on_test=self._test_gateway_from_dialog,
            parent=self,
        )
        dlg.exec()

    def open_edit_gateway_dialog(self, gw: GatewayConfig):
        dlg = GatewayConfigDialog(
            gw,
            on_save=self._save_gateway,
            on_test=self._test_gateway_from_dialog,
            parent=self,
        )
        dlg.exec()

    def _save_gateway(self, gw: GatewayConfig, password: str):
        if password:
            import uuid
            secret_id = gw.auth_secret_id or str(uuid.uuid4())
            gw.auth_secret_id = secret_id
            self.gw_manager.save_credential(secret_id, password)
        self.gw_repo.upsert(gw)
        self._refresh_all_views()

    def _test_gateway_from_dialog(self, gw: GatewayConfig, password: str):
        worker = FunctionWorker(self.gw_manager.test_connection, gw, password)
        worker.signals.finished.connect(
            lambda res: QMessageBox.information(
                self,
                "Gateway Test Result",
                f"{'Connection Successful!' if res[0] else 'Connection Failed!'}\n\n{res[1]}",
            )
        )
        self._start_worker(worker)

    def activate_gateway(self, gw_id: str):
        worker = FunctionWorker(self.gw_manager.set_active_gateway, gw_id)
        worker.signals.finished.connect(self._after_gateway_activated)
        self._start_worker(worker)

    def _after_gateway_activated(self, res):
        ok, msg = res
        if ok:
            self.notif_service.post(NotificationCategory.SUCCESS, "Gateway Activated", msg)
            self._async_refresh_discovery()
        else:
            self.notif_service.post(NotificationCategory.ERROR, "Gateway Activation Failed", msg)
        self._refresh_all_views()

    def test_gateway(self, gw: GatewayConfig):
        worker = FunctionWorker(self.gw_manager.test_connection, gw, None)
        worker.signals.finished.connect(
            lambda res: QMessageBox.information(
                self,
                "Gateway Test Result",
                f"{'Connection Successful!' if res[0] else 'Connection Failed!'}\n\n{res[1]}",
            )
        )
        self._start_worker(worker)

    def _start_worker(self, worker: FunctionWorker):
        """Track running background worker to prevent garbage collection crashes."""
        self._active_workers.add(worker)
        worker.signals.finished.connect(lambda _: self._active_workers.discard(worker))
        worker.signals.error.connect(lambda _: self._active_workers.discard(worker))
        self.threadpool.start(worker)

    def delete_gateway(self, gw_id: str):
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM gateways WHERE gateway_id = ?", (gw_id,))
            conn.commit()
        self._refresh_all_views()

    # --- Notifications & Log Callbacks ---
    def _on_toast_received(self, toast: ToastNotification):
        self.ui_bridge.toast_received.emit(toast)

    def _on_log_emitted(self, entry):
        self.ui_bridge.log_emitted.emit(entry)

    def _handle_toast(self, toast: ToastNotification):
        self.toast_container.add_toast(toast)

    def _handle_log(self, entry):
        if self.stack.currentWidget() == self.views.get("diagnostics"):
            self.views["diagnostics"].set_logs(get_ring_buffer().get_entries())

    def mark_all_notifications_read(self):
        self.notif_service.mark_all_read()
        self._refresh_all_views()

    def clear_notifications(self):
        self.notif_service.clear()
        self._refresh_all_views()

    def export_support_bundle(self):
        dest, _ = QFileDialog.getSaveFileName(
            self, "Save Diagnostic Support Bundle", str(Path.home() / "netcutter-support-bundle.zip"), "Zip Files (*.zip)"
        )
        if dest:
            try:
                report = self.health_service.get_cached_report()
                report_dict = report.to_dict() if report else None
                bundle_path = generate_support_bundle(Path(dest), system_health_report=report_dict)
                self.notif_service.post(
                    NotificationCategory.SUCCESS,
                    "Support Bundle Exported",
                    f"Saved sanitized diagnostic bundle to: {bundle_path.name}",
                )
            except Exception as ex:
                self.notif_service.post(
                    NotificationCategory.ERROR, "Export Failed", f"Could not create bundle: {ex}"
                )

    # --- Settings & Safe Mode ---
    def save_settings(self, settings: Dict[str, str]):
        with self.db.get_connection() as conn:
            for k, v in settings.items():
                conn.execute(
                    "INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (k, v),
                )
            conn.commit()
        if "reconcile_interval" in settings and settings["reconcile_interval"].isdigit():
            self.reconcile_engine.interval = int(settings["reconcile_interval"])
        self.notif_service.post(NotificationCategory.INFO, "Settings Saved", "Preferences updated successfully.")

    def toggle_safe_mode(self, enable: bool):
        if enable:
            self.health_service.enter_safe_mode("Manual operator lockdown")
            self.notif_service.post(
                NotificationCategory.WARNING, "Safe Mode Engaged", "Disruptive mutations are now blocked."
            )
        else:
            ok, msg = self.health_service.exit_safe_mode()
            if ok:
                self.notif_service.post(NotificationCategory.SUCCESS, "Safe Mode Deactivated", msg)
            else:
                self.notif_service.post(NotificationCategory.ERROR, "Safe Mode Exit Rejected", msg)
        self._refresh_all_views()

    def inject_simulation_fault(self, fault_type: str):
        backend = self.gw_manager.get_active_backend()
        from netcutter.backends.mock_backend import MockGatewayBackend
        if not isinstance(backend, MockGatewayBackend):
            QMessageBox.warning(
                self,
                "Fault Injection Restricted",
                "Fault injection is strictly isolated and can only be applied to the Mock Gateway Simulator.",
            )
            return

        if fault_type == "timeout":
            backend.inject_fault_timeout()
            self.notif_service.post(NotificationCategory.WARNING, "Fault Injected", "Simulating router command timeout.")
        elif fault_type == "disconnect":
            backend.inject_fault_disconnect()
            self.notif_service.post(NotificationCategory.WARNING, "Fault Injected", "Simulating gateway disconnection.")
        elif fault_type == "auth":
            backend.inject_fault_auth_error()
            self.notif_service.post(NotificationCategory.WARNING, "Fault Injected", "Simulating authentication failure.")
        elif fault_type == "partial":
            backend.inject_fault_partial_failure()
            self.notif_service.post(NotificationCategory.WARNING, "Fault Injected", "Simulating partial conntrack failure.")
        elif fault_type == "clear":
            backend.clear_faults()
            self.notif_service.post(NotificationCategory.SUCCESS, "Faults Cleared", "Mock simulator restored to normal.")
        self._refresh_all_views()

    # --- Asynchronous Worker Runners ---
    def _on_worker_error(self, operation: str, err: str):
        if not shiboken6.isValid(self):
            return
        logger.error(f"Operation '{operation}' failed: {err}")
        self.notif_service.post(
            NotificationCategory.ERROR,
            f"{operation} Failed",
            f"An unexpected error occurred: {err}",
        )
        self._refresh_all_views()

    def _async_execute_block(self, guid: str):
        worker = FunctionWorker(self.policy_service.block_device, guid)
        worker.signals.finished.connect(lambda res: self._refresh_all_views())
        worker.signals.error.connect(lambda err: self._on_worker_error("Block Device", err))
        self._start_worker(worker)

    def _async_execute_unblock(self, guid: str):
        worker = FunctionWorker(self.policy_service.unblock_device, guid)
        worker.signals.finished.connect(lambda res: self._refresh_all_views())
        worker.signals.error.connect(lambda err: self._on_worker_error("Unblock Device", err))
        self._start_worker(worker)

    def _async_execute_bandwidth(self, guid: str, dl: int, ul: int):
        if dl == 0 and ul == 0:
            worker = FunctionWorker(self.policy_service.remove_bandwidth_limits, guid)
        else:
            worker = FunctionWorker(self.policy_service.set_bandwidth_limits, guid, dl, ul)
        worker.signals.finished.connect(lambda res: self._refresh_all_views())
        worker.signals.error.connect(lambda err: self._on_worker_error("QoS Configuration", err))
        self._start_worker(worker)

    def _async_refresh_discovery(self):
        worker = FunctionWorker(self.device_service.refresh_discovery)
        worker.signals.finished.connect(lambda _: self._refresh_all_views())
        worker.signals.error.connect(lambda err: self._on_worker_error("Device Discovery", err))
        self._start_worker(worker)

    def _async_reconcile(self):
        worker = FunctionWorker(self.reconcile_engine.reconcile_once)
        worker.signals.finished.connect(self._after_reconcile)
        worker.signals.error.connect(lambda err: self._on_worker_error("State Reconciliation", err))
        self._start_worker(worker)

    def _after_reconcile(self, results):
        if not shiboken6.isValid(self):
            return
        self.notif_service.post(
            NotificationCategory.SUCCESS,
            "Reconciliation Completed",
            f"Audited {len(results)} device rules against live gateway kernel state.",
        )
        self._refresh_all_views()

    def _async_run_health_checks(self):
        worker = FunctionWorker(self.health_service.run_health_checks)
        worker.signals.finished.connect(self._after_health_checks)
        worker.signals.error.connect(lambda err: self._on_worker_error("Health Diagnostics", err))
        self._start_worker(worker)

    def _after_health_checks(self, report):
        if not shiboken6.isValid(self):
            return
        self.views["diagnostics"].set_health_report(report)
        self._refresh_all_views()

    def _update_traffic_metrics(self):
        """High-frequency (1.5s) calculation of delta rates and UI refresh without discovery scan."""
        if not shiboken6.isValid(self):
            return
        from netcutter.services.traffic_accounting import get_traffic_accounting_service
        get_traffic_accounting_service().take_snapshot()
        devices = self.device_service.get_all_devices()
        if "bandwidth" in self.views and shiboken6.isValid(self.views["bandwidth"]):
            self.views["bandwidth"].set_devices(devices)
        if "activity" in self.views and shiboken6.isValid(self.views["activity"]):
            self.views["activity"].set_devices(devices)
        if "domains" in self.views and shiboken6.isValid(self.views["domains"]):
            self.views["domains"].set_devices(devices)
            self.views["domains"].update_rules(self.domain_service.get_rules())
            self.views["domains"].update_events(self.domain_service.get_recent_events(50))


    def _async_start_metering(self, guid: str):
        worker = FunctionWorker(self.device_service.start_active_traffic_metering, guid)
        def _on_started(res):
            if not shiboken6.isValid(self):
                return
            ok, msg = res
            if ok:
                self.notif_service.post(NotificationCategory.SUCCESS, "Active Metering Started", msg)
            else:
                self.notif_service.post(NotificationCategory.WARNING, "Metering Failed", msg)
            self._refresh_all_views()
        worker.signals.finished.connect(_on_started)
        worker.signals.error.connect(lambda err: self._on_worker_error("Traffic Metering", err))
        self._start_worker(worker)

    def _async_stop_metering(self, guid: str):
        worker = FunctionWorker(self.device_service.stop_active_traffic_metering, guid)
        def _on_stopped(res):
            if not shiboken6.isValid(self):
                return
            ok, msg = res
            if ok:
                self.notif_service.post(NotificationCategory.INFO, "Direct Routing Restored", msg)
            else:
                self.notif_service.post(NotificationCategory.WARNING, "Restoration Notice", msg)
            self._refresh_all_views()
        worker.signals.finished.connect(_on_stopped)
        worker.signals.error.connect(lambda err: self._on_worker_error("Stop Metering", err))
        self._start_worker(worker)

    # --- UI View Updates ---
    def _refresh_all_views(self):
        if not shiboken6.isValid(self):
            return
        devices = self.device_service.get_all_devices()
        active_gw = self.gw_manager.get_active_config()
        recent_events = self.audit_service.get_recent_events(30)
        recent_notifs = self.notif_service.get_recent(200)
        unread_notifs = self.notif_service.get_unread_count()
        drift_count = self.reconcile_engine.drift_count

        # Update Header & Sidebar
        if active_gw:
            self.lbl_sidebar_gw.setText(f"GW: {active_gw.name}")
            self.lbl_header_gw.setText(f"Gateway: {active_gw.name} ({active_gw.host})")
            self.badge_header_status.setText(active_gw.status.value)
            self.badge_header_status.set_variant("success" if active_gw.status == GatewayStatus.ONLINE else "danger")
        else:
            self.lbl_sidebar_gw.setText("GW: None Selected")
            self.lbl_header_gw.setText("Gateway: None Selected")
            self.badge_header_status.setText("OFFLINE")
            self.badge_header_status.set_variant("danger")

        # Safe Mode Indicator
        is_safe = self.health_service.is_safe_mode
        self.safe_mode_chip.setVisible(is_safe)
        self.views["settings"].set_safe_mode_state(is_safe)

        # Notification Bell
        self.btn_notif_bell.setText(f"Notifications ({unread_notifs})")
        if unread_notifs > 0:
            self.btn_notif_bell.setStyleSheet(f"""
                QPushButton {{
                    background-color: #1e3a6a;
                    color: #38bdf8;
                    border: 1px solid #0284c7;
                    border-radius: 6px;
                    padding: 5px 14px;
                    font-size: 12px;
                    font-weight: 700;
                }}
                QPushButton:hover {{
                    background-color: #0284c7;
                    color: #ffffff;
                }}
            """)
        else:
            self.btn_notif_bell.setStyleSheet(f"""
                QPushButton {{
                    background-color: {Theme.BG_CARD};
                    color: {Theme.TEXT_SECONDARY};
                    border: 1px solid {Theme.BORDER_DEFAULT};
                    border-radius: 6px;
                    padding: 5px 14px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                QPushButton:hover {{
                    background-color: {Theme.BG_HOVER};
                    color: #ffffff;
                }}
            """)

        # View updates
        self.views["dashboard"].update_view(devices, active_gw, recent_events, drift_count=drift_count)
        self.views["devices"].set_devices(devices)
        self.views["policies"].set_devices(devices)
        self.views["bandwidth"].set_devices(devices)
        if "activity" in self.views and shiboken6.isValid(self.views["activity"]):
            self.views["activity"].set_devices(devices)
        self.views["notifications"].set_notifications(recent_notifs)

        backend = self.gw_manager.get_active_backend()
        caps = format_capabilities_report(backend.capabilities) if backend else {}
        self.views["gateways"].set_gateways(self.gw_repo.get_all(), caps)
        self.views["diagnostics"].set_logs(get_ring_buffer().get_entries())

        # Update Website & Domain Blocking View
        if "domains" in self.views and shiboken6.isValid(self.views["domains"]):
            self.views["domains"].set_devices(devices)
            self.views["domains"].update_rules(self.domain_service.get_rules())
            self.views["domains"].update_events(self.domain_service.get_recent_events(50))
            if backend:
                is_mock_backend = "mock" in backend.backend_name.lower()
                is_win_backend = "windows" in backend.backend_name.lower()
                engine_name = "Mock Simulator" if is_mock_backend else ("L2 DNS Interceptor" if is_win_backend else "Router DNS Filter")
                self.views["domains"].set_engine_status(engine_name, backend.is_connected())

        # Update Simulator / Demo Banner
        is_mock = self.device_service.is_simulator_active()
        self.simulator_banner.setVisible(is_mock)

        # Update Installation View if cached report exists
        cached_report = self.install_service.get_cached_report()
        if cached_report:
            self.views["installation"].update_readiness_report(cached_report)

    # --- Domain Blocking Handlers ---
    def _on_add_domain_rule(self, data: dict):
        ok, rule, err = self.domain_service.add_rule(
            raw_domain=data["domain"],
            match_type=data["match_type"],
            target_scope=data["target_scope"],
            target_device_guid=data["target_device_guid"],
            notes=data.get("notes"),
        )
        if ok and rule:
            self.notif_service.post(
                NotificationCategory.SUCCESS,
                "Domain Rule Added",
                f"Rule for '{rule.domain}' ({rule.match_type.value}) added. Status: {rule.enforcement_status.value}.",
            )
        else:
            self.notif_service.post(
                NotificationCategory.ERROR,
                "Failed to Add Domain Rule",
                err or "Unknown validation or enforcement error.",
            )
        self._refresh_all_views()

    def _on_toggle_domain_rule(self, rule_id: str):
        rule = self.domain_service.get_rule(rule_id)
        if not rule:
            return
        new_state = not rule.is_enabled
        ok, err = self.domain_service.update_rule(rule_id, is_enabled=new_state)
        if ok:
            action = "Enabled" if new_state else "Disabled"
            self.notif_service.post(
                NotificationCategory.INFO,
                f"Domain Rule {action}",
                f"Rule for '{rule.domain}' is now {action.lower()}.",
            )
        else:
            self.notif_service.post(
                NotificationCategory.ERROR,
                "Toggle Failed",
                err or "Failed to update rule state.",
            )
        self._refresh_all_views()

    def _on_delete_domain_rule(self, rule_id: str):
        rule = self.domain_service.get_rule(rule_id)
        domain_name = rule.domain if rule else rule_id
        ok, err = self.domain_service.delete_rule(rule_id)
        if ok:
            self.notif_service.post(
                NotificationCategory.INFO,
                "Domain Rule Deleted",
                f"Rule for '{domain_name}' was removed and access restored.",
            )
        else:
            self.notif_service.post(
                NotificationCategory.ERROR,
                "Delete Failed",
                err or "Failed to delete rule.",
            )
        self._refresh_all_views()

    def _on_verify_domain_rules(self):
        worker = FunctionWorker(self.domain_service.verify_all_rules)
        def _after_verify(results):
            if not shiboken6.isValid(self):
                return
            passed = sum(1 for success, _ in results.values() if success)
            total = len(results)
            self.notif_service.post(
                NotificationCategory.SUCCESS if passed == total else NotificationCategory.WARNING,
                "Domain Rules Audit",
                f"Verified {passed}/{total} active domain rules against kernel/DNS state.",
            )
            self._refresh_all_views()
        worker.signals.finished.connect(_after_verify)
        self._start_worker(worker)

    def _on_clear_domain_events(self):
        self.domain_service.clear_events()
        self._refresh_all_views()

    def _refresh_domain_blocking_view(self):
        self._refresh_all_views()


    def _switch_to_windows_lan(self):
        """Quickly switch active gateway to Windows LAN Off-Path mode."""
        self.activate_gateway("gw-windows-lan")

    def _async_run_installation_audit(self):
        """Asynchronously run system readiness audit."""
        worker = FunctionWorker(self.install_service.run_system_audit)
        worker.signals.finished.connect(self._after_installation_audit)
        worker.signals.error.connect(lambda err: self._on_worker_error("Readiness Audit", err))
        self._start_worker(worker)

    def _after_installation_audit(self, report):
        if not shiboken6.isValid(self):
            return
        self.views["installation"].update_readiness_report(report)
        self._refresh_all_views()

    def _async_repair_dependency(self, dep_id: str):
        """Execute automated repair or verification of a dependency."""
        worker = FunctionWorker(self.install_service.repair_component, dep_id)
        worker.signals.finished.connect(self._after_repair_dependency)
        worker.signals.error.connect(lambda err: self._on_worker_error("Component Action", err))
        self._start_worker(worker)

    def _after_repair_dependency(self, result):
        if not shiboken6.isValid(self):
            return
        cat = NotificationCategory.SUCCESS if result.success else NotificationCategory.WARNING
        self.notif_service.post(cat, f"Component: {result.dependency_id}", result.details)
        if result.requires_elevation:
            QMessageBox.information(
                self,
                "Administrator Elevation Required",
                "This action requires Administrator privileges. Please relaunch NetCutter as Administrator.",
            )
        # Re-run audit to reflect changes
        self._async_run_installation_audit()

    def _relaunch_as_admin(self):
        """Attempt to relaunch NetCutter with elevated administrator privileges."""
        if os.name == "nt":
            import ctypes
            try:
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                if int(ret) > 32:
                    QApplication.quit()
                    return
            except Exception as ex:
                logger.error(f"Failed to elevate process: {ex}")
        QMessageBox.information(
            self,
            "Administrator Elevation",
            "To elevate permissions, right-click NetCutter.exe and select 'Run as administrator'.",
        )

    def _export_installation_diagnostics(self):
        """Export sanitized JSON system readiness report."""
        dest, _ = QFileDialog.getSaveFileName(
            self,
            "Save System Readiness Diagnostics",
            str(Path.home() / "netcutter-system-readiness.json"),
            "JSON Files (*.json)",
        )
        if dest:
            try:
                data = self.install_service.generate_redacted_diagnostic_json()
                Path(dest).write_text(data, encoding="utf-8")
                self.notif_service.post(
                    NotificationCategory.SUCCESS,
                    "Readiness Diagnostics Exported",
                    f"Saved report to: {Path(dest).name}",
                )
            except Exception as ex:
                self.notif_service.post(
                    NotificationCategory.ERROR, "Export Failed", f"Could not write file: {ex}"
                )

    # --- System Tray Integration ---
    def _init_system_tray(self):
        """Configure system tray icon with context menu and minimize-to-tray capability."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = None
            return

        tray_menu = QMenu(self)
        action_show = tray_menu.addAction("Show NetCutter")
        action_show.triggered.connect(self._restore_from_tray)

        action_refresh = tray_menu.addAction("Audit & Refresh Now")
        action_refresh.triggered.connect(self._async_refresh_discovery)

        tray_menu.addSeparator()

        action_quit = tray_menu.addAction("Exit NetCutter")
        action_quit.triggered.connect(self._force_quit)

        icon_path = get_asset_path("netcutter-mark.png")
        if not icon_path.exists():
            icon_path = get_asset_path("icon.ico")

        tray_icon_obj = QIcon(str(icon_path)) if icon_path.exists() else self.windowIcon()
        if tray_icon_obj.isNull():
            logger.warning("No valid icon found for system tray; disabling tray integration.")
            self.tray_icon = None
            return

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(tray_icon_obj)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.setToolTip("NetCutter — Gateway Management & Policy Control")
        self.tray_icon.activated.connect(self._on_tray_activated)
        try:
            self.tray_icon.show()
        except Exception as ex:
            logger.warning(f"Could not display system tray icon: {ex}")
            self.tray_icon = None

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            if self.isVisible():
                if self.isMinimized():
                    self.showNormal()
                    self.activateWindow()
                else:
                    self.hide()
            else:
                self._restore_from_tray()

    def _restore_from_tray(self):
        self.showNormal()
        self.activateWindow()

    def _force_quit(self):
        try:
            if hasattr(self, "timer_refresh"):
                self.timer_refresh.stop()
            if hasattr(self, "reconcile_engine"):
                self.reconcile_engine.stop()
            if hasattr(self, "gw_manager"):
                self.gw_manager.disconnect_active()
            if hasattr(self, "threadpool"):
                self.threadpool.waitForDone(1500)
        except Exception as ex:
            logger.warning(f"Error during force quit: {ex}")
        if getattr(self, "tray_icon", None):
            try:
                self.tray_icon.hide()
            except Exception:
                pass
        QApplication.quit()

    def closeEvent(self, event):
        """Minimize to system tray on window close if available and valid, else clean shutdown."""
        if (
            getattr(self, "tray_icon", None)
            and self.tray_icon.isVisible()
            and not self.tray_icon.icon().isNull()
        ):
            self.hide()
            try:
                self.tray_icon.showMessage(
                    "NetCutter Running in Background",
                    "Reconciliation engine is actively monitoring gateway state.",
                    QSystemTrayIcon.Information,
                    2000,
                )
            except Exception:
                pass
            event.ignore()
        else:
            try:
                if hasattr(self, "timer_refresh"):
                    self.timer_refresh.stop()
                if hasattr(self, "reconcile_engine"):
                    self.reconcile_engine.stop()
                if hasattr(self, "gw_manager"):
                    self.gw_manager.disconnect_active()
                if hasattr(self, "threadpool"):
                    self.threadpool.waitForDone(1500)
            except Exception as ex:
                logger.warning(f"Error during app shutdown: {ex}")
            if getattr(self, "tray_icon", None):
                try:
                    self.tray_icon.hide()
                except Exception:
                    pass
            event.accept()
