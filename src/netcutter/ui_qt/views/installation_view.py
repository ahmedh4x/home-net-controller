"""
Installation and System Readiness Center View for NetCutter.
Provides declarative dependency inspection, system readiness cards,
automated repair actions, elevation guidance, and architecture selection.
"""
from __future__ import annotations

from typing import List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netcutter.services.installation_service import (
    ComponentStatus,
    DependencyItem,
    InstallationOperationResult,
    SystemReadinessReport,
)
from netcutter.ui_qt.components import MetricCard, PageHeader, StatusBadge
from netcutter.ui_qt.theme import Theme


class InstallationView(QWidget):
    verify_requested = Signal()
    repair_requested = Signal(str)  # dependency_id
    relaunch_elevated_requested = Signal()
    export_diagnostics_requested = Signal()
    switch_to_gateways_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        # Outer layout with scroll area to prevent any clipping on small windows
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("background-color: transparent;")

        container = QWidget()
        self.layout = QVBoxLayout(container)
        self.layout.setContentsMargins(24, 20, 24, 20)
        self.layout.setSpacing(16)

        # 1. Page Header
        header = PageHeader(
            title="Installation & System Readiness Center",
            subtitle="Declarative dependency inspection, driver management, system readiness, and permission guidance.",
        )
        self.btn_verify = QPushButton("Verify System Readiness")
        self.btn_verify.setObjectName("PrimaryBtn")
        self.btn_verify.clicked.connect(self.verify_requested.emit)
        header.add_action(self.btn_verify)

        self.btn_export = QPushButton("Export Diagnostics JSON")
        self.btn_export.clicked.connect(self.export_diagnostics_requested.emit)
        header.add_action(self.btn_export)

        self.layout.addWidget(header)

        # 2. System Readiness Metric Cards (Grid)
        self.cards_grid = QGridLayout()
        self.cards_grid.setSpacing(12)

        self.card_os = MetricCard("Operating System", "Windows", "Probing...", Theme.CYAN)
        self.card_admin = MetricCard("Privileges", "Standard", "Evaluation pending", Theme.WARNING)
        self.card_storage = MetricCard("Disk & Storage", "-- GB", "App Data storage", Theme.TEXT_PRIMARY)
        self.card_network = MetricCard("Gateway Link", "Probing...", "Local network", Theme.INFO)
        self.card_overall = MetricCard("Overall Readiness", "AUDIT PENDING", "Checking components", Theme.TEXT_SECONDARY)

        self.cards_grid.addWidget(self.card_os, 0, 0)
        self.cards_grid.addWidget(self.card_admin, 0, 1)
        self.cards_grid.addWidget(self.card_storage, 0, 2)
        self.cards_grid.addWidget(self.card_network, 0, 3)
        self.cards_grid.addWidget(self.card_overall, 0, 4)

        self.layout.addLayout(self.cards_grid)

        # 3. Privilege / Elevation Guidance Card
        self.elevation_card = QFrame()
        self.elevation_card.setObjectName("SurfaceCard")
        elev_layout = QHBoxLayout(self.elevation_card)
        elev_layout.setContentsMargins(16, 12, 16, 12)
        elev_layout.setSpacing(12)

        elev_text_layout = QVBoxLayout()
        elev_text_layout.setSpacing(4)
        self.lbl_elev_title = QLabel("PERMISSION & ELEVATION GUIDANCE")
        self.lbl_elev_title.setObjectName("CardHeader")
        elev_text_layout.addWidget(self.lbl_elev_title)

        self.lbl_elev_body = QLabel(
            "Standard User privileges allow managing OpenWrt, Linux, and MikroTik routers via direct SSH/API credentials. "
            "Windows LAN Off-Path packet redirection requires Administrator privileges and the Npcap packet capture driver."
        )
        self.lbl_elev_body.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY};")
        self.lbl_elev_body.setWordWrap(True)
        elev_text_layout.addWidget(self.lbl_elev_body)
        elev_layout.addLayout(elev_text_layout, stretch=1)

        self.btn_elevate = QPushButton("Relaunch as Administrator")
        self.btn_elevate.setObjectName("WarningBtn")
        self.btn_elevate.clicked.connect(self.relaunch_elevated_requested.emit)
        elev_layout.addWidget(self.btn_elevate, alignment=Qt.AlignVCenter)

        self.layout.addWidget(self.elevation_card)

        # 4. Declarative Component & Dependency Table
        table_card = QFrame()
        table_card.setObjectName("SurfaceCard")
        t_card_layout = QVBoxLayout(table_card)
        t_card_layout.setContentsMargins(16, 14, 16, 14)
        t_card_layout.setSpacing(10)

        t_title = QLabel("DECLARATIVE DEPENDENCY REGISTRY & HARDWARE DRIVERS")
        t_title.setObjectName("CardHeader")
        t_card_layout.addWidget(t_title)

        self.table_deps = QTableWidget()
        self.table_deps.setColumnCount(6)
        self.table_deps.setHorizontalHeaderLabels([
            "Component",
            "Category",
            "Status",
            "Detected Version / Details",
            "Required Privilege",
            "Action",
        ])
        self.table_deps.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_deps.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_deps.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_deps.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_deps.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_deps.horizontalHeader().setSectionResizeMode(5, QHeaderView.Fixed)
        self.table_deps.setColumnWidth(5, 140)
        self.table_deps.verticalHeader().setVisible(False)
        self.table_deps.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_deps.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_deps.setStyleSheet(f"""
            QTableWidget {{
                background-color: {Theme.BG_CARD};
                border: 1px solid {Theme.BORDER_DEFAULT};
                border-radius: 8px;
                gridline-color: {Theme.BORDER_MUTED};
            }}
            QHeaderView::section {{
                background-color: {Theme.BG_HOVER};
                color: {Theme.TEXT_SECONDARY};
                font-size: 11px;
                font-weight: 600;
                padding: 6px 10px;
                border: none;
                border-bottom: 1px solid {Theme.BORDER_DEFAULT};
            }}
            QTableWidget::item {{
                padding: 6px 10px;
                border-bottom: 1px solid {Theme.BORDER_MUTED};
            }}
        """)
        self.table_deps.setMinimumHeight(240)
        t_card_layout.addWidget(self.table_deps)

        self.layout.addWidget(table_card)

        # 5. Network Architecture Guidance Card
        arch_card = QFrame()
        arch_card.setObjectName("SurfaceCard")
        arch_layout = QHBoxLayout(arch_card)
        arch_layout.setContentsMargins(16, 14, 16, 14)
        arch_layout.setSpacing(16)

        arch_info = QVBoxLayout()
        arch_info.setSpacing(4)
        arch_title = QLabel("CHOOSE YOUR NETWORK CONTROL ARCHITECTURE")
        arch_title.setObjectName("CardHeader")
        arch_info.addWidget(arch_title)

        arch_desc = QLabel(
            "• Managed Router Mode (Recommended): Full hardware-level control (nftables / simple queues) on OpenWrt, Linux, or MikroTik. True bandwidth counters, no local packet drivers required.\n"
            "• Windows LAN Off-Path Mode: Operates alongside any standard ISP router using Npcap Layer-2 packet interception. Best when router credentials are not available."
        )
        arch_desc.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY}; line-height: 1.4;")
        arch_desc.setWordWrap(True)
        arch_info.addWidget(arch_desc)
        arch_layout.addLayout(arch_info, stretch=1)

        btn_gw = QPushButton("Configure Gateways")
        btn_gw.setObjectName("PrimaryBtn")
        btn_gw.clicked.connect(self.switch_to_gateways_requested.emit)
        arch_layout.addWidget(btn_gw, alignment=Qt.AlignVCenter)

        self.layout.addWidget(arch_card)

        scroll_area.setWidget(container)
        outer_layout.addWidget(scroll_area)

    def update_readiness_report(self, report: SystemReadinessReport):
        """Render readiness data into cards, elevation guidance, and dependency table."""
        # 1. Update Metric Cards
        self.card_os.set_value(f"{report.os_name} {report.os_arch}", report.os_version.split("(")[0].strip())
        
        if report.is_admin:
            self.card_admin.set_value("Administrator", "Elevated / Full Access")
            self.card_admin.lbl_value.setStyleSheet(f"color: {Theme.SUCCESS}; font-size: 24px; font-weight: 700;")
            self.btn_elevate.setText("Administrator Mode Active")
            self.btn_elevate.setEnabled(False)
            self.btn_elevate.setStyleSheet(f"background-color: {Theme.BG_HOVER}; color: {Theme.SUCCESS}; border: 1px solid {Theme.SUCCESS};")
        else:
            self.card_admin.set_value("Standard User", "Unprivileged host")
            self.card_admin.lbl_value.setStyleSheet(f"color: {Theme.WARNING}; font-size: 24px; font-weight: 700;")
            self.btn_elevate.setText("Relaunch as Administrator")
            self.btn_elevate.setEnabled(True)
            self.btn_elevate.setStyleSheet("")

        self.card_storage.set_value(f"{report.disk_free_gb:.1f} GB", "Storage ready" if report.local_app_data_ok else "App Data Error")
        
        gw_text = report.default_gateway_ip if report.default_gateway_ip else "Not detected"
        self.card_network.set_value(gw_text, "Gateway detected" if report.network_connected else "Offline / Disconnected")

        if report.overall_ready:
            self.card_overall.set_value("READY", "All dependencies met")
            self.card_overall.lbl_value.setStyleSheet(f"color: {Theme.SUCCESS}; font-size: 24px; font-weight: 700;")
        else:
            self.card_overall.set_value("SETUP NEEDED", "Components require action")
            self.card_overall.lbl_value.setStyleSheet(f"color: {Theme.WARNING}; font-size: 24px; font-weight: 700;")

        # 2. Populate Dependency Table
        self.table_deps.setRowCount(len(report.dependencies))
        for row, dep in enumerate(report.dependencies):
            # Column 0: Component Name
            item_name = QTableWidgetItem(dep.name)
            item_name.setFont(QFont("Segoe UI", 10, QFont.DemiBold))
            item_name.setForeground(QColor(Theme.TEXT_PRIMARY))
            self.table_deps.setItem(row, 0, item_name)

            # Column 1: Category
            item_cat = QTableWidgetItem(dep.category)
            item_cat.setForeground(QColor(Theme.TEXT_SECONDARY))
            self.table_deps.setItem(row, 1, item_cat)

            # Column 2: Status Badge Widget
            variant = "neutral"
            if dep.status == ComponentStatus.READY:
                variant = "success"
            elif dep.status == ComponentStatus.NEEDS_INSTALLATION:
                variant = "danger"
            elif dep.status in (ComponentStatus.NEEDS_CONFIGURATION, ComponentStatus.REQUIRES_ELEVATION):
                variant = "warning"
            elif dep.status == ComponentStatus.OPTIONAL:
                variant = "neutral"
            elif dep.status == ComponentStatus.UNSUPPORTED:
                variant = "neutral"

            badge = StatusBadge(dep.status.value, variant=variant)
            badge_container = QWidget()
            b_layout = QHBoxLayout(badge_container)
            b_layout.setContentsMargins(6, 4, 6, 4)
            b_layout.addWidget(badge, alignment=Qt.AlignLeft)
            self.table_deps.setCellWidget(row, 2, badge_container)

            # Column 3: Detected Version / Details
            details_text = dep.verification_details
            if dep.error_message:
                details_text += f" ({dep.error_message})"
            item_det = QTableWidgetItem(details_text)
            item_det.setForeground(QColor(Theme.TEXT_PRIMARY if dep.status == ComponentStatus.READY else Theme.TEXT_MUTED))
            self.table_deps.setItem(row, 3, item_det)

            # Column 4: Required Privilege
            item_priv = QTableWidgetItem(dep.privilege_required)
            item_priv.setForeground(QColor(Theme.TEXT_SECONDARY))
            self.table_deps.setItem(row, 4, item_priv)

            # Column 5: Action Button
            btn_action = QPushButton()
            btn_action.setFixedHeight(26)
            if dep.status == ComponentStatus.READY:
                btn_action.setText("Re-Verify")
                btn_action.setStyleSheet(f"background-color: {Theme.BG_HOVER}; color: {Theme.TEXT_SECONDARY}; font-size: 11px;")
                dep_id = dep.id
                btn_action.clicked.connect(lambda checked=False, d=dep_id: self.repair_requested.emit(d))
            elif dep.status == ComponentStatus.NEEDS_CONFIGURATION:
                btn_action.setText("Configure / Start")
                btn_action.setStyleSheet(f"background-color: {Theme.WARNING}; color: #000000; font-weight: 600; font-size: 11px;")
                dep_id = dep.id
                btn_action.clicked.connect(lambda checked=False, d=dep_id: self.repair_requested.emit(d))
            elif dep.status == ComponentStatus.NEEDS_INSTALLATION:
                btn_action.setText("Repair / Install")
                btn_action.setStyleSheet(f"background-color: {Theme.CYAN}; color: #000000; font-weight: 600; font-size: 11px;")
                dep_id = dep.id
                btn_action.clicked.connect(lambda checked=False, d=dep_id: self.repair_requested.emit(d))
            else:
                btn_action.setText("Verify")
                btn_action.setStyleSheet(f"background-color: {Theme.BG_HOVER}; color: {Theme.TEXT_SECONDARY}; font-size: 11px;")
                dep_id = dep.id
                btn_action.clicked.connect(lambda checked=False, d=dep_id: self.repair_requested.emit(d))

            act_container = QWidget()
            a_layout = QHBoxLayout(act_container)
            a_layout.setContentsMargins(4, 2, 4, 2)
            a_layout.addWidget(btn_action)
            self.table_deps.setCellWidget(row, 5, act_container)
