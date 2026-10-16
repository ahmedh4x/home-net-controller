"""
Dashboard Overview View for NetCutter.
Displays system KPI cards, topology hero banner, device category breakdown pills,
active gateway health, quick action triggers, and recent activity.
"""
from __future__ import annotations

from typing import Dict, List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netcutter.common.paths import get_asset_path
from netcutter.domain.events import AuditEvent
from netcutter.domain.models import Device, DeviceCategory, GatewayConfig
from netcutter.ui_qt.components import MetricCard, PageHeader, StatusBadge
from netcutter.ui_qt.models import AuditTableModel, get_category_icon
from netcutter.ui_qt.theme import Theme


class CategoryPill(QFrame):
    """Visual summary badge displaying device category icon, label, and device count."""

    def __init__(self, category: DeviceCategory, parent=None):
        super().__init__(parent)
        self.category = category
        self.setObjectName("SurfaceCard")
        self.setStyleSheet(
            f"QFrame {{ background-color: {Theme.BG_CARD}; border: 1px solid {Theme.BORDER_DEFAULT}; border-radius: 8px; padding: 4px 10px; }}"
            f"QFrame:hover {{ border-color: {Theme.CYAN_ACCENT}; }}"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 4, 8, 4)
        layout.setSpacing(6)

        icon = get_category_icon(category)
        lbl_icon = QLabel()
        if icon:
            lbl_icon.setPixmap(icon.pixmap(18, 18))
        layout.addWidget(lbl_icon)

        self.lbl_text = QLabel(f"{category.value}: 0")
        self.lbl_text.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {Theme.TEXT_SECONDARY};")
        layout.addWidget(self.lbl_text)

    def set_count(self, count: int):
        self.lbl_text.setText(f"{self.category.value}: {count}")
        if count > 0:
            self.lbl_text.setStyleSheet("font-size: 11px; font-weight: 700; color: #ffffff;")
        else:
            self.lbl_text.setStyleSheet(f"font-size: 11px; font-weight: 500; color: {Theme.TEXT_MUTED};")


class DashboardView(QWidget):
    refresh_requested = Signal()
    reconcile_requested = Signal()
    diagnostics_requested = Signal()
    open_device_requested = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(24, 20, 24, 20)
        outer_layout.setSpacing(16)

        # 1. Page Header
        header = PageHeader(
            title="Operational Overview",
            subtitle="Real-time gateway enforcement state, client inventory, and policy reconciliation.",
        )
        btn_refresh = QPushButton("Discover Clients")
        btn_refresh.setObjectName("PrimaryBtn")
        btn_refresh.clicked.connect(self.refresh_requested.emit)
        header.add_action(btn_refresh)

        btn_reconcile = QPushButton("Reconcile Drift")
        btn_reconcile.clicked.connect(self.reconcile_requested.emit)
        header.add_action(btn_reconcile)

        btn_diag = QPushButton("Run Health Checks")
        btn_diag.clicked.connect(self.diagnostics_requested.emit)
        header.add_action(btn_diag)

        outer_layout.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("background: transparent;")

        scroll_widget = QWidget()
        layout = QVBoxLayout(scroll_widget)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(16)

        # 2. Hero Gateway Topology Banner Card
        self.banner_card = QFrame()
        self.banner_card.setObjectName("SurfaceCard")
        b_layout = QHBoxLayout(self.banner_card)
        b_layout.setContentsMargins(18, 14, 18, 14)
        b_layout.setSpacing(16)

        topo_path = get_asset_path("network_topology_banner.svg")
        self.lbl_topo = QLabel()
        if topo_path.exists():
            pix = QPixmap(str(topo_path)).scaledToHeight(64, Qt.SmoothTransformation)
            self.lbl_topo.setPixmap(pix)
        b_layout.addWidget(self.lbl_topo)

        gw_info_layout = QVBoxLayout()
        gw_info_layout.setSpacing(2)
        self.lbl_gw_title = QLabel("Active Gateway: Initializing...")
        self.lbl_gw_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #ffffff;")
        gw_info_layout.addWidget(self.lbl_gw_title)

        self.lbl_gw_sub = QLabel("Subsystem: In-kernel netfilter & tc orchestration")
        self.lbl_gw_sub.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY};")
        gw_info_layout.addWidget(self.lbl_gw_sub)

        b_layout.addLayout(gw_info_layout, stretch=1)

        self.gw_status_badge = StatusBadge("CONNECTING", variant="warning")
        b_layout.addWidget(self.gw_status_badge)

        layout.addWidget(self.banner_card)

        # 3. Metric KPI Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        self.card_total = MetricCard("Total Clients", "0", "Discovered logical devices")
        cards_layout.addWidget(self.card_total)

        self.card_online = MetricCard("Active Online", "0", "Connected clients", accent_color=Theme.SUCCESS_TEXT)
        cards_layout.addWidget(self.card_online)

        self.card_blocked = MetricCard("Blocked Access", "0", "Forwarding drops active", accent_color=Theme.DANGER_TEXT)
        cards_layout.addWidget(self.card_blocked)

        self.card_shaped = MetricCard("QoS Shaped", "0", "Token-bucket limits", accent_color=Theme.INFO)
        cards_layout.addWidget(self.card_shaped)

        self.card_drift = MetricCard("Policy Drift", "0", "Out-of-sync rules", accent_color=Theme.WARNING_TEXT)
        cards_layout.addWidget(self.card_drift)

        layout.addLayout(cards_layout)

        # 4. Device Category Breakdown Pills
        cat_card = QFrame()
        cat_card.setObjectName("SurfaceCard")
        cat_card_layout = QVBoxLayout(cat_card)
        cat_card_layout.setContentsMargins(16, 12, 16, 12)
        cat_card_layout.setSpacing(8)

        lbl_cat_title = QLabel("Device Category Distribution")
        lbl_cat_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #ffffff;")
        cat_card_layout.addWidget(lbl_cat_title)

        self.pills_layout = QGridLayout()
        self.pills_layout.setSpacing(8)
        self.category_pills: Dict[DeviceCategory, CategoryPill] = {}

        categories_to_show = [
            DeviceCategory.SMARTPHONE,
            DeviceCategory.LAPTOP_PC,
            DeviceCategory.MAC,
            DeviceCategory.TABLET,
            DeviceCategory.SMART_TV,
            DeviceCategory.PRINTER,
            DeviceCategory.GAMING_CONSOLE,
            DeviceCategory.ROUTER_AP,
            DeviceCategory.IOT_DEVICE,
        ]

        for i, cat in enumerate(categories_to_show):
            pill = CategoryPill(cat, self)
            self.category_pills[cat] = pill
            row = i // 3
            col = i % 3
            self.pills_layout.addWidget(pill, row, col)

        cat_card_layout.addLayout(self.pills_layout)
        layout.addWidget(cat_card)

        # 5. Recent Network Audit Trail Section
        lbl_act = QLabel("Recent Network Audit Trail")
        lbl_act.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 6px;")
        layout.addWidget(lbl_act)

        self.audit_model = AuditTableModel([], self)
        self.table_recent = QTableView()
        self.table_recent.setModel(self.audit_model)
        self.table_recent.setAlternatingRowColors(True)
        self.table_recent.verticalHeader().setVisible(False)
        self.table_recent.verticalHeader().setDefaultSectionSize(32)
        self.table_recent.setSelectionBehavior(QTableView.SelectRows)
        self.table_recent.setMinimumHeight(160)
        self.table_recent.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table_recent.setColumnWidth(0, 95)   # Timestamp
        self.table_recent.setColumnWidth(1, 160)  # Action
        self.table_recent.setColumnWidth(2, 140)  # Target
        self.table_recent.setColumnWidth(3, 110)  # Status
        self.table_recent.setVisible(False)
        layout.addWidget(self.table_recent)

        # Clean empty state container when audit trail has no security drift
        self.empty_audit_card = QFrame()
        self.empty_audit_card.setObjectName("SurfaceCard")
        self.empty_audit_card.setStyleSheet(f"""
            QFrame#SurfaceCard {{
                background-color: {Theme.BG_CARD};
                border: 1px dashed {Theme.BORDER_DEFAULT};
                border-radius: 8px;
                padding: 24px;
            }}
        """)
        e_layout = QVBoxLayout(self.empty_audit_card)
        e_layout.setContentsMargins(20, 20, 20, 20)
        e_layout.setAlignment(Qt.AlignCenter)
        e_layout.setSpacing(6)

        lbl_check = QLabel("✓")
        lbl_check.setStyleSheet(f"font-size: 26px; color: {Theme.SUCCESS_TEXT}; font-weight: bold;")
        lbl_check.setAlignment(Qt.AlignCenter)
        e_layout.addWidget(lbl_check)

        lbl_sync_title = QLabel("Gateway Enforcement & Policies Synchronized")
        lbl_sync_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        lbl_sync_title.setAlignment(Qt.AlignCenter)
        e_layout.addWidget(lbl_sync_title)

        lbl_sync_desc = QLabel("No unauthorized rule drift, dropped packets, or security anomalies detected in current session.")
        lbl_sync_desc.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY};")
        lbl_sync_desc.setAlignment(Qt.AlignCenter)
        e_layout.addWidget(lbl_sync_desc)

        layout.addWidget(self.empty_audit_card)

        scroll.setWidget(scroll_widget)
        outer_layout.addWidget(scroll)

    def update_view(
        self,
        devices: List[Device],
        gateway_config: Optional[GatewayConfig],
        recent_events: List[AuditEvent],
        drift_count: int = 0,
    ):
        total = len(devices)
        online = sum(1 for d in devices if d.is_online)
        blocked = sum(1 for d in devices if d.desired_policy.is_blocked)
        shaped = sum(1 for d in devices if d.desired_policy.has_download_limit or d.desired_policy.has_upload_limit)

        self.card_total.set_value(str(total))
        self.card_online.set_value(str(online), f"{int((online / total * 100)) if total else 0}% of clients online")
        self.card_blocked.set_value(str(blocked), "Clients dropped at forward chain")
        self.card_shaped.set_value(str(shaped), "Clients with HTB/fq_codel active")
        self.card_drift.set_value(str(drift_count), "Requires reconciliation" if drift_count else "All rules in sync")

        # Update category counts
        cat_counts: Dict[DeviceCategory, int] = {}
        for d in devices:
            cat_counts[d.category] = cat_counts.get(d.category, 0) + 1

        for cat, pill in self.category_pills.items():
            pill.set_count(cat_counts.get(cat, 0))

        # Toggle table vs clean empty state
        self.audit_model.set_events(recent_events)
        has_events = bool(recent_events)
        self.table_recent.setVisible(has_events)
        self.empty_audit_card.setVisible(not has_events)

        if gateway_config:
            self.lbl_gw_title.setText(f"Active Gateway: {gateway_config.name} ({gateway_config.host})")
            self.lbl_gw_sub.setText(f"Driver: {gateway_config.backend_type.value} | Interfaces: LAN={gateway_config.lan_interface}, WAN={gateway_config.wan_interface}")
            self.gw_status_badge.setText(gateway_config.status.value)
            variant = "success" if gateway_config.status.value == "ONLINE" else "danger"
            self.gw_status_badge.set_variant(variant)
        else:
            self.lbl_gw_title.setText("Active Gateway: None Selected")
            self.gw_status_badge.setText("OFFLINE")
            self.gw_status_badge.set_variant("danger")
