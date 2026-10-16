"""
Device Inventory and Management View for NetCutter.
Provides real-time search, multi-factor filtering, category filtering,
table visualization, empty state illustrations, and policy action triggers.
"""
from __future__ import annotations

from typing import List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netcutter.common.paths import get_asset_path
from netcutter.domain.models import Device, DeviceCategory, PolicyStatus
from netcutter.ui_qt.components import PageHeader
from netcutter.ui_qt.models import DeviceTableModel
from netcutter.ui_qt.theme import Theme


class DevicesView(QWidget):
    open_device_requested = Signal(str)         # device_guid
    block_requested = Signal(object)            # Device
    unblock_requested = Signal(str)             # device_guid
    set_bandwidth_requested = Signal(object)    # Device
    refresh_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._all_devices: List[Device] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # 1. Page Header
        header = PageHeader(
            title="Connected Client Devices",
            subtitle="Authoritative device identities, Layer-2 MAC correlations, and live enforcement state.",
        )
        btn_refresh = QPushButton("Refresh Discovery")
        btn_refresh.clicked.connect(self.refresh_requested.emit)
        header.add_action(btn_refresh)
        layout.addWidget(header)

        # 2. Search & Filter Tool Bar
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(10)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search by device name, MAC, IPv4, IPv6, or vendor...")
        self.txt_search.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.txt_search, stretch=3)

        self.combo_category = QComboBox()
        self.combo_category.addItems([
            "All Categories",
            "Smartphones",
            "PCs & Laptops",
            "Macs",
            "Tablets",
            "Smart TVs",
            "Printers",
            "Gaming Consoles",
            "Routers & APs",
            "IoT Devices",
            "Unknown",
        ])
        self.combo_category.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.combo_category, stretch=1)

        self.combo_filter = QComboBox()
        self.combo_filter.addItems([
            "All Devices",
            "Online Only",
            "Blocked Access",
            "QoS Shaped",
            "Private (Randomized) MACs",
            "Policy Drifted",
        ])
        self.combo_filter.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.combo_filter, stretch=1)

        layout.addLayout(filter_layout)

        # 3. Main Virtualized Device Table
        self.table = QTableView()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.doubleClicked.connect(self._on_table_double_clicked)

        self.model = DeviceTableModel([], self)
        self.table.setModel(self.model)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 115)  # Category
        self.table.setColumnWidth(2, 130)  # MAC Address
        self.table.setColumnWidth(3, 110)  # IP Address
        self.table.setColumnWidth(4, 110)  # Vendor
        self.table.setColumnWidth(5, 95)   # Access
        self.table.setColumnWidth(6, 110)  # Bandwidth QoS
        self.table.setColumnWidth(7, 130)  # Sync State
        layout.addWidget(self.table)

        # 4. Modern Empty State Illustration Card
        self.empty_card = QFrame()
        self.empty_card.setObjectName("SurfaceCard")
        empty_layout = QVBoxLayout(self.empty_card)
        empty_layout.setContentsMargins(30, 40, 30, 40)
        empty_layout.setAlignment(Qt.AlignCenter)
        empty_layout.setSpacing(12)

        empty_svg = get_asset_path("empty_devices.svg")
        self.lbl_empty_img = QLabel()
        if empty_svg.exists():
            pix = QPixmap(str(empty_svg)).scaled(200, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.lbl_empty_img.setPixmap(pix)
        self.lbl_empty_img.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(self.lbl_empty_img)

        lbl_empty_title = QLabel("No Client Devices Found")
        lbl_empty_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #ffffff;")
        lbl_empty_title.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(lbl_empty_title)

        lbl_empty_sub = QLabel("No devices match your search query or selected category filter.")
        lbl_empty_sub.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")
        lbl_empty_sub.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(lbl_empty_sub)

        layout.addWidget(self.empty_card)
        self.empty_card.setVisible(False)

        # 5. Contextual Bottom Action Bar
        action_layout = QHBoxLayout()
        action_layout.setSpacing(10)

        self.lbl_count = QLabel("Showing 0 devices")
        self.lbl_count.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        action_layout.addWidget(self.lbl_count)
        action_layout.addStretch()

        btn_inspect = QPushButton("Inspect Details")
        btn_inspect.clicked.connect(self._on_inspect_clicked)
        action_layout.addWidget(btn_inspect)

        btn_block = QPushButton("Block Access")
        btn_block.setObjectName("DangerBtn")
        btn_block.clicked.connect(self._on_block_clicked)
        action_layout.addWidget(btn_block)

        btn_unblock = QPushButton("Restore Access")
        btn_unblock.setObjectName("SuccessBtn")
        btn_unblock.clicked.connect(self._on_unblock_clicked)
        action_layout.addWidget(btn_unblock)

        btn_qos = QPushButton("Configure QoS")
        btn_qos.setObjectName("PrimaryBtn")
        btn_qos.clicked.connect(self._on_qos_clicked)
        action_layout.addWidget(btn_qos)

        layout.addLayout(action_layout)

    def set_devices(self, devices: List[Device]):
        self._all_devices = list(devices)
        self._apply_filters()

    def _apply_filters(self):
        query = self.txt_search.text().lower().strip()
        filter_mode = self.combo_filter.currentText()
        cat_mode = self.combo_category.currentText()

        cat_map = {
            "Smartphones": DeviceCategory.SMARTPHONE,
            "PCs & Laptops": DeviceCategory.LAPTOP_PC,
            "Macs": DeviceCategory.MAC,
            "Tablets": DeviceCategory.TABLET,
            "Smart TVs": DeviceCategory.SMART_TV,
            "Printers": DeviceCategory.PRINTER,
            "Gaming Consoles": DeviceCategory.GAMING_CONSOLE,
            "Routers & APs": DeviceCategory.ROUTER_AP,
            "IoT Devices": DeviceCategory.IOT_DEVICE,
            "Unknown": DeviceCategory.UNKNOWN,
        }

        filtered = []
        for dev in self._all_devices:
            # Category filter
            if cat_mode != "All Categories":
                target_cat = cat_map.get(cat_mode)
                if target_cat and dev.category != target_cat:
                    continue

            # Mode filter
            if filter_mode == "Online Only" and not dev.is_online:
                continue
            elif filter_mode == "Blocked Access" and not dev.desired_policy.is_blocked:
                continue
            elif filter_mode == "QoS Shaped" and not (dev.desired_policy.has_download_limit or dev.desired_policy.has_upload_limit):
                continue
            elif filter_mode == "Private (Randomized) MACs" and not dev.is_randomized_mac:
                continue
            elif filter_mode == "Policy Drifted" and dev.policy_status != PolicyStatus.DRIFTED:
                continue

            # Text query
            if query:
                match_name = query in dev.display_name.lower()
                match_mac = query in dev.primary_mac.lower()
                match_v4 = any(query in ip for ip in dev.ipv4_addresses)
                match_v6 = any(query in ip.lower() for ip in dev.ipv6_addresses)
                match_vendor = query in (dev.vendor.lower() if dev.vendor else "")
                if not (match_name or match_mac or match_v4 or match_v6 or match_vendor):
                    continue

            filtered.append(dev)

        self.model.set_devices(filtered)
        self.lbl_count.setText(f"Showing {len(filtered)} of {len(self._all_devices)} devices")

        # Toggle empty state illustration
        is_empty = len(filtered) == 0
        self.table.setVisible(not is_empty)
        self.empty_card.setVisible(is_empty)

    def _get_selected_device(self) -> Optional[Device]:
        sel = self.table.selectionModel()
        if not sel:
            return None
        selected_indexes = sel.selectedRows()
        if selected_indexes:
            return self.model.get_device(selected_indexes[0].row())
        return None

    def _on_table_double_clicked(self, index):
        dev = self.model.get_device(index.row())
        if dev:
            self.open_device_requested.emit(dev.device_guid)

    def _on_inspect_clicked(self):
        dev = self._get_selected_device()
        if dev:
            self.open_device_requested.emit(dev.device_guid)

    def _on_block_clicked(self):
        dev = self._get_selected_device()
        if dev:
            self.block_requested.emit(dev)

    def _on_unblock_clicked(self):
        dev = self._get_selected_device()
        if dev:
            self.unblock_requested.emit(dev.device_guid)

    def _on_qos_clicked(self):
        dev = self._get_selected_device()
        if dev:
            self.set_bandwidth_requested.emit(dev)
