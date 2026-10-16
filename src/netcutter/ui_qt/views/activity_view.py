"""
Activity and Real-Time Network Observability View for NetCutter.
Displays live observable network traffic, real-time bandwidth meters, device tracking,
and Layer-2 packet activity with instant filtering and search.
"""
from __future__ import annotations

from typing import List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netcutter.domain.models import Device, format_bytes, format_rate
from netcutter.ui_qt.components import PageHeader
from netcutter.ui_qt.models import BandwidthTableModel
from netcutter.ui_qt.theme import Theme


class ActivityView(QWidget):
    """
    Unified Activity view providing real-time traffic monitoring,
    per-device speed meters, and packet tracking.
    """
    open_device_requested = Signal(str)           # device_guid
    set_bandwidth_requested = Signal(object)      # Device
    start_metering_requested = Signal(str)        # device_guid
    stop_metering_requested = Signal(str)         # device_guid
    refresh_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._devices: List[Device] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # 1. Header with Refresh action
        header = PageHeader(
            title="Network Activity & Real-Time Tracking",
            subtitle="Observable Layer-2 network events, live throughput telemetry, and client traffic tracking.",
        )
        self.btn_refresh = QPushButton("Refresh Telemetry")
        self.btn_refresh.setObjectName("PrimaryBtn")
        self.btn_refresh.clicked.connect(self.refresh_requested.emit)
        header.add_action(self.btn_refresh)
        layout.addWidget(header)

        # 2. KPI Summary Cards Strip
        metrics_box = QHBoxLayout()
        metrics_box.setSpacing(12)

        self.card_dl = self._create_metric_card("Live Download", "0 B/s", Theme.CYAN)
        self.card_ul = self._create_metric_card("Live Upload", "0 B/s", Theme.ACCENT_HOVER)
        self.card_total = self._create_metric_card("Total Cumulative", "0 B", "#ffffff")
        self.card_metered = self._create_metric_card("Active Tracking", "0 Devices", Theme.SUCCESS_TEXT)

        metrics_box.addWidget(self.card_dl)
        metrics_box.addWidget(self.card_ul)
        metrics_box.addWidget(self.card_total)
        metrics_box.addWidget(self.card_metered)
        layout.addLayout(metrics_box)

        # 3. Filtering Toolbar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(10)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Filter active traffic by device name, IP, or MAC...")
        self.txt_search.textChanged.connect(self._apply_filter)
        filter_bar.addWidget(self.txt_search, stretch=3)

        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["All Activity", "Active Metering Only", "Passive Broadcast Only"])
        self.combo_mode.currentIndexChanged.connect(self._apply_filter)
        filter_bar.addWidget(self.combo_mode, stretch=1)

        layout.addLayout(filter_bar)

        # 4. Main Telemetry Table
        self.table = QTableView()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.doubleClicked.connect(self._on_double_clicked)

        self.model = BandwidthTableModel([], self)
        self.table.setModel(self.model)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 105)  # IP Address
        self.table.setColumnWidth(2, 125)  # MAC Address
        self.table.setColumnWidth(3, 85)   # ↓ Rate
        self.table.setColumnWidth(4, 85)   # ↑ Rate
        self.table.setColumnWidth(5, 85)   # Total ↓
        self.table.setColumnWidth(6, 85)   # Total ↑
        self.table.setColumnWidth(7, 90)   # Combined
        self.table.setColumnWidth(8, 105)  # Mode
        self.table.setColumnWidth(9, 85)   # Access
        layout.addWidget(self.table)

        # 5. Bottom Action & Device Tracking Bar
        act_box = QHBoxLayout()
        act_box.setSpacing(10)

        self.lbl_selected_status = QLabel("Select a device in the table to control active metering or track packets.")
        self.lbl_selected_status.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        act_box.addWidget(self.lbl_selected_status)
        act_box.addStretch()

        self.btn_meter = QPushButton("Track Device (Active Metering)")
        self.btn_meter.setObjectName("PrimaryBtn")
        self.btn_meter.setStyleSheet(f"background-color: {Theme.CYAN}; color: #000000; font-weight: 700; padding: 7px 16px; border-radius: 6px;")
        self.btn_meter.clicked.connect(self._on_toggle_metering)
        act_box.addWidget(self.btn_meter)

        self.btn_limit = QPushButton("Set Speed Limit")
        self.btn_limit.clicked.connect(self._on_set_limit)
        act_box.addWidget(self.btn_limit)

        self.btn_details = QPushButton("View Device History")
        self.btn_details.clicked.connect(self._on_view_details)
        act_box.addWidget(self.btn_details)

        layout.addLayout(act_box)
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)

    def _create_metric_card(self, title: str, initial_val: str, color_hex: str) -> QFrame:
        """Create a styled operational KPI metric card with top accent."""
        card = QFrame()
        card.setObjectName("MetricCard")
        card.setStyleSheet(f"""
            QFrame#MetricCard {{
                background-color: {Theme.BG_CARD};
                border: 1px solid {Theme.BORDER_DEFAULT};
                border-top: 3px solid {color_hex};
                border-radius: 8px;
            }}
            QFrame#MetricCard:hover {{
                border-color: {color_hex};
                background-color: {Theme.BG_SURFACE};
            }}
        """)
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(16, 12, 16, 12)
        vbox.setSpacing(4)

        lbl_t = QLabel(title.upper())
        lbl_t.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {Theme.TEXT_SECONDARY}; letter-spacing: 0.6px;")
        vbox.addWidget(lbl_t)

        lbl_v = QLabel(initial_val)
        lbl_v.setObjectName(f"val_{title.lower().replace(' ', '_')}")
        lbl_v.setStyleSheet(f"font-size: 24px; font-weight: 800; color: {color_hex};")
        vbox.addWidget(lbl_v)

        return card

    def set_devices(self, devices: List[Device]):
        """Update devices list and recalculate summary metrics."""
        self._devices = list(devices)
        self._apply_filter()
        self._update_metric_cards()

    def _apply_filter(self):
        """Filter the displayed telemetry table."""
        query = self.txt_search.text().strip().lower()
        mode_idx = self.combo_mode.currentIndex()

        filtered = []
        for dev in self._devices:
            if query:
                name_match = query in dev.display_name.lower()
                mac_match = query in dev.primary_mac.lower()
                ip_match = any(query in ip for ip in dev.ipv4_addresses + dev.ipv6_addresses)
                if not (name_match or mac_match or ip_match):
                    continue

            if mode_idx == 1 and dev.traffic_monitoring_mode != "ACTIVE_METERING":
                continue
            elif mode_idx == 2 and dev.traffic_monitoring_mode == "ACTIVE_METERING":
                continue

            filtered.append(dev)

        self.model.set_devices(filtered)

    def _update_metric_cards(self):
        """Refresh KPI aggregate numbers."""
        total_dl_rate = sum(d.download_rate_bps for d in self._devices)
        total_ul_rate = sum(d.upload_rate_bps for d in self._devices)
        total_bytes = sum(d.total_download_bytes + d.total_upload_bytes for d in self._devices)
        active_metered = sum(1 for d in self._devices if d.traffic_monitoring_mode == "ACTIVE_METERING")

        lbl_dl = self.card_dl.findChild(QLabel, "val_live_download")
        if lbl_dl:
            lbl_dl.setText(format_rate(total_dl_rate))

        lbl_ul = self.card_ul.findChild(QLabel, "val_live_upload")
        if lbl_ul:
            lbl_ul.setText(format_rate(total_ul_rate))

        lbl_tot = self.card_total.findChild(QLabel, "val_total_cumulative")
        if lbl_tot:
            lbl_tot.setText(format_bytes(total_bytes))

        lbl_met = self.card_metered.findChild(QLabel, "val_active_tracking")
        if lbl_met:
            lbl_met.setText(f"{active_metered} Devices")

    def _get_selected_device(self) -> Optional[Device]:
        """Return the device currently selected in the table."""
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return None
        return self.model.get_device(indexes[0].row())

    def _on_selection_changed(self):
        """Update button labels and action states upon table selection change."""
        dev = self._get_selected_device()
        if not dev:
            self.lbl_selected_status.setText("Select a device in the table to control active metering or track packets.")
            self.btn_meter.setText("Track Device (Active Metering)")
            self.btn_meter.setEnabled(False)
            self.btn_limit.setEnabled(False)
            self.btn_details.setEnabled(False)
            return

        self.btn_meter.setEnabled(True)
        self.btn_limit.setEnabled(True)
        self.btn_details.setEnabled(True)

        is_metering = dev.traffic_monitoring_mode == "ACTIVE_METERING"
        if is_metering:
            self.btn_meter.setText("Stop Tracking")
            self.btn_meter.setStyleSheet(f"background-color: {Theme.DANGER}; color: #ffffff; font-weight: 700; padding: 6px 14px; border-radius: 4px;")
            self.lbl_selected_status.setText(f"Active Metering enabled for {dev.display_name}. Full-duplex Layer-2 telemetry flowing.")
        else:
            self.btn_meter.setText("Track Device (Active Metering)")
            self.btn_meter.setStyleSheet(f"background-color: {Theme.CYAN}; color: #000000; font-weight: 700; padding: 6px 14px; border-radius: 4px;")
            self.lbl_selected_status.setText(f"Passive mode for {dev.display_name}. Broadcast frames monitored.")

    def _on_toggle_metering(self):
        """Handle start/stop active metering for selected client."""
        dev = self._get_selected_device()
        if not dev:
            return
        if dev.traffic_monitoring_mode == "ACTIVE_METERING":
            self.stop_metering_requested.emit(dev.device_guid)
        else:
            self.start_metering_requested.emit(dev.device_guid)

    def _on_set_limit(self):
        """Open speed limit dialog for selected client."""
        dev = self._get_selected_device()
        if dev:
            self.set_bandwidth_requested.emit(dev)

    def _on_view_details(self):
        """Open detailed device inspector for selected client."""
        dev = self._get_selected_device()
        if dev:
            self.open_device_requested.emit(dev.device_guid)

    def _on_double_clicked(self, index):
        """Navigate to device inspection on row double-click."""
        dev = self.model.get_device(index.row())
        if dev:
            self.open_device_requested.emit(dev.device_guid)
