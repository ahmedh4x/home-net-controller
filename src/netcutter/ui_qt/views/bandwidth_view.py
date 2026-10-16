"""
Bandwidth QoS, Traffic Accounting and Real-Time Usage Monitoring View for NetCutter.
Adapted from the LANtern-Control real-time packet accounting pipeline (MIT License).
Displays live per-device download/upload speeds, cumulative data transferred, and active monitoring mode badges.
"""
from __future__ import annotations

from typing import List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netcutter.domain.models import Device, format_bytes, format_rate
from netcutter.ui_qt.components import PageHeader
from netcutter.ui_qt.models import BandwidthTableModel
from netcutter.ui_qt.theme import Theme


class BandwidthView(QWidget):
    set_bandwidth_requested = Signal(object)      # Device
    open_device_requested = Signal(str)           # device_guid
    start_metering_requested = Signal(str)        # device_guid
    stop_metering_requested = Signal(str)         # device_guid

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._devices: List[Device] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # 1. Page Header
        header = PageHeader(
            title="Real-Time Bandwidth & Traffic Accounting",
            subtitle="Genuine per-device usage monitoring, live throughput rates, and Layer-2 transparent metering (LANtern-Control engine).",
        )
        layout.addWidget(header)

        # 2. Metric Summary Cards Strip
        metrics_box = QHBoxLayout()
        metrics_box.setSpacing(12)

        self.card_dl = self._create_metric_card("Live Download", "0 B/s", Theme.CYAN)
        self.card_ul = self._create_metric_card("Live Upload", "0 B/s", Theme.ACCENT_HOVER)
        self.card_total = self._create_metric_card("Total Cumulative", "0 B", "#ffffff")
        self.card_metered = self._create_metric_card("Active Metering", "0 Devices", Theme.SUCCESS_TEXT)

        metrics_box.addWidget(self.card_dl)
        metrics_box.addWidget(self.card_ul)
        metrics_box.addWidget(self.card_total)
        metrics_box.addWidget(self.card_metered)
        layout.addLayout(metrics_box)

        # 3. Informational Switched LAN Notice Card
        info_card = QFrame()
        info_card.setObjectName("SurfaceCard")
        i_l = QVBoxLayout(info_card)
        i_l.setContentsMargins(14, 12, 14, 12)
        i_l.setSpacing(4)

        t = QLabel("Switched LAN Visibility & Active Metering Notice")
        t.setStyleSheet("font-weight: 700; color: #ffffff; font-size: 13px;")
        i_l.addWidget(t)

        d = QLabel(
            "Hardware switches and Wi-Fi access points isolate unicast frames between other clients and the router. "
            "In Passive mode, NetCutter strictly meters broadcasts and controller traffic. "
            "Select 'Enable Active Metering' on any device to establish a transparent Layer-2 bridge that measures "
            "real full-duplex internet throughput without interrupting connectivity."
        )
        d.setWordWrap(True)
        d.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        i_l.addWidget(d)
        layout.addWidget(info_card)

        # 4. Live Bandwidth Table
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
        self.table.setColumnWidth(0, 180)  # Device Name
        self.table.setColumnWidth(1, 120)  # IP Address
        self.table.setColumnWidth(2, 130)  # MAC Address
        self.table.setColumnWidth(3, 110)  # Download Rate
        self.table.setColumnWidth(4, 110)  # Upload Rate
        self.table.setColumnWidth(5, 120)  # Total Downloaded
        self.table.setColumnWidth(6, 120)  # Total Uploaded
        self.table.setColumnWidth(7, 120)  # Combined Usage
        self.table.setColumnWidth(8, 160)  # Monitoring Mode
        self.table.setColumnWidth(9, 80)   # Access
        layout.addWidget(self.table)

        # 5. Bottom Actions Bar
        act_box = QHBoxLayout()
        act_box.setSpacing(10)

        self.lbl_selected_status = QLabel("Select a device to control traffic monitoring.")
        self.lbl_selected_status.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        act_box.addWidget(self.lbl_selected_status)
        act_box.addStretch()

        self.btn_meter = QPushButton("Enable Active Metering")
        self.btn_meter.setStyleSheet(f"background-color: {Theme.CYAN}; color: #000000; font-weight: 700; padding: 6px 14px; border-radius: 4px;")
        self.btn_meter.clicked.connect(self._on_start_metering)
        act_box.addWidget(self.btn_meter)

        self.btn_stop_meter = QPushButton("Stop Metering (Restore Direct)")
        self.btn_stop_meter.setObjectName("SecondaryBtn")
        self.btn_stop_meter.clicked.connect(self._on_stop_metering)
        act_box.addWidget(self.btn_stop_meter)

        btn_edit = QPushButton("Configure Rate Limits")
        btn_edit.setObjectName("PrimaryBtn")
        btn_edit.clicked.connect(self._on_edit_qos)
        act_box.addWidget(btn_edit)

        layout.addLayout(act_box)

        # Selection change listener
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)

    def _create_metric_card(self, title: str, value: str, val_color: str) -> QFrame:
        card = QFrame()
        card.setObjectName("SurfaceCard")
        l = QVBoxLayout(card)
        l.setContentsMargins(14, 10, 14, 10)
        l.setSpacing(2)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet(f"font-size: 11px; color: {Theme.TEXT_MUTED}; font-weight: 600; text-transform: uppercase;")
        l.addWidget(lbl_t)

        lbl_v = QLabel(value)
        lbl_v.setObjectName(f"val_{title.lower().replace(' ', '_')}")
        lbl_v.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {val_color};")
        l.addWidget(lbl_v)
        return card

    def set_devices(self, devices: List[Device]):
        self._devices = list(devices)
        self.model.set_devices(self._devices)
        self._update_metric_cards()
        self._update_selected_ui()

    def _update_metric_cards(self):
        total_dl_rate = sum(d.download_rate_bps for d in self._devices)
        total_ul_rate = sum(d.upload_rate_bps for d in self._devices)
        total_cumulative = sum(d.total_download_bytes + d.total_upload_bytes for d in self._devices)
        metered_count = sum(1 for d in self._devices if d.traffic_monitoring_mode == "ACTIVE_METERING")

        lbl_dl = self.card_dl.findChild(QLabel, "val_live_download")
        if lbl_dl:
            lbl_dl.setText(format_rate(total_dl_rate))

        lbl_ul = self.card_ul.findChild(QLabel, "val_live_upload")
        if lbl_ul:
            lbl_ul.setText(format_rate(total_ul_rate))

        lbl_tot = self.card_total.findChild(QLabel, "val_total_cumulative")
        if lbl_tot:
            lbl_tot.setText(format_bytes(total_cumulative))

        lbl_met = self.card_metered.findChild(QLabel, "val_active_metering")
        if lbl_met:
            lbl_met.setText(f"{metered_count} Devices")

    def _get_selected_device(self) -> Optional[Device]:
        sel = self.table.selectionModel()
        if not sel:
            return None
        rows = sel.selectedRows()
        if rows:
            return self.model.get_device(rows[0].row())
        return None

    def _on_selection_changed(self):
        self._update_selected_ui()

    def _update_selected_ui(self):
        dev = self._get_selected_device()
        if not dev:
            self.lbl_selected_status.setText("Select a device to control traffic monitoring.")
            self.btn_meter.setEnabled(False)
            self.btn_stop_meter.setEnabled(False)
            return

        is_metered = (dev.traffic_monitoring_mode == "ACTIVE_METERING")
        if is_metered:
            self.lbl_selected_status.setText(f"Device {dev.display_name} is ACTIVELY METERED (transparent forwarding bridge).")
            self.btn_meter.setEnabled(False)
            self.btn_stop_meter.setEnabled(True)
        else:
            self.lbl_selected_status.setText(f"Device {dev.display_name} is in PASSIVE observation mode.")
            self.btn_meter.setEnabled(True)
            self.btn_stop_meter.setEnabled(False)

    def _on_start_metering(self):
        dev = self._get_selected_device()
        if dev:
            self.start_metering_requested.emit(dev.device_guid)

    def _on_stop_metering(self):
        dev = self._get_selected_device()
        if dev:
            self.stop_metering_requested.emit(dev.device_guid)

    def _on_edit_qos(self):
        dev = self._get_selected_device()
        if dev:
            self.set_bandwidth_requested.emit(dev)

    def _on_double_clicked(self, index):
        dev = self.model.get_device(index.row())
        if dev:
            self.open_device_requested.emit(dev.device_guid)
