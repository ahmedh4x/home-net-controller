"""
Device Details and Deep Inspection View for NetCutter.
Provides multi-identifier inspection, MAC history, IPv4/IPv6 parity audit, and direct policy mutation.
"""
from __future__ import annotations

from typing import Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from netcutter.domain.models import Device
from netcutter.ui_qt.components import PageHeader, StatusBadge
from netcutter.ui_qt.theme import Theme


class DeviceDetailsView(QWidget):
    back_requested = Signal()
    block_requested = Signal(object)          # Device
    unblock_requested = Signal(str)           # device_guid
    set_bandwidth_requested = Signal(object)  # Device
    rename_requested = Signal(str, str)       # device_guid, new_name

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.device: Optional[Device] = None

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # 1. Page Header with Back Button
        self.header = PageHeader(
            title="Device Deep Inspection",
            subtitle="Authoritative identity parameters, historical Layer-2 MACs, and active kernel filters.",
        )
        btn_back = QPushButton("← Back to Devices")
        btn_back.clicked.connect(self.back_requested.emit)
        self.header.add_action(btn_back)
        main_layout.addWidget(self.header)

        # Scrollable Area for detailed inspection
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content_widget = QWidget()
        scroll_layout = QVBoxLayout(content_widget)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(16)

        # 2. Rename and Identity Banner Card
        self.banner_card = QFrame()
        self.banner_card.setObjectName("SurfaceCard")
        b_layout = QHBoxLayout(self.banner_card)
        b_layout.setContentsMargins(16, 14, 16, 14)

        b_info = QVBoxLayout()
        b_info.setSpacing(6)

        rename_layout = QHBoxLayout()
        self.txt_display_name = QLineEdit()
        self.txt_display_name.setStyleSheet("font-size: 16px; font-weight: 700; max-width: 340px;")
        rename_layout.addWidget(self.txt_display_name)

        btn_save_name = QPushButton("Save Name")
        btn_save_name.clicked.connect(self._on_save_name)
        rename_layout.addWidget(btn_save_name)
        rename_layout.addStretch()
        b_info.addLayout(rename_layout)

        self.lbl_guid = QLabel("GUID: None")
        self.lbl_guid.setStyleSheet(f"color: {Theme.TEXT_MUTED}; font-size: 11px;")
        b_info.addWidget(self.lbl_guid)
        b_layout.addLayout(b_info)
        b_layout.addStretch()

        self.badge_status = StatusBadge("ONLINE", variant="success")
        b_layout.addWidget(self.badge_status)

        scroll_layout.addWidget(self.banner_card)

        # 3. Two-Column Detailed Specifications
        cols_layout = QHBoxLayout()
        cols_layout.setSpacing(16)

        # Column A: Network Identifiers Card
        col_a_card = QFrame()
        col_a_card.setObjectName("SurfaceCard")
        col_a = QFormLayout(col_a_card)
        col_a.setContentsMargins(16, 14, 16, 14)
        col_a.setSpacing(10)

        lbl_sec_a = QLabel("NETWORK IDENTIFIERS")
        lbl_sec_a.setObjectName("CardHeader")
        col_a.addRow(lbl_sec_a)

        self.lbl_primary_mac = QLabel("-")
        col_a.addRow("Primary MAC:", self.lbl_primary_mac)

        self.lbl_is_rand = QLabel("-")
        col_a.addRow("MAC Randomization:", self.lbl_is_rand)

        self.lbl_hist_macs = QLabel("-")
        col_a.addRow("Historical MACs:", self.lbl_hist_macs)

        self.lbl_ipv4 = QLabel("-")
        col_a.addRow("IPv4 Addresses:", self.lbl_ipv4)

        self.lbl_ipv6 = QLabel("-")
        col_a.addRow("IPv6 Addresses:", self.lbl_ipv6)

        self.lbl_vendor = QLabel("-")
        col_a.addRow("OUI Vendor:", self.lbl_vendor)

        self.lbl_duid = QLabel("-")
        col_a.addRow("DHCP DUID:", self.lbl_duid)

        cols_layout.addWidget(col_a_card, stretch=1)

        # Column B: Policy & Gateway Enforcement State Card
        col_b_card = QFrame()
        col_b_card.setObjectName("SurfaceCard")
        col_b = QFormLayout(col_b_card)
        col_b.setContentsMargins(16, 14, 16, 14)
        col_b.setSpacing(10)

        lbl_sec_b = QLabel("GATEWAY ENFORCEMENT AUDIT")
        lbl_sec_b.setObjectName("CardHeader")
        col_b.addRow(lbl_sec_b)

        self.lbl_desired_acc = QLabel("-")
        col_b.addRow("Desired Internet:", self.lbl_desired_acc)

        self.lbl_observed_acc = QLabel("-")
        col_b.addRow("Router Observed:", self.lbl_observed_acc)

        self.lbl_sync_status = QLabel("-")
        col_b.addRow("Synchronization:", self.lbl_sync_status)

        self.lbl_dl_limit = QLabel("-")
        col_b.addRow("Download Limit:", self.lbl_dl_limit)

        self.lbl_ul_limit = QLabel("-")
        col_b.addRow("Upload Limit:", self.lbl_ul_limit)

        self.lbl_last_sync = QLabel("-")
        col_b.addRow("Last Verified:", self.lbl_last_sync)

        self.lbl_last_err = QLabel("-")
        col_b.addRow("Last Error:", self.lbl_last_err)

        cols_layout.addWidget(col_b_card, stretch=1)
        scroll_layout.addLayout(cols_layout)

        # 4. Action Buttons Bar
        actions_card = QFrame()
        actions_card.setObjectName("SurfaceCard")
        act_layout = QHBoxLayout(actions_card)
        act_layout.setContentsMargins(16, 14, 16, 14)
        act_layout.setSpacing(12)

        self.btn_block = QPushButton("Block Access")
        self.btn_block.setObjectName("DangerBtn")
        self.btn_block.clicked.connect(self._on_block)
        act_layout.addWidget(self.btn_block)

        self.btn_unblock = QPushButton("Restore Access")
        self.btn_unblock.setObjectName("SuccessBtn")
        self.btn_unblock.clicked.connect(self._on_unblock)
        act_layout.addWidget(self.btn_unblock)

        self.btn_bandwidth = QPushButton("Configure Bandwidth (QoS)")
        self.btn_bandwidth.setObjectName("PrimaryBtn")
        self.btn_bandwidth.clicked.connect(self._on_bandwidth)
        act_layout.addWidget(self.btn_bandwidth)

        act_layout.addStretch()
        scroll_layout.addWidget(actions_card)

        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll)

    def load_device(self, device: Device):
        self.device = device
        self.txt_display_name.setText(device.display_name)
        self.lbl_guid.setText(f"GUID: {device.device_guid}")

        # Badge
        if not device.is_online:
            self.badge_status.setText("OFFLINE")
            self.badge_status.set_variant("neutral")
        elif device.desired_policy.is_blocked:
            self.badge_status.setText("BLOCKED")
            self.badge_status.set_variant("danger")
        else:
            self.badge_status.setText("ONLINE")
            self.badge_status.set_variant("success")

        # Network Identifiers
        self.lbl_primary_mac.setText(device.primary_mac)
        self.lbl_is_rand.setText("Private / Randomized (Bit 1 set)" if device.is_randomized_mac else "Hardware Factory MAC")
        self.lbl_hist_macs.setText(", ".join(device.historical_macs) if device.historical_macs else "-")
        self.lbl_ipv4.setText(", ".join(device.ipv4_addresses) if device.ipv4_addresses else "No IPv4")
        self.lbl_ipv6.setText(", ".join(device.ipv6_addresses) if device.ipv6_addresses else "No IPv6")
        self.lbl_vendor.setText(device.vendor or "Unknown Manufacturer")
        self.lbl_duid.setText(device.duid or "None")

        # Policies
        self.lbl_desired_acc.setText(device.desired_policy.internet_access.value)
        self.lbl_observed_acc.setText(device.observed_policy.internet_access.value)
        self.lbl_sync_status.setText(device.policy_status.value)
        dl = device.desired_policy.download_limit_kbps
        self.lbl_dl_limit.setText(f"{dl} Kbps ({round(dl / 1024, 2)} Mbps)" if dl > 0 else "Unlimited")
        ul = device.desired_policy.upload_limit_kbps
        self.lbl_ul_limit.setText(f"{ul} Kbps ({round(ul / 1024, 2)} Mbps)" if ul > 0 else "Unlimited")
        self.lbl_last_sync.setText(device.last_sync.strftime("%Y-%m-%d %H:%M:%S") if device.last_sync else "Never")
        self.lbl_last_err.setText(device.last_policy_error or "None")

    def _on_save_name(self):
        if self.device:
            new_name = self.txt_display_name.text().strip()
            if new_name:
                self.rename_requested.emit(self.device.device_guid, new_name)

    def _on_block(self):
        if self.device:
            self.block_requested.emit(self.device)

    def _on_unblock(self):
        if self.device:
            self.unblock_requested.emit(self.device.device_guid)

    def _on_bandwidth(self):
        if self.device:
            self.set_bandwidth_requested.emit(self.device)
