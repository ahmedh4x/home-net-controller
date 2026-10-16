"""
Policy Registry and Drift Reconciliation View for NetCutter.
Displays desired vs observed kernel rules and triggers continuous state reconciliation.
"""
from __future__ import annotations

from typing import List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netcutter.domain.models import Device, PolicyStatus
from netcutter.ui_qt.components import PageHeader
from netcutter.ui_qt.models import PoliciesTableModel
from netcutter.ui_qt.theme import Theme


class PoliciesView(QWidget):
    reconcile_requested = Signal()
    open_device_requested = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._all_devices: List[Device] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        header = PageHeader(
            title="Policy Enforcement Registry",
            subtitle="Continuous reconciliation tracking desired administrative policies against actual observed router state.",
        )
        btn_reconcile = QPushButton("Reconcile All Drift")
        btn_reconcile.setObjectName("PrimaryBtn")
        btn_reconcile.clicked.connect(self.reconcile_requested.emit)
        header.add_action(btn_reconcile)
        layout.addWidget(header)

        # Search Bar
        filter_layout = QHBoxLayout()
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Filter by device name or MAC address...")
        self.txt_search.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.txt_search)
        layout.addLayout(filter_layout)

        # Table
        self.table = QTableView()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.doubleClicked.connect(self._on_double_clicked)

        self.model = PoliciesTableModel([], self)
        self.table.setModel(self.model)
        layout.addWidget(self.table)

        # Status Summary Bar
        self.lbl_summary = QLabel("All policies verified and synchronized.")
        self.lbl_summary.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(self.lbl_summary)

    def set_devices(self, devices: List[Device]):
        self._all_devices = list(devices)
        self._apply_filter()

    def _apply_filter(self):
        query = self.txt_search.text().lower().strip()
        filtered = []
        drift_count = 0

        for dev in self._all_devices:
            if dev.policy_status == PolicyStatus.DRIFTED:
                drift_count += 1
            if query and (query not in dev.display_name.lower() and query not in dev.primary_mac.lower()):
                continue
            filtered.append(dev)

        self.model.set_devices(filtered)
        if drift_count > 0:
            self.lbl_summary.setText(f"Warning: {drift_count} device rule(s) have drifted from desired state on gateway.")
            self.lbl_summary.setStyleSheet(f"color: {Theme.WARNING_TEXT}; font-size: 12px; font-weight: 600;")
        else:
            self.lbl_summary.setText(f"All {len(self._all_devices)} client policies verified in sync with router kernel.")
            self.lbl_summary.setStyleSheet(f"color: {Theme.SUCCESS_TEXT}; font-size: 12px;")

    def _on_double_clicked(self, index):
        dev = self.model.get_device(index.row())
        if dev:
            self.open_device_requested.emit(dev.device_guid)
