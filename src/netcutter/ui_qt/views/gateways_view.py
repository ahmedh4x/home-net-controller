"""
Gateway Router Management View for NetCutter.
Manages router connections, credential resolution, and live hardware capability declarations.
"""
from __future__ import annotations

from typing import Dict, List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netcutter.domain.models import GatewayConfig
from netcutter.ui_qt.components import PageHeader


class GatewaysView(QWidget):
    add_gw_requested = Signal()
    edit_gw_requested = Signal(object)      # GatewayConfig
    delete_gw_requested = Signal(str)       # gateway_id
    activate_gw_requested = Signal(str)     # gateway_id
    test_gw_requested = Signal(object)      # GatewayConfig

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._gateways: List[GatewayConfig] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = PageHeader(
            title="Gateway Router Management",
            subtitle="Configure SSH and REST credentials, orchestrate kernel drivers, and inspect backend capabilities.",
        )
        btn_add = QPushButton("+ Add Gateway Router")
        btn_add.setObjectName("PrimaryBtn")
        btn_add.clicked.connect(self.add_gw_requested.emit)
        header.add_action(btn_add)
        layout.addWidget(header)

        # Gateways Table
        lbl_gws = QLabel("Configured Gateway Routers:")
        lbl_gws.setStyleSheet("font-size: 13px; font-weight: 700; color: #ffffff;")
        layout.addWidget(lbl_gws)

        self.table_gws = QTableWidget()
        self.table_gws.setColumnCount(7)
        self.table_gws.setHorizontalHeaderLabels([
            "Active", "Gateway Name", "Backend Mode", "Host / URL", "Port", "Status", "Last Error"
        ])
        self.table_gws.setAlternatingRowColors(True)
        self.table_gws.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_gws.setSelectionMode(QTableWidget.SingleSelection)
        self.table_gws.verticalHeader().setVisible(False)
        self.table_gws.verticalHeader().setDefaultSectionSize(34)
        self.table_gws.horizontalHeader().setStretchLastSection(True)
        self.table_gws.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        layout.addWidget(self.table_gws)

        # Action Buttons for Selected Gateway
        btn_bar = QHBoxLayout()
        btn_bar.setSpacing(10)

        btn_activate = QPushButton("Activate Selected")
        btn_activate.setObjectName("PrimaryBtn")
        btn_activate.clicked.connect(self._on_activate)
        btn_bar.addWidget(btn_activate)

        btn_test = QPushButton("Test Connection")
        btn_test.clicked.connect(self._on_test)
        btn_bar.addWidget(btn_test)

        btn_edit = QPushButton("Edit Configuration")
        btn_edit.clicked.connect(self._on_edit)
        btn_bar.addWidget(btn_edit)

        btn_del = QPushButton("Delete")
        btn_del.setObjectName("DangerBtn")
        btn_del.clicked.connect(self._on_delete)
        btn_bar.addWidget(btn_del)

        btn_bar.addStretch()
        layout.addLayout(btn_bar)

        # Active Backend Capabilities Matrix
        lbl_caps = QLabel("Active Backend Capabilities Matrix:")
        lbl_caps.setStyleSheet("font-size: 13px; font-weight: 700; color: #ffffff;")
        layout.addWidget(lbl_caps)

        self.table_caps = QTableWidget()
        self.table_caps.setColumnCount(2)
        self.table_caps.setHorizontalHeaderLabels(["Feature / Enforcement Capability", "Hardware / Kernel Support"])
        self.table_caps.horizontalHeader().setStretchLastSection(True)
        self.table_caps.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_caps.verticalHeader().setVisible(False)
        self.table_caps.setMinimumHeight(220)
        self.table_caps.setMaximumHeight(280)
        layout.addWidget(self.table_caps)

    def set_gateways(self, gateways: List[GatewayConfig], capabilities_report: Dict[str, str]):
        self._gateways = list(gateways)
        self.table_gws.setRowCount(len(self._gateways))

        for row, gw in enumerate(self._gateways):
            # Active check
            act_item = QTableWidgetItem("● ACTIVE" if gw.is_active else "")
            act_item.setTextAlignment(Qt.AlignCenter)
            if gw.is_active:
                act_item.setForeground(Qt.green)
            self.table_gws.setItem(row, 0, act_item)

            self.table_gws.setItem(row, 1, QTableWidgetItem(gw.name))
            self.table_gws.setItem(row, 2, QTableWidgetItem(gw.backend_type.value))
            self.table_gws.setItem(row, 3, QTableWidgetItem(gw.host))
            self.table_gws.setItem(row, 4, QTableWidgetItem(str(gw.port)))

            status_item = QTableWidgetItem(gw.status.value)
            status_item.setTextAlignment(Qt.AlignCenter)
            self.table_gws.setItem(row, 5, status_item)

            self.table_gws.setItem(row, 6, QTableWidgetItem(gw.last_error or "None"))

        # Update capabilities table
        self.table_caps.setRowCount(len(capabilities_report))
        for r, (feat, supp) in enumerate(capabilities_report.items()):
            self.table_caps.setItem(r, 0, QTableWidgetItem(feat))
            item = QTableWidgetItem(supp)
            item.setTextAlignment(Qt.AlignCenter)
            if supp == "SUPPORTED":
                item.setForeground(Qt.green)
            else:
                item.setForeground(Qt.gray)
            self.table_caps.setItem(r, 1, item)

    def _get_selected_gateway(self) -> Optional[GatewayConfig]:
        sel = self.table_gws.selectionModel()
        if not sel:
            return None
        rows = sel.selectedRows()
        if rows and 0 <= rows[0].row() < len(self._gateways):
            return self._gateways[rows[0].row()]
        return None

    def _on_activate(self):
        gw = self._get_selected_gateway()
        if gw:
            self.activate_gw_requested.emit(gw.gateway_id)

    def _on_test(self):
        gw = self._get_selected_gateway()
        if gw:
            self.test_gw_requested.emit(gw)

    def _on_edit(self):
        gw = self._get_selected_gateway()
        if gw:
            self.edit_gw_requested.emit(gw)

    def _on_delete(self):
        gw = self._get_selected_gateway()
        if gw:
            self.delete_gw_requested.emit(gw.gateway_id)
