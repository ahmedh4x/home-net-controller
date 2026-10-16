"""
In-App Notification Center View for NetCutter.
Displays event log alerts, unread counts, and severity-categorized notifications.
"""
from __future__ import annotations

from typing import List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netcutter.persistence.repository import NotificationItem
from netcutter.ui_qt.components import PageHeader
from netcutter.ui_qt.models import NotificationsTableModel


class NotificationsView(QWidget):
    mark_all_read_requested = Signal()
    clear_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._all_items: List[NotificationItem] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        header = PageHeader(
            title="Notification Center",
            subtitle="Centralized operational history, policy mutation events, and security warnings.",
        )
        btn_read_all = QPushButton("Mark All Read")
        btn_read_all.clicked.connect(self.mark_all_read_requested.emit)
        header.add_action(btn_read_all)

        btn_clear = QPushButton("Clear History")
        btn_clear.clicked.connect(self.clear_requested.emit)
        header.add_action(btn_clear)

        layout.addWidget(header)

        # Filter
        filter_layout = QHBoxLayout()
        self.combo_filter = QComboBox()
        self.combo_filter.addItems(["All Notifications", "Unread Only"])
        self.combo_filter.currentIndexChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.combo_filter)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Table
        self.table = QTableView()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        self.model = NotificationsTableModel([], self)
        self.table.setModel(self.model)
        layout.addWidget(self.table)

    def set_notifications(self, items: List[NotificationItem]):
        self._all_items = list(items)
        self._apply_filter()

    def _apply_filter(self):
        unread_only = self.combo_filter.currentText() == "Unread Only"
        filtered = [it for it in self._all_items if (not unread_only or not it.is_read)]
        self.model.set_items(filtered)
