"""
Diagnostics and Structured Log Viewer View for NetCutter.
Displays subsystem health evaluations, live ring-buffer logs, and diagnostic support bundle exports.
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
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netcutter.common.logging import LogEntry
from netcutter.services.health_service import SystemHealthReport
from netcutter.ui_qt.components import PageHeader, StatusBadge
from netcutter.ui_qt.models import LogsTableModel
from netcutter.ui_qt.theme import Theme


class DiagnosticsView(QWidget):
    run_diagnostics_requested = Signal()
    export_bundle_requested = Signal()
    clear_logs_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._all_logs: List[LogEntry] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        header = PageHeader(
            title="Diagnostics & Structured Observability",
            subtitle="Automated subsystem health checks, ring-buffer logging, and sanitized support bundle exports.",
        )
        btn_run = QPushButton("Run Health Checks")
        btn_run.setObjectName("PrimaryBtn")
        btn_run.clicked.connect(self.run_diagnostics_requested.emit)
        header.add_action(btn_run)

        btn_export = QPushButton("Export Support Bundle (.zip)")
        btn_export.clicked.connect(self.export_bundle_requested.emit)
        header.add_action(btn_export)

        layout.addWidget(header)

        # 1. Health Status Card
        self.health_card = QFrame()
        self.health_card.setObjectName("SurfaceCard")
        h_layout = QVBoxLayout(self.health_card)
        h_layout.setContentsMargins(14, 12, 14, 12)
        h_layout.setSpacing(6)

        h_title = QLabel("SUBSYSTEM HEALTH STATUS")
        h_title.setObjectName("CardHeader")
        h_layout.addWidget(h_title)

        self.lbl_health_summary = QLabel("Health evaluation pending...")
        self.lbl_health_summary.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")
        h_layout.addWidget(self.lbl_health_summary)

        self.health_badges_layout = QHBoxLayout()
        self.health_badges_layout.setSpacing(10)
        h_layout.addLayout(self.health_badges_layout)

        layout.addWidget(self.health_card)

        # 2. Log Filter Toolbar
        log_bar = QHBoxLayout()
        log_bar.setSpacing(10)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Filter logs by message or correlation ID...")
        self.txt_search.textChanged.connect(self._apply_filter)
        log_bar.addWidget(self.txt_search, stretch=3)

        self.combo_level = QComboBox()
        self.combo_level.addItems(["ALL LEVELS", "DEBUG", "INFO", "WARNING", "ERROR"])
        self.combo_level.currentIndexChanged.connect(self._apply_filter)
        log_bar.addWidget(self.combo_level, stretch=1)

        btn_clear = QPushButton("Clear View")
        btn_clear.clicked.connect(self.clear_logs_requested.emit)
        log_bar.addWidget(btn_clear)

        layout.addLayout(log_bar)

        # 3. Logs Table
        self.table_logs = QTableView()
        self.table_logs.setAlternatingRowColors(True)
        self.table_logs.setSelectionBehavior(QTableView.SelectRows)
        self.table_logs.verticalHeader().setVisible(False)
        self.table_logs.horizontalHeader().setStretchLastSection(True)
        self.table_logs.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        self.model = LogsTableModel([], self)
        self.table_logs.setModel(self.model)
        layout.addWidget(self.table_logs)

    def set_health_report(self, report: SystemHealthReport):
        self.lbl_health_summary.setText(
            f"Overall Status: {report.overall_status.value} | Safe Mode: {'ACTIVE' if report.is_safe_mode else 'INACTIVE'}"
        )

        # Clear old badges
        while self.health_badges_layout.count():
            item = self.health_badges_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for name, check in report.checks.items():
            variant = "success" if check.status.value == "HEALTHY" else ("warning" if check.status.value == "DEGRADED" else "danger")
            lat_str = f" ({check.latency_ms}ms)" if check.latency_ms is not None else ""
            badge = StatusBadge(f"{name}: {check.status.value}{lat_str}", variant=variant)
            badge.setToolTip(check.message)
            self.health_badges_layout.addWidget(badge)
        self.health_badges_layout.addStretch()

    def set_logs(self, entries: List[LogEntry]):
        self._all_logs = list(entries)
        self._apply_filter()

    def _apply_filter(self):
        query = self.txt_search.text().lower().strip()
        level = self.combo_level.currentText()

        filtered = []
        for e in self._all_logs:
            if level != "ALL LEVELS" and e.level != level:
                continue
            if query and (query not in e.message.lower() and (not e.exception or query not in e.exception.lower())):
                continue
            filtered.append(e)

        self.model.set_entries(filtered)
