"""
Application Settings and Simulation Fault-Injection View for NetCutter.
"""
from __future__ import annotations

from typing import Callable, Dict, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from netcutter.ui_qt.components import PageHeader
from netcutter.ui_qt.theme import Theme


class SettingsView(QWidget):
    save_settings_requested = Signal(dict)
    safe_mode_toggled = Signal(bool)
    inject_fault_requested = Signal(str)  # "timeout", "disconnect", "auth", "partial", "clear"

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(18)

        header = PageHeader(
            title="Settings & System Controls",
            subtitle="Configure operational polling loops, enforce Safe Mode, and control simulation fault injection.",
        )
        layout.addWidget(header)

        # 1. Operational Parameters Card
        ops_card = QFrame()
        ops_card.setObjectName("SurfaceCard")
        ops_layout = QFormLayout(ops_card)
        ops_layout.setContentsMargins(16, 14, 16, 14)
        ops_layout.setSpacing(12)

        lbl_ops_title = QLabel("OPERATIONAL TIMERS & RECONCILIATION")
        lbl_ops_title.setObjectName("CardHeader")
        ops_layout.addRow(lbl_ops_title)

        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(5, 600)
        self.spin_interval.setValue(30)
        self.spin_interval.setSuffix(" seconds")
        ops_layout.addRow("Background Drift Audit Interval:", self.spin_interval)

        self.spin_poll = QSpinBox()
        self.spin_poll.setRange(5, 300)
        self.spin_poll.setValue(15)
        self.spin_poll.setSuffix(" seconds")
        ops_layout.addRow("Active Discovery Polling:", self.spin_poll)

        btn_save = QPushButton("Save Preferences")
        btn_save.setObjectName("PrimaryBtn")
        btn_save.clicked.connect(self._on_save)
        ops_layout.addRow("", btn_save)

        layout.addWidget(ops_card)

        # 2. Safe Mode Control Card
        safe_card = QFrame()
        safe_card.setObjectName("SurfaceCard")
        safe_layout = QVBoxLayout(safe_card)
        safe_layout.setContentsMargins(16, 14, 16, 14)
        safe_layout.setSpacing(8)

        lbl_safe_title = QLabel("SAFE MODE LOCKDOWN CONTROL")
        lbl_safe_title.setObjectName("CardHeader")
        safe_layout.addWidget(lbl_safe_title)

        lbl_safe_desc = QLabel(
            "Safe Mode blocks all disruptive router mutations (blocking, unblocking, QoS shaping) "
            "and locks the application into read-only diagnostic inspection. "
            "Safe Mode engages automatically upon database or kernel connectivity failures."
        )
        lbl_safe_desc.setWordWrap(True)
        lbl_safe_desc.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        safe_layout.addWidget(lbl_safe_desc)

        self.btn_toggle_safe = QPushButton("Engage Safe Mode Lockdown")
        self.btn_toggle_safe.setObjectName("DangerBtn")
        self.btn_toggle_safe.clicked.connect(self._on_toggle_safe)
        safe_layout.addWidget(self.btn_toggle_safe)

        layout.addWidget(safe_card)

        # 3. Simulation & Fault Injection Panel
        fault_card = QFrame()
        fault_card.setObjectName("SurfaceCard")
        f_layout = QVBoxLayout(fault_card)
        f_layout.setContentsMargins(16, 14, 16, 14)
        f_layout.setSpacing(8)

        lbl_f_title = QLabel("MOCK SIMULATOR FAULT INJECTION HARNESS")
        lbl_f_title.setObjectName("CardHeader")
        f_layout.addWidget(lbl_f_title)

        lbl_f_desc = QLabel(
            "Test how NetCutter recovers from router anomalies. "
            "These injections only affect the Mock Gateway Simulator and never live network hardware."
        )
        lbl_f_desc.setWordWrap(True)
        lbl_f_desc.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        f_layout.addWidget(lbl_f_desc)

        f_btns = QHBoxLayout()
        f_btns.setSpacing(8)

        btn_t_out = QPushButton("Inject Timeout")
        btn_t_out.clicked.connect(lambda: self.inject_fault_requested.emit("timeout"))
        f_btns.addWidget(btn_t_out)

        btn_disc = QPushButton("Inject Disconnect")
        btn_disc.clicked.connect(lambda: self.inject_fault_requested.emit("disconnect"))
        f_btns.addWidget(btn_disc)

        btn_auth = QPushButton("Inject Auth Error")
        btn_auth.clicked.connect(lambda: self.inject_fault_requested.emit("auth"))
        f_btns.addWidget(btn_auth)

        btn_part = QPushButton("Inject Partial Failure")
        btn_part.clicked.connect(lambda: self.inject_fault_requested.emit("partial"))
        f_btns.addWidget(btn_part)

        btn_clear = QPushButton("Clear All Faults")
        btn_clear.setObjectName("SuccessBtn")
        btn_clear.clicked.connect(lambda: self.inject_fault_requested.emit("clear"))
        f_btns.addWidget(btn_clear)

        f_layout.addLayout(f_btns)
        layout.addWidget(fault_card)
        layout.addStretch()

    def set_safe_mode_state(self, is_safe: bool):
        if is_safe:
            self.btn_toggle_safe.setText("Exit Safe Mode Lockdown")
            self.btn_toggle_safe.setObjectName("SuccessBtn")
        else:
            self.btn_toggle_safe.setText("Engage Safe Mode Lockdown")
            self.btn_toggle_safe.setObjectName("DangerBtn")
        self.btn_toggle_safe.style().unpolish(self.btn_toggle_safe)
        self.btn_toggle_safe.style().polish(self.btn_toggle_safe)

    def _on_save(self):
        settings = {
            "reconcile_interval": str(self.spin_interval.value()),
            "discovery_poll_interval": str(self.spin_poll.value()),
        }
        self.save_settings_requested.emit(settings)

    def _on_toggle_safe(self):
        is_exiting = "Exit" in self.btn_toggle_safe.text()
        self.safe_mode_toggled.emit(not is_exiting)
