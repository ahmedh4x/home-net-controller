"""
More & Settings Consolidated Hub for NetCutter.
Provides clean sub-tab navigation across Gateways, Diagnostics & Logs,
Setup & Tools (Installation), System Settings, and About information.
Eliminates primary sidebar clutter while keeping all advanced features fully accessible.
"""
from __future__ import annotations

from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from netcutter.ui_qt.components import PageHeader
from netcutter.ui_qt.theme import Theme
from netcutter.ui_qt.views.about_view import AboutView
from netcutter.ui_qt.views.diagnostics_view import DiagnosticsView
from netcutter.ui_qt.views.gateways_view import GatewaysView
from netcutter.ui_qt.views.installation_view import InstallationView
from netcutter.ui_qt.views.settings_view import SettingsView


class MoreHubView(QWidget):
    """
    Consolidated settings and system configuration hub.
    Embeds Gateways, Diagnostics, Setup & Tools, Settings, and About in clean sub-tabs.
    """

    def __init__(
        self,
        gateways_view: GatewaysView,
        diagnostics_view: DiagnosticsView,
        installation_view: InstallationView,
        settings_view: SettingsView,
        about_view: AboutView,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)

        self.gateways_view = gateways_view
        self.diagnostics_view = diagnostics_view
        self.installation_view = installation_view
        self.settings_view = settings_view
        self.about_view = about_view

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # 1. Header
        header = PageHeader(
            title="System Configuration & Management Hub",
            subtitle="Router gateways, system diagnostics, dependency setup, administrative settings, and project info.",
        )
        layout.addWidget(header)

        # 2. Modern Tab Bar
        tab_bar = QFrame()
        tab_bar.setObjectName("TabBarFrame")
        tab_bar.setStyleSheet(f"""
            QFrame#TabBarFrame {{
                background-color: {Theme.BG_CARD};
                border: 1px solid {Theme.BORDER_DEFAULT};
                border-radius: 8px;
                padding: 4px;
            }}
        """)
        tab_layout = QHBoxLayout(tab_bar)
        tab_layout.setContentsMargins(4, 4, 4, 4)
        tab_layout.setSpacing(6)

        self.tabs = [
            ("gateways", "Router Gateways", self.gateways_view),
            ("diagnostics", "Diagnostics & Logs", self.diagnostics_view),
            ("installation", "Setup & Tools", self.installation_view),
            ("settings", "System Settings", self.settings_view),
            ("about", "About HNC", self.about_view),
        ]

        self.tab_buttons = {}
        for tab_id, label, _ in self.tabs:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {Theme.TEXT_SECONDARY};
                    border: 1px solid transparent;
                    border-radius: 6px;
                    padding: 8px 18px;
                    font-size: 13px;
                    font-weight: 600;
                }}
                QPushButton:hover {{
                    color: #ffffff;
                    background-color: #162035;
                }}
                QPushButton:checked {{
                    color: {Theme.CYAN};
                    background-color: #101e38;
                    border: 1px solid {Theme.CYAN};
                    font-weight: 700;
                }}
            """)
            btn.clicked.connect(lambda _, t=tab_id: self.switch_subtab(t))
            tab_layout.addWidget(btn)
            self.tab_buttons[tab_id] = btn

        tab_layout.addStretch()
        layout.addWidget(tab_bar)

        # 3. Stacked Sub-pages
        self.stack = QStackedWidget()
        for tab_id, _, view_widget in self.tabs:
            self.stack.addWidget(view_widget)

        layout.addWidget(self.stack)

        # Default to first tab
        self.switch_subtab("gateways")

    def switch_subtab(self, tab_id: str):
        """Switch active sub-tab view."""
        for idx, (t_id, _, widget) in enumerate(self.tabs):
            if t_id == tab_id:
                self.stack.setCurrentIndex(idx)
                self.tab_buttons[t_id].setChecked(True)
            else:
                self.tab_buttons[t_id].setChecked(False)
